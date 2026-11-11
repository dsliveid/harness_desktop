//! Tauri 2 GUI 薄壳：把 [`crate::commands`] 的纯逻辑函数包成 `#[tauri::command]`。
//!
//! ## 这一层为什么必须「薄」
//!
//! 每个 command 只做三件事：取 `State` → 调纯逻辑函数 → 把错误翻成字符串。
//! 任何业务判断都不许写在这里，原因有两个：
//! 1. `#[tauri::command]` 的函数**没法在无 GUI 环境单测**（要 `AppHandle`/`State` 注入），
//!    写在这里的逻辑等于永久失去测试覆盖；
//! 2. 「能力探测清单」（`SUPPORTED_COMMANDS`）与真实实现必须一一对应，
//!    逻辑散进 GUI 层后很容易出现「清单里有、实际没注册」的漂移。
//!
//! 🔴 本文件**永不**注册 `get_device_token` / `raw_ws_send` / `exec_shell`，
//! 原因见 `crate::commands` 模块文档。

use tauri::{Manager, State};

// 别名导入：下面定义的 `#[tauri::command] fn` 与纯逻辑函数同名，
// 直接 `use` 会冲突。用 `core_` 前缀反而让「这层只是转发」更明显。
use crate::boot_state::BootUiState;
use crate::commands::start_pairing_real as core_start_pairing_real;
use crate::commands::ReinjectOutcome as core_reinject_outcome;
use crate::commands::{
    apply_session_grant, check_update as core_check_update, core_sign_in,
    device_status as core_device_status, get_workspace_roots as core_get_workspace_roots,
    log_dir as core_log_dir, open_web_ui_target as core_open_web_ui_target,
    reinject_session_cookie as core_reinject_session_cookie, runner_status as core_runner_status,
    set_workspace_roots_and_push as core_set_workspace_roots_and_push,
    sign_out as core_sign_out, start_pairing as core_start_pairing,
    unpair_device as core_unpair_device, DeviceStatusResponse, HostState, ListCommandsResponse,
    RunnerStatusResponse, SessionCookieSink, StartPairingResponse, UnpairResult, WorkspaceRootsResult,
};

/// 便于前端统一处理错误：Tauri 的 `Result<_, E>` 要求 `E: Serialize`，
/// 这里用 `String` 而不是裸枚举，避免把内部错误结构（可能含路径）变成前端 API 契约。
fn err_str<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// 🔴 能力探测锚点，永不删除（§14.6.3）。
#[tauri::command]
pub fn list_commands() -> ListCommandsResponse {
    crate::commands::list_commands()
}

#[tauri::command]
pub fn device_status(state: State<'_, HostState>) -> DeviceStatusResponse {
    core_device_status(&state)
}

#[tauri::command]
pub fn runner_status(state: State<'_, HostState>) -> RunnerStatusResponse {
    core_runner_status(&state)
}

/// 读取启动状态（前端首屏据此决定显示配对引导 / 正常 / 错误提示）。
///
/// 单独一个 command 而不是塞进 `device_status`：`device_status` 回答「设备是否在线」，
/// 这个回答「宿主启动流程走到哪一步」。两者生命周期不同（启动状态一次定型，
/// 设备状态持续变化），混在一起会让前端难以区分「还没开始」与「连不上」。
#[tauri::command]
pub fn get_boot_state(state: State<'_, HostState>) -> BootUiState {
    state.boot_state()
}

/// 真实配对（异步 command）：调服务端 → 落 token → 写档案 → 拉起 Runner → 接守护。
///
/// 单独一个 command 而不替换上面的同步版：
/// 同步版被现有 5 个单测依赖（且它确实在做输入校验），
/// 真实网络动作必须是异步的（Tauri command 支持 async）。
///
/// ## 🔴 守护接线（2026-11 修的真实缺口）
///
/// `start_pairing_real` 若抢到了守护权（`resp.supervise == true`），这里必须
/// spawn 后台 `supervise` 任务：启动时未配对的实例不进守护循环，若配对路径
/// 也不进，Runner 一退出就永久停在 stopped（「绑定成功但引擎已停止」的根因）。
#[tauri::command]
pub async fn pair_device(
    app: tauri::AppHandle,
    state: State<'_, HostState>,
    code: String,
    name: String,
    server_base_url: Option<String>,
) -> Result<StartPairingResponse, String> {
    let base = server_base_url.unwrap_or_else(crate::bootstrap::default_http_url);
    let resp = core_start_pairing_real(&state, &code, &name, &base)
        .await
        .map_err(|e| e.to_string())?;

    // 🔴 配对成功且已免登录 → 自动进入主界面（方案 A，2026-11）。
    //
    // Cookie 已在 core 路径里写好（apply_session_grant → TauriSessionCookieSink），
    // 此时导航过去就是已登录的主界面。决策收口在 plan_web_ui_navigation（纯函数，
    // 已穷举单测）；signed_in=false（旧服务端未签发会话）不导航，留在基线页提示登录。
    if crate::commands::plan_web_ui_navigation(false, resp.signed_in) {
        navigate_to_web_ui(&app, &base);
    }

    if resp.supervise {
        // 与启动编排完全同源的 Bootstrap 配置（档案 / 策略重放 / 反向收敛）。
        // 🔴 AppHandle 由 Tauri 直接注入 command（Clone + Send + Sync，可进 'static）。
        let app_for_revoked = app.clone();
        let release_app = app.clone();
        let supervise_boot = crate::bootstrap::Bootstrap::new(
            state.vault_ref(),
            state.daemon(),
            "hd-runner",
            hd_protocol::CURRENT_PROTOCOL_VERSION,
        )
        .with_profile_store(std::sync::Arc::new(
            crate::profile::FileProfileStore::with_default_path(),
        ))
        .with_policy_source({
            let snapshot = state.policy();
            std::sync::Arc::new(move || (*snapshot).clone())
        })
        .with_revoked_handler({
            std::sync::Arc::new(move |reason: crate::bootstrap::RevokedReason| {
                let Some(st) = app_for_revoked.try_state::<HostState>() else {
                    tracing::warn!("服务端解绑收敛跳过：HostState 不可用");
                    return;
                };
                let fault = match reason {
                    crate::bootstrap::RevokedReason::ServerUnpaired => {
                        crate::commands::SessionFault::ServerUnpaired
                    }
                    crate::bootstrap::RevokedReason::Generic => {
                        crate::commands::SessionFault::Revoked
                    }
                };
                crate::commands::converge_revoked_to_pairing(&st, fault);
            })
        });

        // 守护循环必须后台跑：command 要立即返回，不能被无限循环堵住。
        //
        // 🔴 释放通道：任务闭包是 'static 的，拿不到 `&HostState`；
        // 通过刚注入的 `AppHandle`（'static 可用）在循环退出时取回状态清标志，
        // 与启动编排（setup 里预取 handle）是同一官方通道。
        let daemon = state.daemon();
        tauri::async_runtime::spawn(async move {
            let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut guard = crate::supervisor::Guard::new(
                hd_runner::reconnect::ReconnectPolicy::default(),
                std::sync::Arc::clone(&shutdown),
            );
            let stop = supervise_boot.supervise(&mut guard, shutdown).await;
            // 归还守护权：通过 AppHandle（'static 可用）取回 HostState 再清标志。
            if let Some(st) = release_app.try_state::<HostState>() {
                st.release_supervision();
            }
            let last_exit = daemon.last_exit();
            tracing::warn!(?stop, ?last_exit, "配对路径守护循环结束");
        });
    }

    Ok(resp)
}

#[tauri::command]
pub fn get_workspace_roots(state: State<'_, HostState>) -> Vec<String> {
    core_get_workspace_roots(&state)
}

/// 解除配对（用户主动解约）：**先通知服务端** → 停 Runner → 清令牌 → 切到需要配对。
///
/// 返回 `UnpairResult`（两段式契约）：本地解绑恒成功，`server_unpaired == false`
/// 表示「服务端可能没同步」（warn 色提示，不是失败）。
#[tauri::command]
pub async fn unpair_device(state: State<'_, HostState>) -> Result<UnpairResult, String> {
    core_unpair_device(&state).await.map_err(err_str)
}

/// 设置工作区白名单，**并下发给执行引擎**。
///
/// 必须走 `_and_push` 版本：宿主记了白名单而 Runner 不知道，是改造前最隐蔽的
/// 安全口径错位（详见 `commands::set_workspace_roots_and_push` 的文档）。
///
/// ## 返回 `WorkspaceRootsResult` 而不是 `Vec<String>`
///
/// 「已保存但未下发」是**成功结果里的降级标记**，不是错误：它必须以 `Ok` 穿过 IPC，
/// 前端才能拿到 `{ roots, pushed, warning }` 并选用 warn 色（`tauriBridge.call()`
/// 会把任何 reject 归一成 null，用 `Err` 送这句话等于让前端只会说「命令未成功」）。
/// 只有校验类真失败（`EmptyRoots` / `NotADirectory` / `Unresolvable`）才走 `Err`。
#[tauri::command]
pub async fn set_workspace_roots(
    state: State<'_, HostState>,
    roots: Vec<String>,
) -> Result<WorkspaceRootsResult, String> {
    core_set_workspace_roots_and_push(&state, roots)
        .await
        .map_err(err_str)
}

/// 配对入口。
///
/// ⚠️ 本壳**未**把它列进 `SUPPORTED_COMMANDS`：它目前只在本地做输入校验与排队，
/// 真正的配对需要 Runner 侧新增 IPC 命令（`hd-runner::ipc::IpcCommand` 现在没有）。
/// 因此这里虽然注册了（方便前端联调），但不对外宣称「支持」——`list_commands`
/// 是给前端做能力判断的，宣称了却做不到会让 UI 展示一个必然失败的功能。
#[tauri::command]
pub fn start_pairing(
    state: State<'_, HostState>,
    code: String,
    name: String,
) -> Result<StartPairingResponse, String> {
    core_start_pairing(&state, &code, &name).map_err(err_str)
}

/// 默认服务端地址（用于启动时重放会话 Cookie）。
fn cookie_base_url() -> String {
    use crate::profile::ProfileStore;
    crate::profile::FileProfileStore::with_default_path()
        .load()
        .ok()
        .flatten()
        .map(|p| p.server_base_url)
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(crate::bootstrap::default_http_url)
}

/// 真实实现：把 `hg_sess` 写进 Tauri WebView 的 Cookie 存储。
///
/// ## 为什么要 `.build()` 一个 `Cookie` 而不是拼字符串
///
/// `hg_sess` 是 HttpOnly + SameSite=Lax —— 这两条**必须**由 Cookie 属性表达，
/// 手拼 `Set-Cookie` 字符串既容易写错顺序，也无法通过 WebView 的 API 生效。
///
/// ## 为什么 Path=/ 且不带 Domain
///
/// （历史小节标题保留以定位上下文；正文已修正：2026-11 起 set/clear 都**显式
/// 带 domain**，见 `TauriSessionCookieSink` —— 不带 domain 的 Cookie 会归属到
/// 写入时窗口所在的域（基线页），服务端页面读不到，这正是免登录失效的根因。）
///
/// 服务端契约就是 `Path=/`（整个 Web UI 共用一条会话）。domain 只该属于
/// 当前连接的那台服务端（从配对档案地址解析，绝不写死）。
#[cfg(feature = "gui")]
struct TauriSessionCookieSink {
    app: tauri::AppHandle,
}

#[cfg(feature = "gui")]
impl TauriSessionCookieSink {
    /// WebView 的 Cookie API 需要 `http(s)` URL（`file://`/`tauri://` 不被接受）。
    fn webview(&self) -> Result<tauri::WebviewWindow, String> {
        self.app
            .get_webview_window("main")
            .ok_or_else(|| "主窗口不存在（无法写入会话 Cookie）".to_string())
    }
}

#[cfg(feature = "gui")]
impl SessionCookieSink for TauriSessionCookieSink {
    fn set_session_cookie(
        &self,
        base_url: &str,
        token: &crate::vault::UserToken,
    ) -> Result<(), String> {
        use tauri::webview::cookie::{time, Cookie};
        // 🔴 显式归属到**服务端域**（2026-11 免登录修复）：
        //
        // `Webview::set_cookie` 收到不带 domain 的 Cookie 时，会把它归属到**写入
        // 时窗口所在的域**（基线页的 localhost:1420 / asset 协议）—— 导航发生后
        // 页面读不到它，用户撞登录墙。这正是「配对成功却要登录」的根因。
        // 移动端 sink 一直显式传 `domain: parsed.host`，此处对齐同款语义。
        // 🔴 127.0.0.1 与 localhost 是不同 host，domain 必须取自档案地址本身。
        // 地址合法性（http/https + 有主机名）由 cookie_host_for 统一判定。
        let host = crate::commands::cookie_host_for(base_url)
            .ok_or_else(|| format!("服务端地址非法或缺少主机名，无法归属 Cookie：{base_url}"))?;
        let mut cookie = Cookie::new(SESSION_COOKIE_NAME, token.expose().to_string());
        cookie.set_path("/");
        cookie.set_domain(host);
        // https 部署必须 Secure（与移动端 isSecure 同款语义，更严格不放宽）。
        if crate::commands::base_url_is_secure(base_url) {
            cookie.set_secure(true);
        }
        cookie.set_http_only(true);
        cookie.set_same_site(tauri::webview::cookie::SameSite::Lax);
        // 与服务端 `session_ttl_s` 默认值对齐（7 天）。即便略有偏差也不影响正确性：
        // 服务端会以自己的过期判定为准，这里只避免客户端留下永不过期的 cookie。
        cookie.set_expires(time::OffsetDateTime::now_utc() + time::Duration::days(7));
        self.webview()?
            .set_cookie(cookie)
            .map_err(|e| format!("写入 hg_sess Cookie 失败：{e}"))
    }

    fn clear_session_cookie(&self, base_url: &str) -> Result<(), String> {
        use tauri::webview::cookie::{time, Cookie};
        // 地址合法性由 cookie_host_for 统一判定（http/https + 有主机名）。
        let host = crate::commands::cookie_host_for(base_url)
            .ok_or_else(|| format!("服务端地址非法或缺少主机名，无法清除 Cookie：{base_url}"))?;
        // 与 set 同源：清除也必须带同一个 domain，否则清的是「另一个域的同名
        // Cookie」，服务端域上的旧会话会残留（WebView 按 (name, domain, path)
        // 三元组匹配）。
        let mut cookie = Cookie::new(SESSION_COOKIE_NAME, String::new());
        cookie.set_path("/");
        cookie.set_domain(host);
        // 过期时间置为过去 = 删除。只置空值是不够的：同名 cookie 会残留。
        cookie.set_expires(time::OffsetDateTime::UNIX_EPOCH);
        self.webview()?
            .delete_cookie(cookie)
            .map_err(|e| format!("清除 hg_sess Cookie 失败：{e}"))
    }
}

/// 服务端 Web UI 的会话 Cookie 名（契约固定，勿改）。
#[cfg(feature = "gui")]
const SESSION_COOKIE_NAME: &str = "hg_sess";

/// 登出账号（**保留设备绑定**）。
///
/// 与 `unpair_device` 严格正交：登出只清会话凭据，设备仍配对、执行引擎继续在线。
///
/// 2026-11 契约一：登录只在原生。登出成功后**自动回基线页**——否则用户停在
/// 服务端主界面上（此时已带失效 Cookie，只会看到登录墙），而登录表单在基线页。
/// 回基线页失败不阻断登出（会话已清，界面只是少了导航）。
#[tauri::command]
pub async fn sign_out(
    app: tauri::AppHandle,
    state: State<'_, HostState>,
) -> Result<(), String> {
    let base = cookie_base_url();
    core_sign_out(&state, &base).map_err(err_str)?;

    // 自动回基线页（登录入口）。复用 open_baseline 的逻辑（快照导航）。
    if let Some(w) = app.get_webview_window("main") {
        if let Some(u) = baseline_url_snapshot(&app) {
            if let Ok(parsed) = url::Url::parse(&u) {
                if let Err(e) = w.navigate(parsed) {
                    tracing::warn!(error = %e, "登出后回基线页失败（会话已清，不影响登出）");
                }
            }
        }
    }
    Ok(())
}

/// 检查更新：返回壳版本与通道（当前 dev 阶段 = 版本对比提示，不做下载安装）。
#[tauri::command]
pub fn check_update() -> crate::commands::CheckUpdateResponse {
    core_check_update()
}

/// 打开设置（轻实现）：主窗口前置聚焦 + 通知 web 页滚动到设置区。
///
/// 壳内没有独立设置窗口（设置面板在远程 UI 里），所以事件名 [`crate::commands::OPEN_SETTINGS_EVENT`]
/// 是跨进程契约，前端 `main.ts` 监听它做页内滚动/聚焦。
#[tauri::command]
pub fn open_settings(app: tauri::AppHandle) -> Result<(), String> {
    // Tauri 2 中 `emit` 在独立 trait 上，必须显式导入。
    use tauri::Emitter;
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "主窗口不存在".to_string())?;
    window.set_focus().map_err(|e| e.to_string())?;
    window
        .emit(crate::commands::OPEN_SETTINGS_EVENT, ())
        .map_err(|e| e.to_string())
}

/// 打开日志目录：排障刚需（Runner 退出原因、宿主守护日志都在这里）。
///
/// 目录不存在时**先创建再打开**：空日志目录也比「点了没反应」好。
/// `explorer` 调用失败按 Err 上浮，让前端给出可读提示。
#[tauri::command]
pub fn open_logs() -> Result<(), String> {
    let dir = core_log_dir().ok_or_else(|| "无法定位系统配置目录（日志目录不可用）".to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建日志目录失败：{e}"))?;
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&dir)
            .spawn()
            .map_err(|e| format!("打开资源管理器失败：{e}"))?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&dir)
            .spawn()
            .map_err(|e| format!("打开 Finder 失败：{e}"))?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(&dir)
            .spawn()
            .map_err(|e| format!("打开文件管理器失败：{e}"))?;
    }
    Ok(())
}

/// 把主窗口导航到服务端 Web UI（内部辅助，供自动导航与 `open_web_ui` 复用）。
///
/// ## 为什么用 `navigate` 而不是 `eval("location.href=...")`
///
/// `navigate` 是 WebView 原生导航：目标不可达时**窗口仍停留在原页面**（基线页
/// 完好），用户可以点「进入主界面」重试；`location.href` 会让 WebView 进入错误态，
/// 基线页 DOM 被销毁，唯一恢复手段是 `reload()`（时机难控）。与「宁可置灰也不要
/// 打开后报错」的既有取向一致。
///
/// 失败只 warn 不上抛：自动导航路径上这不该打断配对成功流程（引擎已经起来了）。
fn navigate_to_web_ui(app: &tauri::AppHandle, base_url: &str) {
    if let Some(w) = app.get_webview_window("main") {
        match url::Url::parse(base_url) {
            Ok(u) => {
                if let Err(e) = w.navigate(u) {
                    tracing::warn!(error = %e, "导航到主界面失败（保留基线页，可手动重试）");
                } else {
                    tracing::info!(url = %base_url, "已导航到服务端主界面");
                }
            }
            Err(e) => tracing::warn!(error = %e, "服务端地址非法，无法导航到主界面"),
        }
    } else {
        tracing::warn!("主窗口不存在，无法导航到主界面");
    }
}

/// 进入主界面（手动兜底入口）：基线页按钮点击后跳服务端 Web UI。
///
/// 自动导航（配对成功/启动自续成功）失败或被用户手动关闭时，从这里重进。
/// 未配对状态点它也放行：目标是服务端登录页，服务端自己会拦截。
///
/// ## 三段式（契约二，2026-11 接入 ticket 主路径）
///
/// 导航目标不是裸地址：先按移动端 `prepareAuth` 同构的三段式产出「带凭据的
/// 首帧 URL」——
/// ① vault 有 user_token → 签发一次性 ticket，拼进 URL fragment（Web 端
///    `authStore.boot()` 已实现消费，免登直达）；
/// ② ①失败且已配对 → 用设备令牌换新会话（vault + Cookie）→ 重签一次 ticket；
/// ③ 仍失败 → 退回裸地址（Cookie 兜底：启动自续/登录路径已写过 hg_sess）。
///
/// 每一段失败都只降级不报错：用户要么免登直达，要么看到服务端登录页，
/// 绝不白屏。
#[tauri::command]
pub fn open_web_ui(app: tauri::AppHandle, state: tauri::State<'_, HostState>) -> Result<(), String> {
    let target = core_open_web_ui_target().ok_or_else(|| "无法确定服务端地址".to_string())?;
    let url = prepare_web_ui_entry(&state, &target);
    navigate_to_web_ui(&app, &url);
    Ok(())
}

/// 三段式产出 Web UI 首帧 URL（纯编排，逐段降级，绝不报错中断）。
///
/// 与移动端 `WebViewTicketApi.prepareAuth` 同构：
/// ① user_token 签发 ticket → `entry#ticket=...`；
/// ② ①失败 → 设备令牌续期（POST /api/v1/devices/session，vault+Cookie）→ 重签；
/// ③ 全败 → 裸地址（兜底：hg_sess Cookie 可能已在，服务端自己判）。
///
/// 阻塞说明：`open_web_ui` 是同步 command，内部用 `block_on` 跑一次网络调用。
/// 该路径由用户点击触发，卡顿可接受；启动路径的自动导航**不经**本函数
/// （启动走 `reinject_session_cookie` 的异步三段式，不阻塞首帧）。
fn prepare_web_ui_entry(state: &HostState, target: &str) -> String {
    // ① 直接用 vault 里的会话签票。
    let user_token = state.user_token().ok().flatten();
    if let Some(token) = user_token {
        let ticket_result = tauri::async_runtime::block_on(async {
            crate::pairing::PairingClient::new(target)
                .issue_webview_ticket(&token, &device_id_of(state))
                .await
        });
        if let Ok(ticket) = ticket_result {
            return crate::pairing::append_ticket_fragment(target, &ticket);
        }
        tracing::info!("ticket 签发未成功，尝试设备令牌续期后重签（三段式②）");

        // ② 设备令牌换新会话 → 重签一次。
        if let Some(grant) = tauri::async_runtime::block_on(async {
            crate::pairing::PairingClient::new(target)
                .renew_session(&state.vault_ref().get().ok().flatten()?)
                .await
                .ok()
        }) {
            if apply_session_grant(state, &grant, target) {
                if let Ok(ticket) = tauri::async_runtime::block_on(async {
                    crate::pairing::PairingClient::new(target)
                        .issue_webview_ticket(&grant.token, &device_id_of(state))
                        .await
                }) {
                    return crate::pairing::append_ticket_fragment(target, &ticket);
                }
            }
        }
        tracing::info!("设备令牌续期未成功，退回裸地址（Cookie 兜底，三段式③）");
    }
    target.to_string()
}

/// 当前设备 ID（ticket 请求体需要；握手前为空串 —— 服务端按展示用处理）。
fn device_id_of(state: &HostState) -> String {
    state.handshake_device_id().unwrap_or_default()
}

/// 原生登录（契约一：登录只在原生）。
///
/// 前端基线页登录表单提交 → 本命令 → Rust 调 `/api/v1/auth/login` →
/// vault + Cookie 落地。成功且服务端可达 → 自动进主界面（与配对成功同款
/// 导航决策）。失败原样上抛错误文案（前端展示）。
///
/// 🔴 密码只进 Rust 堆与 HTTP body，不进日志、不进 URL、不经 JS 堆之外的
/// 任何持久化。
#[tauri::command]
pub async fn sign_in(
    app: tauri::AppHandle,
    state: tauri::State<'_, HostState>,
    username: String,
    password: String,
) -> Result<crate::commands::SignInResponse, String> {
    let base = cookie_base_url();
    let resp = core_sign_in(&state, &username, &password, &base)
        .await
        .map_err(err_str)?;
    // 登录成功 → 自动进主界面（对齐「配对成功即免登直达」的既有体验）。
    if crate::commands::plan_web_ui_navigation(false, resp.signed_in) {
        navigate_to_web_ui(&app, &base);
    }
    Ok(resp)
}

/// 返回基线页（契约三：从服务端 Web UI 回到设置/登录界面）。
///
/// 双通道之一（另一条是托盘菜单，不依赖 IPC）。目标地址用**启动时快照**的
/// 基线页 URL（dev 是 localhost:1420、prod 是壳内 asset 协议地址，二者写死
/// 必错其一）。
///
/// 🔴 **失败必须返回 Err，绝不「假成功」**（2026-11 修正）。
///
/// 早期实现里「无快照」「navigate 失败」两条路径都是 `return Ok(())` —— 只写一条
/// `tracing::warn`。IPC 调用方（服务端 Web UI 的宿主设置浮标）拿到 Ok 后认为
/// 跳转成功，页面却纹丝不动；叠加前端 `if (!promise)` 的真值误判，最终表现为
/// 「浮标点了毫无反应，且永远不隐藏」的死钮，且日志只在壳侧可见，极难排查。
///
/// 现在的语义：**只有真的发起导航才 Ok**；其余一律 Err(可读原因)，
/// 让前端能据 `ok === false` 隐藏浮标并 console 带出原因。
#[tauri::command]
pub fn open_baseline(app: tauri::AppHandle) -> Result<(), String> {
    let Some(w) = app.get_webview_window("main") else {
        return Err("主窗口不存在".to_string());
    };
    let _ = w.set_focus();

    let Some(u) = baseline_url_snapshot(&app) else {
        // 无快照（极端时序：setup 尚未写入）。此前「仅聚焦后报成功」是错的：
        // 若窗口其实已停在服务端 Web UI，聚焦等于什么都没发生。
        tracing::warn!("无基线页快照，无法返回设置界面");
        return Err("无基线页快照（应用可能刚启动，请稍后重试或从托盘菜单返回）".to_string());
    };

    let parsed = url::Url::parse(&u).map_err(|e| {
        tracing::warn!(error = %e, "基线页地址非法，无法导航返回");
        format!("基线页地址非法：{e}")
    })?;

    w.navigate(parsed).map_err(|e| {
        tracing::warn!(error = %e, "返回基线页失败（保留当前页面）");
        format!("导航到基线页失败：{e}")
    })?;

    tracing::info!("已返回基线页（设置界面）");
    Ok(())
}

/// 基线页 URL 快照的存取（启动 setup 时写入一次，之后只读）。
///
/// 为什么放 `open_baseline` 旁边：快照与消费必须同源维护，分散到 setup 的
/// 闭包里会漂移（dev 与 prod 的地址形态不同，写死必错其一）。
fn baseline_url_snapshot(app: &tauri::AppHandle) -> Option<String> {
    app.try_state::<HostState>()
        .and_then(|st| st.baseline_url.read().unwrap_or_else(|e| e.into_inner()).clone())
}



/// 组装并运行 Tauri 应用。
///
/// 顺序有讲究：
/// 1. **single-instance 必须最先注册**。它依赖 `Setup` 钩子里的回调；
///    若在它之前注册了别的插件，第二个实例可能来不及退出就已经启动了 Runner，
///    出现两个 Runner 抢同一个设备令牌（服务端会判定 `device.replaced` 互踢）。
/// 2. 托盘在 `setup` 里创建：需要窗口已存在才能绑定菜单事件。
/// 3. `invoke_handler` 的注册顺序无关紧要，但**必须与 `SUPPORTED_COMMANDS` 完全一致**。
pub fn run() -> tauri::Result<()> {
    let vault = crate::vault::default_vault();
    // 🔴 用户会话令牌走独立的密钥链条目（与设备令牌正交）。
    let user_vault = crate::vault::default_user_vault();
    let stats = std::sync::Arc::new(crate::daemon::RuntimeStats::default());
    let state = HostState::with_user_vault(vault, user_vault, stats);

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // 第二个实例的意图通常是「用户又点了一次图标」→ 把已有窗口提到前台，
            // 而不是再起一套 Runner。
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_focus();
            }
        }))
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            list_commands,
            device_status,
            runner_status,
            get_workspace_roots,
            set_workspace_roots,
            get_boot_state,
            pair_device,
            start_pairing,
            unpair_device,
            sign_out,
            sign_in,
            check_update,
            open_settings,
            open_logs,
            open_web_ui,
            open_baseline
        ])
        .setup(|app| {
            // 🔴 会话 Cookie 通道注入：把 user_token 作为 hg_sess 写进 WebView，
            // 让内嵌的 Web UI 免登录。
            //
            // 为什么必须在 setup 里做（而不是 run() 开头）：`TauriSessionCookieSink`
            // 需要 `AppHandle`，而 AppHandle 只有在 Builder 启动后才可用；
            // 故 `HostState.cookie_sink` 做成运行期可替换槽位。
            //
            // 为什么用 `app.manage` 之外的 state：HostState 已在 `.manage(state)` 里
            // 移入 Tauri，这里只能通过 handle 取回。
            let cookie_app = app.handle().clone();
            if let Some(state) = cookie_app.try_state::<HostState>() {
                state.set_cookie_sink(std::sync::Arc::new(TauriSessionCookieSink {
                    app: cookie_app.clone(),
                }));
            }

            // 🔴 启动会话自续（三段式）：校验 → 失效则用设备令牌换新 → 仍失败才清。
            //
            // 为什么**必须异步**：这一版不再是无条件本地写 Cookie，而要出网询问
            // `GET /api/v1/auth/me`，必要时再 `POST /api/v1/devices/session`。
            // 在 `setup` 里同步等待会直接卡住窗口首帧（用户看到白屏），而用户
            // 最在意的恰恰是「界面能不能开」。
            //
            // 为什么失败不 return Err：自续失败只意味着「需要重新登录/重新配对」，
            // 那是一句可展示的状态，不是启动失败。
            let renew_app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let Some(state) = renew_app.try_state::<HostState>() else {
                    tracing::warn!("启动会话自续跳过：HostState 不可用");
                    return;
                };
                let base = cookie_base_url();
                let outcome = core_reinject_session_cookie(&state, &base).await;
                tracing::info!(?outcome, "启动会话自续完成");

                // 🔴 已登录 → 自动进入主界面（方案 A，2026-11）。
                //
                // Replayed（会话仍有效）与 Renewed（设备令牌换新成功）都意味着
                // 「服务端可达 + Cookie 就绪」，导航过去即已登录的主界面——
                // 这才是「已配对用户每次打开应用」的预期形态，而不是永远停在
                // 配置基线页。决策收口在 plan_web_ui_navigation（纯函数穷举单测）。
                if crate::commands::plan_web_ui_navigation(
                    matches!(
                        outcome,
                        core_reinject_outcome::Replayed | core_reinject_outcome::Renewed
                    ),
                    false,
                ) {
                    navigate_to_web_ui(&renew_app, &base);
                }

                // 会话发生过变化（续期成功 / 已清空）时刷新一次页面：
                // WebView 在 setup 阶段已按「无 Cookie」发出了首批请求，若不刷新，
                // 用户仍会停在登录墙上看不到刚换到的新会话。
                // `Replayed` 不刷新 —— 写回的是同一份 Cookie，刷新纯属浪费。
                // （导航已到新页面时 reload 无害：新页面重新加载自身。）
                if outcome.page_should_reload() {
                    if let Some(w) = renew_app.get_webview_window("main") {
                        let _ = w.eval("window.location.reload()");
                    }
                }
            });

            // 托盘：关窗后进程继续驻留（桌面端常态）。
            // 图标缺失时不让整个启动失败 —— 托盘不是核心功能，UI 仍可用。
            //
            // 2026-11 契约三：菜单加「返回设置界面」。为什么放托盘：主窗口一旦
            // 导航到服务端 Web UI，基线页 DOM 被销毁，页面内按钮无从谈起；
            // 托盘菜单不依赖 WebView 的 IPC（服务端远程页面的 invoke 可能因
            // capability 未授权而不可用），是最保底的通道。
            if let Ok(tray) = tauri::tray::TrayIconBuilder::with_id("main-tray").build(app) {
                // Tauri 2 的 set_tooltip 收 `Option<S>`（`None` 表示清除悬浮提示）。
                let _ = tray.set_tooltip(Some("harness_desktop"));
            }

            // 🔴 基线页 URL 快照（契约三）：`open_baseline` 的导航目标。
            //
            // 为什么必须在 setup 快照：dev 是 `http://localhost:1420`、prod 是
            // 壳内 asset 协议地址 —— 形态由构建模式决定，事后推导必错其一。
            // 窗口此刻必然还停在基线页（首次导航只发生在异步编排之后）。
            let baseline_app = app.handle().clone();
            if let Some(w) = baseline_app.get_webview_window("main") {
                if let Ok(u) = w.url() {
                    if let Some(state) = baseline_app.try_state::<HostState>() {
                        *state.baseline_url.write().unwrap_or_else(|e| e.into_inner()) =
                            Some(u.to_string());
                        tracing::info!(url = %u, "已快照基线页地址（供返回设置用）");
                    }
                }
            }

            // 🔴 启动编排：把「已配对」变成「Runner 在跑」。
            //
            // 为什么用 `tauri::async_runtime::spawn` 而不是 `block_on`：
            // 阻塞会让窗口首帧延后（用户看到几秒白屏），而启动 Runner 需要
            // 建连接、读密钥链，全是 IO。spawn 后立即返回，窗口先出来。
            //
            // 为什么失败也不 return Err：用户最在意「界面能不能开」。Runner 起不来
            // 应该是一个**可见的状态**（前端读 get_boot_state 显示原因），
            // 而不是「打不开」。
            let handle = app.handle().clone();
            // 🔴 同样必须在 spawn 前预取：revoked_handler 闭包要捕获的
            // `AppHandle` 不能在 async block 内从 `app`（&mut App，非 Send）派生。
            let revoked_app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let Some(state) = handle.try_state::<HostState>() else {
                    tracing::warn!("启动编排跳过：HostState 不可用");
                    return;
                };

                // 复用上一轮已 e2e 验证的 Bootstrap；Runner 可执行文件名按平台约定。
                //
                // 🔴 用 `state.daemon()` 而非新建：与 `pair_device` 共用同一实例，
                // 让两处的 is_running() 互相可见，避免重复 spawn。
                let boot = crate::bootstrap::Bootstrap::new(
                    state.vault_ref(),
                    state.daemon(),
                    "hd-runner",
                    hd_protocol::CURRENT_PROTOCOL_VERSION,
                )
                // 🔴 生产必须注入档案：否则连非默认服务端时重启会连错地址
                // （回退到 default_ws_url 的 127.0.0.1:5611）。
                .with_profile_store(std::sync::Arc::new(
                    crate::profile::FileProfileStore::with_default_path(),
                ))
                // 守护循环重启后要重放工作区白名单：注入取值函数读当前 HostState。
                //
                // `State<'_, HostState>` 的生命周期绑定在 setup 回调上，不能直接被
                // `'static` 闭包捕获。这里在进入守护循环前**先把当前 policy 快照
                // 克隆出来**：用户后续改设置时会走 `set_workspace_roots_and_push`
                // 直接下发给运行中的 Runner，因此重启时重放"进入循环那一刻"的快照
                // 已经覆盖了绝大多数场景（改配置 → 立即下发，无需等重启）。
                .with_policy_source({
                    // 🔴 `state` 是 `State<'_, HostState>`（内部引用 `&mut App`），
                    // `.policy()` 必须在 async block 构建期（setup 线程）完成调用，
                    // 只把 Arc 快照捕获进 'static 闭包，避免 `&mut App` 进 future。
                    let snapshot = state.policy();
                    std::sync::Arc::new(move || (*snapshot).clone())
                })
                // 🔴 服务端解绑的**反向收敛**：WS 推 `device.revoked` → Runner 以
                // `EXIT_REVOKED` 退出 → 守护循环判定后调这里清全部凭据并回 NeedsPairing。
                //
                // 为什么用回调注入而不是让 `Bootstrap` 直接依赖 `HostState`：
                // `Bootstrap` 在状态层下层，直接依赖会形成反向依赖环。
                //
                // 为什么捕获 `AppHandle` 而不是 `HostState`：`HostState` 已被 `.manage()`
                // 移入 Tauri，`State<'_, _>` 的生命周期绑在 setup 回调上，无法进 `'static`
                // 闭包。`AppHandle` 是 `Clone + Send + Sync`，回调里 `try_state` 取回即可
                // （与 `cookie_sink` 注入同一手法）。
                .with_revoked_handler({
                    // 🔴 必须在 spawn 的 async block 外先 clone 出 `AppHandle`：
                    // `app`（`&mut tauri::App`）不是 Send，直接在 async move 里
                    // `app.handle()` 会把 `&mut App` 捕进 'static future，
                    // `tauri::async_runtime::spawn` 要求 `Send` → 编译失败。
                    let app_handle = revoked_app;
                    std::sync::Arc::new(move |reason: crate::bootstrap::RevokedReason| {
                        let Some(st) = app_handle.try_state::<HostState>() else {
                            tracing::warn!("服务端解绑收敛跳过：HostState 不可用");
                            return;
                        };
                        let fault = match reason {
                            crate::bootstrap::RevokedReason::ServerUnpaired => {
                                crate::commands::SessionFault::ServerUnpaired
                            }
                            crate::bootstrap::RevokedReason::Generic => {
                                crate::commands::SessionFault::Revoked
                            }
                        };
                        crate::commands::converge_revoked_to_pairing(&st, fault);
                    })
                });

                let outcome = boot.ensure_running().await;
                let owns_lock = state.daemon().holds_instance_lock();
                if let Err(e) = &outcome {
                    tracing::warn!(error = %e, "启动编排失败");
                }
                let ui = crate::boot_state::plan_boot(outcome);
                tracing::info!(state = ?ui.state, detail = %ui.detail, "启动状态已确定");
                state.set_boot_state(ui);

                // ④ 进入守护循环（需求② + 2026-11 配对路径补口）：Runner 意外退出后
                // 按退出码契约自动重启。
                //
                // 只在「本实例真的拉起了 Runner」时启动：外部实例在跑（owns_lock=false）
                // 或未配对/启动失败时，本实例不该抢职责（见 Guard::with_lock_ownership）。
                //
                // 🔴 必须先 CAS 认领 `supervision_running`：若启动时未配对（NeedsPairing
                // → 不进循环），稍后用户配对成功的路径也会进循环 —— CAS 保证两边
                // 只有一个赢家，绝不双循环抢 `wait_exit`。
                if owns_lock && state.claim_supervision() {
                    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let mut guard = crate::supervisor::Guard::new(
                        hd_runner::reconnect::ReconnectPolicy::default(),
                        std::sync::Arc::clone(&shutdown),
                    );
                    let stop = boot.supervise(&mut guard, shutdown).await;
                    // 循环退出必须归还所有权，否则后续配对永远进不了守护。
                    state.release_supervision();
                    let last_exit = state.daemon().last_exit();
                    tracing::warn!(?stop, ?last_exit, "守护循环结束");
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    // 刻意不 `use super::*`：下面只比对纯常量，不需要 gui 模块的任何符号。
    // （导入 `super::*` 会被 clippy 判为 unused import。）

    /// 注册清单与能力清单必须一致：这条测试是「漂移防线」。
    ///
    /// 它只比对常量，不需要 GUI 环境，因此在 `--features gui` 下也能跑。
    #[test]
    fn registered_commands_match_supported_list() {
        // gui.rs 里实际 `generate_handler!` 注册的（不含 start_pairing，见其文档）。
        let registered = [
            "list_commands",
            "device_status",
            "runner_status",
            "get_workspace_roots",
            "set_workspace_roots",
            "get_boot_state",
            "pair_device",
            "sign_out",
            "sign_in",
            "check_update",
            "open_settings",
            "open_logs",
            "open_web_ui",
            "open_baseline",
        ];
        for name in registered {
            assert!(
                crate::commands::SUPPORTED_COMMANDS.contains(&name),
                "已注册但未声明支持的 command：{name}"
            );
        }
        for name in crate::commands::SUPPORTED_COMMANDS {
            assert!(
                registered.contains(&name),
                "宣称支持但未注册的 command：{name}（前端调用会抛异常）"
            );
        }
    }
}
