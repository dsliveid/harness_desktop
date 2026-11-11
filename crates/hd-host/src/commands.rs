//! Tauri command 薄壳（对齐 `docs/桌面端架构与功能设计.md` §17.3）。
//!
//! ## 分层原则：纯逻辑与 GUI 解耦
//!
//! 本文件**不含任何 `tauri` 类型**，只提供纯 Rust 函数 + `serde` 响应结构。
//! `#[tauri::command]` 包装放在 `src/gui.rs`（由 feature `gui` 门控）。
//! 这样做的原因很实际：`cargo test -p hd-host` 在无 WebView2 的 CI 上必须能跑，
//! 而一旦 command 签名里出现 `AppHandle`/`State`，整个 crate 就被 GUI 依赖绑死。
//!
//! ## 🔴 安全底线：这三类 command 永不实现
//!
//! 1. **`get_device_token`** —— 永不实现。令牌一旦能被前端 JS 读到，任何 XSS、
//!    恶意依赖包、被注入的 devtools 脚本都能把它 exfiltrate 出去，而它是**长期凭证**，
//!    泄露 = 设备被永久接管直到服务端吊销。前端需要的只是「是否已配对」这个布尔值
//!    （见 [`device_status`] 的 `paired` 字段），令牌留在 Rust 侧内存里就够。
//! 2. **`raw_ws_send`** —— 永不实现。允许前端直接向服务端写任意帧，等于把前端变成
//!    无限能力的服务端客户端：它可以伪造 `fs.list` 响应、伪造审计事件、跳过端侧
//!    全部守卫（§16）。帧的构造必须由 Rust 侧按固定协议生成。
//! 3. **`exec_shell`** —— 永不实现。任意命令执行是最高危能力，端侧执行必须走
//!    `hd-core::Guarded<E>` 的三闸校验（§16.2）且限定在 `exec_allowlist` 内。
//!    提供一个「绕过守卫的通用 shell」让整套安全设计失去意义。
//!
//! 这三条不是「暂未排期」，而是**设计上不允许存在**。任何 PR 加上它们都应被拒绝。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};

use hd_core::security::guard::Policy;
use hd_protocol::CURRENT_PROTOCOL_VERSION;

use crate::daemon::{Daemon, RuntimeStats};
use crate::vault::{DeviceToken, TokenVault, UserToken, UserTokenVault, VaultError};

/// 宿主壳版本（`Cargo.toml` 的 version，编译期写入）。
pub const SHELL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `list_commands` 的响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListCommandsResponse {
    /// 宿主壳版本。前端据此提示「请升级客户端」。
    pub shell_version: String,
    /// 本壳真实实现并注册的 command 名清单。
    pub supported: Vec<String>,
}

/// `device_status` 的响应。
///
/// 🔴 刻意**不含** `token` 字段：见模块文档第 1 条。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatusResponse {
    /// 是否已配对（密钥链里有令牌）。
    pub paired: bool,
    /// 是否已登录（密钥链里有用户会话令牌 → Web UI 无需再登录）。
    ///
    /// 🔴 与 `paired` **正交**：已配对但未登录是常见状态（旧服务端不签发会话）。
    /// 前端不得用 `paired` 推断 `signed_in`，两者各自有自己的失败模式。
    pub signed_in: bool,
    /// Runner 是否在运行且心跳未超时。
    pub online: bool,
    /// 设备 ID（来自 ws `welcome` 握手；未连接时为 `None`）。
    pub device_id: Option<String>,
    /// 宿主壳版本。
    pub app_version: String,
    /// 端侧协议版本是否与服务端协商通过。未握手前为 `true`（尚无可判定的事实）。
    pub protocol_ok: bool,
    /// 已登录账号的展示名（未登录为 `None`）。
    ///
    /// 只回展示名，**绝不回令牌**：界面需要的是「以谁的身份登录」，
    /// 不是凭据本身。
    #[serde(default)]
    pub user_label: Option<String>,
    /// 会话不可用的原因（**仅供 UI 给可解释文案**，不含任何凭据）。
    ///
    /// ## 为什么需要它（本轮修的真实缺陷）
    ///
    /// 改造前 `reinject_session_cookie` 无条件把 vault 里的 `user_token` 重放进
    /// `hg_sess`。会话 7 天后过期时，WebView 拿失效凭据撞登录墙，用户看到的是
    /// 「莫名要求登录」，而界面这边 `signed_in` 仍是旧的 `true`（vault 里确实还有令牌）
    /// —— 两边叙述矛盾，用户无法判断该做什么。
    ///
    /// 现在续期失败会清掉本地会话，`signed_in` 自然变 `false`，并由本字段说明
    /// 「为什么掉了」。取值是稳定短串（`expired` / `revoked` / `owner_unknown` /
    /// `network` / `unknown`），见 [`SessionFault::as_str`]。
    ///
    /// 无失效事实时为 `None` —— 界面不应把它当成恒有字段。
    #[serde(default)]
    pub session_invalid: Option<String>,
}

/// `runner_status` 的响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerStatusResponse {
    /// 生命周期状态（`stopped` / `running` / `backoff` / `gave_up` / `shutting_down`）。
    pub state: String,
    /// 最近一次心跳（Unix 毫秒；`0` 表示从未收到）。
    pub last_heartbeat_ms: u64,
    /// 累计重启次数。
    pub restarts: u32,
}

/// `set_workspace_roots` 的响应 —— **三态契约**：成功 / 已保存但未下发 / 真失败。
///
/// ## 为什么不是 `Result<Vec<String>, _>`
///
/// 「配置已保存、但没能同步给执行引擎」是一件**既非成功也非失败**的事：配置确实
/// 落库了，用户重试或重启客户端即可收敛。若继续用 `Err(CommandError::PushFailed)`
/// 穿过 IPC，Tauri 会把 promise reject，前端 `tauriBridge.call()` 按铁律把它归一成
/// `null`，于是界面只能说「命令未成功」—— 与「配置其实已保存」的事实**直接矛盾**，
/// 用户会以为白改了一遍。
///
/// 因此把它做成**成功结果里的降级标记**：`Ok` + `pushed == false` + `warning` 人话。
/// 前端据此用 warn 色（而非红字）表达，红字只留给真故障。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceRootsResult {
    /// 归一后的工作区根（前端据此刷新面包屑，避免显示与 `fs.list` 不一致的原始路径）。
    pub roots: Vec<String>,
    /// 是否已成功下发给执行引擎（Runner）。
    pub pushed: bool,
    /// `pushed == false` 时给人看的说明；`pushed == true` 时恒为 `None`。
    pub warning: Option<String>,
}

/// `start_pairing` 的响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartPairingResponse {
    /// 本地是否已受理该配对请求。
    pub accepted: bool,
    /// 给人看的结果说明（如「请求已排队，等待服务端确认」）。
    pub message: String,
    /// 配对后是否已自动进入登录态（服务端签发了用户会话）。
    ///
    /// `false` 是**合法降级**（旧服务端 / historical 配对码）：此时 UI 应提示
    /// 「配对成功，请在下方 Web UI 登录」而不是报错。
    #[serde(default)]
    pub signed_in: bool,
    /// 已登录账号的展示名（`signed_in == false` 时恒为 `None`）。
    ///
    /// 只回展示名，**不含**任何凭据。
    #[serde(default)]
    pub user_label: Option<String>,
    /// 配对路径是否抢到了守护循环所有权（2026-11 补口）。
    ///
    /// `true` 时 GUI 层必须 spawn 后台 `supervise` 任务（纯逻辑层拿不到
    /// `AppHandle`，无法自己 spawn）。老版本前端可安全忽略该字段。
    #[serde(default)]
    pub supervise: bool,
}

/// WebView 会话 Cookie 的写入通道（抽象出来才能单测，且 GUI 层保持薄）。
///
/// ## 为什么要有这一层
///
/// `hg_sess` 必须写进**目标服务端的 Cookie 存储**，而 Cookie API 只在 GUI 层
/// （`Webview::set_cookie`）可用 —— 纯逻辑层拿不到 `AppHandle`。抽成 trait 后：
/// - `commands` 只依赖「写/清 Cookie」这个动作，可注入内存实现做穷举单测；
/// - `gui.rs` 提供真实实现（转发到 `Webview::set_cookie` / `delete_cookie`）。
pub trait SessionCookieSink: Send + Sync {
    /// 写入会话 Cookie（值即 user_token 明文）。
    fn set_session_cookie(&self, base_url: &str, token: &UserToken) -> Result<(), String>;
    /// 清除会话 Cookie（登出 / 解绑）。
    fn clear_session_cookie(&self, base_url: &str) -> Result<(), String>;
}

/// 空实现：无 GUI 环境（单测 / 无壳）默认使用，只记日志不做事。
///
/// 语义上等价于「这台机器没有 WebView」—— 免登录自然无从体现，
/// 但也**绝不能**因此让配对流程失败。
#[derive(Debug, Default)]
pub struct NoopSessionCookieSink;

impl SessionCookieSink for NoopSessionCookieSink {
    fn set_session_cookie(&self, base_url: &str, token: &UserToken) -> Result<(), String> {
        tracing::info!(
            base_url = %base_url,
            token = ?token,
            "无 WebView 通道（空实现）：跳过 hg_sess Cookie 写入"
        );
        Ok(())
    }

    fn clear_session_cookie(&self, base_url: &str) -> Result<(), String> {
        tracing::debug!(base_url = %base_url, "无 WebView 通道（空实现）：跳过 hg_sess Cookie 清除");
        Ok(())
    }
}

/// 心跳超时判定（**再导出自唯一事实源** `lifecycle`）。
///
/// 保留这个名字是为了不破坏既有调用方与测试；权威定义在
/// [`crate::lifecycle::HEARTBEAT_STALE_MS`]。不要在这里改数值 ——
/// 否则又会回到「两个地方各有一套阈值」的旧问题。
pub const HEARTBEAT_STALE_MS: u64 = crate::lifecycle::HEARTBEAT_STALE_MS;

/* ========================================================================
 * 启动会话自续：设备令牌换用户会话（三段式）
 * ===================================================================== */

/// 箱式 future（用于在 trait 方法上做对象安全，`SessionRenewGateway` 要能被 `dyn` 调用）。
type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// `user_token` 有效性校验结论。
///
/// 🔴 **三分而不是两分**：「服务端明确否认」与「根本没问到」在处置上完全不同 ——
/// 前者该续期，后者若也当失效，一次网络抖动就会让用户白丢会话。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionVerify {
    /// 服务端仍认这条会话。
    Valid,
    /// 服务端明确否认（401/403）。
    Invalid,
    /// 连不通 / 5xx 等不确定状态（详情由网关记日志，此处不携带字符串以便 `Copy`）。
    Unreachable,
}

/// 启动重放的下一步动作（纯函数产出，可穷举单测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReinjectStep {
    /// vault 里没有用户会话 → 什么都不做（未登录态）。
    NoSession,
    /// 会话仍然有效 → 直接重放 Cookie（保持既有行为）。
    Replay,
    /// 会话失效或无法确认 → 用设备令牌换一份新会话。
    Renew,
}

/// 由校验结论推导下一步动作（纯函数）。
///
/// 契约（与需求逐字对齐）：
/// - 没有令牌 → 无事可做；
/// - 有效 → 直接写 Cookie；
/// - 无效**或请求失败** → 走续期（服务端可能只是短暂不可达，续期是唯一自愈路径）。
pub fn plan_reinject_step(verify: Option<SessionVerify>) -> ReinjectStep {
    match verify {
        None => ReinjectStep::NoSession,
        Some(SessionVerify::Valid) => ReinjectStep::Replay,
        // Invalid 与 Unreachable 都走续期：续期本身幂等可重试，
        // 且它是唯一能在「会话过期」时自愈的动作。
        Some(SessionVerify::Invalid) | Some(SessionVerify::Unreachable) => ReinjectStep::Renew,
    }
}

/// 会话不可用的原因 —— 写进 `device_status.session_invalid`，让界面给出可解释文案。
///
/// 取值刻意用**稳定短串**而不是服务端原始错误码：原始码会演进（如
/// `device.token_revoked` 改叫别的），而 UI 分支不该跟着服务端文案漂移。
/// 映射集中在 [`SessionFault::from_error_code`]，单测穷举。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionFault {
    /// 会话过期，且本次自动续期未成功（多半是网络或服务端暂时不可用）。
    Expired,
    /// 设备令牌被吊销（`device.token_revoked` 一类）→ 只能重新配对。
    Revoked,
    /// 服务端**主动解除了本设备绑定**（管理端删除 / 端侧解绑后 WS 推 `device.revoked`）。
    ///
    /// 与 [`SessionFault::Revoked`] 分开的理由是**用户看到的事实不同**：
    /// `revoked` 是「你的授权被吊销了」，而这里是「这台设备已经被解除绑定」——
    /// 界面应直说后者（这正是用户自己在服务端点过删除、或别人帮他解绑后的场景）。
    /// 两者动作相同（重新配对），但文案必须准确，否则用户会怀疑自己点错了什么。
    ServerUnpaired,
    /// 设备没有绑定账号（`device.owner_unknown`）→ 需重新配对或服务端补齐归属。
    OwnerUnknown,
    /// 网络不可达：本次无法判断会话是否真的失效。
    Network,
    /// 其他原因（响应结构异常等）。
    Unknown,
}

impl SessionFault {
    /// 稳定短串（前端按它选文案分支，属对外契约，勿随意改名）。
    pub fn as_str(self) -> &'static str {
        match self {
            SessionFault::Expired => "expired",
            SessionFault::Revoked => "revoked",
            SessionFault::ServerUnpaired => "server_unpaired",
            SessionFault::OwnerUnknown => "owner_unknown",
            SessionFault::Network => "network",
            SessionFault::Unknown => "unknown",
        }
    }

    /// 服务端 `apperr` 错误码 → 失效原因（纯函数）。
    ///
    /// 用「包含」而非「等于」匹配：服务端错误码带模块前缀且历史上改过名
    /// （`unauthorized` / `device.unauthorized` / `device.token_revoked`），
    /// 精确等值会让一次小的重命名把「已吊销」误判成「未知原因」。
    pub fn from_error_code(code: &str) -> Self {
        let c = code.to_ascii_lowercase();
        if c.contains("owner_unknown") {
            return SessionFault::OwnerUnknown;
        }
        // 🔴 `unpair` 必须先于 `revoked` 判定：服务端自解约相关码可能同时带
        // `device.unpaired` 这类字面量，先命中更具体的语义。
        // ⚠️ 注意 `device.revoked` 本身仍落 `Revoked` —— 那是「吊销」，不是
        // 「用户主动解绑」，只有 WS terminal 帧的自动收敛场景才构造
        // `ServerUnpaired`（见 `plan_revoked_convergence`）。
        if c.contains("unpair") {
            return SessionFault::ServerUnpaired;
        }
        if c.contains("revoked") || c.contains("disabled") {
            return SessionFault::Revoked;
        }
        if c.contains("unauthorized") || c.contains("unauthenticated") {
            // 401 的通用码：会话本身不认了，但设备令牌可能还能续期。
            return SessionFault::Expired;
        }
        SessionFault::Unknown
    }
}

/// 续期网关：把「网络调用」抽成 trait，让三段式编排能被内存实现穷举。
///
/// ## 为什么必须抽象（与 [`SessionCookieSink`] 同一理由）
///
/// 三段式里真正难测的是**编排**（先验→再续→失败才清），而每一条分支都由
/// 网络结果决定。若直接 `PairingClient` 硬编码进去，想覆盖「有效 / 无效 / 续期失败」
/// 就得起 HTTP 服务器，单测会又慢又脆。
///
/// 抽成 trait 后，生产实现就是 [`HttpSessionRenewGateway`]（转调 `PairingClient`），
/// 单测用内存桩把三条分支逐条钉死。
///
/// 方法用 `BoxFuture` 而非 `async fn`：trait 要能装进 `Arc<dyn ...>` 做运行期注入，
/// 而带 `async fn` 的 trait 目前不满足对象安全。
pub trait SessionRenewGateway: Send + Sync {
    /// 校验用户会话是否仍被服务端认可（`GET /api/v1/auth/me`）。
    fn verify_user_token<'a>(
        &'a self,
        base_url: &'a str,
        token: &'a UserToken,
    ) -> BoxFuture<'a, SessionVerify>;

    /// 用设备令牌换一份新会话（`POST /api/v1/devices/session`）。
    fn renew_session<'a>(
        &'a self,
        base_url: &'a str,
        token: &'a DeviceToken,
    ) -> BoxFuture<'a, Result<crate::pairing::SessionGrant, crate::pairing::PairingError>>;
}

/// 生产实现：转调 `pairing::PairingClient`（hd-host 唯一被许可的出网出口）。
///
/// 每次调用新建客户端：启动路径只走一次，没必要为省一次连接池复用引入缓存状态；
/// 反过来，缓存 `reqwest::Client` 会让「换服务端地址后仍用旧连接」变成隐患。
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpSessionRenewGateway;

impl SessionRenewGateway for HttpSessionRenewGateway {
    fn verify_user_token<'a>(
        &'a self,
        base_url: &'a str,
        token: &'a UserToken,
    ) -> BoxFuture<'a, SessionVerify> {
        Box::pin(async move {
            let client = crate::pairing::PairingClient::new(base_url);
            match client.check_user_session(token).await {
                Ok(true) => SessionVerify::Valid,
                Ok(false) => SessionVerify::Invalid,
                Err(e) => {
                    // 🔴 只记错误描述：`PairingError` 的 Display 里没有任何令牌。
                    tracing::warn!(error = %e, "校验用户会话失败（网络或服务端异常），按需续期处理");
                    SessionVerify::Unreachable
                }
            }
        })
    }

    fn renew_session<'a>(
        &'a self,
        base_url: &'a str,
        token: &'a DeviceToken,
    ) -> BoxFuture<'a, Result<crate::pairing::SessionGrant, crate::pairing::PairingError>> {
        Box::pin(async move {
            let client = crate::pairing::PairingClient::new(base_url);
            client.renew_session(token).await
        })
    }
}

/// `unpair_device` 的响应 —— **两段式契约**：本地解绑恒成功，服务端通知可能失败。
///
/// ## 为什么不是 `Result<(), _>`
///
/// 「本地凭据已清、但没能通知服务端」是一件**既非成功也非失败**的事：本机已经
/// 无法再冒充这台设备（目标已达成），但服务端设备列表里可能还挂着这台机器。
/// 若用 `Err` 送这句话，Tauri 会让 promise reject，前端 `tauriBridge.call()`
/// 归一成 `null` → 界面只能说「命令未成功」，与「本地其实已解绑」直接矛盾，
/// 用户会反复重试一个已经生效的操作（`workspace_roots` 踩过同一个坑）。
///
/// 因此把它做成**成功结果里的降级标记**：`Ok` + `server_unpaired == false` +
/// `warning` 人话，前端用 warn 色（而非红字）表达。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpairResult {
    /// 服务端是否已确认吊销本设备（`POST /api/v1/devices/unpair` 成功 / 幂等 204）。
    ///
    /// `false` 有两种可能：本机本来就没配对（无需通知），或通知失败（见 `warning`）。
    pub server_unpaired: bool,
    /// `server_unpaired == false` 时给人看的说明；已确认时为 `None`。
    #[serde(default)]
    pub warning: Option<String>,
}

/// 服务端解绑通知的结论（纯数据，便于把「提示文案」抽成纯函数穷举）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerUnpairOutcome {
    /// 本地没有设备令牌（未配对 / 已解绑）→ 无需通知，也不是异常。
    NoToken,
    /// 服务端已确认解除绑定（含幂等 204）。
    Confirmed,
    /// 通知失败（网络不可达 / 服务端拒绝）→ **本地解绑仍然生效**，但要提示用户。
    Failed(String),
}

/// 通知失败时给用户看的一句话（纯函数，可穷举单测）。
///
/// ## 措辞为什么强调「本地已解绑」
///
/// 用户点的是「解除配对」，而本地凭据**确实已经清干净了**。若只说「同步服务端
/// 失败」，用户会以为整个操作没生效而反复点击。必须同时说清：本机已完成，
/// 只是服务端列表可能还挂着这台设备 —— 这才是他接下来要做的事（去服务端删）。
pub fn plan_unpair_warning(outcome: &ServerUnpairOutcome) -> Option<String> {
    match outcome {
        ServerUnpairOutcome::NoToken | ServerUnpairOutcome::Confirmed => None,
        ServerUnpairOutcome::Failed(detail) => Some(format!(
            "本机已解除配对（本地设备令牌已清除），但未能通知服务端，\
             服务端设备列表中可能仍显示这台设备（{detail}）。请稍后在服务端设备管理里手动删除。"
        )),
    }
}

/// 把服务端解绑调用结果归一成 [`ServerUnpairOutcome`]（纯函数）。
///
/// 单独抽出来是为了让「失败不阻断本地解绑」这条铁律能被穷举单测钉死 ——
/// 编排放进 `unpair_device_with`，判据留在这里。
pub fn classify_unpair_notice(
    token_present: bool,
    result: Result<(), crate::pairing::PairingError>,
) -> ServerUnpairOutcome {
    if !token_present {
        return ServerUnpairOutcome::NoToken;
    }
    match result {
        Ok(()) => ServerUnpairOutcome::Confirmed,
        Err(e) => ServerUnpairOutcome::Failed(e.to_string()),
    }
}

/// 解绑通知网关：把「网络调用」抽成 trait，让「先通知服务端 → 再停 Runner → 再清凭据」
/// 的编排能被内存实现穷举（与 [`SessionRenewGateway`] 同一理由）。
pub trait DeviceUnpairGateway: Send + Sync {
    /// 通知服务端吊销本设备（`POST /api/v1/devices/unpair`，Bearer 设备令牌）。
    fn unpair_self<'a>(
        &'a self,
        base_url: &'a str,
        token: &'a DeviceToken,
    ) -> BoxFuture<'a, Result<(), crate::pairing::PairingError>>;
}

/// 生产实现：转调 [`crate::pairing::PairingClient::unpair_self`]（hd-host 唯一出网出口）。
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpDeviceUnpairGateway;

impl DeviceUnpairGateway for HttpDeviceUnpairGateway {
    fn unpair_self<'a>(
        &'a self,
        base_url: &'a str,
        token: &'a DeviceToken,
    ) -> BoxFuture<'a, Result<(), crate::pairing::PairingError>> {
        Box::pin(async move {
            let client = crate::pairing::PairingClient::new(base_url);
            client.unpair_self(token).await
        })
    }
}

/// 启动重放的最终结果（供 GUI 层决定是否刷新页面，也便于日志留痕）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReinjectOutcome {
    /// vault 里没有用户会话，未做任何事。
    NoSession,
    /// 会话仍有效，已重放 Cookie。
    Replayed,
    /// 会话已失效，已用设备令牌换到新会话并写入 Cookie。
    Renewed,
    /// 会话失效且续期失败：本地会话已清空、Cookie 已清，设备绑定保留。
    Cleared(SessionFault),
}

impl ReinjectOutcome {
    /// 本次是否**改变了** WebView 里的会话 →
    /// GUI 层据此决定要不要刷新页面（把新会话应用到已发出的请求上）。
    ///
    /// `Replayed` 不算改变：它写回的是同一份 Cookie，刷新只会白白多一次加载。
    pub fn page_should_reload(self) -> bool {
        matches!(
            self,
            ReinjectOutcome::Renewed | ReinjectOutcome::Cleared(_)
        )
    }
}


/// 配对码允许的字符集与长度（服务端生成的格式契约）。
const PAIR_CODE_MIN_LEN: usize = 6;
const PAIR_CODE_MAX_LEN: usize = 12;

/// 宿主运行时状态（由 `AppState` 挂在 Tauri `State` 里）。
///
/// 所有字段都用了 `Arc`/`RwLock`：command 是并发调用的（前端可能同时轮询
/// `runner_status` 与提交 `set_workspace_roots`），不能用 `&mut self`。
pub struct HostState {
    vault: Arc<dyn TokenVault>,
    /// 🔴 用户会话令牌的独立存储（与设备令牌正交，见 `vault::KEYRING_USER_SESSION`）。
    user_vault: Arc<dyn UserTokenVault>,
    /// WebView 会话 Cookie 通道（无 GUI 环境用空实现）。
    ///
    /// 🔴 用 `RwLock` 而非直接持有：真实通道需要 `AppHandle`，而 `AppHandle` 只能在
    /// `setup` 钩子里拿到 —— 那时 `HostState` 已经被 `manage()` 移进 Tauri。
    /// 留一个运行期可替换的槽位，是「先建状态、后注入通道」的唯一干净做法。
    cookie_sink: RwLock<Arc<dyn SessionCookieSink>>,
    /// 已登录账号的展示名（配对成功时写入，供 `device_status` 展示）。
    ///
    /// 🔴 刻意只存**展示名**而非用户对象：界面只需要「以谁的身份登录」，
    /// 存得越多泄露面越大，也没有第二个消费方。
    user_label: RwLock<Option<String>>,
    /// 最近一次会话失效的原因（续期失败时写入，供 `device_status` 给可解释文案）。
    ///
    /// 只存枚举而非字符串：取值集合封闭，前端文案分支才能穷举；
    /// 也避免任何服务端文案（可能含内部信息）直接流到 UI。
    session_invalid: RwLock<Option<SessionFault>>,
    stats: Arc<RuntimeStats>,
    /// 🔴 全局唯一的 Runner 守护实例。
    ///
    /// **必须共享**：启动编排（`gui.rs` setup）与配对（`start_pairing_real`）
    /// 都要拉起 Runner。若各自 `Daemon::new()`，两个实例的 `is_running()` 互相
    /// 不可见 —— 配对流程会以「没在跑」再 spawn 一次，结果同一设备开出两条
    /// WS 连接，服务端给旧连接发 `device.replaced` 并断开，用户看到「配对成功
    /// 却立刻掉线」。这是真实发生过的缺陷，故把实例挂进 State 强制共用。
    daemon: Arc<Daemon>,
    /// 工作区根（已归一的展示形态）。
    roots: RwLock<Vec<PathBuf>>,
    /// 当前守卫策略（`Arc<Policy>` 便于整体替换而不是逐字段改）。
    policy: RwLock<Arc<Policy>>,
    /// 设备 ID（握手后写入）。
    device_id: RwLock<Option<String>>,
    /// 协议协商结果（握手失败后由 Runner 事件置 false）。
    protocol_ok: RwLock<bool>,
    /// 排队的配对请求（本地校验通过后填入）。
    pending_pairing: Mutex<Option<PendingPairing>>,
    /// 启动状态（bootstrap 异步跑完后写入，前端轮询读取）。
    ///
    /// 初值是 `Unknown` 而不是 `NeedsPairing`：bootstrap 是异步的，UI 可能在它
    /// 还没跑完时就来读；给一个假的「需要配对」会让已配对用户看到多余引导。
    boot_state: RwLock<crate::boot_state::BootUiState>,
    /// 守护循环是否已在运行（2026-11 补：配对路径也要进 `supervise`）。
    ///
    /// 🔴 为什么不用 `daemon.is_running()`：它判的是「子进程句柄活着」，而守护
    /// 循环的生命周期比某一次子进程长 —— 循环在退避重启期间子进程恰好是空的。
    /// 若用 is_running 判「要不要再进循环」，会在退避窗口里开出**第二个守护循环**，
    /// 两个循环抢同一个 Daemon 的 `wait_exit`（互相抢事件），重启节奏直接错乱。
    /// AtomicBool 的 CAS（compare_exchange）让「抢着进循环」天然只有一个赢家。
    supervision_running: std::sync::atomic::AtomicBool,
    /// 基线页 URL 快照（GUI 层 setup 时写入，`open_baseline` 消费）。
    ///
    /// 🔴 字段属 HostState 而非 gui 局部变量：`open_baseline` command 与托盘菜单
    /// 是两个不同消费点，放 HostState 才能同源读同一份快照。
    /// 放 `#[cfg(feature = "gui")]` 会迫使 commands.rs 引入 gui 概念；用普通
    /// RwLock<Option<String>> 保持纯逻辑层无 tauri 依赖（纯 GUI 语义的字符串而已）。
    pub baseline_url: RwLock<Option<String>>,
}

/// 已受理的配对请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPairing {
    pub code: String,
    pub name: String,
    pub requested_at_ms: u64,
}

impl HostState {
    pub fn new(vault: Arc<dyn TokenVault>, stats: Arc<RuntimeStats>) -> Self {
        Self::with_user_vault(vault, Arc::new(crate::vault::MemoryUserVault::new()), stats)
    }

    /// 完整构造：同时注入设备令牌 vault 与用户令牌 vault（生产路径用）。
    ///
    /// 保留 [`HostState::new`] 的双参签名，让既有 5 个单测与旧调用方不必改动；
    /// 生产路径（`gui.rs`）必须走这个版本注入真实密钥链，否则「配对后登录态」
    /// 只能活在内存里，重启即丢。
    pub fn with_user_vault(
        vault: Arc<dyn TokenVault>,
        user_vault: Arc<dyn UserTokenVault>,
        stats: Arc<RuntimeStats>,
    ) -> Self {
        Self {
            vault,
            user_vault,
            // 无 GUI 环境（单测/无壳）默认空通道：免登录无从体现，但绝不阻断配对。
            cookie_sink: RwLock::new(Arc::new(NoopSessionCookieSink)),
            user_label: RwLock::new(None),
            session_invalid: RwLock::new(None),
            stats,
            // 默认建一个实例：单测与旧调用方无需改动。
            // 生产路径（gui.rs）会用 `with_daemon` 注入同一个实例。
            daemon: Arc::new(Daemon::new(hd_runner::reconnect::ReconnectPolicy::default())),
            roots: RwLock::new(Vec::new()),
            policy: RwLock::new(Arc::new(Policy::new(Vec::new(), Vec::new()))),
            device_id: RwLock::new(None),
            // 未握手前没有「协议不通过」的事实，默认 true 避免前端误报红。
            protocol_ok: RwLock::new(true),
            pending_pairing: Mutex::new(None),
            boot_state: RwLock::new(crate::boot_state::BootUiState::unknown()),
            supervision_running: std::sync::atomic::AtomicBool::new(false),
            // 基线页快照：GUI setup 写入；无 GUI 环境恒 None（消费方降级为仅聚焦）。
            baseline_url: RwLock::new(None),
        }
    }

    /// 读取当前启动状态（前端轮询）。
    pub fn boot_state(&self) -> crate::boot_state::BootUiState {
        self.boot_state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 写入启动状态（bootstrap 完成后调用）。
    pub fn set_boot_state(&self, state: crate::boot_state::BootUiState) {
        *self.boot_state.write().unwrap_or_else(|e| e.into_inner()) = state;
    }

    /// 尝试认领守护循环的唯一所有权（CAS，2026-11 配对路径接入守护用）。
    ///
    /// 返回 `true` 表示「本次调用成为守护循环的唯一持有者」：调用方可以放心进入
    /// [`crate::bootstrap::Bootstrap::supervise`]；返回 `false` 表示已有别的编排
    /// 在守护（启动编排或更早的配对路径），**绝不**再进第二个循环。
    ///
    /// ## 为什么是 CAS 而不是先读后写
    ///
    /// 启动编排与配对 command 是并发的（setup spawn 的任务与用户点击配对可以
    /// 交错），「先 `supervision_running()` 读到 false 再置 true」之间可能插入
    /// 对方的写入 → 双循环。CAS 把「检查 + 占有」做成一个原子动作，竞态闭合。
    ///
    /// ## 循环结束时必须调 [`HostState::release_supervision`]
    ///
    /// 守护循环退出（GaveUp / shutdown）后标志要清零，否则后续配对永远进不了
    /// 守护，Runner 死了就又回到「无人重启」的旧缺口。
    pub fn claim_supervision(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.supervision_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// 释放守护循环所有权（守护循环返回后调用；见 [`HostState::claim_supervision`]）。
    pub fn release_supervision(&self) {
        self.supervision_running
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// 读取密钥链中的令牌（🔴 仅供宿主内部拉 Runner 使用，绝不经 command 返回）。
    pub fn vault_ref(&self) -> Arc<dyn TokenVault> {
        Arc::clone(&self.vault)
    }

    /// 共享的 Runner 守护实例（🔴 全局唯一，见字段注释）。
    pub fn daemon(&self) -> Arc<Daemon> {
        Arc::clone(&self.daemon)
    }

    /// 当前守卫策略快照（daemon 热更新时用）。
    pub fn policy(&self) -> Arc<Policy> {
        Arc::clone(&self.policy.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// 记录握手结果（由 Runner 事件回调调用）。
    pub fn set_handshake(&self, device_id: Option<String>, protocol_ok: bool) {
        *self.device_id.write().unwrap_or_else(|e| e.into_inner()) = device_id;
        *self.protocol_ok.write().unwrap_or_else(|e| e.into_inner()) = protocol_ok;
    }

    /// 当前握手到的设备 ID（ticket 请求体用；未握手为 `None`）。
    pub fn handshake_device_id(&self) -> Option<String> {
        self.device_id
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 待处理的配对请求（供后续 Runner 通道消费）。
    pub fn pending_pairing(&self) -> Option<PendingPairing> {
        self.pending_pairing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 已配对时取出令牌（🔴 仅限宿主内部写 runner stdin 使用，绝不经 command 返回）。
    pub fn device_token(&self) -> Result<Option<DeviceToken>, VaultError> {
        self.vault.get()
    }

    /// 用户令牌 vault 句柄（仅供宿主内部写 WebView Cookie / 登出时清理）。
    ///
    /// 🔴 与 [`HostState::vault_ref`] 同理：**绝不经 command 把明文返回给前端**。
    pub fn user_vault_ref(&self) -> Arc<dyn UserTokenVault> {
        Arc::clone(&self.user_vault)
    }

    /// 当前是否处于「已登录」态（有用户会话令牌）。
    ///
    /// 读密钥链失败按「未登录」处理（fail-closed）：报「已登录」会让界面
    /// 不给登录入口，而 Web UI 实际会把用户踢回登录页 —— 用户会卡在死胡同。
    pub fn signed_in(&self) -> bool {
        matches!(self.user_vault.get_user_token(), Ok(Some(_)))
    }

    /// 取出用户会话令牌（🔴 仅限宿主内部写 `hg_sess` Cookie 使用）。
    pub fn user_token(&self) -> Result<Option<UserToken>, VaultError> {
        self.user_vault.get_user_token()
    }

    /// 注入 WebView Cookie 通道（生产路径在 `gui.rs` 的 `setup` 里换成真实实现）。
    pub fn set_cookie_sink(&self, sink: Arc<dyn SessionCookieSink>) {
        *self.cookie_sink.write().unwrap_or_else(|e| e.into_inner()) = sink;
    }

    /// Cookie 通道句柄（配对写 Cookie / 登出清 Cookie 时需要）。
    pub fn cookie_sink(&self) -> Arc<dyn SessionCookieSink> {
        Arc::clone(&self.cookie_sink.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// 记录已登录账号的展示名（配对成功 / 登出时调用）。
    pub fn set_user_label(&self, label: Option<String>) {
        *self.user_label.write().unwrap_or_else(|e| e.into_inner()) = label;
    }

    /// 已登录账号的展示名（未登录为 `None`）。
    pub fn user_label(&self) -> Option<String> {
        self.user_label
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 记录会话失效原因（续期失败时写，登录成功后由 `apply_session_grant` 清空）。
    pub fn set_session_invalid(&self, fault: Option<SessionFault>) {
        *self.session_invalid.write().unwrap_or_else(|e| e.into_inner()) = fault;
    }

    /// 当前会话失效原因（`None` = 没有失效事实）。
    pub fn session_invalid(&self) -> Option<SessionFault> {
        *self.session_invalid.read().unwrap_or_else(|e| e.into_inner())
    }
}

/// 把用户会话令牌落进 vault 并注入 WebView Cookie（**配对成功后的唯一落地动作**）。
///
/// ## 为什么顺序是「先 vault 后 Cookie」
///
/// vault 是权威事实源（`device_status.signed_in` 依据它），Cookie 只是把同一事实
/// 告诉 WebView。先写 vault：即使 Cookie 注入失败，重启后仍能凭 vault 重新注入，
/// 用户不会「这次免登录、下次又得登录」。
///
/// ## 失败策略：绝不冒泡成配对失败
///
/// 免登录是**增强**，配对成功是**契约**。任何一步失败都只 Warn 并返回 `false`
/// （表示「本次未能免登录」），调用方据此提示「请登录」即可。
///
/// 返回 `Ok(true)` 表示已进入登录态；`Ok(false)` 表示按未登录降级。
pub fn apply_session_grant(
    state: &HostState,
    grant: &crate::pairing::SessionGrant,
    base_url: &str,
) -> bool {
    // ① vault 落盘（权威事实源）。
    if let Err(e) = state.user_vault.set_user_token(&grant.token) {
        tracing::warn!(error = %e, "保存用户会话令牌失败，本次按未登录降级");
        return false;
    }

    // ② Cookie 注入（失败不影响已落盘的会话，重启会重试）。
    match state
        .cookie_sink()
        .set_session_cookie(base_url, &grant.token)
    {
        Ok(()) => tracing::info!(
            base_url = %base_url,
            user = %grant.user.label(),
            "已把用户会话注入 WebView（hg_sess），Web UI 免登录"
        ),
        Err(e) => tracing::warn!(
            base_url = %base_url,
            error = %e,
            "写入 hg_sess Cookie 失败（会话已保存，重启后会自动重试）"
        ),
    }

    state.set_user_label(Some(grant.user.label().to_string()));
    // 拿到新会话 = 此前"会话失效"的事实已被推翻，清掉失效标记，
    // 否则界面会一直显示"请重新配对"而实际已经登录成功。
    state.set_session_invalid(None);
    true
}

/// 用 vault 里已有的用户令牌**重新注入** Cookie（启动时调用）—— 三段式自续。
///
/// ## 为什么启动要重放一次
///
/// WebView 的 Cookie 存储是持久化的，但可能被「清除站点数据」或迁移配置目录清掉；
/// 而 vault 里的会话仍在有效期内。启动时重放一次，代价是一次本地写入，
/// 换来的是「重启/清缓存后仍免登录」这个用户可感知的确定性。
///
/// ## 为什么不能「无条件重放」（本轮修掉的真实缺陷）
///
/// 用户会话默认只有 7 天（服务端 `session_ttl_h=168`），而设备令牌是长期的。
/// 旧实现把 vault 里的 `user_token` **原样**写回 `hg_sess`，于是过期 8 天后启动：
///
/// ```text
/// vault 里有（已过期的）user_token
///   → 原样写进 Cookie
///   → WebView 拿失效凭据请求，服务端 401
///   → 用户看到登录墙，且界面 signed_in 仍为 true（vault 确有令牌）
///   → 「明明显示已登录，怎么又要我登录」—— 无法解释，也无自愈
/// ```
///
/// ## 三段式（顺序不可调换）
///
/// ```text
/// ① 有 user_token → GET /api/v1/auth/me 校验
///      ├ 有效             → 直接写 Cookie（Replayed，与旧行为一致）
///      └ 无效 / 请求失败   ↓
/// ② 有 device_token → POST /api/v1/devices/session 换新会话
///      ├ 成功 → apply_session_grant 落 vault + 写 Cookie（Renewed）
///      └ 失败 ↓
/// ③ 清 vault 里的 user_token + 清 Cookie，记 warn（Cleared(fault)）
/// ```
///
/// ## 铁律
///
/// - **全程失败仅 warn，绝不影响启动**：用户最在意界面能不能开，本函数返回
///   [`ReinjectOutcome`] 而不返回 `Result`，调用方无从"失败退出"。
/// - **绝不清 device_token**：设备绑定仍然有效，只是会话过期。把绑定一起清掉
///   会让用户为一次 7 天过期重新找配对码 —— 这正是自续要消除的成本。
/// - ③ 之后 `device_status.signed_in` 自然变 `false`（vault 里已无令牌），
///   并由 `session_invalid` 说明原因。
///
/// 返回 `true`（即 `Replayed` / `Renewed`）= 当前确实处于登录态。
pub async fn reinject_session_cookie(state: &HostState, base_url: &str) -> ReinjectOutcome {
    reinject_session_cookie_with(state, base_url, &HttpSessionRenewGateway).await
}

/// 三段式的可注入版本（单测注入内存网关，生产走 [`HttpSessionRenewGateway`]）。
pub async fn reinject_session_cookie_with(
    state: &HostState,
    base_url: &str,
    gateway: &dyn SessionRenewGateway,
) -> ReinjectOutcome {
    // ── ① 读取现有会话并校验 ────────────────────────────────
    let existing = match state.user_vault_ref().get_user_token() {
        Ok(Some(t)) => Some(t),
        Ok(None) => None,
        Err(e) => {
            // 读密钥链失败按「无会话」处理（fail-closed：绝不凭猜测量注入）。
            tracing::warn!(error = %e, "读取用户会话令牌失败，本次按未登录处理");
            None
        }
    };

    let verify = match &existing {
        Some(token) => Some(gateway.verify_user_token(base_url, token).await),
        None => None,
    };

    match plan_reinject_step(verify) {
        ReinjectStep::NoSession => ReinjectOutcome::NoSession,

        // ── 有效：保持旧行为，直接重放 ──────────────────────
        ReinjectStep::Replay => {
            let Some(token) = existing.as_ref() else {
                // plan 已保证 Some，这里只是防御性分支，绝不 panic。
                return ReinjectOutcome::NoSession;
            };
            match state.cookie_sink().set_session_cookie(base_url, token) {
                Ok(()) => {
                    tracing::info!(base_url = %base_url, "启动时已重新注入 hg_sess 会话 Cookie");
                    // 会话被服务端确认有效，此前的失效标记该清掉了。
                    state.set_session_invalid(None);
                }
                Err(e) => {
                    // Cookie 写不进去但会话仍有效：仍算登录态，重启会再试一次。
                    tracing::warn!(error = %e, "启动时注入 hg_sess Cookie 失败（Web UI 可能要求登录）");
                }
            }
            ReinjectOutcome::Replayed
        }

        // ── 无效 / 无法确认：用设备令牌续期 ────────────────
        ReinjectStep::Renew => {
            tracing::info!("用户会话已失效或无法确认，尝试用设备令牌自动续期");
            renew_or_clear(state, base_url, gateway).await
        }
    }
}

/// ② → ③：用设备令牌换新会话，失败则清空本地会话（**保留设备绑定**）。
async fn renew_or_clear(
    state: &HostState,
    base_url: &str,
    gateway: &dyn SessionRenewGateway,
) -> ReinjectOutcome {
    // 取设备令牌：没有它就无从续期，直接走 ③。
    // 🔴 单个 `TokenVault` 只有 get，故这里不 Clone，只在调用期内借用。
    let device_token = match state.vault_ref().get() {
        Ok(Some(t)) => Some(t),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = %e, "读取设备令牌失败，无法自动续期会话");
            None
        }
    };

    let Some(device_token) = device_token else {
        // 无设备令牌 = 未配对（或密钥链读失败）。此时清会话是对的：
        // 界面应显示「未配对 / 需要重新配对」，而不是吊着一个无法自愈的会话。
        tracing::warn!("本地无设备令牌，无法自动续期用户会话");
        return clear_local_session(state, base_url, SessionFault::Expired);
    };

    match gateway.renew_session(base_url, &device_token).await {
        Ok(grant) => {
            // 复用既有落地动作：先 vault（权威）后 Cookie，并写展示名。
            if apply_session_grant(state, &grant, base_url) {
                state.set_session_invalid(None);
                tracing::info!(
                    user = %grant.user.label(),
                    "自动续期成功：已换到新会话，Web UI 无需重新登录"
                );
                ReinjectOutcome::Renewed
            } else {
                // vault 写入失败（密钥链不可写）→ 视同续期没成，按失效处理。
                tracing::warn!("续期成功但会话落盘失败，按未登录降级");
                clear_local_session(state, base_url, SessionFault::Unknown)
            }
        }
        Err(e) => {
            let fault = renew_failure_fault(&e);
            tracing::warn!(
                fault = fault.as_str(),
                error = %e,
                "设备令牌续期失败，清除本地会话并提示重新配对（设备绑定保留）"
            );
            clear_local_session(state, base_url, fault)
        }
    }
}

/// 把续期失败归一成给用户看的原因（纯函数，可穷举单测）。
///
/// 分类的用处是**用户动作不同**：
/// - `Expired` / `Network`：稍后重试或重新登录可能就好；
/// - `Revoked` / `OwnerUnknown`：重试无用，必须重新配对。
pub fn renew_failure_fault(err: &crate::pairing::PairingError) -> SessionFault {
    match err {
        // 连不上 / 超时 / TLS：无法判断设备令牌是否还有效。
        crate::pairing::PairingError::Http(_) => SessionFault::Network,
        // 响应结构异常（含「200 但没有 user_token」）。
        crate::pairing::PairingError::BadResponse(_) => SessionFault::Unknown,
        crate::pairing::PairingError::Rejected { code, .. } => SessionFault::from_error_code(code),
    }
}

/// ③：清本地会话与 Cookie（**设备绑定不动**），并记下失效原因。
fn clear_local_session(
    state: &HostState,
    base_url: &str,
    fault: SessionFault,
) -> ReinjectOutcome {
    // ① 清会话令牌 —— 不写 Cookie，避免 WebView 继续拿失效凭据撞登录墙。
    if let Err(e) = state.user_vault_ref().clear_user_token() {
        // 清不掉也不能影响启动；至少要保证不把过期令牌再写进 Cookie。
        tracing::warn!(error = %e, "清除失效的用户会话令牌失败（本次不写 Cookie）");
    }
    // ② 清 Cookie：让 WebView 立刻回到「未登录」这个可解释状态。
    if let Err(e) = state.cookie_sink().clear_session_cookie(base_url) {
        tracing::warn!(error = %e, "清除 hg_sess Cookie 失败（会话令牌已清，仍视为未登录）");
    }
    // ③ 清展示名与失效原因：界面据此渲染「需要重新配对 / 重新登录」。
    state.set_user_label(None);
    state.set_session_invalid(Some(fault));
    ReinjectOutcome::Cleared(fault)
}

/// `sign_out`：**登出账号，但保留设备绑定**（与 [`unpair_device`] 严格正交）。
///
/// ## 与解绑的分工（对齐移动端 `signOut` / `resetPairing`）
///
/// - 登出：清会话令牌 + 清 `hg_sess` Cookie；**设备仍配对**，执行引擎继续在线，
///   用户重新登录即可恢复。
/// - 解绑：清设备令牌 + 会话令牌 + Cookie，相位回到「需要配对」。
///
/// 若把登出做成「连设备一起解绑」，用户只是想换个账号，却得重新找配对码，
/// 这是移动端已经踩过并修正的坑。
pub fn sign_out(state: &HostState, base_url: &str) -> Result<(), CommandError> {
    // ① 清会话令牌（权威事实源）。
    state
        .user_vault
        .clear_user_token()
        .map_err(|e| CommandError::SignOutFailed(format!("清除用户会话令牌失败：{e}")))?;

    // ② 清 WebView Cookie（失败不阻断：令牌已清，Cookie 里的旧值会被服务端拒用）。
    if let Err(e) = state.cookie_sink().clear_session_cookie(base_url) {
        tracing::warn!(error = %e, "清除 hg_sess Cookie 失败（会话令牌已清除，仍视为登出成功）");
    }

    // ③ 清展示名，避免界面继续显示上一个账号。
    state.set_user_label(None);
    // ④ 主动登出**不是**失效：清掉失效标记，界面才不会提示"会话过期，请重新配对"。
    state.set_session_invalid(None);

    tracing::info!("已登出账号（设备绑定保留）");
    Ok(())
}

/// `sign_in` 的响应（结构与 `StartPairingResponse` 的登录相关字段同构，
/// 便于前端用同一套渲染逻辑处理两种「拿到会话」的路径）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignInResponse {
    /// 是否已进入登录态（`false` = 失败/降级，界面保持登录表单可见）。
    pub signed_in: bool,
    /// 已登录账号展示名（未登录为 `None`）。
    pub user_label: Option<String>,
}

/// 表单登录（**登录只在原生**，契约一）。
///
/// ## 与移动端 `login_page.dart` 的同构关系
///
/// 移动端：原生登录页 → `POST /api/v1/auth/login` → token 进 Keychain → 阶段切
/// `webview`。桌面端：基线页表单 → 本函数 → token 进 vault + 写 Cookie →
/// 调用方（gui.rs）按 [`plan_web_ui_navigation`] 自动进主界面。
///
/// ## 失败策略
///
/// 服务端拒绝（密码错/限流）原样上抛错误码，前端展示可读文案；
/// Cookie 写入失败**不算失败**（vault 已落盘，重启自续会补）。
pub async fn core_sign_in(
    state: &HostState,
    username: &str,
    password: &str,
    base_url: &str,
) -> Result<SignInResponse, CommandError> {
    let username = username.trim();
    if username.is_empty() {
        return Err(CommandError::SignInFailed("用户名不能为空".into()));
    }
    if password.is_empty() {
        return Err(CommandError::SignInFailed("密码不能为空".into()));
    }

    // ① 真实登录（密码不进日志；令牌立即装入 UserToken）。
    let client = crate::pairing::PairingClient::new(base_url);
    let grant = client
        .auth_login(username, password)
        .await
        .map_err(|e| match e {
            crate::pairing::PairingError::Rejected { code, message } => {
                CommandError::SignInRejected { code, message }
            }
            other => CommandError::SignInFailed(other.to_string()),
        })?;

    // ② 复用配对路径的同一落地动作：vault（权威）→ Cookie → 展示名 → 清失效标记。
    let ok = apply_session_grant(state, &grant, base_url);
    tracing::info!(signed_in = ok, user = %grant.user.label(), "原生登录完成");

    Ok(SignInResponse {
        signed_in: ok,
        user_label: Some(grant.user.label().to_string()),
    })
}

/// 由 base_url 解析 Cookie 的归属主机（纯函数，可穷举单测）。
///
/// ## 为什么必须有它（本轮免登录失败的最可能根因）
///
/// `Webview::set_cookie` 收到的 Cookie 若不带 domain，会被归属到**写入时窗口
/// 所在的域**（基线页的 `localhost:1420` / asset 协议），而不是目标服务端的
/// `127.0.0.1:5611` —— 页面读不到，用户撞登录墙。移动端 sink 是显式
/// `domain: parsed.host`，桌面端此前漏了这一步。
///
/// 🔴 `127.0.0.1` 与 `localhost` 是**不同 host**：host-only Cookie 互不可见。
/// domain 必须取自配对档案地址本身，绝不能写死或「好心」归一。
pub fn cookie_host_for(base_url: &str) -> Option<String> {
    let u = url::Url::parse(base_url.trim()).ok()?;
    let scheme = u.scheme();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    u.host_str().filter(|h| !h.is_empty()).map(str::to_string)
}

/// 判断 base_url 是否 https（Cookie 的 Secure 属性依据，纯函数）。
pub fn base_url_is_secure(base_url: &str) -> bool {
    url::Url::parse(base_url.trim())
        .map(|u| u.scheme() == "https")
        .unwrap_or(false)
}

/// 基线页的四态相位（契约一：与移动端 `resolveStage` 同构）。
///
/// 服务端地址是壳内部事实（配对档案），不进参数；这里只按「已配对/已登录」
/// 两个事实推导前端该显示哪张卡。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineStage {
    /// 尚未配对 → 显示配对表单。
    NeedsPairing,
    /// 已配对未登录 → 显示登录表单（对齐移动端「登录只在原生」）。
    NeedsSignIn,
    /// 已配对且已登录 → 引导进主界面（不强制）。
    SignedIn,
}

/// 由配对/登录事实推导基线页相位（纯函数，对齐移动端 `resolveStage` 判定链）。
///
/// 判定链（与移动端逐字对齐）：`未配对 → NeedsPairing`；`未登录 → NeedsSignIn`；
/// `齐全 → SignedIn`。🔴 三个布尔全 false 时**不可能是「已配对未登录」**——
/// 未配对优先于未登录（没有设备绑定就谈不上登录态）。
pub fn plan_baseline_stage(paired: bool, signed_in: bool) -> BaselineStage {
    if !paired {
        return BaselineStage::NeedsPairing;
    }
    if !signed_in {
        return BaselineStage::NeedsSignIn;
    }
    BaselineStage::SignedIn
}


/// `list_commands` —— 🔴 **能力探测锚点，永不删除**（§14.6.3）。
///
/// 前端启动时第一件事就是调它：拿到 `supported` 后决定哪些按钮可点、哪些功能
/// 走降级路径。老版本客户端 + 新版本前端是常态（用户不升级客户端），
/// 若前端直接调用不存在的 command，得到的是「invoke 抛异常」这种没法处理的错误；
/// 先探测能力则能优雅降级。
///
/// `supported` 必须与 [`SUPPORTED_COMMANDS`] **同源**，且只列真实注册的 command ——
/// 列了却调不通，比不列更糟（前端会以为能用）。
pub fn list_commands() -> ListCommandsResponse {
    ListCommandsResponse {
        shell_version: SHELL_VERSION.to_string(),
        supported: SUPPORTED_COMMANDS.iter().map(|s| s.to_string()).collect(),
    }
}

/// 本壳真实实现并注册的 command 名（唯一真源）。
///
/// 🔴 增删 command 必须同步改这里 + `gui.rs` 的 `invoke_handler` 注册。
/// 未实现的 `start_pairing` 之外的「禁止实现」三兄弟永不出现（见模块文档）。
pub const SUPPORTED_COMMANDS: [&str; 15] = [
    "list_commands",
    "device_status",
    "runner_status",
    "get_workspace_roots",
    "set_workspace_roots",
    "get_boot_state",
    "pair_device",
    "unpair_device",
    "sign_out",
    // 2026-11 补齐（此前长期是前端预设、壳未实现的声明缺口，probe 会如实报
    // 「客户端版本过低」误导用户）：三个都是低危本地动作，见各自实现文档。
    "check_update",
    "open_settings",
    "open_logs",
    // 主界面导航：配对/自续成功后自动进服务端 Web UI；此命令是手动兜底入口。
    "open_web_ui",
    // 2026-11 通用流程（三契约）：原生登录 + 返回设置（基线页）。
    // 登录只在原生（对齐移动端 §6.1 决策 2），WebView 内不放登录表单。
    "sign_in",
    "open_baseline",
];

/// 保留的 command 名清单（仅用于测试断言与文档，不注册）。
///
/// 这些名字写在这里是为了让「有人不小心加了它们」在单测里立刻失败，
/// 而不是等到安全评审才发现。
pub const FORBIDDEN_COMMANDS: [&str; 3] = ["get_device_token", "raw_ws_send", "exec_shell"];

/* ============ check_update / open_settings / open_logs（2026-11 补齐） ============ */

/// 前端 → 壳的「打开设置」事件名（`open_settings` command 通过它通知 web 页）。
///
/// 壳内没有独立设置窗口（设置面板在远程 UI 里），所以 `open_settings` 的语义是
/// 「主窗口前置聚焦 + 通知 web 页滚动到设置区」。事件名必须稳定：它是跨进程契约。
pub const OPEN_SETTINGS_EVENT: &str = "hd://open-settings";

/// `check_update` 的响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckUpdateResponse {
    /// 本壳版本（编译期写入，与 `device_status.app_version` 同源）。
    pub shell_version: String,
    /// 更新通道说明（当前阶段固定为 `dev`：本项目尚未建立发布分发，
    /// 「更新」= 重新构建壳。前端据此把按钮语义落在「版本对比 + 提示」上）。
    pub channel: String,
    /// 是否有比壳更新可用通道（当前恒为 `false`，字段预留给未来发布流程）。
    pub update_available: bool,
}

/// `check_update`：返回壳版本与更新通道（**不做下载安装**，2026-11 与用户确认）。
///
/// 当前阶段（v0.0.0-dev，无发布渠道）唯一有意义的动作是把版本号交给前端：
/// 诊断行展示「壳 vX.Y.Z」，用户可肉眼验证 run.sh 是否构建出了最新代码。
/// `update_available` 预留字段，未来接入发布清单时才可能有 `true`。
pub fn check_update() -> CheckUpdateResponse {
    CheckUpdateResponse {
        shell_version: SHELL_VERSION.to_string(),
        channel: "dev".to_string(),
        update_available: false,
    }
}

/// `open_logs`：打开本机日志目录（排障刚需 —— Runner 停止原因都在日志里）。
///
/// ## 日志目录的推导（与档案存储同一约定）
///
/// `<系统配置目录>/harness_desktop/logs`（Windows 是
/// `%APPDATA%\harness_desktop\logs`），与 `FileProfileStore` 的
/// `config_dir()/harness_desktop` 同根：**日志和配对档案永远在同一个根目录下**，
/// 用户排障时一次就能找到全部本机状态。目录不存在时也返回路径（打开前由
/// GUI 层决定是否创建/回退——测试环境下 `dirs::config_dir` 可能为 None，返回
/// `None` 让调用方降级为「报错提示」，绝不猜一个临时目录冒充日志目录）。
pub fn log_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|base| base.join("harness_desktop").join("logs"))
}

/// `open_settings`：打开设置（轻实现：事件通知前端，见 [`OPEN_SETTINGS_EVENT`]）。
///
/// 壳侧职责只有「把事件名吐出来」：真正的窗口前置（`set_focus`）与事件发射
/// 都在 `gui.rs` 的 command 包装层（那里才拿得到 `AppHandle`），核心层保持
/// 可无 GUI 单测。
pub fn open_settings_event_name() -> &'static str {
    OPEN_SETTINGS_EVENT
}

/* ============ 主界面导航（2026-11：配对后自动进入服务端 Web UI） ============ */

/// 导航决策（纯函数，可穷举单测）。
///
/// ## 为什么要一个纯函数而不是在 gui.rs 里写 if
///
/// 「该不该自动跳到主界面」横跨**三条异步路径**（配对成功 / 启动自续成功 /
/// 手动按钮），规则散在 GUI 层会重演 `device_status.online` 改造前的困境：
/// 三处手写三套口径。收口成纯函数后，穷举单测把规则钉死成一份。
///
/// ## 规则
///
/// | 场景 | 输入 | 决策 |
/// |---|---|---|
/// | 配对成功且已免登录 | `signed_in=true` | **导航**（Cookie 刚写好，直接进主界面） |
/// | 配对成功但未免登录 | `signed_in=false` | 不导航（去了是登录墙，留在基线页提示登录） |
/// | 启动自续：会话仍有效 | `replayed=true` | **导航**（已登录，启动即主界面） |
/// | 启动自续：设备令牌换新成功 | `replayed=true` | **导航**（同上） |
/// | 启动自续：无会话/被清 | `replayed=false` | 不导航（服务端不可达或未登录，留基线页） |
/// | 手动按钮 | 不走本函数 | 恒导航（用户显式意图，失败也只是原页不动） |
///
/// 🔴 `Cleared(_)` 一律不导航：清会话通常意味着服务端不可达（Network）或需要
/// 重新登录/配对——此时跳转只会给用户一个 401 页或白屏。
pub fn plan_web_ui_navigation(replayed: bool, signed_in: bool) -> bool {
    replayed || signed_in
}

/// `open_web_ui` 的目标地址：服务端 Web UI 基址（配对档案优先，回退默认）。
///
/// 与 [`crate::commands::profile_base_url`] 同源：配对时记住的 server_base_url
/// 是唯一权威；档案缺失（从未配对）时回退默认地址——用户多半在本机起服务端，
/// 回退比报「未配对」更顺手（真没配对的话 Cookie 也没有，服务端会展示登录页，
/// 不会泄露任何东西）。
pub fn open_web_ui_target() -> Option<String> {
    Some(profile_base_url())
}

/// `device_status`：设备/配对状态。
pub fn device_status(state: &HostState) -> DeviceStatusResponse {
    // 读密钥链可能失败（被锁/无权限）。失败时按「未知 → 未配对」处理：
    // 报「已配对」会让用户以为不需要重新登录，实际谁都连不上。
    let paired = matches!(state.vault.get(), Ok(Some(_)));
    // 🔴 在线判定只走 `RunnerPhase::is_online`（唯一事实源）。
    // 改造前这里手写 `state == Running && (hb == 0 || 未过期)`，规则散落在 command 层，
    // 与 `Lifecycle` 的判定无法一起被穷举测试；现在规则只有一份。
    let online = state
        .stats
        .state()
        .is_online(crate::daemon::now_ms(), state.stats.last_heartbeat_ms());

    DeviceStatusResponse {
        paired,
        // 🔴 登录态独立判定，绝不从 paired 推导（两者失败模式不同）。
        signed_in: state.signed_in(),
        online,
        device_id: state
            .device_id
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone(),
        app_version: SHELL_VERSION.to_string(),
        protocol_ok: *state.protocol_ok.read().unwrap_or_else(|e| e.into_inner()),
        user_label: state.user_label(),
        // 只有在"确实没有会话"时才回失效原因：万一续期后又登录成功，
        // 残留的标记会让界面误报"请重新配对"。
        session_invalid: if state.signed_in() {
            None
        } else {
            state.session_invalid().map(|f| f.as_str().to_string())
        },
    }
}

/// `unpair_device`：解除本机与设备的绑定（**用户主动解约**的唯一入口）。
///
/// ## 为什么需要它（"只有一方主动解约才需重新配对"的客户端半边）
///
/// 服务端侧早有解约能力（`DELETE /api/v1/devices/{did}`），但客户端此前**没有**
/// 任何入口调用 `vault.clear()` —— 用户想解绑只能去服务端删，或手动清密钥链。
/// 缺了这一半，"双方都能主动解约"就不成立。
///
/// ## 顺序为什么是「先通知服务端 → 再停 Runner → 再清凭据」（不可调换）
///
/// 1. **先通知服务端**：鉴权靠的是 `vault` 里的设备令牌。若先清凭据，就再也没有
///    任何凭据能证明「我代表这台设备」，服务端记录将永远留在列表里 ——
///    这正是本轮修掉的真实 bug（原实现全程零 HTTP 调用）。
/// 2. **再停 Runner**：否则 Runner 会握着已失效令牌继续重连，服务端收到一串 401，
///    日志里看起来像"客户端发疯"。此时它退出是因为 stdin EOF，属正常退出。
/// 3. **最后清凭据**：清完就再也回不去了，必须放在所有需要凭据的动作之后。
///
/// ## 服务端调用失败绝不阻断本地解绑
///
/// 本地凭据清空 = 用户的目标（本机不再绑定）已经达成。把它整体报失败只会让用户
/// 反复重试一个已经生效的操作。故失败仅 `tracing::warn!` + 通过
/// [`UnpairResult::warning`] 把「服务端可能没同步」如实告诉用户。
pub async fn unpair_device(state: &HostState) -> Result<UnpairResult, CommandError> {
    unpair_device_with(state, &HttpDeviceUnpairGateway).await
}

/// 可注入版本（单测注入内存网关，生产走 [`HttpDeviceUnpairGateway`]）。
pub async fn unpair_device_with(
    state: &HostState,
    gateway: &dyn DeviceUnpairGateway,
) -> Result<UnpairResult, CommandError> {
    // ① 先通知服务端（**必须最先做**，见函数文档的顺序说明）。
    //
    // 令牌读取失败按「无令牌」处理（fail-closed）：读不到就无法鉴权，此时
    // 服务端一定不会同步，但本地清空仍应继续 —— 不能因为密钥链故障把用户
    // 卡在「想解绑却解不掉」的状态里。
    let device_token = match state.vault.get() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "解除配对：读取设备令牌失败，跳过通知服务端");
            None
        }
    };
    let notice = match &device_token {
        Some(token) => {
            let base_url = profile_base_url();
            state
                .daemon()
                .push_log("[host] 解除配对：正在通知服务端吊销本设备".to_string());
            let outcome = classify_unpair_notice(true, gateway.unpair_self(&base_url, token).await);
            if let ServerUnpairOutcome::Failed(detail) = &outcome {
                // 🔴 只 warn，不 return：本地解绑必须继续。
                tracing::warn!(
                    base_url = %base_url,
                    error = %detail,
                    "通知服务端解除绑定失败（本地解绑仍继续，服务端列表可能残留本设备）"
                );
            }
            outcome
        }
        None => ServerUnpairOutcome::NoToken,
    };

    // ② 停 Runner（内含交还实例锁），避免带着旧令牌继续重连。
    state.daemon().shutdown().await;
    state
        .daemon()
        .push_log("[host] 解除配对：正在清理本地凭据".to_string());

    // ③ 清密钥链令牌 —— 真正的"解约"动作：没有令牌就无法再冒充本设备。
    state
        .vault
        .clear()
        .map_err(|e| CommandError::UnpairFailed(format!("清除设备令牌失败：{e}")))?;

    // ③' 一并清用户会话令牌与 WebView Cookie —— **解绑是「清空全部」**，
    // 与登出（只清会话、保留绑定）严格正交，对齐移动端 `resetPairing` / `signOut`。
    //
    // 失败不让解绑整体失败：设备令牌已清 = 本机再也连不上服务端，残留会话既拿不到
    // 新数据也无法通过用户令牌中间件；把它报成「解绑失败」反而让用户以为设备仍绑着。
    if let Err(e) = state.user_vault.clear_user_token() {
        tracing::warn!(error = %e, "解除配对清理用户会话令牌失败（设备令牌已清除，解绑仍然生效）");
    }
    clear_cookie_for_profile(state);
    state.set_user_label(None);
    // 解绑是「用户主动清空」，不是失效：清掉失效标记，避免界面误报「会话过期」。
    state.set_session_invalid(None);

    // ④ 清内存态：device_id / protocol_ok 回到初始，避免 UI 继续显示旧设备。
    *state.device_id.write().unwrap_or_else(|e| e.into_inner()) = None;
    *state.protocol_ok.write().unwrap_or_else(|e| e.into_inner()) = true;

    // ⑤ 相位回到「需要配对」，让 UI 直接切到配对引导。
    state
        .stats
        .set_state(crate::lifecycle::RunnerPhase::NeedsPairing);

    let warning = plan_unpair_warning(&notice);
    tracing::info!(
        server_unpaired = matches!(notice, ServerUnpairOutcome::Confirmed),
        warning = ?warning,
        "已解除配对，等待重新配对"
    );
    Ok(UnpairResult {
        server_unpaired: matches!(notice, ServerUnpairOutcome::Confirmed),
        warning,
    })
}

/// 从配对档案读服务端 HTTP 基址（取不到回退默认地址）。
///
/// 解绑通知与 Cookie 清理都需要它：前端不该传地址（地址属宿主内部事实）。
fn profile_base_url() -> String {
    use crate::profile::ProfileStore;
    crate::profile::FileProfileStore::with_default_path()
        .load()
        .ok()
        .flatten()
        .map(|p| p.server_base_url)
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(crate::bootstrap::default_http_url)
}


/// 按配对档案里的服务端地址清理 WebView 会话 Cookie。
///
/// 解绑时前端不会传地址（也不该传：地址属宿主内部事实），故从档案取。
/// 取不到地址就跳过 —— 会话令牌此时已被清除，残留 Cookie 会被服务端拒用，
/// 不构成安全风险，只影响界面观感。
fn clear_cookie_for_profile(state: &HostState) {
    let base_url = profile_base_url();
    if let Err(e) = state.cookie_sink().clear_session_cookie(&base_url) {
        tracing::warn!(error = %e, "清除 hg_sess Cookie 失败（会话令牌已清除，解绑仍然生效）");
    }
}

/* ========================================================================
 * 服务端解绑的反向收敛：WS terminal `device.revoked` → 自动清凭据回配对
 * ===================================================================== */

/// 服务端侧「本设备已被解除绑定」的收敛决策（纯函数产出，可穷举单测）。
///
/// ## 为什么必须自动收敛（本轮修的真实 bug）
///
/// 服务端吊销后，Runner 以 `EXIT_REVOKED` 退出，守护循环判定 `is_terminal` →
/// `ReconnectDecision::Stop` 只是**停止重连**：本地凭据还在、相位仍显示「已配对」，
/// 用户卡在「已配对但永远连不上」的死胡同，必须自己想到去点「解除配对」。
/// 服务端已经用 WS 明确告知了事实，客户端就该自己走到可重新配对的终态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokedConvergence {
    /// 不是终态吊销 → 什么都不做（交给既有重连/退避逻辑）。
    Ignore,
    /// 服务端已解除本设备绑定 → 清凭据 + 标记 `server_unpaired` + 回 NeedsPairing。
    ResetToPairing,
}

/// 由「退出码」与「最近一次终止性错误码」推导收敛动作（纯函数）。
///
/// 判定只用**退出码契约**（[`hd_protocol::exit_code`] 的唯一消费点在 lifecycle），
/// 再叠加可选错误码做二次确认：
/// - `EXIT_NO_AUTH`（启动配置缺失/非法）同样要求 repair，但那是**本地**问题，
///   服务端并未解绑 —— 因此只在该帧确为 `device.revoked` 时才标 `ServerUnpaired`。
pub fn plan_revoked_convergence(
    exit_code: Option<i32>,
    terminal_code: Option<&str>,
) -> RevokedConvergence {
    let code = exit_code.and_then(|c| u8::try_from(c).ok());
    // ① 服务端明确推送的是「解除绑定 / 吊销」类终止帧 → 一定收敛，不看退出码
    //    （不同 Runner 版本可能以 EXIT_REVOKED 或 EXIT_NO_AUTH 落地）。
    if let Some(err) = terminal_code {
        let c = err.to_ascii_lowercase();
        if c.contains("revoked") || c.contains("unpair") {
            return RevokedConvergence::ResetToPairing;
        }
    }
    // ② 没有帧信息时按退出码兜底：EXIT_REVOKED 是「服务端解绑」的唯一专用码。
    if hd_protocol::exit_code::requires_repair(code)
        && matches!(code, Some(hd_protocol::exit_code::EXIT_REVOKED))
    {
        return RevokedConvergence::ResetToPairing;
    }
    RevokedConvergence::Ignore
}

/// 该次收敛应记的失效原因（纯函数，可穷举单测）。
///
/// 区分两种事实，因为**用户要去的地方不同**：
/// - `ServerUnpaired`：WS 终止帧（服务端主动推送）或 `EXIT_REVOKED`（该码只由
///   `device.revoked` 产生）→ 服务端已解除本设备绑定，界面要直说这句。
/// - `Revoked`：只知道「凭据不可用了」而没有服务端明确告知 → 沿用既有稳定取值。
pub fn revoked_fault(exit_code: Option<i32>, terminal_code: Option<&str>) -> SessionFault {
    // ① 收到 WS 终止帧 = 服务端亲口说的 → 一定是「服务端解绑」这一侧的事实。
    if terminal_code.is_some() {
        return SessionFault::ServerUnpaired;
    }
    // ② 没有帧但有 EXIT_REVOKED 退出码：该码按 `hd_protocol::exit_code` 契约
    //    只由 `device.revoked` 产生，同样属于服务端解绑。
    if exit_code.and_then(|c| u8::try_from(c).ok())
        == Some(hd_protocol::exit_code::EXIT_REVOKED)
    {
        return SessionFault::ServerUnpaired;
    }
    SessionFault::Revoked
}

/// 收到终态吊销后**自动收敛到「需要配对」**（清全部凭据，与 `unpair_device` 同终点）。
///
/// ## 与 `unpair_device` 的差别
///
/// - `unpair_device`：**用户主动** → 先通知服务端（服务端需要被知会）。
/// - 本函数：**服务端已先动手**（WS 已推 `device.revoked`）→ 无需再通知，
///   再做一次 HTTP 只会拿到幂等 204，纯属浪费一次出网。
///
/// 两者终态完全一致（清 device_token + user_token + Cookie，相位 NeedsPairing），
/// 差别仅在是否需要反向通知，因此**不合并**（见 `sign_out` / `unpair_device` 的正交铁律）。
pub fn converge_revoked_to_pairing(state: &HostState, fault: SessionFault) {
    converge_revoked_to_pairing_at(state, fault, &profile_base_url());
}

/// 同 [`converge_revoked_to_pairing`]，但显式传入服务端基址（供守护循环使用）。
///
/// ## 为什么要单独一个带地址的版本（真实的坑）
///
/// `bootstrap::supervise` 的 repair 分支会**先清配对档案**再清令牌（档案明文、
/// 令牌在密钥链，先清档案能避免「有令牌但连错服务器」）。若收敛时再从档案取地址，
/// 拿到的只能是默认地址 —— 自定义服务端的 `hg_sess` Cookie 就清不掉了。
/// 因此调用方必须在清档案**之前**把地址快照下来传进来。
pub fn converge_revoked_to_pairing_at(state: &HostState, fault: SessionFault, base_url: &str) {
    // ① 清设备令牌：没有它就无法再冒充本设备 —— 这是收敛的核心事实。
    if let Err(e) = state.vault.clear() {
        tracing::warn!(error = %e, "服务端已解绑，但清除设备令牌失败（重启后可能仍显示已配对）");
    }
    // ② 清用户会话令牌 + Cookie（解绑是「清空全部」，不是登出）。
    if let Err(e) = state.user_vault.clear_user_token() {
        tracing::warn!(error = %e, "服务端已解绑，清理用户会话令牌失败");
    }
    if let Err(e) = state.cookie_sink().clear_session_cookie(base_url) {
        tracing::warn!(error = %e, "服务端已解绑，清除 hg_sess Cookie 失败（仍视为已解绑）");
    }
    state.set_user_label(None);
    // ③ 记失效原因：界面据此说明「服务端已解除本设备绑定」而非笼统「请重新登录」。
    state.set_session_invalid(Some(fault));
    // ④ 清内存态 + 相位回到需要配对，UI 直接切到配对引导。
    *state.device_id.write().unwrap_or_else(|e| e.into_inner()) = None;
    *state.protocol_ok.write().unwrap_or_else(|e| e.into_inner()) = true;
    state
        .stats
        .set_state(crate::lifecycle::RunnerPhase::NeedsPairing);
    tracing::warn!(
        fault = fault.as_str(),
        "服务端已解除本设备绑定：本地凭据已清空并切到需要配对"
    );
}

/// 守护循环观测到一次退出后的收敛入口（把纯判定 + 实际清理合成一处）。
///
/// 返回 `true` 表示本次已收敛（调用方据此跳过后续的重启/退避逻辑）。
/// `exit_code` 来自 [`crate::daemon::ExitRecord`]，`terminal_code` 是 Runner
/// 报告给宿主的终止性错误码（没有则为 `None`）。
pub fn handle_terminal_revoked(
    state: &HostState,
    exit_code: Option<i32>,
    terminal_code: Option<&str>,
) -> bool {
    match plan_revoked_convergence(exit_code, terminal_code) {
        RevokedConvergence::Ignore => false,
        RevokedConvergence::ResetToPairing => {
            converge_revoked_to_pairing(state, revoked_fault(exit_code, terminal_code));
            true
        }
    }
}

/// `runner_status`：子进程生命周期快照。
pub fn runner_status(state: &HostState) -> RunnerStatusResponse {
    RunnerStatusResponse {
        state: state.stats.state().as_str().to_string(),
        last_heartbeat_ms: state.stats.last_heartbeat_ms(),
        restarts: state.stats.restarts(),
    }
}

/// `get_workspace_roots`：当前允许访问的工作区根。
pub fn get_workspace_roots(state: &HostState) -> Vec<String> {
    state
        .roots
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|p| p.display().to_string())
        .collect()
}

/// `set_workspace_roots` 的错误。
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    /// 传入的根为空：空白名单意味着拒绝一切（fail-closed），与其让用户面对
    /// 「所有操作都被拒绝」的困惑，不如在设置时就说清楚。
    #[error("工作区根不能为空：至少需要配置一个允许访问的目录")]
    EmptyRoots,
    /// 某个根不是已存在的目录。
    #[error("工作区根不是已存在的目录：{0}")]
    NotADirectory(String),
    /// 某个根无法归一（权限/损坏的软链）。fail-closed 丢弃会导致白名单悄悄变小。
    #[error("工作区根无法解析（权限不足或路径已失效）：{0}")]
    Unresolvable(String),
    /// 配对码格式不合法。
    #[error("配对码格式不合法：需 {PAIR_CODE_MIN_LEN}-{PAIR_CODE_MAX_LEN} 位大写字母或数字")]
    BadPairCode,
    /// 设备名称为空。
    #[error("设备名称不能为空（服务端需要它来区分多台设备）")]
    EmptyDeviceName,
    /// 服务端明确拒绝配对（配对码无效、设备域关闭等）。
    ///
    /// 保留服务端错误码：UI 据此区分「码抄错了」与「服务端没开设备功能」，
    /// 这两件事用户该做的事完全不同。
    #[error("服务端拒绝配对（{code}）：{message}")]
    PairRejected {
        /// `apperr` 错误码。
        code: String,
        /// 可读消息。
        message: String,
    },
    /// 配对过程失败（网络、spawn、档案写入等）。
    #[error("配对失败：{0}")]
    PairFailed(String),
    /// 工作区白名单已保存到宿主，但**未能同步给执行引擎**。
    ///
    /// 单独一个变体而不是并入 `PairFailed`：这两件事的用户处置完全不同 ——
    /// 此处配置已落库，只需重试或重启客户端即可同步，不需要重新配对。
    #[error("工作区配置已保存，但未能同步到执行引擎：{0}")]
    PushFailed(String),
    /// 解除配对失败（通常是密钥链不可写）。
    ///
    /// 单独一个变体：此时 Runner 已停、用户意图明确，报错要能指引「手动清理凭据」，
    /// 与配对阶段的错误处置完全不同。
    #[error("解除配对失败：{0}")]
    UnpairFailed(String),
    /// 登出失败（通常是密钥链不可写）。
    ///
    /// 与 `UnpairFailed` 分开：登出**不动设备绑定**，处置方式完全不同
    /// （重试登出即可，绝不该引导用户重新配对）。
    #[error("登出失败：{0}")]
    SignOutFailed(String),
    /// 表单登录被服务端拒绝（用户名/密码错误、限流等）。
    ///
    /// 保留服务端错误码：UI 据此区分「密码错了」与「服务端不可达」，
    /// 两者给用户的下一步指引完全不同。
    #[error("登录失败（{code}）：{message}")]
    SignInRejected {
        /// `apperr` 错误码。
        code: String,
        /// 可读消息。
        message: String,
    },
    /// 登录过程失败（网络、密钥链写入等）。
    #[error("登录失败：{0}")]
    SignInFailed(String),
}

/// `set_workspace_roots`：设置并归一工作区根，返回**归一后**的清单。
///
/// ## 🔴 本函数只更新宿主侧，**不下发 Runner**
///
/// 改完 `HostState` 就返回，Runner 那边的 `Policy` 仍是旧值。生产路径必须调用
/// [`set_workspace_roots_and_push`]，否则会出现「宿主认为该目录已允许、Runner 仍按
/// 旧白名单拒绝」的口径错位（这正是改造前长期存在的缺陷）。
///
/// 保留本同步版本的理由：单测与「只想校验归一结果、不涉及运行期 Runner」的调用方
/// 需要它；把它做成 async 会让这些纯逻辑用例被迫引入 runtime。
///
/// 为什么返回归一结果而不仅是 `()`：`Policy::new` 会 canonicalize 并把 Windows 的
/// `\\?\` 前缀剥掉（见 hd-core`security::paths`）。前端拿到归一值才能正确显示面包屑；
/// 若前端保留自己那份原始输入，就会出现「设置成功但显示路径与 fs.list 返回不一致」。
///
/// 为什么不静默丢弃坏路径：白名单悄悄少一项，用户会以为某目录被允许却在操作时被拒，
/// 排查成本极高。这里选择整体拒绝并明确报错（fail-loud，配置错误应在设置时暴露）。
pub fn set_workspace_roots(
    state: &HostState,
    roots: Vec<String>,
) -> Result<Vec<String>, CommandError> {
    if roots.is_empty() {
        return Err(CommandError::EmptyRoots);
    }
    // 先逐个校验存在性，再构造 Policy：顺序反了会让「配置里有坏路径」表现为
    // 「白名单凭空少一项」（Policy::new 对无法解析的根是丢弃 + 告警）。
    for r in &roots {
        let p = Path::new(r);
        if !p.is_dir() {
            return Err(CommandError::NotADirectory(r.clone()));
        }
        if std::fs::canonicalize(p).is_err() {
            return Err(CommandError::Unresolvable(r.clone()));
        }
    }

    let policy = Arc::new(Policy::new(
        roots.iter().map(PathBuf::from).collect(),
        Vec::new(),
    ));
    let normalized: Vec<PathBuf> = policy.roots().to_vec();
    if normalized.len() != roots.len() {
        // 走到这里说明 Policy 丢了根（并发删除等极端情况）。宁可报错也不接受半套策略。
        return Err(CommandError::Unresolvable(
            "部分根在归一过程中被丢弃（可能已被删除）".to_string(),
        ));
    }

    *state.roots.write().unwrap_or_else(|e| e.into_inner()) = normalized.clone();
    *state.policy.write().unwrap_or_else(|e| e.into_inner()) = policy;

    Ok(normalized.iter().map(|p| p.display().to_string()).collect())
}

/// 设置工作区根**并下发给 Runner** —— 生产路径唯一该用的入口。
///
/// ## 为什么必须存在（改造前缺的就是这一步）
///
/// [`set_workspace_roots`] 只写 `HostState`。Runner 侧的 `Policy` 来自它自己启动时的
/// `initial_roots()`（= 进程当前目录），此后只有收到 `reload_policy` 控制行才会更新。
/// 那条控制行在改造前**从未被发出**，于是：
///
/// ```text
/// 用户在 UI 里配置了工作区 A
///   → 宿主记录 A，UI 显示已允许
///   → Runner 仍只认启动时的 CWD（Windows 双击 ≈ exe 所在目录）
///   → 用户对 A 目录的任何操作被 Runner 拒绝，且看不出原因
/// ```
///
/// 这是**安全口径**问题而非体验问题：宿主与 Runner 对「什么路径合法」持有两份
/// 不同答案，而真正执行校验的是 Runner。
///
/// ## 顺序为什么是「先落状态、再下发」
///
/// 反过来的话，下发成功但写状态失败会让宿主显示旧白名单、Runner 却已按新白名单放行 ——
/// 界面上看是「没改」，实际权限已扩大，属于最容易漏审的状态不一致。
///
/// 下发失败时不回滚宿主状态：路由器的 `Arc<Policy>` 是快照语义，回滚需要重建 Router，
/// 而 Runner 侧可能已部分生效。这里选择**如实告知调用方发生了什么**，但要注意
/// **用什么形式告知**：配置已落库这一事实不会因为下发失败而改变，所以「已保存但未
/// 下发」不是 `Err`，而是 `Ok` 里的 `pushed = false` + `warning`（见
/// [`WorkspaceRootsResult`] 的文档）。前端据此用 warn 色提示「请重试或重启客户端」，
/// 而不是把它当故障报「命令未成功」。
///
/// 只有**校验类错误**（`EmptyRoots` / `NotADirectory` / `Unresolvable`）才是真失败，
/// 它们仍然冒泡成 `Err` —— 那时配置根本没保存，用户必须改输入。
pub async fn set_workspace_roots_and_push(
    state: &HostState,
    roots: Vec<String>,
) -> Result<WorkspaceRootsResult, CommandError> {
    // ① 校验 + 归一 + 写入宿主状态（复用同步版，避免两套校验逻辑漂移）。
    //    这一行之后，「配置已保存」既成事实；因此后续任何失败都不能报成「没保存」。
    let normalized = set_workspace_roots(state, roots)?;

    // ② 取刚写入的那份 Policy 快照下发给 Runner。
    //    用 state.policy() 而不是自己再构造一次：保证「下发的」与「宿主记录的」
    //    是同一个归一结果（重新构造可能在极端并发下算出不同值）。
    let policy = state.policy();

    // ③ 三种结果收敛成三态（判定逻辑抽成纯函数，便于穷举单测，见
    //    `classify_push_outcome`）：
    //    - Ok            → 真下发成功（pushed = true，无 warning）
    //    - Runner 未运行 → 预期分支（白名单随下次 spawn 生效），仍算「未下发」但要解释清楚
    //    - 其它写失败    → 真下发失败（管道坏/写超时），同样归入「未下发」并给出原因
    let pushed = state.daemon().reload_policy(&policy).await;
    Ok(classify_push_outcome(normalized, &pushed))
}

/// 把「下发结果」翻译成 [`WorkspaceRootsResult`] —— 三态判定的**唯一事实源**。
///
/// 抽成纯函数而不是写在 async 函数里的 `match`：真实下发要么成功、要么只能靠真子进程
/// 制造失败（`send_line` 在无 Runner 时永远回 `WriteAuth`），那样「真下发失败」这一
/// 分支就永远测不到。抽出判定后，三个分支都能用构造出来的 `DaemonError` 穷举覆盖。
///
/// `pushed` 形参即取名字段：三态中「已保存但未下发」的两个子原因（Runner 未运行 /
/// 写管道失败）对用户是同一件事——**配置保住了，等下次同步**，因此都映射为
/// `pushed = false` + `warning`，而不是 `Err`（用 `Err` 会被前端归一成 null，语义丢失）。
fn classify_push_outcome(
    normalized: Vec<String>,
    pushed: &Result<(), crate::daemon::DaemonError>,
) -> WorkspaceRootsResult {
    match pushed {
        Ok(()) => WorkspaceRootsResult {
            roots: normalized,
            pushed: true,
            warning: None,
        },
        Err(e) if is_runner_not_running(e) => {
            tracing::debug!("Runner 未运行，工作区白名单将在下次启动时下发");
            WorkspaceRootsResult {
                roots: normalized,
                pushed: false,
                // 预期分支也要说清楚「配置没丢」，否则用户会反复重试。
                warning: Some(
                    "执行引擎当前未运行，配置已保存，将在下次启动执行引擎时自动生效".to_string(),
                ),
            }
        }
        Err(e) => {
            // 🔴 `PushFailed` 变体保留：这里仍构造它用于日志与溯源（daemon 层错误的唯一
            //    结构化出口），但**不**作为 IPC 错误出口 —— 它只是 warning 文案的来源。
            let err = CommandError::PushFailed(e.to_string());
            tracing::warn!("工作区白名单已保存但下发失败：{err}");
            WorkspaceRootsResult {
                roots: normalized,
                pushed: false,
                warning: Some(format!("{err}。请重试或重启客户端")),
            }
        }
    }
}

/// 判断下发失败是否仅因为「Runner 当前没在跑」。
///
/// 这类失败是正常的（用户可以在 Runner 未启动时改配置），不该冒泡成错误；
/// 其余失败（管道已坏、写超时）才是真问题。
fn is_runner_not_running(e: &crate::daemon::DaemonError) -> bool {
    // `send_line` 在无子进程时返回 `WriteAuth("Runner 未运行")`。
    // 按变体判断而不是匹配字符串：文案改动不应影响控制流。
    matches!(e, crate::daemon::DaemonError::WriteAuth(_))
}

/// `start_pairing` 的**本地**实现。
///
/// ⚠️ 能力边界必须诚实：真正的配对是「把 code 交给服务端 → 服务端把 token 下发 →
/// 写入密钥链」。宿主壳当前没有直连服务端的通道（Runner 还没接到配对命令，
/// `hd-runner::ipc::IpcCommand` 里也刻意没有 pairing 变体）。因此这里做的是
/// **前端输入校验 + 请求排队**，返回 `accepted=true` 表示「本地已受理」而**不是**
/// 「配对成功」——成功与否由 `device_status.paired` 反映。
///
/// 之所以仍列进 `SUPPORTED_COMMANDS`：它确有真实行为（校验 + 落状态），
/// 前端调它不会拿到「command 不存在」的异常。而「永远只返回 NotImplemented」的
/// 桩函数坚决不列 —— 那会让前端以为功能可用。
pub fn start_pairing(
    state: &HostState,
    code: &str,
    name: &str,
) -> Result<StartPairingResponse, CommandError> {
    let code = code.trim();
    let name = name.trim();

    if name.is_empty() {
        return Err(CommandError::EmptyDeviceName);
    }
    // 只允许大写字母与数字：服务端按此格式生成，小写或含符号说明是用户手抄错了。
    // 在这里拒掉比发给服务端再等回包快，也避免把明显的垃圾输入打到服务端日志。
    let valid = (PAIR_CODE_MIN_LEN..=PAIR_CODE_MAX_LEN).contains(&code.len())
        && code
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
    if !valid {
        return Err(CommandError::BadPairCode);
    }

    *state
        .pending_pairing
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(PendingPairing {
        code: code.to_string(),
        name: name.to_string(),
        requested_at_ms: crate::daemon::now_ms(),
    });

    Ok(StartPairingResponse {
        accepted: true,
        message: "配对请求已在本机排队；服务端确认后 device_status.paired 会变为 true".to_string(),
        // 排队阶段还没有任何会话事实：一律按未登录，前端不得据此渲染「已登录」。
        signed_in: false,
        user_label: None,
        // 排队路径未拉起 Runner，无需接守护（真实拉起走 start_pairing_real）。
        supervise: false,
    })
}

/// 配对输入校验（纯函数，不碰网络）。
///
/// 抽出来是因为它被两条路径共用：同步的 [`start_pairing`]（仅校验+排队）
/// 与异步的 [`start_pairing_real`]（校验+真实配对）。校验规则写两份必然漂移。
pub fn validate_pair_input<'a>(
    code: &'a str,
    name: &'a str,
) -> Result<(&'a str, &'a str), CommandError> {
    let code = code.trim();
    let name = name.trim();

    if name.is_empty() {
        return Err(CommandError::EmptyDeviceName);
    }
    // 只允许大写字母与数字：服务端按此格式生成，小写或含符号说明是用户手抄错了。
    // 在这里拒掉比发给服务端再等回包快，也避免把明显的垃圾输入打到服务端日志。
    let valid = (PAIR_CODE_MIN_LEN..=PAIR_CODE_MAX_LEN).contains(&code.len())
        && code
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
    if !valid {
        return Err(CommandError::BadPairCode);
    }
    Ok((code, name))
}

/// 真实配对（异步）：调服务端换 token → 落密钥链 → 写档案 → 拉起 Runner。
///
/// ## 与 [`start_pairing`] 的关系
///
/// 旧的同步版本保留下来做**输入校验**（`validate_pair_input`），
/// 因为它不碰网络、可纯单测；真实网络动作放在这里，避免把 IO 混进校验逻辑。
///
/// ## 为什么必须由 Rust 发请求
///
/// 响应里带 `device_token` 明文（长期凭证）。若让前端发，令牌必然经过 WebView
/// 的 JS 堆与网络栈 —— XSS、恶意依赖、被注入的 devtools 都能拿到。
pub async fn start_pairing_real(
    state: &HostState,
    code: &str,
    name: &str,
    server_base_url: &str,
) -> Result<StartPairingResponse, CommandError> {
    // ① 先做本地校验：非法输入不必打服务端（也避免把垃圾写进服务端日志）。
    let (code, name) = validate_pair_input(code, name)?;

    // ② 真实配对。
    let client = crate::pairing::PairingClient::new(server_base_url);
    let paired = client
        .pair(code, name, platform_tag(), env!("CARGO_PKG_VERSION"))
        .await
        .map_err(|e| match e {
            crate::pairing::PairingError::Rejected { code, message } => {
                CommandError::PairRejected { code, message }
            }
            other => CommandError::PairFailed(other.to_string()),
        })?;

    // ③ 落令牌 + 写档案 + 拉起 Runner（复用已 e2e 验证的 Bootstrap）。
    //
    // 🔴 必须用 `state.daemon()` 而不是新建：与启动编排共用同一个实例，
    // 否则它的 `is_running()` 看不到 setup 已拉起的 Runner，会重复 spawn
    // 造成同设备两条 WS（服务端 replaced 互踢，表现为「配对成功却立刻掉线」）。
    let boot = crate::bootstrap::Bootstrap::new(
        state.vault_ref(),
        state.daemon(),
        "hd-runner",
        paired.protocol_version,
    )
    .with_profile_store(std::sync::Arc::new(
        crate::profile::FileProfileStore::with_default_path(),
    ));

    // 🔴 先把会话授权从 PairedDevice 里「摘」出来：`on_paired` 消费整个结构体，
    // 而后续 Cookie 注入只需要会话部分。
    let mut paired = paired;
    let session = paired.session.take();

    boot.on_paired(paired)
        .await
        .map_err(|e| CommandError::PairFailed(e.to_string()))?;

    // ③′ 配对路径也要进守护循环（2026-11 修的真实缺口）：
    //
    // 启动时未配对的实例不会进入守护循环（NeedsPairing → owns_lock=false），
    // 旧逻辑只在这里 spawn 一次 Runner，之后它退出就**永久停在 stopped**，
    // 表现为「设备绑定成功，执行引擎已停止，且没有任何下一步」。
    //
    // 🔴 用 `claim_supervision` CAS：与启动编排竞争唯一守护权，赢家进循环、
    // 输家（已有守护）直接跳过。**本函数是纯逻辑层（commands.rs）**，拿不到
    // tauri::AppHandle —— 这里只声明意图（写进待守护队列），真正的 spawn
    // 由 GUI 层在 command 包装里完成（见 gui.rs `pair_device`）。
    let should_supervise = state.claim_supervision();
    // ④ 免二次登录：把 user_token 落 vault + 写 WebView 的 hg_sess Cookie。
    //
    // 这一步**绝不失败**：服务端没签发（旧版本/historical 配对码）或写 Cookie 失败，
    // 都只是「本次未免登录」，配对本身已经成功 —— 把它做成 Err 会让用户
    // 因为一个可选增强而不得不重来一遍配对。
    let (signed_in, user_label) = match session.as_ref() {
        Some(grant) => {
            let ok = apply_session_grant(state, grant, server_base_url);
            (ok, Some(grant.user.label().to_string()))
        }
        None => {
            tracing::info!("服务端未签发用户会话（旧版本或 historical 配对码），保持「配对后需登录」");
            (false, None)
        }
    };

    Ok(StartPairingResponse {
        accepted: true,
        message: if signed_in {
            format!(
                "配对成功，已自动登录为 {}，执行引擎已启动",
                user_label.as_deref().unwrap_or("该账号")
            )
        } else {
            "配对成功，执行引擎已启动；请在 Web UI 登录后使用".to_string()
        },
        signed_in,
        user_label,
        // 交给 GUI 层：true = 本路径 CAS 抢到了守护权，必须 spawn supervise 任务。
        supervise: should_supervise,
    })
}

/// 平台标识（服务端用于展示与排障，不参与鉴权）。
fn platform_tag() -> &'static str {
    if cfg!(windows) {
        "windows-amd64"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// 端侧期望的协议版本（透出给前端做「客户端太旧」提示）。
pub fn protocol_version() -> i32 {
    CURRENT_PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::RunnerState;
    use crate::vault::MemoryVault;

    fn state() -> HostState {
        let vault = Arc::new(MemoryVault::new());
        let stats = Arc::new(RuntimeStats::default());
        HostState::new(vault, stats)
    }

    /// 🔴 防回归：`daemon()` 多次调用必须返回**同一个**实例。
    ///
    /// 这条守的是一个真实发生过的缺陷：启动编排与配对流程曾各自
    /// `Daemon::new()`，导致 is_running() 互不可见 → 重复 spawn →
    /// 同设备两条 WS → 服务端 replaced 互踢（用户看到「配对成功却立刻掉线」）。
    #[test]
    fn daemon_is_shared_across_callers() {
        let st = state();
        let a = st.daemon();
        let b = st.daemon();
        assert!(
            Arc::ptr_eq(&a, &b),
            "daemon() 返回了不同实例：会让启动编排与配对流程互相看不见运行状态"
        );
    }

    fn paired_state() -> HostState {
        let vault = Arc::new(MemoryVault::new());
        vault
            .set(&DeviceToken::new("hgd_testtoken123".to_string()))
            .unwrap();
        let stats = Arc::new(RuntimeStats::default());
        HostState::new(vault, stats)
    }

    #[test]
    fn list_commands_is_the_capability_anchor() {
        let r = list_commands();
        assert_eq!(r.shell_version, SHELL_VERSION);
        // 锚点必须永远在场：前端整个降级逻辑都依赖它。
        assert!(r.supported.contains(&"list_commands".to_string()));
        assert_eq!(r.supported.len(), SUPPORTED_COMMANDS.len());
    }

    #[test]
    fn supported_never_contains_forbidden_commands() {
        let r = list_commands();
        for bad in FORBIDDEN_COMMANDS {
            assert!(
                !r.supported.iter().any(|s| s == bad),
                "禁止实现的 command `{bad}` 不得出现在 supported 中"
            );
        }
    }

    #[test]
    fn supported_has_no_duplicates() {
        let mut seen = Vec::new();
        for c in SUPPORTED_COMMANDS {
            assert!(!seen.contains(&c), "supported 出现重复项：{c}");
            seen.push(c);
        }
    }

    #[test]
    fn check_update_reports_dev_channel_and_shell_version() {
        let r = check_update();
        assert_eq!(r.shell_version, SHELL_VERSION);
        assert_eq!(r.channel, "dev");
        // 当前无发布渠道，恒无更新可装；若未来接入发布清单，此断言随之更新。
        assert!(!r.update_available);
    }

    #[test]
    fn open_settings_event_name_is_stable() {
        assert_eq!(open_settings_event_name(), "hd://open-settings");
    }

    #[test]
    fn log_dir_lives_next_to_profile_root() {
        // 有系统配置目录时，日志目录必须与档案同根（harness_desktop/logs）；
        // 无配置目录（极简容器）时返回 None，绝不用临时目录冒充。
        if let Some(p) = log_dir() {
            assert!(p.ends_with("harness_desktop/logs"), "意外路径：{p:?}");
        }
    }

    #[test]
    fn web_ui_navigation_covers_all_paths() {
        // 穷举（见 plan_web_ui_navigation 文档表格）：
        // 配对成功免登录 / 启动自续成功 → 导航；未免登录、自续失败 → 留基线页。
        assert!(plan_web_ui_navigation(false, true), "配对成功免登录应导航");
        assert!(plan_web_ui_navigation(true, false), "自续成功（Replayed/Renewed）应导航");
        assert!(plan_web_ui_navigation(true, true), "双真恒导航");
        assert!(!plan_web_ui_navigation(false, false), "未登录且自续失败不导航（登录墙/白屏保护）");
    }

    #[test]
    fn open_web_ui_target_always_resolves() {
        // 目标地址永远可解析（档案缺失回退默认 127.0.0.1:5611）：
        // 未配对用户点「进入主界面」也应跳到服务端登录页，而不是报「未配对」。
        let t = open_web_ui_target().expect("目标地址不应为 None");
        assert!(t.starts_with("http"), "目标必须是 http(s) URL：{t}");
    }

    #[test]
    fn cookie_host_resolves_from_base_url() {
        // Cookie domain 必须取自配对档案地址本身（127.0.0.1 与 localhost 互不可见）。
        assert_eq!(
            cookie_host_for("http://127.0.0.1:5611").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            cookie_host_for("https://harness.example.com/api").as_deref(),
            Some("harness.example.com")
        );
    }

    #[test]
    fn cookie_host_rejects_bad_urls() {
        // 非 http(s) / 空主机 / 非法地址：一律 None（调用方跳过写入，不 panic）。
        assert_eq!(cookie_host_for("ftp://example.com"), None);
        assert_eq!(cookie_host_for("not a url"), None);
        assert_eq!(cookie_host_for(""), None);
    }

    #[test]
    fn secure_flag_follows_scheme() {
        assert!(base_url_is_secure("https://h.example.com"));
        assert!(!base_url_is_secure("http://127.0.0.1:5611"));
        assert!(!base_url_is_secure("garbage"), "非法地址按非 https 降级");
    }

    #[test]
    fn baseline_stage_matches_mobile_resolve_stage() {
        // 与移动端 resolveStage 判定链逐字对齐：未配对优先于未登录。
        use BaselineStage::*;
        assert_eq!(plan_baseline_stage(false, false), NeedsPairing);
        assert_eq!(plan_baseline_stage(false, true), NeedsPairing);
        assert_eq!(plan_baseline_stage(true, false), NeedsSignIn);
        assert_eq!(plan_baseline_stage(true, true), SignedIn);
    }

    #[test]
    fn device_status_reports_unpaired_initially() {
        let st = state();
        let r = device_status(&st);
        assert!(!r.paired);
        assert!(!r.online);
        assert!(r.device_id.is_none());
        assert!(r.protocol_ok, "未握手前不该报协议不通过");
        assert_eq!(r.app_version, SHELL_VERSION);
    }

    #[test]
    fn device_status_reflects_vault_and_never_exposes_token() {
        let st = paired_state();
        let r = device_status(&st);
        assert!(r.paired);
        // 🔴 序列化后的 JSON 里绝不能出现令牌子串（结构体本身没有 token 字段，
        // 这条断言防的是「以后有人顺手加了一个 token 字段」）。
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("hgd_testtoken123"),
            "device_status 泄露令牌：{json}"
        );
        assert!(
            !json.contains("token"),
            "device_status 不应含 token 相关字段：{json}"
        );
    }

    #[test]
    fn device_status_online_follows_runner_state_and_heartbeat() {
        let st = state();
        st.stats.set_state(RunnerState::Running);
        // 未收到心跳（0）但子进程在跑 → 视为在线。
        assert!(device_status(&st).online);

        // 心跳新鲜 → 在线。
        st.stats.mark_heartbeat();
        assert!(device_status(&st).online);

        // 心跳过旧 → 离线：这样才能反映「子进程还在但已经连不上服务端」。
        st.stats.last_heartbeat_ms.store(
            crate::daemon::now_ms() - HEARTBEAT_STALE_MS - 1,
            std::sync::atomic::Ordering::Relaxed,
        );
        assert!(!device_status(&st).online);

        // 子进程已退出 → 离线。
        st.stats.set_state(RunnerState::Stopped);
        assert!(!device_status(&st).online);
    }

    #[test]
    fn runner_status_maps_state_to_stable_strings() {
        let st = state();
        assert_eq!(runner_status(&st).state, "stopped");
        st.stats.set_state(RunnerState::Running);
        assert_eq!(runner_status(&st).state, "running");
        st.stats.set_state(RunnerState::Backoff);
        assert_eq!(runner_status(&st).state, "backoff");
        st.stats.set_state(RunnerState::GaveUp);
        assert_eq!(runner_status(&st).state, "gave_up");
        st.stats.set_state(RunnerState::ShuttingDown);
        assert_eq!(runner_status(&st).state, "shutting_down");
        assert_eq!(runner_status(&st).restarts, 0);
    }

    #[test]
    fn workspace_roots_start_empty_and_set_normalizes() {
        let st = state();
        assert!(get_workspace_roots(&st).is_empty());

        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().display().to_string();
        let got = set_workspace_roots(&st, vec![raw.clone()]).expect("设置应成功");
        assert_eq!(got.len(), 1);
        // 返回的必须是归一形态（Windows 下不能带 \\?\ 前缀）。
        assert!(
            !got[0].starts_with(r"\\?\"),
            "归一结果不应带扩展前缀：{}",
            got[0]
        );
        assert_eq!(get_workspace_roots(&st), got);
        // 策略同步更新，daemon 热更新读到的是同一份。
        assert_eq!(st.policy().roots().len(), 1);
    }

    #[test]
    fn set_workspace_roots_rejects_empty_and_bad_paths() {
        let st = state();
        assert!(matches!(
            set_workspace_roots(&st, vec![]),
            Err(CommandError::EmptyRoots)
        ));

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        // 文件不是目录 → 拒绝（避免「把文件当工作区根」导致 fs.list 行为怪异）。
        let err = set_workspace_roots(&st, vec![file.display().to_string()]);
        assert!(matches!(err, Err(CommandError::NotADirectory(_))));

        let missing = dir.path().join("nope");
        assert!(matches!(
            set_workspace_roots(&st, vec![missing.display().to_string()]),
            Err(CommandError::NotADirectory(_))
        ));
        // 失败不改变既有配置（不留下半套策略）。
        assert!(get_workspace_roots(&st).is_empty());
    }

    #[test]
    fn set_workspace_roots_rejects_dotdot_traversal_like_input() {
        let st = state();
        let dir = tempfile::tempdir().unwrap();
        let traversal = format!(
            "{}{}..{}..",
            dir.path().display(),
            std::path::MAIN_SEPARATOR,
            std::path::MAIN_SEPARATOR
        );
        // canonicalize 会把 `..` 抹平，因此这里能通过；真正的穿越拒绝在 hd-core 三闸里。
        // 本测试说明的是「宿主侧不做路径安全判定」，判定权集中在 Guarded，避免两处漂移。
        let _ = set_workspace_roots(&st, vec![traversal]);
    }

    #[test]
    fn start_pairing_validates_and_queues() {
        let st = state();
        // 小写/过短/含符号 → 拒绝
        assert!(matches!(
            start_pairing(&st, "abc", "我的电脑"),
            Err(CommandError::BadPairCode)
        ));
        assert!(matches!(
            start_pairing(&st, "ABCDEFG!", "我的电脑"),
            Err(CommandError::BadPairCode)
        ));
        assert!(matches!(
            start_pairing(&st, "ABCDEF", "   "),
            Err(CommandError::EmptyDeviceName)
        ));
        assert!(st.pending_pairing().is_none());

        let r = start_pairing(&st, " AB12CD ", " 我的电脑 ").expect("合法配对码应受理");
        assert!(r.accepted);
        let p = st.pending_pairing().expect("应已排队");
        assert_eq!(p.code, "AB12CD");
        assert_eq!(p.name, "我的电脑");
    }

    #[test]
    fn protocol_version_matches_protocol_crate() {
        assert_eq!(protocol_version(), CURRENT_PROTOCOL_VERSION);
    }

    // ===== P3：工作区白名单必须真正下发到 Runner =====

    /// 「Runner 未运行」必须落在三态里的**中间态**（pushed=false + warning），
    /// 而不是 `Err`；若实现退回成只写 HostState，这里会拿到 pushed=true，测试失败。
    ///
    /// 为什么那条 `Err` 不能再被期望：`Err` 穿过 IPC 会被 Tauri 转成 promise reject，
    /// 前端 `tauriBridge.call()` 按铁律归一成 `null` → 界面只能说「命令未成功」，
    /// 与「配置其实已保存」直接矛盾。这条用例钉住的就是这个契约。
    #[tokio::test]
    async fn push_path_actually_attempts_to_reach_runner() {
        let st = state();
        let dir = tempfile::tempdir().unwrap();
        let got = set_workspace_roots_and_push(&st, vec![dir.path().display().to_string()])
            .await
            .expect("Runner 未运行时下发应被视为合法分支（配置仍生效于下次启动）");
        assert_eq!(got.roots.len(), 1, "归一结果应被返回");
        assert!(
            !got.pushed,
            "本次 daemon 无子进程，不可能真的下发成功 → pushed 必须为 false"
        );
        assert!(
            got.warning.as_deref().is_some_and(|w| !w.trim().is_empty()),
            "未下发必须带人话 warning，否则前端只能显示「已执行」而误导用户"
        );
        // 宿主侧状态已更新（先落状态、再下发的顺序保证）
        assert_eq!(get_workspace_roots(&st), got.roots);

        // 证明「确实调过 daemon」而不是只写内存：
        // daemon 当前没有子进程，`send_line` 必然返回 `WriteAuth`；
        // 上面的 `expect` 之所以没失败，正因为实现识别了该错误并当作合法分支。
        // 换言之，若实现退回成「只写 HostState、不碰 daemon」，
        // 这条测试依然通过 —— 因此真正的接线证明放在 daemon_e2e 的真子进程用例里
        // （见 `push_workspace_roots_reaches_fake_runner`）。
        assert!(
            !st.daemon().is_running().await,
            "本用例假定 daemon 未运行，否则走的是真实下发分支"
        );
    }

    /// 下拉路径必须把**归一后**的策略下发，而不是调用方传进来的原始字符串。
    ///
    /// 若下发了原始值，Runner 侧会按含 `\\?\` 前缀或未解软链的形态判断归属，
    /// 出现「宿主认为在根内、Runner 认为越界」的错位。
    #[tokio::test]
    async fn push_path_sends_normalized_policy() {
        let st = state();
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().display().to_string();
        let _ = set_workspace_roots_and_push(&st, vec![raw.clone()]).await;

        // 宿主记录的 policy 已归一（不带扩展前缀），下发用的就是这一份。
        let roots: Vec<String> = st
            .policy()
            .roots()
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(roots.len(), 1);
        assert!(
            !roots[0].starts_with(r"\\?\"),
            "下发用的策略必须是归一形态：{}",
            roots[0]
        );
    }

    /// 空列表必须在**校验阶段**就被拒绝，不应走到下发（避免把空白名单推给 Runner）。
    ///
    /// 校验类错误才是**真失败**：配置根本没保存，必须冒泡成 `Err`，不能混进三态中间档。
    #[tokio::test]
    async fn push_path_rejects_empty_before_any_push() {
        let st = state();
        let err = set_workspace_roots_and_push(&st, Vec::new())
            .await
            .expect_err("空白名单必须拒绝");
        assert!(matches!(err, CommandError::EmptyRoots), "实际 {err:?}");
        assert!(
            get_workspace_roots(&st).is_empty(),
            "校验失败不应改动宿主状态"
        );
    }

    /// 校验类错误（不是目录）同样必须保持 `Err`：这条钉住「三态化没有把真错误也吞掉」。
    #[tokio::test]
    async fn push_path_keeps_validation_errors_as_err() {
        let st = state();
        let dir = tempfile::tempdir().unwrap();
        let not_a_dir = dir.path().join("a.txt");
        std::fs::write(&not_a_dir, b"x").unwrap();

        let err = set_workspace_roots_and_push(&st, vec![not_a_dir.display().to_string()])
            .await
            .expect_err("非目录必须报错，不能被降级成「已保存但未下发」");
        assert!(
            matches!(err, CommandError::NotADirectory(_)),
            "实际 {err:?}"
        );
        assert!(
            get_workspace_roots(&st).is_empty(),
            "校验失败不该留下半套配置"
        );
    }

    // ===== P3 三态：pushed 判定的穷举覆盖 =====

    /// 三态判定（`classify_push_outcome`）的穷举单测。
    ///
    /// 为什么必须穷举而不是只测端到端：端到端只能制造出「Runner 未运行」这一种失败
    /// （`send_line` 在无子进程时永远回 `WriteAuth`），「真下发失败（管道坏）」这条
    /// 分支在单测环境里造不出来。判定的三个分支必须逐个钉死，否则「已保存但未下发」
    /// 很容易被后续改动悄悄退回 `Err`，前端又变回「命令未成功」。
    #[test]
    fn classify_push_outcome_covers_all_three_states() {
        use crate::daemon::DaemonError;

        let roots = vec!["C:\\ws".to_string()];

        // ① 真下发成功 → Ok(pushed=true, warning=None)
        let ok = classify_push_outcome(roots.clone(), &Ok(()));
        assert!(ok.pushed, "下发成功必须 pushed=true");
        assert!(
            ok.warning.is_none(),
            "成功时不得带 warning，否则前端会白白显示黄字"
        );
        assert_eq!(ok.roots, roots, "归一结果必须原样带回给前端刷面包屑");

        // ② Runner 未运行 → 预期分支，仍是 pushed=false + 人话 warning
        let not_running = classify_push_outcome(
            roots.clone(),
            &Err(DaemonError::WriteAuth("Runner 未运行".to_string())),
        );
        assert!(
            !not_running.pushed,
            "Runner 未运行等于没下发成功，pushed 必须为 false"
        );
        let w = not_running.warning.as_deref().unwrap_or_default();
        assert!(!w.is_empty(), "未下发必须给 warning");
        assert!(
            w.contains("配置已保存") || w.contains("已保存"),
            "warning 必须说清「配置没丢」，实际：{w}"
        );

        // ③ 真下发失败 → 同样 pushed=false，但 warning 要带出原因与恢复动作。
        //    ⚠️ 这里用非 `WriteAuth` 变体：`is_runner_not_running` 按变体判定，所有
        //    `WriteAuth` 都算「Runner 未运行」这一预期分支（见其文档），因此「真失败」
        //    只能用其它 daemon 错误模拟（写管道异常/拉起异常在本层同属 daemon 错误）。
        let broken = classify_push_outcome(
            roots.clone(),
            &Err(DaemonError::Spawn("写入管道 BrokenPipe".to_string())),
        );
        assert!(!broken.pushed, "写失败同样属于未下发");
        let w = broken.warning.as_deref().unwrap_or_default();
        assert!(
            w.contains("BrokenPipe"),
            "真失败必须把底层原因带给用户，实际：{w}"
        );
        assert!(
            w.contains("重试") || w.contains("重启"),
            "真失败要给出恢复动作，实际：{w}"
        );
        assert!(
            w.contains("已保存"),
            "这句话的语义是「配置保住了」，不能说成「没保存」，实际：{w}"
        );

        // 三个分支的 roots 都不该空（否则前端面包屑会被清空）
        for (name, r) in [
            ("ok", &ok),
            ("not_running", &not_running),
            ("broken", &broken),
        ] {
            assert_eq!(r.roots, roots, "{name} 分支丢了归一结果");
        }
    }

    /// `WorkspaceRootsResult` 的序列化形态必须是 `{ roots, pushed, warning }` ——
    /// 前端 `tauriBridge` 的 ReturnType 就按这个形状取值，字段名改动等于破约。
    #[test]
    fn workspace_roots_result_serializes_with_expected_keys() {
        let ok = WorkspaceRootsResult {
            roots: vec!["C:\\ws".to_string()],
            pushed: true,
            warning: None,
        };
        let v = serde_json::to_value(&ok).expect("必须可序列化");
        assert_eq!(v["roots"][0], "C:\\ws");
        assert_eq!(v["pushed"], true);
        assert!(
            v["warning"].is_null(),
            "None 必须序列化为 null 而不是被省略"
        );

        let degraded = WorkspaceRootsResult {
            roots: vec![],
            pushed: false,
            warning: Some("已保存但未下发".to_string()),
        };
        let v = serde_json::to_value(&degraded).expect("必须可序列化");
        assert_eq!(v["pushed"], false);
        assert_eq!(v["warning"], "已保存但未下发");
        assert!(v["roots"].is_array());
    }

    // ===== P6：解约闭环 =====

    /// 解除配对后：令牌被清、设备信息被清、相位切到「需要配对」。
    ///
    /// 这条钉住"只有主动解约才需重配对"的客户端半边 —— 改造前 `vault.clear()`
    /// 在整个 hd-host 里**零调用点**，用户没有自助解绑入口。
    #[tokio::test]
    async fn unpair_clears_token_and_switches_to_needs_pairing() {
        let st = state();
        // 先制造「已配对」状态。
        st.vault
            .set(&DeviceToken::new("hgd_to_be_cleared".into()))
            .expect("写令牌");
        *st.device_id.write().unwrap() = Some("dev-123".to_string());
        st.stats.set_state(RunnerState::Running);
        assert!(device_status(&st).paired, "前置条件：应处于已配对");

        unpair_device(&st).await.expect("解约应成功");

        assert!(!device_status(&st).paired, "解约后必须变为未配对");
        assert!(
            st.vault.get().expect("读 vault").is_none(),
            "令牌必须被真正清除，否则服务端仍认这台设备"
        );
        assert!(
            st.device_id.read().unwrap().is_none(),
            "设备 ID 必须清空，否则 UI 继续显示旧设备"
        );
        assert_eq!(
            st.stats.state(),
            RunnerState::NeedsPairing,
            "相位应切到需要配对，让 UI 直接给配对引导"
        );
    }

    /// 解约必须**先停 Runner**：否则 Runner 会握着已失效令牌继续重连。
    #[tokio::test]
    async fn unpair_stops_runner_first() {
        let st = state();
        st.vault
            .set(&DeviceToken::new("hgd_x".into()))
            .expect("写令牌");
        unpair_device(&st).await.expect("解约应成功");
        assert!(
            !st.daemon().is_running().await,
            "解约后 Runner 不应仍在运行"
        );
    }

    /// 未配对状态下调用解约应幂等成功（用户重复点击按钮是常见操作）。
    #[tokio::test]
    async fn unpair_is_idempotent_when_already_unpaired() {
        let st = state();
        assert!(!device_status(&st).paired);
        unpair_device(&st).await.expect("重复解约不应报错");
        unpair_device(&st).await.expect("再次解约仍不应报错");
        assert!(!device_status(&st).paired);
    }

    /* ============ 启动会话自续（三段式） ============ */

    /// 内存 Cookie 通道：记录最后一次写入/清除，用于断言「到底写没写 Cookie」。
    #[derive(Default)]
    struct RecordingSink {
        set: Mutex<Vec<String>>,
        cleared: Mutex<u32>,
    }

    impl RecordingSink {
        fn set_count(&self) -> usize {
            self.set.lock().unwrap().len()
        }
        fn clear_count(&self) -> u32 {
            *self.cleared.lock().unwrap()
        }
        fn last_set(&self) -> Option<String> {
            self.set.lock().unwrap().last().cloned()
        }
    }

    impl SessionCookieSink for RecordingSink {
        fn set_session_cookie(&self, _base_url: &str, token: &UserToken) -> Result<(), String> {
            // 记录写入值便于断言「写进去的是新换到的令牌」。
            self.set.lock().unwrap().push(token.expose().to_string());
            Ok(())
        }
        fn clear_session_cookie(&self, _base_url: &str) -> Result<(), String> {
            *self.cleared.lock().unwrap() += 1;
            Ok(())
        }
    }

    /// 内存续期网关：校验结论与续期结果都由用例指定，不触网。
    struct StubGateway {
        verify: SessionVerify,
        /// 🔴 用 `Mutex<Option<_>>` 而不是 `Option<_>`：`SessionGrant` 刻意不实现
        /// `Clone`（内含 zeroize 令牌，克隆会多一份明文），故只能 `take` 一次。
        renew: Mutex<Option<Result<crate::pairing::SessionGrant, crate::pairing::PairingError>>>,
        /// 续期被调用了几次（断言"有效时不续期"）。
        renew_calls: Mutex<u32>,
    }

    impl StubGateway {
        fn new(
            verify: SessionVerify,
            renew: Option<Result<crate::pairing::SessionGrant, crate::pairing::PairingError>>,
        ) -> Self {
            Self {
                verify,
                renew: Mutex::new(renew),
                renew_calls: Mutex::new(0),
            }
        }
        fn renew_calls(&self) -> u32 {
            *self.renew_calls.lock().unwrap()
        }
    }

    impl SessionRenewGateway for StubGateway {
        fn verify_user_token<'a>(
            &'a self,
            _base_url: &'a str,
            _token: &'a UserToken,
        ) -> BoxFuture<'a, SessionVerify> {
            Box::pin(async move { self.verify })
        }
        fn renew_session<'a>(
            &'a self,
            _base_url: &'a str,
            _token: &'a DeviceToken,
        ) -> BoxFuture<'a, Result<crate::pairing::SessionGrant, crate::pairing::PairingError>>
        {
            *self.renew_calls.lock().unwrap() += 1;
            // 锁不跨 await：先 take 出 owned 值再交给 future。
            let configured = self.renew.lock().unwrap().take();
            Box::pin(async move {
                // 每个用例都会给出 renew 结果；未给则说明用例设计有误，用明确错误代替 panic。
                configured.unwrap_or_else(|| {
                    Err(crate::pairing::PairingError::BadResponse(
                        "用例未配置续期结果".into(),
                    ))
                })
            })
        }
    }

    fn grant_with(token: &str, label: &str) -> crate::pairing::SessionGrant {
        crate::pairing::parse_session_grant(
            Some(token.to_string()),
            Some(crate::pairing::PairedUser {
                display_name: label.to_string(),
                ..Default::default()
            }),
            Some(604800),
        )
        .expect("构造 grant")
    }

    /// 造一个「已配对 + 已登录」的状态，并挂上可观测 Cookie 通道。
    fn signed_in_state(user_token: &str) -> (HostState, Arc<RecordingSink>) {
        let vault = Arc::new(MemoryVault::new());
        vault
            .set(&DeviceToken::new("hgd_device_long_lived".into()))
            .expect("写设备令牌");
        let st = HostState::new(vault, Arc::new(RuntimeStats::default()));
        st.user_vault_ref()
            .set_user_token(&UserToken::new(user_token.to_string()))
            .expect("写用户令牌");
        let sink = Arc::new(RecordingSink::default());
        st.set_cookie_sink(sink.clone());
        (st, sink)
    }

    /// ① vault 里根本没有会话 → 不校验、不续期、不写 Cookie。
    #[tokio::test]
    async fn reinject_no_session_is_a_noop() {
        let st = state();
        let sink = Arc::new(RecordingSink::default());
        st.set_cookie_sink(sink.clone());
        let gw = StubGateway::new(SessionVerify::Valid, None);

        let out = reinject_session_cookie_with(&st, "http://x", &gw).await;
        assert_eq!(out, ReinjectOutcome::NoSession);
        assert_eq!(sink.set_count(), 0, "无会话时不得写 Cookie");
        assert_eq!(gw.renew_calls(), 0, "无会话时不得触发续期");
        assert!(!out.page_should_reload(), "什么都没变，不该刷新页面");
    }

    /// ② 会话有效 → 直接重放（保持改造前行为），且**不**触发续期。
    #[tokio::test]
    async fn reinject_valid_session_replays_without_renewing() {
        let (st, sink) = signed_in_state("hgt_still_valid");
        let gw = StubGateway::new(SessionVerify::Valid, None);

        let out = reinject_session_cookie_with(&st, "http://x", &gw).await;
        assert_eq!(out, ReinjectOutcome::Replayed);
        assert_eq!(sink.set_count(), 1, "有效会话应重放一次 Cookie");
        assert_eq!(sink.last_set().as_deref(), Some("hgt_still_valid"));
        assert_eq!(sink.clear_count(), 0, "有效期不该清 Cookie");
        assert_eq!(gw.renew_calls(), 0, "有效期绝不该出网续期");
        assert!(st.signed_in(), "登录态保持");
        assert!(!out.page_should_reload(), "同一份 Cookie，不必刷新");
        assert_eq!(device_status(&st).session_invalid, None);
    }

    /// ③ 会话失效 + 续期成功 → 落新会话、写新 Cookie、**设备令牌不动**。
    #[tokio::test]
    async fn reinject_invalid_session_renews_and_persists() {
        let (st, sink) = signed_in_state("hgt_expired");
        let gw = StubGateway::new(
            SessionVerify::Invalid,
            Some(Ok(grant_with("hgt_brand_new", "爱丽丝"))),
        );

        let out = reinject_session_cookie_with(&st, "http://x", &gw).await;
        assert_eq!(out, ReinjectOutcome::Renewed);
        assert_eq!(gw.renew_calls(), 1, "失效时应用设备令牌续期一次");
        assert_eq!(
            sink.last_set().as_deref(),
            Some("hgt_brand_new"),
            "写进 Cookie 的必须是新换到的令牌"
        );
        assert_eq!(
            st.user_token().expect("读会话").map(|t| t.expose().to_string()),
            Some("hgt_brand_new".to_string()),
            "vault 里必须换成新会话"
        );
        assert!(st.signed_in(), "续期成功后应处于登录态");
        assert_eq!(st.user_label().as_deref(), Some("爱丽丝"));
        assert_eq!(device_status(&st).session_invalid, None);
        assert!(
            st.device_token().expect("读设备令牌").is_some(),
            "续期绝不该影响设备绑定"
        );
        assert!(out.page_should_reload(), "换到新会话后需要刷新页面生效");
    }

    /// ④ 会话失效 + 续期失败（owner_unknown）→ 清会话、清 Cookie、
    ///    **保留设备令牌**、`signed_in` 自然变 false。
    #[tokio::test]
    async fn reinject_renew_failure_clears_session_but_keeps_device() {
        let (st, sink) = signed_in_state("hgt_expired");
        let gw = StubGateway::new(
            SessionVerify::Invalid,
            Some(Err(crate::pairing::PairingError::Rejected {
                code: "device.owner_unknown".into(),
                message: "设备归属账号未知".into(),
            })),
        );

        let out = reinject_session_cookie_with(&st, "http://x", &gw).await;
        assert_eq!(out, ReinjectOutcome::Cleared(SessionFault::OwnerUnknown));
        assert_eq!(sink.set_count(), 0, "续期失败时绝不能把旧令牌写进 Cookie");
        assert_eq!(sink.clear_count(), 1, "应清掉可能残留的 hg_sess");
        assert!(st.user_token().expect("读会话").is_none(), "失效会话必须清空");
        assert!(!st.signed_in(), "③ 之后 signed_in 应自然变 false");
        assert!(
            st.device_token().expect("读设备令牌").is_some(),
            "🔴 续期失败不得清设备令牌：设备绑定仍然有效"
        );
        assert_eq!(
            device_status(&st).session_invalid.as_deref(),
            Some("owner_unknown"),
            "界面需要可解释原因"
        );
        assert!(out.page_should_reload(), "会话被清空后要刷新回可登录页");
    }

    /// ⑤ 校验时网络不可达（不确定）→ 仍走续期（这是唯一自愈路径）。
    #[tokio::test]
    async fn reinject_unreachable_verify_still_tries_renew() {
        let (st, sink) = signed_in_state("hgt_unknown_state");
        let gw = StubGateway::new(
            SessionVerify::Unreachable,
            Some(Ok(grant_with("hgt_recovered", "鲍勃"))),
        );

        let out = reinject_session_cookie_with(&st, "http://x", &gw).await;
        assert_eq!(out, ReinjectOutcome::Renewed);
        assert_eq!(gw.renew_calls(), 1);
        assert_eq!(sink.last_set().as_deref(), Some("hgt_recovered"));
    }

    /// ⑥ 吊销：续期 401 → 清会话，原因为 revoked（提示重新配对）。
    #[tokio::test]
    async fn reinject_revoked_device_clears_with_revoked_fault() {
        let (st, _sink) = signed_in_state("hgt_expired");
        let gw = StubGateway::new(
            SessionVerify::Invalid,
            Some(Err(crate::pairing::PairingError::Rejected {
                code: "device.token_revoked".into(),
                message: "设备令牌已吊销".into(),
            })),
        );
        let out = reinject_session_cookie_with(&st, "http://x", &gw).await;
        assert_eq!(out, ReinjectOutcome::Cleared(SessionFault::Revoked));
        assert_eq!(
            device_status(&st).session_invalid.as_deref(),
            Some("revoked")
        );
    }

    /// ⑦ 没有设备令牌（仅剩会话）→ 无法续期，清会话；不得凭空造绑定。
    #[tokio::test]
    async fn reinject_without_device_token_clears_session() {
        let st = state(); // 无设备令牌
        st.user_vault_ref()
            .set_user_token(&UserToken::new("hgt_orphan".into()))
            .expect("写会话");
        let sink = Arc::new(RecordingSink::default());
        st.set_cookie_sink(sink.clone());
        // 网关给 Invalid，但续期不该被调用（本地无设备令牌）。
        let gw = StubGateway::new(SessionVerify::Invalid, None);

        let out = reinject_session_cookie_with(&st, "http://x", &gw).await;
        assert_eq!(out, ReinjectOutcome::Cleared(SessionFault::Expired));
        assert_eq!(gw.renew_calls(), 0, "无设备令牌时不该出网");
        assert!(!st.signed_in());
        assert_eq!(sink.set_count(), 0);
    }

    /* ---------- 纯函数：决策与映射 ---------- */

    #[test]
    fn plan_reinject_step_covers_all_verifications() {
        assert_eq!(plan_reinject_step(None), ReinjectStep::NoSession);
        assert_eq!(
            plan_reinject_step(Some(SessionVerify::Valid)),
            ReinjectStep::Replay
        );
        assert_eq!(
            plan_reinject_step(Some(SessionVerify::Invalid)),
            ReinjectStep::Renew
        );
        assert_eq!(
            plan_reinject_step(Some(SessionVerify::Unreachable)),
            ReinjectStep::Renew,
            "请求失败也必须续期：那是唯一能自愈的路径"
        );
    }

    #[test]
    fn session_fault_maps_server_error_codes() {
        assert_eq!(
            SessionFault::from_error_code("device.owner_unknown"),
            SessionFault::OwnerUnknown
        );
        assert_eq!(
            SessionFault::from_error_code("device.token_revoked"),
            SessionFault::Revoked
        );
        assert_eq!(
            SessionFault::from_error_code("unauthorized"),
            SessionFault::Expired
        );
        // 大小写与未知码都必须安全落位。
        assert_eq!(
            SessionFault::from_error_code("DEVICE.OWNER_UNKNOWN"),
            SessionFault::OwnerUnknown
        );
        assert_eq!(
            SessionFault::from_error_code("something_else"),
            SessionFault::Unknown
        );
    }

    #[test]
    fn renew_failure_fault_covers_all_error_kinds() {
        use crate::pairing::PairingError;
        assert_eq!(
            renew_failure_fault(&PairingError::Http("connect timeout".into())),
            SessionFault::Network
        );
        assert_eq!(
            renew_failure_fault(&PairingError::BadResponse("无 user_token".into())),
            SessionFault::Unknown
        );
        assert_eq!(
            renew_failure_fault(&PairingError::Rejected {
                code: "device.owner_unknown".into(),
                message: String::new(),
            }),
            SessionFault::OwnerUnknown
        );
    }

    /// 失效原因短串是**对外契约**（前端按它选文案），改名会静默丢文案。
    #[test]
    fn session_fault_strings_are_stable() {
        assert_eq!(SessionFault::Expired.as_str(), "expired");
        assert_eq!(SessionFault::Revoked.as_str(), "revoked");
        assert_eq!(SessionFault::OwnerUnknown.as_str(), "owner_unknown");
        assert_eq!(SessionFault::Network.as_str(), "network");
        assert_eq!(SessionFault::Unknown.as_str(), "unknown");
    }

    /// `device_status` 的序列化必须带 `session_invalid` 键（前端按可选字段解析）。
    #[test]
    fn device_status_serializes_session_invalid() {
        let st = state();
        st.set_session_invalid(Some(SessionFault::Expired));
        let v = serde_json::to_value(device_status(&st)).expect("可序列化");
        // 未登录（无会话）时该字段应出现且为 expired。
        assert_eq!(v["signed_in"], false);
        assert_eq!(v["session_invalid"], "expired");

        // 登录成功后该字段必须消失（残留会让界面误报"请重新配对"）。
        st.user_vault_ref()
            .set_user_token(&UserToken::new("hgt_ok".into()))
            .expect("写会话");
        let v = serde_json::to_value(device_status(&st)).expect("可序列化");
        assert!(v["session_invalid"].is_null());
    }

    /// 主动登出不是"失效"：不得留下失效标记，否则界面会提示会话过期。
    #[test]
    fn sign_out_clears_session_invalid_marker() {
        let (st, _sink) = signed_in_state("hgt_x");
        st.set_session_invalid(Some(SessionFault::Revoked));
        sign_out(&st, "http://x").expect("登出应成功");
        assert!(!st.signed_in());
        assert_eq!(st.session_invalid(), None);
        assert_eq!(device_status(&st).session_invalid, None);
    }

    /* ============ 解绑双向收敛（本轮修复） ============ */

    /// 记录「是否被叫过」的解绑网关桩（成功 / 失败两种）。
    struct StubUnpairGateway {
        calls: Mutex<u32>,
        fail: bool,
    }

    impl StubUnpairGateway {
        fn ok() -> Self {
            Self {
                calls: Mutex::new(0),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                calls: Mutex::new(0),
                fail: true,
            }
        }
        fn calls(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }

    impl DeviceUnpairGateway for StubUnpairGateway {
        fn unpair_self<'a>(
            &'a self,
            _base_url: &'a str,
            _token: &'a DeviceToken,
        ) -> BoxFuture<'a, Result<(), crate::pairing::PairingError>> {
            *self.calls.lock().unwrap() += 1;
            let fail = self.fail;
            Box::pin(async move {
                if fail {
                    Err(crate::pairing::PairingError::Http("connect refused".into()))
                } else {
                    Ok(())
                }
            })
        }
    }

    /// ① 解绑必须**先通知服务端**（本轮 bug①：原实现零 HTTP 调用）。
    #[tokio::test]
    async fn unpair_notifies_server_before_clearing_credentials() {
        let st = state();
        st.vault
            .set(&DeviceToken::new("hgd_notify_me".into()))
            .expect("写令牌");
        let gw = StubUnpairGateway::ok();

        let r = unpair_device_with(&st, &gw).await.expect("解绑应成功");

        assert_eq!(gw.calls(), 1, "必须调用一次服务端解绑端点（原实现完全没调）");
        assert!(r.server_unpaired, "服务端已确认时必须如实回报");
        assert!(r.warning.is_none(), "成功时不得带 warning，否则前端白打黄字");
        assert!(!device_status(&st).paired, "本地凭据必须已清");
        assert_eq!(st.stats.state(), RunnerState::NeedsPairing);
    }

    /// ② 服务端失败**不阻断**本地解绑，但要给出可读 warning。
    #[tokio::test]
    async fn unpair_survives_server_failure_with_readable_warning() {
        let st = state();
        st.vault
            .set(&DeviceToken::new("hgd_x".into()))
            .expect("写令牌");
        let gw = StubUnpairGateway::failing();

        let r = unpair_device_with(&st, &gw)
            .await
            .expect("服务端失败不得让解绑整体失败");

        assert_eq!(gw.calls(), 1, "失败也要尝试过一次");
        assert!(!r.server_unpaired);
        let w = r.warning.as_deref().unwrap_or_default();
        assert!(w.contains("本机已解除配对"), "必须说清本地已生效：{w}");
        assert!(w.contains("服务端"), "必须点明服务端可能没同步：{w}");
        // 本地状态仍必须彻底清空（目标已达成）。
        assert!(!device_status(&st).paired);
        assert!(!st.signed_in());
        assert_eq!(st.stats.state(), RunnerState::NeedsPairing);
        assert_eq!(st.session_invalid(), None, "主动解绑不是失效");
    }

    /// ③ 未配对时解绑：不打扰服务端，也不报错（幂等）。
    #[tokio::test]
    async fn unpair_without_token_skips_server_call() {
        let st = state();
        let gw = StubUnpairGateway::ok();
        let r = unpair_device_with(&st, &gw).await.expect("未配对解绑应成功");
        assert_eq!(gw.calls(), 0, "没有令牌就无从鉴权，不该出网");
        assert!(!r.server_unpaired);
        assert!(r.warning.is_none(), "未配对不是异常，不该给 warning");
    }

    /// ④ `UnpairResult` 序列化形状是前端契约（`server_unpaired` / `warning`）。
    #[test]
    fn unpair_result_serializes_with_expected_keys() {
        let ok = UnpairResult {
            server_unpaired: true,
            warning: None,
        };
        let v = serde_json::to_value(&ok).expect("可序列化");
        assert_eq!(v["server_unpaired"], true);
        assert!(v["warning"].is_null());

        let degraded = UnpairResult {
            server_unpaired: false,
            warning: Some("w".to_string()),
        };
        let v = serde_json::to_value(&degraded).expect("可序列化");
        assert_eq!(v["server_unpaired"], false);
        assert_eq!(v["warning"], "w");
    }

    /// ⑤ 纯判据穷举：`classify_unpair_notice` 必须把三种情形分得清。
    #[test]
    fn classify_unpair_notice_covers_all_cases() {
        assert_eq!(
            classify_unpair_notice(false, Ok(())),
            ServerUnpairOutcome::NoToken,
            "无令牌优先于调用结果：此时压根没出网"
        );
        assert_eq!(
            classify_unpair_notice(true, Ok(())),
            ServerUnpairOutcome::Confirmed
        );
        let failed = classify_unpair_notice(
            true,
            Err(crate::pairing::PairingError::Http("timeout".into())),
        );
        match failed {
            ServerUnpairOutcome::Failed(detail) => assert!(
                detail.contains("timeout"),
                "失败明细必须带给用户（便于支持排查）：{detail}"
            ),
            other => panic!("应归一为 Failed，实际：{other:?}"),
        }
    }

    /// ⑥ `plan_unpair_warning`：只有失败才给文案，且文案必须两种信息齐全。
    #[test]
    fn plan_unpair_warning_only_warns_on_failure() {
        assert_eq!(plan_unpair_warning(&ServerUnpairOutcome::NoToken), None);
        assert_eq!(plan_unpair_warning(&ServerUnpairOutcome::Confirmed), None);
        let w = plan_unpair_warning(&ServerUnpairOutcome::Failed("boom".into()))
            .expect("失败必须给 warning");
        assert!(w.contains("boom"), "必须带上底层原因：{w}");
        assert!(w.contains("服务端"), "必须提示服务端状态未知：{w}");
    }

    /// ⑦ 纯判据穷举：终止帧收敛决策。
    #[test]
    fn plan_revoked_convergence_is_exhaustive() {
        use hd_protocol::exit_code;
        // 服务端推了终止帧 → 一定收敛（不论退出码是什么）。
        assert_eq!(
            plan_revoked_convergence(None, Some("device.revoked")),
            RevokedConvergence::ResetToPairing
        );
        assert_eq!(
            plan_revoked_convergence(Some(exit_code::EXIT_REVOKED as i32), Some("device.revoked")),
            RevokedConvergence::ResetToPairing
        );
        // 没有帧、只有专用退出码 → 也收敛（守护循环只能看到退出码）。
        assert_eq!(
            plan_revoked_convergence(Some(exit_code::EXIT_REVOKED as i32), None),
            RevokedConvergence::ResetToPairing
        );
        // 本地配置问题 / 可重试 / 正常退出 → 一律不收敛（交给既有重连逻辑）。
        for code in [
            exit_code::EXIT_NO_AUTH,
            exit_code::EXIT_RETRYABLE,
            exit_code::EXIT_OK,
            exit_code::EXIT_GENERIC_FAILURE,
            exit_code::EXIT_REPLACED,
            exit_code::EXIT_PROTOCOL_MISMATCH,
        ] {
            assert_eq!(
                plan_revoked_convergence(Some(code as i32), None),
                RevokedConvergence::Ignore,
                "退出码 {code} 不该被误判成服务端解绑"
            );
        }
        assert_eq!(
            plan_revoked_convergence(None, None),
            RevokedConvergence::Ignore
        );
        assert_eq!(
            plan_revoked_convergence(None, Some("device.disabled")),
            RevokedConvergence::Ignore,
            "只有 revoked / unpair 类帧才算解绑"
        );
    }

    /// ⑧ 失效原因必须区分「服务端解绑」与「笼统吊销」。
    #[test]
    fn revoked_fault_distinguishes_server_unpair() {
        use hd_protocol::exit_code;
        assert_eq!(
            revoked_fault(Some(exit_code::EXIT_REVOKED as i32), None),
            SessionFault::ServerUnpaired,
            "EXIT_REVOKED 只由 device.revoked 产生，属服务端解绑"
        );
        assert_eq!(
            revoked_fault(None, Some("device.revoked")),
            SessionFault::ServerUnpaired
        );
        assert_eq!(
            revoked_fault(Some(exit_code::EXIT_NO_AUTH as i32), None),
            SessionFault::Revoked,
            "没有帧信息时不得断言是服务端解绑"
        );
    }

    /// ⑨ 收敛必须清「全部」凭据并回 NeedsPairing（bug② 的终态）。
    #[tokio::test]
    async fn handle_terminal_revoked_clears_everything_and_goes_needs_pairing() {
        let (st, sink) = signed_in_state("hgt_session");
        st.vault
            .set(&DeviceToken::new("hgd_device".into()))
            .expect("写设备令牌");
        st.set_user_label(Some("alice".into()));
        st.stats.set_state(RunnerState::Running);
        assert!(device_status(&st).paired, "前置：应已配对");

        let converged = handle_terminal_revoked(&st, Some(4), Some("device.revoked"));
        assert!(converged, "terminal revoked 必须收敛");

        assert!(!device_status(&st).paired, "设备令牌必须清掉");
        assert!(!st.signed_in(), "用户会话令牌必须清掉");
        assert!(sink.clear_count() >= 1, "hg_sess Cookie 必须清掉");
        assert_eq!(st.stats.state(), RunnerState::NeedsPairing);
        assert_eq!(
            st.session_invalid(),
            Some(SessionFault::ServerUnpaired),
            "必须让界面能说清「服务端已解除本设备绑定」"
        );
        assert_eq!(st.user_label(), None);
        assert!(st.device_id.read().unwrap().is_none());
    }

    /// ⑩ 非终态退出不得触发收敛（否则网络抖动就会把用户踢回配对）。
    #[tokio::test]
    async fn handle_terminal_revoked_ignores_recoverable_exits() {
        let (st, _sink) = signed_in_state("hgt_keep");
        st.vault
            .set(&DeviceToken::new("hgd_keep".into()))
            .expect("写设备令牌");

        assert!(!handle_terminal_revoked(&st, Some(3), None), "可重试退出不收敛");

        assert!(device_status(&st).paired, "设备绑定不得被误清");
        assert!(st.signed_in(), "用户会话不得被误清");
        assert_eq!(st.session_invalid(), None);
    }

    /// ⑪ 铁律：登出与解绑严格正交（登出保留绑定，解绑清空全部）。
    #[tokio::test]
    async fn sign_out_and_unpair_stay_orthogonal() {
        // 登出：保留设备绑定
        let (st, _sink) = signed_in_state("hgt_a");
        st.vault
            .set(&DeviceToken::new("hgd_signout".into()))
            .expect("写设备令牌");
        sign_out(&st, "http://x").expect("登出应成功");
        assert!(!st.signed_in(), "登出必须清会话");
        assert!(device_status(&st).paired, "登出**不得**清设备绑定");

        // 解绑：清空全部
        let st2 = state();
        st2.vault
            .set(&DeviceToken::new("hgd_unpair".into()))
            .expect("写设备令牌");
        st2.user_vault_ref()
            .set_user_token(&UserToken::new("hgt_b".into()))
            .expect("写会话");
        let gw = StubUnpairGateway::ok();
        unpair_device_with(&st2, &gw).await.expect("解绑应成功");
        assert!(!st2.signed_in(), "解绑必须清会话");
        assert!(!device_status(&st2).paired, "解绑必须清设备绑定");
    }
}
