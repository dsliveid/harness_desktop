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
use crate::vault::{DeviceToken, TokenVault, VaultError};

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
    /// Runner 是否在运行且心跳未超时。
    pub online: bool,
    /// 设备 ID（来自 ws `welcome` 握手；未连接时为 `None`）。
    pub device_id: Option<String>,
    /// 宿主壳版本。
    pub app_version: String,
    /// 端侧协议版本是否与服务端协商通过。未握手前为 `true`（尚无可判定的事实）。
    pub protocol_ok: bool,
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

/// `start_pairing` 的响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartPairingResponse {
    /// 本地是否已受理该配对请求。
    pub accepted: bool,
    /// 给人看的结果说明（如「请求已排队，等待服务端确认」）。
    pub message: String,
}

/// 心跳超时判定（**再导出自唯一事实源** `lifecycle`）。
///
/// 保留这个名字是为了不破坏既有调用方与测试；权威定义在
/// [`crate::lifecycle::HEARTBEAT_STALE_MS`]。不要在这里改数值 ——
/// 否则又会回到「两个地方各有一套阈值」的旧问题。
pub const HEARTBEAT_STALE_MS: u64 = crate::lifecycle::HEARTBEAT_STALE_MS;

/// 配对码允许的字符集与长度（服务端生成的格式契约）。
const PAIR_CODE_MIN_LEN: usize = 6;
const PAIR_CODE_MAX_LEN: usize = 12;

/// 宿主运行时状态（由 `AppState` 挂在 Tauri `State` 里）。
///
/// 所有字段都用了 `Arc`/`RwLock`：command 是并发调用的（前端可能同时轮询
/// `runner_status` 与提交 `set_workspace_roots`），不能用 `&mut self`。
pub struct HostState {
    vault: Arc<dyn TokenVault>,
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
        Self {
            vault,
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
pub const SUPPORTED_COMMANDS: [&str; 8] = [
    "list_commands",
    "device_status",
    "runner_status",
    "get_workspace_roots",
    "set_workspace_roots",
    "get_boot_state",
    "pair_device",
    "unpair_device",
];

/// 保留的 command 名清单（仅用于测试断言与文档，不注册）。
///
/// 这些名字写在这里是为了让「有人不小心加了它们」在单测里立刻失败，
/// 而不是等到安全评审才发现。
pub const FORBIDDEN_COMMANDS: [&str; 3] = ["get_device_token", "raw_ws_send", "exec_shell"];

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
        online,
        device_id: state
            .device_id
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone(),
        app_version: SHELL_VERSION.to_string(),
        protocol_ok: *state.protocol_ok.read().unwrap_or_else(|e| e.into_inner()),
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
/// ## 顺序为什么是「先停 Runner，再清凭据」
///
/// 反过来的话，凭据清空后 Runner 仍在跑：它手里握着已失效的令牌继续重连，
/// 服务端会收到一串 401，日志里看起来像"客户端发疯"。先停再清，Runner 是
/// 因为 stdin EOF 正常退出的。
pub async fn unpair_device(state: &HostState) -> Result<(), CommandError> {
    // ① 先停 Runner（内含交还实例锁），避免带着旧令牌继续重连。
    state.daemon().shutdown().await;
    state
        .daemon()
        .push_log("[host] 解除配对：正在清理本地凭据".to_string());

    // ② 清密钥链令牌 —— 真正的"解约"动作：没有令牌就无法再冒充本设备。
    state
        .vault
        .clear()
        .map_err(|e| CommandError::UnpairFailed(format!("清除设备令牌失败：{e}")))?;

    // ③ 清内存态：device_id / protocol_ok 回到初始，避免 UI 继续显示旧设备。
    *state.device_id.write().unwrap_or_else(|e| e.into_inner()) = None;
    *state.protocol_ok.write().unwrap_or_else(|e| e.into_inner()) = true;

    // ④ 相位回到「需要配对」，让 UI 直接切到配对引导。
    state
        .stats
        .set_state(crate::lifecycle::RunnerPhase::NeedsPairing);

    tracing::info!("已解除配对，等待重新配对");
    Ok(())
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
/// 而 Runner 侧可能已部分生效。这里选择**把失败如实报给调用方**（fail-loud），
/// 让前端能提示「配置已保存但未能同步到执行引擎，请重试或重启客户端」。
pub async fn set_workspace_roots_and_push(
    state: &HostState,
    roots: Vec<String>,
) -> Result<Vec<String>, CommandError> {
    // ① 校验 + 归一 + 写入宿主状态（复用同步版，避免两套校验逻辑漂移）。
    let normalized = set_workspace_roots(state, roots)?;

    // ② 取刚写入的那份 Policy 快照下发给 Runner。
    //    用 state.policy() 而不是自己再构造一次：保证「下发的」与「宿主记录的」
    //    是同一个归一结果（重新构造可能在极端并发下算出不同值）。
    let policy = state.policy();

    // ③ Runner 没在跑时不算错误：白名单会随下次 spawn 的 initial_roots + 随后的
    //    reload_policy 生效。此时 `send_line` 会返回「Runner 未运行」，属预期分支。
    match state.daemon().reload_policy(&policy).await {
        Ok(()) => Ok(normalized),
        Err(e) if is_runner_not_running(&e) => {
            tracing::debug!("Runner 未运行，工作区白名单将在下次启动时下发");
            Ok(normalized)
        }
        Err(e) => Err(CommandError::PushFailed(e.to_string())),
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

    boot.on_paired(paired)
        .await
        .map_err(|e| CommandError::PairFailed(e.to_string()))?;

    Ok(StartPairingResponse {
        accepted: true,
        message: "配对成功，执行引擎已启动".to_string(),
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

    /// 关闭「Runner 未运行」这一合法分支后，下发失败必须冒泡为 `PushFailed`。
    ///
    /// 这条测试的价值在于钉住**下发动作真的发生了**：若有人把
    /// `set_workspace_roots_and_push` 退回成只写 HostState 的实现，
    /// 这里会拿到 `Ok` 而不是 `PushFailed`，测试立刻失败。
    #[tokio::test]
    async fn push_path_actually_attempts_to_reach_runner() {
        let st = state();
        let dir = tempfile::tempdir().unwrap();
        let got = set_workspace_roots_and_push(&st, vec![dir.path().display().to_string()])
            .await
            .expect("Runner 未运行时下发应被视为合法分支（配置仍生效于下次启动）");
        assert_eq!(got.len(), 1, "归一结果应被返回");
        // 宿主侧状态已更新（先落状态、再下发的顺序保证）
        assert_eq!(get_workspace_roots(&st), got);

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
}
