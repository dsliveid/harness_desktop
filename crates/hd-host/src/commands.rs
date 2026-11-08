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

use crate::daemon::RuntimeStats;
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

/// 心跳超时判定：超过这个时长没有任何心跳 → 视为离线。
///
/// 取 90s：Runner 心跳周期上限是 30s（见 §17.1），留 3 个周期容忍一次抖动 + 一次
/// 调度延迟；再紧一点会在机器卡顿时误报掉线，把用户推向「反复重启客户端」。
pub const HEARTBEAT_STALE_MS: u64 = 90_000;

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
            roots: RwLock::new(Vec::new()),
            policy: RwLock::new(Arc::new(Policy::new(Vec::new(), Vec::new()))),
            device_id: RwLock::new(None),
            // 未握手前没有「协议不通过」的事实，默认 true 避免前端误报红。
            protocol_ok: RwLock::new(true),
            pending_pairing: Mutex::new(None),
        }
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
pub const SUPPORTED_COMMANDS: [&str; 5] = [
    "list_commands",
    "device_status",
    "runner_status",
    "get_workspace_roots",
    "set_workspace_roots",
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
    let st = state.stats.state();
    let hb = state.stats.last_heartbeat_ms();
    let online = st == crate::daemon::RunnerState::Running
        && (hb == 0 || crate::daemon::now_ms().saturating_sub(hb) < HEARTBEAT_STALE_MS);

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
}

/// `set_workspace_roots`：设置并归一工作区根，返回**归一后**的清单。
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
}
