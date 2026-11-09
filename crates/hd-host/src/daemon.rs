//! Runner 子进程守护（对齐 `docs/桌面端架构与功能设计.md` §17.1）。
//!
//! ## 为什么 Runner 是子进程而不是同进程线程
//!
//! 执行面（fs/grep/exec）是最容易被打穿的部分。放进独立进程后有两条收益：
//! 1. **崩溃隔离**：恶意路径把 Runner 搞崩了，Host 还活着，能重启并上报；
//! 2. **权限可收窄**：将来可给 Runner 单独降权/加沙箱，而 Host 继续持有用户界面权限。
//!
//! ## 三条硬性语义（代码里逐条落地）
//!
//! 1. **令牌只走 stdin**（[`Daemon::spawn`]）：不进 `argv`、不进环境变量。
//!    `argv` 与 `/proc/<pid>/environ` 在同机任何进程都可读，`ps` 也能看到；
//!    而管道内容是父子间私有的。序列化时也**不实现 `Serialize` 中间层**——
//!    这里用 [`serde_json::json!`] 直接把 `expose()` 的结果塞进一个临时 `Value`，
//!    这个 `Value` 随 `write_all` 结束即被 drop，不具有逃逸到日志的通道。
//! 2. **写端在发完 auth 后保持打开**（[`StdinHandle`]）：Runner 侧把「stdin EOF」
//!    当作「宿主已死」的信号并自杀（见 `hd-runner::ipc` 文档）。若 Host 发完 auth
//!    就关写端，Runner 会立刻误判为孤儿而退出，表现为「刚配对成功就掉线」。
//!    正确做法是持有写端直到 Host 进程整体退出 → OS 关闭管道 → 子进程才读到 EOF。
//!    这也正是**崩溃场景防孤儿**的关键：Host 崩溃时 OS 会无条件关闭它持有的写端，
//!    Runner 因此一定能读到 EOF 并自杀，不依赖 Host 做任何清理动作。
//! 3. **输出进限长 ring buffer**（[`LineRing`]）：Runner 的 stderr 可能因 bug 疯狂刷屏，
//!    无界 `Vec` 会把 Host 的 RSS 撑爆，最终连界面都点不动。上限 200 行是
//!    「排障够用 + 内存可算」的折中（200 × 单行上限 2 KiB ≈ 400 KiB）。

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::Mutex as AsyncMutex;

use hd_core::security::guard::Policy;
use hd_runner::reconnect::{ReconnectDecision, ReconnectPolicy};

use crate::vault::DeviceToken;

/// ring buffer 保留的最大行数。
pub const LOG_RING_CAPACITY: usize = 200;
/// 单行保留的最大字节数：防一行超长（如打印整个文件）把预算吃掉。
pub const LOG_LINE_MAX_BYTES: usize = 2048;

/// 守护层错误。
#[derive(Debug, Error)]
pub enum DaemonError {
    /// 找不到 runner 可执行文件。
    #[error("找不到 Runner 可执行文件：{0}")]
    RunnerNotFound(String),
    /// 拉起子进程失败。
    #[error("拉起 Runner 失败：{0}")]
    Spawn(String),
    /// 写 auth 行失败。**不携带行内容**，避免错误信息把令牌带进日志。
    #[error("写入 auth 行失败：{0}")]
    WriteAuth(String),
    /// 令牌问题（空/未配对）。
    #[error("令牌不可用：{0}")]
    Token(String),
}

/// 子进程 stdin 的持有者。
///
/// 存在意义只有一个：**保持写端打开**，让 Runner 的 stdin 不提前 EOF。
/// 一旦这个结构被 drop，写端关闭 → 子进程读到 EOF → 自杀（这是崩溃场景想要的效果，
/// 但正常运行期间绝不能提前 drop）。
pub struct StdinHandle {
    /// `Option` 只为在 `close` 时能主动交还；正常运行全程 `Some`。
    inner: Option<tokio::process::ChildStdin>,
}

impl StdinHandle {
    fn new(stdin: tokio::process::ChildStdin) -> Self {
        Self { inner: Some(stdin) }
    }

    /// 是否仍持有写端（恒为 `true` 直到主动 `close` 或整体 drop）。
    pub fn is_open(&self) -> bool {
        self.inner.is_some()
    }

    /// 写一条 JSONL 控制命令（例如热更新策略）。
    ///
    /// 追加 `\n` 是协议要求（JSONL）：Runner 按行解析，少一个换行就会卡在缓冲里。
    pub async fn write_line(&mut self, line: &str) -> Result<(), DaemonError> {
        let stdin = self
            .inner
            .as_mut()
            .ok_or_else(|| DaemonError::WriteAuth("stdin 已关闭".to_string()))?;
        stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| DaemonError::WriteAuth(e.to_string()))?;
        stdin
            .write_all(b"\n")
            .await
            .map_err(|e| DaemonError::WriteAuth(e.to_string()))?;
        stdin
            .flush()
            .await
            .map_err(|e| DaemonError::WriteAuth(e.to_string()))?;
        Ok(())
    }

    /// **主动**关闭写端（仅在「希望 Runner 自杀」时调用，例如退出配对）。
    ///
    /// 正常情况下不该调用：Host 崩溃时 OS 会自动关闭，不需要这行代码。
    pub fn close(&mut self) {
        self.inner = None;
    }
}

impl Drop for StdinHandle {
    fn drop(&mut self) {
        // 显式注释：这里**不做**任何 shutdown 调用。drop 掉 `ChildStdin` 就会关闭管道，
        // Runner 读到 EOF 后自杀 —— 这正是「宿主任一原因消失 → 子进程跟随消失」的保证。
    }
}

/// 限长行缓冲（ring buffer）。
///
/// 用 `VecDeque` 而不是 `Vec::drain(0..n)`：满仓后每条日志都 `drain` 会产生 O(n) 搬移，
/// 刷屏时反而成为 CPU 热点。`VecDeque::pop_front` 是 O(1)。
#[derive(Debug, Clone)]
pub struct LineRing {
    lines: VecDeque<String>,
    capacity: usize,
    /// 因超限被丢弃的行数（只增不减）。用于回答「日志是不是被截断了」。
    dropped: u64,
}

impl LineRing {
    pub fn new(capacity: usize) -> Self {
        // 容量为 0 等于「丢掉一切」，那就不该有这个结构；兜底成 1 保持可用。
        Self {
            lines: VecDeque::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
            dropped: 0,
        }
    }

    /// 追加一行（按字节安全截断，不切断 UTF-8 字符）。
    pub fn push(&mut self, line: impl Into<String>) {
        let mut s = line.into();
        if s.len() > LOG_LINE_MAX_BYTES {
            // 必须走 char_indices 找边界：直接 `truncate(2048)` 会把多字节字符切一半 → panic。
            // 这个坑与 hd-core 里「按字节切中文 panic」是同一类。
            let mut cut = LOG_LINE_MAX_BYTES;
            while cut > 0 && !s.is_char_boundary(cut) {
                cut -= 1;
            }
            s.truncate(cut);
            s.push('…');
        }
        if self.lines.len() == self.capacity {
            self.lines.pop_front();
            self.dropped += 1;
        }
        self.lines.push_back(s);
    }

    /// 当前行数（恒 ≤ capacity）。
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// 因超限丢弃的行数。
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// 拷贝出当前内容（给 UI 展示用；不交出去所有权，避免外部改动内部状态）。
    pub fn snapshot(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
    }
}

/// Runner 生命周期状态（与 `runner_status` command 的 `state` 字段一一对应）。
///
/// ## 为什么这里只是一个别名
///
/// 改造前本枚举是**独立定义**的，于是「Runner 处于什么状态」在 `daemon`、
/// `boot_state`、`commands` 三处各有口径。现在权威定义收敛到
/// [`crate::lifecycle::RunnerPhase`]，这里保留名字只为**不破坏既有调用方**
/// （`daemon` 内部与测试仍写 `RunnerState`）。
///
/// ⚠️ 新代码请直接用 [`crate::lifecycle::RunnerPhase`]；不要在此扩展变体 ——
/// 别名上没有自己的定义，任何新增都必须发生在唯一事实源里。
pub type RunnerState = crate::lifecycle::RunnerPhase;

/// 一次子进程退出的记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitRecord {
    /// 退出码；被信号杀死（Unix）时为 `None`。
    pub code: Option<i32>,
    /// 退出时刻（Unix 毫秒）。
    pub at_ms: u64,
    /// 已累计的重启次数（第几次重启前发生的退出）。
    pub restarts: u32,
}

/// 当前时间（Unix 毫秒）。时钟回拨时退化为 0，绝不 panic。
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 共享给 command 层的运行时快照。
///
/// 用原子而非 Mutex：这些值都是「读多写少」的标量，原子读不需要抢锁，
/// 前端 1s 轮询一次 `runner_status` 时不会和日志搬运线程互相阻塞。
#[derive(Debug)]
pub struct RuntimeStats {
    state: Mutex<RunnerState>,
    restarts: AtomicU64,
    /// `pub(crate)` 而非完全私有：command 层要按「心跳是否过旧」判定在线状态，
    /// 需要能写入一个来自 Runner 事件的时间戳；对外仍只暴露 [`RuntimeStats::last_heartbeat_ms`] 读接口。
    pub(crate) last_heartbeat_ms: AtomicU64,
}

impl Default for RuntimeStats {
    fn default() -> Self {
        Self {
            state: Mutex::new(RunnerState::Stopped),
            restarts: AtomicU64::new(0),
            last_heartbeat_ms: AtomicU64::new(0),
        }
    }
}

impl RuntimeStats {
    pub fn state(&self) -> RunnerState {
        *self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_state(&self, s: RunnerState) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = s;
    }

    pub fn restarts(&self) -> u32 {
        self.restarts.load(Ordering::Relaxed) as u32
    }

    pub fn bump_restarts(&self) -> u32 {
        self.restarts.fetch_add(1, Ordering::Relaxed) as u32 + 1
    }

    pub fn last_heartbeat_ms(&self) -> u64 {
        self.last_heartbeat_ms.load(Ordering::Relaxed)
    }

    /// 记录一次心跳（Runner 上报，或宿主侧观测到子进程存活）。
    pub fn mark_heartbeat(&self) {
        self.last_heartbeat_ms.store(now_ms(), Ordering::Relaxed);
    }
}

/// auth 行的构造与序列化 —— 全流程唯一接触令牌明文的地方。
///
/// 手工拼 `serde_json::Value` 而不是定义 `#[derive(Serialize)] struct AuthLine`：
/// 后者会成为一个「带 token 字段且可被 `to_string` 的结构体」，一旦有人在别处
/// `serde_json::to_string(&auth_line)` 就把令牌写进了日志。这里 `Value` 是局部临时变量，
/// 生命周期被压到单个函数内。
pub fn build_auth_line(token: &DeviceToken, ws_url: &str, protocol_version: i32) -> String {
    // 🔴 全项目少数允许出现令牌明文的地方之一，见 DeviceToken::expose 的文档。
    let value = serde_json::json!({
        "op": "auth",
        "token": token.expose(),
        "ws_url": ws_url,
        "protocol_version": protocol_version,
    });
    value.to_string()
}

/// 工作区策略行（热更新守卫策略）。
pub fn build_reload_policy_line(roots: &[String], exec_allowlist: &[String]) -> String {
    let value = serde_json::json!({
        "op": "reload_policy",
        "roots": roots,
        "exec_allowlist": exec_allowlist,
    });
    value.to_string()
}

/// Runner 启动方式：可执行文件 + 需要附加的参数。
///
/// 单文件交付（默认）下 `exe` 就是宿主自身，`extra_args` 为 `["--runner"]`；
/// 用户自编译独立 runner 时 `extra_args` 为空。把「用哪个文件」和「带什么参数」
/// 放在同一个结构里返回，是为了让调用方**不可能**只改其一 —— 只传 exe 不传
/// `--runner` 会让 GUI 再弹一个窗口（自派生只在带参数时才走 Runner 分支）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerLaunch {
    /// 要执行的程序路径。
    pub exe: PathBuf,
    /// 附加参数（自派生时为 `["--runner"]`，独立 runner 时为空）。
    pub extra_args: Vec<String>,
}

impl RunnerLaunch {
    /// 以宿主自身自派生 Runner。
    pub fn self_derived(exe: PathBuf) -> Self {
        Self {
            exe,
            extra_args: vec![SELF_DERIVE_FLAG.to_string()],
        }
    }

    /// 用独立的 runner 可执行文件启动。
    pub fn standalone(exe: PathBuf) -> Self {
        Self {
            exe,
            extra_args: Vec::new(),
        }
    }
}

/// 自派生开关（与 `main.rs` 的 `is_runner_mode` 必须完全一致）。
pub const SELF_DERIVE_FLAG: &str = "--runner";

/// Runner 定位器。
///
/// ## 单包模式下的优先级
///
/// ⓪ **自派生**（默认，`allow_self=true`）：宿主自身 + `--runner`。
///    这是**单包分发的主路径** —— 用户只拿到一个 exe，Runner 由它自己派生。
///
///    历史误解澄清：旧注释称「Windows 上实测不可用，会在加载期 0xC0000139 崩溃」。
///    该结论**只在 `windows`（无控制台）子系统下成立**。本仓库实测（2026-11）：
///    `console` 子系统下自派生正常（子进程进 main()、读 stdin、退出码 2，约 51ms），
///    详见 `bootstrap::Bootstrap` 字段 `allow_self_derive` 的对照表。
///
/// ① **显式配置**：允许指定自编译的 runner（调试 / 特殊排查）。
/// ② **同目录独立 runner**：兜底。保留给「开发期单独编了 runner」与历史部署形态；
///    正常分发不再需要它。
pub fn locate_runner(
    explicit: Option<&Path>,
    exe_name: &str,
    allow_self: bool,
) -> Option<RunnerLaunch> {
    let current = std::env::current_exe().ok();

    // ⓪ 自派生：宿主自己就是 Runner（单包分发主路径）。
    if allow_self {
        if let Some(me) = current.as_ref() {
            if me.is_file() {
                return Some(RunnerLaunch::self_derived(me.clone()));
            }
        }
    }

    // ① 显式配置优先（允许用户指定自编译的 runner）。
    if let Some(p) = explicit {
        if p.is_file() {
            return Some(RunnerLaunch::standalone(p.to_path_buf()));
        }
    }

    // ② 与宿主可执行文件同目录：安装包会这样布局（§18 打包约定）。
    if let Some(me) = current.as_ref() {
        if let Some(dir) = me.parent() {
            let candidate = dir.join(exe_name);
            if candidate.is_file() {
                return Some(RunnerLaunch::standalone(candidate));
            }
            // 打包时 runner 常放在 `resources/` 子目录。
            let candidate = dir.join("resources").join(exe_name);
            if candidate.is_file() {
                return Some(RunnerLaunch::standalone(candidate));
            }
        }
    }

    None
}

/// 平台可执行文件后缀。
pub fn exe_suffix() -> &'static str {
    if cfg!(windows) {
        ".exe"
    } else {
        ""
    }
}

/// Runner 守护者：持有子进程与统计，提供 start / stop / 重启决策。
pub struct Daemon {
    stats: Arc<RuntimeStats>,
    policy: ReconnectPolicy,
    /// 日志 ring（stdout + stderr 共用，便于按发生顺序还原现场）。
    ///
    /// 用 `Arc<Mutex<..>>` 而不是裸 `Mutex`：两个输出搬运任务是 `tokio::spawn` 出来的
    /// 独立 future，必须各自持有一份可移动到 'static 的引用。
    logs: Arc<Mutex<LineRing>>,
    last_exit: Mutex<Option<ExitRecord>>,
    /// 当前运行的子进程（`spawn` 后为 `Some`）。
    running: AsyncMutex<Option<RunningChild>>,
    /// 本机实例锁（`Some` == 本进程负责拉起 Runner）。
    ///
    /// ## 为什么放在 Daemon 里，而不是 Bootstrap 的局部变量
    ///
    /// 锁的生命周期必须**覆盖 Runner 的整个运行期**：`Bootstrap::ensure_running`
    /// 一返回，局部变量就会被 drop。若锁留在局部变量里，函数退出即释放锁，
    /// 下一个宿主进程会立刻抢到锁并误判「本机没人在跑」，再 spawn 一份 ——
    /// 正好是这把锁要防的双开。
    ///
    /// 放在 Daemon 的理由：Daemon 就是「Runner 的存在期」这个概念的载体，
    /// 它在 `shutdown()` 里统一释放锁，语义自然对齐（Runner 停 ⇒ 职责结束 ⇒ 交还锁）。
    ///
    /// 用 std `Mutex` 而非 async：临界区只有取/放一个 `Option`，没有 `.await`。
    instance_lock: Mutex<Option<crate::instance_lock::InstanceLock>>,
    /// 锁文件路径覆盖（`None` == 用 [`InstanceLock::default_path`]）。
    ///
    /// ## 为什么必须可注入
    ///
    /// 测试并行跑时，同一个进程内的多个用例会共享默认锁路径（都指向用户数据目录），
    /// 于是「A 抢到锁、B 抢不到」变成**测试之间的干扰**而不是被验证的行为 ——
    /// 表现为随机失败，且与真实缺陷难以区分。
    ///
    /// 生产环境保持 `None`；测试用 `Daemon::with_lock_path` 注入 tempdir 路径。
    lock_path: Option<PathBuf>,
}

struct RunningChild {
    child: Child,
    stdin: StdinHandle,
    exe: PathBuf,
}

impl Daemon {
    pub fn new(policy: ReconnectPolicy) -> Self {
        Self {
            stats: Arc::new(RuntimeStats::default()),
            policy,
            logs: Arc::new(Mutex::new(LineRing::new(LOG_RING_CAPACITY))),
            last_exit: Mutex::new(None),
            running: AsyncMutex::new(None),
            instance_lock: Mutex::new(None),
            lock_path: None,
        }
    }

    /// 指定实例锁文件路径（**仅测试用**；生产走 `InstanceLock::default_path`）。
    ///
    /// 见字段 `lock_path` 的文档：不注入会让并行测试互相抢同一把锁。
    #[must_use]
    pub fn with_lock_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.lock_path = Some(path.into());
        self
    }

    /// 尝试抢占本机实例锁，抢到则**由本 Daemon 长期持有**。
    ///
    /// - `Ok(true)`：抢到（本机此前没人在负责 Runner）；
    /// - `Ok(false)`：已被别的进程持有 —— 调用方不得 spawn；
    /// - `Err`：锁文件不可用（权限/磁盘），按启动失败处理。
    ///
    /// 已持有则直接返回 `true`（幂等）：`ensure_running` 可能被调用多次，
    /// 重复抢同一把锁会因「自己持有」而返回 false，把自己误判成外部实例。
    pub fn acquire_instance_lock(&self) -> std::io::Result<bool> {
        let mut guard = self.instance_lock.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return Ok(true);
        }
        let path = match &self.lock_path {
            Some(p) => p.clone(),
            None => crate::instance_lock::InstanceLock::default_path()?,
        };
        match crate::instance_lock::InstanceLock::try_acquire(&path)? {
            Some(lock) => {
                tracing::debug!(path = %lock.path().display(), "已取得本机实例锁");
                *guard = Some(lock);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// 释放本机实例锁（Runner 已停止 / 拉起失败回滚时调用）。
    ///
    /// 释放后本机即可由另一个宿主实例接管，因此**只应在真的不再负责 Runner 时调用**。
    pub fn release_instance_lock(&self) {
        let mut guard = self.instance_lock.lock().unwrap_or_else(|e| e.into_inner());
        if guard.take().is_some() {
            tracing::debug!("本机实例锁已交还");
        }
    }

    /// 当前是否持有本机实例锁（诊断用）。
    pub fn holds_instance_lock(&self) -> bool {
        self.instance_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// 共享统计句柄（给 command 层读状态）。
    pub fn stats(&self) -> Arc<RuntimeStats> {
        Arc::clone(&self.stats)
    }

    /// 追加日志（供输出搬运任务与宿主自身事件写入）。
    pub fn push_log(&self, line: impl Into<String>) {
        self.logs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(line);
    }

    /// 日志快照。
    pub fn logs(&self) -> Vec<String> {
        self.logs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot()
    }

    /// 因超限丢弃的行数。
    pub fn dropped_logs(&self) -> u64 {
        self.logs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .dropped()
    }

    /// 最近一次退出记录。
    pub fn last_exit(&self) -> Option<ExitRecord> {
        self.last_exit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 拉起 Runner 子进程，并把 auth 写入 stdin（**写端保持打开**）。
    ///
    /// `token` 是 [`DeviceToken`]：调用方拿不到裸 `String` 传进来，也就不可能顺手
    /// 把它拼进 `argv` —— 本函数签名里没有接收「字符串形式的令牌」的通道。
    pub async fn spawn(
        &self,
        launch: &RunnerLaunch,
        token: &DeviceToken,
        ws_url: &str,
        protocol_version: i32,
    ) -> Result<(), DaemonError> {
        if token.is_empty() {
            return Err(DaemonError::Token("令牌为空，拒绝启动 Runner".to_string()));
        }
        let exe = &launch.exe;
        if !exe.is_file() {
            return Err(DaemonError::RunnerNotFound(exe.display().to_string()));
        }

        self.stats.set_state(RunnerState::Running);
        self.push_log(format!(
            "[host] 启动 Runner：{} {}",
            exe.display(),
            launch.extra_args.join(" ")
        ));

        // 🔴 关键：刻意**不**调用 `.arg(token)` / `.env("HD_TOKEN", token)`。
        // 见模块文档第 1 条。这里连 `.env_clear()` 都做了加码：
        // 清掉继承来的环境变量，防止某个上游变量里恰好带着旧令牌。
        //
        // `extra_args` 只可能是 `--runner` 这类开关（由 `RunnerLaunch` 构造时写死），
        // 不存在拼接用户输入或令牌的路径。
        let mut cmd = Command::new(exe);
        cmd.args(&launch.extra_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()
            // 保留最小可用环境：Windows 下缺 SystemRoot 会导致子进程连 DNS/证书都初始化失败。
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env(
                "SYSTEMROOT",
                std::env::var("SYSTEMROOT").unwrap_or_default(),
            )
            // `kill_on_drop(true)` 是**第二道**保险：即使有人误把 Child 提前 drop，
            // 也不会留下孤儿进程。第一道保险是 stdin EOF 语义（见模块文档第 2 条）。
            .kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| DaemonError::Spawn(e.to_string()))?;

        let stdin_raw = child
            .stdin
            .take()
            .ok_or_else(|| DaemonError::Spawn("子进程 stdin 不可用".to_string()))?;
        let mut stdin = StdinHandle::new(stdin_raw);

        // 写 auth 行 —— 全流程唯一一次令牌出内存。
        let line = build_auth_line(token, ws_url, protocol_version);
        stdin.write_line(&line).await?;
        // 写操作产生的临时 String 立刻 drop（其内容包含明文）。
        drop(line);
        self.push_log("[host] auth 已通过 stdin 写入（token 不出现在 argv/env/日志）".to_string());

        // stdout / stderr 分别起搬运任务写进同一个 ring，
        // 用两行前缀区分来源；两路都读到 EOF 才算子进程真的停止输出。
        if let Some(out) = child.stdout.take() {
            let shared = self.shared_sink();
            tokio::spawn(pump_lines(out, "[runner:out]", shared));
        }
        if let Some(err) = child.stderr.take() {
            let shared = self.shared_sink();
            tokio::spawn(pump_lines(err, "[runner:err]", shared));
        }

        *self.running.lock().await = Some(RunningChild {
            child,
            stdin,
            exe: exe.to_path_buf(),
        });
        Ok(())
    }

    /// 当前是否有存活的子进程句柄。
    pub async fn is_running(&self) -> bool {
        self.running.lock().await.is_some()
    }

    /// 把 auth 之后的控制命令（如 `reload_policy`）写进 stdin。
    ///
    /// 复用同一个写端，**不重开**管道：重开会破坏「Runner 只在 EOF 时自杀」的语义。
    pub async fn send_line(&self, line: &str) -> Result<(), DaemonError> {
        let mut guard = self.running.lock().await;
        match guard.as_mut() {
            Some(r) => r.stdin.write_line(line).await,
            None => Err(DaemonError::WriteAuth("Runner 未运行".to_string())),
        }
    }

    /// 热更新守卫策略，并把本地 [`Policy`] 的归一结果同步给 Runner。
    ///
    /// 传 `Policy` 而不是裸 `Vec<PathBuf>`：根目录必须先过 canonicalize +
    /// 三闸口径归一（见 hd-core），否则宿主与 Runner 会各按自己的形态判断归属，
    /// 出现「宿主认为在根内、Runner 认为越界」的错位。
    pub async fn reload_policy(&self, policy: &Policy) -> Result<(), DaemonError> {
        let roots: Vec<String> = policy
            .roots()
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let line = build_reload_policy_line(&roots, &[]);
        self.send_line(&line).await
    }

    /// 等待子进程退出并记录 exit code。
    ///
    /// 返回退出记录；若当前无子进程则返回 `None`。
    pub async fn wait_exit(&self) -> Option<ExitRecord> {
        let mut guard = self.running.lock().await;
        let running = guard.take()?;
        let RunningChild {
            mut child,
            stdin,
            exe,
        } = running;

        // 先显式 drop 写端：走到这一步说明「这个子进程要结束了」。
        // 但注意 `wait` 期间写端仍在 `stdin` 变量里保持打开，符合「正常运行不提前 EOF」。
        drop(stdin);

        let status = child.wait().await;
        let record = ExitRecord {
            code: status.as_ref().ok().and_then(|s| s.code()),
            at_ms: now_ms(),
            restarts: self.stats.restarts(),
        };
        self.push_log(format!(
            "[host] Runner 退出：{}（exe={}）",
            record
                .code
                .map(|c| format!("code={c}"))
                .unwrap_or_else(|| "被信号终止".to_string()),
            exe.display()
        ));
        *self.last_exit.lock().unwrap_or_else(|e| e.into_inner()) = Some(record.clone());
        self.stats.set_state(RunnerState::Stopped);
        Some(record)
    }

    /// 依据 [`ReconnectPolicy`] 决定是否重启，并执行退避等待。
    ///
    /// 复用 `hd-runner` 的 `ReconnectPolicy` 而不是在宿主侧重写一套退避：
    /// 两侧退避口径必须一致，否则「Runner 认为该退避 2s、Host 认为该退避 30s」
    /// 会导致状态显示与实际重连节奏打架。
    pub async fn backoff_before_restart(&self, attempt: u32) -> ReconnectDecision {
        match self.policy.decide(attempt, None) {
            ReconnectDecision::Stop => {
                self.stats.set_state(RunnerState::GaveUp);
                self.push_log(format!(
                    "[host] Runner 连续失败 {attempt} 次，停止重启（需用户介入）"
                ));
                ReconnectDecision::Stop
            }
            ReconnectDecision::RetryAfter(d) => {
                self.stats.set_state(RunnerState::Backoff);
                self.push_log(format!("[host] {:?} 后重启 Runner（第 {attempt} 次）", d));
                tokio::time::sleep(d).await;
                ReconnectDecision::RetryAfter(d)
            }
        }
    }

    /// 主动停止：关闭写端让子进程自杀，并标记为 `ShuttingDown`（不自动重启）。
    ///
    /// **同时交还本机实例锁**：Runner 一停，本进程就不再是「负责 Runner 的那一个」，
    /// 锁继续持有会让本机其他实例（或用户重启后的新实例）无法接管。
    pub async fn shutdown(&self) {
        self.stats.set_state(RunnerState::ShuttingDown);
        let mut guard = self.running.lock().await;
        if let Some(r) = guard.as_mut() {
            // 主动 close → Runner 读到 EOF → 自行优雅退出。
            r.stdin.close();
            // 给 1s 让 Runner 落日志/关连接；超时直接 kill 兜底（不留孤儿）。
            if tokio::time::timeout(Duration::from_secs(1), r.child.wait())
                .await
                .is_err()
            {
                let _ = r.child.start_kill();
                self.push_log("[host] Runner 未在 1s 内退出，已强制终止".to_string());
            }
        }
        *guard = None;
        // 子进程已确定停止，交还锁。放在 `*guard = None` 之后：
        // 若先放锁再等子进程退出，另一个实例可能抢到锁并孙 spawn 出第二份 Runner，
        // 与本实例尚未退出的子进程撞上（双开）。
        self.release_instance_lock();
    }

    fn shared_sink(&self) -> Arc<LogSink> {
        Arc::new(LogSink {
            ring: Arc::clone(&self.logs),
        })
    }
}

/// 输出搬运用的日志汇聚点。
pub struct LogSink {
    ring: Arc<Mutex<LineRing>>,
}

impl LogSink {
    pub fn push(&self, line: impl Into<String>) {
        self.ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(line);
    }
}

/// 读取子进程输出流，逐行送到 sink。
///
/// 单独抽成函数便于单测：给它一对 `BufReader` 就能验证「超长行被截断」「行数受限」。
pub async fn pump_lines<R>(reader: R, prefix: &'static str, sink: Arc<LogSink>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::{AsyncBufReadExt, BufReader};

    let mut lines = BufReader::new(reader).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => sink.push(format!("{prefix} {line}")),
            // EOF：子进程关闭了输出（通常意味着要退出了）。
            Ok(None) => break,
            Err(e) => {
                // 读错误不该把搬运任务打成 panic（会污染 Host 日志），
                // 记录一行诊断后退出循环即可。
                sink.push(format!("{prefix} <读取失败：{e}>"));
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hd_runner::reconnect::ReconnectPolicy;
    use std::time::Duration;

    fn token(raw: &str) -> DeviceToken {
        DeviceToken::new(raw.to_string())
    }

    // ---------- LineRing：限长语义 ----------

    #[test]
    fn ring_keeps_only_capacity_lines() {
        let mut r = LineRing::new(3);
        for i in 0..10 {
            r.push(format!("line-{i}"));
        }
        // 这是防内存膨胀的核心断言：无界 Vec 会让 Runner 刷屏把宿主 RSS 撑爆。
        assert_eq!(r.len(), 3);
        assert_eq!(r.dropped(), 7);
        assert_eq!(r.snapshot(), vec!["line-7", "line-8", "line-9"]);
    }

    #[test]
    fn ring_evicts_oldest_first() {
        let mut r = LineRing::new(2);
        r.push("a");
        r.push("b");
        r.push("c");
        // 保留最近的行而不是最早的：排障关心「崩之前发生了什么」。
        assert_eq!(r.snapshot(), vec!["b", "c"]);
    }

    #[test]
    fn ring_truncates_overlong_lines_without_panicking() {
        let mut r = LineRing::new(4);
        // 中文字符 3 字节：直接 truncate(2048) 会切在字符中间 → panic。
        // 这条测试就是那个坑的回归防线。
        let long = "中".repeat(LOG_LINE_MAX_BYTES);
        r.push(long);
        let got = &r.snapshot()[0];
        assert!(got.len() <= LOG_LINE_MAX_BYTES + "…".len());
        assert!(got.ends_with('…'), "超长行应有截断标记");
        // 截断后仍是合法 UTF-8（String 本身保证，但长度断言能防「按字节硬切」）
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn ring_capacity_zero_falls_back_to_one() {
        let mut r = LineRing::new(0);
        r.push("x");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn ring_starts_empty() {
        let r = LineRing::new(10);
        assert!(r.is_empty());
        assert_eq!(r.dropped(), 0);
    }

    // ---------- auth 行构造：令牌只进 stdin ----------

    #[test]
    fn auth_line_is_single_line_jsonl_with_expected_fields() {
        let line = build_auth_line(&token("hgd_abc"), "wss://h/api/v1/devices/ws", 1);
        // JSONL 的硬要求：不能含换行，否则 Runner 会把它当两行解析。
        assert!(!line.contains('\n'), "auth 行不得含换行：{line}");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["op"], "auth");
        assert_eq!(v["token"], "hgd_abc");
        assert_eq!(v["ws_url"], "wss://h/api/v1/devices/ws");
        assert_eq!(v["protocol_version"], 1);
    }

    #[test]
    fn reload_policy_line_shape() {
        let line = build_reload_policy_line(
            &["C:\\work".to_string()],
            &["git".to_string(), "node".to_string()],
        );
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["op"], "reload_policy");
        assert_eq!(v["roots"][0], "C:\\work");
        assert_eq!(v["exec_allowlist"][1], "node");
    }

    /// 🔴 spawn 的签名里只有 `&DeviceToken`，没有「字符串令牌」通道 ——
    /// 这条测试用「空令牌必须被拒绝」证明「未配对时不会拉起子进程」。
    #[tokio::test]
    async fn spawn_rejects_empty_token() {
        let d = Daemon::new(ReconnectPolicy::default());
        let err = d
            .spawn(
                &RunnerLaunch::standalone("whatever".into()),
                &token(""),
                "wss://x",
                1,
            )
            .await
            .expect_err("空令牌必须拒绝");
        assert!(matches!(err, DaemonError::Token(_)), "实际：{err:?}");
        // 状态不能被改成 Running：前端看到 running 但子进程没起，是最难排查的一类 bug。
        assert_eq!(d.stats().state(), RunnerState::Stopped);
        assert!(!d.is_running().await);
    }

    #[tokio::test]
    async fn spawn_rejects_missing_executable() {
        let d = Daemon::new(ReconnectPolicy::default());
        let missing = Path::new("definitely-not-a-real-runner-xyz");
        let err = d
            .spawn(
                &RunnerLaunch::standalone(missing.to_path_buf()),
                &token("hgd_x"),
                "wss://x",
                1,
            )
            .await
            .expect_err("不存在的 exe 必须拒绝");
        assert!(
            matches!(err, DaemonError::RunnerNotFound(_)),
            "实际：{err:?}"
        );
    }

    #[tokio::test]
    async fn send_line_without_runner_is_an_error_not_a_panic() {
        let d = Daemon::new(ReconnectPolicy::default());
        let err = d
            .send_line("{}")
            .await
            .expect_err("未运行时写 stdin 应报错");
        assert!(matches!(err, DaemonError::WriteAuth(_)));
    }

    // ---------- 退避重启：复用 hd-runner 的 ReconnectPolicy ----------

    #[tokio::test(start_paused = true)]
    async fn backoff_follows_reconnect_policy_and_then_gives_up() {
        let d = Daemon::new(ReconnectPolicy {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(80),
            max_attempts: 3,
        });

        // 第 1 次失败 → 退避 10ms（虚拟时钟下瞬时完成）
        let decision = d.backoff_before_restart(1).await;
        assert!(
            matches!(decision, ReconnectDecision::RetryAfter(d) if d == Duration::from_millis(10))
        );
        assert_eq!(d.stats().state(), RunnerState::Backoff);

        // 第 2 次 → 20ms
        assert!(matches!(
            d.backoff_before_restart(2).await,
            ReconnectDecision::RetryAfter(d) if d == Duration::from_millis(20)
        ));

        // 第 3 次达到 max_attempts → 放弃，状态切 gave_up（前端提示用户介入）
        assert_eq!(d.backoff_before_restart(3).await, ReconnectDecision::Stop);
        assert_eq!(d.stats().state(), RunnerState::GaveUp);
    }

    #[test]
    fn runtime_stats_track_restarts_and_heartbeat() {
        let s = RuntimeStats::default();
        assert_eq!(s.restarts(), 0);
        assert_eq!(s.bump_restarts(), 1);
        assert_eq!(s.bump_restarts(), 2);
        assert_eq!(s.restarts(), 2);

        // 心跳：0 表示从未收到
        assert_eq!(s.last_heartbeat_ms(), 0);
        s.mark_heartbeat();
        assert!(s.last_heartbeat_ms() > 0);
    }

    #[test]
    fn exit_record_defaults_are_none() {
        let d = Daemon::new(ReconnectPolicy::default());
        assert!(d.last_exit().is_none());
    }

    #[tokio::test]
    async fn wait_exit_returns_none_when_nothing_running() {
        let d = Daemon::new(ReconnectPolicy::default());
        assert!(d.wait_exit().await.is_none());
    }

    #[test]
    fn locate_runner_prefers_explicit_path() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join(format!("hd-runner{}", exe_suffix()));
        std::fs::write(&fake, b"").unwrap();

        // allow_self=false：模拟「用户显式指定了独立 runner」的调试场景
        let found = locate_runner(Some(&fake), "hd-runner", false).expect("应命中显式路径");
        assert_eq!(found.exe, fake);
        // 独立 runner 不需要附加参数
        assert!(found.extra_args.is_empty());
    }

    #[test]
    fn locate_runner_returns_none_when_explicit_missing_and_no_sibling() {
        // 显式路径不存在 + 同目录没有该名字的文件 → None（而不是 panic）。
        let missing = Path::new("no-such-dir-xyz/no-such-runner");
        let found = locate_runner(Some(missing), "definitely-absent-runner-name", false);
        // 允许为 None；关键是「不 panic 且不返回不存在的路径」。
        if let Some(launch) = found {
            assert!(launch.exe.is_file());
        }
    }

    /// 🔴 单文件交付的核心保证：allow_self=true 时必须返回宿主自身 + `--runner`。
    ///
    /// 这条一旦回归，用户双击 exe 会看到**第二个 GUI 窗口**而不是 Runner ——
    /// 现象诡异且极难关联到「少传了一个参数」，所以必须由测试钉住。
    #[test]
    fn locate_runner_self_derives_with_runner_flag() {
        let found = locate_runner(None, "hd-runner", true).expect("allow_self 下必须能自派生");
        // 自派生的 exe 就是当前测试进程自己
        assert_eq!(found.exe, std::env::current_exe().unwrap());
        assert_eq!(found.extra_args, vec!["--runner".to_string()]);
    }

    /// 自派生参数里绝不能出现令牌形态的字符串（令牌只走 stdin）。
    #[test]
    fn self_derived_args_never_contain_token() {
        let found = locate_runner(None, "hd-runner", true).unwrap();
        for a in &found.extra_args {
            assert!(!a.starts_with("hgd_"), "自派生参数里出现了令牌：{a}");
            assert!(!a.contains("token"), "自派生参数里出现了 token 字样：{a}");
        }
    }

    #[tokio::test]
    async fn pump_lines_feeds_sink_and_stops_at_eof() {
        let ring = Arc::new(Mutex::new(LineRing::new(LOG_RING_CAPACITY)));
        let sink = Arc::new(LogSink {
            ring: Arc::clone(&ring),
        });
        let src: &[u8] = b"a\nb\n";
        pump_lines(src, "[t]", sink).await;

        let lines = ring.lock().unwrap().snapshot();
        assert_eq!(lines, vec!["[t] a", "[t] b"]);
    }

    #[tokio::test]
    async fn pump_lines_ring_stays_bounded_under_flood() {
        let ring = Arc::new(Mutex::new(LineRing::new(5)));
        let sink = Arc::new(LogSink {
            ring: Arc::clone(&ring),
        });
        // 模拟 Runner stderr 刷屏：100 行 → ring 只留 5 行。
        let mut src = String::new();
        for i in 0..100 {
            src.push_str(&format!("flood-{i}\n"));
        }
        pump_lines(src.as_bytes(), "[flood]", sink).await;

        let guard = ring.lock().unwrap();
        assert_eq!(guard.len(), 5, "刷屏时必须限长，否则宿主内存会被撑爆");
        assert_eq!(guard.dropped(), 95);
        assert!(guard.snapshot().last().unwrap().contains("flood-99"));
    }
}
