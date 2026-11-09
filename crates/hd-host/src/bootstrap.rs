//! 启动编排：把「已配对」变成「Runner 在跑」。
//!
//! ## 这个模块存在的理由
//!
//! `vault` 知道令牌、`daemon` 会拉起子进程、`pairing` 能做配对，但**没人把它们
//! 串成一条链**。缺了这层，用户双击 exe 只会看到 GUI，Runner 永远不会被拉起
//! （实测过：`locate_runner` 与 `Daemon::spawn` 一度只在单测里被调用）。
//!
//! 本模块承担唯一职责：**给定「是否已配对」这个事实，把 Runner 拉到运行态**。
//! 它不关心 UI 怎么显示、也不关心配对码从哪来。
//!
//! ## 两条入口
//!
//! - [`Bootstrap::ensure_running`]：**启动时**调用。有令牌就直接拉起（用户上次
//!   配对过就不必每次手动点击）；没有就返回 [`BootstrapOutcome::NeedsPairing`]。
//! - [`Bootstrap::on_paired`]：**配对成功后**调用。先落令牌再拉起，顺序不可颠倒。

use std::path::PathBuf;
use std::sync::Arc;

use crate::daemon::{locate_runner, Daemon};
use crate::pairing::PairedDevice;
use crate::profile::ProfileStore;
use crate::vault::TokenVault;

/// `ensure_running` 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// Runner 已拉起（或本来就在跑）。
    Started {
        /// 设备 ID 提示（来自本机记录的 WS 握手，未连接时为空）。
        device_id_hint: String,
    },
    /// 密钥链里没有令牌 —— 需要用户走配对流程。
    NeedsPairing,
    /// 有令牌但**定位不到任何 Runner 启动方式**（自派生与兜底路径都失败）。
    ///
    /// 单包模式下自派生总会命中，因此本分支正常不会出现；一旦出现，说明
    /// `current_exe()` 取不到（极端的进程环境），属于**程序自身异常**而非用户漏拷文件。
    /// 保留独立分支是为了给出可操作提示，而不是含糊地报「启动失败」。
    RunnerMissing {
        /// 已搜索的路径描述，便于排障。
        searched: String,
    },
    /// 本机**已有别的进程**在负责 Runner，本实例不再拉起（不算失败）。
    ///
    /// 触发条件：本机独占锁被他人持有。典型场景是用户双击了两次图标，
    /// 或上一个实例还在托盘驻留。
    ///
    /// 为什么单列一个变体而不是复用 `Started`：两者的后续行为不同 ——
    /// `Started` 意味着「Runner 由我拉起、我能管它」，而这里 Runner 的 stdin
    /// 写端在别人手里，本实例**既下发不了策略也不能优雅停止它**。
    /// 混为一谈会让 UI 显示「一切正常」，实际本实例对执行引擎毫无控制权。
    ExternallyRunning,
}

/// 启动编排失败。
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// 读令牌失败（密钥链被锁/无权限）。
    #[error("读取设备令牌失败：{0}")]
    Vault(String),
    /// 写令牌失败。
    #[error("保存设备令牌失败：{0}")]
    VaultWrite(String),
    /// 拉起 Runner 失败。
    #[error("启动 Runner 失败：{0}")]
    Spawn(String),
}

/// 启动编排器。
pub struct Bootstrap {
    vault: Arc<dyn TokenVault>,
    daemon: Arc<Daemon>,
    /// Runner 可执行文件名（默认 `hd-runner` + 平台后缀）。
    ///
    /// 单包模式下这个名字**只在「显式路径 / 同目录独立文件」两种兜底场景**用到；
    /// 默认走自派生（宿主自身 + `--runner`），不依赖此文件名。
    runner_exe_name: String,
    /// 是否允许「宿主自身 + `--runner`」自派生。
    ///
    /// 🔴 **默认 true**（单包分发）。
    ///
    /// ## 曾经这里写的是「默认必须 false」，那是基于一次误判
    ///
    /// 旧注释称：链接了 Tauri 的 exe 被父进程经 `Stdio::piped()` 拉起时，Windows 下
    /// 会在加载期以 `0xC0000139` 崩溃。**该结论只在 `windows`（无控制台）子系统下成立。**
    ///
    /// 实测（2026-11，本仓库探针，复刻 `Stdio::piped()` + 写 stdin 的完整场景）：
    ///
    /// | 子系统 | GUI 双击 | 自派生 |
    /// | --- | --- | --- |
    /// | `windows` | 无黑框 | ❌ 加载期 `0xC0000139` |
    /// | `console` | 闪黑框 | ✅ 正常（进 main()、读 stdin、退出码 2，约 51ms） |
    ///
    /// `hd-host/src/main.rs` 已显式选择 console 子系统，因此自派生可用，
    /// 单包分发成为默认形态。代价是 GUI 双击时闪一下控制台窗口
    /// （可由 NSIS 快捷方式 `ShowWindow=Hidden` 规避，见 `scripts/build-exe.ps1`）。
    allow_self_derive: bool,
    /// 显式指定的 runner 路径（`None` 表示按约定搜索）。
    explicit_runner: Option<PathBuf>,
    /// 本地配对档案（记住 ws_url，重启后能连回同一台服务端）。
    ///
    /// `None` 时回退到硬编码默认地址（兼容旧调用方与单测）。
    profile_store: Option<Arc<dyn ProfileStore>>,
    /// WS 基址（用于日志与状态展示，实际地址在配对时已确定）。
    protocol_version: i32,
    /// 当前守卫策略的取值函数（守护循环重启后重放用）。
    ///
    /// 为什么要注入而不是直接读 `HostState`：`Bootstrap` 位于 `commands` 的下层，
    /// 反向依赖会让「状态层 → 编排层」出现环。注入一个 `Fn` 保持单向依赖，
    /// 同时让单测可以不构造整个 `HostState`。
    policy_source:
        Option<std::sync::Arc<dyn Fn() -> hd_core::security::guard::Policy + Send + Sync>>,
}

impl Bootstrap {
    /// 构造编排器。
    pub fn new(
        vault: Arc<dyn TokenVault>,
        daemon: Arc<Daemon>,
        runner_exe_name: impl Into<String>,
        protocol_version: i32,
    ) -> Self {
        Self {
            vault,
            daemon,
            runner_exe_name: runner_exe_name.into(),
            // 单包分发：默认启用自派生（详见字段文档的实测表）。
            allow_self_derive: true,
            explicit_runner: None,
            profile_store: None,
            protocol_version,
            policy_source: None,
        }
    }

    /// 注入「当前守卫策略」的取值函数（守护循环重启后重放用）。
    ///
    /// 不注入时回退为空白名单策略 —— 与 Runner 启动时的默认一致，
    /// 不会意外放宽或收紧权限。
    #[must_use]
    pub fn with_policy_source(
        mut self,
        f: std::sync::Arc<dyn Fn() -> hd_core::security::guard::Policy + Send + Sync>,
    ) -> Self {
        self.policy_source = Some(f);
        self
    }

    /// 注入本地档案存储（用于记住 ws_url）。
    ///
    /// 不注入时 `ensure_running` 回退到默认地址 —— 这让单测与旧调用方无需改动，
    /// 但**生产环境必须注入**，否则连非默认服务端时重启会连错地址。
    pub fn with_profile_store(mut self, store: Arc<dyn ProfileStore>) -> Self {
        self.profile_store = Some(store);
        self
    }

    /// 开关自派生（默认已开启；主要用于排查问题时**关闭**它）。
    ///
    /// 关闭后退化为「同目录独立 runner」路径，需要旁边真的存在 `hd-runner.exe`。
    pub fn with_self_derive(mut self, allow: bool) -> Self {
        self.allow_self_derive = allow;
        self
    }

    /// 显式指定 runner 路径。
    pub fn with_explicit_runner(mut self, path: Option<PathBuf>) -> Self {
        self.explicit_runner = path;
        self
    }

    /// 启动时调用：有令牌就拉起 Runner，没有就要求配对。
    ///
    /// **幂等**：Runner 已在运行时不重复 spawn —— 重复 spawn 会让同一设备
    /// 开两条 WS 连接，服务端会给旧连接发 `device.replaced` 并断开，
    /// 表现为「一启动就断线」的诡异现象。
    ///
    /// ## 两级幂等判据（缺一不可）
    ///
    /// 1. **本进程句柄**（`daemon.is_running()`）：覆盖「同一宿主重复调用
    ///    `ensure_running`」的场景（启动编排 + 配对完成各调一次）。
    /// 2. **本机独占锁**（[`InstanceLock`]）：覆盖「另一个宿主进程已经拉起过」的
    ///    场景。第 1 条看不见别的进程，只靠它会双开。
    pub async fn ensure_running(&self) -> Result<BootstrapOutcome, BootstrapError> {
        // ① 本进程已在运行 → 直接返回成功（幂等）。
        if self.daemon.is_running().await {
            tracing::debug!("Runner 已在运行，跳过重复拉起");
            return Ok(BootstrapOutcome::Started {
                device_id_hint: String::new(),
            });
        }

        // ② 读令牌。`Ok(None)` 是「未配对」，与「读失败」严格区分：
        //    前者引导用户去配对，后者要报错（可能是密钥链被锁）。
        //
        //    放在抢锁之前：没令牌时根本不需要拉起 Runner，也就不该占用实例锁
        //    （否则「未配对」的窗口会一直挡着另一个真能工作的实例）。
        let token = self
            .vault
            .get()
            .map_err(|e| BootstrapError::Vault(e.to_string()))?;
        let Some(token) = token else {
            return Ok(BootstrapOutcome::NeedsPairing);
        };

        // ③ 抢本机独占锁 —— 「本机有没有别的宿主已经在负责 Runner」的唯一可信判据。
        //
        //    为什么不能用「读 pid 再判进程存活」：pid 会被复用，会出现「明明没人在跑
        //    却拒绝启动」或「持锁者已崩溃却永远卡住」两类误判。OS 独占锁在进程以任何
        //    方式死亡时由内核释放，天然不留 stale。
        //
        //    锁在这里**交给 Daemon 持有**：它的生命周期必须覆盖 Runner 的整个运行期，
        //    若留在 `Bootstrap` 的局部变量里，函数一返回锁就释放，
        //    下一个宿主会立刻误判「没人在跑」并再 spawn 一份。
        if !self.acquire_instance_lock().await? {
            tracing::info!("本机已有执行引擎在运行，本实例不再拉起 Runner");
            return Ok(BootstrapOutcome::ExternallyRunning);
        }

        // ④ 定位 runner。
        let Some(launch) = locate_runner(
            self.explicit_runner.as_deref(),
            &self.runner_exe_name,
            self.allow_self_derive,
        ) else {
            let searched = match &self.explicit_runner {
                Some(p) => p.display().to_string(),
                None => format!(
                    "同目录 / resources 下的 {}{}",
                    self.runner_exe_name,
                    crate::daemon::exe_suffix()
                ),
            };
            tracing::warn!(searched = %searched, "找不到 Runner 可执行文件");
            // 拉起失败要把锁还回去，否则本机会一直显示「外部已在运行」而实际没人在跑。
            self.daemon.release_instance_lock();
            return Ok(BootstrapOutcome::RunnerMissing { searched });
        };

        // ④ 拉起。地址来自配对档案（重启后连回同一台服务端）。
        let ws_url = self.resolve_ws_url();
        self.daemon
            .spawn(&launch, &token, &ws_url, self.protocol_version)
            .await
            .map_err(|e| BootstrapError::Spawn(e.to_string()))?;

        Ok(BootstrapOutcome::Started {
            device_id_hint: String::new(),
        })
    }

    /// 守护循环：**Runner 意外退出后按策略自动重启**（需求②的核心）。
    ///
    /// ## 它做什么
    ///
    /// ```text
    /// loop {
    ///     exit = daemon.wait_exit()          // 阻塞到子进程死
    ///     action = guard.on_exit(exit)       // 纯逻辑决策（见 supervisor::Guard）
    ///     match action {
    ///         Stop    => 退出循环（含清令牌的 repair 分支）
    ///         Restart => 睡 delay → 重新 spawn → 重放工作区白名单 → 继续
    ///     }
    /// }
    /// ```
    ///
    /// ## 为什么重启后必须重放 policy
    ///
    /// Runner 每次启动的 `Policy` 来自 `initial_roots()`，那只是**进程当前目录**。
    /// 用户配置的精确白名单靠宿主经 `reload_policy` 下发。重启后若不重放，
    /// 白名单会静默回退成 CWD —— 表现为「重启后某些目录突然不能访问了」，
    /// 且日志里看不出异常（`reload_policy` 不会报错，它只是没被调用）。
    ///
    /// ## 为什么先睡退避再 spawn，而不是先 spawn 再睡
    ///
    /// 服务端可能正处于重启中。先睡能把「同时重连」的峰值摊平，
    /// 也避免在明显不可能成功时反复握手（每次握手都会在服务端留审计）。
    ///
    /// 返回最终停止的原因，供调用方更新 UI。
    pub async fn supervise(
        &self,
        guard: &mut crate::supervisor::Guard,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> crate::supervisor::GuardAction {
        use crate::supervisor::GuardAction;

        loop {
            // ① 阻塞等子进程退出。`None` 表示当前根本没有子进程（比如刚被 shutdown），
            //    此时没有「退出事件」可判定，直接结束循环。
            let Some(exit) = self.daemon.wait_exit().await else {
                return GuardAction::Stop {
                    phase: self.daemon.stats().state(),
                    repair: false,
                };
            };

            // ② 用户主动停止：立刻结束，不进入退避。
            if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                return GuardAction::Stop {
                    phase: self.daemon.stats().state(),
                    repair: false,
                };
            }

            // ③ 决策（纯逻辑，已单测穷举）。
            let action = guard.on_exit(exit, crate::lifecycle::RunnerPhase::Running);

            match action {
                GuardAction::Stop { phase, repair } => {
                    if repair {
                        // 令牌已失效：清掉本地凭据，让用户重新配对。
                        // 顺序：先清档案再清令牌 —— 档案是明文，令牌在密钥链，
                        // 若中途失败，至少不会留下「有令牌但连错服务器」的状态。
                        if let Some(store) = self.profile_store.as_ref() {
                            let _ = store.clear();
                        }
                        let _ = self.vault.clear();
                        tracing::warn!("Runner 终止且需重新配对，本地凭据已清理");
                    }
                    self.daemon.stats().set_state(phase);
                    return GuardAction::Stop { phase, repair };
                }
                GuardAction::Restart { attempt, delay } => {
                    self.daemon
                        .stats()
                        .set_state(crate::lifecycle::RunnerPhase::Backoff);
                    tracing::info!(attempt, delay = ?delay, "Runner 已退出，退避后重启");

                    // ④ 退避等待，但**逐段检查** shutdown：用户可能在这期间点退出，
                    //    若一次性 sleep 完整 delay，退出最多要等 30 秒才生效。
                    if wait_or_shutdown(delay, &shutdown).await {
                        return GuardAction::Stop {
                            phase: self.daemon.stats().state(),
                            repair: false,
                        };
                    }

                    // ⑤ 重新拉起（复用完整编排：读令牌 → 定位 → spawn）。
                    match self.ensure_running().await {
                        Ok(BootstrapOutcome::Started { .. }) => {
                            // ⑥ 重放工作区白名单（见上文「为什么必须重放」）。
                            let policy = self.current_policy();
                            if let Err(e) = self.daemon.reload_policy(&policy).await {
                                // 重放失败不该终止守护：下一轮重启还能再试，
                                // 且 Runner 至少已经起来了（用 CWD 兜底）。
                                tracing::warn!(error = %e, "重启后重放工作区白名单失败");
                            }
                            tracing::info!(attempt, "Runner 已重新拉起");
                        }
                        Ok(other) => {
                            // 未配对 / 外部实例接管 / 找不到 exe —— 都不该继续循环。
                            tracing::warn!(outcome = ?other, "重启未能拉起 Runner，结束守护");
                            return GuardAction::Stop {
                                phase: crate::lifecycle::RunnerPhase::GaveUp,
                                repair: false,
                            };
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "重启失败，结束守护");
                            return GuardAction::Stop {
                                phase: crate::lifecycle::RunnerPhase::GaveUp,
                                repair: false,
                            };
                        }
                    }
                }
            }
        }
    }

    /// 当前生效的守卫策略快照（供重启后重放下发）。
    ///
    /// 用 `bearer_policy()` 这类「外部注入」的方式会让循环依赖变复杂，
    /// 故这里让调用方通过 [`Bootstrap::with_policy_source`] 注入一个取值函数；
    /// 未注入时回退为「空白名单 + 不限工具」，与 Runner 启动时的默认一致。
    fn current_policy(&self) -> hd_core::security::guard::Policy {
        match self.policy_source.as_ref() {
            Some(f) => f(),
            None => hd_core::security::guard::Policy::new(Vec::new(), Vec::new()),
        }
    }

    /// 抢占本机实例锁（薄包装：把 `io::Error` 翻成 `BootstrapError`）。
    ///
    /// 抽出来是为了让 `ensure_running` 的主流程读起来只有「读令牌 → 抢锁 → 定位 → 拉起」
    /// 四步，不被错误映射干扰。
    async fn acquire_instance_lock(&self) -> Result<bool, BootstrapError> {
        self.daemon
            .acquire_instance_lock()
            .map_err(|e| BootstrapError::Spawn(format!("实例锁不可用：{e}")))
    }

    /// 配对成功后调用：**先落令牌，再拉起 Runner**。
    ///
    /// 顺序不可颠倒：若先 spawn 后落盘而落盘失败，用户会遇到「这次能用、重启后
    /// 又要重新配对，但 Runner 已经在跑」的不一致状态。
    pub async fn on_paired(&self, paired: PairedDevice) -> Result<(), BootstrapError> {
        // ① 先持久化令牌。失败则**不拉起**。
        self.vault
            .set(&paired.token)
            .map_err(|e| BootstrapError::VaultWrite(e.to_string()))?;

        // ② 持久化「连哪台服务端」，供重启后自动连回。
        //
        // 失败不让整个流程失败：档案丢了最多下次回退默认地址，而令牌已存，
        // 当前这次配对仍然可用。这种「尽量记住但不阻断」的处理比整体失败更实用。
        if let Some(store) = self.profile_store.as_ref() {
            let profile = crate::profile::Profile::new(
                paired.server_base_url.clone(),
                paired.ws_url.clone(),
                paired.device_id.clone(),
                paired.protocol_version,
                crate::daemon::now_ms(),
            );
            if let Err(e) = store.save(&profile) {
                tracing::warn!(error = %e, "保存配对档案失败（不影响本次配对）");
            }
        }

        // ③ 幂等：已在跑就不重复拉起。
        if self.daemon.is_running().await {
            tracing::debug!("Runner 已在运行，配对后不重复拉起");
            return Ok(());
        }

        // ④ 定位并拉起。
        let Some(launch) = locate_runner(
            self.explicit_runner.as_deref(),
            &self.runner_exe_name,
            self.allow_self_derive,
        ) else {
            return Err(BootstrapError::Spawn(format!(
                "找不到 Runner 可执行文件（{}）",
                self.runner_exe_name
            )));
        };

        self.daemon
            .spawn(
                &launch,
                &paired.token,
                &paired.ws_url,
                paired.protocol_version,
            )
            .await
            .map_err(|e| BootstrapError::Spawn(e.to_string()))?;

        tracing::info!(
            device_id = %paired.device_id,
            "配对完成，Runner 已拉起"
        );
        Ok(())
    }

    /// 取「重启后该连哪台服务端」的 WS 地址。
    ///
    /// 优先读本地档案（配对时记下的真实地址）；档案缺失/损坏时回退到默认地址。
    /// 回退是必要的：首次升级的老用户磁盘上没有档案文件，不能因此连不上。
    fn resolve_ws_url(&self) -> String {
        if let Some(store) = self.profile_store.as_ref() {
            match store.load() {
                Ok(Some(p)) if p.is_usable() => return p.ws_url,
                Ok(_) => {
                    tracing::debug!("无可用配对档案，回退到默认服务端地址");
                }
                Err(e) => {
                    // 档案读失败不阻止启动：回退默认地址，让用户至少能尝试连接。
                    tracing::warn!(error = %e, "读取配对档案失败，回退到默认地址");
                }
            }
        }
        default_ws_url()
    }
}

/// 默认服务端地址（档案缺失时的回退值）。
///
/// 对齐 `harness_go` 的默认监听端口（`internal/config/config.go` 的
/// `Default().Server.Addr` = `:5611`，且项目约定用 `127.0.0.1` 而非 `localhost`）。
pub fn default_ws_url() -> String {
    "ws://127.0.0.1:5611/api/v1/devices/ws".to_string()
}

/// 默认服务端 HTTP 基址（配对用）。
///
/// 与 [`default_ws_url`] 同源（同一台机器的 5611 端口），只是协议不同。
pub fn default_http_url() -> String {
    "http://127.0.0.1:5611".to_string()
}

/// 从令牌是否存在推断是否需要配对（供 UI 首屏判断，不发网络请求）。
pub fn needs_pairing(vault: &dyn TokenVault) -> bool {
    // 读失败按「需要配对」处理：报「已配对」会让用户以为不用重新登录，
    // 实际谁都连不上（与 `commands::device_status` 的取舍一致）。
    !matches!(vault.get(), Ok(Some(_)))
}

/// 退避等待，但**逐段检查**用户是否要求停止。
///
/// 返回 `true` 表示「等待期间被要求停止，调用方应放弃重启」。
///
/// 为什么不用 `tokio::select!` 配合通知 channel：这里的取消源只有一个原子标志，
/// 每 100ms 轮询一次足够（最坏多等 100ms，相对 1~30s 的退避可忽略），
/// 而不必引入 broadcast/watch 这类需要管理生命周期的原语。
async fn wait_or_shutdown(
    total: std::time::Duration,
    shutdown: &std::sync::atomic::AtomicBool,
) -> bool {
    use std::sync::atomic::Ordering;
    const SLICE: std::time::Duration = std::time::Duration::from_millis(100);

    let mut remaining = total;
    while !remaining.is_zero() {
        if shutdown.load(Ordering::SeqCst) {
            return true;
        }
        let step = remaining.min(SLICE);
        tokio::time::sleep(step).await;
        remaining = remaining.saturating_sub(step);
    }
    shutdown.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{DeviceToken, MemoryVault};
    use hd_runner::reconnect::ReconnectPolicy;

    fn bootstrap_with(vault: Arc<dyn TokenVault>) -> Bootstrap {
        let daemon = Arc::new(Daemon::new(ReconnectPolicy::default()));
        Bootstrap::new(vault, daemon, "hd-runner-does-not-exist-xyz", 1)
    }

    #[tokio::test]
    async fn needs_pairing_when_vault_empty() {
        let vault = Arc::new(MemoryVault::new());
        let b = bootstrap_with(vault);
        assert_eq!(
            b.ensure_running().await.unwrap(),
            BootstrapOutcome::NeedsPairing
        );
    }

    #[tokio::test]
    async fn runner_missing_reports_search_path() {
        // 有令牌但**所有启动方式都定位不到** → 明确告知，而不是静默失败。
        //
        // 单包模式下默认走自派生（`current_exe()` 在测试进程里总是可用），
        // 因此必须显式关掉自派生才能触发 RunnerMissing 分支。
        let vault = Arc::new(MemoryVault::new());
        vault.set(&DeviceToken::new("hgd_test".into())).unwrap();
        let b = bootstrap_with(vault).with_self_derive(false);
        match b.ensure_running().await.unwrap() {
            BootstrapOutcome::RunnerMissing { searched } => {
                assert!(searched.contains("hd-runner-does-not-exist-xyz"));
            }
            other => panic!("期望 RunnerMissing，实际 {other:?}"),
        }
    }

    #[test]
    fn needs_pairing_helper_matches_vault_state() {
        let vault = MemoryVault::new();
        assert!(needs_pairing(&vault));
        vault.set(&DeviceToken::new("hgd_x".into())).unwrap();
        assert!(!needs_pairing(&vault));
    }

    #[test]
    fn self_derive_is_on_by_default_for_single_package() {
        // 单包分发依赖自派生：宿主 exe 通过 `--runner` 拉起自己的第二个进程。
        //
        // 历史注记：这里曾经断言 `!allow_self_derive`（护栏），依据是「Windows 上
        // 自派生必崩 0xC0000139」。后续实测证明该结论只适用于 `windows` 子系统；
        // `console` 子系统下自派生正常（详见字段文档的对照表），故默认值改为 true。
        // 若将来有人把子系统改回 `windows`，本测试仍会通过，但运行时自派生会崩 ——
        // 因此 `main.rs` 里必须保留 console 子系统，那条注释是真正的护栏。
        let vault = Arc::new(MemoryVault::new());
        let b = bootstrap_with(vault);
        assert!(b.allow_self_derive);
    }

    #[test]
    fn self_derive_can_be_disabled_for_debugging() {
        // 保留关闭能力：排查「是不是自派生导致的问题」时把它关掉，
        // 退化为同目录独立 runner。
        let vault = Arc::new(MemoryVault::new());
        let b = bootstrap_with(vault).with_self_derive(false);
        assert!(!b.allow_self_derive);
    }
}
