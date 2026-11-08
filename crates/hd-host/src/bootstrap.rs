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
    /// 有令牌但找不到 Runner 可执行文件。
    ///
    /// 这是**打包/部署**问题（用户只拷了 hd-host.exe 而漏了 hd-runner.exe），
    /// 与配对无关，故单独一个分支以便 UI 给出可操作提示。
    RunnerMissing {
        /// 已搜索的路径描述，便于用户自查。
        searched: String,
    },
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
    runner_exe_name: String,
    /// 是否允许「宿主自身 + `--runner`」自派生。
    ///
    /// 🔴 **默认必须为 false**：链接了 Tauri 的 exe 被父进程经 `Stdio::piped()`
    /// 拉起时，Windows 下会在加载期以 `0xC0000139` 崩溃（stderr 为空，从未进入
    /// `main()`）；而独立的 `hd-runner.exe` 走同一条 spawn 路径完全正常。
    /// 这是 Tauri 加载期初始化与管道子进程上下文的冲突，不是业务逻辑缺陷。
    /// 详见 `docs/桌面端架构与功能设计.md` §3.2.1 的实测记录。
    allow_self_derive: bool,
    /// 显式指定的 runner 路径（`None` 表示按约定搜索）。
    explicit_runner: Option<PathBuf>,
    /// 本地配对档案（记住 ws_url，重启后能连回同一台服务端）。
    ///
    /// `None` 时回退到硬编码默认地址（兼容旧调用方与单测）。
    profile_store: Option<Arc<dyn ProfileStore>>,
    /// WS 基址（用于日志与状态展示，实际地址在配对时已确定）。
    protocol_version: i32,
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
            allow_self_derive: false,
            explicit_runner: None,
            profile_store: None,
            protocol_version,
        }
    }

    /// 注入本地档案存储（用于记住 ws_url）。
    ///
    /// 不注入时 `ensure_running` 回退到默认地址 —— 这让单测与旧调用方无需改动，
    /// 但**生产环境必须注入**，否则连非默认服务端时重启会连错地址。
    pub fn with_profile_store(mut self, store: Arc<dyn ProfileStore>) -> Self {
        self.profile_store = Some(store);
        self
    }

    /// 开启自派生（仅非 Windows 平台或已验证可用的环境使用）。
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
    pub async fn ensure_running(&self) -> Result<BootstrapOutcome, BootstrapError> {
        // ① 已在运行 → 直接返回成功（幂等）。
        if self.daemon.is_running().await {
            tracing::debug!("Runner 已在运行，跳过重复拉起");
            return Ok(BootstrapOutcome::Started {
                device_id_hint: String::new(),
            });
        }

        // ② 读令牌。`Ok(None)` 是「未配对」，与「读失败」严格区分：
        //    前者引导用户去配对，后者要报错（可能是密钥链被锁）。
        let token = self
            .vault
            .get()
            .map_err(|e| BootstrapError::Vault(e.to_string()))?;
        let Some(token) = token else {
            return Ok(BootstrapOutcome::NeedsPairing);
        };

        // ③ 定位 runner。
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
        // 有令牌但 runner 不存在 → 明确告知是部署问题，而不是静默失败
        let vault = Arc::new(MemoryVault::new());
        vault.set(&DeviceToken::new("hgd_test".into())).unwrap();
        let b = bootstrap_with(vault);
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
    fn self_derive_is_off_by_default() {
        // 这条是安全/稳定性护栏：自派生在 Windows 上实测崩溃（§3.2.1），
        // 若有人把默认值改成 true，本测试会立刻失败。
        let vault = Arc::new(MemoryVault::new());
        let b = bootstrap_with(vault);
        assert!(!b.allow_self_derive);
    }
}
