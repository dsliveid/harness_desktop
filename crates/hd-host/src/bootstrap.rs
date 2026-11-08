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
            protocol_version,
        }
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

        // ④ 拉起。注意：ws_url 来自持久化的配对信息，此处不重新配对。
        //    若将来需要持久化 ws_url，应一并存入密钥链旁的配置项；
        //    当前版本由调用方在 `on_paired` 后已知道地址，故这里用占位说明。
        let ws_url = self.ws_url_placeholder();
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
        // ① 先持久化。失败则**不拉起**。
        self.vault
            .set(&paired.token)
            .map_err(|e| BootstrapError::VaultWrite(e.to_string()))?;

        // ② 幂等：已在跑就不重复拉起。
        if self.daemon.is_running().await {
            tracing::debug!("Runner 已在运行，配对后不重复拉起");
            return Ok(());
        }

        // ③ 定位并拉起。
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

    /// `ensure_running` 用的 WS 地址。
    ///
    /// 说明：完整地址本应在配对时持久化（`ws_url` 与令牌一同保存）。当前版本
    /// 尚未引入「配对信息持久化」，故 `ensure_running` 只能使用约定地址；
    /// 这在**单机自用**场景（固定 `127.0.0.1:5611`）下成立。
    /// 待办：把 ws_url 一并存入本地配置，使重启后能连任意服务端。
    fn ws_url_placeholder(&self) -> String {
        // 保持与 commands::HostState 的默认服务端地址一致。
        "ws://127.0.0.1:5611/api/v1/devices/ws".to_string()
    }
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
