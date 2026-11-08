//! # hd-host —— 桌面宿主壳（Tauri 2）
//!
//! 按 `docs/桌面端架构与功能设计.md` §17 落地。宿主的职责边界很窄：
//! **管好令牌、管好子进程、把能力以固定接口暴露给前端**。它自己不执行任何用户命令，
//! 那是 Runner 的活（见 `hd-runner` / `hd-core`）。
//!
//! ## 为什么 GUI 依赖是可选 feature
//!
//! Tauri 2 在 Windows 上要链接 WebView2、在 Linux 上要系统 webkit2gtk，无图形环境的
//! CI 装不出来。而本 crate 里**真正需要单测的逻辑（令牌保管、进程守护、command 语义）**
//! 与 GUI 毫无关系。因此分两层：
//!
//! - **纯逻辑层**（默认，无任何 GUI 依赖）：[`vault`] / [`daemon`] / [`commands`]。
//!   `cargo test -p hd-host` 在任何环境都能跑。
//! - **GUI 层**（feature `gui`）：`gui` 模块把纯逻辑函数包成 `#[tauri::command]`，
//!   `main.rs` 里组装 builder。
//!
//! 这个划分不是为省编译时间，而是为了让「安全语义的单测」不依赖图形栈 ——
//! 否则一旦 CI 环境变化，最该被守住的那几十条断言会最先消失。
#![deny(unsafe_code)]

pub mod boot_state;
pub mod bootstrap;
pub mod commands;
pub mod daemon;
pub mod pairing;
pub mod profile;
pub mod vault;

#[cfg(feature = "gui")]
pub mod gui;

pub use boot_state::{plan_boot, BootStateKind, BootUiState};
pub use bootstrap::{default_ws_url, needs_pairing, Bootstrap, BootstrapError, BootstrapOutcome};
pub use commands::{
    device_status, get_workspace_roots, list_commands, runner_status, set_workspace_roots,
    start_pairing, CommandError, DeviceStatusResponse, HostState, ListCommandsResponse,
    RunnerStatusResponse, StartPairingResponse, FORBIDDEN_COMMANDS, SUPPORTED_COMMANDS,
};
pub use daemon::{
    build_auth_line, build_reload_policy_line, exe_suffix, locate_runner, Daemon, DaemonError,
    ExitRecord, LineRing, RunnerState, RuntimeStats, StdinHandle, LOG_RING_CAPACITY,
};
pub use pairing::{ws_url_from, PairedDevice, PairingClient, PairingError};
pub use profile::{FileProfileStore, MemoryProfileStore, Profile, ProfileError, ProfileStore};
pub use vault::{
    default_vault, DeviceToken, MemoryVault, PlatformVault, TokenVault, VaultError,
    KEYRING_SERVICE, KEYRING_USER,
};
