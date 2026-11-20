//! harness_desktop 执行引擎 Runner。
//!
//! ## 已实现范围（截至 `fcf9dbe` 接通 fs.list 端到端）
//!
//! - **连接面**：`transport`（WS 连接 / Session）、`ipc`（stdio 首行 auth 控制面）；
//! - **节奏面**：`heartbeat`（间隔必须来自 `welcome`）、`reconnect`（退避决策）；
//! - **执行面**：`supervisor`（守护主循环 / 派发编排 / 并发上限）、`router`
//!   （`task.dispatch` → `Guarded<E>` 执行 → `task.result`）、`idempot`（TTL 幂等回放）、
//!   `frames::fs_list`（`fs.list` 帧编解）、`capabilities`（能力申报，派生自
//!   [`Router::tool_names`]，不维护手写常量数组）。
//!
//! 🔴 **执行器与安全闸门不在本 crate**：`Guarded` / `Policy` / `ListDirsExecutor` 全部由
//! `hd-core` 实现，本 crate 只**接入**（`router.rs` 的 `ToolTable` 里只可能存在
//! `Guarded<E>`，见该文件头 §16.2 的类型级保证）。设计依据见
//! `docs/桌面端架构与功能设计.md` §16.2 / §19。
//!
//! ## 分层原则
//!
//! 纯逻辑（`heartbeat` / `reconnect`）与 IO（`transport`）严格分离：
//! 前者可在无网络环境秒级单测，后者由 `hd-testkit` 假服务端做 e2e。
//! 这个划分让「心跳间隔必须来自 welcome」这类约束能被钉死在单测里，
//! 而不是靠代码评审记忆。

pub mod capabilities;
pub mod cli;
pub mod frames;
pub mod heartbeat;
pub mod idempot;
pub mod ipc;
pub mod progress;
pub mod reconnect;
pub mod router;
pub mod supervisor;
pub mod transport;

pub use capabilities::{capabilities_hash, capabilities_of, snapshot as capabilities_snapshot};
pub use cli::{run_cli, EXIT_NO_AUTH};
pub use frames::{error_envelope, fs_list_result_envelope, FrameOutcome};
pub use heartbeat::HeartbeatPolicy;
pub use idempot::{
    ClaimGuard, ClaimResult, Clock, IdempotStore, SystemClock, DEFAULT_CAPACITY, DEFAULT_TTL,
};
pub use ipc::{parse_auth_first_line, parse_command, AuthConfig, IpcCommand, IpcError, IpcReader};
pub use progress::ChannelSink;
pub use reconnect::{ReconnectDecision, ReconnectPolicy};
pub use router::{CollectingSink, Router, CODE_DEVICE_TIMEOUT, STATUS_FAILED, STATUS_SUCCESS};
pub use supervisor::{
    Connector, LiveLink, NoopObserver, NoopSleeper, Sleeper, StopReason, Supervisor,
    SupervisorEvent, SupervisorObserver, TokioSleeper, WsConnector, DEFAULT_MAX_CONCURRENCY,
    FS_FRAME_MAX_CONCURRENCY,
};
pub use transport::{Connection, Session, TransportError};
