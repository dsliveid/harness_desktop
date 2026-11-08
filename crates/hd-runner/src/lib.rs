//! harness_desktop 执行引擎 Runner。
//!
//! 当前阶段（P2）已实现：WS 连接、`welcome` 握手、心跳节奏驱动、重连决策。
//! 尚未实现（P3+）：任务派发路由、执行器、安全闸门 —— 见
//! `docs/桌面端架构与功能设计.md` §19。
//!
//! ## 分层原则
//!
//! 纯逻辑（`heartbeat` / `reconnect`）与 IO（`transport`）严格分离：
//! 前者可在无网络环境秒级单测，后者由 `hd-testkit` 假服务端做 e2e。
//! 这个划分让「心跳间隔必须来自 welcome」这类约束能被钉死在单测里，
//! 而不是靠代码评审记忆。

pub mod cli;
pub mod heartbeat;
pub mod idempot;
pub mod ipc;
pub mod progress;
pub mod reconnect;
pub mod router;
pub mod supervisor;
pub mod transport;

pub use cli::{run_cli, EXIT_NO_AUTH};
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
};
pub use transport::{Connection, Session, TransportError};
