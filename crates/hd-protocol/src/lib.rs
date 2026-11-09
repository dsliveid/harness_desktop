//! harness_desktop 设备协议线格式。
//!
//! 本 crate 是 Go 侧 `internal/device/protocol.go` 的 Rust 镜像，**唯一职责**是把
//! 线上 JSON 映射成强类型结构体。它不含任何 IO、网络、异步运行时依赖 —— 详见
//! `Cargo.toml` 的依赖红线。
//!
//! ## 为什么必须镜像而非复用
//!
//! `harness-go/internal/device` 是 Go 的 internal 包，跨模块编译器禁止 import；
//! 且服务端二进制硬依赖 `//go:embed web/dist`，无法瘦身成客户端。故协议在 Rust 侧
//! 重写一遍，用 `fixtures/` 黄金样本门禁锁死漂移（见 `tests/golden_fixtures.rs`）。
//!
//! ## 向后兼容铁律
//!
//! 与 Go 侧同规格：**只允许新增字段**，禁止删除/改名/改类型。所有 payload 字段都带
//! `#[serde(default)]`，保证「旧服务端缺字段」与「新服务端多字段」双向可解析。

pub mod envelope;
pub mod error_code;
pub mod exit_code;
pub mod payload;

pub use envelope::{
    compatible_version, supported_versions, Envelope, MessageType, ProtocolError,
    CURRENT_PROTOCOL_VERSION, MIN_PROTOCOL_VERSION,
};
pub use exit_code::{
    requires_repair, should_restart, ALL as EXIT_CODES, EXIT_GENERIC_FAILURE, EXIT_NO_AUTH,
    EXIT_OK, EXIT_PROTOCOL_MISMATCH, EXIT_REPLACED, EXIT_RETRYABLE, EXIT_REVOKED,
};
pub use payload::{
    Capability, ErrorPayload, HelloPayload, LeaseRevokedPayload, PingPayload, PongPayload,
    SourceTrust, TaskDispatchPayload, TaskProgressPayload, TaskResultPayload, WelcomePayload,
};
