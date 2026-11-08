//! # hd-core —— 端侧执行面地基（执行器抽象 + 安全闸门）
//!
//! 本 crate 是桌面端 Runner 里**唯一能触达执行面**的领域层，按
//! `docs/桌面端架构与功能设计.md` §14.2 / §16 落地。三条硬性约束写在类型系统里：
//!
//! 1. **无网络依赖**：依赖树里没有 reqwest / tokio-tungstenite，tokio 也不启用 `net`
//!    feature → 安全逻辑可在无网络的离线环境（CI / 断网机器）完整单测。
//! 2. **端侧结果恒不可信**（不变量 4）：[`SourceTrust`] 只有 `Untrusted` 一个变体，
//!    「把结果标成可信」这件事在 Rust 里根本无法构造出来。
//! 3. **端侧永不直写 DB**（不变量 1）：审计走 [`security::guard::AuditSink`] 本地 sink，
//!    本 crate 不认识任何数据库/HTTP 类型。
//!
//! 唯一合法的执行入口是 [`security::guard::Guarded<E>`]：router 只持有它，拿不到裸 executor，
//! 因此绕过安全闸门在类型层面不可能发生（§16.2）。
#![deny(unsafe_code)]

pub mod executor;
pub mod security;

pub use executor::fs::{DirEntry, DirListing, ListDirsExecutor, FS_MAX_DIRS};
pub use executor::{
    ExecCtx, ExecError, ExecOutput, Executor, Limits, NoopSink, ProgressSink, SourceTrust,
};
pub use security::guard::{AuditEvent, AuditOutcome, AuditSink, Guarded, NullAuditSink, Policy};
