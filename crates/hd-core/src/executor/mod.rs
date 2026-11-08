//! 执行器抽象（设计文档 §16.1）。
//!
//! 这是「执行面」唯一的对外接口：router 拿到的是 `Arc<dyn Executor>`
//! （实际永远是 [`crate::security::guard::Guarded`]），executor 只能看到
//! 本次派发的 [`ExecCtx`]、参数 JSON 和一个进度出口，**看不到任何连接/令牌/数据库**。
//!
//! 关键取舍：
//! - `deadline` 用 [`std::time::Instant`] 而不是 `SystemTime`：调度时限必须走单调时钟，
//!   否则用户改系统时间（或 NTP 校正）会让「已超时」凭空变回「还没超时」。
//! - `tool_name` 返回 `&'static str`：工具名是编译期常量，避免运行期拼串被注入。
//! - [`Limits`] 只能由 executor 声明**上限**，真正生效的时限是它与 ctx.deadline 的较小值，
//!   由 router 取小（executor 无权给自己放宽）。

pub mod fs;

use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// 执行上下文：由 router 从 `TaskDispatchPayload` 构造，**executor 不可伪造**。
#[derive(Debug, Clone)]
pub struct ExecCtx {
    /// 服务端下发的 tool_event_id，审计与 result 回执都要带它做关联。
    pub tool_event_id: String,
    /// 所属 run，用于把同一轮执行的多个工具事件串起来。
    pub run_id: String,
    /// 本地单调时钟上的硬截止时间（已从服务端的墙钟时限换算过来）。
    pub deadline: Instant,
    /// 重试次数（首次为 0）。重试要能被 executor 感知，才能做「幂等工具直接重放」的判断。
    pub attempt: i32,
}

impl ExecCtx {
    /// 以「从现在起 timeout」构造上下文，测试与本地调试用。
    pub fn with_timeout(
        tool_event_id: impl Into<String>,
        run_id: impl Into<String>,
        timeout: Duration,
        attempt: i32,
    ) -> Self {
        Self {
            tool_event_id: tool_event_id.into(),
            run_id: run_id.into(),
            deadline: Instant::now() + timeout,
            attempt,
        }
    }

    /// 距截止还剩多久；已过期返回 `Duration::ZERO`（而不是 panic 或负数）。
    pub fn remaining(&self) -> Duration {
        self.deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO)
    }

    /// 是否已过期。长耗时 executor 应在关键阶段之间自查，主动提前退出而不是硬撑到被砍。
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

/// 工具自带的上限声明。默认值刻意保守：宁可早失败，也不要卡住 Runner 的心跳。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// 单次执行超时上限。
    pub timeout: Duration,
    /// 结果与流式输出的总字节上限（router 据此截断，避免一条巨大的 stdout 撑爆 WS 帧）。
    pub max_output_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // 30s：比服务端默认工具超时更短，端侧先失败才能及时上报而不是静默挂住
            timeout: Duration::from_secs(30),
            // 1MB：单帧上限的保守取值，超过就该分流/截断而不是硬塞进一帧
            max_output_bytes: 1024 * 1024,
        }
    }
}

/// 流式输出出口（stdout 边产边发）。用 `&dyn` 而非泛型，避免把 sink 类型泄漏进 trait 签名。
pub trait ProgressSink: Send + Sync {
    /// 追加一段输出。实现方自行保证不阻塞（可能是被限流的 channel send）。
    fn chunk(&self, s: &str);
}

/// 什么都不做的 sink：非流式工具、单测、以及「还没接上流式通道」的阶段都用它。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSink;

impl ProgressSink for NoopSink {
    fn chunk(&self, _s: &str) {}
}

/// 端侧结果的来源可信度。
///
/// 🔴 **不变量 4：端侧结果恒不可信。** 这里刻意**只提供 `Untrusted` 一个变体**：
/// 想让结果变可信，必须先在类型里存在 `Trusted`，而它不存在——
/// 于是「误标可信」从「代码评审要盯住的纪律」降级成「编译器直接拒绝」。
/// 任何「为了对称而补一个 Trusted」的改动都等于拆掉不变量，禁止。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceTrust {
    #[default]
    #[serde(rename = "untrusted")]
    Untrusted,
}

impl SourceTrust {
    /// 线格式字面量，需与服务端 `model.Capability` 同侧的可信度取值保持一致。
    pub fn as_str(self) -> &'static str {
        match self {
            SourceTrust::Untrusted => "untrusted",
        }
    }
}

/// 一次执行的产物。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecOutput {
    pub result: serde_json::Value,
    /// 恒为 `Untrusted`，字段保留是为了让线格式显式带上它（服务端要看到这个声明）。
    pub source_trust: SourceTrust,
}

impl ExecOutput {
    /// 唯一推荐的构造方式：强制 Untrusted，调用方连「填别的值」的机会都没有。
    pub fn untrusted(result: serde_json::Value) -> Self {
        Self {
            result,
            source_trust: SourceTrust::Untrusted,
        }
    }
}

impl From<serde_json::Value> for ExecOutput {
    fn from(result: serde_json::Value) -> Self {
        Self::untrusted(result)
    }
}

/// 执行失败原因。
///
/// 文案与错误码对齐服务端 `harness_go/internal/apperr/apperr.go:82-84` 的
/// `fs.path_denied` / `fs.path_not_found`（**用手写字面量而不是依赖 hd-protocol**：
/// hd-core 是被 hd-protocol 之外的所有层引用的叶子，反向依赖会成环）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecError {
    /// 路径越界/含穿越段/不在白名单：一律按「拒绝」处理，不回显系统细节。
    #[error("该目录不在允许的范围内：{path}")]
    PathDenied { path: String },

    /// 路径不存在（404 语义）。与 PathDenied 分开，前端才能区分「没权限」和「打错了」。
    #[error("目录不存在：{path}")]
    PathNotFound { path: String },

    /// 超出 deadline 或自带 limits。
    #[error("执行超时")]
    Timeout,

    /// 底层 IO 错误（已转成文本，不把 OS 错误结构泄漏到上层）。
    #[error("IO 错误：{0}")]
    Io(String),

    /// 参数不合法（缺字段、类型不对）。必须在触达文件系统之前就拒绝。
    #[error("参数不合法：{0}")]
    BadArgs(String),

    /// 工具/能力未授权（不在 exec_allowlist、或端侧未声明该能力）。
    #[error("不允许执行：{0}")]
    NotAllowed(String),
}

impl ExecError {
    /// 映射到服务端 `apperr` 错误码；仅路径类有确定的跨端码，其余返回 `None`
    /// （端侧内部错误不该被伪装成服务端已定义的错误码，否则前端会按错误码做出错误决策）。
    pub fn apperr_code(&self) -> Option<&'static str> {
        match self {
            // 出处：harness_go/internal/apperr/apperr.go:82
            ExecError::PathDenied { .. } => Some("fs.path_denied"),
            // 出处：harness_go/internal/apperr/apperr.go:84
            ExecError::PathNotFound { .. } => Some("fs.path_not_found"),
            _ => None,
        }
    }

    /// 供审计与日志使用的稳定分类名（不随文案变化）。
    pub fn kind(&self) -> &'static str {
        match self {
            ExecError::PathDenied { .. } => "path_denied",
            ExecError::PathNotFound { .. } => "path_not_found",
            ExecError::Timeout => "timeout",
            ExecError::Io(_) => "io",
            ExecError::BadArgs(_) => "bad_args",
            ExecError::NotAllowed(_) => "not_allowed",
        }
    }
}

/// 执行器。实现者只关心「怎么做」，不关心「准不准做」（那是 [`crate::security::guard::Guarded`] 的事）。
#[async_trait]
pub trait Executor: Send + Sync {
    /// 工具名，需与服务端 dispatch 的工具名逐字一致（如 `fs.list`）。
    fn tool_name(&self) -> &'static str;

    /// 声明默认超时与最大输出；router 会与 deadline 取小值。
    fn limits(&self) -> Limits {
        Limits::default()
    }

    /// 执行。实现时**必须**在触达 IO 前校验参数，失败立刻返回，不要「先做了再说」。
    async fn execute(
        &self,
        ctx: &ExecCtx,
        args: &serde_json::Value,
        sink: &dyn ProgressSink,
    ) -> Result<ExecOutput, ExecError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_trust_serializes_as_untrusted_literal() {
        let s = serde_json::to_string(&SourceTrust::Untrusted).expect("serialize");
        assert_eq!(s, "\"untrusted\"");
        let back: SourceTrust = serde_json::from_str("\"untrusted\"").expect("deserialize");
        assert_eq!(back, SourceTrust::Untrusted);
    }

    #[test]
    fn source_trust_rejects_trusted_literal() {
        // 编译期没有 Trusted 变体，运行期也无法从线格式「诱惑」出一个可信值
        let err = serde_json::from_str::<SourceTrust>("\"trusted\"").unwrap_err();
        assert!(err.to_string().contains("unknown variant"), "{err}");
    }

    #[test]
    fn exec_output_is_always_untrusted() {
        let out = ExecOutput::untrusted(serde_json::json!({ "a": 1 }));
        assert_eq!(out.source_trust, SourceTrust::Untrusted);
        // 序列化后字节层面也必须带 untrusted
        let s = serde_json::to_string(&out).expect("serialize");
        assert!(s.contains("\"source_trust\":\"untrusted\""), "{s}");
    }

    #[test]
    fn limits_default_is_conservative() {
        let l = Limits::default();
        assert_eq!(l.timeout, Duration::from_secs(30));
        assert_eq!(l.max_output_bytes, 1024 * 1024);
        assert!(l.timeout <= Duration::from_secs(60), "默认超时不该超过 60s");
    }

    #[test]
    fn exec_ctx_remaining_and_expiry() {
        let ctx = ExecCtx::with_timeout("evt-1", "run-1", Duration::from_millis(50), 0);
        assert!(!ctx.is_expired());
        assert!(ctx.remaining() <= Duration::from_millis(50));
        // 已经过期的 ctx 不能 panic，remaining 收敛到 0
        let past = ExecCtx {
            deadline: Instant::now() - Duration::from_secs(1),
            ..ctx
        };
        assert!(past.is_expired());
        assert_eq!(past.remaining(), Duration::ZERO);
    }

    #[test]
    fn exec_error_maps_only_path_codes() {
        assert_eq!(
            ExecError::PathDenied { path: "x".into() }.apperr_code(),
            Some("fs.path_denied")
        );
        assert_eq!(
            ExecError::PathNotFound { path: "x".into() }.apperr_code(),
            Some("fs.path_not_found")
        );
        assert_eq!(ExecError::Timeout.apperr_code(), None);
        assert_eq!(ExecError::Io("e".into()).kind(), "io");
    }

    #[test]
    fn noop_sink_accepts_chunks() {
        let sink = NoopSink;
        sink.chunk("whatever");
    }
}
