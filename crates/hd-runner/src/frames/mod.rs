//! 逐帧处理层（**每条帧一个文件**）。
//!
//! ## 为什么要把帧处理从 `supervisor.rs` 拆出来
//!
//! 改造前的 `handle_frame` 是一个大 match，业务逻辑（解码、执行、回帧）全内联在里面。
//! 后果有两个，都在本次 `fs.list` 事故里现形了：
//! 1. **加一条帧就动一次核心循环**：`supervisor.rs` 是心跳/重连的中枢，任何改动都
//!    可能影响连接存活，评审成本极高，于是「加帧」被无限拖后；
//! 2. **无帧可测**：业务逻辑与 `&mut link`、`JoinSet`、信号量纠缠在一起，只能整体
//!    e2e，无法对「这一帧进来会发生什么」做秒级纯函数单测。
//!
//! 现在 `supervisor::handle_frame` 只做**三件事**：解码 → 委派到 `frames::*` → 归一化
//! 结果。业务语义全部落在本模块，可独立单测。
//!
//! ## 契约
//!
//! 每个帧处理器签名统一为：
//!
//! ```text
//! fn handle_x(router: &Router, req: &Envelope, payload: &XPayload,
//!             out_tx: &mpsc::Sender<Envelope>) -> impl Future<Output = FrameOutcome>
//! ```
//!
//! - `req` 是**原始请求帧**，只为了拿 `req.id`：服务端按 envelope `id` 配对
//!   （`internal/device/pathquery.go` 的 `Deliver(env.ID, ...)`），payload 内没有 id 字段；
//! - 回帧一律走 `out_tx`（session_loop 的单写者队列），处理器**绝不**直接碰连接；
//! - 处理器**绝不**调用 `Router::dispatch`（那是任务链路，会落库产生 tool_event）。

pub mod fs_list;

use hd_protocol::envelope::{Envelope, MessageType};
use hd_protocol::payload::FsListResultPayload;

pub use fs_list::{handle_fs_list, list_result, list_with_timeout, FS_FRAME_TIMEOUT};

/// 帧处理结果。
///
/// 刻意只有两态：帧处理要么**已经**排入出站队列，要么明确丢弃。
/// 不需要「稍后再说」这种第三态 —— 会 `await` 的语义都由处理器内部的
/// 自守超时（如 [`fs_list::FS_FRAME_TIMEOUT`]）收敛成一次确定的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOutcome {
    /// 已把应答帧排入出站队列。
    Replied,
    /// 未回帧：无 Router、负载非法或出站队列已关闭。调用方无需额外动作。
    Dropped,
}

impl FrameOutcome {
    /// 是否为「已回帧」（供日志与测试断言阅读）。
    pub fn is_replied(&self) -> bool {
        matches!(self, FrameOutcome::Replied)
    }
}

/// 构造一条 `fs.list.result` 应答帧。
///
/// 🔴 `id` **必须**逐字等于请求帧的 `id`：服务端用它配对在途等待者，错一位就
/// 变成「迟到应答」，服务端只会 3 秒超时并（在步骤 9/10 之后）把设备误判成不支持。
pub fn fs_list_result_envelope(req_id: &str, payload: FsListResultPayload) -> Envelope {
    // 失败/空结果一律用 `Value::Null` 之外的显式对象：payload 必须是可解码的完整结构。
    let value = serde_json::to_value(payload).unwrap_or(serde_json::Value::Null);
    Envelope::new(MessageType::FsListResult, req_id.to_string(), Some(value))
}

/// 构造一条错误帧（用于「快速失败」，替代静默丢弃）。
///
/// 只在**无法产出业务应答**时使用（例如帧类型未知、负载解码失败）。
/// 业务级失败（越界/不存在/超时）必须走 `fs.list.result` 的 `code` 字段，
/// 而不是 error 帧 —— 否则前端拿不到 `roots`/`separator` 就无法渲染选择器。
pub fn error_envelope(req_id: &str, code: &str, message: &str) -> Envelope {
    Envelope::new(
        MessageType::Error,
        req_id.to_string(),
        Some(serde_json::json!({
            "code": code,
            "message": message,
            // 帧级错误不致命：连接可继续用，只是这一帧没被接受。
            "fatal": false,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_envelope_echoes_request_id() {
        let env = fs_list_result_envelope("fsq-1", FsListResultPayload::default());
        assert_eq!(env.msg_type, MessageType::FsListResult);
        assert_eq!(env.id, "fsq-1", "应答必须逐字回显请求 id");
        assert_eq!(env.v, hd_protocol::CURRENT_PROTOCOL_VERSION);
    }

    #[test]
    fn error_envelope_is_frame_level_and_not_fatal() {
        let env = error_envelope("f-1", "device.bad_frame", "未知帧类型");
        assert_eq!(env.msg_type, MessageType::Error);
        assert_eq!(env.id, "f-1");
        let p: hd_protocol::payload::ErrorPayload =
            env.decode().expect("解码").expect("错误帧必须有负载");
        assert_eq!(p.code, "device.bad_frame");
        assert!(!p.fatal, "帧级错误不得触发断连（连接本身是健康的）");
    }

    #[test]
    fn frame_outcome_replied_matches() {
        assert!(FrameOutcome::Replied.is_replied());
        assert!(!FrameOutcome::Dropped.is_replied());
    }
}
