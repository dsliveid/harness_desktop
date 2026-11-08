//! 重连策略（纯逻辑，不碰网络）。
//!
//! ## 两类错误的处理必须分开
//!
//! 判定依据是 [`hd_protocol::error_code::is_terminal`]：
//! - **终态**（`device.replaced` / `revoked` / `protocol_mismatch` / `disabled`）
//!   → **停止重连**。继续重连会被服务端立刻再拒一次，形成无效重试风暴并在服务端
//!   日志刷屏；用户看到的现象是「一直转圈但永远连不上」。
//! - **可恢复**（网络抖动、`write_failed`、`offline_timeout`、`server_closing`）
//!   → 指数退避重连。

use std::time::Duration;

/// 重连决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectDecision {
    /// 退避后重连。
    RetryAfter(Duration),
    /// 停止重连（服务端已明确拒绝，重试无意义）。
    Stop,
}

/// 指数退避重连策略。
#[derive(Debug, Clone, Copy)]
pub struct ReconnectPolicy {
    /// 首次退避时长。
    pub initial: Duration,
    /// 退避上限。
    pub max: Duration,
    /// 连续失败多少次后放弃（进入「需用户介入」态）。
    pub max_attempts: u32,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        // 1s → 2s → 4s → 8s → 16s → 30s(封顶)，连续 5 次后放弃。
        // 与 docs/桌面端架构与功能设计.md §17.1 的守护策略一致。
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
            max_attempts: 5,
        }
    }
}

impl ReconnectPolicy {
    /// 依据「第几次连续失败」与「错误码」给出决策。
    ///
    /// `attempt` 从 1 开始（第 1 次失败）。
    pub fn decide(&self, attempt: u32, err_code: Option<&str>) -> ReconnectDecision {
        // ① 服务端明确拒绝 → 立即停止，不看 attempt
        if let Some(code) = err_code {
            if hd_protocol::error_code::is_terminal(code) {
                return ReconnectDecision::Stop;
            }
        }
        // ② 连续失败超限 → 停止（需用户介入，例如检查服务端是否在运行）
        if attempt >= self.max_attempts {
            return ReconnectDecision::Stop;
        }
        // ③ 指数退避：initial * 2^(attempt-1)，封顶 max
        let factor = 1u32 << (attempt.saturating_sub(1).min(16));
        let backoff = self.initial.saturating_mul(factor).min(self.max);
        ReconnectDecision::RetryAfter(backoff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hd_protocol::error_code;

    #[test]
    fn terminal_codes_stop_immediately() {
        let p = ReconnectPolicy::default();
        for code in [
            error_code::FRAME_REPLACED,
            error_code::FRAME_REVOKED,
            error_code::FRAME_PROTOCOL_MISMATCH,
            error_code::DEVICE_DISABLED,
        ] {
            assert_eq!(
                p.decide(1, Some(code)),
                ReconnectDecision::Stop,
                "终态错误 {code} 必须停止重连，否则会形成无效重试风暴"
            );
        }
    }

    #[test]
    fn recoverable_codes_back_off_exponentially() {
        let p = ReconnectPolicy::default();
        // 无错误码（网络层失败）→ 退避重连
        assert_eq!(
            p.decide(1, None),
            ReconnectDecision::RetryAfter(Duration::from_secs(1))
        );
        assert_eq!(
            p.decide(2, None),
            ReconnectDecision::RetryAfter(Duration::from_secs(2))
        );
        assert_eq!(
            p.decide(3, None),
            ReconnectDecision::RetryAfter(Duration::from_secs(4))
        );
        assert_eq!(
            p.decide(4, None),
            ReconnectDecision::RetryAfter(Duration::from_secs(8))
        );
        // 第 5 次达到上限 → 停止
        assert_eq!(p.decide(5, None), ReconnectDecision::Stop);
    }

    #[test]
    fn backoff_is_capped_at_max() {
        let p = ReconnectPolicy {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
            max_attempts: 20,
        };
        // 2^9 = 512s 会被封顶到 30s
        assert_eq!(
            p.decide(10, None),
            ReconnectDecision::RetryAfter(Duration::from_secs(30))
        );
    }

    #[test]
    fn server_closing_is_recoverable() {
        // 服务端正常关闭不是终态：它可能只是重启，退避后应重连
        let p = ReconnectPolicy::default();
        assert!(matches!(
            p.decide(1, Some(error_code::FRAME_SERVER_CLOSING)),
            ReconnectDecision::RetryAfter(_)
        ));
    }
}
