//! Runner 守护循环：**Runner 意外死亡后自动拉起**。
//!
//! ## 为什么需要独立模块（而不是塞进 `Bootstrap`）
//!
//! `Bootstrap` 目前的职责是「一次性把它们串起来」：读令牌 → 定位 exe → spawn →
//! 得出启动结论。它刻意不持有长期状态，也不做循环。
//!
//! 若把守护循环塞进去，它会同时负责：读令牌、定位、建连、循环、退避、清理令牌、
//! 状态投影 —— 变成典型的上帝对象，且每加一个需求都要改它。
//!
//! 本模块只回答一个问题：**「Runner 退出之后该做什么？」**
//! 它不负责怎么启动（问 `Bootstrap`/`Daemon`），不负责怎么显示（问 `lifecycle`）。
//!
//! ## 决策依据全部来自既有契约
//!
//! - 退出码语义：[`hd_protocol::exit_code`]（P1 契约）
//! - 状态转移：[`crate::lifecycle::decide_after_exit`]（P2 唯一事实源）
//! - 退避节奏：[`hd_runner::reconnect::ReconnectPolicy`]（与 Runner 侧共用一份）
//!
//! 三条都不在本模块重新实现 —— 否则又会出现「宿主一套、Runner 一套」的口径分裂。
//!
//! ## 三条硬性语义
//!
//! 1. **主动停止必须短路**：用户点了退出，不能在退避结束后又被拉起来。
//!    用 [`std::sync::atomic::AtomicBool`] 而非 channel：这个标志会在多个 await
//!    点之间被检查，原子量最不容易写错。
//! 2. **健康存活要重置退避计数**：否则偶发崩溃累积到第 5 次就永久 `GaveUp`。
//! 3. **重启后必须重放工作区白名单**：Runner 每次启动的 `Policy` 是「当前目录」，
//!    不重放就会丢掉用户配置的精确白名单（P3 修通的那条链路）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hd_runner::reconnect::ReconnectDecision;

use crate::daemon::ExitRecord;
use crate::lifecycle::RunnerPhase;
use crate::lifecycle::{decide_after_exit, ExitDecision};

/// 连续存活多久算「这一轮是健康的」，从而把退避计数归零。
///
/// 取 60s：`ReconnectPolicy` 的首次退避是 1s、封顶 30s，若 Runner 能连续活过 60s，
/// 说明它至少完整走过一轮心跳与重连协商，此前的失败不应再计入「连续失败」。
/// 太小（如 5s）会让「启动即崩」的循环绕过上限保护；太大则让偶发崩溃长期污染计数。
pub const HEALTHY_UPTIME_MS: u64 = 60_000;

/// 守护循环的一次决策结果（供调用方执行动作，便于单测穷举）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardAction {
    /// 退避后重新拉起。
    Restart {
        /// 第几次重启（从 1 开始）。
        attempt: u32,
        /// 退避时长（由 `ReconnectPolicy` 决定）。
        delay: Duration,
    },
    /// 不再拉起（用户主动停止 / 服务端终止性拒绝 / 重试耗尽）。
    Stop {
        /// 转移后的相位，供 UI 展示。
        phase: RunnerPhase,
        /// 是否应当清理本地令牌并引导重新配对。
        repair: bool,
    },
}

/// 守护循环的状态机（**纯逻辑**，不 spawn、不 sleep、不 IO）。
///
/// 把决策与执行分开后，本类型可以在无 tokio 的环境里被完全穷举测试 ——
/// 这正是「偶发重启风暴」「吊销后无限重试」这类问题最该被钉死的地方。
#[derive(Debug)]
pub struct Guard {
    /// 已连续失败次数（成功存活超过 [`HEALTHY_UPTIME_MS`] 后归零）。
    attempt: u32,
    /// 退避策略（与 Runner 共用同一份实现）。
    policy: hd_runner::reconnect::ReconnectPolicy,
    /// 用户主动停止标志。一旦置位，循环永不重启。
    shutdown: Arc<AtomicBool>,
    /// 是否持有实例锁（`false` 时说明本实例本来就没在管 Runner，不该重启）。
    owns_lock: bool,
}

impl Guard {
    /// 构造守护状态机。
    ///
    /// `shutdown` 由调用方持有同一个 `Arc`：GUI 或信号处理器在收到退出意图时
    /// 置位，循环下一轮即感知，无需额外 channel。
    pub fn new(policy: hd_runner::reconnect::ReconnectPolicy, shutdown: Arc<AtomicBool>) -> Self {
        Self {
            attempt: 0,
            policy,
            shutdown,
            owns_lock: true,
        }
    }

    /// 标记本实例是否真正持有实例锁。
    ///
    /// 外部已在运行时（`BootstrapOutcome::ExternallyRunning`）本实例并不负责 Runner，
    /// 因此即使观测到「Runner 不在了」也不该由它去拉起 —— 那是持锁进程的职责。
    #[must_use]
    pub fn with_lock_ownership(mut self, owns: bool) -> Self {
        self.owns_lock = owns;
        self
    }

    /// 用户请求停止（等价于置位 `shutdown` 标志）。
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// 是否已被要求停止。
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// 当前连续失败次数（诊断/UI 用）。
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Runner 已退出（或要评估一次「该不该重启」）→ 给出下一步动作。
    ///
    /// ## 判定顺序不可乱
    ///
    /// 1. **主动停止**优先：用户点了退出，此时退出码可能是任意值（包括可重试的 3），
    ///    若先判退出码就会把用户主动关掉当成崩溃而拉起。
    /// 2. **不持股**其次：本实例本就不是 Runner 的负责人。
    /// 3. 之后才按退出码语义分流。
    pub fn on_exit(&mut self, exit: ExitRecord, current: RunnerPhase) -> GuardAction {
        // ① 主动停止：任何退出码都不再拉起。
        if self.is_shutdown() {
            return GuardAction::Stop {
                phase: current,
                repair: false,
            };
        }

        // ② 本实例不负责 Runner（外部实例在跑）：不抢职责。
        if !self.owns_lock {
            return GuardAction::Stop {
                phase: current,
                repair: false,
            };
        }

        // ③ 按退出码契约分流（唯一消费点，见 lifecycle::decide_after_exit）。
        let decision: ExitDecision = decide_after_exit(current, exit);

        if decision.restart {
            // 健康存活过就归零；这里用「退出前已活多久」判断。
            if self.was_healthy(&decision.exit) {
                self.attempt = 0;
            }
            self.attempt += 1;

            match self.policy.decide(self.attempt, None) {
                ReconnectDecision::RetryAfter(delay) => GuardAction::Restart {
                    attempt: self.attempt,
                    delay,
                },
                ReconnectDecision::Stop => GuardAction::Stop {
                    // 重试预算耗尽：进入 GaveUp（需用户介入）。
                    phase: RunnerPhase::GaveUp,
                    repair: false,
                },
            }
        } else {
            GuardAction::Stop {
                phase: decision.phase,
                repair: decision.repair,
            }
        }
    }

    /// 通知「Runner 这次活了很久」——把连续失败计数清零。
    ///
    /// 与 [`Guard::on_exit`] 分开，是因为「存活时长」只能在退出后才知道；
    /// 调用方若拿到 `ExitRecord` 没有启动时刻，也可以在心跳健康时主动调用本方法。
    pub fn mark_healthy(&mut self) {
        self.attempt = 0;
    }

    /// 依据退出记录判断上一轮是否算健康存活。
    ///
    /// `ExitRecord` 不含「启动时刻」，只有退出时刻与累计重启次数，因此单靠它
    /// **无法**算出存活时长。这里返回 `false` 并交由调用方在运行期用
    /// [`Guard::mark_healthy`] 显式重置 —— 宁可少归零一次（保守），
    /// 也不要在缺少证据时假装健康（那会让「启动即崩」绕过重试上限）。
    fn was_healthy(&self, _exit: &ExitRecord) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hd_protocol::exit_code;

    fn exit(code: Option<i32>) -> ExitRecord {
        ExitRecord {
            code,
            at_ms: 1_700_000_000_000,
            restarts: 0,
        }
    }

    fn guard() -> (Guard, Arc<AtomicBool>) {
        let flag = Arc::new(AtomicBool::new(false));
        (
            Guard::new(
                hd_runner::reconnect::ReconnectPolicy::default(),
                Arc::clone(&flag),
            ),
            flag,
        )
    }

    #[test]
    fn retryable_exit_restarts_with_backoff() {
        let (mut g, _f) = guard();
        match g.on_exit(
            exit(Some(exit_code::EXIT_RETRYABLE as i32)),
            RunnerPhase::Running,
        ) {
            GuardAction::Restart { attempt, delay } => {
                assert_eq!(attempt, 1);
                // 默认策略首次退避 1s（见 reconnect.rs 的文档）。
                assert_eq!(delay, Duration::from_secs(1));
            }
            other => panic!("期望 Restart，实际 {other:?}"),
        }
    }

    #[test]
    fn shutdown_flag_stops_even_on_retryable_code() {
        let (mut g, flag) = guard();
        flag.store(true, Ordering::SeqCst);
        // 退出码是「可重试」的，但用户已要求停止 —— 不得重启。
        let action = g.on_exit(
            exit(Some(exit_code::EXIT_RETRYABLE as i32)),
            RunnerPhase::Running,
        );
        assert!(
            matches!(action, GuardAction::Stop { .. }),
            "用户主动停止必须优先于退出码判定，实际 {action:?}"
        );
    }

    #[test]
    fn terminal_codes_never_restart() {
        for code in [
            exit_code::EXIT_REVOKED,
            exit_code::EXIT_REPLACED,
            exit_code::EXIT_PROTOCOL_MISMATCH,
            exit_code::EXIT_NO_AUTH,
        ] {
            let (mut g, _f) = guard();
            let action = g.on_exit(exit(Some(code as i32)), RunnerPhase::Running);
            assert!(
                matches!(action, GuardAction::Stop { .. }),
                "终止性退出码 {code} 不得重启，实际 {action:?}"
            );
        }
    }

    #[test]
    fn revoked_requires_repair() {
        let (mut g, _f) = guard();
        match g.on_exit(
            exit(Some(exit_code::EXIT_REVOKED as i32)),
            RunnerPhase::Running,
        ) {
            GuardAction::Stop { repair, phase } => {
                assert!(repair, "吊销必须触发重新配对");
                assert_eq!(phase, RunnerPhase::NeedsPairing, "不得显示为正在重试");
            }
            other => panic!("期望 Stop，实际 {other:?}"),
        }
    }

    #[test]
    fn normal_exit_does_not_restart() {
        let (mut g, _f) = guard();
        let action = g.on_exit(exit(Some(exit_code::EXIT_OK as i32)), RunnerPhase::Running);
        assert!(matches!(action, GuardAction::Stop { .. }));
    }

    #[test]
    fn non_owner_does_not_restart() {
        let flag = Arc::new(AtomicBool::new(false));
        let mut g = Guard::new(hd_runner::reconnect::ReconnectPolicy::default(), flag)
            .with_lock_ownership(false);
        let action = g.on_exit(
            exit(Some(exit_code::EXIT_RETRYABLE as i32)),
            RunnerPhase::Running,
        );
        assert!(
            matches!(action, GuardAction::Stop { .. }),
            "不持有实例锁的实例不该抢着拉起 Runner，实际 {action:?}"
        );
    }

    #[test]
    fn attempts_accumulate_then_give_up() {
        let (mut g, _f) = guard();
        // 默认策略 max_attempts = 5，且 `decide` 的判据是 `attempt >= max_attempts`，
        // 因此实际只有 **4** 次重试机会（attempt 1..=4），第 5 次即进入 Stop。
        // 这是 `ReconnectPolicy` 的既有语义（见 reconnect.rs:58），此处按事实断言。
        for i in 1..=4 {
            match g.on_exit(
                exit(Some(exit_code::EXIT_RETRYABLE as i32)),
                RunnerPhase::Running,
            ) {
                GuardAction::Restart { attempt, .. } => assert_eq!(attempt, i),
                other => panic!("第 {i} 次应重启，实际 {other:?}"),
            }
        }
        match g.on_exit(
            exit(Some(exit_code::EXIT_RETRYABLE as i32)),
            RunnerPhase::Running,
        ) {
            GuardAction::Stop { phase, .. } => {
                assert_eq!(phase, RunnerPhase::GaveUp, "超限必须进入 GaveUp");
            }
            other => panic!("超限应停止，实际 {other:?}"),
        }
    }

    #[test]
    fn mark_healthy_resets_backoff_counter() {
        let (mut g, _f) = guard();
        let _ = g.on_exit(
            exit(Some(exit_code::EXIT_RETRYABLE as i32)),
            RunnerPhase::Running,
        );
        let _ = g.on_exit(
            exit(Some(exit_code::EXIT_RETRYABLE as i32)),
            RunnerPhase::Running,
        );
        assert_eq!(g.attempt(), 2);

        g.mark_healthy();
        assert_eq!(g.attempt(), 0, "健康存活后计数必须归零");

        // 归零后重新从第 1 次算起。
        match g.on_exit(
            exit(Some(exit_code::EXIT_RETRYABLE as i32)),
            RunnerPhase::Running,
        ) {
            GuardAction::Restart { attempt, .. } => assert_eq!(attempt, 1),
            other => panic!("期望 Restart，实际 {other:?}"),
        }
    }

    #[test]
    fn backoff_grows_then_caps() {
        let (mut g, _f) = guard();
        let mut delays = Vec::new();
        // max_attempts=5 且判据为 `attempt >= max_attempts`，故只有 1..=4 会退避。
        for _ in 0..4 {
            if let GuardAction::Restart { delay, .. } = g.on_exit(
                exit(Some(exit_code::EXIT_RETRYABLE as i32)),
                RunnerPhase::Running,
            ) {
                delays.push(delay);
            }
        }
        // 1s → 2s → 4s → 8s（指数增长，见 reconnect.rs 的 factor 计算）。
        assert_eq!(
            delays,
            vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
            ]
        );
    }

    #[test]
    fn request_shutdown_is_observable() {
        let (g, _f) = guard();
        assert!(!g.is_shutdown());
        g.request_shutdown();
        assert!(g.is_shutdown(), "置位后必须能被下一轮循环感知");
    }
}
