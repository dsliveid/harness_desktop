//! Runner 生命周期的**唯一事实源**（纯逻辑，无 IO / 无 tokio）。
//!
//! ## 为什么需要这个模块
//!
//! 改造前，「Runner 现在处于什么状态」有**三个互不同步的答案**：
//!
//! | 位置 | 表达 | 问题 |
//! | --- | --- | --- |
//! | `daemon::RuntimeStats::state` | `RunnerState` | 只管子进程，不知道「需要配对」 |
//! | `boot_state::BootStateKind` | 启动结果 | 与上一行语义重叠（都有 started / needs_pairing） |
//! | `commands::device_status` | 自行用 `state + last_heartbeat_ms` 二次推导 `online` | 推导规则散落在 command 层，无法单测到完整组合 |
//!
//! 三个答案叠加的结果是：UI 想显示「当前能不能干活」，得同时读两个 command 再自己
//! 拼装；而任何一处新增状态（例如「本机已有别的 host 在跑」）都要改至少三处。
//!
//! 本模块把它们收敛成**一个枚举 + 一个纯函数**：
//!
//! - [`RunnerPhase`]：从「宿主刚启动」到「放弃重启」的完整生命周期，含配对态；
//! - [`RunnerPhase::liveness`]：把「相位 + 心跳时刻 + 当前时间」压成三态
//!   [`Liveness`]，让 `online` 的判定规则只有一份；
//! - [`next`]：相位转移的唯一入口，非法组合一律原地停留而非 panic。
//!
//! ## 为什么是纯函数
//!
//! 状态机的价值在于「所有组合都能被断言」。一旦它依赖 `SystemTime` / 进程句柄，
//! 单测就只能覆盖到少数幸运路径。故本模块的时间一律**从参数传入**，
//! 与 `hd-core` 的 `Policy` 保持同样的可测性取舍。

use serde::{Deserialize, Serialize};

use crate::daemon::ExitRecord;

/// 心跳超时判定：超过这个时长没有任何心跳 → 视为失联。
///
/// 取 90s：Runner 心跳周期上限是 30s（见设计文档 §17.1），留 3 个周期容忍一次抖动
/// 加一次调度延迟；再紧一点会在机器卡顿时误报掉线，把用户推向「反复重启客户端」。
pub const HEARTBEAT_STALE_MS: u64 = 90_000;

/// Runner 生命周期相位（**全应用唯一权威**）。
///
/// 序列化为 `snake_case`，`runner_status` / `boot_state` 的字符串字段都直接取自
/// [`RunnerPhase::as_str`]，因此前端只需维护一套状态到颜色的映射。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerPhase {
    /// 宿主刚启动，启动编排还没跑完 —— 「还不知道」。
    ///
    /// 必须独立于 `Stopped`：启动是异步的，UI 首帧读到的就是这个相位，
    /// 返回一个假的「已停止」会让用户以为程序坏了。
    Idle,
    /// 需要用户配对：密钥链无令牌（首次使用，或令牌已被吊销清理）。
    NeedsPairing,
    /// 子进程在跑。
    Running,
    /// 子进程已退出，且**尚未作出后续决策**（是否重启由上层按退出码判定）。
    ///
    /// 这是一个**事实态**而非决策态：它只陈述「进程没了」，
    /// 不暗示「要不要重启」。与 [`RunnerPhase::Backoff`] 的区别是后者已确定会重试。
    Stopped,
    /// 子进程已退出，正在退避等待重启。
    Backoff,
    /// 连续失败超限，停止重启，需用户介入（检查 Runner 是否被删 / 被杀软隔离）。
    GaveUp,
    /// 主动停止（用户退出 / 解除配对），**不自动重启**。
    ShuttingDown,
    /// 本机已有 Runner 在跑，但不是本宿主拉起的（例如用户手工启动或另一个宿主实例）。
    ///
    /// 语义要点：本相位下宿主**不 spawn**（避免同一设备两条 WS 连接互踢），
    /// 但由于那条 Runner 的 stdin 写端不受本宿主持有，宿主也**无法**给它下发令牌
    /// 或策略 —— 只能如实展示，不假装在管它。
    ExternallyRunning,
}

impl RunnerPhase {
    /// 对外字符串形式（前端按此做颜色映射）。
    ///
    /// 与历史值完全兼容：`stopped`/`running`/`backoff`/`gave_up`/`shutting_down`
    /// 原样保留，因此既有前端无需改动；新增的 `idle` / `needs_pairing` /
    /// `externally_running` 是本次收口带来的新相位。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::NeedsPairing => "needs_pairing",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Backoff => "backoff",
            Self::GaveUp => "gave_up",
            Self::ShuttingDown => "shutting_down",
            Self::ExternallyRunning => "externally_running",
        }
    }

    /// 该相位下的存活判定。
    ///
    /// ## 为什么 `hb == 0` 判为在线
    ///
    /// 「子进程在跑但从未收到心跳」有两种可能：刚 spawn 还没握手（正常），
    /// 或心跳通路坏了（异常）。在无法区分时选择**给信任**：报离线会让用户
    /// 在启动瞬间看到「离线」闪一下，反而更像故障。真正的异常由心跳过期
    /// （[`Liveness::Stale`]）覆盖。
    #[must_use]
    pub fn liveness(&self, now_ms: u64, last_heartbeat_ms: u64) -> Liveness {
        if *self != Self::Running {
            return Liveness::Offline;
        }
        if last_heartbeat_ms == 0 {
            return Liveness::Online;
        }
        let age = now_ms.saturating_sub(last_heartbeat_ms);
        if age < HEARTBEAT_STALE_MS {
            Liveness::Online
        } else {
            Liveness::Stale
        }
    }

    /// 是否「此刻能干活」（供 `device_status.online` 使用）。
    #[must_use]
    pub fn is_online(&self, now_ms: u64, last_heartbeat_ms: u64) -> bool {
        self.liveness(now_ms, last_heartbeat_ms) == Liveness::Online
    }

    /// 该相位下宿主是否应当尝试拉起 Runner。
    ///
    /// 明确列出**不该拉起**的相位，其余（`Idle` / `NeedsPairing` 之外的过渡态）
    /// 交由调用方按业务决定 —— 这里只回答「拉起是否安全」。
    #[must_use]
    pub fn allows_spawn(&self) -> bool {
        !matches!(
            self,
            // 已在跑 / 外部已在跑：再拉一个会互踢。
            Self::Running | Self::ExternallyRunning | Self::Backoff
            // 主动停止中：拉起会与退出流程打架。
            | Self::ShuttingDown
            // 没有令牌：拉了也只会以 EXIT_NO_AUTH 立刻退出。
            | Self::NeedsPairing
        )
    }
}

/// 存活三态（由 [`RunnerPhase::liveness`] 派生）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// 在线：子进程在跑且心跳新鲜（或尚未收到心跳）。
    Online,
    /// 失联：子进程在跑，但心跳已过期 —— 「进程还在，但连不上服务端」。
    ///
    /// 必须与 [`Liveness::Offline`] 区分：此时重启 Runner 是有意义的
    /// （重连可能恢复），而 `Offline` 意味着根本没在跑。
    Stale,
    /// 离线：子进程不在跑。
    Offline,
}

/// 相位转移事件。
///
/// 每个事件对应一个真实动作的**完成**（而不是开始），这样状态永远反映事实，
/// 不会出现「已进入 Running 但 spawn 其实失败了」的错觉。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseEvent {
    /// 启动编排发现没有令牌 → 需要用户配对。
    NeedsPairing,
    /// 启动编排发现本机已有外部 Runner → 不重复拉起。
    ExternalDetected,
    /// 子进程已成功拉起。
    Spawned,
    /// 子进程退出且判定为「可重启」→ 进入退避。
    ExitedRetryable,
    /// 子进程退出且重试预算耗尽 → 放弃。
    ExitedExhausted,
    /// 用户主动停止（退出应用 / 解除配对）。
    ShutdownRequested,
    /// 令牌被清理（解约 / 被吊销后的自愈）→ 回到需要配对。
    Unpaired,
    /// 重置到初始相位（测试与「重新开始编排」用）。
    Reset,
}

/// 相位转移的**唯一入口**。
///
/// 设计取舍：非法组合一律**原地停留**而不是 `panic`。
/// 理由是这个函数跑在宿主关键路径上（一个 panic 会把用户界面一起带走），
/// 而「忽略一个不该发生的事件」最多导致状态显示滞后一秒，下一轮轮询即自愈。
/// 非法组合的合法性由单元测试穷举钉死，不靠运行时崩溃求发现。
#[must_use]
pub fn next(current: RunnerPhase, event: PhaseEvent) -> RunnerPhase {
    use PhaseEvent as E;
    use RunnerPhase as P;

    match (current, event) {
        // ---- 重置：任何相位都能被显式重置 ----
        (_, E::Reset) => P::Idle,

        // ---- 启动编排的两种非 Running 结论 ----
        // 只在「还没决定」时接受，避免把正在跑的 Runner 误标成需要配对。
        (P::Idle | P::NeedsPairing | P::GaveUp | P::Backoff, E::NeedsPairing) => P::NeedsPairing,
        (P::Idle | P::NeedsPairing | P::GaveUp | P::Backoff, E::ExternalDetected) => {
            P::ExternallyRunning
        }

        // ---- 拉起成功：从任何「没在跑」的相位都合法 ----
        (
            P::Idle
            | P::NeedsPairing
            | P::Stopped
            | P::Backoff
            | P::GaveUp
            | P::ExternallyRunning
            | P::ShuttingDown,
            E::Spawned,
        ) => P::Running,

        // ---- 退出分流 ----
        // 只有 Running / Stopped 会收到退出事件：前者是「刚检测到退出」，
        // 后者是「daemon 已记录事实、此处做决策」。退避中/已放弃时的重复报告一律忽略，
        // 防止「同一退出被上报两次导致 attempt 虚增」。
        (P::Running | P::Stopped, E::ExitedRetryable) => P::Backoff,
        (P::Running | P::Stopped, E::ExitedExhausted) => P::GaveUp,

        // ---- 主动停止：Running / Backoff / Stopped 都要能停下来 ----
        // Backoff 也接受，是因为用户可能在退避倒计时期间点退出；
        // 若不接受，会留下一个「没人等待却仍会重启」的定时逻辑。
        (P::Running | P::Stopped | P::Backoff | P::GaveUp | P::Idle, E::ShutdownRequested) => {
            P::ShuttingDown
        }

        // ---- 解约：任何相位都要能回到需要配对 ----
        // 含 ExternallyRunning：外部 Runner 占着连接，但用户解约后本地令牌已清，
        // 继续显示「外部运行中」会误导用户以为还能用。
        (_, E::Unpaired) => P::NeedsPairing,

        // ---- 其余组合：原地停留（见函数文档的取舍说明） ----
        _ => current,
    }
}

/// 一次「退出 → 决策」的完整快照，供 UI 与日志使用。
///
/// 把 `exit` 与转移后相位放在一起，是为了让宿主在**同一处**同时拿到
/// 「发生了什么」与「接下来是什么状态」，避免调用方各拼一半。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitDecision {
    /// 子进程退出记录（含退出码与累计重启次数）。
    pub exit: ExitRecord,
    /// 转移后的相位。
    pub phase: RunnerPhase,
    /// 是否应当退避后重启。
    pub restart: bool,
    /// 是否应当清理本地令牌并重新配对。
    pub repair: bool,
}

/// 依据退出码作出决策，并给出转移后的相位。
///
/// 这是「退出码契约」（[`hd_protocol::exit_code`]）在宿主侧的**唯一消费点**：
/// 其余模块不得自行解释退出码，否则又会出现多套判定。
#[must_use]
pub fn decide_after_exit(current: RunnerPhase, exit: ExitRecord) -> ExitDecision {
    let code = exit.code.map(|c| c as u8);
    let restart = hd_protocol::exit_code::should_restart(code);
    let repair = hd_protocol::exit_code::requires_repair(code);

    let phase = if repair {
        // 令牌已失效：直接进入需要配对，绝不能落到 Backoff/Exhausted ——
        // 那会让 UI 显示「正在重试」，而事实是「重试永远不可能成功」。
        RunnerPhase::NeedsPairing
    } else if restart {
        next(current, PhaseEvent::ExitedRetryable)
    } else {
        next(current, PhaseEvent::ExitedExhausted)
    };

    ExitDecision {
        exit,
        phase,
        restart,
        repair,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(code: Option<i32>) -> ExitRecord {
        ExitRecord {
            code,
            at_ms: 1_700_000_000_000,
            restarts: 0,
        }
    }

    #[test]
    fn as_str_keeps_legacy_values_stable() {
        // 旧前端的颜色映射依赖这些字面量，改动即为破坏性变更。
        assert_eq!(RunnerPhase::Running.as_str(), "running");
        assert_eq!(RunnerPhase::Backoff.as_str(), "backoff");
        assert_eq!(RunnerPhase::GaveUp.as_str(), "gave_up");
        assert_eq!(RunnerPhase::ShuttingDown.as_str(), "shutting_down");
    }

    #[test]
    fn serializes_to_snake_case() {
        let json = serde_json::to_string(&RunnerPhase::ExternallyRunning).unwrap();
        assert_eq!(json, "\"externally_running\"");
        let back: RunnerPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(back, RunnerPhase::ExternallyRunning);
    }

    #[test]
    fn non_running_phases_are_offline() {
        for phase in [
            RunnerPhase::Idle,
            RunnerPhase::NeedsPairing,
            RunnerPhase::Stopped,
            RunnerPhase::Backoff,
            RunnerPhase::GaveUp,
            RunnerPhase::ShuttingDown,
            RunnerPhase::ExternallyRunning,
        ] {
            assert_eq!(
                phase.liveness(1_000_000, 1_000_000),
                Liveness::Offline,
                "{phase:?} 不该被判为在线"
            );
        }
    }

    #[test]
    fn stopped_is_a_fact_state_not_a_decision() {
        // Stopped 只陈述「进程没了」：它既不自动重启，也不代表放弃。
        assert_eq!(RunnerPhase::Stopped.as_str(), "stopped");
        assert_eq!(
            next(RunnerPhase::Stopped, PhaseEvent::ExitedRetryable),
            RunnerPhase::Backoff,
            "事实态收到可重试退出后应进入退避"
        );
    }

    #[test]
    fn running_without_heartbeat_is_online_optimistically() {
        assert_eq!(
            RunnerPhase::Running.liveness(1_000_000, 0),
            Liveness::Online
        );
    }

    #[test]
    fn running_with_fresh_heartbeat_is_online() {
        assert_eq!(
            RunnerPhase::Running.liveness(1_000_000, 1_000_000 - HEARTBEAT_STALE_MS + 1),
            Liveness::Online
        );
    }

    #[test]
    fn running_with_stale_heartbeat_is_stale_not_offline() {
        let l = RunnerPhase::Running.liveness(1_000_000, 1_000_000 - HEARTBEAT_STALE_MS);
        assert_eq!(l, Liveness::Stale);
        assert!(!RunnerPhase::Running.is_online(1_000_000, 1_000_000 - HEARTBEAT_STALE_MS));
    }

    #[test]
    fn clock_going_backwards_does_not_panic() {
        // 心跳时刻在未来（时钟回拨）：saturating_sub 得 0 → 视为新鲜，绝不 panic。
        assert_eq!(
            RunnerPhase::Running.liveness(1_000, 9_999_999),
            Liveness::Online
        );
    }

    #[test]
    fn spawn_is_refused_for_phases_that_would_double_run() {
        assert!(!RunnerPhase::Running.allows_spawn());
        assert!(!RunnerPhase::ExternallyRunning.allows_spawn());
        assert!(!RunnerPhase::Backoff.allows_spawn(), "退避中不该另起一个");
        assert!(!RunnerPhase::ShuttingDown.allows_spawn());
        assert!(
            !RunnerPhase::NeedsPairing.allows_spawn(),
            "没令牌拉了也是白死"
        );
    }

    #[test]
    fn spawn_is_allowed_when_nothing_is_running() {
        assert!(RunnerPhase::Idle.allows_spawn());
        assert!(RunnerPhase::GaveUp.allows_spawn(), "用户修好环境后应能重试");
    }

    #[test]
    fn spawn_transition_from_every_non_running_phase() {
        for from in [
            RunnerPhase::Idle,
            RunnerPhase::NeedsPairing,
            RunnerPhase::Stopped,
            RunnerPhase::Backoff,
            RunnerPhase::GaveUp,
            RunnerPhase::ExternallyRunning,
            RunnerPhase::ShuttingDown,
        ] {
            assert_eq!(next(from, PhaseEvent::Spawned), RunnerPhase::Running);
        }
    }

    #[test]
    fn exit_from_running_splits_by_retryability() {
        assert_eq!(
            next(RunnerPhase::Running, PhaseEvent::ExitedRetryable),
            RunnerPhase::Backoff
        );
        assert_eq!(
            next(RunnerPhase::Running, PhaseEvent::ExitedExhausted),
            RunnerPhase::GaveUp
        );
    }

    #[test]
    fn duplicate_exit_report_is_ignored() {
        // 同一次退出被上报两次时不得把 Backoff 推进成 GaveUp。
        assert_eq!(
            next(RunnerPhase::Backoff, PhaseEvent::ExitedExhausted),
            RunnerPhase::Backoff
        );
    }

    #[test]
    fn shutdown_accepted_from_live_phases() {
        for from in [
            RunnerPhase::Running,
            RunnerPhase::Stopped,
            RunnerPhase::Backoff,
            RunnerPhase::GaveUp,
            RunnerPhase::Idle,
        ] {
            assert_eq!(
                next(from, PhaseEvent::ShutdownRequested),
                RunnerPhase::ShuttingDown
            );
        }
    }

    #[test]
    fn unpaired_wins_from_any_phase() {
        for from in [
            RunnerPhase::Idle,
            RunnerPhase::NeedsPairing,
            RunnerPhase::Stopped,
            RunnerPhase::Running,
            RunnerPhase::Backoff,
            RunnerPhase::GaveUp,
            RunnerPhase::ShuttingDown,
            RunnerPhase::ExternallyRunning,
        ] {
            assert_eq!(next(from, PhaseEvent::Unpaired), RunnerPhase::NeedsPairing);
        }
    }

    #[test]
    fn reset_returns_to_idle() {
        assert_eq!(
            next(RunnerPhase::GaveUp, PhaseEvent::Reset),
            RunnerPhase::Idle
        );
    }

    #[test]
    fn illegal_transition_stays_put_instead_of_panicking() {
        // 非 Running 收到「退出」事件：原地不动，不 panic。
        assert_eq!(
            next(RunnerPhase::Idle, PhaseEvent::ExitedRetryable),
            RunnerPhase::Idle
        );
    }

    #[test]
    fn normal_exit_does_not_restart() {
        // code 0 = 用户主动停止：绝不重启。
        let d = decide_after_exit(RunnerPhase::Running, exit(Some(0)));
        assert!(!d.restart);
        assert!(!d.repair);
        assert_eq!(d.phase, RunnerPhase::GaveUp, "用户停止后不应留在 Backoff");
    }

    #[test]
    fn retryable_exit_restarts() {
        let d = decide_after_exit(
            RunnerPhase::Running,
            exit(Some(hd_protocol::exit_code::EXIT_RETRYABLE as i32)),
        );
        assert!(d.restart);
        assert!(!d.repair);
        assert_eq!(d.phase, RunnerPhase::Backoff);
    }

    #[test]
    fn revoked_exit_requires_repair_and_skips_backoff() {
        let d = decide_after_exit(
            RunnerPhase::Running,
            exit(Some(hd_protocol::exit_code::EXIT_REVOKED as i32)),
        );
        assert!(!d.restart, "吊销不是可重试问题");
        assert!(d.repair, "吊销必须清令牌重新配对");
        assert_eq!(
            d.phase,
            RunnerPhase::NeedsPairing,
            "吊销不得显示为「正在重试」"
        );
    }

    #[test]
    fn replaced_exit_neither_restarts_nor_repairs() {
        let d = decide_after_exit(
            RunnerPhase::Running,
            exit(Some(hd_protocol::exit_code::EXIT_REPLACED as i32)),
        );
        assert!(!d.restart, "重启会与对方互踢");
        assert!(!d.repair, "被替换不代表令牌失效");
        assert_eq!(d.phase, RunnerPhase::GaveUp);
    }

    #[test]
    fn signal_kill_is_conservatively_not_restarted() {
        let d = decide_after_exit(RunnerPhase::Running, exit(None));
        assert!(!d.restart);
        assert_eq!(d.phase, RunnerPhase::GaveUp);
    }
}
