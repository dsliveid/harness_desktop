//! 启动状态的 UI 投影（纯函数，可单测）。
//!
//! ## 为什么单独抽出来
//!
//! `gui.rs` 的 `setup` 钩子里会调 [`crate::bootstrap::Bootstrap::ensure_running`]，
//! 但那段代码**没法单测**（需要真实的 Tauri `AppHandle`）。所以把「bootstrap 结果 →
//! UI 状态」这一步做成纯数据映射放在这里 —— 输入输出都是普通结构体，可以完整覆盖。
//!
//! 这直接决定了单测能覆盖到什么：如果把判断逻辑写在 setup 里，等于永久失去覆盖，
//! 而这段逻辑恰恰是「用户看到的第一个状态」，错了体验立刻崩。

use serde::{Deserialize, Serialize};

use crate::bootstrap::{BootstrapError, BootstrapOutcome};
use crate::lifecycle::RunnerPhase;

/// 前端可见的启动状态。
///
/// 序列化成 `snake_case` 的 `state` 字段 + 可选 `detail`。
/// 前端据 `state` 决定显示哪块 UI，据 `detail` 显示具体原因（如搜索了哪个路径）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootUiState {
    /// 机器可读的状态名。
    pub state: BootStateKind,
    /// 给人看的补充说明（可为空）。
    pub detail: String,
}

/// 启动状态枚举。
///
/// ## 与 [`RunnerPhase`] 的关系（重要）
///
/// 两者**不是**重复定义，职责严格区分：
///
/// - [`RunnerPhase`] 是**全应用唯一事实源**，回答「Runner 现在能不能干活」，
///   含运行期持续变化的所有相位（backoff / gave_up / externally_running …）；
/// - `BootStateKind` 只回答「启动编排这一次得出了什么结论」，是一次性的**事件快照**，
///   由 [`plan_boot`] 从 bootstrap 的返回值投影而来，**不参与运行期状态流转**。
///
/// 因此 `BootStateKind` 刻意只有 4 个终态 + 1 个 `Unknown`，不复制 `RunnerPhase` 的
/// 全部变体 —— 若把它扩成第二个全量状态机，就退回了改造前「三处口径」的老问题。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootStateKind {
    /// 还没开始/还在进行中。
    Unknown,
    /// 需要用户配对（密钥链里没有令牌）。
    NeedsPairing,
    /// Runner 已启动（或本来就在跑）。
    Started,
    /// 找不到 Runner 可执行文件（部署问题：漏拷了 hd-runner.exe）。
    RunnerMissing,
    /// 启动过程出错。
    Failed,
}

impl BootStateKind {
    /// 投影到对应的生命周期相位（供宿主把启动结论写进唯一事实源）。
    ///
    /// `Unknown` 映射到 [`RunnerPhase::Idle`]（「还不知道」），
    /// `RunnerMissing` / `Failed` 映射到 [`RunnerPhase::GaveUp`]
    /// —— 它们是「没有在跑且不该自动重试」的终态，与用户主动停止不同，
    /// 但都落在 `GaveUp` 的语义范围内（需用户介入）。
    #[must_use]
    pub fn to_phase(&self) -> RunnerPhase {
        match self {
            Self::Unknown => RunnerPhase::Idle,
            Self::NeedsPairing => RunnerPhase::NeedsPairing,
            Self::Started => RunnerPhase::Running,
            Self::RunnerMissing | Self::Failed => RunnerPhase::GaveUp,
        }
    }
}

impl BootUiState {
    /// 初始状态（bootstrap 还没跑完）。
    pub fn unknown() -> Self {
        Self {
            state: BootStateKind::Unknown,
            detail: String::new(),
        }
    }
}

impl Default for BootUiState {
    fn default() -> Self {
        Self::unknown()
    }
}

/// 把 `Bootstrap::ensure_running` 的结果映射成 UI 状态。
///
/// 每个分支的 `detail` 文案都是**可操作**的：告诉用户下一步做什么，
/// 而不是复述技术原因。例如缺 runner 时要说「请确认两个文件在同一目录」，
/// 而不是「RunnerNotFound」。
pub fn plan_boot(outcome: Result<BootstrapOutcome, BootstrapError>) -> BootUiState {
    match outcome {
        Ok(BootstrapOutcome::Started { .. }) => BootUiState {
            state: BootStateKind::Started,
            detail: String::new(),
        },
        Ok(BootstrapOutcome::NeedsPairing) => BootUiState {
            state: BootStateKind::NeedsPairing,
            detail: "尚未配对：请输入配对码完成设备绑定".to_string(),
        },
        Ok(BootstrapOutcome::RunnerMissing { searched }) => BootUiState {
            state: BootStateKind::RunnerMissing,
            // 单包模式下不再让用户「去找第二个文件」——那会把人引向错误的排查方向。
            detail: format!(
                "无法启动执行引擎（程序内部异常，非缺少文件）。请重启客户端；若持续出现请联系支持并提供：{searched}"
            ),
        },
        Ok(BootstrapOutcome::ExternallyRunning) => BootUiState {
            // 映射到 `Started`：本机确实在执行任务，用户体验上「能用」。
            // 但 detail 必须说清本实例只是监护者 —— 否则用户在本窗口改工作区白名单
            // 却发现「设置成功但不生效」（实际生效的是另一个实例），会以为是 bug。
            state: BootStateKind::Started,
            detail: "检测到本机已有执行引擎在运行，本窗口仅做状态监护。\
                     工作区等配置请在那个实例中修改。"
                .to_string(),
        },
        // 错误分支保留原始信息：这类问题（密钥链被锁、spawn 失败）用户自己
        // 往往无法解决，需要把原因带给支持人员。
        Err(e) => BootUiState {
            state: BootStateKind::Failed,
            detail: format!("启动失败：{e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_state_projects_to_lifecycle_phase() {
        // 启动结论必须能落到唯一事实源里，否则 UI 会出现两套状态。
        assert_eq!(BootStateKind::Started.to_phase(), RunnerPhase::Running);
        assert_eq!(
            BootStateKind::NeedsPairing.to_phase(),
            RunnerPhase::NeedsPairing
        );
        assert_eq!(BootStateKind::Unknown.to_phase(), RunnerPhase::Idle);
        // 部署/运行失败都是「没在跑且需用户介入」。
        assert_eq!(BootStateKind::RunnerMissing.to_phase(), RunnerPhase::GaveUp);
        assert_eq!(BootStateKind::Failed.to_phase(), RunnerPhase::GaveUp);
    }

    #[test]
    fn started_has_no_detail_noise() {
        let s = plan_boot(Ok(BootstrapOutcome::Started {
            device_id_hint: "dev_1".into(),
        }));
        assert_eq!(s.state, BootStateKind::Started);
        // Started 是正常态，不该显示任何提示文案
        assert!(s.detail.is_empty());
    }

    #[test]
    fn needs_pairing_is_actionable() {
        let s = plan_boot(Ok(BootstrapOutcome::NeedsPairing));
        assert_eq!(s.state, BootStateKind::NeedsPairing);
        // 文案必须告诉用户「做什么」，而不是只描述「现在是什么状态」
        assert!(s.detail.contains("配对码"), "文案不可操作：{}", s.detail);
    }

    #[test]
    fn runner_missing_points_to_internal_fault_not_missing_file() {
        let s = plan_boot(Ok(BootstrapOutcome::RunnerMissing {
            searched: "current_exe 不可用".into(),
        }));
        assert_eq!(s.state, BootStateKind::RunnerMissing);
        // 单包模式下不存在「漏拷第二个文件」，文案必须把方向指向程序自身异常，
        // 否则会把用户引去满盘找 hd-runner.exe（一个已不存在的产物）。
        assert!(
            !s.detail.contains("hd-runner.exe"),
            "文案不该再提已删除的独立可执行文件：{}",
            s.detail
        );
        assert!(
            !s.detail.contains("同一目录"),
            "不应再提示把两个文件放一起：{}",
            s.detail
        );
        // 但仍必须带上可操作的下一步与排障信息。
        assert!(s.detail.contains("重启"), "{}", s.detail);
        assert!(s.detail.contains("current_exe 不可用"), "{}", s.detail);
    }

    #[test]
    fn failure_keeps_original_reason() {
        let s = plan_boot(Err(BootstrapError::Vault("密钥链被锁定".into())));
        assert_eq!(s.state, BootStateKind::Failed);
        // 保留原始原因：这类问题用户无法自救，要能带给支持人员
        assert!(s.detail.contains("密钥链被锁定"), "{}", s.detail);
    }

    #[test]
    fn unknown_is_the_default_not_a_fake_answer() {
        // bootstrap 还没跑完时必须返回 Unknown，不能假装「需要配对」——
        // 那会让已配对用户看到一个多余的配对引导
        assert_eq!(BootUiState::default().state, BootStateKind::Unknown);
        assert_eq!(BootUiState::unknown().state, BootStateKind::Unknown);
    }

    #[test]
    fn state_serializes_to_snake_case_for_frontend() {
        // 前端按字符串判断（web/src/desktop/tauriBridge.ts），改成 camelCase 会静默失配
        let json = serde_json::to_string(&BootUiState {
            state: BootStateKind::NeedsPairing,
            detail: String::new(),
        })
        .expect("序列化");
        assert!(json.contains("\"needs_pairing\""), "实际：{json}");
    }
}
