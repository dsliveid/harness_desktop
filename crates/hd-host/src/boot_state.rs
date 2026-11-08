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
/// 刻意包含 `Unknown` 与 `Failed`：启动是异步的，UI 可能在 bootstrap 还没跑完时
/// 就来读状态。给一个明确的「还不知道」比返回一个假的 `NeedsPairing` 诚实。
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
            detail: format!(
                "缺少执行引擎 hd-runner.exe。请确认它与 hd-host.exe 在同一目录（已查找：{searched}）"
            ),
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
    fn runner_missing_mentions_files_and_search_path() {
        let s = plan_boot(Ok(BootstrapOutcome::RunnerMissing {
            searched: "同目录 / resources 下的 hd-runner.exe".into(),
        }));
        assert_eq!(s.state, BootStateKind::RunnerMissing);
        // 部署问题的提示必须点明「两个文件要在一起」，并带上已搜索路径
        assert!(s.detail.contains("hd-runner.exe"), "{}", s.detail);
        assert!(s.detail.contains("同一目录"), "{}", s.detail);
        assert!(s.detail.contains("已查找"), "{}", s.detail);
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
