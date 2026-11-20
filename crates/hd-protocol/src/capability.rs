//! 设备能力的**唯一真相源**（能力名常量 + 工具名 → 能力名映射）。
//!
//! ## 为什么必须放在协议层
//!
//! 能力名（`workspace.list` 这类字符串）有三个消费方，此前各自手写字面量：
//! 1. `hd-host/src/pairing.rs` 配对请求的能力申报；
//! 2. `hd-runner/src/capabilities.rs` 的 `hello` / `ping` 能力清单；
//! 3. `harness_go` 服务端的派发判定（`pkg/toolapi/spec.go` 的合法常量）。
//!
//! 只要其中任意一处拼错一个字符，就会出现**最难查的一类故障**：端侧明明注册了
//! executor，服务端却认为「该设备不具备 workspace.list 能力」，于是永远不派发，
//! 前端表现为「桌面端空间」目录选择器永久转圈/置灰，而日志里没有任何报错。
//!
//! 因此本模块把「工具名 → 能力名」固化成一张表，所有申报点都必须经它派生；
//! 表外的工具即使被注册也**不申报**（保持既有白名单语义，见 `capabilities.rs`）。
//!
//! ## 与 Go 侧的关系
//!
//! 常量值必须逐字对齐 `harness_go/pkg/toolapi/spec.go` 的合法能力常量词汇，
//! 不得自造。`harness_go` 侧对能力的判定是字符串比较，拼错即静默失效。

/// 工作区目录列举能力。
///
/// 对应端侧工具 `fs.list`（`hd_core::ListDirsExecutor`）：只读列举白名单内的子目录
/// （只读目录名、不读文件内容、跳过软链）。服务端本身跑在服务器上，看不到用户机器
/// 的目录，故必须由端侧提供。
pub const WORKSPACE_LIST: &str = "workspace.list";

/// 本地工具名 → 对外申报的能力名。
///
/// 返回 `None` 表示「该工具不对外申报」。**这是唯一的映射入口**：新增需要申报的工具
/// 必须在这里显式加一行（并在 `hd-runner/src/capabilities.rs` 的 `EXPOSED_TOOLS`
/// 里同步），比「忘了申报」更容易在评审里被看见。
///
/// 目前只映射 `fs.list`：
/// - 工具名与方法名刻意不同（`fs.list` vs `workspace.list`）是历史契约 ——
///   服务端的能力词汇表用 `workspace.*` 命名空间，端侧工具名用 `fs.*` 命名空间。
pub fn capability_for_tool(tool: &str) -> Option<&'static str> {
    match tool {
        "fs.list" => Some(WORKSPACE_LIST),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_list_maps_to_workspace_list() {
        assert_eq!(capability_for_tool("fs.list"), Some(WORKSPACE_LIST));
    }

    #[test]
    fn unknown_tool_is_not_reported() {
        // 表外工具一律不申报（白名单语义），不得退化成「原样返回工具名」
        assert_eq!(capability_for_tool("fs.read"), None);
        assert_eq!(capability_for_tool("process"), None);
        assert_eq!(capability_for_tool(""), None);
    }

    #[test]
    fn workspace_list_constant_matches_go_vocabulary() {
        // 逐字对齐 harness_go/pkg/toolapi/spec.go 的合法能力常量
        assert_eq!(WORKSPACE_LIST, "workspace.list");
    }

    /// 能力名与方法名是两个命名空间，**不得**被「顺手统一」。
    #[test]
    fn capability_name_differs_from_tool_name() {
        assert_ne!(capability_for_tool("fs.list"), Some("fs.list"));
    }
}
