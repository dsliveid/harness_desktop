//! 各帧负载（对齐 `internal/device/protocol.go:187-268`）。
//!
//! 🔴 铁律：**只能追加字段**，禁止删除/改名/改类型。所有字段带 `#[serde(default)]`，
//! 保证旧服务端缺字段时可解析。字段名（`rename`）必须与 Go 的 json tag 逐字符一致。

use serde::{Deserialize, Serialize};

/// 设备能力项（对齐 `model.Capability`）。
///
/// 注意 `updated_at` **没有** omitempty，Go 侧会固定输出 0；故这里不能用
/// `skip_serializing_if`，否则 Rust 序列化结果与 Go 不一致，双向门禁会红。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// 设备 ID（读路径按需填充，端侧上报时通常省略）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device_id: String,
    /// 能力名（必须是 `pkg/toolapi/spec.go` 中的合法常量）。
    pub name: String,
    /// 能力版本。
    #[serde(default)]
    pub version: String,
    /// 更新时间（毫秒）。固定输出，无 omitempty。
    #[serde(default)]
    pub updated_at: i64,
}

/// 端侧自述（首帧），对齐 `HelloPayload`。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HelloPayload {
    /// 设备显示名。
    #[serde(default)]
    pub name: String,
    /// 平台标识（如 `windows-amd64`）。
    #[serde(default)]
    pub platform: String,
    /// 客户端版本。
    #[serde(default)]
    pub app_version: String,
    /// 能力清单摘要（变更时服务端据此判断是否需要重拉）。
    #[serde(default)]
    pub capabilities_hash: String,
    /// 端侧协议版本。
    #[serde(default)]
    pub protocol_version: i32,
    /// 能力清单。
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

/// 握手确认（服务端参数下发），对齐 `WelcomePayload`。
///
/// 需要 `Serialize` 不只是为了对称：`hd-testkit` 假服务端要构造并下发本帧，
/// 真实服务端（Go）也必然序列化它。只实现 `Deserialize` 会让「造服务端」的代码无处安放。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomePayload {
    /// 服务端分配的设备 ID。
    pub device_id: String,
    /// 服务端毫秒时间戳。
    pub server_time: i64,
    /// 服务端协议版本。
    pub protocol_version: i32,
    /// 🔴 心跳间隔（秒）。**端侧必须据此驱动心跳，不得硬编码 15s** —— 服务端调整
    /// 心跳节奏时硬编码会导致端侧被误判离线。
    pub heartbeat_s: i32,
    /// 判定离线的超时（秒）。
    pub offline_after_s: i32,
    /// 待派发任务数。
    #[serde(default)]
    pub pending: i32,
    /// 会话租约代次（0 表示无租约信息）。
    #[serde(default)]
    pub lease_epoch: i64,
}

/// 端侧心跳，对齐 `PingPayload`。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PingPayload {
    /// 负载快照（形状由端侧决定，服务端透传）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load: Option<serde_json::Value>,
    /// 能力清单摘要。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub capabilities_hash: String,
    /// 端侧协议版本。
    #[serde(default)]
    pub protocol_version: i32,
}

/// 服务端心跳应答，对齐 `PongPayload`。
///
/// 同 `WelcomePayload`：需要 `Serialize` 供假服务端/测试构造。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PongPayload {
    /// 服务端毫秒时间戳。
    #[serde(default)]
    pub server_time: i64,
    /// 待派发任务数。
    #[serde(default)]
    pub pending: i32,
    /// 服务端协议版本。
    #[serde(default)]
    pub protocol_version: i32,
}

/// 错误帧负载，对齐 `ErrorPayload`。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorPayload {
    /// 错误码（`device.*` 帧级码或 `fs.*` 业务码，见 [`crate::error_code`]）。
    pub code: String,
    /// 可读消息。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    /// `true` 表示服务端写出本帧后关闭连接。
    #[serde(default)]
    pub fatal: bool,
}

/// 任务派发（服→端），对齐 `TaskDispatchPayload`。
///
/// 🔴 刻意**不设** `task_id` 字段：Go 侧 `TaskID` 与 `ToolEventID` 值恒等
/// （`protocol.go:235` 注释「端侧据此做幂等」）。只解析 `tool_event_id` 可从类型层
/// 杜绝二者分叉——想用 task_id 就必须显式写 `tool_event_id.clone()`，无法拿错。
#[derive(Debug, Clone, Deserialize)]
pub struct TaskDispatchPayload {
    /// 关联 Run。
    pub run_id: String,
    /// 工具事件 ID，**同时是幂等键**（端侧缓存已完成的 ID，断线重派只回放不重跑）。
    pub tool_event_id: String,
    /// 工具名。
    pub tool_name: String,
    /// 工具参数（形状由各工具自定）。
    #[serde(default)]
    pub args: Option<serde_json::Value>,
    /// 截止时间（毫秒时间戳）。端侧超时必须主动回 `failed`，不许挂死。
    pub deadline: i64,
    /// 重派次数（>=1）。
    #[serde(default = "default_attempt")]
    pub attempt: i32,
}

fn default_attempt() -> i32 {
    1
}

/// 执行进度流式块（端→服），对齐 `TaskProgressPayload`。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskProgressPayload {
    /// 任务 ID（= `tool_event_id`）。
    pub task_id: String,
    /// 关联 Run。
    pub run_id: String,
    /// 工具事件 ID。
    pub tool_event_id: String,
    /// 流式文本块。
    #[serde(default)]
    pub chunk: String,
}

/// 结果可信度。
///
/// 🔴 **只提供 `Untrusted` 一个变体**：端侧结果恒不可信（不变量 4），Rust 无法构造
/// 不存在的变体 —— 这比「约定不要设 trusted」强得多，是编译期保证而非口头纪律。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceTrust {
    /// 端侧产出，服务端按不可信处理。
    #[default]
    #[serde(rename = "untrusted")]
    Untrusted,
}

/// 任务终态（端→服），对齐 `TaskResultPayload`。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskResultPayload {
    /// 任务 ID（= `tool_event_id`）。
    pub task_id: String,
    /// 关联 Run。
    pub run_id: String,
    /// 工具事件 ID。
    pub tool_event_id: String,
    /// 终态：`success` | `failed` | `cancelled`。
    pub status: String,
    /// 结果体。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// 失败原因。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// 可信度，恒 `untrusted`。
    #[serde(default)]
    pub source_trust: SourceTrust,
}

/// 租约被抢占通知（服→端），对齐 `LeaseRevokedPayload`。
///
/// 同 `WelcomePayload`：需要 `Serialize` 供假服务端构造（P3 重连测试会用到）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LeaseRevokedPayload {
    /// 会话 ID。
    pub session_id: String,
    /// 新代次。
    #[serde(default)]
    pub epoch: i64,
    /// 原因。
    #[serde(default)]
    pub reason: String,
}

// ============ fs.* 目录列举族（L1 旁路查询，非任务帧） ============
//
// 对齐 `protocol.go:243-282`（`FsListPayload` / `FsDirEntry` / `FsListResultPayload`）
// 与 `docs/工作区宿主与目录选择对接约定.md` §3.3。
//
// 🔴 三条铁律（均来自真实事故）：
// 1. **不是任务帧**：不产生 `tool_event`、不进幂等缓存、不占任务并发池；
// 2. **`id` 只在信封上配对**：应答的 `env.id` 逐字等于请求的 `env.id`，payload 内无 id 字段；
// 3. **`DirEntry` 只有 `name` + `path`**：多一个元数据字段就会诱使前端把「浏览」
//    升级成「枚举」。

/// 目录列举请求（服→端），对齐 `FsListPayload`。
///
/// `path` 为空串表示「未定位」：端侧只回 `roots`（盘符/挂载点/白名单根），
/// 让用户从根开始浏览。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsListPayload {
    /// 目标目录绝对路径；空串 = 未定位（只回 roots）。
    #[serde(default)]
    pub path: String,
    /// 是否附带 roots（Go 侧 `omitempty`）。
    #[serde(default, skip_serializing_if = "is_false")]
    pub with_roots: bool,
}

/// 一个目录项，对齐 `FsDirEntry`。
///
/// 🔴 **只允许 `name` 与 `path`**：这是目录选择器，不是文件浏览器。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsDirEntry {
    /// 显示名（盘根没有 file_name 时退化为全路径）。
    #[serde(default)]
    pub name: String,
    /// 绝对路径（宿主本机口径）。
    #[serde(default)]
    pub path: String,
}

/// 目录列举结果（端→服），对齐 `FsListResultPayload`。
///
/// 字段与 web 端 `DirListing`、桌面端 `hd_core::DirListing` 逐字对齐（`hd-core` 的
/// 本地 `host` 字段**刻意不带上行**：服务端已从连接上下文知道设备身份，
/// 多带字段会被服务端拒绝/丢弃）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsListResultPayload {
    /// 当前目录绝对路径；空串 = 未定位（此时只有 roots）。
    #[serde(default)]
    pub path: String,
    /// 上级目录；`null` = 已在白名单根层级（**绝不返回 `".."`**）。
    ///
    /// 🔴 无 `skip_serializing_if`：Go 侧 `Parent *string` 无 omitempty，
    /// `null` 必须显式出现在线上，否则前端无法区分「根层级」与「缺字段」。
    #[serde(default)]
    pub parent: Option<String>,
    /// 宿主路径分隔符（Windows `\`，POSIX `/`），前端据此切面包屑。
    #[serde(default)]
    pub separator: String,
    /// 可选根（仅在 `path` 为空时给出）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<FsDirEntry>,
    /// 子目录（**只含目录，永不含文件**）。
    #[serde(default)]
    pub dirs: Vec<FsDirEntry>,
    /// 目录项过多被截断。
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
    /// 端侧拒绝/失败原因（非空表示本次列举失败）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// 端侧错误码（`fs.path_denied` / `fs.path_not_found` / `fs.host_timeout` 等），
    /// 服务端据此映射 `apperr`。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub code: String,
}

/// `skip_serializing_if` 需要的「为假」判定（Go 侧 `omitempty` 语义）。
fn is_false(v: &bool) -> bool {
    !*v
}
