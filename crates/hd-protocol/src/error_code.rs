//! 错误码常量（字符串唯一来源）。
//!
//! 对齐两侧实现：
//! - 帧级码 → `internal/device/protocol.go:55-74`（`FrameCode*`）
//! - 业务码 → `internal/apperr/apperr.go:78-105`（`CodeFS*` / `CodeDevice*`）
//!
//! 端侧依据这些码决定行为（重连 / 停连 / 提示 / 降级），故**必须与服务端逐字符一致**：
//! 拼错一个字符，端侧就会走进「未知错误」的兜底分支。

/// 帧格式非法（可继续使用连接）。
pub const FRAME_BAD_FRAME: &str = "device.bad_frame";
/// 协议版本不兼容（Fatal，端侧应提示升级）。
pub const FRAME_PROTOCOL_MISMATCH: &str = "device.protocol_mismatch";
/// 服务端未启用远端执行。
pub const FRAME_TASK_UNSUPPORTED: &str = "device.task_unsupported";
/// 同一设备被新连接替换（旧连接被服务端关闭，**端侧不得自动重连**）。
pub const FRAME_REPLACED: &str = "device.replaced";
/// 超时无帧，服务端判定离线并关闭。
pub const FRAME_OFFLINE_TIMEOUT: &str = "device.offline_timeout";
/// 设备已被吊销（**端侧必须停止重连**）。
pub const FRAME_REVOKED: &str = "device.revoked";
/// 服务端关闭（进程退出/设备域停用）。
pub const FRAME_SERVER_CLOSING: &str = "device.server_closing";
/// 服务端写失败（通常是端侧已断开）。
pub const FRAME_WRITE_FAILED: &str = "device.write_failed";

// ============ fs.* 工作区宿主业务码（apperr.go:78-91） ============

/// 路径越界或非法（穿越防护 / 不在根白名单内）。
pub const FS_PATH_DENIED: &str = "fs.path_denied";
/// 路径不存在，或存在但不是目录。
pub const FS_PATH_NOT_FOUND: &str = "fs.path_not_found";
/// 目标宿主不在线（**绝不静默换机，也不降级到服务端目录**）。
pub const FS_HOST_OFFLINE: &str = "fs.host_offline";
/// 宿主不具备目录列举能力（未申报 `workspace.list`）→ 前端应置灰而非报错。
pub const FS_HOST_UNSUPPORTED: &str = "fs.host_unsupported";
/// 端侧列举超时（3s 硬超时自守）。
pub const FS_HOST_TIMEOUT: &str = "fs.host_timeout";

// ============ device.* 业务码（apperr.go:93-105） ============

/// 配对码不存在 / 已消费 / 已过期（三者统一，防枚举）。
pub const DEVICE_PAIR_CODE_INVALID: &str = "device.pair_code_invalid";
/// 设备不存在。
pub const DEVICE_NOT_FOUND: &str = "device.not_found";
/// 设备已吊销（令牌立即失效，**停止重连**）。
///
/// ⚠️ 与 [`FRAME_REVOKED`] **字面量完全相同**（`device.revoked`）：服务端的帧级码
/// （`device/protocol.go`）与业务码（`apperr.go`）在同一语义上各定义了一次。已实测
/// 确认二者相等，故调用方不必区分来源，按字符串判断即可。
pub const DEVICE_REVOKED: &str = "device.revoked";
/// 端侧协议版本不兼容（支持 N / N-1）。
///
/// ⚠️ 与 [`FRAME_PROTOCOL_MISMATCH`] **字面量完全相同**，同上。
pub const DEVICE_PROTOCOL_MISMATCH: &str = "device.protocol_mismatch";
/// 设备域被配置关闭。
pub const DEVICE_DISABLED: &str = "device.disabled";

/// 是否应**停止**重连（对齐 §19 P3 `ReconnectPolicy` 的决策依据）。
///
/// 只有这几种是「重连也没用」的终态：重连会被立刻再次拒绝，形成无效重试风暴，
/// 且在服务端日志里刷屏。其余错误（网络抖动、写失败、超时）都应退避重连。
///
/// 注意：形参里**不再重复列** `DEVICE_REVOKED` / `DEVICE_PROTOCOL_MISMATCH` ——
/// 它们与本函数的 `FRAME_REVOKED` / `FRAME_PROTOCOL_MISMATCH` 字面量相同，重复列会被
/// clippy 判定为 unreachable pattern（已实测确认重叠，见上面常量的注释）。
pub fn is_terminal(code: &str) -> bool {
    matches!(
        code,
        FRAME_REPLACED | FRAME_REVOKED | FRAME_PROTOCOL_MISMATCH | DEVICE_DISABLED
    )
}

/// 是否属于 `fs.*` 命名空间（供前端/路由器分流）。
pub fn is_fs_code(code: &str) -> bool {
    code.starts_with("fs.")
}
