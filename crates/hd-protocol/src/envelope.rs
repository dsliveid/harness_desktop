//! 协议信封与消息类型（对齐 `internal/device/protocol.go:30-185`）。

use serde::{Deserialize, Serialize};

/// 服务端当前设备协议版本（N），对齐 `model.DefaultDeviceProtocolVersion`。
pub const CURRENT_PROTOCOL_VERSION: i32 = 1;

/// 服务端仍接受的最低版本，对齐 `MinProtocolVersion`。
///
/// N=1 时最低即 1；将来升到 2 时这里保持 1（双代兼容一个版本）。
pub const MIN_PROTOCOL_VERSION: i32 = 1;

/// 设备协议消息类型。
///
/// `Unknown` 是**必要的向后兼容防御**：服务端未来新增帧类型时，旧桌面端必须丢弃
/// 而不是解析失败断连（对应 Go 侧 `MessageType.Valid()` 的白名单语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// 端→服：连上后的首帧自述。
    #[serde(rename = "hello")]
    Hello,
    /// 服→端：握手确认（服务端时间、心跳参数、协议版本）。
    #[serde(rename = "welcome")]
    Welcome,
    /// 端→服：心跳。
    #[serde(rename = "ping")]
    Ping,
    /// 服→端：心跳应答。
    #[serde(rename = "pong")]
    Pong,
    /// 双向：错误帧（`fatal=true` 表示随后断开）。
    #[serde(rename = "error")]
    Error,
    /// 服→端：任务派发。
    #[serde(rename = "task.dispatch")]
    TaskDispatch,
    /// 端→服：执行进度流式块。
    #[serde(rename = "task.progress")]
    TaskProgress,
    /// 端→服：任务终态结果。
    #[serde(rename = "task.result")]
    TaskResult,
    /// 服→端：会话租约被抢占。
    #[serde(rename = "lease.revoked")]
    LeaseRevoked,
    /// 未知帧类型（服务端新增、本端未实现）。调用方应静默丢弃。
    #[serde(other)]
    Unknown,
}

impl MessageType {
    /// 是否为任务派发族（供路由分流）。
    pub fn is_task_frame(&self) -> bool {
        matches!(
            self,
            MessageType::TaskDispatch | MessageType::TaskProgress | MessageType::TaskResult
        )
    }

    /// 是否为已知类型（对齐 Go 侧 `Valid()`）。
    pub fn is_valid(&self) -> bool {
        !matches!(self, MessageType::Unknown)
    }

    /// 线上字面量（日志与错误信息用；`Unknown` 返回空串）。
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageType::Hello => "hello",
            MessageType::Welcome => "welcome",
            MessageType::Ping => "ping",
            MessageType::Pong => "pong",
            MessageType::Error => "error",
            MessageType::TaskDispatch => "task.dispatch",
            MessageType::TaskProgress => "task.progress",
            MessageType::TaskResult => "task.result",
            MessageType::LeaseRevoked => "lease.revoked",
            MessageType::Unknown => "",
        }
    }
}

/// 统一帧信封（所有设备协议消息的唯一外形）。
///
/// 字段语义逐条对齐 `protocol.go:96-109`，**形状已冻结**，只允许追加。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// 协议版本（缺省 0 视为「未声明」，按最低兼容版本处理）。
    #[serde(default)]
    pub v: i32,
    /// 消息类型。
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    /// 帧 ID（请求/应答配对与幂等用；任务族复用 `tool_event_id`）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// 关联 Run（任务族与租约族使用）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_id: String,
    /// 发送端毫秒时间戳（仅观测用，不参与判定）。
    #[serde(default)]
    pub ts: i64,
    /// 具体负载（原始 JSON，按 `msg_type` 二次解码）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

impl Envelope {
    /// 构造带当前版本号的信封（`payload` 传 `None` 表示空负载）。
    ///
    /// 与 Go 侧 `NewEnvelope` 的差异：不自动填 `ts`，由调用方决定（Runner 侧应传
    /// 真实时间，测试侧传固定值以保证样本稳定）。
    pub fn new(
        msg_type: MessageType,
        id: impl Into<String>,
        payload: Option<serde_json::Value>,
    ) -> Self {
        Self {
            v: CURRENT_PROTOCOL_VERSION,
            msg_type,
            id: id.into(),
            run_id: String::new(),
            ts: 0,
            payload,
        }
    }

    /// 把 `payload` 解码到具体负载类型。
    ///
    /// 空负载时返回 `None`（对齐 Go 侧 `Decode` 的「置零并返回 nil」语义）。
    pub fn decode<T: serde::de::DeserializeOwned>(&self) -> Result<Option<T>, ProtocolError> {
        match &self.payload {
            None => Ok(None),
            Some(v) if v.is_null() => Ok(None),
            Some(v) => serde_json::from_value(v.clone()).map(Some).map_err(|e| {
                ProtocolError::PayloadDecode {
                    msg_type: self.msg_type,
                    source: e.to_string(),
                }
            }),
        }
    }

    /// 校验帧基本合法性（对齐 `Envelope.Validate`）。
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if !self.msg_type.is_valid() {
            return Err(ProtocolError::UnknownMessageType);
        }
        Ok(())
    }
}

/// 协议层错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// 未知帧类型。
    UnknownMessageType,
    /// 帧负载解码失败。
    PayloadDecode {
        /// 出错的帧类型。
        msg_type: MessageType,
        /// 底层错误描述。
        source: String,
    },
    /// 协议版本不兼容（端侧应提示升级，**不得静默降级执行**）。
    VersionMismatch {
        /// 端侧声明的版本。
        got: i32,
        /// 服务端最低支持版本。
        min: i32,
        /// 服务端当前版本。
        current: i32,
    },
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::UnknownMessageType => write!(f, "device: 未知帧类型"),
            ProtocolError::PayloadDecode { msg_type, source } => {
                write!(f, "device: 解析 {} 帧负载失败: {source}", msg_type.as_str())
            }
            ProtocolError::VersionMismatch { got, min, current } => write!(
                f,
                "端侧协议版本 {got} 不受支持（服务端支持 {min}~{current}）"
            ),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// 返回服务端接受的版本集合（N 与 N-1），对齐 `SupportedVersions`。
pub fn supported_versions() -> Vec<i32> {
    if MIN_PROTOCOL_VERSION >= CURRENT_PROTOCOL_VERSION {
        vec![CURRENT_PROTOCOL_VERSION]
    } else {
        vec![CURRENT_PROTOCOL_VERSION, CURRENT_PROTOCOL_VERSION - 1]
    }
}

/// 判定端侧声明的协议版本是否兼容，对齐 `CompatibleVersion`（宽进严出）。
///
/// 语义：
/// - `v == 0`：端侧未声明（老端/首帧省略）→ 按最低兼容版本接受；
/// - `MIN..=CURRENT` → 兼容；
/// - 其余（过旧/超前）→ [`ProtocolError::VersionMismatch`]，端侧必须提示升级。
pub fn compatible_version(v: i32) -> Result<(), ProtocolError> {
    if v == 0 {
        return Ok(());
    }
    if v >= MIN_PROTOCOL_VERSION && v <= CURRENT_PROTOCOL_VERSION {
        return Ok(());
    }
    Err(ProtocolError::VersionMismatch {
        got: v,
        min: MIN_PROTOCOL_VERSION,
        current: CURRENT_PROTOCOL_VERSION,
    })
}
