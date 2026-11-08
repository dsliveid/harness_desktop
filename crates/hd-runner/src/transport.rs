//! 与 harness_go 设备网关的 WS 连接层。
//!
//! ## 服务端契约（已核实 `internal/device/gateway.go`）
//!
//! | 事实 | 位置 | 端侧必须怎么做 |
//! | --- | --- | --- |
//! | 端点 `/api/v1/devices/ws`，令牌经 `?token=` 传 | device_handler.go:147 | WS 无法自定义头，只能走 query |
//! | 令牌无效 → **升级前 401，绝不 101** | gateway.go:145 | 区分「被拒」与「连不上」，前者是终态 |
//! | 连上即下发 `welcome`（不等 hello） | gateway.go:205 | 必须能处理「未发 hello 就收到 welcome」 |
//! | `heartbeat_s` 由 welcome 下发 | gateway.go:209 | **禁止硬编码 15s**（见 `heartbeat.rs`） |
//! | 服务端读超时 = `offline_after + heartbeat` | gateway.go:228 | 端侧读超时取同口径 |
//! | 每帧都可携带 `v`，不兼容立即终止 | gateway.go:285 | 勿发 `v=0` 以外的可疑版本 |

use futures_util::{SinkExt, StreamExt};
use hd_protocol::envelope::{Envelope, MessageType};
use hd_protocol::payload::{HelloPayload, PingPayload, WelcomePayload};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

use crate::heartbeat::HeartbeatPolicy;

/// 连接层错误。
#[derive(Debug)]
pub enum TransportError {
    /// WS 层错误（含网络不可达）。
    Ws(String),
    /// 服务端在升级前拒绝（401），携带错误体文本。
    ///
    /// 这类失败重连无意义，调用方应按终态处理。
    Unauthorized(String),
    /// 服务端下发 `error` 帧拒绝本次操作。
    ///
    /// 刻意**保留 `code`**（而不是像早期版本那样塞进 `Ws(String)`）：重连环要拿
    /// 它去查 [`hd_protocol::error_code::is_terminal`] 决定「退避重试」还是「立刻停止」。
    /// 把 code 降级成一句人话字符串，等于把决策依据丢进了日志里。
    Server {
        /// 错误码（`device.*` 帧级码或 `fs.*` 业务码）。
        code: String,
        /// 可读消息（仅用于日志/UI 提示）。
        message: String,
    },
    /// 协议解析/校验失败。
    Protocol(hd_protocol::ProtocolError),
    /// 帧负载解码失败。
    Payload(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Ws(e) => write!(f, "WS 错误: {e}"),
            TransportError::Unauthorized(e) => write!(f, "设备令牌被拒绝: {e}"),
            TransportError::Server { code, message } => {
                write!(f, "服务端错误: {code} {message}")
            }
            TransportError::Protocol(e) => write!(f, "协议错误: {e}"),
            TransportError::Payload(e) => write!(f, "负载解码失败: {e}"),
        }
    }
}

impl TransportError {
    /// 重连决策所需的错误码。
    ///
    /// 映射规则（与 `docs/桌面端架构与功能设计.md` §17.1 对齐）：
    /// - 服务端 `error` 帧 → 原样返回其 `code`；
    /// - 握手前 401 → 归一成 `device.revoked`。两者语义一致：令牌失效，重连不会
    ///   自己变好，必须由用户重新配对。用统一错误码走同一套终态判定，
    ///   避免「401 走一条路、revoked 走另一条路」的双口径。
    pub fn terminal_code(&self) -> Option<&str> {
        match self {
            TransportError::Server { code, .. } => Some(code),
            TransportError::Unauthorized(_) => Some(hd_protocol::error_code::FRAME_REVOKED),
            _ => None,
        }
    }
}

impl std::error::Error for TransportError {}

/// 连接建立后的会话状态。
pub struct Session {
    /// 服务端分配的设备 ID（来自 welcome）。
    pub device_id: String,
    /// 心跳节奏（来自 welcome）。
    pub heartbeat: HeartbeatPolicy,
    /// 服务端下发的协议版本。
    pub protocol_version: i32,
    /// 连接建立时的待派发任务数。
    pub pending: i32,
}

/// 已完成握手、正在运行的连接。
pub struct Connection {
    /// 握手结果。
    pub session: Session,
    inner: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
}

/// 手写 `Debug`：底层 WS 流不实现 `Debug`，且**不应**在日志里输出连接内部状态。
/// 只暴露握手结果，够用于断言失败时的报错信息。
impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("device_id", &self.session.device_id)
            .field("protocol_version", &self.session.protocol_version)
            .field("heartbeat", &self.session.heartbeat)
            .field("pending", &self.session.pending)
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// 建立连接并完成握手。
    ///
    /// `ws_url` 形如 `wss://host/api/v1/devices/ws`，**不含** token（本方法会附加）。
    /// `hello` 传 `None` 表示不发首帧自述（服务端允许，`gateway.go:35` 注释「可选」）。
    pub async fn connect(
        ws_url: &str,
        token: &str,
        hello: Option<HelloPayload>,
    ) -> Result<Self, TransportError> {
        let url = build_url(ws_url, token)?;
        let request = url
            .into_client_request()
            .map_err(|e| TransportError::Ws(format!("构造 WS 请求失败: {e}")))?;

        let (mut ws, _resp) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(map_handshake_error)?;

        // 可选的首帧自述。服务端允许先收 hello 再回 welcome（gateway.go:306），
        // 但**不依赖**它 —— 真实网关在连上时就已主动推了 welcome（gateway.go:205）。
        if let Some(h) = hello {
            let env = Envelope::new(
                MessageType::Hello,
                new_frame_id(),
                Some(serde_json::to_value(&h).map_err(|e| TransportError::Payload(e.to_string()))?),
            );
            let text =
                serde_json::to_string(&env).map_err(|e| TransportError::Payload(e.to_string()))?;
            ws.send(Message::Text(text))
                .await
                .map_err(|e| TransportError::Ws(e.to_string()))?;
        }

        // 等待 welcome。真实网关连上即推，故这里必然先到。
        let session = match wait_welcome(&mut ws).await? {
            Some(s) => s,
            None => return Err(TransportError::Ws("连接在握手前被关闭".into())),
        };

        Ok(Self { session, inner: ws })
    }

    /// 发送一次心跳并等待 `pong`。
    ///
    /// 返回 `pong` 中的待派发任务数（服务端借此提示有活可干）。
    pub async fn ping_once(&mut self) -> Result<i32, TransportError> {
        let env = Envelope::new(
            MessageType::Ping,
            new_frame_id(),
            Some(
                serde_json::to_value(PingPayload {
                    load: None,
                    capabilities_hash: String::new(),
                    protocol_version: hd_protocol::CURRENT_PROTOCOL_VERSION,
                })
                .map_err(|e| TransportError::Payload(e.to_string()))?,
            ),
        );
        let text =
            serde_json::to_string(&env).map_err(|e| TransportError::Payload(e.to_string()))?;
        self.inner
            .send(Message::Text(text))
            .await
            .map_err(|e| TransportError::Ws(e.to_string()))?;

        // 等待 pong（期间可能插入其它帧，按类型分流）
        loop {
            let env = self
                .next_frame()
                .await?
                .ok_or_else(|| TransportError::Ws("等待 pong 时连接被关闭".into()))?;
            match env.msg_type {
                MessageType::Pong => {
                    let p: hd_protocol::payload::PongPayload = env
                        .decode()
                        .map_err(TransportError::Protocol)?
                        .ok_or_else(|| TransportError::Payload("pong 无负载".into()))?;
                    return Ok(p.pending);
                }
                MessageType::Error => {
                    // 服务端主动报错（含 fatal）→ 交给上层按错误码处理
                    let e: hd_protocol::payload::ErrorPayload = env
                        .decode()
                        .map_err(TransportError::Protocol)?
                        .ok_or_else(|| TransportError::Payload("error 无负载".into()))?;
                    return Err(TransportError::Ws(format!(
                        "服务端错误: {} {}",
                        e.code, e.message
                    )));
                }
                _ => continue,
            }
        }
    }

    /// 发送任意帧（唯一用途：把 `task.result` / 后续 `task.progress` 回给服务端）。
    ///
    /// 与 `ping_once` 的区别是**不等应答**：任务族是单向回执，等回复只会把
    /// 读帧节奏和心跳节奏缠在一起（`ping_once` 内部读帧的循环本就是为此特例写的）。
    pub async fn send_envelope(&mut self, env: &Envelope) -> Result<(), TransportError> {
        let text =
            serde_json::to_string(env).map_err(|e| TransportError::Payload(e.to_string()))?;
        self.inner
            .send(Message::Text(text))
            .await
            .map_err(|e| TransportError::Ws(e.to_string()))
    }

    /// 读取下一帧。返回 `None` 表示连接已关闭。
    ///
    /// **未知帧类型一律丢弃并继续**（`MessageType::Unknown`）——服务端未来新增帧时
    /// 旧端绝不能因此断连（见 hd-protocol 的 `unknown_frame_type_is_dropped_not_fatal`）。
    pub async fn next_frame(&mut self) -> Result<Option<Envelope>, TransportError> {
        loop {
            let msg = self
                .inner
                .next()
                .await
                .ok_or_else(|| TransportError::Ws("连接已关闭".into()))?;
            let msg = msg.map_err(|e| TransportError::Ws(e.to_string()))?;
            match msg {
                Message::Text(text) => {
                    let env: Envelope = serde_json::from_str(&text)
                        .map_err(|e| TransportError::Payload(format!("帧不是合法 JSON: {e}")))?;
                    if !env.msg_type.is_valid() {
                        // 未知类型：丢弃而非断连
                        continue;
                    }
                    return Ok(Some(env));
                }
                Message::Close(_) => return Ok(None),
                Message::Ping(_) | Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => {
                    continue
                }
            }
        }
    }
}

/// 等待 `welcome` 并构造 `Session`。
async fn wait_welcome(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<Option<Session>, TransportError> {
    loop {
        let msg = match ws.next().await {
            Some(Ok(m)) => m,
            Some(Err(e)) => return Err(TransportError::Ws(e.to_string())),
            None => return Ok(None),
        };
        let Message::Text(text) = msg else {
            continue;
        };
        let env: Envelope = serde_json::from_str(&text)
            .map_err(|e| TransportError::Payload(format!("帧不是合法 JSON: {e}")))?;
        match env.msg_type {
            MessageType::Welcome => {
                let w: WelcomePayload = env
                    .decode()
                    .map_err(TransportError::Protocol)?
                    .ok_or_else(|| TransportError::Payload("welcome 无负载".into()))?;
                // 端侧也做一次版本校验：服务端已校验，这里防止对端是旧版/错版
                hd_protocol::compatible_version(w.protocol_version)
                    .map_err(TransportError::Protocol)?;
                return Ok(Some(Session {
                    device_id: w.device_id,
                    heartbeat: HeartbeatPolicy::from_welcome(w.heartbeat_s, w.offline_after_s),
                    protocol_version: w.protocol_version,
                    pending: w.pending,
                }));
            }
            MessageType::Error => {
                let e: hd_protocol::payload::ErrorPayload = env
                    .decode()
                    .map_err(TransportError::Protocol)?
                    .ok_or_else(|| TransportError::Payload("error 无负载".into()))?;
                return Err(TransportError::Ws(format!(
                    "握手被拒: {} {}",
                    e.code, e.message
                )));
            }
            MessageType::Unknown => continue,
            _ => continue,
        }
    }
}

/// 拼接带上 token 的 WS URL。
fn build_url(ws_url: &str, token: &str) -> Result<String, TransportError> {
    let sep = if ws_url.contains('?') { '&' } else { '?' };
    if token.is_empty() {
        return Err(TransportError::Unauthorized("设备令牌为空".into()));
    }
    Ok(format!("{ws_url}{sep}token={token}"))
}

/// 把 tungstenite 的握手错误映射为我们的错误类型。
///
/// 🔑 关键：服务端在**升级前**用 HTTP 401 拒绝（`gateway.go:145`），tungstenite 会把它
/// 表现为 `Http(Response { status: 401 })`。必须识别并归为 `Unauthorized` ——
/// 这类失败重连无意义（令牌不会自己变好），要按终态处理。
fn map_handshake_error(e: tokio_tungstenite::tungstenite::Error) -> TransportError {
    use tokio_tungstenite::tungstenite::Error as WsErr;
    match &e {
        WsErr::Http(resp) => {
            let status = resp.status();
            if status == tokio_tungstenite::tungstenite::http::StatusCode::UNAUTHORIZED {
                TransportError::Unauthorized(format!("HTTP {status}"))
            } else {
                TransportError::Ws(format!("握手失败 HTTP {status}"))
            }
        }
        _ => TransportError::Ws(e.to_string()),
    }
}

/// 生成帧 ID（仅需本地唯一，不要求全局唯一）。
fn new_frame_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("f-{ms}-{n}")
}
