//! 假服务端：在**服务端 L1（`fs.*` 派发）未落地前**提供可联调的对端。
//!
//! 它严格复刻 `harness_go/internal/device/gateway.go` 的对外行为中最关键的三条：
//!
//! 1. **升级前鉴权**：`?token=` 缺失/错误 → **HTTP 401，绝不返回 101**
//!    （gateway.go:145 的语义）。端侧据此区分「连上了但被拒」与「压根没连上」。
//! 2. **连上即下发 `welcome`**（gateway.go:205）：不等端侧 `hello`，服务端主动推。
//! 3. **`ping` → `pong` 回带同一 `id`**（gateway.go:299）。
//!
//! 刻意**不**复刻的部分：真实鉴权（token→sha256 查库）、任务派发、租约。
//! 那些依赖服务端 DB 与 dispatcher，属于后续阶段；此处的目标是让协议层可独立验收。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use hd_protocol::envelope::{Envelope, MessageType, CURRENT_PROTOCOL_VERSION};
use hd_protocol::payload::{PingPayload, PongPayload, WelcomePayload};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;

/// 假服务端配置。
#[derive(Debug, Clone)]
pub struct FakeServerConfig {
    /// 期望的 device token（`?token=` 必须与之一致）。
    pub token: String,
    /// 下发的设备 ID。
    pub device_id: String,
    /// 下发的心跳间隔（秒）。
    ///
    /// 🔴 端侧**必须**据此驱动心跳，不得硬编码 15s。测试里刻意设成非 15 的值
    /// （如 1），一旦端侧硬编码就会立刻暴露。
    pub heartbeat_s: i32,
    /// 下发的离线判定超时（秒）。
    pub offline_after_s: i32,
}

impl Default for FakeServerConfig {
    fn default() -> Self {
        Self {
            token: "hgd_test_token".into(),
            device_id: "dev_fake_001".into(),
            heartbeat_s: 1,
            offline_after_s: 45,
        }
    }
}

/// 假服务端运行句柄。`Drop` 时不主动 abort（由测试决定），故需显式 `shutdown`。
pub struct FakeServer {
    /// 实际监听的 WebSocket URL，**不含 token**。
    ///
    /// 刻意不把 token 拼进 URL：`Connection::connect` 会自行附加，若这里也带一个，
    /// URL 就会出现两个 `token=` 参数，而鉴权逻辑可能命中"正确那个"，导致
    /// 「错误令牌应被拒」的测试假通过（这个坑已经踩过）。
    pub url: String,
    /// 收到的 `ping` 次数（供断言端侧确实在发心跳）。
    pub pings: Arc<AtomicUsize>,
    /// 收到的 `hello` 次数。
    pub hellos: Arc<AtomicUsize>,
    /// 最近一次 `ping` 帧里携带的 `capabilities_hash`（供断言心跳复述能力摘要）。
    pub last_ping_caps_hash: Arc<std::sync::Mutex<Option<String>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl FakeServer {
    /// 启动假服务端（绑定 `127.0.0.1` 随机端口）。
    pub async fn start(cfg: FakeServerConfig) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let pings = Arc::new(AtomicUsize::new(0));
        let hellos = Arc::new(AtomicUsize::new(0));
        let last_ping_caps_hash: Arc<std::sync::Mutex<Option<String>>> =
            Arc::new(std::sync::Mutex::new(None));
        let expected_token = cfg.token.clone();
        let url = format!("ws://{addr}/api/v1/devices/ws");

        let pings_task = Arc::clone(&pings);
        let hellos_task = Arc::clone(&hellos);
        let caps_task = Arc::clone(&last_ping_caps_hash);

        let handle = tokio::spawn(async move {
            // 只服务一个连接即可满足 P2 验收（重连测试会重复 start）。
            if let Ok((stream, _)) = listener.accept().await {
                let exp = expected_token.clone();
                // 升级前鉴权：token 不匹配直接 401，绝不 101。
                //
                // `result_large_err`：`ErrorResponse` 是 tungstenite 的类型，体积由它决定，
                // 我们无法缩小。握手回调整体只执行一次，栈上多占几十字节无实际代价，
                // 故在此精确抑制而非全局关闭该 lint。
                #[allow(clippy::result_large_err)]
                let callback =
                    move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
                        if token_matches(req.uri().query().unwrap_or(""), &exp) {
                            Ok(resp)
                        } else {
                            let mut err = ErrorResponse::new(Some("缺少或无效的设备令牌".into()));
                            *err.status_mut() = StatusCode::UNAUTHORIZED;
                            Err(err)
                        }
                    };

                let Ok(ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
                    return;
                };
                let (mut sink, mut src) = ws.split();

                // 复刻 gateway.go:205 —— 连上即主动下发 welcome，不等 hello。
                let welcome = WelcomePayload {
                    device_id: cfg.device_id.clone(),
                    server_time: now_ms(),
                    protocol_version: CURRENT_PROTOCOL_VERSION,
                    heartbeat_s: cfg.heartbeat_s,
                    offline_after_s: cfg.offline_after_s,
                    pending: 0,
                    lease_epoch: 0,
                };
                let env = Envelope::new(
                    MessageType::Welcome,
                    "",
                    Some(serde_json::to_value(&welcome).unwrap()),
                );
                let text = serde_json::to_string(&env).unwrap();
                if sink.send(Message::Text(text)).await.is_err() {
                    return;
                }

                while let Some(Ok(msg)) = src.next().await {
                    let Message::Text(text) = msg else { continue };
                    let Ok(env) = serde_json::from_str::<Envelope>(&text) else {
                        continue;
                    };
                    match env.msg_type {
                        MessageType::Ping => {
                            pings_task.fetch_add(1, Ordering::SeqCst);
                            if let Ok(Some(p)) = env.decode::<PingPayload>() {
                                if let Ok(mut guard) = caps_task.lock() {
                                    *guard = Some(p.capabilities_hash);
                                }
                            }
                            let pong = PongPayload {
                                server_time: now_ms(),
                                pending: 0,
                                protocol_version: CURRENT_PROTOCOL_VERSION,
                            };
                            // 复刻 gateway.go:299 —— pong 必须回带 ping 的 id。
                            let resp = Envelope::new(
                                MessageType::Pong,
                                env.id.clone(),
                                Some(serde_json::to_value(&pong).unwrap()),
                            );
                            let out = serde_json::to_string(&resp).unwrap();
                            if sink.send(Message::Text(out)).await.is_err() {
                                return;
                            }
                        }
                        MessageType::Hello => {
                            hellos_task.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                }
            }
        });

        Ok(Self {
            url,
            pings,
            hellos,
            last_ping_caps_hash,
            handle,
        })
    }

    /// 已收到的 ping 数。
    pub fn ping_count(&self) -> usize {
        self.pings.load(Ordering::SeqCst)
    }

    /// 已收到的 hello 数。
    pub fn hello_count(&self) -> usize {
        self.hellos.load(Ordering::SeqCst)
    }

    /// 最近一次 ping 携带的 `capabilities_hash`（尚未收到 ping 时为 `None`）。
    pub fn last_ping_capabilities_hash(&self) -> Option<String> {
        self.last_ping_caps_hash.lock().ok().and_then(|g| g.clone())
    }

    /// 显式停止（测试结束调用，避免任务泄漏到下一个测试）。
    pub fn shutdown(self) {
        self.handle.abort();
    }
}

/// 当前毫秒时间戳。
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 严格校验 query 中的 `token=`。
///
/// 刻意**不使用** `.any()`：那样只要 URL 里出现任意一个正确的 `token=x` 就放行，
/// 而重复 token 参数（`?token=right&token=wrong`）在真实服务端是可疑输入。
/// 这里要求「恰好一个 token 参数，且值等于期望值」，让测试能真正捕捉多参数问题。
fn token_matches(query: &str, expected: &str) -> bool {
    let mut found: Option<&str> = None;
    for kv in query.split('&') {
        if let Some(v) = kv.strip_prefix("token=") {
            if found.is_some() {
                // 出现多个 token 参数 → 一律拒绝
                return false;
            }
            found = Some(v);
        }
    }
    found == Some(expected)
}
