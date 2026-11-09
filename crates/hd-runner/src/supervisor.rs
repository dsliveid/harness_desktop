//! 重连环：把「断线」这件事真正接到 [`ReconnectPolicy`] 上。
//!
//! ## 为什么需要这一层
//!
//! `reconnect.rs` 只是一张决策表（给定第几次失败 + 错误码 → 退避多久或停止），
//! `transport.rs` 只管一条连接的生死读写。两者之间缺一个东西：**谁在什么时机
//! 把断线事实喂给决策表、谁负责等那段退避、谁负责记账（连续失败次数）**。
//! 缺了它，上层只能自己写 `loop { connect(); sleep(1s); }` —— 那就必然出现
//! 「终态错误也照着重试」和「重连成功但计数没清零，几次抖动后永久放弃」两个经典 bug。
//!
//! ## 状态机
//!
//! ```text
//!           ┌──────────── 失败 → decide(attempt, code)
//!           ▼                    ├─ Stop  → Stopped{RejectedByServer | AttemptsExhausted}
//!     Connecting ──成功──▶ Connected ──断线──▶ attempt += 1
//!           ▲                    │
//!           └──── RetryAfter ◀────┘  （先睡 delay，再重连）
//! ```
//!
//! 三条铁律（都有测试钉住）：
//! 1. **连接成功即把 attempt 清零**。否则网络抖三次就永久放弃，用户会看到
//!    「重启一下 Runner 才能用」的玄学故障。
//! 2. **终态错误码不睡直接停**。服务端说 `device.replaced` 时重连只会再被拒一次。
//! 3. **心跳间隔只认 `welcome`**（`link.heartbeat().interval`），本文件里不允许出现
//!    任何 `15`。
//!
//! ## 可测试性
//!
//! 连接与等待都被抽成 trait（[`Connector`] / [`Sleeper`]），所以「退避 1→2→4s」这类
//! 断言用 [`NoopSleeper`] 零延迟跑完，不需要真的等 7 秒。

// 本模块的 trait 方法刻意写成 `-> impl Future<...> + Send` 而非 `async fn`：
// trait 里 `async fn` 生成的 future **不带 Send 约束**，会让 `Supervisor::run` 这个
// future 不再 Send，e2e 里就没法 `tokio::spawn` 它。clippy 的建议在这里会牺牲
// 可并发性，故整模块关掉该 lint（仅此一条，不放宽其他告警）。
#![allow(clippy::manual_async_fn)]

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use hd_protocol::envelope::{Envelope, MessageType};
use hd_protocol::error_code;
use hd_protocol::payload::{ErrorPayload, HelloPayload, TaskDispatchPayload, TaskProgressPayload};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::heartbeat::HeartbeatPolicy;
use crate::progress::ChannelSink;
use crate::reconnect::{ReconnectDecision, ReconnectPolicy};
use crate::router::Router;
use crate::transport::{Connection, TransportError};

/// 默认并发派发上限。
///
/// 为什么必须有个数：executor 会真跑子进程（`git` / `node`），无上限的并发
/// 等于「服务端一口气推 100 条派发 → 端侧起 100 个进程」把用户机器打爆。
/// 4 是「桌面机从容、又不是串行白等」的经验值，可由构造器注入以便调节。
pub const DEFAULT_MAX_CONCURRENCY: usize = 4;

/// 出站帧队列容量。
///
/// 出站帧是**不可丢**的（`task.result` 丢了服务端会重派，`task.progress` 丢了
/// 进度条就断句），所以这里用 `send().await` 而不是 `try_send`：队列满时让
/// 生产方等一等，天然形成背压。容量取 256：单帧几十字节到几 KB，即使打满也
/// 只有几百 KB，却足以吸收「一次派发突发吐几十个 chunk」的瞬时尖峰。
const OUTBOUND_QUEUE_CAPACITY: usize = 256;

/// 并发处理一条派发任务：建独立 sink → 执行 → 把 chunk 转成 `task.progress` 帧。
///
/// ## 为什么进度帧必须在**这里**（而不是在 session_loop 里逐个 select）
///
/// `router.dispatch` 内部会 `await` executor，期间 executor 线程不断
/// `sink.chunk(..)`。要把这些块变成帧，必须与 dispatch future **同时**推进，
/// 否则只能等 dispatch 结束才一次性发完 —— 那就不是流式了。
/// 放进一个独立任务后，`tokio::select!` 可以在「dispatch 还没完」时就把块发出去。
///
/// ## 出站为什么只走 mpsc
///
/// `tx` 是 [`mpsc::Sender<Envelope>`] 的克隆：所有并发任务共享同一个队列，
/// 由 `session_loop` 的**单一写者**串行写入 WS。这样既不需要 `&mut link` 打锁，
/// 也不可能出现两帧字节交错（WS 帧是原子写，交错只会出现在"同一帧被分两次写"）。
async fn run_dispatch(
    router: Arc<Router>,
    payload: TaskDispatchPayload,
    tx: mpsc::Sender<Envelope>,
) {
    let (sink, mut chunks) = ChannelSink::new();
    // task_id 与 tool_event_id 值恒等（protocol.go:235 / payload.rs 注释）。
    let task_id = payload.tool_event_id.clone();
    let run_id = payload.run_id.clone();

    // 用 Box::pin 而不是裸 future：select! 需要 `Unpin`，而 dispatch 返回的
    // future 里含 async fn 链，体积不可控，pin 之后才能安全地被 select 反复轮询。
    let mut dispatch = Box::pin(router.dispatch(&payload, &sink));

    let result = loop {
        tokio::select! {
            // ① 有一个 chunk 就到了发一帧（真正流式的关键分支）
            Some(chunk) = chunks.recv() => {
                let p = TaskProgressPayload {
                    task_id: task_id.clone(),
                    run_id: run_id.clone(),
                    tool_event_id: task_id.clone(),
                    chunk,
                };
                let env = Envelope::new(
                    MessageType::TaskProgress,
                    task_id.clone(),
                    serde_json::to_value(p).ok(),
                );
                // 队列满时在这里等：宁可拖慢 executor 的吐块速度，也不丢进度。
                // 发送失败（写者任务已退出 = 连接已死）则立刻停手，不再白跑。
                if tx.send(env).await.is_err() {
                    debug!(task_id = %task_id, "出站队列已关闭，停止转发进度");
                    break dispatch.as_mut().await;
                }
            }
            // ② 执行结束了。此时 chunks 里可能还有残余块没发完，
            //    一次性抽干（否则最后几行输出会永久滞留）。
            r = &mut dispatch => {
                while let Ok(chunk) = chunks.try_recv() {
                    let p = TaskProgressPayload {
                        task_id: task_id.clone(),
                        run_id: run_id.clone(),
                        tool_event_id: task_id.clone(),
                        chunk,
                    };
                    let env = Envelope::new(
                        MessageType::TaskProgress,
                        task_id.clone(),
                        serde_json::to_value(p).ok(),
                    );
                    if tx.send(env).await.is_err() {
                        break;
                    }
                }
                break r;
            }
        }
    };

    // 终态放最后一帧：服务端据此收尾，必须严格晚于该任务的所有 progress。
    let env = Envelope::new(
        MessageType::TaskResult,
        result.tool_event_id.clone(),
        serde_json::to_value(&result).ok(),
    );
    if tx.send(env).await.is_err() {
        debug!(task_id = %task_id, "出站队列已关闭，task.result 未能发出");
    }
}

/// 循环终止的原因（给上层 UI 用：要不要弹「重新配对」由它决定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// 服务端明确拒绝，重连无意义，必须用户介入（重新配对 / 升级客户端）。
    RejectedByServer {
        /// 触发拒绝的错误码，如 `device.revoked`。
        code: String,
    },
    /// 连续失败次数耗尽。多半是服务端没起来或本机断网，用户检查后重启即可。
    AttemptsExhausted {
        /// 放弃时的连续失败次数。
        attempts: u32,
    },
}

impl StopReason {
    /// 映射到进程退出码（契约见 `hd_protocol::exit_code`）。
    ///
    /// ## 为什么映射放在这里而不是调用方
    ///
    /// 「终止原因 → 退出码」是 `StopReason` 自身的语义延伸，写在这里能让
    /// **穷尽性检查**替我们兜底：将来有人给 `StopReason` 新增变体，会在这里
    /// 编译失败，而不是悄悄落到某个 `_ =>` 兜底分支上。
    ///
    /// ## 判定依据
    ///
    /// `RejectedByServer` 携带的是服务端帧级错误码，语义差异很大，必须逐个区分：
    /// 被吊销要清令牌重配对，被替换则连重启都不该做（会互踢）。
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        use hd_protocol::exit_code as ec;

        match self {
            StopReason::RejectedByServer { code } => match code.as_str() {
                // 字面量与 `hd_protocol::error_code` 的 FRAME_REVOKED / DEVICE_REVOKED 相同。
                "device.revoked" => ec::EXIT_REVOKED,
                // 被新连接替换：重启只会把对方踢掉，形成互踢循环。
                "device.replaced" => ec::EXIT_REPLACED,
                // 协议不匹配：重试不会让版本变匹配。
                "device.protocol_mismatch" => ec::EXIT_PROTOCOL_MISMATCH,
                // 其余帧级拒绝（如 task_unsupported / server_closing）按配置性问题处理：
                // 不重启，让宿主把原因带给用户，而不是盲目重试掩盖真正的问题。
                _ => ec::EXIT_NO_AUTH,
            },
            // 重试预算耗尽：典型的「服务端没起来 / 本机断网」，修好即可恢复。
            StopReason::AttemptsExhausted { .. } => ec::EXIT_RETRYABLE,
        }
    }
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopReason::RejectedByServer { code } => {
                write!(f, "服务端拒绝连接（{code}），需重新配对")
            }
            StopReason::AttemptsExhausted { attempts } => {
                write!(f, "连续 {attempts} 次连接失败，已停止重试")
            }
        }
    }
}

/// 循环对外可见的事件。既用于 UI 状态灯，也是测试断言的抓手。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorEvent {
    /// 即将发起一次连接（含首次）。
    Connecting,
    /// 握手成功，进入在线态。
    Connected {
        /// 服务端分配的设备 ID。
        device_id: String,
        /// 服务端下发的心跳节奏（UI 可展示，测试可断言没被硬编码）。
        heartbeat: HeartbeatPolicy,
    },
    /// 连接断了（原因已脱敏，只含错误码/可读描述，不含令牌）。
    Disconnected {
        /// 断开原因。
        reason: String,
    },
    /// 已决定退避重连。
    Reconnecting {
        /// 第几次连续失败（从 1 开始）。
        attempt: u32,
        /// 等待时长。
        delay: Duration,
    },
    /// 循环终止。
    Stopped {
        /// 终止原因。
        reason: StopReason,
    },
}

/// 事件观察者。全部方法都有默认空实现，调用方只需覆写关心的那几个。
///
/// 刻意用 trait 而不是 channel：重连环运行在单个 tokio 任务里，同步回调不会丢事件，
/// 测试里直接 `Vec::push` 就能断言顺序，不必为「收齐事件」加 sleep。
pub trait SupervisorObserver {
    /// 收到一个事件。
    fn on_event(&mut self, _event: SupervisorEvent) {}
}

/// 什么都不做的观察者。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopObserver;

impl SupervisorObserver for NoopObserver {}

/// 可等待器（把「等退避」抽出来，测试才能零延迟）。
pub trait Sleeper {
    /// 等待 `d`。
    fn sleep(&mut self, d: Duration) -> impl Future<Output = ()> + Send;
}

/// 生产用等待器。
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioSleeper;

impl Sleeper for TokioSleeper {
    fn sleep(&mut self, d: Duration) -> impl Future<Output = ()> + Send {
        async move { tokio::time::sleep(d).await }
    }
}

/// 零延迟等待器：只用于测试，以及「不允许重试」的单次连接场景。
///
/// 它能存在正是因为退避被做成了可注入的；若把 `tokio::time::sleep` 写死在循环里，
/// 验证「1→2→4s 递增」的测试就得真跑 7 秒。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSleeper;

impl Sleeper for NoopSleeper {
    fn sleep(&mut self, _d: Duration) -> impl Future<Output = ()> + Send {
        async move {}
    }
}

/// 一条「已经握手成功、还活着」的连接。
///
/// 只暴露重连环真正需要的四件事，因此 [`Connection`] 之外的实现（测试假连接）成本极低。
pub trait LiveLink {
    /// 服务端分配的设备 ID。
    fn device_id(&self) -> &str;
    /// 服务端下发的心跳节奏。
    fn heartbeat(&self) -> HeartbeatPolicy;
    /// 发一次心跳并等 `pong`，返回待派发任务数。
    fn send_ping(&mut self) -> impl Future<Output = Result<i32, TransportError>> + Send;
    /// 读下一帧；`None` 表示对端正常关闭。
    fn read_frame(
        &mut self,
    ) -> impl Future<Output = Result<Option<Envelope>, TransportError>> + Send;
    /// 发送一帧（任务族回执用）。
    ///
    /// 默认实现是「静默丢弃」而不是抽象成必须实现：真实 [`Connection`] 会覆盖它，
    /// 而只关心心跳节奏的测试假连接可以完全不理会任务回执。若把它做成必选方法，
    /// 每个假连接都要补一段与自身断言无关的样板代码。
    fn send_frame(
        &mut self,
        _env: &Envelope,
    ) -> impl Future<Output = Result<(), TransportError>> + Send {
        async move { Ok(()) }
    }
}

impl LiveLink for Connection {
    fn device_id(&self) -> &str {
        &self.session.device_id
    }

    fn heartbeat(&self) -> HeartbeatPolicy {
        self.session.heartbeat
    }

    fn send_ping(&mut self) -> impl Future<Output = Result<i32, TransportError>> + Send {
        // 方法名刻意与固有方法 `Connection::ping_once` 不同，避免 trait 方法自调用。
        async move { self.ping_once().await }
    }

    fn read_frame(
        &mut self,
    ) -> impl Future<Output = Result<Option<Envelope>, TransportError>> + Send {
        async move { self.next_frame().await }
    }

    fn send_frame(
        &mut self,
        env: &Envelope,
    ) -> impl Future<Output = Result<(), TransportError>> + Send {
        let env = env.clone();
        // 克隆而非借用：返回的 future 必须 `'static + Send` 才能进 select 与 `tokio::spawn`，
        // 而 `Envelope` 只是一层小 JSON，克隆成本远低于为此改签名。
        async move { self.send_envelope(&env).await }
    }
}

/// 连接工厂。
pub trait Connector {
    /// 产出的连接类型。
    type Link: LiveLink;
    /// 建立连接（含握手）。失败必须返回带错误码的 [`TransportError`]。
    fn connect(&mut self) -> impl Future<Output = Result<Self::Link, TransportError>> + Send;
}

/// 面向真实网关的连接工厂。
pub struct WsConnector {
    /// WS 端点，**不含** token（由 `Connection::connect` 追加）。
    url: String,
    /// 设备令牌。
    token: String,
    /// 可选首帧自述。
    hello: Option<HelloPayload>,
}

impl WsConnector {
    /// 构造连接工厂。
    pub fn new(url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            token: token.into(),
            hello: None,
        }
    }

    /// 附加 `hello` 首帧自述。
    pub fn with_hello(mut self, hello: HelloPayload) -> Self {
        self.hello = Some(hello);
        self
    }
}

/// 🔴 手写 `Debug`：令牌绝不能进日志。
impl fmt::Debug for WsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsConnector")
            .field("url", &self.url)
            .field("token", &crate::ipc::redact_token(&self.token))
            .field("hello", &self.hello.is_some())
            .finish()
    }
}

impl Connector for WsConnector {
    type Link = Connection;

    fn connect(&mut self) -> impl Future<Output = Result<Connection, TransportError>> + Send {
        async move { Connection::connect(&self.url, &self.token, self.hello.clone()).await }
    }
}

/// 重连环。
pub struct Supervisor<C, S = TokioSleeper> {
    connector: C,
    policy: ReconnectPolicy,
    sleeper: S,
    /// 任务路由器。
    ///
    /// 刻意做成 `Option` 而不是必填：现有心跳/重连测试与「只做心跳」的部署形态
    /// 不需要路由能力，`None` 时遇到 dispatch 帧的行为与改造前完全一致（忽略）。
    /// 这样本次改造不会逼着每个既有测试去构造一个 Router。
    router: Option<Arc<Router>>,
    /// 并发派发上限（`Semaphore` 的初始许可数）。
    ///
    /// 做成字段而不是常量：单测要能用「上限=1」验证排队、「上限=4」验证并行，
    /// 运维也可能因为机器规格需要调低。默认 [`DEFAULT_MAX_CONCURRENCY`]。
    max_concurrency: usize,
}

impl<C: Connector> Supervisor<C, TokioSleeper> {
    /// 用默认（tokio）等待器构造。
    pub fn new(connector: C, policy: ReconnectPolicy) -> Self {
        Self::with_sleeper(connector, policy, TokioSleeper)
    }
}

impl Supervisor<WsConnector, TokioSleeper> {
    /// 直连真实网关的快捷构造。
    pub fn for_ws(
        url: impl Into<String>,
        token: impl Into<String>,
        hello: Option<HelloPayload>,
    ) -> Self {
        let mut connector = WsConnector::new(url, token);
        if let Some(hello) = hello {
            connector = connector.with_hello(hello);
        }
        Self::new(connector, ReconnectPolicy::default())
    }
}

impl<C: Connector, S: Sleeper> Supervisor<C, S> {
    /// 注入自定义等待器（测试用 [`NoopSleeper`]）。
    pub fn with_sleeper(connector: C, policy: ReconnectPolicy, sleeper: S) -> Self {
        Self {
            connector,
            policy,
            sleeper,
            router: None,
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
        }
    }

    /// 设置并发派发上限（最小夹到 1）。
    ///
    /// 用 `max(1)` 兜底而不是让 0 生效：`Semaphore::new(0)` 会让**所有**派发任务
    /// 永久挂起等许可，表现是「Runner 在线但什么都不执行」—— 最难查的一类故障。
    pub fn with_max_concurrency(mut self, n: usize) -> Self {
        self.max_concurrency = n.max(1);
        self
    }

    /// 挂上任务路由器：此后 `task.dispatch` 帧会被真正执行并回 `task.result`。
    ///
    /// 用 `Arc<Router>` 而非 `Router` 值：路由表与幂等缓存在重连之间必须**继续存在**，
    /// 否则每次断线重连都换一份新缓存，「重派只回放」这条语义就在重连处失效了。
    pub fn with_router(mut self, router: Arc<Router>) -> Self {
        self.router = Some(router);
        self
    }

    /// 运行到终止为止，返回终止原因。
    ///
    /// 只有两种返回值，且都是「不该再自动重试」的情况：被服务端终态拒绝，或重试耗尽。
    /// 正常情况下本方法不会返回 —— 它会一直在线并持续发心跳。
    pub async fn run<O: SupervisorObserver>(&mut self, observer: &mut O) -> StopReason {
        // 连续失败计数。🔴 只在「连接成功」时清零，别在别处动它。
        let mut attempt: u32 = 0;
        loop {
            observer.on_event(SupervisorEvent::Connecting);
            match self.connector.connect().await {
                Ok(mut link) => {
                    // 连上就清零：一次成功足以证明网络与令牌都正常，历史失败不再累计。
                    attempt = 0;
                    observer.on_event(SupervisorEvent::Connected {
                        device_id: link.device_id().to_string(),
                        heartbeat: link.heartbeat(),
                    });

                    let err =
                        session_loop(&mut link, self.router.as_ref(), self.max_concurrency).await;
                    observer.on_event(SupervisorEvent::Disconnected {
                        reason: err.to_string(),
                    });
                    attempt += 1;
                    if let Some(stop) = self
                        .backoff_or_stop(attempt, err.terminal_code(), observer)
                        .await
                    {
                        return stop;
                    }
                }
                Err(err) => {
                    attempt += 1;
                    if let Some(stop) = self
                        .backoff_or_stop(attempt, err.terminal_code(), observer)
                        .await
                    {
                        return stop;
                    }
                }
            }
        }
    }

    /// 按策略决定「睡多久再来」还是「停」。返回值 `Some` 即终止原因。
    async fn backoff_or_stop<O: SupervisorObserver>(
        &mut self,
        attempt: u32,
        err_code: Option<&str>,
        observer: &mut O,
    ) -> Option<StopReason> {
        match self.policy.decide(attempt, err_code) {
            ReconnectDecision::Stop => {
                // 终止原因要能区分「服务端不认你」与「次数用完」，否则 UI 只能干瞪眼。
                let reason = match err_code {
                    Some(code) if error_code::is_terminal(code) => StopReason::RejectedByServer {
                        code: code.to_string(),
                    },
                    _ => StopReason::AttemptsExhausted { attempts: attempt },
                };
                observer.on_event(SupervisorEvent::Stopped {
                    reason: reason.clone(),
                });
                Some(reason)
            }
            ReconnectDecision::RetryAfter(delay) => {
                observer.on_event(SupervisorEvent::Reconnecting { attempt, delay });
                self.sleeper.sleep(delay).await;
                None
            }
        }
    }
}

/// 「多久没收到任何帧」的判定错误（口径同服务端 `gateway.go:228`）。
fn silence_error(hb: HeartbeatPolicy) -> TransportError {
    TransportError::Server {
        code: error_code::FRAME_OFFLINE_TIMEOUT.to_string(),
        message: format!("{}s 内未收到任何帧", hb.read_timeout().as_secs()),
    }
}

/// 一条连接的生命周期内循环：按服务端下发节奏发心跳，并盯住对端帧/静默。
///
/// 返回即代表「这条连接死了」，返回值同时是重连决策的错误来源。
///
/// ## 架构：三件并发的事 + 一个单写者
///
/// ```text
///   ┌─────────────── session_loop（本函数）───────────────┐
///   │  · 心跳定时（独占 &mut link 发 ping/pong）           │
///   │  · 读帧（独占 &mut link）                            │
///   │  · 收到 task.dispatch → 抢信号量 → spawn 执行任务     │
///   └───────────────────────┬─────────────────────────────┘
///                           │ mpsc::Sender<Envelope>（clone 给每个任务）
///                           ▼
///              ┌───── outbound_writer（唯一写者）─────┐
///              │  串行 link.send_frame(env)           │
///              └──────────────────────────────────────┘
/// ```
///
/// ## 为什么要「单写者」而不是「给连接加锁」
///
/// `send_frame` 需要 `&mut self`，N 个并发任务都想写就必须共享连接。两种做法：
/// 1. `Arc<Mutex<Link>>` —— 每个任务持锁写帧。看起来能用，但**心跳也在这把锁上**：
///    长任务吐块时持锁写 WS，一旦网络慢（写阻塞），心跳就被饿住，服务端会按
///    `offline_after` 判端侧离线并踢掉连接 —— 这是最坏的一种耦合。
/// 2. **单写者任务 + mpsc**（本实现）—— 所有帧排进无共享的队列，只有一个地方
///    碰连接。天然串行（不会两帧字节交错）、天然保序、心跳与写帧互不抢占。
///
/// 另外，`link` 是泛型参数 `&mut L`，**根本没法**跨任务共享（`&mut L` 不是 `'static`
/// 也不可 `Clone`）。单写者也是这里唯一不需要改 `LiveLink` 签名的解法。
async fn session_loop<L: LiveLink>(
    link: &mut L,
    router: Option<&Arc<Router>>,
    max_concurrency: usize,
) -> TransportError {
    let hb = link.heartbeat();
    // 连上立刻发一次心跳：握手成功不代表通道真的可用，早发早发现；顺带让 e2e
    // 不必为「首拍」多等一个完整周期。
    let mut next_ping = Instant::now();
    // 静默计时从「最近一次收到帧」算起，而不是从本轮循环开始算 —— 否则持续
    // 收到无关帧时静默判定永远不会触发，连接已死也发现不了。
    let mut last_rx = Instant::now();

    // 出站队列 + 单写者。writer 在独立任务里跑，本循环从此不再直接写帧。
    //
    // 但 `link` 是 `&mut L`，无法 move 进 spawn。因此这里把写者做成
    // 「一个不 spawn 的 future，由本循环的 select! 推进」——它依然只有一个
    // 执行者、天然串行，同时借用关系保持简单。
    let (out_tx, mut out_rx) = mpsc::channel::<Envelope>(OUTBOUND_QUEUE_CAPACITY);
    // 自己再留一份发送端：否则一旦所有任务结束，`out_rx.recv()` 会返回 None，
    // 下面的 select 分支就会被永久禁用（喝水被渴死）。
    let _keepalive_tx = out_tx.clone();

    let semaphore = Arc::new(Semaphore::new(max_concurrency.max(1)));
    let mut tasks: JoinSet<()> = JoinSet::new();

    loop {
        // 顺带回收已完成的任务，避免 JoinSet 无限增长。
        while tasks.try_join_next().is_some() {}

        let now = Instant::now();
        if now >= next_ping {
            match link.send_ping().await {
                // 间隔只认 welcome 下发值，绝不硬编码
                Ok(_pending) => {
                    next_ping = Instant::now() + hb.interval;
                    // pong 已回，等价于收到帧
                    last_rx = Instant::now();
                }
                Err(e) => return e,
            }
            continue;
        }

        let ping_wait = next_ping.saturating_duration_since(now);
        let silence_left = (last_rx + hb.read_timeout()).saturating_duration_since(now);
        if silence_left.is_zero() {
            return silence_error(hb);
        }

        tokio::select! {
            // ① 该发下一次心跳了：只跳出等待，真正的发送在循环头（那里独占 link）
            _ = tokio::time::sleep(ping_wait) => {}
            // ② 有出站帧待写：唯一的写者路径（心跳与它在 select 里互斥，
            //    所以 `&mut link` 的两个借用不会同时存在）。
            Some(env) = out_rx.recv() => {
                if let Err(e) = link.send_frame(&env).await {
                    warn!(error = %e, "出站帧发送失败，连接已坏");
                    tasks.abort_all();
                    return e;
                }
            }
            // ③ 读帧
            res = tokio::time::timeout(silence_left, link.read_frame()) => {
                match res {
                    Err(_elapsed) => return silence_error(hb),
                    Ok(Err(e)) => return e,
                    Ok(Ok(None)) => {
                        return TransportError::Server {
                            // 对端正常关闭不是死局：服务端重启后应退避重连，
                            // 故借用 server_closing 这个「可恢复」码，而不是当成终态。
                            code: error_code::FRAME_SERVER_CLOSING.to_string(),
                            message: "对端关闭了连接".to_string(),
                        };
                    }
                    Ok(Ok(Some(env))) => {
                        last_rx = Instant::now();
                        // 单帧处理抽成独立函数：既要让 session_loop 保持线性可读，
                        // 也为了让「一帧进来会发生什么」可以在不跑时钟循环的情况下测。
                        match handle_frame(env, router, &out_tx, &semaphore, &mut tasks) {
                            FrameAction::Continue => {}
                            FrameAction::Close(err) => {
                                // 等未完成的任务把终态写进队列，再尽量发出去一点点，
                                // 免得重连后服务端还得重派（幂等保证正确性，但没必要
                                // 白白浪费一次往返）。
                                tasks.abort_all();
                                return err;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// `handle_frame` 的判定结果。
enum FrameAction {
    /// 该帧处理完毕，继续维持连接。
    Continue,
    /// 该帧要求关闭连接（携带原因，交给重连决策）。
    Close(TransportError),
}

/// 处理一帧（**同步**，不 `await`）。
///
/// 之所以能是同步的：接上出站队列之后，处理一帧只剩下「解码 + 把活派给任务」，
/// 不再需要就地写连接。这让 `session_loop` 的 select 干净很多 —— 一个会
/// `.await` 的帧处理函数会让读帧分支持有 `&mut link` 的同时去等任务完成。
///
/// `router` 为 `None` 时，任务派发帧被静默忽略——这正是本文件接入 router 之前的
/// 行为，因此所有既有的心跳/重连测试无需改动即可继续通过。
fn handle_frame(
    env: Envelope,
    router: Option<&Arc<Router>>,
    out_tx: &mpsc::Sender<Envelope>,
    semaphore: &Arc<Semaphore>,
    tasks: &mut JoinSet<()>,
) -> FrameAction {
    match env.msg_type {
        // 错误码必须原样上报，重连决策全靠它
        MessageType::Error => {
            let p = env
                .decode::<ErrorPayload>()
                .ok()
                .flatten()
                .unwrap_or_default();
            FrameAction::Close(TransportError::Server {
                code: p.code,
                message: p.message,
            })
        }
        MessageType::TaskDispatch => {
            let Some(router) = router else {
                // 未接路由：保持旧行为（忽略），而不是报错断连 ——
                // 服务端可能对未申报能力的端下发任务，那不该被当成链路故障。
                debug!("未挂载 router，忽略 task.dispatch 帧");
                return FrameAction::Continue;
            };
            // 解码失败属于**服务端**的问题，不该断连也不该 panic：回一条 failed
            // 让服务端知道这次派发没被接受，比静默吞掉更容易排查。
            match env.decode::<TaskDispatchPayload>() {
                Ok(Some(payload)) => {
                    // Semaphore 在上限内立刻放行；打满时这里会**等**（而不是丢任务）：
                    // 派发帧本身已经收到了，丢掉它等于静默拒绝用户请求。
                    // 但等待期间我们持有着 session_loop 的控制权 —— 所以把「等信号量」
                    // 也一起搬进任务里，让读帧循环不被任务排队阻塞。
                    let router = Arc::clone(router);
                    let tx = out_tx.clone();
                    let permit_pool = Arc::clone(semaphore);
                    tasks.spawn(async move {
                        let Ok(_permit) = permit_pool.acquire_owned().await else {
                            // 信号量被关闭（会话结束）：不再启动新任务。
                            return;
                        };
                        run_dispatch(router, payload, tx).await
                    });
                }
                Ok(None) => warn!("task.dispatch 无负载，已忽略"),
                Err(e) => warn!(error = %e, "task.dispatch 负载解码失败，已忽略"),
            }
            FrameAction::Continue
        }
        // 其余帧（pong / welcome / 租约等）当前不参与判定
        _ => FrameAction::Continue,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// 一次读帧的结果（测试脚本的最小单元）。
    type FrameResult = Result<Option<Envelope>, TransportError>;
    /// 单条连接要依次吐出的读帧结果队列。
    type FrameScript = VecDeque<FrameResult>;

    /// 事件收集器：单任务同步回调，`Vec::push` 即可完整保序。
    #[derive(Default, Clone)]
    struct CollectingObserver {
        events: Arc<Mutex<Vec<SupervisorEvent>>>,
    }

    impl CollectingObserver {
        fn events(&self) -> Vec<SupervisorEvent> {
            self.events.lock().expect("测试内不应有锁竞争").clone()
        }

        fn reconnecting_attempts(&self) -> Vec<u32> {
            self.events()
                .into_iter()
                .filter_map(|e| match e {
                    SupervisorEvent::Reconnecting { attempt, .. } => Some(attempt),
                    _ => None,
                })
                .collect()
        }

        fn stop_reason(&self) -> Option<StopReason> {
            self.events().into_iter().find_map(|e| match e {
                SupervisorEvent::Stopped { reason } => Some(reason),
                _ => None,
            })
        }
    }

    impl SupervisorObserver for CollectingObserver {
        fn on_event(&mut self, event: SupervisorEvent) {
            self.events.lock().expect("测试内不应有锁竞争").push(event);
        }
    }

    /// 假连接：ping 成功，读帧的行为由脚本决定（模拟「连上后收到什么」）。
    struct ScriptedLink {
        device_id: String,
        heartbeat: HeartbeatPolicy,
        /// 依次弹出的读帧结果；`None` 表示脚本用尽 → 挂起（模拟健康的长连接）。
        frames: Arc<Mutex<FrameScript>>,
        /// 记录本连接发出的帧（验证 `task.result` 回执是否真的发出去）。
        outbox: Arc<Mutex<Vec<Envelope>>>,
    }

    impl LiveLink for ScriptedLink {
        fn device_id(&self) -> &str {
            &self.device_id
        }

        fn heartbeat(&self) -> HeartbeatPolicy {
            self.heartbeat
        }

        fn send_ping(&mut self) -> impl Future<Output = Result<i32, TransportError>> + Send {
            async move { Ok(0) }
        }

        fn read_frame(
            &mut self,
        ) -> impl Future<Output = Result<Option<Envelope>, TransportError>> + Send {
            let next = self.frames.lock().expect("不应有锁竞争").pop_front();
            async move {
                match next {
                    Some(r) => r,
                    // 脚本用尽后永不返回：等价于「连接一直健康」，避免循环空转
                    None => std::future::pending().await,
                }
            }
        }

        fn send_frame(
            &mut self,
            env: &Envelope,
        ) -> impl Future<Output = Result<(), TransportError>> + Send {
            self.outbox.lock().expect("不应有锁竞争").push(env.clone());
            async move { Ok(()) }
        }
    }

    /// 按脚本依次返回连接结果的假工厂。
    struct ScriptedConnector {
        script: VecDeque<Result<HeartbeatPolicy, TransportError>>,
        /// 每建立一条连接时弹出的读帧脚本（与 `script` 的下标对齐）。
        frames: VecDeque<FrameScript>,
        /// 所有连接共享的「已发出帧」记录：测试据此断言回执，而不必从 link 上取。
        outbox: Arc<Mutex<Vec<Envelope>>>,
    }

    impl Connector for ScriptedConnector {
        type Link = ScriptedLink;

        fn connect(&mut self) -> impl Future<Output = Result<ScriptedLink, TransportError>> + Send {
            // 脚本耗尽后沿用最后一格，便于测「一直失败到放弃」
            let next = if self.script.len() > 1 {
                self.script.pop_front().expect("len > 1")
            } else {
                self.script.front().map(clone_result).expect("脚本不能为空")
            };
            // 🔴 只有「连接真的建立」才消费读帧脚本：失败的连接不产生 link，
            // 若在这里无条件 pop，第一个失败尝试就会白吃掉一格脚本，
            // 后续成功连接的读帧脚本错位（踩过：导致测试永久挂起）。
            let frames = match &next {
                Ok(_) => self.frames.pop_front().unwrap_or_default(),
                Err(_) => VecDeque::new(),
            };
            let outbox = Arc::clone(&self.outbox);
            async move {
                next.map(|hb| ScriptedLink {
                    device_id: "dev_mock".to_string(),
                    heartbeat: hb,
                    frames: Arc::new(Mutex::new(frames)),
                    outbox,
                })
            }
        }
    }

    fn clone_result(
        r: &Result<HeartbeatPolicy, TransportError>,
    ) -> Result<HeartbeatPolicy, TransportError> {
        match r {
            Ok(hb) => Ok(*hb),
            Err(TransportError::Ws(m)) => Err(TransportError::Ws(m.clone())),
            Err(TransportError::Unauthorized(m)) => Err(TransportError::Unauthorized(m.clone())),
            Err(TransportError::Server { code, message }) => Err(TransportError::Server {
                code: code.clone(),
                message: message.clone(),
            }),
            Err(TransportError::Protocol(e)) => Err(TransportError::Protocol(e.clone())),
            Err(TransportError::Payload(m)) => Err(TransportError::Payload(m.clone())),
        }
    }

    /// 构造一个「只连失败」的脚本工厂。
    fn scripted(script: Vec<Result<HeartbeatPolicy, TransportError>>) -> ScriptedConnector {
        ScriptedConnector {
            script: script.into(),
            frames: VecDeque::new(),
            outbox: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[test]
    fn exit_code_maps_each_stop_reason() {
        use hd_protocol::exit_code as ec;

        // 吊销：宿主必须据此清令牌重配对。
        assert_eq!(
            StopReason::RejectedByServer {
                code: error_code::FRAME_REVOKED.to_string()
            }
            .exit_code(),
            ec::EXIT_REVOKED
        );

        // 被替换：不能重启，否则与对方互踢。
        assert_eq!(
            StopReason::RejectedByServer {
                code: error_code::FRAME_REPLACED.to_string()
            }
            .exit_code(),
            ec::EXIT_REPLACED
        );

        // 协议不匹配：重试不会让版本变匹配。
        assert_eq!(
            StopReason::RejectedByServer {
                code: error_code::FRAME_PROTOCOL_MISMATCH.to_string()
            }
            .exit_code(),
            ec::EXIT_PROTOCOL_MISMATCH
        );

        // 重试耗尽：网络类问题，允许宿主退避重启。
        assert_eq!(
            StopReason::AttemptsExhausted { attempts: 5 }.exit_code(),
            ec::EXIT_RETRYABLE
        );
    }

    #[test]
    fn exit_code_never_restarts_on_terminal_reasons() {
        use hd_protocol::exit_code as ec;

        // 三条终止性原因都不允许宿主重启——这是「不产生无效重启循环」的硬约束。
        for code in [
            error_code::FRAME_REVOKED,
            error_code::FRAME_REPLACED,
            error_code::FRAME_PROTOCOL_MISMATCH,
        ] {
            let reason = StopReason::RejectedByServer {
                code: code.to_string(),
            };
            assert!(
                !ec::should_restart(Some(reason.exit_code())),
                "{code} 对应的退出码不应触发宿主重启"
            );
        }

        // 重试耗尽则应当重启。
        assert!(ec::should_restart(Some(
            StopReason::AttemptsExhausted { attempts: 5 }.exit_code()
        )));
    }

    #[test]
    fn unknown_frame_code_falls_back_to_no_restart() {
        use hd_protocol::exit_code as ec;

        // 未识别的帧级拒绝：宁可不重启也不盲目重试，避免掩盖真实原因。
        let reason = StopReason::RejectedByServer {
            code: "device.some_future_code".to_string(),
        };
        assert!(!ec::should_restart(Some(reason.exit_code())));
    }

    #[tokio::test]
    async fn terminal_code_stops_without_retry() {
        // 终态（device.revoked）：一次都不许重试，否则就是重试风暴
        let connector = scripted(vec![Err(TransportError::Server {
            code: error_code::FRAME_REVOKED.to_string(),
            message: "已被管理员吊销".into(),
        })]);
        let mut sup = Supervisor::with_sleeper(connector, ReconnectPolicy::default(), NoopSleeper);
        let mut obs = CollectingObserver::default();

        let reason = sup.run(&mut obs).await;

        assert_eq!(
            reason,
            StopReason::RejectedByServer {
                code: error_code::FRAME_REVOKED.to_string()
            }
        );
        assert_eq!(
            obs.reconnecting_attempts(),
            Vec::<u32>::new(),
            "终态错误不允许出现任何重连事件"
        );
        assert_eq!(obs.stop_reason(), Some(reason));
    }

    #[tokio::test]
    async fn unauthorized_token_is_treated_as_terminal() {
        // 握手前 401 与 device.revoked 同义：令牌失效，重连不会自愈
        let connector = scripted(vec![Err(TransportError::Unauthorized("HTTP 401".into()))]);
        let mut sup = Supervisor::with_sleeper(connector, ReconnectPolicy::default(), NoopSleeper);
        let mut obs = CollectingObserver::default();

        let reason = sup.run(&mut obs).await;

        assert!(matches!(reason, StopReason::RejectedByServer { .. }));
        assert!(obs.reconnecting_attempts().is_empty());
    }

    #[tokio::test]
    async fn recoverable_failures_back_off_with_increasing_attempt() {
        let connector = scripted(vec![Err(TransportError::Ws("拒绝连接".into()))]);
        let mut sup = Supervisor::with_sleeper(
            connector,
            ReconnectPolicy {
                initial: Duration::from_secs(1),
                max: Duration::from_secs(30),
                max_attempts: 4,
            },
            NoopSleeper,
        );
        let mut obs = CollectingObserver::default();

        let reason = sup.run(&mut obs).await;

        assert_eq!(reason, StopReason::AttemptsExhausted { attempts: 4 });
        assert_eq!(obs.reconnecting_attempts(), vec![1, 2, 3]);
        // 退避必须递增：1s → 2s → 4s
        let delays: Vec<Duration> = obs
            .events()
            .into_iter()
            .filter_map(|e| match e {
                SupervisorEvent::Reconnecting { delay, .. } => Some(delay),
                _ => None,
            })
            .collect();
        assert_eq!(
            delays,
            vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4)
            ]
        );
    }

    #[tokio::test]
    async fn attempt_counter_resets_after_successful_connect() {
        // 剧本：连接失败 → 连上（读帧脚本让服务端下发终态错误帧）→ 停止。
        // 若成功后没清零，这条连接断线时的 attempt 会是 2 而不是 1，
        // 「Reconnecting{attempt:1} 出现两次」这个断言就会失败。
        let mut connector = scripted(vec![
            Err(TransportError::Ws("第一次失败".into())),
            Ok(HeartbeatPolicy::from_welcome(1, 10)),
        ]);
        // 第一条连接不建立（失败），第二条连接建立后立刻收到终态错误帧
        connector
            .frames
            .push_back(VecDeque::from([Ok(Some(error_envelope(
                error_code::FRAME_REPLACED,
            )))]));

        let mut sup = Supervisor::with_sleeper(
            connector,
            ReconnectPolicy {
                initial: Duration::from_secs(1),
                max: Duration::from_secs(30),
                max_attempts: 5,
            },
            NoopSleeper,
        );
        let mut obs = CollectingObserver::default();

        let reason = sup.run(&mut obs).await;

        assert_eq!(
            reason,
            StopReason::RejectedByServer {
                code: error_code::FRAME_REPLACED.to_string()
            }
        );
        assert_eq!(
            obs.reconnecting_attempts(),
            vec![1],
            "首次失败是第 1 次；连接成功后断线必须重新从 1 计数"
        );
        assert!(
            obs.events()
                .iter()
                .any(|e| matches!(e, SupervisorEvent::Disconnected { .. })),
            "断线必须产生 Disconnected 事件"
        );
        // 心跳来自 welcome，而非硬编码
        assert!(obs.events().iter().any(|e| matches!(
            e,
            SupervisorEvent::Connected { heartbeat, .. }
                if *heartbeat == HeartbeatPolicy::from_welcome(1, 10)
        )));
    }

    #[tokio::test]
    async fn error_frame_code_is_propagated_to_decide() {
        // 终态错误帧由 link 上报 → 传给 decide → 立即 Stop，不再重试。
        // 这是「错误码不能丢」的关键链路：早期把 code 降级成字符串的实现会在这里挂掉。
        let mut connector = scripted(vec![Ok(HeartbeatPolicy::from_welcome(1, 10))]);
        connector
            .frames
            .push_back(VecDeque::from([Ok(Some(error_envelope(
                error_code::FRAME_REVOKED,
            )))]));
        let mut sup = Supervisor::with_sleeper(connector, ReconnectPolicy::default(), NoopSleeper);
        let mut obs = CollectingObserver::default();

        let reason = sup.run(&mut obs).await;

        assert_eq!(
            reason,
            StopReason::RejectedByServer {
                code: error_code::FRAME_REVOKED.to_string()
            }
        );
        assert!(
            obs.reconnecting_attempts().is_empty(),
            "终态错误帧不允许触发任何退避"
        );
    }

    #[tokio::test]
    async fn recoverable_error_frame_keeps_retrying() {
        // 可恢复错误帧（server_closing）应走退避而不是停止。
        // 注意：重连成功后本连接是「健康的」（读帧脚本用尽 → 挂起），
        // `run` 会一直在线，故这里必须用超时把它掐断，不能直接 await 返回值 ——
        // 那正是「没有无限重试」与「在线不退出」两件事都成立的表现。
        let mut connector = scripted(vec![Ok(HeartbeatPolicy::from_welcome(1, 10))]);
        connector
            .frames
            .push_back(VecDeque::from([Ok(Some(error_envelope(
                error_code::FRAME_SERVER_CLOSING,
            )))]));
        let mut sup = Supervisor::with_sleeper(
            connector,
            ReconnectPolicy {
                initial: Duration::from_secs(1),
                max: Duration::from_secs(30),
                max_attempts: 3,
            },
            NoopSleeper,
        );
        let mut obs = CollectingObserver::default();

        let timed_out = tokio::time::timeout(Duration::from_millis(300), sup.run(&mut obs))
            .await
            .is_err();

        assert!(timed_out, "可恢复错误后应保持在线，而不是返回终态");
        assert_eq!(
            obs.reconnecting_attempts(),
            vec![1],
            "可恢复错误必须走退避重连一次"
        );
        assert!(
            obs.stop_reason().is_none(),
            "可恢复错误不允许停止，实际: {:?}",
            obs.stop_reason()
        );
    }

    /// 造一个「服务端错误帧」信封。
    fn error_envelope(code: &str) -> Envelope {
        Envelope::new(
            MessageType::Error,
            "f-err",
            Some(serde_json::json!({ "code": code, "message": "测试错误" })),
        )
    }

    /// 最小假 executor：只回一个固定结果，用来验证「帧路由 → 执行 → 回执」全链。
    struct EchoTool {
        calls: Arc<Mutex<usize>>,
    }

    #[async_trait::async_trait]
    impl hd_core::Executor for EchoTool {
        fn tool_name(&self) -> &'static str {
            "fs.list"
        }

        fn limits(&self) -> hd_core::Limits {
            hd_core::Limits {
                timeout: Duration::from_secs(5),
                max_output_bytes: 4096,
            }
        }

        async fn execute(
            &self,
            ctx: &hd_core::ExecCtx,
            args: &serde_json::Value,
            _sink: &dyn hd_core::ProgressSink,
        ) -> Result<hd_core::ExecOutput, hd_core::ExecError> {
            *self.calls.lock().expect("不应有锁竞争") += 1;
            Ok(hd_core::ExecOutput::untrusted(serde_json::json!({
                "tool_event_id": ctx.tool_event_id,
                "args": args,
            })))
        }
    }

    /// 造一个挂好 `fs.list` 的 router（policy 允许当前目录、工具不限）。
    fn test_router(calls: Arc<Mutex<usize>>) -> Arc<Router> {
        let root = std::env::current_dir().expect("cwd");
        let mut router = Router::new(
            Arc::new(hd_core::Policy::new(vec![root], Vec::new())),
            Arc::new(hd_core::NullAuditSink),
            Arc::new(crate::idempot::IdempotStore::with_defaults()),
        );
        router.register(EchoTool { calls });
        Arc::new(router)
    }

    /// 造一个 `task.dispatch` 帧（deadline 给足，避免测试机慢导致误判过期）。
    fn dispatch_envelope(tool_event_id: &str) -> Envelope {
        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("钟不该早于 1970")
            .as_millis() as i64
            + 30_000;
        Envelope::new(
            MessageType::TaskDispatch,
            tool_event_id,
            Some(serde_json::json!({
                "run_id": "run-1",
                "tool_event_id": tool_event_id,
                "tool_name": "fs.list",
                "args": { "max": 5 },
                "deadline": deadline,
                "attempt": 1,
            })),
        )
    }

    #[tokio::test]
    async fn dispatch_frame_is_executed_and_result_sent_back() {
        let calls = Arc::new(Mutex::new(0usize));
        let mut connector = scripted(vec![Ok(HeartbeatPolicy::from_welcome(1, 10))]);
        connector
            .frames
            .push_back(VecDeque::from([Ok(Some(dispatch_envelope("evt-1")))]));
        let outbox = Arc::clone(&connector.outbox);
        let mut sup = Supervisor::with_sleeper(connector, ReconnectPolicy::default(), NoopSleeper)
            .with_router(test_router(Arc::clone(&calls)));
        let mut obs = CollectingObserver::default();

        // 处理完 dispatch 后读帧脚本用尽 → 连接保持健康，run 不返回，用超时掐断
        let timed_out = tokio::time::timeout(Duration::from_millis(500), sup.run(&mut obs))
            .await
            .is_err();
        assert!(timed_out, "处理完派发应继续在线等待，而不是退出");

        assert_eq!(
            *calls.lock().expect("不应有锁竞争"),
            1,
            "派发必须真的执行一次"
        );
        let sent = outbox.lock().expect("不应有锁竞争").clone();
        assert_eq!(sent.len(), 1, "必须回一帧 task.result，实际: {sent:?}");
        assert_eq!(sent[0].msg_type, MessageType::TaskResult);
        assert_eq!(sent[0].id, "evt-1", "帧 ID 应为 tool_event_id");
        let p: hd_protocol::payload::TaskResultPayload = sent[0]
            .decode()
            .expect("负载应可解码")
            .expect("task.result 必须有负载");
        assert_eq!(p.status, "success");
        assert_eq!(p.tool_event_id, "evt-1");
    }

    #[tokio::test]
    async fn redelivered_dispatch_is_replayed_not_reexecuted() {
        // 断线重派：同一 tool_event_id 连来两帧，executor 只能跑一次。
        let calls = Arc::new(Mutex::new(0usize));
        let mut connector = scripted(vec![Ok(HeartbeatPolicy::from_welcome(1, 10))]);
        connector.frames.push_back(VecDeque::from([
            Ok(Some(dispatch_envelope("evt-dup"))),
            Ok(Some(dispatch_envelope("evt-dup"))),
        ]));
        let outbox = Arc::clone(&connector.outbox);
        let mut sup = Supervisor::with_sleeper(connector, ReconnectPolicy::default(), NoopSleeper)
            .with_router(test_router(Arc::clone(&calls)));
        let mut obs = CollectingObserver::default();

        let _ = tokio::time::timeout(Duration::from_millis(500), sup.run(&mut obs)).await;

        assert_eq!(
            *calls.lock().expect("不应有锁竞争"),
            1,
            "重派必须只回放，不得二次执行"
        );
        // 两帧都要有回执：服务端重派时也在等结果，静默不回会让它一直等到超时。
        assert_eq!(outbox.lock().expect("不应有锁竞争").len(), 2);
    }

    #[tokio::test]
    async fn dispatch_frame_is_ignored_without_router() {
        // 未挂 router：行为必须与改造前一致（忽略该帧，不断连、不回执）。
        let mut connector = scripted(vec![Ok(HeartbeatPolicy::from_welcome(1, 10))]);
        connector
            .frames
            .push_back(VecDeque::from([Ok(Some(dispatch_envelope("evt-x")))]));
        let outbox = Arc::clone(&connector.outbox);
        let mut sup = Supervisor::with_sleeper(connector, ReconnectPolicy::default(), NoopSleeper);
        let mut obs = CollectingObserver::default();

        let timed_out = tokio::time::timeout(Duration::from_millis(300), sup.run(&mut obs))
            .await
            .is_err();

        assert!(timed_out, "忽略派发帧后应继续在线");
        assert!(
            outbox.lock().expect("不应有锁竞争").is_empty(),
            "未挂 router 不得发出任何任务回执"
        );
    }

    #[tokio::test]
    async fn malformed_dispatch_payload_does_not_break_connection() {
        // 畸形负载是服务端的问题：忽略即可，绝不能因此断连（重连也修不好它）。
        let mut connector = scripted(vec![Ok(HeartbeatPolicy::from_welcome(1, 10))]);
        connector
            .frames
            .push_back(VecDeque::from([Ok(Some(Envelope::new(
                MessageType::TaskDispatch,
                "f-bad",
                Some(serde_json::json!({ "run_id": 1 })),
            )))]));
        let outbox = Arc::clone(&connector.outbox);
        let calls = Arc::new(Mutex::new(0usize));
        let mut sup = Supervisor::with_sleeper(connector, ReconnectPolicy::default(), NoopSleeper)
            .with_router(test_router(Arc::clone(&calls)));
        let mut obs = CollectingObserver::default();

        let timed_out = tokio::time::timeout(Duration::from_millis(300), sup.run(&mut obs))
            .await
            .is_err();

        assert!(timed_out, "畸形负载不得导致断连");
        assert_eq!(*calls.lock().expect("不应有锁竞争"), 0);
        assert!(outbox.lock().expect("不应有锁竞争").is_empty());
        assert!(obs.stop_reason().is_none());
    }
}
