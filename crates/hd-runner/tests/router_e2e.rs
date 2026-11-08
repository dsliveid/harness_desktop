//! 任务路由端到端：`task.dispatch` 帧 → [`Router`] → `Guarded` → `task.result` 帧。
//!
//! ## 为什么这层还需要 e2e（明明 router 单测已覆盖）
//!
//! 单测直接调 `Router::dispatch`，跳过了**帧这一层**：信封形状、`tool_event_id`
//! 作为帧 ID、结果负载的二次解码。这些恰恰是两端联调时最容易错位的地方
//! （字段名对了但嵌错层级、发出去的 `msg_type` 拼错等），单测看不见。
//!
//! 刻意**不连真 WS**：连接与握手已由 `transport_e2e` / `supervisor_e2e` 用假服务端
//! 覆盖，这里若再起端口，只是把两类失败混在一条断言里。故用假 `LiveLink` 把
//! 「帧进 / 帧出」端到端串起来。

// `LiveLink` 的方法签名刻意是 `-> impl Future<...> + Send`（trait 里写 `async fn`
// 生成的 future 不带 Send，`tokio::spawn` 就用不了）。实现方因此只能手写这种形式，
// clippy 的 `manual_async_fn` 建议在这里与「可 spawn」目标直接冲突，故整体关掉它
// ——与 `supervisor.rs` 内的同名 allow 同一理由，仅此一条不放大到其他 lint。
#![allow(clippy::manual_async_fn)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use hd_core::{
    AuditEvent, AuditSink, ExecCtx, ExecError, ExecOutput, Executor, Limits, Policy, ProgressSink,
};
use hd_protocol::envelope::{Envelope, MessageType};
use hd_protocol::payload::TaskResultPayload;
use hd_runner::idempot::IdempotStore;
use hd_runner::router::{Router, STATUS_FAILED, STATUS_SUCCESS};
use hd_runner::supervisor::{
    Connector, LiveLink, StopReason, Supervisor, SupervisorEvent, SupervisorObserver,
};
use hd_runner::{HeartbeatPolicy, ReconnectPolicy, TransportError};

// ---------------------------------------------------------------------------
// 受测组件：假 Executor（只回显参数，并统计调用次数）
// ---------------------------------------------------------------------------

struct EchoTool {
    calls: Arc<AtomicUsize>,
    fail: Option<ExecError>,
}

#[async_trait]
impl Executor for EchoTool {
    fn tool_name(&self) -> &'static str {
        "fs.list"
    }

    fn limits(&self) -> Limits {
        Limits {
            timeout: Duration::from_secs(5),
            max_output_bytes: 64 * 1024,
        }
    }

    async fn execute(
        &self,
        ctx: &ExecCtx,
        args: &serde_json::Value,
        sink: &dyn ProgressSink,
    ) -> Result<ExecOutput, ExecError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        sink.chunk("首个进度块");
        if let Some(e) = &self.fail {
            return Err(e.clone());
        }
        Ok(ExecOutput::untrusted(serde_json::json!({
            "tool_event_id": ctx.tool_event_id,
            "run_id": ctx.run_id,
            "args": args,
        })))
    }
}

/// 记录审计的 sink：用来证明请求真的经过闸门（Guarded 会写审计）。
#[derive(Default)]
struct CountingAudit {
    count: AtomicUsize,
}

impl AuditSink for CountingAudit {
    fn record(&self, _e: AuditEvent) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

fn policy_for_current_dir() -> Arc<Policy> {
    // 空 allowlist = 不限工具；roots 给当前目录（必然存在且可 canonicalize）。
    let root = std::env::current_dir().expect("cwd 应可读");
    Arc::new(Policy::new(vec![root], Vec::new()))
}

fn router_with(
    calls: Arc<AtomicUsize>,
    fail: Option<ExecError>,
) -> (Arc<Router>, Arc<CountingAudit>) {
    let audit = Arc::new(CountingAudit::default());
    let mut router = Router::new(
        policy_for_current_dir(),
        audit.clone(),
        Arc::new(IdempotStore::with_defaults()),
    );
    router.register(EchoTool { calls, fail });
    (Arc::new(router), audit)
}

// ---------------------------------------------------------------------------
// 假连接：按脚本吐帧，并记录所有发出的帧
// ---------------------------------------------------------------------------

type FrameResult = Result<Option<Envelope>, TransportError>;

struct ScriptedLink {
    heartbeat: HeartbeatPolicy,
    frames: VecDeque<FrameResult>,
    outbox: Arc<Mutex<Vec<Envelope>>>,
}

impl LiveLink for ScriptedLink {
    fn device_id(&self) -> &str {
        "dev_e2e"
    }

    fn heartbeat(&self) -> HeartbeatPolicy {
        self.heartbeat
    }

    fn send_ping(
        &mut self,
    ) -> impl std::future::Future<Output = Result<i32, TransportError>> + Send {
        async move { Ok(0) }
    }

    fn read_frame(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Option<Envelope>, TransportError>> + Send {
        let next = self.frames.pop_front();
        async move {
            match next {
                Some(r) => r,
                // 脚本用尽 = 连接保持健康（等待下一条指令），与真实长连接一致
                None => std::future::pending().await,
            }
        }
    }

    fn send_frame(
        &mut self,
        env: &Envelope,
    ) -> impl std::future::Future<Output = Result<(), TransportError>> + Send {
        self.outbox.lock().expect("不应有锁竞争").push(env.clone());
        async move { Ok(()) }
    }
}

struct OneShotConnector {
    heartbeat: HeartbeatPolicy,
    /// 这条连接要依次吐出的帧（用尽即挂起 = 连接保持健康）。
    frames: VecDeque<FrameResult>,
    /// 所有连接共享的出站记录（本文件里只有一条连接，但仍按共享方式建模）。
    outbox: Arc<Mutex<Vec<Envelope>>>,
}

impl Connector for OneShotConnector {
    type Link = ScriptedLink;

    fn connect(
        &mut self,
    ) -> impl std::future::Future<Output = Result<ScriptedLink, TransportError>> + Send {
        let heartbeat = self.heartbeat;
        let frames = std::mem::take(&mut self.frames);
        let outbox = Arc::clone(&self.outbox);
        async move {
            Ok(ScriptedLink {
                heartbeat,
                frames,
                outbox,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// 杂项
// ---------------------------------------------------------------------------

fn deadline_in(ms: i64) -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("钟不该早于 1970")
        .as_millis() as i64;
    now + ms
}

fn dispatch_frame(tool_event_id: &str, tool_name: &str, deadline: i64) -> Envelope {
    Envelope::new(
        MessageType::TaskDispatch,
        tool_event_id,
        Some(serde_json::json!({
            "run_id": "run-e2e",
            "tool_event_id": tool_event_id,
            "tool_name": tool_name,
            "args": { "max": 5 },
            "deadline": deadline,
            "attempt": 1,
        })),
    )
}

#[derive(Default, Clone)]
struct CollectingObserver {
    events: Arc<Mutex<Vec<SupervisorEvent>>>,
}

impl SupervisorObserver for CollectingObserver {
    fn on_event(&mut self, event: SupervisorEvent) {
        self.events.lock().expect("不应有锁竞争").push(event);
    }
}

/// 跑一次「连接 → 处理脚本里的那些帧」的过程，返回所有已发出的帧。
///
/// `Supervisor::run` 在连接健康时永不返回，故统一用超时掐断。
async fn run_once(
    frames: Vec<FrameResult>,
    router: Arc<Router>,
    budget: Duration,
) -> Vec<Envelope> {
    let outbox = Arc::new(Mutex::new(Vec::new()));
    let connector = OneShotConnector {
        heartbeat: HeartbeatPolicy::from_welcome(1, 10),
        frames: VecDeque::from(frames),
        outbox: Arc::clone(&outbox),
    };
    let mut sup = Supervisor::with_sleeper(
        connector,
        ReconnectPolicy::default(),
        hd_runner::NoopSleeper,
    )
    .with_router(router);
    let mut obs = CollectingObserver::default();
    let _ = tokio::time::timeout(budget, sup.run(&mut obs)).await;
    let sent = outbox.lock().expect("不应有锁竞争").clone();
    sent
}

fn results(sent: &[Envelope]) -> Vec<TaskResultPayload> {
    sent.iter()
        .filter(|e| e.msg_type == MessageType::TaskResult)
        .map(|e| {
            e.decode::<TaskResultPayload>()
                .expect("负载应可解码")
                .expect("task.result 必须有负载")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 用例
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dispatch_through_frame_layer_produces_result_frame() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (router, audit) = router_with(Arc::clone(&calls), None);

    let sent = run_once(
        vec![Ok(Some(dispatch_frame(
            "evt-e2e-1",
            "fs.list",
            deadline_in(30_000),
        )))],
        router,
        Duration::from_millis(600),
    )
    .await;

    let results = results(&sent);
    assert_eq!(results.len(), 1, "必须回一帧 task.result，实际: {sent:?}");
    assert_eq!(results[0].status, STATUS_SUCCESS);
    assert_eq!(results[0].tool_event_id, "evt-e2e-1");
    assert_eq!(
        results[0].task_id, "evt-e2e-1",
        "task_id 与 tool_event_id 恒等"
    );
    assert_eq!(results[0].run_id, "run-e2e");
    // 结果体透传了 executor 的产出
    let body = results[0].result.as_ref().expect("success 必须带 result");
    assert_eq!(body["tool_event_id"], serde_json::json!("evt-e2e-1"));
    // 执行真的发生了，且经过闸门（审计有记录）
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        audit.count.load(Ordering::SeqCst) >= 1,
        "经过 Guarded 就必须留下审计"
    );
    // 线格式里必须显式带 untrusted（进度帧排在结果帧之前，故这里定位 result 帧而非 sent[0]）
    let result_env = sent
        .iter()
        .find(|e| e.msg_type == MessageType::TaskResult)
        .expect("必须存在 task.result 帧");
    let raw = serde_json::to_string(result_env).expect("序列化");
    assert!(raw.contains("\"type\":\"task.result\""), "{raw}");
    assert!(raw.contains("\"source_trust\":\"untrusted\""), "{raw}");
}

#[tokio::test]
async fn idempotent_replay_across_two_frames() {
    // 断线重派：同一 tool_event_id 连来两帧 → 只执行一次，但两次都回执。
    let calls = Arc::new(AtomicUsize::new(0));
    let (router, _audit) = router_with(Arc::clone(&calls), None);

    let sent = run_once(
        vec![
            Ok(Some(dispatch_frame(
                "evt-dup",
                "fs.list",
                deadline_in(30_000),
            ))),
            Ok(Some(dispatch_frame(
                "evt-dup",
                "fs.list",
                deadline_in(30_000),
            ))),
        ],
        router,
        Duration::from_millis(800),
    )
    .await;

    let results = results(&sent);
    assert_eq!(results.len(), 2, "两次派发都要有回执");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "同一 tool_event_id 只允许执行一次"
    );
    assert_eq!(results[0].status, results[1].status);
    assert_eq!(
        results[0].result, results[1].result,
        "回放结果必须与首次执行完全一致"
    );
}

#[tokio::test]
async fn unknown_tool_returns_failed_frame_without_crashing() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (router, _audit) = router_with(Arc::clone(&calls), None);

    let sent = run_once(
        vec![Ok(Some(dispatch_frame(
            "evt-unknown",
            "shell.exec",
            deadline_in(30_000),
        )))],
        router,
        Duration::from_millis(500),
    )
    .await;

    let results = results(&sent);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, STATUS_FAILED);
    assert!(
        results[0].error.contains("未实现该工具"),
        "错误必须可读，实际: {}",
        results[0].error
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "未知工具不得触达任何 executor"
    );
}

#[tokio::test]
async fn expired_dispatch_returns_failed_and_skips_execution() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (router, _audit) = router_with(Arc::clone(&calls), None);

    // deadline 设在 1 秒前
    let sent = run_once(
        vec![Ok(Some(dispatch_frame(
            "evt-late",
            "fs.list",
            deadline_in(-1_000),
        )))],
        router,
        Duration::from_millis(500),
    )
    .await;

    let results = results(&sent);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, STATUS_FAILED);
    assert!(
        results[0].error.contains("device_timeout"),
        "错误码语义要对齐 device_timeout，实际: {}",
        results[0].error
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "已过期不得执行");
}

#[tokio::test]
async fn executor_failure_is_reported_with_apperr_code() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (router, _audit) = router_with(
        Arc::clone(&calls),
        Some(ExecError::PathDenied {
            path: "C:\\secret".to_string(),
        }),
    );

    let sent = run_once(
        vec![Ok(Some(dispatch_frame(
            "evt-denied",
            "fs.list",
            deadline_in(30_000),
        )))],
        router,
        Duration::from_millis(500),
    )
    .await;

    let results = results(&sent);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, STATUS_FAILED);
    assert!(
        results[0].error.starts_with("fs.path_denied"),
        "必须带服务端错误码，实际: {}",
        results[0].error
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "失败也是执行过");
}

#[tokio::test]
async fn guarded_blocks_overreach_even_in_full_chain() {
    // 端到端验证「闸门不可绕过」：policy 的 roots 里不含 temp 目录之外的路径时，
    // 带非法路径参数的派发必须在 inner executor 之前被拒。
    let calls = Arc::new(AtomicUsize::new(0));
    let audit = Arc::new(CountingAudit::default());
    let mut router = Router::new(
        // 空 roots = 任何路径都判越界
        Arc::new(Policy::new(Vec::new(), Vec::new())),
        audit.clone(),
        Arc::new(IdempotStore::with_defaults()),
    );
    router.register(EchoTool {
        calls: Arc::clone(&calls),
        fail: None,
    });
    let router = Arc::new(router);

    let frame = Envelope::new(
        MessageType::TaskDispatch,
        "evt-traversal",
        Some(serde_json::json!({
            "run_id": "run-e2e",
            "tool_event_id": "evt-traversal",
            "tool_name": "fs.list",
            "args": { "path": "C:\\Windows\\System32" },
            "deadline": deadline_in(30_000),
            "attempt": 1,
        })),
    );

    let sent = run_once(vec![Ok(Some(frame))], router, Duration::from_millis(500)).await;

    let results = results(&sent);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, STATUS_FAILED);
    assert!(
        results[0].error.starts_with("fs.path_denied"),
        "越界路径必须被闸门拒绝，实际: {}",
        results[0].error
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "闸门拦下的请求绝不能触达 inner executor"
    );
    assert!(audit.count.load(Ordering::SeqCst) >= 1, "拒绝也必须留审计");
}

#[tokio::test]
async fn terminal_error_frame_still_wins_over_dispatch() {
    // 错误帧的既有语义不能被本次改造改变：device.revoked 仍须直接停止。
    let calls = Arc::new(AtomicUsize::new(0));
    let (router, _audit) = router_with(Arc::clone(&calls), None);

    let outbox = Arc::new(Mutex::new(Vec::new()));
    let connector = OneShotConnector {
        heartbeat: HeartbeatPolicy::from_welcome(1, 10),
        frames: VecDeque::from(vec![Ok(Some(Envelope::new(
            MessageType::Error,
            "f-err",
            Some(serde_json::json!({
                "code": hd_protocol::error_code::FRAME_REVOKED,
                "message": "已吊销",
            })),
        )))]),
        outbox: Arc::clone(&outbox),
    };
    let mut sup = Supervisor::with_sleeper(
        connector,
        ReconnectPolicy::default(),
        hd_runner::NoopSleeper,
    )
    .with_router(router);
    let mut obs = CollectingObserver::default();

    let reason = sup.run(&mut obs).await;

    assert!(
        matches!(reason, StopReason::RejectedByServer { .. }),
        "终态错误帧必须直接停止，实际: {reason:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "错误帧不得触发任何执行");
}
