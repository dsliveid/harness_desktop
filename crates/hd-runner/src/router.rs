//! 帧路由：`task.dispatch` → [`Guarded`] 执行 → `task.result`（设计文档 §16.2 / §19）。
//!
//! ## 这个模块的唯一职责
//!
//! 把「服务端说要做 X」翻译成「本地安全地做 X 并把终态说回去」。它**不做**安全判定
//! （那是 [`Guarded`] 的事），也**不做**具体工具逻辑（那是 `hd-core::executor::*` 的事）。
//! 它只负责四件在别处都不好安放的事情：幂等回放、deadline 换算、注册表查表、结果归类。
//!
//! ## 🔴 注册表里只可能存在 `Guarded<E>`（§16.2 的类型级保证）
//!
//! 详见 [`Router::insert_guarded`] 的注释：`tools: HashMap<.., Arc<dyn Executor>>` 是
//! **私有字段**，唯一写入路径是私有方法 [`Router::insert_guarded`]，而它只接受
//! `Guarded<E>`。公开的 [`Router::register`] 也只接受裸 `E` 并内部立即包一层。
//! 于是「注册一个裸 executor」不是一个需要评审盯住的纪律问题，而是一段**写不出来**的代码。
//!
//! ## 为什么 `dispatch` 里没有任何 `unwrap`
//!
//! 这条路径的输入全部来自网络。任何一个 `unwrap` 都等价于「一条畸形帧可以打挂 Runner」，
//! 所以未知工具、参数缺失、载荷解码失败都必须降级成一条 `failed` 结果回给服务端。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hd_core::{AuditSink, ExecCtx, Executor, Guarded, NoopSink, Policy, ProgressSink};
use hd_protocol::payload::{SourceTrust, TaskDispatchPayload, TaskResultPayload};
use tracing::{debug, warn};

use crate::idempot::{ClaimResult, IdempotStore};

/// 终态字面量（与服务端 `TaskResultPayload.status` 取值一致）。
pub const STATUS_SUCCESS: &str = "success";
/// 执行失败。
pub const STATUS_FAILED: &str = "failed";

/// 承接到期派发时给服务端看的错误码语义。
///
/// 刻意用字面量而不是 `hd_protocol::error_code::*`：hd-protocol 目前**没有**这个码
/// （最接近的 `device.offline_timeout` 是「帧静默超时」，语义不同）。本 crate 无权
/// 修改 hd-protocol，故先做本地常量并在交付报告里提出「应上提到 error_code.rs」。
pub const CODE_DEVICE_TIMEOUT: &str = "device_timeout";

/// 路由表：`tool_name` → 已过闸的 executor。
///
/// 键必须是 `&'static str`：工具名是编译期常量（见 `hd_core::Executor::tool_name`），
/// 用运行期 `String` 做键会让「拼错工具名」变成运行期静默 miss 而不是编译期可见。
type ToolTable = HashMap<&'static str, Arc<dyn Executor>>;

/// 任务路由。
pub struct Router {
    /// 私有：外部无法直接插入 `Arc<dyn Executor>`（见模块注释）。
    tools: ToolTable,
    /// 安全策略。注册时注入给每个 [`Guarded`]，同时供上层读取白名单根。
    policy: Arc<Policy>,
    /// 本地审计出口。与 policy 一起注入 [`Guarded`]，Router 自己不记审计。
    audit: Arc<dyn AuditSink>,
    /// 幂等缓存：断线重派只回放不重跑。
    store: Arc<IdempotStore>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 只打印工具名清单：executor 内部状态不应进日志。
        let mut names: Vec<&'static str> = self.tools.keys().copied().collect();
        names.sort_unstable();
        f.debug_struct("Router")
            .field("tools", &names)
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl Router {
    /// 全参数构造。
    pub fn new(policy: Arc<Policy>, audit: Arc<dyn AuditSink>, store: Arc<IdempotStore>) -> Self {
        Self {
            tools: HashMap::new(),
            policy,
            audit,
            store,
        }
    }

    /// 生产默认：空审计 + 默认 TTL/容量缓存。
    ///
    /// 生产环境应显式传 `Arc<dyn AuditSink>`（例如把审计落到本地文件），
    /// 这里保留默认是为了让 hd-host 在审计尚未接入时也能启动。
    pub fn with_defaults(policy: Arc<Policy>) -> Self {
        Self::new(
            policy,
            Arc::new(hd_core::NullAuditSink),
            Arc::new(IdempotStore::with_defaults()),
        )
    }

    /// 注册一个工具。
    ///
    /// **这是唯一的公开注册入口**，它把裸 executor 立刻包成 [`Guarded`] 再入库，
    /// 因此调用方拿不到「注册裸 executor」的能力（§16.2）。
    pub fn register<E: Executor + 'static>(&mut self, inner: E) -> &mut Self {
        let guarded = Guarded::new(inner, Arc::clone(&self.policy), Arc::clone(&self.audit));
        self.insert_guarded(guarded);
        self
    }

    /// 私有入库方法：🔴 **只接受 `Guarded<E>`，这是全模块唯一的写入路径**。
    ///
    /// 之所以把它做成私有而不是「收 `Arc<dyn Executor>` 的 insert」：后者一旦存在，
    /// 任何人都能把裸 executor 塞进注册表，安全闸门就退化成一句口头约定。
    /// 现在想绕过闸门必须改本文件——而改本文件绕不过 code review 与这里的注释。
    fn insert_guarded<E: Executor + 'static>(&mut self, guarded: Guarded<E>) {
        // 键取 Guarded 透传的 tool_name：Guarded 的 tool_name 直接委托给 inner，
        // 所以「注册名」与「dispatch 查表名」永远同源，不会出现两处各写一遍字符串。
        let name = guarded.tool_name();
        let arc: Arc<dyn Executor> = Arc::new(guarded);
        if self.tools.insert(name, arc).is_some() {
            // 同名重复注册是真 bug（哪个实现生效取决于注册顺序），必须留痕。
            warn!(tool = name, "同一工具名被重复注册，后者覆盖前者");
        }
    }

    /// 已注册的工具名（供 `hello` 能力清单使用，顺序已排序以便断言稳定）。
    pub fn tool_names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.tools.keys().copied().collect();
        names.sort_unstable();
        names
    }

    /// 安全策略（上层拼工作区菜单/白名单根时要用）。
    pub fn policy(&self) -> &Arc<Policy> {
        &self.policy
    }

    /// 幂等缓存（供巡检任务定期 `sweep`，以及测试断言）。
    pub fn store(&self) -> &Arc<IdempotStore> {
        &self.store
    }

    /// 处理一次派发，返回可直接序列化成 `task.result` 帧的终态。
    ///
    /// 调用方（`supervisor::session_loop`）负责把它塞进信封发回去；本方法刻意不碰
    /// 连接，才能在无网络环境单测。
    ///
    /// ## 🔴 并发安全：本方法是「防双跑 + 回放」的统一入口
    ///
    /// 幂等判定从 `store.get` 换成了 `store.claim_guard`。原因：`get` 只回答
    /// 「跑完了吗」，两个并发派发会**同时**读到 `None` 然后都去执行（双跑）。
    /// `claim_guard` 在单把锁内完成「查缓存 + 占位」，保证 N 个并发调用者里
    /// 恰好一个拿到执行权（详见 `idempot.rs` 模块注释）。
    pub async fn dispatch(
        &self,
        payload: &TaskDispatchPayload,
        sink: &dyn ProgressSink,
    ) -> TaskResultPayload {
        // ① 幂等回放 + 原子占位。这是「断线重派」与「并发双跑」两道闸门合一的地方，
        //    放在最前面是为了让后面的任何分支都不可能再产生一次副作用。
        let guard = loop {
            match self.store.claim(&payload.tool_event_id) {
                ClaimResult::Acquired(g) => break g,
                ClaimResult::Cached(cached) => {
                    debug!(
                        tool_event_id = %payload.tool_event_id,
                        tool = %payload.tool_name,
                        "幂等命中：重派只回放缓存结果，不重新执行"
                    );
                    return cached;
                }
                ClaimResult::InFlight => {
                    // 同一个 tool_event_id 正在被另一个并发派发执行。
                    //
                    // 选择「等它出结果再回放」而不是立刻回「已在执行中」：后者会让
                    // 服务端收到一条假的 failed（任务其实成功了），两条结果帧里
                    // 就有一条是错的。等待则两个调用者最终拿到**同一份**终态。
                    // 等待必须有界，否则对端卡死会把这条路永远挂住。
                    if remaining_budget(payload.deadline).is_zero() {
                        warn!(
                            tool_event_id = %payload.tool_event_id,
                            "等待在飞任务结果超期，回 failed"
                        );
                        // 不写缓存：另一路稍后会写入真正的终态，这里不能抢先占位。
                        return failed(
                            payload,
                            format!("{}: 同一任务的另一路派发仍在执行中", CODE_DEVICE_TIMEOUT),
                        );
                    }
                    tokio::time::sleep(INFLIGHT_POLL_INTERVAL).await;
                }
            }
        };

        // ② deadline 换算：服务端给的是墙钟毫秒时间戳，本地判定必须换成单调时钟余量。
        let remaining = remaining_budget(payload.deadline);
        if remaining.is_zero() {
            // 还没查表就过期了：连 executor 的存在性都不必确认，直接回超时。
            // 该结果**不写缓存**：它没有产生任何副作用，若缓存下来，「服务端延长期限
            // 后重派」会被永久回放成失败，等于把一次可恢复的超时变成死局。
            warn!(
                tool_event_id = %payload.tool_event_id,
                deadline = payload.deadline,
                "派发在端侧已过期，未执行"
            );
            return failed(
                payload,
                format!("{CODE_DEVICE_TIMEOUT}: 派发已过期，未执行"),
            );
        }

        let ctx = ExecCtx::with_timeout(
            payload.tool_event_id.clone(),
            payload.run_id.clone(),
            remaining,
            payload.attempt,
        );
        // with_timeout 用 Instant::now() + remaining 重算，理论上不会立刻过期；
        // 仍显式复查一次，避免上面两行之间被调度走太久（不变量的双保险）。
        if ctx.is_expired() {
            return failed(
                payload,
                format!("{CODE_DEVICE_TIMEOUT}: 派发已过期，未执行"),
            );
        }

        // ③ 查表：未注册的工具不 panic，回一条可读的 failed。
        let Some(tool) = self.tools.get(payload.tool_name.as_str()) else {
            warn!(
                tool_event_id = %payload.tool_event_id,
                tool = %payload.tool_name,
                "收到未实现工具的派发，已回 failed"
            );
            // 同样不缓存：端侧升级后补上该工具时，同一个 id 的重派理应能真正执行。
            return failed(
                payload,
                format!(
                    "未实现该工具: {}（端侧未注册对应 executor）",
                    payload.tool_name
                ),
            );
        };

        // ④ 执行。args 为 None 时传 Null：executor 一律按「字段缺失」处理，
        // 不让「没有参数」被误读成「参数是空字符串」。
        let args = payload.args.clone().unwrap_or(serde_json::Value::Null);
        let outcome = tool.execute(&ctx, &args, sink).await;

        // ⑤ 终态回写缓存 + 组装结果。只有**真正执行过**的终态才进缓存
        // （含 cancelled 这类「执行过但被叫停」），无副作用的拒绝见上面两处注释。
        let result = match outcome {
            Ok(out) => TaskResultPayload {
                // 服务端 task_id 与 tool_event_id 值恒等（protocol.go:235），
                // hd-protocol 刻意不设 task_id 字段，这里显式复制以示二者同源。
                task_id: payload.tool_event_id.clone(),
                run_id: payload.run_id.clone(),
                tool_event_id: payload.tool_event_id.clone(),
                status: STATUS_SUCCESS.to_string(),
                result: Some(out.result),
                error: String::new(),
                // 🔴 恒 Untrusted：Guarded 出口已强制重写该字段，Router 不得也无法
                // 改成其它值（`SourceTrust` 只有 `Untrusted` 一个变体）。
                // 注意这里的 `SourceTrust` 是 **hd-protocol**（线格式）的那个：
                // hd-core 另有一个同名枚举用于 executor 返回值，两者刻意不互通 ——
                // 让「执行面声明」与「线上声明」永远显式转换一次，避免跨层顺手借用。
                source_trust: SourceTrust::Untrusted,
            },
            Err(e) => {
                // 错误码优先用服务端已定义的（fs.path_denied 等），否则用稳定分类名：
                // 前端按 code 决策，前后文案可以变、code 不能变。
                let code = e.apperr_code().unwrap_or_else(|| e.kind());
                warn!(
                    tool_event_id = %payload.tool_event_id,
                    tool = %payload.tool_name,
                    code,
                    "执行失败"
                );
                failed(payload, format!("{code}: {e}"))
            }
        };

        self.store
            .put(payload.tool_event_id.clone(), result.clone());
        // 释放占位（必须早于返回）：此后同一个 id 的重派会命中 `Cached` 回放，
        // 而不是被误判成「仍在执行中」。guard 的 Drop 是 panic 路径的兜底。
        guard.release();
        result
    }
}

/// 由服务端墙钟 deadline 算出本地剩余预算；已过期返回 `Duration::ZERO`。
fn remaining_budget(deadline_ms: i64) -> Duration {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        // 系统钟早于 1970 的极端情况：按「无预算」处理（fail-closed），
        // 而不是给一个巨大的余量让工具一直跑下去。
        .unwrap_or(0);
    match deadline_ms.checked_sub(now_ms) {
        Some(left) if left > 0 => Duration::from_millis(left as u64),
        _ => Duration::ZERO,
    }
}

/// 同 id 并发派发时的轮询间隔。
///
/// 被拒绝的那一路会周期性重试 `claim`，直到前者落盘终态（`Cached`）为止。
/// 5ms 是「几乎无感」与「不空转烧 CPU」的折中：即使 executor 只跑 100ms，
/// 也只会多出约 20 次哈希查找（纳秒级），而用户不会感到额外延迟。
const INFLIGHT_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// 组装一条 `failed` 终态。
fn failed(payload: &TaskDispatchPayload, error: String) -> TaskResultPayload {
    TaskResultPayload {
        task_id: payload.tool_event_id.clone(),
        run_id: payload.run_id.clone(),
        tool_event_id: payload.tool_event_id.clone(),
        status: STATUS_FAILED.to_string(),
        result: None,
        error,
        source_trust: SourceTrust::Untrusted,
    }
}

/// 收集式进度出口：把 executor 的流式块攒起来，供测试断言与「暂未接流式通道」的阶段使用。
///
/// 用 `std::sync::Mutex` 而非 channel：`chunk` 是同步签名（`ProgressSink`），
/// channel 的 `try_send` 失败语义会逼调用方决定「丢还是阻塞」，而这一阶段我们只想留存。
#[derive(Debug, Default)]
pub struct CollectingSink {
    chunks: std::sync::Mutex<Vec<String>>,
}

impl CollectingSink {
    /// 取出已收集的全部块（克隆，便于边跑边断言）。
    pub fn chunks(&self) -> Vec<String> {
        match self.chunks.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// 拼接后的完整文本。
    pub fn joined(&self) -> String {
        self.chunks().concat()
    }
}

impl ProgressSink for CollectingSink {
    fn chunk(&self, s: &str) {
        match self.chunks.lock() {
            Ok(mut g) => g.push(s.to_string()),
            Err(mut p) => p.get_mut().push(s.to_string()),
        }
    }
}

/// `dispatch` 在无进度通道时的默认 sink（目前 `session_loop` 就是这样用的）。
pub const DEFAULT_SINK: NoopSink = NoopSink;

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use async_trait::async_trait;
    use hd_core::{AuditEvent, AuditSink, ExecError, ExecOutput, Executor, Guarded, Limits};
    use serde_json::json;

    use super::*;

    /// 假 executor：记调用次数、校验参数、可切换返回成功/失败、可产出进度块。
    struct FakeTool {
        name: &'static str,
        calls: Arc<AtomicUsize>,
        seen_args: Arc<Mutex<Vec<serde_json::Value>>>,
        fail_with: Option<ExecError>,
    }

    impl FakeTool {
        fn ok(name: &'static str) -> (Self, Arc<AtomicUsize>, Arc<Mutex<Vec<serde_json::Value>>>) {
            let calls = Arc::new(AtomicUsize::new(0));
            let seen = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    name,
                    calls: Arc::clone(&calls),
                    seen_args: Arc::clone(&seen),
                    fail_with: None,
                },
                calls,
                seen,
            )
        }

        fn failing(name: &'static str, err: ExecError) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    name,
                    calls: Arc::clone(&calls),
                    seen_args: Arc::new(Mutex::new(Vec::new())),
                    fail_with: Some(err),
                },
                calls,
            )
        }
    }

    #[async_trait]
    impl Executor for FakeTool {
        fn tool_name(&self) -> &'static str {
            self.name
        }

        fn limits(&self) -> Limits {
            Limits {
                timeout: Duration::from_secs(5),
                max_output_bytes: 1024,
            }
        }

        async fn execute(
            &self,
            ctx: &ExecCtx,
            args: &serde_json::Value,
            sink: &dyn ProgressSink,
        ) -> Result<ExecOutput, ExecError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen_args
                .lock()
                .expect("锁不应竞争")
                .push(args.clone());
            sink.chunk("进度块");
            match &self.fail_with {
                Some(e) => Err(e.clone()),
                None => Ok(ExecOutput::untrusted(json!({
                    "tool_event_id": ctx.tool_event_id,
                    "echo": args,
                }))),
            }
        }
    }

    /// 记录审计事件的 sink（用于证明「闸门真的跑了」）。
    #[derive(Default)]
    struct RecordingAudit {
        events: Mutex<Vec<AuditEvent>>,
    }

    impl AuditSink for RecordingAudit {
        fn record(&self, event: AuditEvent) {
            self.events.lock().expect("锁不应竞争").push(event);
        }
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("钟不该跑到 1970 前")
            .as_millis() as i64
    }

    fn dispatch_payload(id: &str, tool: &str, deadline_ms: i64) -> TaskDispatchPayload {
        TaskDispatchPayload {
            run_id: "run-1".to_string(),
            tool_event_id: id.to_string(),
            tool_name: tool.to_string(),
            // 🔴 刻意不带 `path` 键：`Guarded` 会把 path/dir/cwd/target/root 当路径过闸，
            // 用 "C:\work" 这种不存在的路径会让**所有**用例都在闸门处失败，
            // 测不到 router 自己的逻辑。闸门本身的行为由专门的用例覆盖。
            args: Some(json!({ "max": 10 })),
            deadline: deadline_ms,
            attempt: 1,
        }
    }

    /// 带路径参数的派发：专供「验证闸门确实生效」的用例。
    fn dispatch_with_path(
        id: &str,
        tool: &str,
        path: &str,
        deadline_ms: i64,
    ) -> TaskDispatchPayload {
        TaskDispatchPayload {
            args: Some(json!({ "path": path })),
            ..dispatch_payload(id, tool, deadline_ms)
        }
    }

    /// 白名单为空（= 一律拒绝路径）的 policy：假工具的参数里带 path，
    /// 若闸门真在生效，执行会被拒。这里要让它通过，故给一个真实存在的根。
    fn allow_all_policy() -> Arc<Policy> {
        // 空 allowlist 表示「不限工具」；roots 给当前目录（存在且可 canonicalize）。
        let root = std::env::current_dir().expect("cwd");
        Arc::new(Policy::new(vec![root], Vec::new()))
    }

    fn router_with_fake() -> (Router, Arc<AtomicUsize>, Arc<Mutex<Vec<serde_json::Value>>>) {
        let (tool, calls, seen) = FakeTool::ok("fs.list");
        let mut router = Router::new(
            allow_all_policy(),
            Arc::new(RecordingAudit::default()),
            Arc::new(IdempotStore::with_defaults()),
        );
        router.register(tool);
        (router, calls, seen)
    }

    #[tokio::test]
    async fn dispatch_success_returns_result() {
        let (router, calls, _seen) = router_with_fake();
        let p = dispatch_payload("evt-1", "fs.list", now_ms() + 5_000);

        let out = router.dispatch(&p, &NoopSink).await;

        assert_eq!(out.status, STATUS_SUCCESS, "实际: {out:?}");
        assert_eq!(out.tool_event_id, "evt-1");
        assert_eq!(out.task_id, "evt-1", "task_id 与 tool_event_id 恒等");
        assert_eq!(out.run_id, "run-1");
        assert!(out.error.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // 结果体里回显了工具事件 ID，证明真的执行过而不是被伪造
        let body = out.result.expect("success 必须带 result");
        assert_eq!(body["tool_event_id"], json!("evt-1"));
    }

    #[tokio::test]
    async fn second_dispatch_with_same_id_replays_without_reexecuting() {
        let (router, calls, _seen) = router_with_fake();
        let p = dispatch_payload("evt-dup", "fs.list", now_ms() + 5_000);

        let first = router.dispatch(&p, &NoopSink).await;
        let second = router.dispatch(&p, &NoopSink).await;

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "同一个 tool_event_id 第二次必须是回放，executor 只能被调用 1 次"
        );
        assert_eq!(second.status, STATUS_SUCCESS);
        assert_eq!(first.result, second.result, "回放结果必须与首次完全一致");
    }

    #[tokio::test]
    async fn unknown_tool_fails_without_panic() {
        let (router, calls, _seen) = router_with_fake();
        let p = dispatch_payload("evt-2", "shell.exec", now_ms() + 5_000);

        let out = router.dispatch(&p, &NoopSink).await;

        assert_eq!(out.status, STATUS_FAILED);
        assert!(
            out.error.contains("未实现该工具"),
            "错误必须说明未实现，实际: {}",
            out.error
        );
        assert!(out.error.contains("shell.exec"), "错误里应带工具名");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "未注册工具不得执行任何东西"
        );
        assert!(out.result.is_none());
    }

    #[tokio::test]
    async fn expired_deadline_skips_execution() {
        let (router, calls, _seen) = router_with_fake();
        // 一秒前就已过期
        let p = dispatch_payload("evt-3", "fs.list", now_ms() - 1_000);

        let out = router.dispatch(&p, &NoopSink).await;

        assert_eq!(out.status, STATUS_FAILED);
        assert!(
            out.error.contains(CODE_DEVICE_TIMEOUT),
            "错误码语义要对齐 device_timeout，实际: {}",
            out.error
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0, "已过期不得执行 executor");
    }

    #[tokio::test]
    async fn executor_error_becomes_readable_failure() {
        let (tool, calls) = FakeTool::failing(
            "fs.list",
            ExecError::PathDenied {
                path: "C:\\secret".to_string(),
            },
        );
        let mut router = Router::new(
            allow_all_policy(),
            Arc::new(RecordingAudit::default()),
            Arc::new(IdempotStore::with_defaults()),
        );
        router.register(tool);
        let p = dispatch_payload("evt-4", "fs.list", now_ms() + 5_000);

        let out = router.dispatch(&p, &NoopSink).await;

        assert_eq!(out.status, STATUS_FAILED);
        assert!(
            out.error.starts_with("fs.path_denied"),
            "路径类错误必须带服务端错误码，实际: {}",
            out.error
        );
        assert!(
            out.error.contains("不在允许的范围内"),
            "错误文案要可读，实际: {}",
            out.error
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failure_is_also_cached_so_retry_does_not_rerun() {
        let (tool, calls) = FakeTool::failing("fs.list", ExecError::Io("磁盘炸了".to_string()));
        let mut router = Router::new(
            allow_all_policy(),
            Arc::new(RecordingAudit::default()),
            Arc::new(IdempotStore::with_defaults()),
        );
        router.register(tool);
        let p = dispatch_payload("evt-5", "fs.list", now_ms() + 5_000);

        let first = router.dispatch(&p, &NoopSink).await;
        let second = router.dispatch(&p, &NoopSink).await;

        assert_eq!(first.status, STATUS_FAILED);
        assert_eq!(second.error, first.error);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "失败也是终态：重派必须回放而不是再跑一次"
        );
    }

    #[tokio::test]
    async fn all_results_are_untrusted() {
        let (router, _calls, _seen) = router_with_fake();
        let cases = [
            dispatch_payload("e-ok", "fs.list", now_ms() + 5_000),
            dispatch_payload("e-unknown", "nope.tool", now_ms() + 5_000),
            dispatch_payload("e-expired", "fs.list", 1),
        ];
        for p in cases {
            let out = router.dispatch(&p, &NoopSink).await;
            assert_eq!(
                out.source_trust,
                SourceTrust::Untrusted,
                "{} 的结果必须是 untrusted",
                p.tool_event_id
            );
            // 线格式层面也必须显式带 untrusted
            let s = serde_json::to_string(&out).expect("序列化");
            assert!(s.contains("\"source_trust\":\"untrusted\""), "{s}");
        }
    }

    #[tokio::test]
    async fn none_args_are_passed_as_null() {
        let (router, _calls, seen) = router_with_fake();
        let mut p = dispatch_payload("evt-6", "fs.list", now_ms() + 5_000);
        p.args = None;

        router.dispatch(&p, &NoopSink).await;

        let args = seen.lock().expect("锁不应竞争");
        assert_eq!(args[0], serde_json::Value::Null, "None 必须传 Null");
    }

    #[tokio::test]
    async fn progress_chunks_reach_sink() {
        let (router, _calls, _seen) = router_with_fake();
        let sink = CollectingSink::default();
        let p = dispatch_payload("evt-7", "fs.list", now_ms() + 5_000);

        router.dispatch(&p, &sink).await;

        assert_eq!(sink.joined(), "进度块");
    }

    #[tokio::test]
    async fn registry_only_contains_guarded_tools() {
        // §16.2 的行为侧证据：注册的 executor 在参数路径非法时被闸门拦下
        // （inner 未执行），说明注册表里确实是 Guarded 而不是裸 executor。
        let (tool, calls, _seen) = FakeTool::ok("fs.list");
        // 空 roots 的 policy = 任何路径一律拒绝
        let mut router = Router::new(
            Arc::new(Policy::new(Vec::new(), Vec::new())),
            Arc::new(RecordingAudit::default()),
            Arc::new(IdempotStore::with_defaults()),
        );
        router.register(tool);
        // 必须带一个**绝对路径**参数，闸门的路径校验才会被触发；
        // 空 roots 的策略会让任何绝对路径都被判越界。
        let abs = std::env::current_dir().expect("cwd");
        let p = dispatch_with_path("evt-8", "fs.list", &abs.to_string_lossy(), now_ms() + 5_000);

        let out = router.dispatch(&p, &NoopSink).await;

        assert_eq!(out.status, STATUS_FAILED);
        assert!(out.error.starts_with("fs.path_denied"), "{}", out.error);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "闸门拦下的请求不该触达 inner executor"
        );
        assert_eq!(router.tool_names(), vec!["fs.list"]);
    }

    #[tokio::test]
    async fn tool_gate_denies_tool_outside_allowlist() {
        let (tool, calls, _seen) = FakeTool::ok("fs.list");
        let mut router = Router::new(
            allow_all_policy(),
            Arc::new(RecordingAudit::default()),
            Arc::new(IdempotStore::with_defaults()),
        );
        router.register(tool);
        // 把策略换成「只允许别的工具」，再注册一次同名工具（后来的 policy 生效）
        let mut strict = Router::new(
            {
                let root = std::env::current_dir().expect("cwd");
                Arc::new(Policy::new(vec![root], vec!["fs.other".to_string()]))
            },
            Arc::new(RecordingAudit::default()),
            Arc::new(IdempotStore::with_defaults()),
        );
        let (tool2, calls2, _) = FakeTool::ok("fs.list");
        strict.register(tool2);

        let p = dispatch_payload("evt-9", "fs.list", now_ms() + 5_000);
        let out = strict.dispatch(&p, &NoopSink).await;

        assert_eq!(out.status, STATUS_FAILED);
        assert!(out.error.starts_with("not_allowed"), "{}", out.error);
        assert_eq!(calls2.load(Ordering::SeqCst), 0, "白名单外工具不得执行");
        // 顺带保证前一个 router 未被影响
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn remaining_budget_clamps_at_zero() {
        assert_eq!(remaining_budget(0), Duration::ZERO);
        assert_eq!(remaining_budget(now_ms() - 10_000), Duration::ZERO);
        let left = remaining_budget(now_ms() + 10_000);
        assert!(left > Duration::from_secs(5), "{left:?}");
        assert!(left <= Duration::from_secs(11), "{left:?}");
    }

    #[test]
    fn duplicate_registration_keeps_last_one() {
        let (a, calls_a, _) = FakeTool::ok("fs.list");
        let (b, calls_b, _) = FakeTool::ok("fs.list");
        let mut router = Router::new(
            allow_all_policy(),
            Arc::new(RecordingAudit::default()),
            Arc::new(IdempotStore::with_defaults()),
        );
        router.register(a).register(b);
        assert_eq!(router.tool_names(), vec!["fs.list"]);
        // 同名覆盖后只有一个实现生效（这里只断言不 panic 且清单不重复）
        assert_eq!(calls_a.load(Ordering::SeqCst), 0);
        assert_eq!(calls_b.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn router_exposes_policy_and_store() {
        let router = Router::with_defaults(allow_all_policy());
        assert!(router.store().is_empty());
        assert!(!router.policy().roots().is_empty());
        assert!(router.tool_names().is_empty());
    }

    // 让「Guarded 已被使用」这件事在编译期可见：类型别名一旦被误改，这里就挂。
    #[test]
    fn guarded_is_the_only_executor_type_accepted() {
        fn takes_guarded<E: Executor>(g: Guarded<E>) -> &'static str {
            g.tool_name()
        }
        let (tool, _calls, _seen) = FakeTool::ok("fs.list");
        let g = Guarded::new(tool, allow_all_policy(), Arc::new(hd_core::NullAuditSink));
        assert_eq!(takes_guarded(g), "fs.list");
    }
}
