//! `fs.list` 帧处理：工作区目录选择器的端侧实现。
//!
//! ## 语义（对齐 `protocol.go:243-282` / 对接约定 §3.3）
//!
//! 一条 `fs.list` 进来，端侧只做**只读目录列举**，然后回一条 `fs.list.result`：
//!
//! ```text
//!   fs.list{path, with_roots} ──▶ router.policy() ──▶ hd_core::list_dirs(policy, path, 500)
//!                                                       │
//!                                                       ├─ Ok(DirListing) ─▶ From 转换（丢弃 host）
//!                                                       └─ Err(ExecError) ─▶ code/error 映射
//!                                                       ▼
//!                                   out_tx.send(fs.list.result{id = 请求 id})
//! ```
//!
//! ## 三条不可违反的约束
//!
//! 1. **绝不走 `Router::dispatch`**：那是任务链路（落库 `tool_event`、进幂等缓存、
//!    与长任务争并发池）。目录浏览是高频旁路查询，走任务链路会污染审计表，
//!    并且在长任务跑满并发池时被堵到超时。本文件只调用 `policy()` + `list_dirs`。
//! 2. **应答信封 `id` 逐字回显请求 `id`**：服务端 `Deliver(env.ID, ...)` 按此配对。
//! 3. **2.5 秒端侧自守超时**：服务端只等 3 秒，端侧不该做白工（见 [`FS_FRAME_TIMEOUT`]）。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hd_core::{DirListing, ExecError, Policy, FS_MAX_DIRS};
use hd_protocol::envelope::Envelope;
use hd_protocol::error_code;
use hd_protocol::payload::{FsDirEntry, FsListPayload, FsListResultPayload};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::frames::{error_envelope, fs_list_result_envelope, FrameOutcome};
use crate::router::Router;

/// 端侧自守超时。
///
/// 服务端 `internal/device/pathquery.go:49` 的 `pathQueryTimeout = 3s` 是硬超时；
/// 端侧若也等到 3 秒才回，等于让服务端先超时、端侧白做一次目录 IO，用户还要
/// 多等一个来回。留 500ms 余量给「回帧 + 网络」，端侧 2.5 秒即自行放弃并回
/// `fs.host_timeout` —— 这样服务端总能收到一条**有意义的**应答（而不是彻底无回帧，
/// 后者在服务端会被归类成「客户端未实现」）。
pub const FS_FRAME_TIMEOUT: Duration = Duration::from_millis(2500);

/// 处理一条 `fs.list` 帧。
///
/// `router` 为 `None`（未挂载路由能力的部署形态）时回 `fs.host_unsupported`，
/// **不**静默丢弃：静默丢弃会让服务端只能等 3 秒超时，正是本次事故的形态。
pub async fn handle_fs_list(
    router: Option<&Arc<Router>>,
    req: &Envelope,
    payload: &FsListPayload,
    out_tx: &mpsc::Sender<Envelope>,
) -> FrameOutcome {
    let Some(router) = router else {
        warn!(
            req_id = %req.id,
            "未挂载 router，无法列举目录：回 host_unsupported（不静默丢弃）"
        );
        return reply(
            out_tx,
            req.id.as_str(),
            failure_payload(error_code::FS_HOST_UNSUPPORTED, "本端未启用目录列举能力"),
        )
        .await;
    };

    let target = target_of(&payload.path);
    let result = list_with_timeout(router.policy(), target.as_deref(), FS_FRAME_TIMEOUT).await;

    // 失败也走 fs.list.result（带 code），而不是 error 帧：前端需要 separator/roots
    // 才能渲染选择器，纯 error 帧会让它连面包屑都画不出来。
    if !result.error.is_empty() {
        debug!(req_id = %req.id, code = %result.code, "目录列举失败：已按 code 回帧");
    }
    reply(out_tx, req.id.as_str(), result).await
}

/// 列举并**带自守超时**，把成功/失败都收敛成一条应答负载。
///
/// 抽成纯函数（只吃 `Policy`，不碰连接）是本文件可单测的关键：超时、越界、
/// 不存在、截断四种语义都能用 `tempfile` 在毫秒级验完。
pub async fn list_with_timeout(
    policy: &Arc<Policy>,
    target: Option<&Path>,
    timeout: Duration,
) -> FsListResultPayload {
    guard_timeout(timeout, list_result(policy, target)).await
}

/// 自守超时的**唯一实现点**：把任意列举 future 收敛成一条带超时文案的失败负载。
///
/// 抽成泛型函数是为了让超时语义可以被**确定性**单测：直接对一个
/// `std::future::pending()` 施加几十毫秒超时，必定命中超时分支，不依赖磁盘快慢
/// （用「真实目录 + 极小超时」去碰超时是运气型测试，CI 上会随机红）。
async fn guard_timeout<F>(timeout: Duration, fut: F) -> FsListResultPayload
where
    F: std::future::Future<Output = FsListResultPayload>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(payload) => payload,
        Err(_elapsed) => {
            warn!(
                timeout_ms = timeout.as_millis(),
                "目录列举自守超时：回 fs.host_timeout"
            );
            failure_payload(
                error_code::FS_HOST_TIMEOUT,
                &format!("本机列举目录超过 {}ms 未完成", timeout.as_millis()),
            )
        }
    }
}

/// 真正调 `hd_core::list_dirs` 并把结果映射成线上负载（**无超时包装**）。
pub async fn list_result(policy: &Arc<Policy>, target: Option<&Path>) -> FsListResultPayload {
    match hd_core::list_dirs(policy.as_ref(), target, FS_MAX_DIRS).await {
        Ok(listing) => result_from_listing(&listing),
        Err(e) => {
            let (code, msg) = map_exec_error(&e);
            failure_payload(code, &msg)
        }
    }
}

/// `DirListing` → 线上负载。
///
/// 🔴 **显式逐字段搬运，且刻意丢弃本地 `host`**：服务端从连接上下文已知道设备身份，
/// 多一个字段就是协议漂移（Go 侧 `FsListResultPayload` 没有 host，严格解析时会被判成
/// 多余字段）。逐字段写出而不是 `serde_json` 中转，是为了让「哪些字段上行」在编译期
/// 可见、多一个字段就得显式加一行。
///
/// ## 为什么是自由函数而不是 `impl From`
///
/// `From<&DirListing> for FsListResultPayload` 会触发 **孤儿规则**（E0117）：
/// `DirListing`（hd-core）与 `FsListResultPayload`（hd-protocol）都是外部类型，
/// 本 crate 无权为它们实现标准 trait。而把转换放到 hd-protocol 会让协议层反向依赖
/// hd-core（破坏「协议层无执行面」的分层）。故这里用显式命名函数表达同一语义。
pub fn result_from_listing(l: &DirListing) -> FsListResultPayload {
    FsListResultPayload {
        path: l.path.clone(),
        parent: l.parent.clone(),
        separator: l.separator.clone(),
        roots: l.roots.iter().map(entry_of).collect(),
        dirs: l.dirs.iter().map(entry_of).collect(),
        truncated: l.truncated,
        error: String::new(),
        code: String::new(),
    }
}

/// `hd_core::DirEntry` → 线上 `FsDirEntry`（同样只搬 name/path）。
fn entry_of(e: &hd_core::DirEntry) -> FsDirEntry {
    FsDirEntry {
        name: e.name.clone(),
        path: e.path.clone(),
    }
}

/// `ExecError` → `(code, 文案)`。
///
/// 复用 `hd-protocol/src/error_code.rs` 的既有常量（**绝不新增字面量**）：端侧与服务端
/// 对同一错误码的判断是两个字符串比较，拼错即静默失效。
/// 非路径类错误（IO/BadArgs/NotAllowed）没有跨端确定的码，故 `code = ""` 只回文案：
/// 把内部错误伪装成服务端已定义的错误码，会让前端按错误码做出错误决策。
fn map_exec_error(e: &ExecError) -> (&'static str, String) {
    match e {
        ExecError::PathDenied { .. } => (error_code::FS_PATH_DENIED, e.to_string()),
        ExecError::PathNotFound { .. } => (error_code::FS_PATH_NOT_FOUND, e.to_string()),
        ExecError::Timeout => (error_code::FS_HOST_TIMEOUT, e.to_string()),
        ExecError::Io(msg) => ("", msg.clone()),
        ExecError::BadArgs(msg) => ("", msg.clone()),
        ExecError::NotAllowed(msg) => ("", msg.clone()),
    }
}

/// 构造失败负载（字段留全，前端据此渲染错误态而不是空白）。
fn failure_payload(code: &str, message: &str) -> FsListResultPayload {
    FsListResultPayload {
        path: String::new(),
        parent: None,
        separator: hd_core::executor::fs::separator(),
        roots: Vec::new(),
        dirs: Vec::new(),
        truncated: false,
        error: message.to_string(),
        code: code.to_string(),
    }
}

/// 把应答排入出站队列，返回归一化结果。
async fn reply(
    out_tx: &mpsc::Sender<Envelope>,
    req_id: &str,
    payload: FsListResultPayload,
) -> FrameOutcome {
    let env = fs_list_result_envelope(req_id, payload);
    match out_tx.send(env).await {
        Ok(()) => FrameOutcome::Replied,
        // 出站队列已关闭（会话正在结束）：不是错误，但别再白做 IO。
        Err(_) => FrameOutcome::Dropped,
    }
}

/// 请求路径 → 目标目录。空串/纯空白都视为「未定位」（只回 roots）。
fn target_of(path: &str) -> Option<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

/// 处理负载非法时的统一回帧（供 `supervisor` 调用，避免重复写字面量）。
pub async fn reply_bad_payload(out_tx: &mpsc::Sender<Envelope>, req_id: &str) -> FrameOutcome {
    let env = error_envelope(req_id, error_code::FRAME_BAD_FRAME, "fs.list 负载解码失败");
    match out_tx.send(env).await {
        Ok(()) => FrameOutcome::Replied,
        Err(_) => FrameOutcome::Dropped,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use hd_protocol::envelope::MessageType;

    use super::*;
    use crate::idempot::IdempotStore;

    fn policy_of(root: &Path) -> Arc<Policy> {
        Arc::new(Policy::new(
            vec![root.to_path_buf()],
            vec!["fs.list".into()],
        ))
    }

    fn req(id: &str, path: &str) -> Envelope {
        Envelope::new(
            MessageType::FsList,
            id,
            Some(
                serde_json::to_value(FsListPayload {
                    path: path.to_string(),
                    with_roots: path.is_empty(),
                })
                .expect("序列化"),
            ),
        )
    }

    /// 计数假 executor：**断言「目录浏览绝不走任务链路」**。
    ///
    /// 只要 `handle_fs_list` 里有人不小心调了 `Router::dispatch`，这个计数就会 >0，
    /// 测试立刻红 —— 这是「不产生 tool_event」在代码层的可执行证明。
    struct CountingTool {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl hd_core::Executor for CountingTool {
        fn tool_name(&self) -> &'static str {
            "fs.list"
        }

        fn limits(&self) -> hd_core::Limits {
            hd_core::Limits {
                timeout: Duration::from_secs(1),
                max_output_bytes: 1024,
            }
        }

        async fn execute(
            &self,
            _ctx: &hd_core::ExecCtx,
            _args: &serde_json::Value,
            _sink: &dyn hd_core::ProgressSink,
        ) -> Result<hd_core::ExecOutput, hd_core::ExecError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(hd_core::ExecOutput::untrusted(serde_json::Value::Null))
        }
    }

    fn router_with_counter(root: &Path) -> (Arc<Router>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new(
            policy_of(root),
            Arc::new(hd_core::NullAuditSink),
            Arc::new(IdempotStore::with_defaults()),
        );
        router.register(CountingTool {
            calls: Arc::clone(&calls),
        });
        (Arc::new(router), calls)
    }

    /// 处理一帧并把出站队列里排入的帧取出来（容量 8 足够，一帧即返回）。
    async fn run(
        router: Option<&Arc<Router>>,
        req: &Envelope,
        payload: &FsListPayload,
    ) -> (FrameOutcome, Vec<Envelope>) {
        let (tx, mut rx) = mpsc::channel::<Envelope>(8);
        let outcome = handle_fs_list(router, req, payload, &tx).await;
        drop(tx);
        let mut sent = Vec::new();
        while let Some(env) = rx.recv().await {
            sent.push(env);
        }
        (outcome, sent)
    }

    /// 从出站帧里取出第一条 `fs.list.result` 负载，并断言类型/id 配对。
    fn take_result(sent: &[Envelope], want_id: &str) -> FsListResultPayload {
        assert_eq!(sent.len(), 1, "必须且只能回一帧，实际 {sent:?}");
        assert_eq!(
            sent[0].msg_type,
            MessageType::FsListResult,
            "失败也必须走 fs.list.result（前端要 separator 才能渲染）"
        );
        assert_eq!(sent[0].id, want_id, "信封 id 必须逐字回显请求 id");
        sent[0]
            .decode::<FsListResultPayload>()
            .expect("负载应可解码")
            .expect("result 帧必须有负载")
    }

    #[tokio::test]
    async fn lists_only_directories_and_never_dispatches() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().to_path_buf();
        tokio::fs::create_dir(root.join("alpha"))
            .await
            .expect("mkdir");
        tokio::fs::create_dir(root.join("beta"))
            .await
            .expect("mkdir");
        tokio::fs::write(root.join("note.txt"), b"secret")
            .await
            .expect("write");

        let (router, calls) = router_with_counter(&root);
        let payload = FsListPayload {
            path: root.to_string_lossy().into_owned(),
            with_roots: false,
        };
        let (outcome, sent) = run(Some(&router), &req("fsq-1", &payload.path), &payload).await;

        assert_eq!(outcome, FrameOutcome::Replied);
        let p = take_result(&sent, "fsq-1");
        assert!(p.error.is_empty(), "成功列举不应带 error：{p:?}");
        assert!(p.code.is_empty());
        assert_eq!(
            p.dirs.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["alpha", "beta"],
            "只返回目录且按名排序"
        );
        assert!(
            !p.roots.is_empty(),
            "roots 由端侧给出（服务端据此渲染根列表）"
        );
        assert_eq!(p.separator, hd_core::executor::fs::separator());
        // 本地 host 字段绝不上行
        let json = serde_json::to_value(&p).expect("序列化");
        assert!(json.get("host").is_none(), "host 不得上行：{json}");

        // 🔴 核心断言：目录浏览不产生 tool_event（没有调用 dispatch / executor）
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "目录浏览绝不能走 Router::dispatch（会产生 tool_event 并争并发池）"
        );
        assert_eq!(router.store().len(), 0, "幂等缓存不应被目录浏览写入");
    }

    #[tokio::test]
    async fn empty_path_returns_roots_only() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let (router, calls) = router_with_counter(tmp.path());
        let payload = FsListPayload {
            path: String::new(),
            with_roots: true,
        };
        let (_, sent) = run(Some(&router), &req("fsq-roots", ""), &payload).await;

        let p = take_result(&sent, "fsq-roots");
        assert_eq!(p.path, "", "未定位时 path 为空串");
        assert_eq!(p.parent, None);
        assert_eq!(p.roots.len(), 1, "应回白名单根");
        assert!(p.dirs.is_empty(), "未定位时不列子目录");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn outside_root_maps_to_path_denied() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().join("root");
        let outside = tmp.path().join("outside");
        tokio::fs::create_dir_all(&root).await.expect("mkdir");
        tokio::fs::create_dir_all(&outside).await.expect("mkdir");

        let (router, _calls) = router_with_counter(&root);
        let payload = FsListPayload {
            path: outside.to_string_lossy().into_owned(),
            with_roots: false,
        };
        let (_, sent) = run(Some(&router), &req("fsq-denied", &payload.path), &payload).await;

        let p = take_result(&sent, "fsq-denied");
        assert_eq!(
            p.code,
            error_code::FS_PATH_DENIED,
            "越界必须映射 fs.path_denied"
        );
        assert!(!p.error.is_empty(), "错误必须带可读文案");
        assert!(p.dirs.is_empty(), "拒绝时不得回任何目录项（防信息泄漏）");
    }

    #[tokio::test]
    async fn missing_path_maps_to_path_not_found() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().to_path_buf();
        let (router, _calls) = router_with_counter(&root);
        let missing = root.join("ghost");
        let payload = FsListPayload {
            path: missing.to_string_lossy().into_owned(),
            with_roots: false,
        };
        let (_, sent) = run(Some(&router), &req("fsq-404", &payload.path), &payload).await;

        let p = take_result(&sent, "fsq-404");
        assert_eq!(p.code, error_code::FS_PATH_NOT_FOUND);
    }

    #[tokio::test]
    async fn many_dirs_are_truncated_at_server_limit() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().to_path_buf();
        for i in 0..(FS_MAX_DIRS + 5) {
            tokio::fs::create_dir(root.join(format!("d{i:04}")))
                .await
                .expect("mkdir");
        }
        let payload = FsListPayload {
            path: root.to_string_lossy().into_owned(),
            with_roots: false,
        };
        let p = list_result(&policy_of(&root), Some(&root)).await;
        assert_eq!(p.dirs.len(), FS_MAX_DIRS, "上限必须与服务端 fsMaxDirs 一致");
        assert!(p.truncated, "超过上限必须标注 truncated");
        // 未超时的正常路径（顺带验证 list_with_timeout 的成功分支）
        let ok = list_with_timeout(&policy_of(&root), Some(&root), FS_FRAME_TIMEOUT).await;
        assert!(ok.error.is_empty());
        let _ = payload;
    }

    #[tokio::test]
    async fn self_guard_timeout_reports_host_timeout() {
        // 🔴 确定性超时：对一个永不完成的 future 施加超时，必命中超时分支。
        // 用「真实目录 + 极小超时」是运气型测试（磁盘快时根本不会超时，CI 随机红）。
        let p = guard_timeout(Duration::from_millis(1), std::future::pending()).await;
        assert_eq!(p.code, error_code::FS_HOST_TIMEOUT);
        assert!(p.error.contains("未完成"), "应给出可读文案：{p:?}");
        assert!(p.dirs.is_empty());
        assert_eq!(p.parent, None);
        // 失败负载仍带 separator：前端要能画出面包屑才能展示错误态
        assert!(!p.separator.is_empty());

        // 真实目录 + 充足超时：走成功分支（同一条路径的另一端）
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().to_path_buf();
        tokio::fs::create_dir(root.join("child"))
            .await
            .expect("mkdir");
        let ok = list_with_timeout(&policy_of(&root), Some(&root), FS_FRAME_TIMEOUT).await;
        assert!(ok.error.is_empty(), "充足超时下应成功：{ok:?}");
        assert_eq!(ok.dirs.len(), 1);
    }

    #[tokio::test]
    async fn no_router_replies_unsupported_instead_of_silence() {
        let (_, sent) = run(None, &req("fsq-norouter", ""), &FsListPayload::default()).await;
        let p = take_result(&sent, "fsq-norouter");
        assert_eq!(
            p.code,
            error_code::FS_HOST_UNSUPPORTED,
            "未挂 router 必须明确报不支持，绝不静默丢弃（静默 = 服务端 3 秒超时）"
        );
    }

    #[tokio::test]
    async fn closed_outbound_queue_is_dropped_not_panicked() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let (router, _calls) = router_with_counter(tmp.path());
        let (tx, rx) = mpsc::channel::<Envelope>(1);
        drop(rx); // 会话结束：队列没人读
        let outcome = handle_fs_list(
            Some(&router),
            &req("fsq-closed", ""),
            &FsListPayload::default(),
            &tx,
        )
        .await;
        assert_eq!(outcome, FrameOutcome::Dropped);
    }

    #[test]
    fn target_of_treats_blank_as_unlocated() {
        assert!(target_of("").is_none());
        assert!(target_of("   ").is_none());
        assert_eq!(target_of(" C:/x "), Some(PathBuf::from("C:/x")));
    }

    #[test]
    fn from_dir_listing_drops_host_field() {
        let listing = DirListing {
            host: "device:abc".to_string(),
            path: "C:\\work".to_string(),
            parent: Some("C:\\".to_string()),
            separator: "\\".to_string(),
            roots: Vec::new(),
            dirs: vec![hd_core::DirEntry {
                name: "Proj".to_string(),
                path: "C:\\work\\Proj".to_string(),
            }],
            truncated: false,
        };
        let p = result_from_listing(&listing);
        let json = serde_json::to_value(&p).expect("序列化");
        for key in ["path", "parent", "separator", "dirs"] {
            assert!(json.get(key).is_some(), "缺少字段 {key}");
        }
        assert!(json.get("host").is_none(), "host 必须被丢弃");
        assert_eq!(json["dirs"][0]["name"], "Proj");
        // dirs 项只允许 name/path 两个键
        let keys: Vec<&String> = json["dirs"][0].as_object().expect("对象").keys().collect();
        assert_eq!(keys, vec!["name", "path"], "DirEntry 只允许两个字段");
    }

    /// 错误码必须与 `error_code` 常量逐字一致（服务端按字符串比较）。
    #[test]
    fn exec_error_mapping_uses_protocol_constants() {
        let denied = map_exec_error(&ExecError::PathDenied {
            path: "x".to_string(),
        });
        assert_eq!(denied.0, "fs.path_denied");
        let notfound = map_exec_error(&ExecError::PathNotFound {
            path: "x".to_string(),
        });
        assert_eq!(notfound.0, "fs.path_not_found");
        // 非路径类错误不伪装成已定义的跨端码
        assert_eq!(map_exec_error(&ExecError::Io("boom".into())).0, "");
        assert_eq!(map_exec_error(&ExecError::BadArgs("bad".into())).0, "");
    }
}
