//! 三闸路径校验 + `Guarded` 包装 + 本地审计（设计文档 §16.2）。
//!
//! **包装而非内联**的原因：安全判定若写在 executor 内部，第二个 executor 就会漏写一次。
//! 这里把它做成「唯一的执行入口」：router 只持有 [`Guarded<E>`]，拿不到裸 `E`，
//! 因此「忘了过闸」不是纪律问题，而是根本编译不出来的一段代码。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tracing::warn;

use crate::executor::{
    ExecCtx, ExecError, ExecOutput, Executor, Limits, ProgressSink, SourceTrust,
};
use crate::security::paths::{canonical, display_path, has_dotdot_segment, is_within};
use crate::security::redact::scrub;

/// 参数里被视为「路径」的字段名。收窄成固定清单而不是「凡是字符串都当路径」：
/// 把 `max`、`pattern` 这类值丢进白名单校验只会制造无意义的拒绝。
const PATH_ARG_KEYS: [&str; 5] = ["path", "dir", "cwd", "target", "root"];

/// 本地安全策略：能碰哪些目录、能跑哪些工具。
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// 白名单根，**全部是 canonicalize 之后的形态**（`\\?\` 前缀已剥掉）。
    roots: Vec<PathBuf>,
    /// 允许执行的工具名；为空表示「不限制」（由 router 侧的能力声明负责）。
    exec_allowlist: Vec<String>,
}

impl Policy {
    /// 构造策略。无法 canonicalize 的根会被**丢弃并告警**（fail-closed）：
    /// 配置里写错一个根就让「全盘可读」，是最坏的失败方向。
    pub fn new(roots: Vec<PathBuf>, exec_allowlist: Vec<String>) -> Self {
        let mut kept = Vec::with_capacity(roots.len());
        for r in roots {
            match canonical(&r) {
                // canonicalize 会解掉软链与 Windows 重解析点，因此比目录记录下来的
                // 是「真实位置」。若根本身是软链，配置者显然希望的是它指向的目标。
                Some(real) => kept.push(display_path(&real)),
                None => warn!(root = %r.display(), "白名单根无法解析，已丢弃（fail-closed）"),
            }
        }
        Self {
            roots: kept,
            exec_allowlist,
        }
    }

    /// 白名单根（已是归一形态，可直接用于展示与比对）。
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// 工具是否在允许清单内。清单为空视为不限（调用方只在明确配置时才受限）。
    pub fn is_tool_allowed(&self, tool_name: &str) -> bool {
        self.exec_allowlist.is_empty() || self.exec_allowlist.iter().any(|t| t == tool_name)
    }

    /// 工具闸：不在清单内直接拒绝，连参数都不看。
    pub fn check_tool(&self, tool_name: &str) -> Result<(), ExecError> {
        if self.is_tool_allowed(tool_name) {
            Ok(())
        } else {
            Err(ExecError::NotAllowed(format!(
                "工具 {tool_name} 未在端侧允许清单内"
            )))
        }
    }

    /// 三道闸路径校验，返回**归一后的绝对路径**（可直接用于 IO）。
    ///
    /// 闸序刻意固定：先拒原始输入里的 `..`，再杜绝相对路径，最后才做白名单归属。
    /// 顺序颠倒就会出现「已经被 clean 抹平的路径看起来很无辜」的漏洞。
    pub fn check_path(&self, p: &Path) -> Result<PathBuf, ExecError> {
        let deny = || ExecError::PathDenied {
            path: p.to_string_lossy().into_owned(),
        };

        // 闸 1：显式拒绝含 `..` 段的**原始输入**。
        // 必须在 clean/canonicalize 之前判断，否则 `a/../../../etc` 会被抹平后蒙混过关。
        // 出处：harness_go/internal/api/fs_handler.go:108-119 fsContainsDotDot。
        if has_dotdot_segment(p) {
            return Err(deny());
        }

        // 闸 2 的前置：必须绝对路径。相对路径的语义依赖进程 CWD（Runner 的 CWD 不由用户控制，
        // 也可能被后续代码改动），用它做安全判断等于没有判断。对齐 fs_handler.go:148-151。
        if !p.is_absolute() {
            return Err(deny());
        }

        // 白名单为空 → 一律拒绝（失败即关闭，绝不放行全盘）。
        // 出处：fs_handler.go:154-156「服务端未配置可浏览的目录范围」。
        if self.roots.is_empty() {
            return Err(deny());
        }

        // 闸 2：归一化。canonicalize 会解开整条父链上的软链/重解析点，
        // 因此「软链指向白名单外」在这里就变成了「越界」，无需另外写一段软链遍历逻辑。
        let real = match canonical(p) {
            Some(real) => display_path(&real),
            None => {
                // 区分「不存在」与「不给看」：前者是用户输入错误（404），后者是权限问题（拒绝）。
                // 用 metadata 而不是读内容——本 crate 任何地方都不该 read 文件内容。
                return match std::fs::metadata(p) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        Err(ExecError::PathNotFound {
                            path: p.to_string_lossy().into_owned(),
                        })
                    }
                    // 权限不足或其它系统错误：按「拒绝」处理，不回显系统细节（防信息泄漏）
                    Err(_) => Err(deny()),
                    // metadata 成功但 canonicalize 失败（极少数竞态）：保守拒绝
                    Ok(_) => Err(deny()),
                };
            }
        };

        // 闸 3：组件级归属比对（Windows 大小写不敏感由 paths::is_within 内部处理）。
        // 用组件序列而非字符串前缀，防止 `C:\work-evil` 借 `C:\work` 的前缀混进来。
        if self.roots.iter().any(|root| is_within(root, &real)) {
            Ok(real)
        } else {
            Err(deny())
        }
    }

    /// 目录的上级，若已到白名单根则返回 `None`。
    ///
    /// 前端约定「到根层级 parent 为 null，绝不返回 `..`」（workspaceHost.ts:31）：
    /// 返回 `..` 会让前端把面包屑渲染成可以往上跳，而上一级可能已在白名单外。
    pub fn parent_within_roots(&self, dir: &Path) -> Option<PathBuf> {
        let real = display_path(&canonical(dir)?);
        // 「等于某个根」用双向 is_within 判断，而不是 `root == &real`：
        // Windows 上两边盘符/字母大小写可能不一致，Path 的 == 是字节级比较，
        // 会让「当前已在根」被误判成「还在根下面」，于是根层级也返回了 parent。
        let at_root = self
            .roots
            .iter()
            .any(|root| is_within(root, &real) && is_within(&real, root));
        if at_root {
            return None;
        }
        let parent = real.parent()?;
        if self.roots.iter().any(|root| is_within(root, parent)) {
            Some(parent.to_path_buf())
        } else {
            None
        }
    }
}

/// 审计结果分类。用枚举而非错误串，便于本地日志聚合。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditOutcome {
    /// 执行成功。
    Success,
    /// 被闸门拦下（未执行）。
    Denied,
    /// 执行了但失败，携带稳定分类名（[`ExecError::kind`]）。
    Failed(String),
}

/// 一条审计记录。
///
/// 只放「谁在什么时候做了什么、结果如何」，**不放参数原文**：
/// 参数里可能有路径甚至凭据，审计日志本身不该成为泄漏源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub tool_event_id: String,
    pub tool_name: String,
    pub outcome: AuditOutcome,
    /// 是否放行（与 outcome 冗余但分开存：Denied 时 allowed=false 一目了然）。
    pub allowed: bool,
}

/// 本地审计出口（不变量 1：端侧不直写 DB，只交给 sink，由上层决定落到哪里）。
pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEvent);
}

/// 什么都不记的 sink：单测与「审计未接入」阶段使用。
#[derive(Debug, Default, Clone, Copy)]
pub struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn record(&self, _event: AuditEvent) {}
}

/// 唯一的执行入口：安全闸门 + 结果脱敏 + 结果强制标记为不可信。
pub struct Guarded<E: Executor> {
    inner: E,
    policy: Arc<Policy>,
    audit: Arc<dyn AuditSink>,
}

impl<E: Executor> Guarded<E> {
    pub fn new(inner: E, policy: Arc<Policy>, audit: Arc<dyn AuditSink>) -> Self {
        Self {
            inner,
            policy,
            audit,
        }
    }

    /// 暴露策略只为了让 router 组装菜单/根列表；**不提供 inner 的访问器**，
    /// 否则「拿不到裸 executor」这条就在代码里被自己破了。
    pub fn policy(&self) -> &Arc<Policy> {
        &self.policy
    }

    /// 从参数里挑出需要过闸的路径。（只认顶层固定键名，见 [`PATH_ARG_KEYS`]。）
    fn collect_path_args(args: &serde_json::Value) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let serde_json::Value::Object(map) = args {
            for key in PATH_ARG_KEYS {
                if let Some(serde_json::Value::String(s)) = map.get(key) {
                    // 空串等同于「未指定」（前端未定位时会传空串，见 workspaceHost.ts:29）
                    if !s.trim().is_empty() {
                        out.push(PathBuf::from(s));
                    }
                }
            }
        }
        out
    }
}

#[async_trait]
impl<E: Executor> Executor for Guarded<E> {
    fn tool_name(&self) -> &'static str {
        self.inner.tool_name()
    }

    fn limits(&self) -> Limits {
        self.inner.limits()
    }

    async fn execute(
        &self,
        ctx: &ExecCtx,
        args: &serde_json::Value,
        sink: &dyn ProgressSink,
    ) -> Result<ExecOutput, ExecError> {
        let tool = self.inner.tool_name();

        // ① 工具闸
        if let Err(e) = self.policy.check_tool(tool) {
            self.audit.record(AuditEvent {
                tool_event_id: ctx.tool_event_id.clone(),
                tool_name: tool.to_string(),
                outcome: AuditOutcome::Denied,
                allowed: false,
            });
            return Err(e);
        }

        // ② 参数路径闸：任何一个路径越界就整体拒绝，**inner 根本不会被调用**。
        // 这是「先校验、后执行」与「边做边查」的分界线：后者已经在磁盘上留下了痕迹。
        for p in Self::collect_path_args(args) {
            if let Err(e) = self.policy.check_path(&p) {
                self.audit.record(AuditEvent {
                    tool_event_id: ctx.tool_event_id.clone(),
                    tool_name: tool.to_string(),
                    outcome: AuditOutcome::Denied,
                    allowed: false,
                });
                return Err(e);
            }
        }

        // ③ 时限闸：取「工具声明上限」与「服务端 deadline 余量」的较小值，executor 无权放宽。
        let budget = self.inner.limits().timeout.min(ctx.remaining());
        if budget.is_zero() {
            self.audit.record(AuditEvent {
                tool_event_id: ctx.tool_event_id.clone(),
                tool_name: tool.to_string(),
                outcome: AuditOutcome::Denied,
                allowed: false,
            });
            return Err(ExecError::Timeout);
        }

        // ④ 执行
        let outcome = tokio::time::timeout(budget, self.inner.execute(ctx, args, sink)).await;

        let (result, audit) = match outcome {
            Ok(Ok(out)) => (
                Ok(out),
                AuditEvent {
                    tool_event_id: ctx.tool_event_id.clone(),
                    tool_name: tool.to_string(),
                    outcome: AuditOutcome::Success,
                    allowed: true,
                },
            ),
            Ok(Err(e)) => {
                let audit = AuditEvent {
                    tool_event_id: ctx.tool_event_id.clone(),
                    tool_name: tool.to_string(),
                    outcome: AuditOutcome::Failed(e.kind().to_string()),
                    allowed: true,
                };
                (Err(e), audit)
            }
            // 超时同样是「执行过」，allowed=true：闸门放行了，只是没跑完
            Err(_elapsed) => (
                Err(ExecError::Timeout),
                AuditEvent {
                    tool_event_id: ctx.tool_event_id.clone(),
                    tool_name: tool.to_string(),
                    outcome: AuditOutcome::Failed("timeout".to_string()),
                    allowed: true,
                },
            ),
        };
        self.audit.record(audit);

        // ⑤ 出口统一处理：脱敏 + 强制 Untrusted。
        // 即便 inner 编造了别的可信度，这一行也会把它覆盖掉——
        // 更何况 SourceTrust 本来就只有 Untrusted 一个变体（双重保证）。
        result.map(|out| ExecOutput {
            result: scrub(out.result),
            source_trust: SourceTrust::Untrusted,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::executor::NoopSink;

    /// 记录调用次数与被调参数；同时故意返回「带密钥」的结果，用于验证出口脱敏。
    struct FakeExecutor {
        calls: Arc<AtomicUsize>,
        seen: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    impl FakeExecutor {
        fn new() -> (Self, Arc<AtomicUsize>, Arc<Mutex<Vec<serde_json::Value>>>) {
            let calls = Arc::new(AtomicUsize::new(0));
            let seen = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    calls: Arc::clone(&calls),
                    seen: Arc::clone(&seen),
                },
                calls,
                seen,
            )
        }
    }

    #[async_trait]
    impl Executor for FakeExecutor {
        fn tool_name(&self) -> &'static str {
            "fs.list"
        }

        async fn execute(
            &self,
            _ctx: &ExecCtx,
            args: &serde_json::Value,
            _sink: &dyn ProgressSink,
        ) -> Result<ExecOutput, ExecError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().expect("lock").push(args.clone());
            Ok(ExecOutput::untrusted(json!({
                "path": "C:\\work",
                "token": "hgd_secret_value",
            })))
        }
    }

    /// 记录审计事件的 sink。
    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<AuditEvent>>,
    }

    impl AuditSink for RecordingSink {
        fn record(&self, event: AuditEvent) {
            self.events.lock().expect("lock").push(event);
        }
    }

    fn ctx() -> ExecCtx {
        ExecCtx::with_timeout("evt-1", "run-1", Duration::from_secs(5), 0)
    }

    fn policy_for(root: &Path) -> Arc<Policy> {
        Arc::new(Policy::new(
            vec![root.to_path_buf()],
            vec!["fs.list".into()],
        ))
    }

    #[test]
    fn allows_path_inside_root() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).expect("mkdir");
        let policy = policy_for(tmp.path());
        let got = policy.check_path(&sub).expect("应放行");
        // 返回的是归一形态（不存在 `..`、无 `\\?\` 前缀），且仍指向同一目录
        assert!(got.ends_with("sub"));
        assert!(is_within(tmp.path(), &got));
    }

    #[test]
    fn root_itself_is_allowed() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let policy = policy_for(tmp.path());
        assert!(policy.check_path(tmp.path()).is_ok());
    }

    #[test]
    fn rejects_dotdot_segment() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let policy = policy_for(tmp.path());
        // 即便前半段在根内，含 `..` 就拒（clean 之前判断）
        let evil = tmp.path().join("a").join("..").join("..").join("etc");
        let err = policy.check_path(&evil).unwrap_err();
        assert!(matches!(err, ExecError::PathDenied { .. }), "{err:?}");
        assert_eq!(err.apperr_code(), Some("fs.path_denied"));
    }

    #[test]
    fn rejects_relative_path() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let policy = policy_for(tmp.path());
        let err = policy.check_path(Path::new("relative/dir")).unwrap_err();
        assert!(matches!(err, ExecError::PathDenied { .. }), "{err:?}");
    }

    #[test]
    fn rejects_path_outside_root() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().join("work");
        let other = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&root).expect("mkdir root");
        std::fs::create_dir_all(&other).expect("mkdir other");
        let policy = policy_for(&root);
        let err = policy.check_path(&other).unwrap_err();
        assert!(matches!(err, ExecError::PathDenied { .. }), "{err:?}");
    }

    #[test]
    fn rejects_prefix_lookalike_sibling_dir() {
        // 关键回归：`work-evil` 与 `work` 共享前缀，但不该被当成「在内」
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().join("work");
        let evil = tmp.path().join("work-evil");
        std::fs::create_dir_all(&root).expect("mkdir root");
        std::fs::create_dir_all(&evil).expect("mkdir evil");
        let policy = policy_for(&root);
        assert!(policy.check_path(&root).is_ok());
        assert!(policy.check_path(&evil).is_err(), "work-evil 不该被放行");
    }

    #[cfg(windows)]
    #[test]
    fn windows_case_insensitive_path_still_allowed() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let sub = tmp.path().join("WorkDir");
        std::fs::create_dir(&sub).expect("mkdir");
        let policy = policy_for(tmp.path());
        // 故意把大小写改掉：Windows 上指向同一目录，必须放行
        let shouty = PathBuf::from(sub.to_string_lossy().to_uppercase());
        assert!(policy.check_path(&shouty).is_ok(), "{shouty:?}");
    }

    #[test]
    fn nonexistent_path_reports_not_found() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let missing = tmp.path().join("nope");
        let policy = policy_for(tmp.path());
        let err = policy.check_path(&missing).unwrap_err();
        assert!(matches!(err, ExecError::PathNotFound { .. }), "{err:?}");
        assert_eq!(err.apperr_code(), Some("fs.path_not_found"));
    }

    #[test]
    fn empty_roots_denies_everything() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let policy = Policy::new(Vec::new(), Vec::new());
        assert!(policy.check_path(tmp.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escaping_root_is_denied() {
        // Unix 才能无权限阻碍地造软链；Windows 建软链需要开发者模式/管理员
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().join("work");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&root).expect("mkdir root");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        std::os::unix::fs::symlink(&outside, root.join("link")).expect("symlink");

        let policy = policy_for(&root);
        let err = policy.check_path(&root.join("link")).unwrap_err();
        assert!(matches!(err, ExecError::PathDenied { .. }), "{err:?}");
    }

    #[test]
    fn tool_allowlist_checked() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let policy = policy_for(tmp.path());
        assert!(policy.check_tool("fs.list").is_ok());
        assert!(matches!(
            policy.check_tool("shell.exec").unwrap_err(),
            ExecError::NotAllowed(_)
        ));
        // 空清单 = 不限
        let open = Policy::new(vec![tmp.path().to_path_buf()], Vec::new());
        assert!(open.check_tool("anything").is_ok());
    }

    #[test]
    fn parent_within_roots_stops_at_root() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().join("work");
        let sub = root.join("a").join("b");
        std::fs::create_dir_all(&sub).expect("mkdir");
        let policy = policy_for(&root);
        assert_eq!(
            policy
                .parent_within_roots(&sub)
                .map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
            Some(Some("a".to_string()))
        );
        // 根层级 → None（绝不返回 ".."）
        assert!(policy.parent_within_roots(&root).is_none());
    }

    #[tokio::test]
    async fn guarded_allows_inside_path_and_scrubs_output() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let (fake, calls, _seen) = FakeExecutor::new();
        let audit = Arc::new(RecordingSink::default());
        let guarded = Guarded::new(
            fake,
            policy_for(tmp.path()),
            Arc::clone(&audit) as Arc<dyn AuditSink>,
        );

        let args = json!({ "path": tmp.path().to_string_lossy() });
        let out = guarded
            .execute(&ctx(), &args, &NoopSink)
            .await
            .expect("应放行");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // 结果里的 token 字段被脱敏
        assert_eq!(out.result["token"], "***");
        // 可信度被强制为 Untrusted
        assert_eq!(out.source_trust, SourceTrust::Untrusted);

        let events = audit.events.lock().expect("lock");
        assert_eq!(events.len(), 1);
        assert!(events[0].allowed);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert_eq!(events[0].tool_event_id, "evt-1");
    }

    #[tokio::test]
    async fn guarded_never_calls_inner_on_outside_path() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().join("work");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&root).expect("mkdir root");
        std::fs::create_dir_all(&outside).expect("mkdir outside");

        let (fake, calls, seen) = FakeExecutor::new();
        let audit = Arc::new(RecordingSink::default());
        let guarded = Guarded::new(
            fake,
            policy_for(&root),
            Arc::clone(&audit) as Arc<dyn AuditSink>,
        );

        let args = json!({ "path": outside.to_string_lossy() });
        let err = guarded
            .execute(&ctx(), &args, &NoopSink)
            .await
            .expect_err("越界必须被拒");

        assert!(matches!(err, ExecError::PathDenied { .. }), "{err:?}");
        // 核心断言：inner 一次都没被调用，也没看到参数
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(seen.lock().expect("lock").is_empty());

        let events = audit.events.lock().expect("lock");
        assert_eq!(events.len(), 1);
        assert!(!events[0].allowed);
        assert_eq!(events[0].outcome, AuditOutcome::Denied);
    }

    #[tokio::test]
    async fn guarded_rejects_tool_not_in_allowlist_without_calling_inner() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let (fake, calls, _seen) = FakeExecutor::new();
        let policy = Arc::new(Policy::new(
            vec![tmp.path().to_path_buf()],
            vec!["shell.exec".into()],
        ));
        let guarded = Guarded::new(fake, policy, Arc::new(NullAuditSink));

        let err = guarded
            .execute(&ctx(), &json!({}), &NoopSink)
            .await
            .expect_err("工具不在清单内");
        assert!(matches!(err, ExecError::NotAllowed(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn guarded_times_out_per_deadline() {
        let tmp = tempfile::tempdir().expect("tmpdir");

        struct SlowExecutor;
        #[async_trait]
        impl Executor for SlowExecutor {
            fn tool_name(&self) -> &'static str {
                "fs.list"
            }
            async fn execute(
                &self,
                _ctx: &ExecCtx,
                _args: &serde_json::Value,
                _sink: &dyn ProgressSink,
            ) -> Result<ExecOutput, ExecError> {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(ExecOutput::untrusted(json!({})))
            }
        }

        // deadline 只剩 50ms → 必须在 50ms 左右就返回 Timeout，而不是等 30s
        let short = ExecCtx::with_timeout("evt", "run", Duration::from_millis(50), 0);
        let guarded = Guarded::new(
            SlowExecutor,
            policy_for(tmp.path()),
            Arc::new(NullAuditSink),
        );
        let err = guarded
            .execute(&short, &json!({}), &NoopSink)
            .await
            .expect_err("应超时");
        assert_eq!(err, ExecError::Timeout);
    }

    #[tokio::test]
    async fn guarded_rejects_already_expired_ctx() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let (fake, calls, _seen) = FakeExecutor::new();
        let guarded = Guarded::new(fake, policy_for(tmp.path()), Arc::new(NullAuditSink));
        let expired = ExecCtx {
            deadline: std::time::Instant::now() - Duration::from_secs(1),
            ..ctx()
        };
        let err = guarded
            .execute(&expired, &json!({}), &NoopSink)
            .await
            .expect_err("已过期");
        assert_eq!(err, ExecError::Timeout);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
