//! `fs.list` 端侧实现（设计文档 §16.4，C3–C6 逐条落地）。
//!
//! 只做**只读、只看目录**的列举：
//! - 用 `read_dir` + `file_type`，**绝不读取任何文件内容**（`cat .env` 这类能力
//!   不属于目录选择器，混进来就等于把浏览动作升级成读取动作）；
//! - 软链一律跳过（`file_type().is_symlink()`）：可能是环，也可能指向白名单外；
//! - 单次上限 500，对齐服务端 `harness_go/internal/api/fs_handler.go:33` 的 `fsMaxDirs = 500`。
//!   两端阈值不同会造成「服务端空间能看全、客户端看不全」的诡异差异。

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::executor::{ExecCtx, ExecError, ExecOutput, Executor, Limits, ProgressSink};
use crate::security::guard::Policy;
use crate::security::paths::display_path;

/// 单次列举目录项上限。**必须**与服务端 `fsMaxDirs` 一致（见模块注释）。
pub const FS_MAX_DIRS: usize = 500;

/// 未注入真实设备 id 时的宿主标识占位。
///
/// 形态保持 `device:<something>`，与前端 `HostID = 'server' | \`device:${string}\``
/// （web/src/lib/workspaceHost.ts:17）兼容；hd-runner 会用真实 device_id 覆盖它。
pub const DEFAULT_HOST: &str = "device:self";

/// 一个目录项。字段与前端 `DirEntry`（web/src/lib/workspaceHost.ts:20-23）逐字对齐：
/// 只有 `name` 与 `path`，**刻意不含任何文件元数据**（大小/修改时间会让前端误以为能排序文件）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub path: String,
}

/// 一次目录列举结果。字段与前端 `DirListing`（web/src/lib/workspaceHost.ts:26-40）逐字对齐。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirListing {
    pub host: String,
    /// 当前目录绝对路径；空串 = 尚未定位（此时只有 roots）
    pub path: String,
    /// 上级目录；`null` 表示已在白名单根层级（**绝不返回 `..`**，见 workspaceHost.ts:31）
    pub parent: Option<String>,
    /// 路径分隔符：Windows `\`，POSIX `/`（前端用它切面包屑）
    pub separator: String,
    /// 可选根（仅在 path 为空时给出）
    pub roots: Vec<DirEntry>,
    /// 子目录（只含目录，永不含文件）
    pub dirs: Vec<DirEntry>,
    /// 目录项过多被截断
    pub truncated: bool,
}

/// 当前平台路径分隔符，对齐服务端 `fsSeparator()`（fs_handler.go:66-72）。
pub fn separator() -> String {
    if cfg!(windows) {
        "\\".to_string()
    } else {
        "/".to_string()
    }
}

/// 列举目录。`target` 为 `None` 时只回白名单根。
pub async fn list_dirs(
    policy: &Policy,
    target: Option<&Path>,
    max: usize,
) -> Result<DirListing, ExecError> {
    // 0 或超上限都收敛到 500：让调用方无法通过参数把上限「调大」。
    let limit = if max == 0 {
        FS_MAX_DIRS
    } else {
        max.min(FS_MAX_DIRS)
    };

    let roots: Vec<DirEntry> = policy
        .roots()
        .iter()
        .map(|r| DirEntry {
            // 盘根（`C:\`、`/`）没有 file_name，此时直接拿全路径当显示名
            name: r
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| r.to_string_lossy().into_owned()),
            path: r.to_string_lossy().into_owned(),
        })
        .collect();

    // 未定位：只回根，且 dirs 为空、path 为空串（前端据此显示「选择磁盘/目录」）
    let target = match target {
        Some(t) if !t.as_os_str().is_empty() => t,
        _ => {
            return Ok(DirListing {
                host: DEFAULT_HOST.to_string(),
                path: String::new(),
                parent: None,
                separator: separator(),
                roots,
                dirs: Vec::new(),
                truncated: false,
            });
        }
    };

    // 走闸门：这里再校验一次，不是重复劳动——executor 可能被单独装配到别处（单测、CLI），
    // 安全判定不能依赖「调用方一定先调过 Guarded」这种口头约定。
    let real = policy.check_path(target)?;

    let mut entries = tokio::fs::read_dir(&real).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ExecError::PathNotFound {
                path: target.to_string_lossy().into_owned(),
            }
        } else if e.kind() == std::io::ErrorKind::PermissionDenied {
            // 无权限按「拒绝」上报，避免把「存在但不可读」泄漏成可枚举的信息
            ExecError::PathDenied {
                path: target.to_string_lossy().into_owned(),
            }
        } else {
            ExecError::Io(e.to_string())
        }
    })?;

    let mut dirs = Vec::new();
    let mut truncated = false;
    // 只 read_dir 拿元数据，不 open/read 任何文件
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| ExecError::Io(e.to_string()))?
    {
        let file_type = match entry.file_type().await {
            Ok(ft) => ft,
            // 单个条目在枚举途中消失（并发删除）不该让整次列举失败
            Err(_) => continue,
        };
        // 软链跳过：可能成环，也可能指向白名单外，跟随它等于绕开三闸
        if file_type.is_symlink() || !file_type.is_dir() {
            continue;
        }
        if dirs.len() >= limit {
            truncated = true;
            break;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        dirs.push(DirEntry {
            path: display_path(&real)
                .join(&name)
                .to_string_lossy()
                .into_owned(),
            name,
        });
    }

    // 按名排序（大小写不敏感）保证输出稳定：不同文件系统的 readdir 顺序不一样，
    // 不排序会让前端目录顺序随机跳动，也让测试无法断言。
    dirs.sort_by_key(|d| d.name.to_lowercase());

    let parent = policy
        .parent_within_roots(&real)
        .map(|p| p.to_string_lossy().into_owned());

    Ok(DirListing {
        host: DEFAULT_HOST.to_string(),
        path: display_path(&real).to_string_lossy().into_owned(),
        parent,
        separator: separator(),
        roots,
        dirs,
        truncated,
    })
}

/// `fs.list` 的 Executor 实现。
pub struct ListDirsExecutor {
    policy: Arc<Policy>,
    /// 真实宿主标识（`device:<id>`）；为 `None` 时用 [`DEFAULT_HOST`]
    host: Option<String>,
    /// 单次上限，构造时即被钳在 [`FS_MAX_DIRS`] 内
    max: usize,
}

impl ListDirsExecutor {
    pub fn new(policy: Arc<Policy>, host: Option<String>, max: usize) -> Self {
        Self { policy, host, max }
    }

    /// 从参数里取目标路径。空串/缺省都视为「未定位」。
    fn target_of(args: &serde_json::Value) -> Option<std::path::PathBuf> {
        match args.get("path").and_then(|v| v.as_str()) {
            Some(s) if !s.trim().is_empty() => Some(std::path::PathBuf::from(s)),
            _ => None,
        }
    }
}

#[async_trait]
impl Executor for ListDirsExecutor {
    fn tool_name(&self) -> &'static str {
        "fs.list"
    }

    fn limits(&self) -> Limits {
        // 目录列举是高频轻操作：5s 足够，超过说明磁盘或挂载点出了问题，早失败早重试
        Limits {
            timeout: std::time::Duration::from_secs(5),
            ..Limits::default()
        }
    }

    async fn execute(
        &self,
        ctx: &ExecCtx,
        args: &serde_json::Value,
        _sink: &dyn ProgressSink,
    ) -> Result<ExecOutput, ExecError> {
        if ctx.is_expired() {
            return Err(ExecError::Timeout);
        }
        let target = Self::target_of(args);
        let mut listing = list_dirs(&self.policy, target.as_deref(), self.max).await?;
        if let Some(host) = &self.host {
            listing.host = host.clone();
        }
        Ok(ExecOutput::untrusted(
            serde_json::to_value(listing).map_err(|e| ExecError::Io(e.to_string()))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::executor::{ExecError, NoopSink};

    fn policy_of(root: &Path) -> Policy {
        Policy::new(vec![root.to_path_buf()], vec!["fs.list".into()])
    }

    fn ctx() -> ExecCtx {
        ExecCtx::with_timeout("evt", "run", std::time::Duration::from_secs(5), 0)
    }

    #[tokio::test]
    async fn returns_roots_when_target_absent() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let policy = policy_of(tmp.path());
        let listing = list_dirs(&policy, None, 0).await.expect("列举");
        assert_eq!(listing.path, "");
        assert_eq!(listing.parent, None);
        assert_eq!(listing.roots.len(), 1);
        // 未定位时 dirs 必须为空（前端据此只渲染根列表）
        assert!(listing.dirs.is_empty());
        assert!(!listing.truncated);
        assert_eq!(listing.host, DEFAULT_HOST);
        assert_eq!(listing.separator, separator());
    }

    #[tokio::test]
    async fn lists_only_directories_not_files() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path();
        tokio::fs::create_dir(root.join("alpha"))
            .await
            .expect("mkdir");
        tokio::fs::create_dir(root.join("beta"))
            .await
            .expect("mkdir");
        // 放一个文件和一个「看起来像目录」的文件，验证被过滤
        tokio::fs::write(root.join("note.txt"), b"secret content")
            .await
            .expect("write");
        tokio::fs::write(root.join("gamma"), b"i am a file named like a dir")
            .await
            .expect("write");

        let policy = policy_of(root);
        let listing = list_dirs(&policy, Some(root), 0).await.expect("列举");
        let names: Vec<&str> = listing.dirs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta"], "只返回目录且按名排序");
        // 绝对不能把文件内容带出来（哪怕是文件名同形的那一个）
        let serialized = serde_json::to_string(&listing).expect("serialize");
        assert!(!serialized.contains("secret content"));
    }

    #[tokio::test]
    async fn marks_truncated_and_caps_at_limit() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path();
        for i in 0..5 {
            tokio::fs::create_dir(root.join(format!("d{i}")))
                .await
                .expect("mkdir");
        }
        let policy = policy_of(root);
        let listing = list_dirs(&policy, Some(root), 3).await.expect("列举");
        assert_eq!(listing.dirs.len(), 3);
        assert!(listing.truncated);

        // 恰好等于上限 → 不截断（避免前端把「正好 3 个」误显示成「还有更多」）
        let exact = list_dirs(&policy, Some(root), 5).await.expect("列举");
        assert_eq!(exact.dirs.len(), 5);
        assert!(!exact.truncated);
    }

    #[tokio::test]
    async fn max_above_server_limit_is_clamped() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let policy = policy_of(tmp.path());
        // 传入远大于 500 的值，仍不得突破服务端阈值（此处只验证不 panic 且能列举）
        let listing = list_dirs(&policy, Some(tmp.path()), usize::MAX)
            .await
            .expect("列举");
        assert!(listing.dirs.len() <= FS_MAX_DIRS);
    }

    #[tokio::test]
    async fn parent_is_none_at_root_and_set_below() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().join("root");
        let sub = root.join("child");
        tokio::fs::create_dir_all(&sub).await.expect("mkdir");
        let policy = policy_of(&root);

        let at_root = list_dirs(&policy, Some(&root), 0).await.expect("列举");
        assert_eq!(at_root.parent, None, "根层级绝不返回 ..");

        let below = list_dirs(&policy, Some(&sub), 0).await.expect("列举");
        let parent = below.parent.expect("应有上级");
        assert!(parent.ends_with("root"), "{parent}");
        assert!(!parent.contains(".."));
    }

    #[tokio::test]
    async fn rejects_outside_target() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().join("root");
        let outside = tmp.path().join("outside");
        tokio::fs::create_dir_all(&root).await.expect("mkdir");
        tokio::fs::create_dir_all(&outside).await.expect("mkdir");
        let policy = policy_of(&root);
        let err = list_dirs(&policy, Some(&outside), 0).await.unwrap_err();
        assert!(matches!(err, ExecError::PathDenied { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn missing_target_reports_not_found() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let policy = policy_of(tmp.path());
        let missing = tmp.path().join("ghost");
        let err = list_dirs(&policy, Some(&missing), 0).await.unwrap_err();
        assert!(matches!(err, ExecError::PathNotFound { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn executor_emits_contract_shaped_json() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().to_path_buf();
        tokio::fs::create_dir(root.join("only"))
            .await
            .expect("mkdir");
        let policy = Arc::new(Policy::new(vec![root.clone()], vec!["fs.list".into()]));
        let exec = ListDirsExecutor::new(Arc::clone(&policy), Some("device:abc".into()), 0);

        assert_eq!(exec.tool_name(), "fs.list");
        let out = exec
            .execute(
                &ctx(),
                &json!({ "path": root.to_string_lossy() }),
                &NoopSink,
            )
            .await
            .expect("执行");

        // 线格式字段名必须与前端 DirListing 逐个对得上（少一个前端就读到 undefined）
        for key in [
            "host",
            "path",
            "parent",
            "separator",
            "roots",
            "dirs",
            "truncated",
        ] {
            assert!(out.result.get(key).is_some(), "缺少字段 {key}");
        }
        assert_eq!(out.result["host"], "device:abc");
        assert_eq!(out.result["dirs"][0]["name"], "only");
        assert_eq!(out.source_trust, crate::executor::SourceTrust::Untrusted);
    }

    #[tokio::test]
    async fn executor_rejects_expired_ctx() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let policy = Arc::new(Policy::new(vec![tmp.path().to_path_buf()], vec![]));
        let exec = ListDirsExecutor::new(policy, None, 0);
        let expired = ExecCtx {
            deadline: std::time::Instant::now() - std::time::Duration::from_secs(1),
            ..ctx()
        };
        let err = exec
            .execute(&expired, &json!({}), &NoopSink)
            .await
            .unwrap_err();
        assert_eq!(err, ExecError::Timeout);
    }

    #[tokio::test]
    async fn target_that_is_a_file_is_rejected() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path();
        let file = root.join("a.txt");
        tokio::fs::write(&file, b"x").await.expect("write");
        let policy = policy_of(root);
        // 文件能过三闸（确实在白名单内），但 read_dir 会失败 → 必须报错而不是返回空列表，
        // 否则前端会把「选了个文件」显示成「空目录」
        let err = list_dirs(&policy, Some(&file), 0).await.unwrap_err();
        assert!(
            matches!(err, ExecError::Io(_) | ExecError::PathNotFound { .. }),
            "{err:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn skips_symlinks_even_when_they_point_inside() {
        // 软链一律跳过（不区分指向内外）：跟随软链等于允许「白名单内的一个链接」
        // 成为白名单外的跳板，而链目标随时可被替换。
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().join("root");
        let real = root.join("real");
        std::fs::create_dir_all(&real).expect("mkdir");
        std::os::unix::fs::symlink(&real, root.join("link")).expect("symlink");

        let policy = policy_of(&root);
        let listing = list_dirs(&policy, Some(&root), 0).await.expect("列举");
        let names: Vec<&str> = listing.dirs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["real"], "软链必须被跳过");
    }

    #[tokio::test]
    async fn empty_path_arg_means_unlocated() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let policy = Arc::new(Policy::new(vec![tmp.path().to_path_buf()], vec![]));
        let exec = ListDirsExecutor::new(policy, None, 0);
        let out = exec
            .execute(&ctx(), &json!({ "path": "" }), &NoopSink)
            .await
            .expect("执行");
        assert_eq!(out.result["path"], "");
        assert_eq!(out.result["roots"].as_array().map(|a| a.len()), Some(1));
    }
}
