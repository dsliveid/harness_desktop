//! 路径判定的公共原语（guard 与 fs 共用，避免两处各写一套判定而漂移）。
//!
//! 为什么单独抽出来：三闸判定与 `fs.list` 的「到根了就不再往上」是同一套路径语义，
//! 一旦复制两份，改一处忘另一处就会出现「list 认为在根内、guard 认为越界」的矛盾。

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

/// 路径比较是否要忽略大小写：仅 Windows。
///
/// 原因：Windows 的 NTFS/FAT 默认大小写不敏感，`C:\Work` 与 `C:\work` 是同一个目录。
/// 若用字节级比较，用户从别处粘来的大小写不一致路径会被误判「越界」——
/// 这类误拒绝会把人逼去「临时把根配大一点」，反而扩大攻击面。
pub const CASE_INSENSITIVE: bool = cfg!(windows);

/// 判断**原始输入**是否含 `..` 段。
///
/// 必须在 `clean` 之前判断：`a/../../../etc` 经 clean 会被抹平成 `../etc` 甚至合法路径，
/// 事后就再也看不出穿越意图了。服务端 `harness_go/internal/api/fs_handler.go:108-119`
/// (`fsContainsDotDot`) 同理，且**同时按 `/` 与 `\` 切分**：
/// 攻击者不会因为当前平台用哪种分隔符就改用另一种。
pub(crate) fn has_dotdot_segment(raw: &Path) -> bool {
    let s = raw.to_string_lossy();
    s.split(['/', '\\']).any(|seg| seg == "..")
}

/// 单个路径组件的比较键（Windows 下统一小写）。
fn component_key(c: &OsStr) -> Cow<'_, str> {
    let s = c.to_string_lossy();
    if CASE_INSENSITIVE {
        match s {
            Cow::Borrowed(b) => Cow::Owned(b.to_lowercase()),
            Cow::Owned(o) => Cow::Owned(o.to_lowercase()),
        }
    } else {
        s
    }
}

/// 把路径展开成「可逐段比对的键序列」。
///
/// 用组件序列而不是字符串前缀，是为了让 `C:\work-evil` 不会因为共享 `C:\work` 这个
/// 字符串前缀被误判为在 `C:\work` 之内（用户简报里点名的坑）。
fn component_keys(p: &Path) -> Vec<String> {
    p.components()
        .map(|c| match c {
            Component::Prefix(pre) => format!("prefix:{}", component_key(pre.as_os_str())),
            Component::RootDir => "root".to_string(),
            Component::CurDir => ".".to_string(),
            Component::ParentDir => "..".to_string(),
            Component::Normal(n) => component_key(n).into_owned(),
        })
        .collect()
}

/// `child` 是否落在 `parent` 之内（含恰为 `parent` 本身）。
///
/// 前提：两者都应是**canonicalize 之后**的绝对路径。未归一的一方带不带 `\\?\` 前缀、
/// 大小写是否一致都会影响比对结果，所以调用方必须先归一。
pub(crate) fn is_within(parent: &Path, child: &Path) -> bool {
    let pk = component_keys(parent);
    let ck = component_keys(child);
    if pk.is_empty() || ck.len() < pk.len() {
        return false;
    }
    pk.iter().zip(ck.iter()).all(|(a, b)| a == b)
}

/// 归一一个已存在的路径；失败返回 `None`（不存在 / 权限不足）。
///
/// `canonicalize` 会**解开整条父链上的符号链接与 Windows 重解析点**，
/// 因此「软链指向白名单外」这种情况在归一结果里就已经变成「越界」，由 `is_within` 拒绝。
pub(crate) fn canonical(p: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(p).ok()
}

/// 把 canonical 路径转回**用户看得懂的展示形态**。
///
/// Windows 上 `canonicalize` 会加上 `\\?\` 扩展长度前缀，甚至把 UNC 变成 `\\?\UNC\srv\share`。
/// 这个前缀只对人类是噪音，但与服务端返回的路径串不相等 → 前端拿来做面包屑/回填会错。
/// 判定与比较一律用 canonical 形态，只有**要输出给外部**的时候才过这个函数。
pub(crate) fn display_path(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    p.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotdot_segment_detected_on_both_separators() {
        assert!(has_dotdot_segment(Path::new("../etc")));
        assert!(has_dotdot_segment(Path::new(r"a\..\b")));
        assert!(has_dotdot_segment(Path::new("a/b/..")));
        // 只是名字里带两个点，不算穿越
        assert!(!has_dotdot_segment(Path::new("a/..b/c")));
        assert!(!has_dotdot_segment(Path::new("a/b.txt")));
    }

    #[test]
    fn is_within_is_component_wise_not_string_prefix() {
        let root = Path::new("/work");
        assert!(is_within(root, Path::new("/work")));
        assert!(is_within(root, Path::new("/work/a/b")));
        // 字符串前缀相同但组件不同 → 必须拒绝
        assert!(!is_within(root, Path::new("/work-evil")));
        assert!(!is_within(root, Path::new("/work2/a")));
        // 父级方向 → 拒绝
        assert!(!is_within(root, Path::new("/")));
    }

    #[test]
    fn display_path_strips_verbatim_prefix() {
        assert_eq!(
            display_path(Path::new(r"\\?\C:\work\a")),
            PathBuf::from(r"C:\work\a")
        );
        assert_eq!(
            display_path(Path::new(r"\\?\UNC\srv\share\a")),
            PathBuf::from(r"\\srv\share\a")
        );
        assert_eq!(display_path(Path::new("/tmp/a")), PathBuf::from("/tmp/a"));
    }
}
