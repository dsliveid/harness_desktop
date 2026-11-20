//! 默认可浏览的目录范围（端侧「整机」口径的唯一事实源）。
//!
//! ## 为什么需要它（2026-11 缺陷根因）
//!
//! 改造前 Runner 的初始白名单来自 `std::env::current_dir()`。Windows 双击启动时
//! CWD ≈ exe 所在目录（`D:\...\harness_desktop`），于是：
//!
//! ```text
//! 用户在 web 的目录选择器里选设备宿主
//!   → fs.list 只列得出 exe 目录这一层的子目录
//!   → 面包屑想上跳到 F:\WorkSpace 时 parent_within_roots 返回 None（已在根）
//!   → 服务端原样透出 fs.path_denied「该目录不在允许的范围内」
//! ```
//!
//! 而服务端（`internal/api/fs_handler.go::fsAllowedRoots` + `cmd/harness-go/fsroots_*.go`）
//! 的默认口径一直是**整机**：Windows 各逻辑盘符、POSIX `/`，只有显式配置了
//! `workspace.fs_roots` 才收窄。两端口径不同源，同一份 `fs.list` 契约给出完全不同的
//! 可浏览范围 —— 这就是本模块要消灭的漂移。
//!
//! ## 安全口径未放松
//!
//! 这里只决定**默认白名单的内容**，不改变任何判定逻辑：
//! [`super::guard::Policy::check_path`] 的三闸（拒 `..` / 必须绝对路径 / 归属校验）
//! 与「白名单为空 → 一律拒绝」全部照旧。用户仍可用 `set_workspace_roots` 主动收窄。
//!
//! ## 为什么不用 `unsafe` 调 `GetLogicalDrives`
//!
//! `hd-core` 顶部是 `#![deny(unsafe_code)]`。逐个 `'A'..='Z'` 拼 `X:\` 再 `is_dir()`
//! 与 Go 侧「GetLogicalDrives 取位图 → `os.Stat` 过滤未就绪盘」的结果等价
//! （空光驱 / 断连网络盘 Stat 失败，天然被过滤），且零 `unsafe`、零新增依赖。
//! 代价是 26 次 stat，发生在启动期与设置读取时，可忽略。

use std::path::PathBuf;

/// 整机文件系统的根列表（**fail-closed**：枚举失败返回空，由调用方决定兜底）。
///
/// - Windows：遍历 `A:`–`Z:`，只保留 `is_dir()` 为真的盘符（顺序天然 A→Z）；
/// - POSIX：只返回 `/`（若 `/` 不是目录则返回空，理论上不可能）。
///
/// 返回的是**未 canonicalize** 的形态（`C:\`、`/`）：归一交给
/// [`super::guard::Policy::new`]，避免两处各写一套归一逻辑而漂移。
pub fn default_roots() -> Vec<PathBuf> {
    let candidates: Vec<PathBuf> = if cfg!(windows) {
        // 位图式枚举的零 unsafe 等价实现：26 个盘符逐个探测。
        ('A'..='Z')
            .map(|c| PathBuf::from(format!("{c}:\\")))
            .collect()
    } else {
        vec![PathBuf::from("/")]
    };

    candidates.into_iter().filter(|p| p.is_dir()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_a_non_empty_list_on_any_supported_host() {
        // 空列表意味着「拒绝一切」（Policy::check_path 的 fail-closed 分支），
        // 那不是「默认整机」该有的形态。
        let roots = default_roots();
        assert!(!roots.is_empty(), "默认根列表不该为空");
    }

    #[test]
    fn every_default_root_actually_exists_as_a_directory() {
        // 目录选择器里出现一个「点进去就报错」的假根，比少列几个根更糟。
        for r in default_roots() {
            assert!(r.is_dir(), "默认根必须是已存在的目录：{r:?}");
            // 未归一形态不该带 Windows 扩展长度前缀（那是 canonicalize 的产物）。
            assert!(
                !r.to_string_lossy().starts_with(r"\\?\"),
                "默认根不该带扩展前缀：{r:?}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_roots_are_drive_letter_forms() {
        for r in default_roots() {
            let s = r.to_string_lossy();
            assert_eq!(s.len(), 3, "盘符根形态应为 `X:\\`，实际：{s}");
            assert!(s.ends_with('\\'), "盘符根必须以分隔符结尾，实际：{s}");
            assert!(
                s.as_bytes()[0].is_ascii_alphabetic(),
                "盘符首字符必须是字母：{s}"
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn posix_roots_is_the_single_slash() {
        assert_eq!(default_roots(), vec![PathBuf::from("/")]);
    }
}
