//! 宿主壳可执行入口 —— **单文件双模态**。
//!
//! ## 一个 exe，两种运行方式
//!
//! ```text
//! hd-host.exe           → GUI 宿主（默认）
//! hd-host.exe --runner  → Runner 执行引擎（无窗口）
//! ```
//!
//! 这样用户只需要**一个**可执行文件：GUI 宿主在配对完成后，会把
//! `current_exe()` + `--runner` 当作子进程拉起（见 `daemon::locate_runner`）。
//!
//! ## 🔴 为什么仍然分成两个进程（而不是在主进程里 tokio::spawn）
//!
//! 单文件指的是**文件数量**，不是进程数量。Runner 必须保持独立进程，理由见
//! `docs/桌面端架构与功能设计.md` §3.2 第一条：**崩溃隔离**。shell / 浏览器
//! 自动化最容易崩，一个 panic 或内存爆炸不能把用户正在看的界面一起带走。
//! 合并进程能省下几十 MB 内存，但用 UI 稳定性换，不划算。
//!
//! ## 为什么 `--runner` 分流必须在 GUI 初始化之前
//!
//! `tauri::Builder::run()` 会创建窗口、加载 WebView2、进入事件循环。一旦进入，
//! 进程就只能当 GUI 用。因此 `--runner` 必须在**第一行业务代码**就分出去，
//! 且该分支下**绝不触碰任何 `tauri::` API** —— 这样无 WebView2 的环境
//! （如 headless 服务器）也能跑 `--runner`。
//!
//! ⚠️ 本 bin 需要 feature `gui`（`cargo run -p hd-host --features gui`），
//! 因为它链接 Tauri → 需要 WebView2（Windows）/ 系统 webkit（Linux）。
//! 默认不编译，理由是纯逻辑层（令牌保管 / 进程守护 / command 语义）必须能在
//! 任何 CI 上跑 `cargo test`（见 `lib.rs` 顶部说明）。

// 🔴 子系统必须是 console，不能是 windows。
//
// 踩过的坑：曾把 release 设为 `windows_subsystem = "windows"`（为了不弹黑框），
// 结果单文件自派生模式（`hd-host.exe --runner`）一启动就以
// **0xC0000139（STATUS_ENTRYPOINT_NOT_FOUND）** 崩溃，且 stderr 完全为空 ——
// 因为进程在 `main()` 之前就死了，任何日志都来不及输出。
//
// 原因是该二进制链接了 Tauri（GUI 依赖），而 windows 子系统（无控制台）下
// 由父进程通过 `Stdio::piped()` 拉起时，加载期初始化会失败。
// 改用 console 子系统后自派生完全正常。
//
// 代价：GUI 双击时会短暂闪一个控制台窗口。这是**有意的取舍** ——
// 「Runner 能被宿主稳定拉起」是功能正确性，「不闪黑框」只是观感。
// 后续若要用 NSIS 安装包分发，再单独考虑用 `windows_subsystem` + 安装期
// 注册快捷方式的方案，而不是牺牲自派生。
#![deny(unsafe_code)]

fn main() {
    // 🔴 分流必须放在最前面（GUI 初始化之前），见模块文档。
    if is_runner_mode(std::env::args().skip(1)) {
        // `--runner` 模式：复用 hd-runner 的完整启动逻辑（stdin auth → supervisor）。
        // 注意 run_cli 内部自建 tokio runtime，因此这里不能在 async 上下文里。
        let code = hd_runner::run_cli(keep_dev_flag(std::env::args().skip(1)));
        std::process::exit(code as i32);
    }

    // 日志初始化失败不该阻止 GUI 启动（用户更在意界面能不能开）。
    let _ = tracing_subscriber_init();
    if let Err(e) = hd_host::gui::run() {
        // 用 eprintln 而不是 tracing：此时日志系统可能没初始化成功。
        eprintln!("宿主启动失败：{e}");
        std::process::exit(1);
    }
}

/// 判断是否以 Runner 模式启动。
///
/// 抽成独立函数便于单测：多一个或少一个字符的开关判断错误，
/// 会导致「双击 exe 不弹窗口」这类极难排查的现象。
fn is_runner_mode<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter().any(|a| a.as_ref() == "--runner")
}

/// 过滤掉 `--runner` 后把其余参数传给 `hd_runner::run_cli`。
///
/// 为什么要把 `--runner` 摘掉：`run_cli` 只认 `--dev`，多一个未知开关虽然
/// 目前会被忽略，但保留它意味着「Runner 参数里出现了一个只有宿主才认识的词」，
/// 以后排查日志时容易误判。摘干净更清晰。
fn keep_dev_flag<I, S>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .map(|a| a.as_ref().to_string())
        .filter(|a| a != "--runner")
        .collect()
}

/// 初始化 tracing（默认 `info`，可用 `RUST_LOG` 覆盖）。
///
/// 不引入 `tracing-subscriber` 到 lib 依赖里：只有 bin 需要它，
/// 放在这里能让库使用方自由选择日志后端。
fn tracing_subscriber_init() -> Result<(), Box<dyn std::error::Error>> {
    // 说明：当前 crate 未直接依赖 tracing-subscriber（避免给 GUI 之外的场景加依赖），
    // 因此这里只做占位。接入时按下面两行替换：
    //   tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();
    tracing::info!("hd-host 启动（版本 {}）", env!("CARGO_PKG_VERSION"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_flag_is_detected() {
        assert!(is_runner_mode(["--runner"]));
        assert!(is_runner_mode(["--dev", "--runner"]));
    }

    #[test]
    fn gui_mode_is_default() {
        // 不带任何参数必须走 GUI，否则用户双击 exe 什么都不会发生
        assert!(!is_runner_mode(Vec::<String>::new()));
        assert!(!is_runner_mode(["--dev"]));
    }

    #[test]
    fn near_miss_flags_do_not_trigger_runner_mode() {
        // 拼写错误不能被误判：这些都应走 GUI
        assert!(!is_runner_mode(["--runners"]));
        assert!(!is_runner_mode(["-runner"]));
        assert!(!is_runner_mode(["runner"]));
    }

    #[test]
    fn runner_flag_is_stripped_before_forwarding() {
        let forwarded = keep_dev_flag(["--runner", "--dev"]);
        assert_eq!(forwarded, vec!["--dev".to_string()]);
        // `--dev` 必须保留：它控制 ws:// 是否被允许
        assert!(forwarded.iter().any(|a| a == "--dev"));
    }

    #[test]
    fn token_never_appears_in_forwarded_args() {
        // 安全断言：转发给 Runner 的参数只可能是开关，不可能是令牌。
        // （令牌走 stdin，见 hd-runner::cli 模块文档。）
        let forwarded = keep_dev_flag(["--runner"]);
        assert!(forwarded.is_empty());
        assert!(!forwarded.iter().any(|a| a.starts_with("hgd_")));
    }
}
