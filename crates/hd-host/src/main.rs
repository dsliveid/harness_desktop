//! 宿主壳可执行入口。
//!
//! ⚠️ 本 bin 需要 feature `gui`（`cargo run -p hd-host --features gui`），
//! 因为它链接 Tauri → 需要 WebView2（Windows）/ 系统 webkit（Linux）。
//! 默认不编译，理由是纯逻辑层（令牌保管 / 进程守护 / command 语义）必须能在
//! 任何 CI 上跑 `cargo test`（见 `lib.rs` 顶部说明）。
//!
//! 这里刻意不做任何业务逻辑：初始化全部在 `hd_host::gui::run` 里，
//! 与 `lib` 共享同一份 `HostState` 构造代码，避免 bin 与 lib 出现「两套初始化」。

// Windows 发布版不弹控制台黑框；debug 下保留控制台便于看日志。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![deny(unsafe_code)]

fn main() {
    // 日志初始化失败不该阻止 GUI 启动（用户更在意界面能不能开）。
    let _ = tracing_subscriber_init();
    if let Err(e) = hd_host::gui::run() {
        // 用 eprintln 而不是 tracing：此时日志系统可能没初始化成功。
        eprintln!("宿主启动失败：{e}");
        std::process::exit(1);
    }
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
