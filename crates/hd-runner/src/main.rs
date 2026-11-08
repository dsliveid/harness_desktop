//! `hd-runner` 独立可执行入口（薄壳）。
//!
//! 真正的启动逻辑在 [`hd_runner::run_cli`]（见 `src/cli.rs`），这样 `hd-host`
//! 的 `--runner` 自派生分支能复用完全相同的实现 —— 单文件交付模式的关键。
//!
//! ## 这个二进制什么时候还需要单独存在
//!
//! 单文件模式下宿主 `hd-host.exe --runner` 会自派生 Runner，桌面场景不需要本二进制。
//! 但它在两种场景下仍有价值，因此保留：
//! 1. **headless / 服务器节点**（`kind=cli`）：没有 WebView2 也能跑；
//! 2. **调试**：可单独 `--dev` 起来连本地服务端，不牵扯 GUI。
//!
//! ## 启动协议与安全约束
//!
//! 见 `src/cli.rs` 模块文档：token 只从 stdin 首行读，绝不进 argv/env。

#![cfg_attr(not(debug_assertions), windows_subsystem = "console")]
#![deny(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    // 注意：本二进制**保持 console 子系统**（不要改成 windows），
    // 因为它的主要用途是 headless/调试，需要能在终端看到 stderr 日志。
    // 反观 `hd-host` 在 release 下是 windows 子系统（不弹黑框），但它的
    // `--runner` 分支仍能把日志经 stderr 交给宿主 pipe 收集。
    ExitCode::from(hd_runner::run_cli(std::env::args().skip(1)))
}
