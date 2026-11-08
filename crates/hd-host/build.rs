//! 构建脚本：仅为 **gui feature** 生成 Windows 资源与 manifest。
//!
//! ## 🔴 这个文件为什么必须存在
//!
//! Tauri 在 Windows 上会调用 `TaskDialogIndirect`（任务对话框 API）。这个函数
//! **只存在于 Common-Controls v6**，而 v6 需要 exe 内嵌一份 manifest 才会被激活。
//! `tauri_build::build()` 正是负责把这份 manifest 编进二进制的那一步。
//!
//! 缺了它的症状极具误导性：
//!
//! ```text
//! hd-host.exe - 无法找到入口
//! 无法定位程序输入点 TaskDialogIndirect 于动态链接库 ...\hd-host.exe 上。
//! ```
//!
//! 表现为「一启动就弹错误框」，很容易被误判成缺 DLL、缺 WebView2、或杀软拦截，
//! 而真实原因是**没编 manifest**。
//!
//! ## 为什么用 `cfg(feature = "gui")` 而不是无条件执行
//!
//! `tauri_build::build()` 会检查 `tauri.conf.json` 与图标资源；纯逻辑构建
//! （`cargo test -p hd-host`，无 gui）不应被迫依赖这些资源，也不该为了跑单测
//! 而需要 GUI 工具链。因此这里按 feature 门控：只有真正要出 GUI 二进制时才跑。
//!
//! 注意：build script 本身**总会**被编译执行（Cargo 的机制），但门控后
//! 它在无 gui 时什么也不做，因此不影响纯逻辑层的构建速度与依赖。

fn main() {
    #[cfg(feature = "gui")]
    {
        tauri_build::build();
    }

    // 无 gui feature 时不生成任何 Windows 资源（纯逻辑构建无需 manifest）。
    #[cfg(not(feature = "gui"))]
    {
        // 显式空实现：让「为什么不做事」在代码里可见，而不是靠 absence 推断。
    }
}
