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
        // 🔴 `app_manifest` 声明**不是可选优化，而是远程页面能否调用自定义命令的开关**。
        //
        // Tauri 2.12 的判定（`tauri/src/webview/mod.rs`）：
        //
        // ```ignore
        // // Check ACL on plugin commands, when the app defined its ACL manifest,
        // // or when the request comes from a non-local (remote) origin.
        // if (plugin_command.is_some() || has_app_acl_manifest || !is_local)
        //   && invoke.acl.is_none()
        // {
        //   return Err(reject(format!("Command {} not allowed by ACL", request.cmd)));
        // }
        // ```
        //
        // 也就是说：只要请求来自**远程 origin**（我们的服务端 Web UI 正是
        // `http://<server>:5611`，对 WebView 来说就是远程），自定义 app 命令就
        // 必须有 ACL 条目，否则一律 `not allowed by ACL`。
        //
        // 缺了本声明的真实症状（本轮修的用户反馈）：
        // 「桌面端进入主界面后，点击浮动的设置按钮没有反应」——
        // `layout/HostSettingsFab.tsx` 调 `invoke('open_baseline')` 失败 →
        // `openHostSettings()` 返回 `ok:false` → 浮标按设计**自我隐藏** →
        // 用户看到的就是一个点了毫无反应的死钮，壳侧日志只有一条 ACL 拒绝。
        //
        // ## ⚠️ 一旦声明，`has_app_acl_manifest` 变 true，**连本地基线页**也受管
        //
        // 这是最容易踩的坑：`(plugin_command.is_some() || has_app_acl_manifest || !is_local)`
        // 里的 `has_app_acl_manifest` 一旦为真，**本地 origin 的自定义命令同样要求
        // ACL 条目**。所以这里必须列出 `SUPPORTED_COMMANDS` 全部命令（而不是只列
        // open_baseline），否则基线页的配对/解绑/登录会集体变成「not allowed by ACL」——
        // 修好一个浮标，弄坏整页功能。
        //
        // 远程页面能拿到哪些命令**不由此处决定**，而由 capability 的权限列表决定，
        // 见 `capabilities/main.json`（local 全量 + remote 仅返回设置）。
        //
        // ⚠️ 本列表必须与 `commands::SUPPORTED_COMMANDS` 一致：build.rs 是独立编译
        // 单元，无法 `use crate::...`，只能各写一份。这个「双份真源」由
        // `tests/config_guard.rs::app_manifest_covers_all_supported_commands`
        // 守住 —— 漏一条就编译期 ACL 拒绝一条，且症状极隐蔽。
        const APP_COMMANDS: &[&str] = &[
            "list_commands",
            "device_status",
            "runner_status",
            "get_workspace_roots",
            "set_workspace_roots",
            "get_boot_state",
            "pair_device",
            "unpair_device",
            "sign_out",
            "sign_in",
            "check_update",
            "open_settings",
            "open_logs",
            "open_web_ui",
            "open_baseline",
            "set_server_base_url",
        ];
        let attributes = tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(APP_COMMANDS));
        tauri_build::try_build(attributes)
            .expect("tauri-build 失败（检查 tauri.conf.json / icons / capabilities）");
    }

    // 无 gui feature 时不生成任何 Windows 资源（纯逻辑构建无需 manifest）。
    #[cfg(not(feature = "gui"))]
    {
        // 显式空实现：让「为什么不做事」在代码里可见，而不是靠 absence 推断。
    }
}
