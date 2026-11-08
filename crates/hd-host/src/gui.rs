//! Tauri 2 GUI 薄壳：把 [`crate::commands`] 的纯逻辑函数包成 `#[tauri::command]`。
//!
//! ## 这一层为什么必须「薄」
//!
//! 每个 command 只做三件事：取 `State` → 调纯逻辑函数 → 把错误翻成字符串。
//! 任何业务判断都不许写在这里，原因有两个：
//! 1. `#[tauri::command]` 的函数**没法在无 GUI 环境单测**（要 `AppHandle`/`State` 注入），
//!    写在这里的逻辑等于永久失去测试覆盖；
//! 2. 「能力探测清单」（`SUPPORTED_COMMANDS`）与真实实现必须一一对应，
//!    逻辑散进 GUI 层后很容易出现「清单里有、实际没注册」的漂移。
//!
//! 🔴 本文件**永不**注册 `get_device_token` / `raw_ws_send` / `exec_shell`，
//! 原因见 `crate::commands` 模块文档。

use tauri::{Manager, State};

// 别名导入：下面定义的 `#[tauri::command] fn` 与纯逻辑函数同名，
// 直接 `use` 会冲突。用 `core_` 前缀反而让「这层只是转发」更明显。
use crate::boot_state::BootUiState;
use crate::commands::start_pairing_real as core_start_pairing_real;
use crate::commands::{
    device_status as core_device_status, get_workspace_roots as core_get_workspace_roots,
    runner_status as core_runner_status, set_workspace_roots as core_set_workspace_roots,
    start_pairing as core_start_pairing, DeviceStatusResponse, HostState, ListCommandsResponse,
    RunnerStatusResponse, StartPairingResponse,
};

/// 便于前端统一处理错误：Tauri 的 `Result<_, E>` 要求 `E: Serialize`，
/// 这里用 `String` 而不是裸枚举，避免把内部错误结构（可能含路径）变成前端 API 契约。
fn err_str<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// 🔴 能力探测锚点，永不删除（§14.6.3）。
#[tauri::command]
pub fn list_commands() -> ListCommandsResponse {
    crate::commands::list_commands()
}

#[tauri::command]
pub fn device_status(state: State<'_, HostState>) -> DeviceStatusResponse {
    core_device_status(&state)
}

#[tauri::command]
pub fn runner_status(state: State<'_, HostState>) -> RunnerStatusResponse {
    core_runner_status(&state)
}

/// 读取启动状态（前端首屏据此决定显示配对引导 / 正常 / 错误提示）。
///
/// 单独一个 command 而不是塞进 `device_status`：`device_status` 回答「设备是否在线」，
/// 这个回答「宿主启动流程走到哪一步」。两者生命周期不同（启动状态一次定型，
/// 设备状态持续变化），混在一起会让前端难以区分「还没开始」与「连不上」。
#[tauri::command]
pub fn get_boot_state(state: State<'_, HostState>) -> BootUiState {
    state.boot_state()
}

/// 真实配对（异步 command）：调服务端 → 落 token → 写档案 → 拉起 Runner。
///
/// 单独一个 command 而不替换上面的同步版：
/// 同步版被现有 5 个单测依赖（且它确实在做输入校验），
/// 真实网络动作必须是异步的（Tauri command 支持 async）。
#[tauri::command]
pub async fn pair_device(
    state: State<'_, HostState>,
    code: String,
    name: String,
    server_base_url: Option<String>,
) -> Result<StartPairingResponse, String> {
    let base = server_base_url.unwrap_or_else(crate::bootstrap::default_http_url);
    core_start_pairing_real(&state, &code, &name, &base)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_workspace_roots(state: State<'_, HostState>) -> Vec<String> {
    core_get_workspace_roots(&state)
}

#[tauri::command]
pub fn set_workspace_roots(
    state: State<'_, HostState>,
    roots: Vec<String>,
) -> Result<Vec<String>, String> {
    core_set_workspace_roots(&state, roots).map_err(err_str)
}

/// 配对入口。
///
/// ⚠️ 本壳**未**把它列进 `SUPPORTED_COMMANDS`：它目前只在本地做输入校验与排队，
/// 真正的配对需要 Runner 侧新增 IPC 命令（`hd-runner::ipc::IpcCommand` 现在没有）。
/// 因此这里虽然注册了（方便前端联调），但不对外宣称「支持」——`list_commands`
/// 是给前端做能力判断的，宣称了却做不到会让 UI 展示一个必然失败的功能。
#[tauri::command]
pub fn start_pairing(
    state: State<'_, HostState>,
    code: String,
    name: String,
) -> Result<StartPairingResponse, String> {
    core_start_pairing(&state, &code, &name).map_err(err_str)
}

/// 组装并运行 Tauri 应用。
///
/// 顺序有讲究：
/// 1. **single-instance 必须最先注册**。它依赖 `Setup` 钩子里的回调；
///    若在它之前注册了别的插件，第二个实例可能来不及退出就已经启动了 Runner，
///    出现两个 Runner 抢同一个设备令牌（服务端会判定 `device.replaced` 互踢）。
/// 2. 托盘在 `setup` 里创建：需要窗口已存在才能绑定菜单事件。
/// 3. `invoke_handler` 的注册顺序无关紧要，但**必须与 `SUPPORTED_COMMANDS` 完全一致**。
pub fn run() -> tauri::Result<()> {
    let vault = crate::vault::default_vault();
    let stats = std::sync::Arc::new(crate::daemon::RuntimeStats::default());
    let state = HostState::new(vault, stats);

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // 第二个实例的意图通常是「用户又点了一次图标」→ 把已有窗口提到前台，
            // 而不是再起一套 Runner。
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_focus();
            }
        }))
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            list_commands,
            device_status,
            runner_status,
            get_workspace_roots,
            set_workspace_roots,
            get_boot_state,
            pair_device,
            start_pairing
        ])
        .setup(|app| {
            // 托盘：关窗后进程继续驻留（桌面端常态）。
            // 图标缺失时不让整个启动失败 —— 托盘不是核心功能，UI 仍可用。
            if let Ok(tray) = tauri::tray::TrayIconBuilder::with_id("main-tray").build(app) {
                // Tauri 2 的 set_tooltip 收 `Option<S>`（`None` 表示清除悬浮提示）。
                let _ = tray.set_tooltip(Some("harness_desktop"));
            }

            // 🔴 启动编排：把「已配对」变成「Runner 在跑」。
            //
            // 为什么用 `tauri::async_runtime::spawn` 而不是 `block_on`：
            // 阻塞会让窗口首帧延后（用户看到几秒白屏），而启动 Runner 需要
            // 建连接、读密钥链，全是 IO。spawn 后立即返回，窗口先出来。
            //
            // 为什么失败也不 return Err：用户最在意「界面能不能开」。Runner 起不来
            // 应该是一个**可见的状态**（前端读 get_boot_state 显示原因），
            // 而不是「打不开」。
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let Some(state) = handle.try_state::<HostState>() else {
                    tracing::warn!("启动编排跳过：HostState 不可用");
                    return;
                };

                // 复用上一轮已 e2e 验证的 Bootstrap；Runner 可执行文件名按平台约定。
                let daemon = std::sync::Arc::new(crate::daemon::Daemon::new(
                    hd_runner::reconnect::ReconnectPolicy::default(),
                ));
                let boot = crate::bootstrap::Bootstrap::new(
                    state.vault_ref(),
                    daemon,
                    "hd-runner",
                    hd_protocol::CURRENT_PROTOCOL_VERSION,
                )
                // 🔴 生产必须注入档案：否则连非默认服务端时重启会连错地址
                // （回退到 default_ws_url 的 127.0.0.1:5611）。
                .with_profile_store(std::sync::Arc::new(
                    crate::profile::FileProfileStore::with_default_path(),
                ));

                let outcome = boot.ensure_running().await;
                if let Err(e) = &outcome {
                    tracing::warn!(error = %e, "启动编排失败");
                }
                let ui = crate::boot_state::plan_boot(outcome);
                tracing::info!(state = ?ui.state, detail = %ui.detail, "启动状态已确定");
                state.set_boot_state(ui);
            });

            Ok(())
        })
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    // 刻意不 `use super::*`：下面只比对纯常量，不需要 gui 模块的任何符号。
    // （导入 `super::*` 会被 clippy 判为 unused import。）

    /// 注册清单与能力清单必须一致：这条测试是「漂移防线」。
    ///
    /// 它只比对常量，不需要 GUI 环境，因此在 `--features gui` 下也能跑。
    #[test]
    fn registered_commands_match_supported_list() {
        // gui.rs 里实际 `generate_handler!` 注册的（不含 start_pairing，见其文档）。
        let registered = [
            "list_commands",
            "device_status",
            "runner_status",
            "get_workspace_roots",
            "set_workspace_roots",
            "get_boot_state",
            "pair_device",
        ];
        for name in registered {
            assert!(
                crate::commands::SUPPORTED_COMMANDS.contains(&name),
                "已注册但未声明支持的 command：{name}"
            );
        }
        for name in crate::commands::SUPPORTED_COMMANDS {
            assert!(
                registered.contains(&name),
                "宣称支持但未注册的 command：{name}（前端调用会抛异常）"
            );
        }
    }
}
