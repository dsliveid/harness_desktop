//! 壳配置与前端产物的守卫测试（纯文件校验，不需要 gui feature）。
//!
//! ## 为什么需要这个文件
//!
//! `withGlobalTauri` 缺失曾造成一次**极难定位**的真实事故：壳正常启动、托盘正常、
//! 页面正常渲染，但整屏本机能力（执行引擎状态、设备绑定/解绑）全部显示
//! 「当前为浏览器端（未运行在桌面客户端内）」并置灰，用户完全无法继续下一步。
//!
//! 之所以难查，是因为**没有任何一处报错**：
//!   - Rust 侧编译通过（`withGlobalTauri` 是可选字段，缺省即 false）；
//!   - 前端逻辑正确（拿不到 `__TAURI__` 时降级为「浏览器端」本就是设计行为）；
//!   - 结论「运行在浏览器里」看起来完全合理，于是排查方向被带偏到 CSP、端口、构建产物上。
//!
//! 这条链上唯一的破口就是那个配置项，因此用一条测试把它钉住：
//! **它一旦丢失，`cargo test -p hd-host` 立刻失败，并在失败信息里说明后果。**
//!
//! 第二个守卫针对「产物滞后」：`crates/hd-host/ui` 是 `web/dist-baseline` 的同步副本，
//! 改了前端却忘记 `npm run build` + `sync-web.ps1`，壳内跑的就还是旧包 ——
//! 修复看起来「没生效」，实际是根本没被打进二进制。断言关键标记存在即可拦住这种情况。

use std::path::PathBuf;

/// crate 根目录（`cargo test` 的 CWD 不保证是 crate 根，必须用编译期常量）
fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_to_string(rel: &str) -> String {
    let path = crate_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "读取 {} 失败（{}）：该文件是桌面壳的必需构件，不能缺失",
            path.display(),
            e
        )
    })
}

/// 取出 tauri.conf.json 并解析成 JSON，供后续断言使用。
fn tauri_conf() -> serde_json::Value {
    let raw = read_to_string("tauri.conf.json");
    serde_json::from_str(&raw).unwrap_or_else(|e| {
        panic!(
            "tauri.conf.json 不是合法 JSON（{e}）。桌面壳启动时会直接失败，必须先修好格式"
        )
    })
}

/// 🔴 核心守卫：`app.withGlobalTauri` 必须为 true。
#[test]
fn global_tauri_is_enabled() {
    let conf = tauri_conf();
    let value = conf
        .get("app")
        .and_then(|app| app.get("withGlobalTauri"))
        .and_then(|v| v.as_bool());

    assert_eq!(
        value,
        Some(true),
        "🔴 app.withGlobalTauri 必须显式为 true（当前为 {:?}）。\n\
         缺了它，Tauri 2 不会注入 window.__TAURI__，前端 tauriBridge 会把壳内页面\n\
         误判成「浏览器端」，导致执行引擎状态与设备绑定全部置灰、用户卡在首页。\n\
         这个字段缺省值是 false（见 tauri-utils config.rs 的 #[serde(default)]），\n\
         所以「写了才生效」，不能靠省略。",
        value
    );
}

/// CSP 必须放行 IPC 的两个端点，否则桥接层即使拿到 invoke 也发不出请求。
#[test]
fn csp_allows_ipc_endpoints() {
    let conf = tauri_conf();
    let security = conf
        .get("app")
        .and_then(|app| app.get("security"))
        .expect("app.security 缺失：CSP 是桌面壳的安全边界，不允许整块省略");

    // prod 与 dev 两份 CSP 都可能被用到（devCsp 覆盖 csp），逐个检查。
    for key in ["csp", "devCsp"] {
        let Some(csp) = security.get(key).and_then(|v| v.as_str()) else {
            continue; // devCsp 可以缺省，缺省时回落到 csp
        };
        let connect_ok = csp.contains("ipc:") && csp.contains("http://ipc.localhost");
        assert!(
            connect_ok,
            "🔴 {key} 的 connect-src 必须同时包含 `ipc:` 与 `http://ipc.localhost`。\n\
             否则 WebView 会以 CSP 违规拦截 IPC 请求，症状同样是「本机能力不可用」，\n\
             但控制台会看到拒绝记录 —— 与 withGlobalTauri 缺失是两种不同的病，别混。\n\
             当前值：{csp}"
        );
    }
}

/// 🔴 双份真源守卫：`build.rs` 的 APP_COMMANDS 必须覆盖 `SUPPORTED_COMMANDS` 全部命令。
///
/// ## 为什么必须有这条测试
///
/// `build.rs` 是**独立编译单元**，无法 `use crate::commands::SUPPORTED_COMMANDS`，
/// 只能把命令名再抄一遍喂给 `AppManifest`。而一旦声明了 AppManifest，
/// `has_app_acl_manifest` 就为真，Tauri 会对**每一个**自定义命令做 ACL 校验：
///
/// ```ignore
/// if (plugin_command.is_some() || has_app_acl_manifest || !is_local) && invoke.acl.is_none()
/// ```
///
/// 漏抄一条的后果是那条命令**永久 ACL 拒绝**，而且症状极具误导性：命令明明注册了、
/// 能力探测 `list_commands` 也报告支持，点下去却失败。上一轮「浮动设置按钮点了没反应」
/// 就是这条链（当时是根本没声明 manifest，远程 origin 一律被拒）。
///
/// 所以这里把「两份清单必须一致」变成编译期即可发现的失败。
#[test]
fn app_manifest_covers_all_supported_commands() {
    // build.rs 里的 APP_COMMANDS 列表（纯文本解析：它不可被 use，只能读文件）。
    let build_rs = read_to_string("build.rs");
    let list_start = build_rs
        .find("const APP_COMMANDS: &[&str] = &[")
        .expect("build.rs 里找不到 APP_COMMANDS 常量：AppManifest 声明被删了？");
    let list_end = build_rs[list_start..]
        .find("];")
        .map(|i| list_start + i)
        .expect("build.rs 的 APP_COMMANDS 数组没有闭合的 `];`");
    let list_body = &build_rs[list_start..list_end];

    let declared: Vec<String> = list_body
        .split('"')
        .skip(1)
        .step_by(2)
        .map(|s| s.to_string())
        .collect();
    assert!(
        !declared.is_empty(),
        "build.rs 的 APP_COMMANDS 解析为空，正则/格式已变更，请同步本测试"
    );

    // SUPPORTED_COMMANDS 的取值从这里读，避免在测试里再抄一遍。
    let commands_rs = read_to_string("src/commands.rs");
    let start = commands_rs
        .find("pub const SUPPORTED_COMMANDS")
        .expect("commands.rs 里找不到 SUPPORTED_COMMANDS");
    let end = commands_rs[start..]
        .find("];")
        .map(|i| start + i)
        .expect("SUPPORTED_COMMANDS 数组没有闭合的 `];`");
    let supported: Vec<String> = commands_rs[start..end]
        .split('"')
        .skip(1)
        .step_by(2)
        // 数组长度在类型签名里（`[&str; 16]`），不含引号，故 split 出来的都是命令名
        .map(|s| s.to_string())
        .collect();

    for cmd in &supported {
        assert!(
            declared.contains(cmd),
            "🔴 命令 `{cmd}` 在 SUPPORTED_COMMANDS 里，但 build.rs 的 APP_COMMANDS 没有声明它。\n\
             声明了 AppManifest 之后，Tauri 对每个自定义命令都做 ACL 校验，\n\
             未声明的命令会被永久拒绝（`Command {cmd} not allowed by ACL`），\n\
             且能力探测仍会报告「支持」，症状是「点了没反应」。\n\
             修复：把 `{cmd}` 加入 crates/hd-host/build.rs 的 APP_COMMANDS，\n\
             并同步在 capabilities/main.json 里加上 allow-{} 权限。",
            cmd.replace('_', "-")
        );
    }

    // 反向检查：APP_COMMANDS 里也不该有幽灵命令（写错的拼写会静默失效）。
    for cmd in &declared {
        assert!(
            supported.contains(cmd),
            "🔴 build.rs 声明了 `{cmd}`，但它不在 SUPPORTED_COMMANDS 里（拼写错误或已删除）。\n\
             这本身不致故障，但会让权限文件生成一份永不使用的条目，掩盖真实漏项。"
        );
    }
}

/// 🔴 远程页面只能拿到「返回设置」这一个命令（最小权限）。
///
/// 远程内容是服务端下发、可被热更替换的，一旦给它配对/解绑/改地址的能力，
/// 一个被篡改的远程包就能把客户端指向攻击者的服务器。这条测试把该边界钉死。
#[test]
fn remote_capability_is_minimal() {
    let raw = read_to_string("capabilities/main-remote.json");
    let cap: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("capabilities/main-remote.json 不是合法 JSON：{e}"));

    let perms: Vec<String> = cap
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    assert_eq!(
        perms,
        vec!["allow-open-baseline".to_string()],
        "🔴 远程 capability 只能有 allow-open-baseline 一项权限，当前为 {perms:?}。\n\
         服务端 Web UI 内的浮标只需要「返回本地设置页」；给它更多权限等于把\n\
         配对/解绑/改服务端地址这些副作用动作暴露给可被热更替换的远程代码。"
    );

    // local 必须显式为 false：这是「只对远程页面生效」的开关。
    assert_eq!(
        cap.get("local").and_then(|v| v.as_bool()),
        Some(false),
        "🔴 capabilities/main-remote.json 必须 `local: false`，否则这份「最小权限」\n\
         会同时作用于本地基线页，把配对/解绑等全部功能一并锁死。"
    );

    // remote.urls 必须存在：没有它，远程 origin 根本匹配不到这个 capability。
    assert!(
        cap.get("remote")
            .and_then(|v| v.get("urls"))
            .and_then(|v| v.as_array())
            .is_some(),
        "🔴 capabilities/main-remote.json 缺少 remote.urls：远程页面将匹配不到任何\n\
         capability，浮标又会退化成「点了没反应」。"
    );
}

/// 内置基线产物：**存在则校验不滞后，不存在则跳过**。
///
/// ## 为什么必须是「条件断言」而不是硬断言
///
/// `web/dist-baseline/` 与 `crates/hd-host/ui/*` 都是 .gitignore 排除的**构建产物**
/// （见根 .gitignore 第 2、3 节），干净 clone 后只有占位 `ui/index.html`。
/// 若在这里硬断言 `ui/main.js` 存在，CI 上的 `cargo test -p hd-host` 会直接失败 ——
/// 守卫测试反倒成了阻塞项。所以：**产物在就验它是否最新，不在就认作干净 clone。**
#[test]
fn baseline_artifact_is_not_stale_when_present() {
    let ui_dir = crate_root().join("ui");
    assert!(
        ui_dir.join("index.html").exists(),
        "{} 缺少 index.html：这是入库的占位入口，Tauri 的 generate_context!() 在编译期\n\
         就要读取 frontendDist，缺失会直接编译失败。",
        ui_dir.display()
    );

    let main_js_path = ui_dir.join("main.js");
    if !main_js_path.exists() {
        // 干净 clone：还没跑过 build + sync，属正常状态，无需校验。
        eprintln!(
            "[config_guard] ui/main.js 不存在（干净 clone 未构建），跳过产物滞后校验。\n\
             要跑本地形态校验：cd web; npm run build; powershell -File scripts/sync-web.ps1"
        );
        return;
    }

    let main_js = read_to_string("ui/main.js");
    assert!(
        main_js.contains("__TAURI_INTERNALS__"),
        "🔴 crates/hd-host/ui/main.js 中找不到 `__TAURI_INTERNALS__`，说明前端产物已滞后。\n\
         修复前端的桥接层后必须重新打包并同步：\n\
         \x20  cd web; npm run build\n\
         \x20  powershell -File scripts/sync-web.ps1\n\
         否则壳内运行的仍是旧包，改动看起来「完全没生效」。"
    );
}
