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
