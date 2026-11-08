//! 配对链路端到端：真实 HTTP 假服务端 → PairingClient → Bootstrap 拉起 Runner。
//!
//! ## 为什么不 mock
//!
//! 这条链最容易出错的不是「逻辑分支」而是**协议细节**：请求字段名对不对、
//! 响应字段名对不对、`ws_path` 拼出来的地址能不能用。mock 掉 HTTP 就什么都验不到。
//! 所以这里起一个真实的 TCP 服务端，返回真实形状的 JSON。
//!
//! ## 覆盖的场景
//!
//! 1. 成功配对 → 拿到 token → Runner 被拉起（用 `src/bin/fake_runner.rs` 当子进程）
//! 2. 服务端拒绝（配对码无效）→ 错误码原样透传，且**不拉起 Runner**
//! 3. 网络不可达 → 报 Http 错误而不是 panic

use std::sync::Arc;

use hd_host::bootstrap::{Bootstrap, BootstrapOutcome};
use hd_host::daemon::{Daemon, RunnerLaunch};
use hd_host::pairing::{PairingClient, PairingError};
use hd_host::vault::{DeviceToken, MemoryVault, TokenVault};
use hd_runner::reconnect::ReconnectPolicy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// 一次性假 HTTP 服务端：接受一个连接，回固定响应，然后退出。
///
/// 返回 `(base_url, JoinHandle)`。刻意只服务一个连接——本测试每个用例只发一次请求。
async fn spawn_fake_server(status_line: &'static str, body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            // 必须先把请求读完，否则客户端可能收到 RST 而不是响应。
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;

            let resp = format!(
                "HTTP/1.1 {status_line}\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        }
    });

    format!("http://{addr}")
}

/// 定位 fake_runner 可执行文件（与 daemon_e2e.rs 做法一致）。
fn fake_runner_exe() -> std::path::PathBuf {
    let name = format!("fake_runner{}", hd_host::daemon::exe_suffix());
    // 测试产物在 target/<profile>/deps 的上一级
    let mut dir = std::env::current_exe().expect("current_exe");
    dir.pop(); // 去掉测试二进制名
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join(name)
}

#[tokio::test]
async fn pair_then_runner_is_spawned() {
    let base = spawn_fake_server(
        "201 Created",
        r#"{"device_id":"dev_e2e_001","device_token":"hgd_e2e_token_xyz","ws_path":"/api/v1/devices/ws","protocol_version":1}"#,
    )
    .await;

    let client = PairingClient::new(base);
    let paired = client
        .pair("123456", "测试工作站", "windows-amd64", "0.1.0")
        .await
        .expect("配对应成功");

    // 响应字段被正确解析
    assert_eq!(paired.device_id, "dev_e2e_001");
    assert_eq!(paired.protocol_version, 1);
    // ws_url 必须由 ws_path 正确拼出（http → ws）
    assert!(
        paired.ws_url.starts_with("ws://") && paired.ws_url.ends_with("/api/v1/devices/ws"),
        "ws_url 不符合预期：{}",
        paired.ws_url
    );

    // 用真 fake_runner 当子进程，验证 Bootstrap 真的把它拉起来了
    let vault: Arc<dyn TokenVault> = Arc::new(MemoryVault::new());
    let daemon = Arc::new(Daemon::new(ReconnectPolicy::default()));
    let boot = Bootstrap::new(Arc::clone(&vault), Arc::clone(&daemon), "fake_runner", 1);

    let exe = fake_runner_exe();
    assert!(exe.is_file(), "fake_runner 未构建：{}", exe.display());

    // 直接验证 on_paired：先落 token 再拉起
    let ws_url = paired.ws_url.clone();
    let wrapped = hd_host::pairing::PairedDevice {
        device_id: paired.device_id.clone(),
        token: DeviceToken::new("hgd_e2e_token_xyz".into()),
        ws_url,
        protocol_version: 1,
        server_base_url: "http://127.0.0.1:1".into(),
    };
    // 用显式 runner 路径，避免依赖 exe_name 搜索
    let boot = boot.with_explicit_runner(Some(exe));
    boot.on_paired(wrapped).await.expect("on_paired 应成功");

    // token 必须已落库（重启后不必重新配对）
    assert!(
        matches!(vault.get(), Ok(Some(_))),
        "配对后 token 必须写入 vault"
    );
    assert!(daemon.is_running().await, "配对后 Runner 必须处于运行态");

    let _ = daemon.shutdown().await;
}

#[tokio::test]
async fn rejected_pairing_propagates_error_code() {
    let base = spawn_fake_server(
        "401 Unauthorized",
        r#"{"code":"device.pair_code_invalid","message":"配对码不存在或已过期"}"#,
    )
    .await;

    let client = PairingClient::new(base);
    let err = client
        .pair("000000", "x", "windows-amd64", "0.1.0")
        .await
        .expect_err("应被拒绝");

    match err {
        PairingError::Rejected { code, message } => {
            // 错误码必须原样透传：UI 据此区分「码错了」与「设备域关了」
            assert_eq!(code, "device.pair_code_invalid");
            assert!(!message.is_empty());
        }
        other => panic!("期望 Rejected，实际 {other:?}"),
    }
}

#[tokio::test]
async fn unreachable_server_reports_http_error() {
    // 端口 1 必然连不上（无需真起服务）
    let client = PairingClient::new("http://127.0.0.1:1");
    let err = client
        .pair("123456", "x", "windows-amd64", "0.1.0")
        .await
        .expect_err("应失败");
    assert!(
        matches!(err, PairingError::Http(_)),
        "网络失败必须归为 Http 而非 BadResponse，实际 {err:?}"
    );
}

#[tokio::test]
async fn ensure_running_without_token_needs_pairing() {
    let vault: Arc<dyn TokenVault> = Arc::new(MemoryVault::new());
    let daemon = Arc::new(Daemon::new(ReconnectPolicy::default()));
    let boot = Bootstrap::new(vault, daemon, "fake_runner", 1);

    assert_eq!(
        boot.ensure_running().await.expect("不应报错"),
        BootstrapOutcome::NeedsPairing
    );
}

#[tokio::test]
async fn ensure_running_after_pairing_restarts_runner() {
    // 模拟「上次已配对」：vault 里有 token，runner 存在 → 应能自动拉起
    let vault: Arc<dyn TokenVault> = Arc::new(MemoryVault::new());
    vault
        .set(&DeviceToken::new("hgd_persisted".into()))
        .expect("写 vault");

    let exe = fake_runner_exe();
    assert!(exe.is_file(), "fake_runner 未构建");

    let daemon = Arc::new(Daemon::new(ReconnectPolicy::default()));
    let boot = Bootstrap::new(Arc::clone(&vault), Arc::clone(&daemon), "fake_runner", 1)
        .with_explicit_runner(Some(exe));

    let outcome = boot.ensure_running().await.expect("应能自动拉起");
    assert!(
        matches!(outcome, BootstrapOutcome::Started { .. }),
        "期望 Started，实际 {outcome:?}"
    );
    assert!(daemon.is_running().await);

    let _ = daemon.shutdown().await;
}

#[tokio::test]
async fn ensure_running_is_idempotent() {
    // 重复调用不应拉起第二个子进程：同一设备两条 WS 连接会被服务端 replaced
    let vault: Arc<dyn TokenVault> = Arc::new(MemoryVault::new());
    vault.set(&DeviceToken::new("hgd_x".into())).expect("写");

    let exe = fake_runner_exe();
    let daemon = Arc::new(Daemon::new(ReconnectPolicy::default()));
    let boot = Bootstrap::new(Arc::clone(&vault), Arc::clone(&daemon), "fake_runner", 1)
        .with_explicit_runner(Some(exe));

    boot.ensure_running().await.expect("第一次");
    // 第二次应直接返回 Started（不重复 spawn）
    let second = boot.ensure_running().await.expect("第二次");
    assert!(matches!(second, BootstrapOutcome::Started { .. }));
    assert!(daemon.is_running().await);

    let _ = daemon.shutdown().await;
}

/// 保证 `RunnerLaunch` 在本测试里可用（避免未使用导入警告）。
#[allow(dead_code)]
fn _assert_launch_type(_l: RunnerLaunch) {}
