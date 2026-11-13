//! P2 验收：对假服务端跑通「握手 → 心跳 → ping/pong」。
//!
//! 这些测试是**真的开了一个本地 TCP 端口跑 WS 协议**，不是 mock —— 因为协议层
//! 最容易错的恰恰是「连上之后的行为」（首帧顺序、pong 回带的 id、超时口径），
//! 纯单元测试验证不到。

use std::time::Duration;

use hd_protocol::envelope::MessageType;
use hd_protocol::payload::HelloPayload;
use hd_runner::transport::{Connection, TransportError};
use hd_testkit::{FakeServer, FakeServerConfig};

/// 构造一个「非 15 秒」的心跳配置，用于暴露端侧硬编码问题。
fn fast_config() -> FakeServerConfig {
    FakeServerConfig {
        heartbeat_s: 1,
        offline_after_s: 10,
        ..Default::default()
    }
}

#[tokio::test]
async fn handshake_receives_welcome_with_server_provided_heartbeat() {
    let srv = FakeServer::start(fast_config())
        .await
        .expect("假服务端应能启动");
    let conn = Connection::connect(&srv.url, "hgd_test_token", None)
        .await
        .expect("握手应成功");

    // welcome 的三个关键下发项
    assert_eq!(conn.session.device_id, "dev_fake_001");
    assert_eq!(
        conn.session.protocol_version,
        hd_protocol::CURRENT_PROTOCOL_VERSION
    );
    // 🔴 心跳必须来自 welcome（这里是 1s，不是硬编码的 15s）
    assert_eq!(conn.session.heartbeat.interval, Duration::from_secs(1));
    assert_eq!(
        conn.session.heartbeat.offline_after,
        Duration::from_secs(10)
    );
    // 端侧读超时与服务端口径一致：offline_after + heartbeat
    assert_eq!(
        conn.session.heartbeat.read_timeout(),
        Duration::from_secs(11)
    );

    srv.shutdown();
}

#[tokio::test]
async fn ping_receives_pong() {
    let srv = FakeServer::start(fast_config())
        .await
        .expect("假服务端应能启动");
    let mut conn = Connection::connect(&srv.url, "hgd_test_token", None)
        .await
        .expect("握手应成功");

    let pending = conn.ping_once().await.expect("ping 应收到 pong");
    assert_eq!(pending, 0, "假服务端无待派发任务");
    assert_eq!(srv.ping_count(), 1, "服务端应收到 1 次 ping");

    srv.shutdown();
}

#[tokio::test]
async fn heartbeat_loop_keeps_sending_pings() {
    let srv = FakeServer::start(fast_config())
        .await
        .expect("假服务端应能启动");
    let mut conn = Connection::connect(&srv.url, "hgd_test_token", None)
        .await
        .expect("握手应成功");

    // 按 welcome 下发的 1s 间隔发 3 次心跳
    let interval = conn.session.heartbeat.interval;
    for _ in 0..3 {
        tokio::time::sleep(interval).await;
        conn.ping_once().await.expect("心跳应成功");
    }

    assert_eq!(srv.ping_count(), 3, "应按 welcome 的间隔发出 3 次心跳");
    srv.shutdown();
}

#[tokio::test]
async fn hello_is_sent_when_provided() {
    let srv = FakeServer::start(fast_config())
        .await
        .expect("假服务端应能启动");
    let hello = HelloPayload {
        name: "测试 Runner".into(),
        platform: "windows-amd64".into(),
        app_version: "0.1.0".into(),
        capabilities_hash: "sha256:fake".into(),
        protocol_version: hd_protocol::CURRENT_PROTOCOL_VERSION,
        capabilities: vec![],
    };
    let conn = Connection::connect(&srv.url, "hgd_test_token", Some(hello))
        .await
        .expect("握手应成功");

    assert_eq!(conn.session.device_id, "dev_fake_001");
    // 给假服务端一点时间处理 hello
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(srv.hello_count(), 1, "应收到 1 次 hello");

    srv.shutdown();
}

/// 🔴 回归：能力摘要必须由 hello 留存、并随每一次 ping 复述同一个值。
///
/// 历史缺陷：`ping_once` 里 `capabilities_hash` 恒为 `String::new()`，服务端
/// 收到空摘要 → 无法判断该设备能力是否变更，目录列举能力申报形同虚设。
#[tokio::test]
async fn ping_echoes_the_capabilities_hash_from_hello() {
    let srv = FakeServer::start(fast_config())
        .await
        .expect("假服务端应能启动");

    // 用真实派生逻辑算摘要：证明「hello 与 ping 同源」不是靠手写字符串对上的
    let policy = std::sync::Arc::new(hd_core::Policy::new(vec![], vec![]));
    let mut router = hd_runner::Router::new(
        std::sync::Arc::clone(&policy),
        std::sync::Arc::new(hd_core::NullAuditSink),
        std::sync::Arc::new(hd_runner::IdempotStore::with_defaults()),
    );
    router.register(hd_core::ListDirsExecutor::new(
        std::sync::Arc::clone(&policy),
        None,
        500,
    ));
    let (caps, caps_hash) = hd_runner::capabilities_snapshot(&router);
    assert_eq!(caps.len(), 1, "应申报 fs.list");
    assert_eq!(caps[0].name, "fs.list");

    let hello = HelloPayload {
        name: "测试 Runner".into(),
        platform: "windows-amd64".into(),
        app_version: "0.1.0".into(),
        capabilities_hash: caps_hash.clone(),
        protocol_version: hd_protocol::CURRENT_PROTOCOL_VERSION,
        capabilities: caps,
    };

    let mut conn = Connection::connect(&srv.url, "hgd_test_token", Some(hello))
        .await
        .expect("握手应成功");
    assert_eq!(conn.capabilities_hash(), caps_hash.as_str());

    conn.ping_once().await.expect("心跳应成功");

    let seen = srv
        .last_ping_capabilities_hash()
        .expect("假服务端应已解出 ping 负载");
    assert_eq!(
        seen, caps_hash,
        "ping 必须复述 hello 的能力摘要，不得为空串"
    );
    assert!(
        seen.starts_with("fnv1a64:"),
        "摘要应带算法前缀，实际 {seen}"
    );

    srv.shutdown();
}

/// 未提供 hello 时不臆造能力（保持与改造前一致的「不申报」语义）。
#[tokio::test]
async fn ping_without_hello_reports_empty_capabilities_hash() {
    let srv = FakeServer::start(fast_config())
        .await
        .expect("假服务端应能启动");
    let mut conn = Connection::connect(&srv.url, "hgd_test_token", None)
        .await
        .expect("握手应成功");
    assert!(conn.capabilities_hash().is_empty());
    conn.ping_once().await.expect("心跳应成功");
    assert_eq!(srv.last_ping_capabilities_hash().as_deref(), Some(""));
    srv.shutdown();
}

#[tokio::test]
async fn wrong_token_is_rejected_before_upgrade() {
    let srv = FakeServer::start(fast_config())
        .await
        .expect("假服务端应能启动");

    // 服务端在升级前回 401（gateway.go:145），端侧必须把它识别为 Unauthorized
    let err = Connection::connect(&srv.url, "hgd_wrong_token", None)
        .await
        .expect_err("错误令牌必须握手失败");

    assert!(
        matches!(err, TransportError::Unauthorized(_)),
        "401 必须映射为 Unauthorized（终态、不可重连），实际为: {err:?}"
    );

    srv.shutdown();
}

#[tokio::test]
async fn empty_token_fails_fast() {
    // 空令牌应在发起连接前就失败，不发无谓的网络请求
    let err = Connection::connect("ws://127.0.0.1:1/api/v1/devices/ws", "", None)
        .await
        .expect_err("空令牌必须立即失败");
    assert!(matches!(err, TransportError::Unauthorized(_)));
}

#[tokio::test]
async fn unknown_frames_do_not_break_the_connection() {
    let srv = FakeServer::start(fast_config())
        .await
        .expect("假服务端应能启动");
    let mut conn = Connection::connect(&srv.url, "hgd_test_token", None)
        .await
        .expect("握手应成功");

    // 连续多轮心跳后连接仍应可用（中间若有未知帧会被静默丢弃）
    for _ in 0..2 {
        conn.ping_once().await.expect("连接应保持可用");
    }
    // 收到的是 Pong，未知帧已被过滤
    assert_eq!(srv.ping_count(), 2);

    srv.shutdown();
}

#[tokio::test]
async fn session_exposes_protocol_version_for_negotiation() {
    let srv = FakeServer::start(fast_config())
        .await
        .expect("假服务端应能启动");
    let conn = Connection::connect(&srv.url, "hgd_test_token", None)
        .await
        .expect("握手应成功");

    // 端侧必须能读到服务端版本并自行校验（服务端已校验，双保险）
    assert!(hd_protocol::compatible_version(conn.session.protocol_version).is_ok());
    assert!(hd_protocol::supported_versions().contains(&conn.session.protocol_version));

    // 确保 MessageType 的 welcome 确被识别
    assert!(MessageType::Welcome.is_valid());

    srv.shutdown();
}
