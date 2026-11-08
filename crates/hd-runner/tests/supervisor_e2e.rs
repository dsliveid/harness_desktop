//! P3 验收：重连环对**真实假服务端**跑通「连上 → 心跳 → 断线 → 重连 → 放弃」。
//!
//! 这里坚持开真实本地端口而不是 mock 连接，原因与 `transport_e2e.rs` 相同：
//! 重连环最容易错的地方是「事件发生顺序」和「计数何时清零」，两者都依赖真实的
//! 连接失败/断开时机，纯单测里的假连接无法暴露顺序问题。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hd_runner::{ReconnectPolicy, StopReason, Supervisor, SupervisorEvent, SupervisorObserver};
use hd_testkit::{FakeServer, FakeServerConfig};

/// 事件收集器（跨任务共享，故用 `Arc<Mutex<_>>`）。
#[derive(Default, Clone)]
struct SharedObserver {
    events: Arc<Mutex<Vec<SupervisorEvent>>>,
}

impl SharedObserver {
    fn events(&self) -> Vec<SupervisorEvent> {
        self.events.lock().expect("不应有锁竞争").clone()
    }
}

impl SupervisorObserver for SharedObserver {
    fn on_event(&mut self, event: SupervisorEvent) {
        self.events.lock().expect("不应有锁竞争").push(event);
    }
}

/// 刻意用非 15 秒的心跳，端侧一旦硬编码就会在 `Connected.heartbeat` 上暴露。
fn config() -> FakeServerConfig {
    FakeServerConfig {
        heartbeat_s: 1,
        offline_after_s: 10,
        ..Default::default()
    }
}

/// 轮询等待某个条件成立（避免为「等首拍心跳」写死固定 sleep）。
async fn wait_until<F: Fn() -> bool>(cond: F, limit: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if cond() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn supervisor_connects_and_emits_heartbeat() {
    let srv = FakeServer::start(config()).await.expect("假服务端应能启动");
    let obs = SharedObserver::default();

    let mut sup = Supervisor::for_ws(srv.url.clone(), "hgd_test_token", None);
    let mut task_obs = obs.clone();
    // `run` 正常情况下永不返回（它会一直在线发心跳），故放进任务里，最后 abort。
    let handle = tokio::spawn(async move {
        sup.run(&mut task_obs).await;
    });

    assert!(
        wait_until(|| srv.ping_count() >= 1, Duration::from_secs(10)).await,
        "supervisor 必须在 10s 内发出至少一次心跳（间隔取自 welcome 的 1s）"
    );

    let connected = obs
        .events()
        .into_iter()
        .find_map(|e| match e {
            SupervisorEvent::Connected {
                device_id,
                heartbeat,
            } => Some((device_id, heartbeat)),
            _ => None,
        })
        .expect("必须产生 Connected 事件");
    assert_eq!(connected.0, "dev_fake_001");
    // 🔴 心跳节奏必须来自服务端下发，不得硬编码 15s
    assert_eq!(connected.1.interval, Duration::from_secs(1));

    handle.abort();
    srv.shutdown();
}

#[tokio::test]
async fn supervisor_stops_immediately_when_token_rejected() {
    let srv = FakeServer::start(config()).await.expect("假服务端应能启动");
    let obs = SharedObserver::default();

    // 令牌错误 → 握手前 401 → 终态，不重试
    let mut sup = Supervisor::for_ws(srv.url.clone(), "hgd_wrong_token", None);
    let mut task_obs = obs.clone();
    let reason = tokio::time::timeout(Duration::from_secs(10), sup.run(&mut task_obs))
        .await
        .expect("被拒绝时必须立即返回，而不是无限重试");

    match &reason {
        StopReason::RejectedByServer { code } => {
            assert_eq!(
                code,
                hd_protocol::error_code::FRAME_REVOKED,
                "401 语义应归一成 device.revoked"
            );
        }
        other => panic!("应因服务端拒绝而停止，实际: {other:?}"),
    }

    let events = obs.events();
    assert!(matches!(events.first(), Some(SupervisorEvent::Connecting)));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SupervisorEvent::Stopped { .. })),
        "停止时必须发 Stopped 事件供 UI 提示"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SupervisorEvent::Reconnecting { .. })),
        "终态错误不允许退避重连"
    );
    assert_eq!(srv.hello_count(), 0, "未通过鉴权就不该把 hello 发出去");

    srv.shutdown();
}

#[tokio::test]
async fn supervisor_reconnects_after_server_restart_then_gives_up() {
    let srv = FakeServer::start(config()).await.expect("假服务端应能启动");
    let url = srv.url.clone();
    let obs = SharedObserver::default();

    // 退避缩到 50ms 量级，让「重连 → 耗尽」在百毫秒内跑完，测试不必等真实的 1/2/4s。
    let policy = ReconnectPolicy {
        initial: Duration::from_millis(50),
        max: Duration::from_millis(200),
        max_attempts: 3,
    };
    let mut sup = Supervisor::with_sleeper(
        hd_runner::WsConnector::new(url, "hgd_test_token"),
        policy,
        hd_runner::TokioSleeper,
    );
    let mut task_obs = obs.clone();
    let handle = tokio::spawn(async move { sup.run(&mut task_obs).await });

    // 先在线的证据：心跳发出
    assert!(
        wait_until(|| srv.ping_count() >= 1, Duration::from_secs(10)).await,
        "重连测试的前置条件是先连上并发心跳"
    );

    // 服务端整个消失：端口关闭 → 后续连接被拒 → 退避 3 次后放弃
    srv.shutdown();

    let stopped = wait_until(
        || {
            obs.events()
                .iter()
                .any(|e| matches!(e, SupervisorEvent::Stopped { .. }))
        },
        Duration::from_secs(20),
    )
    .await;
    assert!(stopped, "服务端消失后应在重试耗尽时停止");

    let reason = obs
        .events()
        .into_iter()
        .find_map(|e| match e {
            SupervisorEvent::Stopped { reason } => Some(reason),
            _ => None,
        })
        .expect("应有 Stopped 事件");
    assert!(
        matches!(reason, StopReason::AttemptsExhausted { .. }),
        "网络侧失败应归结为「重试耗尽」，而不是「服务端拒绝」，实际: {reason:?}"
    );

    handle.abort();
}
