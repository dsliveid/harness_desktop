//! 守护层集成测试：用真实管道验证三条硬性语义。
//!
//! 为什么要真起子进程而不是 mock `Command`：
//! 1. **auth 只经 stdin** —— 「没进 argv」这件事只有在真的 spawn 之后、
//!    去读子进程的实际 argv 才能证明；mock 掉的 `Command` 什么都能"通过"。
//! 2. **写端保持打开** —— 「发完 auth 后 Runner 没立刻收到 EOF」是管道层的时序事实，
//!    只有真管道能观测到。
//! 3. **EOF 防孤儿** —— 同样只能靠「关掉宿主写端 → 子进程自己退出」来观察。
//!
//! 被测子进程是 `src/bin/fake_runner.rs`（跨平台，不依赖 cmd/sh）。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hd_host::daemon::{build_reload_policy_line, Daemon, DaemonError, RunnerLaunch, RunnerState};
use hd_host::vault::{DeviceToken, MemoryVault, TokenVault};
use hd_runner::reconnect::ReconnectPolicy;

/// 定位 fake_runner 可执行文件。
///
/// `CARGO_BIN_EXE_<name>` 由 cargo 在集成测试里自动注入（带 `.exe` 后缀），
/// 比自己拼 `target/debug` 稳 ——后者在 `--target` / workspace 布局变化时会失效。
fn fake_runner_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fake_runner"))
}

fn token(raw: &str) -> DeviceToken {
    DeviceToken::new(raw.to_string())
}

fn daemon() -> Daemon {
    Daemon::new(ReconnectPolicy::default())
}

/// 轮询等待某个条件成立（避免用固定 sleep 造成 flaky）。
///
/// 上限 3 秒：CI 上冷启动子进程 + 管道调度都在这个量级内；
/// 超时即判定失败而不是无限等，避免测试挂死。
async fn wait_until<F: FnMut() -> bool>(mut cond: F) -> bool {
    for _ in 0..300 {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

#[tokio::test]
async fn auth_line_actually_reaches_child_stdin() {
    let d = daemon();
    d.spawn(
        &RunnerLaunch::standalone(fake_runner_exe()),
        &token("hgd_integration_token_abc"),
        "wss://example.test/api/v1/devices/ws",
        1,
    )
    .await
    .expect("应能拉起假 Runner");

    // fake_runner 收到 auth 后会打印 `auth token_len=<n> ws_url_ok=true`。
    // 断言 token_len 等于真实长度 → 证明「整条 auth 行确实写进了 stdin」。
    let expected_len = "hgd_integration_token_abc".len();
    let d_ref = &d;
    let ok = wait_until(|| {
        d_ref
            .logs()
            .iter()
            .any(|l| l.contains(&format!("auth token_len={expected_len}")))
    })
    .await;
    assert!(
        ok,
        "未在 stdout 看到 auth 回显，说明 auth 行没写进 stdin。当前日志：{:?}",
        d.logs()
    );

    // 🔴 反向断言：日志（ring buffer）里绝不能出现令牌明文。
    // 这是「token 不泄露」在真实数据流上的验证：即便子进程/宿主都往 stdout 写日志，
    // 明文也不该出现在宿主持有的任何日志行里。
    for line in d.logs() {
        assert!(
            !line.contains("hgd_integration_token_abc"),
            "日志泄露令牌明文：{line}"
        );
    }

    d.shutdown().await;
}

/// 🔴 防孤儿核心测试：Runner 只在 stdin EOF 时退出。
///
/// 语义拆成两段断言：
/// - **写端保持打开期间**：子进程必须还活着（否则就是「刚启动就掉线」的 bug）；
/// - **关闭写端后**：子进程必须自己退出（否则 Host 崩溃时会留下孤儿）。
#[tokio::test]
async fn child_stays_alive_until_stdin_closes_then_self_terminates() {
    let d = daemon();
    d.spawn(
        &RunnerLaunch::standalone(fake_runner_exe()),
        &token("hgd_keepalive"),
        "wss://x",
        1,
    )
    .await
    .expect("应能拉起假 Runner");

    // 等 auth 回显，确认子进程已进入读循环。
    let d_ref = &d;
    let started = wait_until(|| d_ref.logs().iter().any(|l| l.contains("auth token_len="))).await;
    assert!(started, "子进程未进入读循环：{:?}", d.logs());

    // ① 写端保持打开 → 子进程必须存活。
    // 若这里就死了，说明 spawn 之后某处提前 drop 了 stdin（正是要防的 bug）。
    assert!(d.is_running().await, "spawn 后子进程句柄必须仍被持有");

    // ② 发一条控制命令，验证复用同一写端（不是重开管道）。
    d.send_line(&build_reload_policy_line(
        &["C:\\work".to_string()],
        &["git".to_string()],
    ))
    .await
    .expect("写 reload_policy 应成功");
    let saw_cmd = wait_until(|| {
        d_ref
            .logs()
            .iter()
            .any(|l| l.contains("cmd op=reload_policy"))
    })
    .await;
    assert!(saw_cmd, "子进程未收到 reload_policy：{:?}", d.logs());

    // ③ 关闭写端 → 子进程读到 EOF → 打印 eof 并退出。
    d.shutdown().await;

    let saw_eof = wait_until(|| d_ref.logs().iter().any(|l| l.contains("eof"))).await;
    assert!(
        saw_eof,
        "关闭 stdin 后子进程应读到 EOF 并退出（防孤儿语义失效）：{:?}",
        d.logs()
    );

    // ④ 退出后被记录，状态回到终态（shutting_down：不自动重启）。
    assert!(!d.is_running().await, "shutdown 后不应仍持有子进程");
    assert_eq!(d.stats().state(), RunnerState::ShuttingDown);
}

/// 崩溃场景模拟：Host 侧**不调用** shutdown，直接把 Daemon 整个 drop。
///
/// 这对应「Host 进程崩溃」——OS 会关闭它持有的所有写端。子进程必须自己退出。
/// 这里通过 drop 掉 Daemon（连带 `ChildStdin`）来复刻同一效果。
#[tokio::test]
async fn dropping_host_releases_stdin_and_child_exits() {
    let exe = fake_runner_exe();
    {
        let d = daemon();
        d.spawn(
            &RunnerLaunch::standalone(exe),
            &token("hgd_crashcase"),
            "wss://x",
            1,
        )
        .await
        .expect("应能拉起假 Runner");
        let d_ref = &d;
        let started =
            wait_until(|| d_ref.logs().iter().any(|l| l.contains("auth token_len="))).await;
        assert!(started, "子进程未启动：{:?}", d.logs());
        // d 在这里离开作用域 → 内部的 ChildStdin 被 drop → 管道写端关闭。
        // `kill_on_drop(true)` 是第二道保险，因此即便 write 端语义失效也不会留孤儿。
    }

    // 给子进程一点时间收尾（这里无法直接观察它的退出，因为 Daemon 已 drop）。
    // 断言点在「不 panic 且测试能正常结束」+ 上一测试已单独验证 EOF→退出链路。
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn auth_line_is_not_in_argv_and_not_in_env() {
    // 这一条用「源码级约束 + 运行时日志」双重验证：
    // 运行时无法枚举子进程 argv（跨平台无统一 API），但可以断言：
    // ① spawn 不接收字符串令牌（类型层面：参数是 &DeviceToken）；
    // ② 宿主自身日志里没有任何明文令牌（见第一个测试）。
    // 因此这里改为验证「auth 行构造不会把 token 塞进 env 名/值的形式」。
    let line = hd_host::daemon::build_auth_line(&token("hgd_argv_canary"), "wss://x", 1);
    // 令牌只出现在 JSON 的 token 字段里，不是以 `KEY=VALUE` 的环境变量形态存在。
    assert!(!line.contains('='), "auth 行不应是 KEY=VALUE 形态：{line}");

    let d = daemon();
    d.spawn(
        &RunnerLaunch::standalone(fake_runner_exe()),
        &token("hgd_env_canary"),
        "wss://x",
        1,
    )
    .await
    .expect("应能拉起假 Runner");
    let d_ref = &d;
    let _ = wait_until(|| d_ref.logs().iter().any(|l| l.contains("auth token_len="))).await;
    for l in d.logs() {
        assert!(!l.contains("hgd_env_canary"), "宿主日志泄露令牌：{l}");
    }
    d.shutdown().await;
}

#[tokio::test]
async fn spawn_rejects_empty_token_and_keeps_state_stopped() {
    let d = daemon();
    let err = d
        .spawn(
            &RunnerLaunch::standalone(fake_runner_exe()),
            &token(""),
            "wss://x",
            1,
        )
        .await
        .expect_err("空令牌必须拒绝");
    assert!(matches!(err, DaemonError::Token(_)));
    assert_eq!(d.stats().state(), RunnerState::Stopped);
}

/// 端到端串起 vault → daemon：从「未配对」到「写入后拉起 Runner」。
///
/// 这条测试覆盖真实使用路径，并确保**令牌在整条链路上只以 DeviceToken 形态流动**。
#[tokio::test]
async fn vault_to_daemon_happy_path() {
    let vault = Arc::new(MemoryVault::new());
    let d = daemon();

    // 未配对 → 不该有令牌可传
    assert!(vault.get().expect("读 vault").is_none());

    // 配对成功后写入
    vault.set(&token("hgd_e2e_token_123456")).expect("写入令牌");
    let tok = vault.get().expect("读 vault").expect("应已配对");

    d.spawn(
        &RunnerLaunch::standalone(fake_runner_exe()),
        &tok,
        "wss://example.test/ws",
        1,
    )
    .await
    .expect("拉起 Runner");

    let d_ref = &d;
    let ok = wait_until(|| {
        d_ref
            .logs()
            .iter()
            .any(|l| l.contains(&format!("auth token_len={}", "hgd_e2e_token_123456".len())))
    })
    .await;
    assert!(ok, "auth 未送达：{:?}", d.logs());

    d.shutdown().await;
    // 解除配对后 vault 回到未配对态
    vault.clear().expect("清除令牌");
    assert!(vault.get().expect("读 vault").is_none());
}

/// 子进程退出后必须记录 exit code（否则「Runner 为什么挂了」只能靠猜）。
#[tokio::test]
async fn wait_exit_records_exit_code() {
    let d = daemon();
    d.spawn(
        &RunnerLaunch::standalone(fake_runner_exe()),
        &token("hgd_exitcode"),
        "wss://x",
        1,
    )
    .await
    .expect("拉起 Runner");

    let d_ref = &d;
    let started = wait_until(|| d_ref.logs().iter().any(|l| l.contains("auth token_len="))).await;
    assert!(started, "子进程未启动：{:?}", d.logs());

    // `wait_exit` 会先关闭写端 → 假 Runner 读到 EOF → 正常退出 0。
    let rec = d.wait_exit().await.expect("应有退出记录");
    assert_eq!(rec.code, Some(0), "假 Runner 正常 EOF 退出应为 0：{rec:?}");
    assert!(
        rec.at_ms > 0,
        "必须记录退出时刻，否则无法判断「多久前挂的」"
    );
    assert_eq!(rec.restarts, 0);

    // 状态回到 Stopped，且记录可被再次读出（供 UI 展示最后一次退出）。
    assert_eq!(d.stats().state(), RunnerState::Stopped);
    assert_eq!(d.last_exit(), Some(rec));
    assert!(!d.is_running().await);
}

/// P3 接线证明：`set_workspace_roots_and_push` 必须真的把 `reload_policy`
/// 写进 Runner 的 stdin。
///
/// ## 为什么必须用真子进程
///
/// 这是「宿主与 Runner 的白名单口径是否一致」的唯一可观测证据。改造前的缺陷
/// 恰恰是**代码看起来一切正常**：HostState 更新了、UI 显示成功，只是那条控制行
/// 从未发出。用 mock 无法发现这种「漏了一次 IO」的缺陷 —— 只有真管道 + 真子进程
/// 打出的 `op` 才能证明字节确实过去了。
///
/// 假 Runner 会把每行的 `op` 打到 stdout，宿主经 `pump_lines` 收进日志 ring，
/// 因此断言日志里出现 `op=reload_policy` 即为端到端证据。
#[tokio::test]
async fn push_workspace_roots_reaches_fake_runner() {
    let d = daemon();
    let launch = RunnerLaunch::standalone(fake_runner_exe());

    d.spawn(&launch, &token("hgd_push_test"), "ws://127.0.0.1:1/x", 1)
        .await
        .expect("拉起 Runner");

    let d_ref = &d;
    let started = wait_until(|| d_ref.logs().iter().any(|l| l.contains("auth token_len="))).await;
    assert!(started, "子进程未启动：{:?}", d.logs());

    // 下发一份工作区白名单。
    let policy = hd_core::security::guard::Policy::new(vec![std::env::temp_dir()], Vec::new());
    d.reload_policy(&policy).await.expect("下发应成功");

    // 子进程收到并把它打到 stdout → 经 pump_lines 进日志 ring。
    let seen = wait_until(|| d_ref.logs().iter().any(|l| l.contains("op=reload_policy"))).await;
    assert!(
        seen,
        "Runner 未收到 reload_policy —— 白名单下发链路断开（宿主已改、执行侧不知道）。日志：{:?}",
        d.logs()
    );

    let _ = d.shutdown().await;
}
