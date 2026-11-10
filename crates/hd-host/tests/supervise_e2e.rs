//! 守护循环（[`Bootstrap::supervise`]）的**执行层**端到端测试。
//!
//! ## 为什么需要这个文件
//!
//! 守护决策早已被 `supervisor::Guard` 的 10 个穷举单测钉死，但那 10 个测试
//! 全部止步于「纯逻辑返回什么动作」。`supervise` 是**把动作执行出去**的那一层，
//! 它承载三条决策层根本管不到的语义：
//!
//! 1. **退避期间分段检查取消**（`wait_or_shutdown`）：若一次性 sleep 完整 delay，
//!    用户点退出最坏要等满整个退避（末日档 8s，`ReconnectPolicy` 封顶 30s）；
//! 2. **重启后必须重放工作区白名单**：Runner 每次启动的 Policy 只是「进程当前目录」，
//!    不重放就静默回退成 CWD —— 表现为「重启后某些目录突然不能访问」且日志无异常；
//! 3. **主动停止优先于退出码判定**：shutdown 已置位时，即便退出码是可重试的 3，
//!    也必须直接 `Stop{repair:false}`，不进入退避、不重启。
//!
//! 三条都只在真子进程上才成立（mock 掉 `Daemon` 会让它们全部「通过」），
//! 因此这里用 `src/bin/fake_runner.rs` 当被测子进程，走真实的管道与真实进程退出。
//!
//! ## 复用的既有基建
//!
//! - `CARGO_BIN_EXE_fake_runner`：由 cargo 注入，比手拼 `target/debug` 稳；
//! - `Daemon::with_lock_path()`：🔴 **每个用例都必须注入唯一的锁路径**，
//!   否则并行运行的测试会抢同一把实例锁、互相把对方判成「外部已在运行」（P4 踩过）；
//! - `Bootstrap::with_self_derive(false)`：🔴 必须显式关闭。`locate_runner` 的
//!   自派生分支优先级最高，而 `current_exe()` 在集成测试里指向**测试二进制自身**，
//!   不关掉就会把测试 harness 当作 Runner 拉起来（没有 `--runner`，行为不可预期）；
//! - `daemon.send_line()` 下发控制行，`daemon.logs()` 断言宿主确实写进了 stdin。
//!
//! ## 关于 fake_runner 的注入通道（与交接书原始建议的偏差，已实测）
//!
//! `Daemon::spawn` 出于安全考虑调用了 `.env_clear()`（见 daemon.rs 的注释：
//! 防止继承来的环境变量里恰好带着旧令牌）。因此**经宿主 spawn 的子进程看不到
//! 任何 `FAKE_RUNNER_*` 环境变量** —— 若只提供 env 通道，「重启」这类场景根本无法构造。
//!
//! 所以 fake_runner 提供**两条**通道：
//!
//! | 通道 | 可用场景 | 本文件用法 |
//! | --- | --- | --- |
//! | stdin 控制行 `fake_exit` / `fake_exit_after_ms` | 经宿主 spawn 后**唯一**可用 | 三个 supervise 用例 |
//! | 环境变量 `FAKE_RUNNER_EXIT_*` | 直接命令行跑 fake_runner | 末尾两个护栏用例 |
//!
//! 两条通道的默认行为都与历史版本完全一致（不注入时照旧「等 stdin EOF 退出 0」），
//! 由末尾的护栏用例守住。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hd_core::security::guard::Policy;
use hd_host::bootstrap::{Bootstrap, BootstrapOutcome};
use hd_host::daemon::Daemon;
use hd_host::lifecycle::RunnerPhase;
use hd_host::supervisor::{Guard, GuardAction};
use hd_host::vault::{DeviceToken, MemoryVault, TokenVault};
use hd_protocol::exit_code;
use hd_runner::reconnect::ReconnectPolicy;

/// 定位 fake_runner 可执行文件。
///
/// `CARGO_BIN_EXE_<name>` 由 cargo 在集成测试里自动注入（带平台后缀），
/// 比自己拼 `target/debug` 稳 —— 后者在 `--target` / workspace 布局变化时会失效。
/// `assert!(is_file())` 是护栏：报错要指向「忘了 `cargo build --bins`」，
/// 而不是让子进程 spawn 失败后一头雾水。
fn fake_runner_exe() -> PathBuf {
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_fake_runner"));
    assert!(
        exe.is_file(),
        "fake_runner 未构建（先 `cargo build -p hd-host --bins`）：{}",
        exe.display()
    );
    exe
}

/// 每个用例独有的实例锁路径。
///
/// 直接拼 `temp_dir()/固定名` 会让并行测试互相抢锁，
/// 现象是「单独跑过、全量跑挂」这类最难查的偶发失败。
fn temp_lock_path(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("hd-sup-{tag}-{}-{n}.lock", std::process::id()))
}

/// 组一份「已配对 + 锁定 fake_runner」的最小编排器。
fn bootstrap(daemon: &Arc<Daemon>, exe: PathBuf) -> (Bootstrap, Arc<dyn TokenVault>) {
    let vault: Arc<dyn TokenVault> = Arc::new(MemoryVault::new());
    vault
        .set(&DeviceToken::new("hgd_supervise_e2e".into()))
        .expect("写入假令牌");
    let boot = Bootstrap::new(Arc::clone(&vault), Arc::clone(daemon), "fake_runner", 1)
        // 🔴 必须关闭：否则 locate_runner 会把测试二进制自身当成 Runner 拉起来。
        .with_self_derive(false)
        .with_explicit_runner(Some(exe));
    (boot, vault)
}

/// 组一个与 `supervise` 共享同一份 shutdown 标志的守护状态机。
///
/// 两个 `Arc` 必须是**同一个**：`supervise` 读自己那份决定「是否放弃重启」，
/// `Guard` 读自己那份决定「是否不重启」。分享两份不同的标志会让
/// 「主动停止优先」这条语义在测试里看起来成立、在真实 GUI 里失效。
fn guard_for(shutdown: &Arc<AtomicBool>) -> Guard {
    Guard::new(ReconnectPolicy::default(), Arc::clone(shutdown))
}

/// 构造一行的「假 Runner 立刻退出」控制行。
fn fake_exit_line(code: u8) -> String {
    format!(r#"{{"op":"fake_exit","code":{code}}}"#)
}

/// 构造一份 `reload_policy` 控制行（护栏用例用）。
fn reload_policy_line(roots: &[&str]) -> String {
    let roots = roots
        .iter()
        .map(|r| format!("\"{r}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"op":"reload_policy","roots":[{roots}],"exec_allowlist":[]}}"#)
}

/// 轮询等待条件成立。返回是否在超时前成立。
///
/// 用轮询而非 channel：被测对象（`Daemon` 的 stats / logs）本来就是无通知的读模型，
/// 加通知通道会为了测试改动生产代码。
async fn wait_until<F>(mut cond: F, timeout: Duration) -> bool
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return cond();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// 统计日志里「子进程被拉起过几次」。
///
/// 判据是 fake_runner 在 auth 之后打的那行 —— 每拉起一份子进程必然出现一次，
/// 比读 `stats().restarts()` 可靠：后者只反映「决策为重启」的次数，
/// 而本文件要断言的是**物理上是否真的有第二个进程**。
fn spawn_count(logs: &[String]) -> usize {
    logs.iter()
        .filter(|l| l.contains("auth token_len="))
        .count()
}

// ============================================================================
// 语义 ①：退避期间分段检查取消
// ============================================================================

/// 子进程以「可重试」退出码死掉 → 循环进入 1s 退避；在退避期间置位 shutdown，
/// 循环必须**立刻**返回 `Stop{repair:false}`，而不是等满退避甚至把 Runner 拉起来。
///
/// ## 为什么断言「超时而非耗时」是主判据
///
/// 若 `wait_or_shutdown` 退化成一次性 `sleep(delay)`，循环会在退避结束后照常重启，
/// 然后阻塞在第二份子进程的 `wait_exit()` 上**永不返回** —— 表现为 GUI 点退出后
/// 进程赖着不走。所以最强的断言是「整个 supervise 必须在超时内返回」，
/// 耗时上界只作为「是否真的逐段检查」的辅助证据（留足 Windows CI 抖动余量）。
#[tokio::test]
async fn shutdown_during_backoff_returns_stop_promptly() {
    let exe = fake_runner_exe();
    let daemon = Arc::new(
        Daemon::new(ReconnectPolicy::default()).with_lock_path(temp_lock_path("cancel-backoff")),
    );
    let (boot, _vault) = bootstrap(&daemon, exe);

    let outcome = boot.ensure_running().await.expect("首次拉起 Runner");
    assert!(
        matches!(outcome, BootstrapOutcome::Started { .. }),
        "期望 Started，实际 {outcome:?}"
    );

    // 让子进程以「可重试」退出码自杀：这是唯一能进入 Restart 分支的退出码档。
    daemon
        .send_line(&fake_exit_line(exit_code::EXIT_RETRYABLE))
        .await
        .expect("下发 fake_exit");

    let shutdown = Arc::new(AtomicBool::new(false));
    let mut guard = guard_for(&shutdown);

    // 动作与观测并发推进：观测到 Backoff 相位后置位取消标志并计时。
    let supervise = boot.supervise(&mut guard, Arc::clone(&shutdown));
    let driver = async {
        let d = &daemon;
        let entered = wait_until(
            || d.stats().state() == RunnerPhase::Backoff,
            Duration::from_secs(5),
        )
        .await;
        assert!(
            entered,
            "未观察到 Backoff 相位，无法确认「退避期间取消」这条语义。日志：{:?}",
            d.logs()
        );
        let t0 = Instant::now();
        shutdown.store(true, Ordering::SeqCst);
        t0
    };

    // 上界取 20s：远大于「1s 退避 + 100ms 分片」，又足以在取消失效时先由 join 卡死、
    // 再由 timeout 报出「循环没有返回」这个真实缺陷（而不是被误报成抖动）。
    let (action, t0) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(supervise, driver)
    })
    .await
    .expect("超时：退避期间置位 shutdown 后 supervise 仍未返回 —— 取消没有被逐段检查");

    let elapsed = t0.elapsed();
    assert!(
        matches!(action, GuardAction::Stop { repair: false, .. }),
        "期望 Stop{{repair:false}}，实际 {action:?}"
    );
    // 宽松上界：正常应 ~100ms。给 3s 是为了不把 CI 抖动当缺陷，
    // 同时仍能拦住「等满整个退避（1s 起，末日档 8s）」这种退化。
    assert!(
        elapsed <= Duration::from_secs(3),
        "取消响应耗时 {elapsed:?} 过长，疑似退避未被分段检查（正常应约 100ms）"
    );
    // 取消生效后绝不能再拉起第二份子进程。
    assert_eq!(
        spawn_count(&daemon.logs()),
        1,
        "取消后仍发生了重启。日志：{:?}",
        daemon.logs()
    );

    daemon.shutdown().await;
}

// ============================================================================
// 语义 ②：重启后必须重放工作区白名单
// ============================================================================

/// 子进程首次退出后成功重启，重启完成必须把宿主侧的工作区白名单**重放**给新进程。
///
/// 判据用 `roots=1` 而不是仅仅 `op=reload_policy`：宿主在不注入 policy_source 时
/// 会重放一份**空白名单**（`roots=0`），日志前缀完全相同。若不核对数量，
/// 「重放发生了但重放的是空默认」这个最危险的退化（= 白名单静默回退成 CWD）
/// 会被判定通过。
#[tokio::test]
async fn workspace_roots_are_replayed_after_restart() {
    let exe = fake_runner_exe();
    let daemon = Arc::new(
        Daemon::new(ReconnectPolicy::default()).with_lock_path(temp_lock_path("replay-roots")),
    );
    let (boot, _vault) = bootstrap(&daemon, exe);

    // 真实存在的目录：`Policy::new` 对无法 canonicalize 的根是 **fail-closed 丢弃**，
    // 传一个不存在的路径会静默变成空白名单，用例就失去意义。
    let roots_dir = tempfile::tempdir().expect("创建临时白名单根");
    let root = roots_dir.path().to_path_buf();
    let boot = boot.with_policy_source(Arc::new(move || {
        Policy::new(vec![root.clone()], Vec::new())
    }));

    let outcome = boot.ensure_running().await.expect("首次拉起 Runner");
    assert!(
        matches!(outcome, BootstrapOutcome::Started { .. }),
        "期望 Started，实际 {outcome:?}"
    );

    daemon
        .send_line(&fake_exit_line(exit_code::EXIT_RETRYABLE))
        .await
        .expect("下发 fake_exit");

    let shutdown = Arc::new(AtomicBool::new(false));
    let mut guard = guard_for(&shutdown);

    let supervise = boot.supervise(&mut guard, Arc::clone(&shutdown));
    let driver = async {
        let d = &daemon;
        let replayed = wait_until(
            || {
                d.logs()
                    .iter()
                    .any(|l| l.contains("op=reload_policy") && l.contains("roots=1"))
            },
            // 1s 退避 + 重新 spawn + 重放，10s 足够；给足是为了不在慢机上误报。
            Duration::from_secs(10),
        )
        .await;
        assert!(
            replayed,
            "重启后没有重放注入了 1 个根的白名单 —— 白名单会静默回退成 CWD。日志：{:?}",
            d.logs()
        );

        // 收尾：让第二次循环也能退出（先置取消标志，再关写端让子进程 EOF 自杀）。
        shutdown.store(true, Ordering::SeqCst);
        d.shutdown().await;
    };

    tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(supervise, driver)
    })
    .await
    .expect("超时：重放白名单用例未能收敛");

    // 物理证据：确实拉起了第二份子进程（否则「重放」可能是给第一个进程发的）。
    assert!(
        spawn_count(&daemon.logs()) >= 2,
        "未观察到第二次拉起，重启分支可能没走到。日志：{:?}",
        daemon.logs()
    );
}

// ============================================================================
// 语义 ③：主动停止优先于退出码判定
// ============================================================================

/// `shutdown` 已置位时，即便子进程以「可重试」的 3 退出，也必须直接
/// `Stop{repair:false}`：不进入退避、不重启、不清令牌。
///
/// 这条与 Guard 的单测重叠在「决策」上，但重叠是必要的：
/// `supervise` 在决策**之前**还有一段自己的短路（② 号检查），
/// 而 Guard 的短路用的是它自己那份 `shutdown` Arc。两份标志若被传成不同实例，
/// 单测全绿而真实 GUI 里「点退出后又被拉起来」。本用例把两者绑在同一份 Arc 上验证。
#[tokio::test]
async fn shutdown_wins_over_retryable_exit_code() {
    let exe = fake_runner_exe();
    let daemon = Arc::new(
        Daemon::new(ReconnectPolicy::default()).with_lock_path(temp_lock_path("shutdown-priority")),
    );
    let (boot, vault) = bootstrap(&daemon, exe);

    let outcome = boot.ensure_running().await.expect("首次拉起 Runner");
    assert!(
        matches!(outcome, BootstrapOutcome::Started { .. }),
        "期望 Started，实际 {outcome:?}"
    );

    // 用户已经点了退出 —— 此时子进程才以可重试码死掉。
    let shutdown = Arc::new(AtomicBool::new(true));
    let mut guard = guard_for(&shutdown);
    daemon
        .send_line(&fake_exit_line(exit_code::EXIT_RETRYABLE))
        .await
        .expect("下发 fake_exit");

    let action = tokio::time::timeout(
        Duration::from_secs(10),
        boot.supervise(&mut guard, Arc::clone(&shutdown)),
    )
    .await
    .expect("超时：已置 shutdown 却仍在重试（主动停止没有优先于退出码）");

    assert!(
        matches!(action, GuardAction::Stop { repair: false, .. }),
        "期望 Stop{{repair:false}}（不清令牌），实际 {action:?}"
    );
    // 不得重启：物理上只有一份子进程。
    assert_eq!(
        spawn_count(&daemon.logs()),
        1,
        "主动停止后仍拉起了第二份 Runner。日志：{:?}",
        daemon.logs()
    );
    assert_eq!(
        daemon.stats().restarts(),
        0,
        "主动停止路径不该记任何重启次数"
    );
    // 不得清令牌：`repair:false` 的执行层后果就是密钥链原样保留。
    assert!(
        vault.get().expect("读令牌").is_some(),
        "主动停止不该清掉本地令牌"
    );

    daemon.shutdown().await;
}

// ============================================================================
// fake_runner 两条注入通道的护栏（防「扩展破坏了默认行为」）
// ============================================================================

/// 不设任何注入时，fake_runner 必须保持历史行为：
/// 读 auth → 回显 op → stdin EOF 后以 0 退出。
#[test]
fn fake_runner_default_behaviour_is_unchanged() {
    use std::io::Write;

    let mut child = std::process::Command::new(fake_runner_exe())
        // 显式清掉注入变量：本用例断言的是「不注入时的历史行为」，
        // 若开发机的 shell 恰好 export 了 FAKE_RUNNER_EXIT_CODE，用例会无辜失败。
        .env_remove("FAKE_RUNNER_EXIT_CODE")
        .env_remove("FAKE_RUNNER_EXIT_AFTER_MS")
        .env_remove("FAKE_RUNNER_EXIT_ONCE_FILE")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("拉起 fake_runner");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        writeln!(
            stdin,
            r#"{{"op":"auth","token":"hgd_x","ws_url":"ws://x","protocol_version":1}}"#
        )
        .expect("写 auth");
        writeln!(stdin, "{}", reload_policy_line(&["/tmp/a", "/tmp/b"])).expect("写 reload_policy");
        stdin.flush().expect("flush");
    }
    // 主动关闭写端 → 子进程读到 EOF。
    drop(child.stdin.take());

    let out = child.wait_with_output().expect("等待退出");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert_eq!(out.status.code(), Some(0), "默认必须以 0 退出：{stdout}");
    assert!(
        stdout.contains("auth token_len="),
        "缺少 auth 回显：{stdout}"
    );
    assert!(
        stdout.contains("op=reload_policy roots=2"),
        "reload_policy 应带上根数量（这是「重放的是哪份白名单」的唯一证据）：{stdout}"
    );
    assert!(stdout.contains("eof"), "EOF 自杀语义丢失：{stdout}");
}

/// 环境变量通道：直接命令行跑 fake_runner 时必须生效。
///
/// 这里刻意**不经过宿主**（`Daemon::spawn` 会 `.env_clear()`，见模块文档），
/// 因此本用例同时充当「为什么中文档说 env 通道只适用于直跑」的可执行说明。
#[test]
fn fake_runner_env_exit_code_is_honoured_when_run_directly() {
    use std::io::Write;

    let mut child = std::process::Command::new(fake_runner_exe())
        .env("FAKE_RUNNER_EXIT_CODE", "3")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("拉起 fake_runner");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        writeln!(
            stdin,
            r#"{{"op":"auth","token":"hgd_x","ws_url":"ws://x","protocol_version":1}}"#
        )
        .expect("写 auth");
        stdin.flush().expect("flush");
    }

    let out = child.wait_with_output().expect("等待退出");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert_eq!(
        out.status.code(),
        Some(3),
        "FAKE_RUNNER_EXIT_CODE 未生效：{stdout}"
    );
    // 必须先看到 auth 回显再退出：否则测试无法断言「子进程确实被拉起过」。
    assert!(
        stdout.contains("auth token_len="),
        "退出太早，没留下 auth 证据：{stdout}"
    );
    assert!(
        stdout.contains("exit_after_auth code=3"),
        "缺少注入退出的标记行：{stdout}"
    );
}
