//! 假 Runner：集成测试用的最小子进程。
//!
//! 它**不是**产品代码的一部分，只做四件事：
//! 1. 从 stdin 逐行读，识别首行 `auth` 是否合法（**只输出字段是否存在与长度，
//!    绝不回显 token 明文**，否则测试日志本身就变成泄露源）；
//! 2. 把每行读到的 `op` 打到 stdout，供测试断言「宿主确实把 auth 写进了 stdin」；
//! 3. stdin EOF 后打印 `eof` 并退出 0 —— 复刻真 Runner 的「EOF 自杀」语义；
//! 4. **可控退出**（见下节）：让测试能造出「子进程非零退出 → 宿主重启」的场景。
//!
//! 之所以用独立 bin 而不是在测试里拼 `cmd /c echo`：Windows/Unix 的 shell 行为差异
//! 会让测试变成平台特判堆砌，而一个跨平台的小 bin 让断言直接落在协议层。
//!
//! ## 可控退出的两条通道（为什么两条都要）
//!
//! 守护循环（`bootstrap::supervise`）的重启分支只在**真子进程**上才会走到，
//! 而拉起子进程的 `Daemon::spawn` 会 `.env_clear()`（安全加固：防止继承来的
//! 环境变量里恰好带着旧令牌，见 daemon.rs 注释）。因此：
//!
//! - **stdin 控制行**（`fake_exit` / `fake_exit_after_ms`）是**经过宿主 spawn 后
//!   唯一可用**的注入通道 —— 它复用 Runner 既有的 JSONL 控制协议，不需要任何
//!   额外权限，也不会给产品代码开洞；
//! - **环境变量**（`FAKE_RUNNER_EXIT_CODE` 等）留给「直接命令行跑 fake_runner」
//!   或将来 spawn 策略变化时使用。经宿主 spawn 时它们**不会生效**（被 env_clear 清掉），
//!   这一点由 `tests/supervise_e2e.rs` 的用例注释明确记录。
//!
//! ## stdin 控制行协议（auth 之后）
//!
//! | 行 | 语义 |
//! | --- | --- |
//! | `{"op":"fake_exit","code":3}` | 立即以 3 退出（造「子进程崩溃」） |
//! | `{"op":"fake_exit_after_ms","ms":50,"code":3}` | 50ms 后以 3 退出（当前进程继续正常读循环） |
//! | `{"op":"reload_policy",...}` | 照常打印，并额外带上 `roots=<数量>` |
//!
//! 未知 op 仍按历史行为打印 `cmd op=<op>`，**默认行为完全不变**。

use std::io::{BufRead, Write};
use std::time::Duration;

/// 默认退出码：取「可重试」档（`exit_code::EXIT_RETRYABLE`），
/// 便于测试「宿主应当重启 Runner」这条分支。
const DEFAULT_EXIT_CODE: i32 = hd_protocol::exit_code::EXIT_RETRYABLE as i32;

/// 读一个数字型环境变量；缺失或解析失败一律视为「未设置」。
fn env_num<T: std::str::FromStr>(key: &str) -> Option<T> {
    std::env::var(key).ok()?.trim().parse::<T>().ok()
}

fn main() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    // ---------- 环境变量注入（经宿主 spawn 时不生效，见模块文档） ----------
    let exit_code = env_num::<i32>("FAKE_RUNNER_EXIT_CODE");
    let exit_after_ms = env_num::<u64>("FAKE_RUNNER_EXIT_AFTER_MS");
    let once_file = std::env::var("FAKE_RUNNER_EXIT_ONCE_FILE")
        .ok()
        .filter(|s| !s.trim().is_empty());

    // 「本次实例是否应当按注入码退出」：
    // - 给了 once 文件 → 只在文件**存在**时生效一次（删除即消费），
    //   于是重启后的第二个实例看到文件已不在，正常存活 —— 这正是
    //   「首次退出、重启成功」用例所需的语义；
    // - 未给 once 文件 → 每次启动都生效。
    let inject_now = match &once_file {
        Some(p) => std::fs::remove_file(p).is_ok(),
        None => true,
    };
    // 只有真的设了某个注入变量才启用注入，否则保持历史默认行为不变。
    let has_injection = exit_code.is_some() || exit_after_ms.is_some() || once_file.is_some();

    let mut exit_after_first_line: Option<i32> = None;
    if has_injection && inject_now {
        let code = exit_code.unwrap_or(DEFAULT_EXIT_CODE);
        match exit_after_ms {
            // 存活 N 毫秒后退出：起独立计时线程，主循环照常处理 stdin，
            // 这样「宿主在子进程活着时下发指令」的时序仍然成立。
            Some(ms) => {
                let _ = writeln!(stdout, "scheduled_exit after_ms={ms} code={code}");
                let _ = stdout.flush();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(ms));
                    std::process::exit(code);
                });
            }
            // 只给了退出码：完成 auth 校验后立刻退出（复刻「握手成功但仍失败」）。
            None => exit_after_first_line = Some(code),
        }
    }

    // 首行必须是 auth：真 Runner 也是这样（见 hd-runner::ipc）。
    let mut first = true;

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            // 解析失败只报错不退出：宿主可能在协议演进中多发了一条字段。
            let _ = writeln!(stdout, "bad_json");
            continue;
        };
        let op = v.get("op").and_then(|o| o.as_str()).unwrap_or("?");

        if first {
            first = false;
            if op != "auth" {
                let _ = writeln!(stdout, "first_not_auth op={op}");
                // 复刻真 Runner：首行不是 auth 直接失败退出。
                std::process::exit(2);
            }
            let token_len = v
                .get("token")
                .and_then(|t| t.as_str())
                .map(str::len)
                .unwrap_or(0);
            let ws_url_ok = v.get("ws_url").and_then(|u| u.as_str()).is_some();
            // 🔴 只输出长度与布尔值。
            let _ = writeln!(stdout, "auth token_len={token_len} ws_url_ok={ws_url_ok}");
            let _ = stdout.flush();
            // 注入的「握手后立即退出」：必须在 flush 之后，
            // 否则测试看不到 auth 行就无法断言「子进程确实被拉起过」。
            if let Some(code) = exit_after_first_line {
                let _ = writeln!(stdout, "exit_after_auth code={code}");
                let _ = stdout.flush();
                std::process::exit(code);
            }
            continue;
        }

        // ---------- auth 之后：控制行（宿主 spawn 后唯一可用的注入通道） ----------
        match op {
            // 立即以指定码退出：造「Runner 崩溃」。
            "fake_exit" => {
                let code = v
                    .get("code")
                    .and_then(serde_json::Value::as_i64)
                    .map_or(DEFAULT_EXIT_CODE, |c| c as i32);
                let _ = writeln!(stdout, "fake_exit code={code}");
                let _ = stdout.flush();
                std::process::exit(code);
            }
            // N 毫秒后退出：让「退避期间点取消」「重启后重放」这类时序场景有确定时间窗。
            "fake_exit_after_ms" => {
                let ms = v.get("ms").and_then(serde_json::Value::as_u64).unwrap_or(0);
                let code = v
                    .get("code")
                    .and_then(serde_json::Value::as_i64)
                    .map_or(DEFAULT_EXIT_CODE, |c| c as i32);
                let _ = writeln!(stdout, "fake_exit_scheduled ms={ms} code={code}");
                let _ = stdout.flush();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(ms));
                    std::process::exit(code);
                });
            }
            // 工作区白名单：额外打出 roots 数量，供测试区分
            // 「重放了注入的白名单」与「重放了一份空默认」—— 这两者的日志前缀若相同，
            // 「重启后白名单静默回退成 CWD」这个缺陷就无法被断言出来。
            "reload_policy" => {
                let n = v
                    .get("roots")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, Vec::len);
                let _ = writeln!(stdout, "cmd op=reload_policy roots={n}");
            }
            _ => {
                let _ = writeln!(stdout, "cmd op={op}");
            }
        }
        let _ = stdout.flush();
    }

    // stdin EOF = 宿主已消失 → 真 Runner 会在这里自杀，假 Runner 同样退出。
    let _ = writeln!(stdout, "eof");
    let _ = stdout.flush();
}
