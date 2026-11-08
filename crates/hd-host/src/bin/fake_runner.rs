//! 假 Runner：集成测试用的最小子进程。
//!
//! 它**不是**产品代码的一部分，只做三件事：
//! 1. 从 stdin 逐行读，识别首行 `auth` 是否合法（**只输出字段是否存在与长度，
//!    绝不回显 token 明文**，否则测试日志本身就变成泄露源）；
//! 2. 把每行读到的 `op` 打到 stdout，供测试断言「宿主确实把 auth 写进了 stdin」；
//! 3. stdin EOF 后打印 `eof` 并退出 0 —— 复刻真 Runner 的「EOF 自杀」语义。
//!
//! 之所以用独立 bin 而不是在测试里拼 `cmd /c echo`：Windows/Unix 的 shell 行为差异
//! 会让测试变成平台特判堆砌，而一个跨平台的小 bin 让断言直接落在协议层。

use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
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
        } else {
            let _ = writeln!(stdout, "cmd op={op}");
        }
        let _ = stdout.flush();
    }

    // stdin EOF = 宿主已消失 → 真 Runner 会在这里自杀，假 Runner 同样退出。
    let _ = writeln!(stdout, "eof");
    let _ = stdout.flush();
}
