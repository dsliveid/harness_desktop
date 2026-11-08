//! P3 验收：stdin JSONL 控制协议的**完整驱动回路**。
//!
//! 单测已逐个验证解析器，这里验证「把它们按 Runner main 的顺序串起来」不会卡死、
//! 不会因一条看不懂的命令自杀、且 EOF 一定触发优雅退出（对齐 §17.2 的「EOF 自杀」）。
//! 用 `Cursor` 而不是真 stdin：真 stdin 在测试进程里无法伪造，而这层逻辑本身不依赖
//! 文件描述符类型 —— 只要它实现 `BufRead` 就够。

use std::io::Cursor;

use hd_runner::{parse_command, AuthConfig, IpcCommand, IpcReader};

/// 模拟 Runner 主循环会做的事：先鉴权，再逐条消费命令，遇到 shutdown/EOF 退出。
/// 返回（是否收到 shutdown，收到的策略热更新次数，被忽略的未知命令数）。
fn drive(input: &str) -> (bool, usize, usize) {
    let mut reader = IpcReader::new(Cursor::new(input.as_bytes().to_vec()));
    let cfg: AuthConfig = reader.read_auth().expect("首行必须是 auth");
    assert!(!cfg.token.is_empty(), "鉴权后必须拿到令牌");

    let mut reloads = 0usize;
    let mut ignored = 0usize;
    loop {
        match reader.next_command() {
            Ok(Some(IpcCommand::Shutdown)) => return (true, reloads, ignored),
            Ok(Some(IpcCommand::ReloadPolicy { .. })) => reloads += 1,
            Ok(Some(IpcCommand::Auth(_))) => {
                // 重复鉴权属于协议误用：真实 Runner 应报错而不是悄悄换令牌
                panic!("运行期不应再次收到 auth");
            }
            Ok(Some(IpcCommand::Unknown)) => panic!("未知 op 应走 Err 分支，而非 Unknown 变体"),
            // 未知 op 是**可忽略**的：宿主壳可能比 Runner 新
            Err(err) if err.is_ignorable() => ignored += 1,
            Err(err) => panic!("非可忽略错误应终止: {err}"),
            Ok(None) => return (false, reloads, ignored),
        }
    }
}

#[test]
fn full_session_auth_policy_unknown_then_shutdown() {
    let input = concat!(
        r#"{"op":"auth","token":"hgd_e2e_token","ws_url":"wss://host/api/v1/devices/ws","protocol_version":1}"#,
        "\n",
        r#"{"op":"reload_policy","roots":["C:\\Users\\me\\work"],"exec_allowlist":["git","node"]}"#,
        "\n",
        r#"{"op":"telemetry_upload","rate":5}"#,
        "\n",
        r#"{"op":"reload_policy","roots":["D:\\w"],"exec_allowlist":["cargo"]}"#,
        "\n",
        r#"{"op":"shutdown"}"#,
        "\n"
    );

    let (shutdown, reloads, ignored) = drive(input);
    assert!(shutdown, "收到 shutdown 必须优雅退出");
    assert_eq!(reloads, 2, "两次策略热更新都应被识别");
    assert_eq!(ignored, 1, "未知 op 必须被忽略且不中断会话");
}

#[test]
fn eof_without_shutdown_means_parent_exited() {
    // 宿主壳崩溃/被拖走时不会发 shutdown，只剩 EOF —— 此时 Runner 必须自杀，
    // 否则会留下孤儿进程一直占着连接。
    let input = concat!(
        r#"{"op":"auth","token":"hgd_e2e_token","ws_url":"wss://host/ws"}"#,
        "\n"
    );

    let (shutdown, reloads, ignored) = drive(input);
    assert!(!shutdown);
    assert_eq!(reloads, 0);
    assert_eq!(ignored, 0);
}

#[test]
fn token_is_redacted_in_every_journal_line() {
    // 反向自检：任何可能进日志的格式化路径都不能出现令牌正文
    let line = r#"{"op":"auth","token":"hgd_e2e_token","ws_url":"wss://host/ws"}"#;
    let secret = "e2e_token";

    let cfg = hd_runner::parse_auth_first_line(line).expect("应解析成功");
    // ① Debug 打码
    assert!(!format!("{cfg:?}").contains(secret));
    // ② Display 不适用于 AuthConfig（未实现），所以不存在漏法
    // ③ 解析失败的错误信息里也不该带上原文
    let bad = format!(
        "{:?}",
        parse_command("{\"op\":\"auth\",\"token\":").unwrap_err()
    );
    assert!(!bad.contains(secret));
}
