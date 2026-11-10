//! 心跳调度（纯逻辑，不碰网络，便于单测）。
//!
//! ## 为什么单独抽出来
//!
//! 心跳周期来自服务端 `welcome.heartbeat_s`，**绝不能硬编码 15s**。
//! 服务端调整节奏时，硬编码的端侧会被误判离线（`gateway.go:228` 的读超时是
//! `offline_after + heartbeat`）。把「间隔从哪来、超时留多少余量」做成纯函数，
//! 才能在不连网络的情况下把这条约束钉死在测试里。

use std::time::Duration;

/// 服务端下发的心跳节奏。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatPolicy {
    /// 发 ping 的间隔。
    pub interval: Duration,
    /// 服务端认可的离线判定时长（用于端侧自检：多久没收到任何帧就认为连接已死）。
    pub offline_after: Duration,
}

impl HeartbeatPolicy {
    /// 从 `welcome` 的两个字段构造。
    ///
    /// `heartbeat_s <= 0` 时回退到 15s（与服务端 `gateway.go:91` 的默认值一致），
    /// 避免服务端传 0 导致端侧疯狂发 ping 打爆连接。
    pub fn from_welcome(heartbeat_s: i32, offline_after_s: i32) -> Self {
        let hb = if heartbeat_s > 0 {
            heartbeat_s as u64
        } else {
            15
        };
        let offline = if offline_after_s > 0 {
            offline_after_s as u64
        } else {
            45
        };
        Self {
            interval: Duration::from_secs(hb),
            offline_after: Duration::from_secs(offline),
        }
    }

    /// 端侧读超时：多久没收到任何帧就判定连接已死并触发重连。
    ///
    /// 取 `offline_after + interval`，与服务端 `readLoop` 的读超时口径一致
    /// （`gateway.go:228`）。比它短会导致端侧在服务端仍认为在线时先断开。
    pub fn read_timeout(&self) -> Duration {
        self.offline_after + self.interval
    }
}

impl Default for HeartbeatPolicy {
    fn default() -> Self {
        Self::from_welcome(0, 0)
    }
}

// ---------------------------------------------------------------------------
// 心跳控制行：Runner → 宿主 的「这条链路此刻真的通」证据
// ---------------------------------------------------------------------------
//
// ## 为什么需要它
//
// 宿主此前只能观测「子进程还活着」，无法区分下面两种截然不同的现场：
//   ① Runner 进程在，且与服务端心跳正常 → 真正在线；
//   ② Runner 进程在，但已连不上服务端（断网 / 网关重启 / 令牌失效）→ 实际已离线。
// 两者在宿主视角下都是「进程在跑」，于是 `device_status` 的 `last_heartbeat_ms == 0`
// 乐观分支会把 ② 也报成在线，故障在 UI 上完全不可见。
//
// ## 为什么要走 stdout 而不是日志
//
// stderr 是 tracing 日志通道，`{"op":"heartbeat"}` 混进去会变成一条用户可见的日志。
// 因此控制行走 **stdout**（本 crate 此前 stdout 完全空置），宿主侧在 `pump_lines`
// 里于进入 `LogSink` **之前**拦下它：既打点，又不污染 UI 日志面板。
//
// 行格式刻意与 stdin 侧的 `{"op":"auth"}` / `{"op":"shutdown"}` 保持一致，
// 便于人阅读与排障，也便于将来扩展其它控制事件。

/// 心跳控制行的 `op` 值。
pub const OP_HEARTBEAT: &str = "heartbeat";

/// 当前 Unix 毫秒。时钟回拨（早于 1970）时退化为 0，绝不 panic。
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 构造一行心跳控制行（**不含**换行符）。
///
/// 纯函数：格式能被钉死在单测里，而不必真连一次服务端。
pub fn heartbeat_control_line(at_ms: u64) -> String {
    format!("{{\"op\":\"{OP_HEARTBEAT}\",\"at_ms\":{at_ms}}}")
}

/// 判定一行是否为心跳控制行。
///
/// 宿主侧复用本函数而不是自己拼字符串字面量：两侧**共用一份实现**，
/// 才不会出现「Runner 改了字段名、宿主还在按旧名字匹配」的静默失配。
///
/// 判定刻意严格：必须是合法 JSON 对象且 `op` 字段值**恰好**等于
/// [`OP_HEARTBEAT`]。这样 `{"op":"heartbeat_typo"}`、纯文本日志、
/// 以及带心跳字样的普通输出都不会误触发打点。
pub fn is_heartbeat_control_line(line: &str) -> bool {
    let trimmed = line.trim();
    // 快速排除：绝大多数日志行不是 JSON，不必进解析器。
    if !trimmed.starts_with('{') {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(trimmed)
        .ok()
        .and_then(|v| {
            v.get("op")
                .and_then(|op| op.as_str())
                .map(|op| op == OP_HEARTBEAT)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_server_provided_interval_not_hardcoded() {
        // 🔴 核心约束：间隔必须来自 welcome，而非硬编码 15s
        let p = HeartbeatPolicy::from_welcome(3, 30);
        assert_eq!(p.interval, Duration::from_secs(3));
        assert_eq!(p.offline_after, Duration::from_secs(30));
        assert_eq!(p.read_timeout(), Duration::from_secs(33));
    }

    #[test]
    fn falls_back_to_server_defaults_when_invalid() {
        // 服务端传 0/负数时应回退到 gateway.go 的默认 15/45
        let p = HeartbeatPolicy::from_welcome(0, 0);
        assert_eq!(p.interval, Duration::from_secs(15));
        assert_eq!(p.offline_after, Duration::from_secs(45));

        let neg = HeartbeatPolicy::from_welcome(-5, -1);
        assert_eq!(neg.interval, Duration::from_secs(15));
        assert_eq!(neg.offline_after, Duration::from_secs(45));
    }

    #[test]
    fn read_timeout_matches_server_side_formula() {
        // 服务端读超时 = offline_after + heartbeat（gateway.go:228）
        let p = HeartbeatPolicy::from_welcome(15, 45);
        assert_eq!(p.read_timeout(), Duration::from_secs(60));
    }

    // ---------- 心跳控制行：格式与判定 ----------

    #[test]
    fn heartbeat_control_line_is_valid_json_with_op_and_at_ms() {
        // 线上形状必须与 stdin 侧的 `{"op":"auth"}` 同构，宿主才能用同一个解析器拦。
        let line = heartbeat_control_line(1_731_000_000_123);
        assert_eq!(line, r#"{"op":"heartbeat","at_ms":1731000000123}"#);

        let v: serde_json::Value = serde_json::from_str(&line).expect("必须是合法 JSON");
        assert_eq!(v["op"], "heartbeat");
        assert_eq!(v["at_ms"], 1_731_000_000_123u64);
    }

    #[test]
    fn heartbeat_control_line_round_trips_through_detector() {
        // 构造与判定必须自洽：改了任一侧而另一侧没跟，这条立刻红。
        assert!(is_heartbeat_control_line(&heartbeat_control_line(1)));
        assert!(is_heartbeat_control_line(&heartbeat_control_line(u64::MAX)));
    }

    #[test]
    fn detector_rejects_non_heartbeat_lines() {
        // 宿主侧「不误触发打点」的底层保证。逐类列举真实会出现在 stdout 的行：
        // tracing 日志（理论上走 stderr，但防御性覆盖）、其它 op、名字相近的诱饵。
        for line in [
            "",
            "   ",
            "[runner:out] hello",
            "auth 已通过 stdin 写入",
            r#"{"op":"auth","token":"hgd_x","ws_url":"wss://h/ws"}"#,
            r#"{"op":"shutdown"}"#,
            r#"{"op":"reload_policy","roots":[]}"#,
            // 名字相近的诱饵：必须**严格**匹配才算，不能靠 contains("heartbeat")
            r#"{"op":"heartbeat_typo"}"#,
            r#"{"op":"HEARTBEAT"}"#,
            r#"{"op":"preheartbeat"}"#,
            // 只有 at_ms 没有 op
            r#"{"at_ms":123}"#,
            // op 不是字符串
            r#"{"op":123}"#,
            // 非 JSON 但含心跳字样
            "heartbeat ok",
        ] {
            assert!(
                !is_heartbeat_control_line(line),
                "不该被识别为心跳控制行：{line:?}"
            );
        }
    }

    #[test]
    fn detector_accepts_whitespace_padded_and_extra_fields() {
        // 容忍前后空白（管道传输不应因空格失配），也容忍将来追加字段。
        assert!(is_heartbeat_control_line("  {\"op\":\"heartbeat\"}  "));
        assert!(is_heartbeat_control_line(
            r#"{"op":"heartbeat","at_ms":9,"seq":1}"#
        ));
    }
}
