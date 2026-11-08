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
}
