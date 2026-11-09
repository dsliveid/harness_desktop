//! Runner 进程退出码契约（**跨 crate 唯一来源**）。
//!
//! ## 为什么这个文件必须存在
//!
//! 宿主（`hd-host`）要决定「Runner 死了之后该做什么」：重启？清理令牌重新配对？
//! 还是什么都不做？这个判断的**唯一输入**就是 Runner 的退出码。
//!
//! 在此之前，`hd-runner` 的所有终止路径都 `return 0`（见 `cli.rs` 历史实现），
//! 于是宿主拿到 `Some(0)` 时无法区分两种情况：
//!
//! - 用户主动退出（应该安静地什么都不做）；
//! - 令牌被服务端吊销（应该清掉本地令牌并引导重新配对）。
//!
//! 后果不是「体验差」而是**不可自愈**：宿主若按「崩溃就重启」处理，令牌被吊销时
//! 会变成每秒一次的无限重启风暴；宿主若按「退出就不管」处理，用户会陷入
//! 「打开就失败、重开也一样」且无法自助恢复的状态。
//!
//! ## 为什么放在 `hd-protocol` 而不是各 crate 里
//!
//! 这是**生产方（hd-runner）与消费方（hd-host）之间的契约**。写在任一侧都会让
//! 另一侧被迫依赖它，或者（更糟）各写一套常量，日后悄悄漂移。`hd-protocol` 是
//! 双方都已依赖、且**不含任何 IO/运行时依赖**的中立层，是唯一合适的位置。
//!
//! 与 `error_code` 模块的关系：`error_code` 描述的是**线上帧**里携带的错误码字符串；
//! 本模块描述的是**进程退出**这一本地事件。两者语义相关（如 `device.revoked` 会让
//! Runner 以 [`EXIT_REVOKED`] 退出），但载体不同，故分开定义、不互相引用。

/// 正常结束：用户主动停止、stdin EOF（宿主已亡）、或收到 `shutdown` 控制命令。
///
/// 宿主动作：**不重启、不清理**。这是唯一「预期内」的退出。
pub const EXIT_OK: u8 = 0;

/// 通用失败（非常规路径，例如运行时创建失败）。
///
/// 宿主动作：按可重试处理（但应记录日志，这类问题通常意味着环境已坏）。
pub const EXIT_GENERIC_FAILURE: u8 = 1;

/// 启动配置缺失或非法：没有收到合法的 `auth` 首行、地址不满足 `wss://` 要求等。
///
/// 宿主动作：**不重启**。这几乎一定是宿主侧写错了令牌或地址，重试只会重复失败。
/// 与「服务端拒绝」区分开，是为了让排障方向明确指向父进程而非服务端。
pub const EXIT_NO_AUTH: u8 = 2;

/// 连接层终止但**可重试**：连续失败次数耗尽、连接被意外中断且重试预算用完。
///
/// 宿主动作：**退避后重启**。这类失败的典型成因是服务端没起来或本机断网，
/// 用户修好网络后重启即可恢复。
pub const EXIT_RETRYABLE: u8 = 3;

/// 设备已被服务端吊销（`device.revoked`）。
///
/// 宿主动作：**清理本地令牌与配对档案，切到「需要配对」状态，不重启**。
/// 这是「只有一方主动解约才需重新配对」在客户端侧的落点：服务端解约后，
/// 客户端必须自愈到可重新配对的状态，否则用户永远连不上且不知道该做什么。
pub const EXIT_REVOKED: u8 = 4;

/// 同一设备被新连接替换（`device.replaced`）。
///
/// 宿主动作：**不重启**。服务端已有一台更新的连接占着该设备身份，
/// 重启只会把那条连接踢掉，形成两个进程互踢的循环。
pub const EXIT_REPLACED: u8 = 5;

/// 协议版本不兼容（`device.protocol_mismatch`）。
///
/// 宿主动作：**不重启**，提示用户升级客户端。重试不会让版本变匹配。
pub const EXIT_PROTOCOL_MISMATCH: u8 = 6;

/// 全部合法退出码（供测试与文档断言使用）。
pub const ALL: [u8; 7] = [
    EXIT_OK,
    EXIT_GENERIC_FAILURE,
    EXIT_NO_AUTH,
    EXIT_RETRYABLE,
    EXIT_REVOKED,
    EXIT_REPLACED,
    EXIT_PROTOCOL_MISMATCH,
];

/// 该退出码是否意味着「宿主应当退避后重启 Runner」。
///
/// 刻意**默认拒绝**（未知码 → `false`）：面对无法归类的退出，安静地不重启比
/// 无脑重启安全 —— 无限重启风暴会刷爆服务端日志并掩盖真正的原因。
#[must_use]
pub fn should_restart(code: Option<u8>) -> bool {
    match code {
        // 正常结束：用户要求的，不该擅自拉起。
        Some(EXIT_OK) => false,
        // 配置错 / 被吊销 / 被替换 / 协议不匹配：重试无意义。
        Some(EXIT_NO_AUTH)
        | Some(EXIT_REVOKED)
        | Some(EXIT_REPLACED)
        | Some(EXIT_PROTOCOL_MISMATCH) => false,
        // 显式可重试 + 通用失败（环境类问题，值得再试一次）。
        Some(EXIT_RETRYABLE) | Some(EXIT_GENERIC_FAILURE) => true,
        // 被信号终止（`code()` 为 None）或未知码：不擅自重启。
        _ => false,
    }
}

/// 该退出码是否意味着「本地令牌已失效，应当清理并重新配对」。
#[must_use]
pub fn requires_repair(code: Option<u8>) -> bool {
    matches!(code, Some(EXIT_NO_AUTH) | Some(EXIT_REVOKED))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_codes_are_unique() {
        let mut seen = ALL;
        seen.sort_unstable();
        for pair in seen.windows(2) {
            assert_ne!(pair[0], pair[1], "退出码必须唯一，否则宿主无法区分语义");
        }
    }

    #[test]
    fn ok_never_restarts() {
        assert!(!should_restart(Some(EXIT_OK)), "用户主动停止不该被擅自拉起");
    }

    #[test]
    fn retryable_restarts() {
        assert!(should_restart(Some(EXIT_RETRYABLE)));
    }

    #[test]
    fn terminal_codes_never_restart() {
        for code in [
            EXIT_NO_AUTH,
            EXIT_REVOKED,
            EXIT_REPLACED,
            EXIT_PROTOCOL_MISMATCH,
        ] {
            assert!(
                !should_restart(Some(code)),
                "终止性退出码 {code} 重启只会造成无效循环"
            );
        }
    }

    #[test]
    fn unknown_and_signal_do_not_restart() {
        assert!(
            !should_restart(None),
            "被信号终止时无法判断原因，默认不重启"
        );
        assert!(!should_restart(Some(99)), "未知码默认不重启（fail-closed）");
    }

    #[test]
    fn repair_only_for_token_failures() {
        assert!(requires_repair(Some(EXIT_REVOKED)));
        assert!(requires_repair(Some(EXIT_NO_AUTH)));
        assert!(
            !requires_repair(Some(EXIT_RETRYABLE)),
            "网络问题不该清掉令牌"
        );
        assert!(!requires_repair(Some(EXIT_OK)));
        assert!(!requires_repair(None));
    }

    #[test]
    fn restart_and_repair_are_mutually_exclusive() {
        // 一个退出码不可能既「该重启」又「该清令牌重新配对」——两者动作矛盾。
        for code in ALL {
            let (r, p) = (should_restart(Some(code)), requires_repair(Some(code)));
            assert!(!(r && p), "退出码 {code} 同时要求重启与重新配对，语义冲突");
        }
    }
}
