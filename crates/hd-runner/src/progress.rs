//! 进度流式通道：把 executor 的**同步** `chunk` 调用接到 async 侧。
//!
//! ## 为什么必须这么做
//!
//! `hd_core::ProgressSink::chunk(&self, &str)` 是**同步**方法（executor 在 stdout
//! 边读边吐，调用点不可能 `await`）。而真正的出口是一条 **async** 的 WS 连接，
//! `send_frame` 必须 `&mut self` 且要 `await`。
//!
//! 两者之间必须有一个缓冲：executor 同步塞、会话循环异步取。这就是本模块。
//!
//! ## 🔴 为什么是 `UnboundedSender` 而不是 bounded + `try_send` / `blocking_send`
//!
//! 三条路都有坑，逐一排除：
//!
//! | 方案 | 后果 |
//! | --- | --- |
//! | `bounded::Sender::blocking_send` | 在 tokio runtime 线程里调用会 **panic**（`blocking_send` 明确禁止 runtime 内使用），而 `chunk` 恰恰就在 runtime 线程上被调 |
//! | `bounded::Sender::try_send` | 缓冲满了就**丢块**。长任务（例如 `git clone` 输出）丢块等于「进度条卡住不动」——功能静默失效，比崩还难查 |
//! | `UnboundedSender::send` | 同步、非阻塞、不丢块。✅ |
//!
//! 选无界的代价是「生产者不受背压」，但进度块的单条体积很小（几十字节到几 KB），
//! 且**唯一的消费者是同一条会话循环**，它一有机会就把块发出去。真正的内存风险
//! 来自「executor 疯狂吐块而网络写不动」，那种情况下有界队列也只是把「内存涨」
//! 换成「静默丢进度」，不如让内存短暂上涨（连接断了整个 channel 就随之释放）。
//!
//! ## 失败语义：receiver 被 drop 之后
//!
//! 会话结束时出站队列会被丢弃，此后 executor 若还在跑并继续 `chunk`，
//! `send` 会返回 `Err`。这里**故意忽略**这个错误：`chunk` 的签名没有返回值，
//! 它无法把"发不出去"告诉任何人；而 panic 会让一个已经结束的会话连带把
//! executor 任务打挂（JoinSet 里 panic 会污染整棵任务树）。丢掉一条无人接收的
//! 进度块是这里唯一正确的选择。

use hd_core::ProgressSink;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// 基于 mpsc 的进度出口。
///
/// 本身只是一个「发送端包装」：克隆它就能给多个执行上下文共用同一个通道
/// （`ProgressSink` 只要求 `&self`，所以内部必须是可共享的）。
#[derive(Debug, Clone)]
pub struct ChannelSink {
    tx: UnboundedSender<String>,
}

impl ChannelSink {
    /// 建一对（sink, receiver）。
    ///
    /// 返回的是未装箱的 `UnboundedReceiver`：调用方通常立刻把它塞进
    /// `tokio::select!` 与执行 future一起轮询，中间不需要任何适配层。
    pub fn new() -> (Self, UnboundedReceiver<String>) {
        let (tx, rx) = unbounded_channel();
        (Self { tx }, rx)
    }
}

impl ProgressSink for ChannelSink {
    fn chunk(&self, s: &str) {
        // 见模块注释「失败语义」：receiver 已 drop 表示会话结束，静默忽略。
        // 用 `let _ =` 而不是 `unwrap`，是因为这条路径**允许**失败。
        let _ = self.tx.send(s.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn chunk_is_received_in_order() {
        let (sink, mut rx) = ChannelSink::new();

        // 同步连续灌三条：验证「chunk 是同步非阻塞」这件事本身 ——
        // 若这里用了 blocking_send，在 #[tokio::test] 的 runtime 里会直接 panic。
        sink.chunk("a");
        sink.chunk("b");
        sink.chunk("c");

        let mut got = Vec::new();
        for _ in 0..3 {
            got.push(rx.recv().await.expect("必须收到块"));
        }
        assert_eq!(got, vec!["a", "b", "c"], "进度块必须保序（拼起来才是原文）");
    }

    #[tokio::test]
    async fn chunk_after_receiver_dropped_does_not_panic() {
        let (sink, rx) = ChannelSink::new();
        drop(rx);

        // 会话已结束、executor 还在跑：这里绝不能 panic（见模块注释失败语义）
        sink.chunk("迟到的块");

        // 再确认 sink 仍可继续被调用（不是「崩一次就废」）
        let cloned = sink.clone();
        cloned.chunk("再来一条");
    }

    #[tokio::test]
    async fn sink_is_shareable_across_clones() {
        // Guarded 会把 &dyn ProgressSink 往里传，多工具并发时可能各自持有一份克隆，
        // 必须保证它们写进的是**同一个**通道（否则进度会分裂到多个无人消费的队列）。
        let (sink, mut rx) = ChannelSink::new();
        let a = sink.clone();
        let b = sink.clone();
        a.chunk("from-a");
        b.chunk("from-b");

        let mut got = vec![
            rx.recv().await.expect("应收到 a 的块"),
            rx.recv().await.expect("应收到 b 的块"),
        ];
        got.sort();
        assert_eq!(got, vec!["from-a", "from-b"]);
    }
}
