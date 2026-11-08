//! 安全闸门：路径三闸校验、`Guarded` 包装、结果脱敏、本地审计。
//!
//! 划分原则：**executor 只管执行，安全判定一律在 security 里**。
//! 一旦把白名单判断写进某个 executor，下一个 executor 就会忘掉它——
//! 所以安全逻辑必须做成「包裹」而不是「内联」（设计文档 §16.2）。

pub mod guard;
pub mod paths;
pub mod redact;
