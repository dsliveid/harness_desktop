//! 设备能力申报（`hello` / `ping` 帧的能力清单与摘要）。
//!
//! ## 为什么单独一个模块
//!
//! 服务端要靠「端侧申报了什么能力」来决定把哪些任务派给这台设备（目录列举就是
//! `fs.list`）。申报一旦与实际注册的工具脱节，就会重现一类极难排查的故障：
//! **端侧明明注册了 executor，服务端却认为该设备不支持**，于是永远不派发。
//!
//! 因此本模块的唯一数据源是 [`Router::tool_names`]，**不维护任何手写的能力常量数组**。
//! 注册新工具后能力集自动跟着变，hash 也随之变化，服务端据此触发重拉。
//!
//! ## 两道闸门
//!
//! 1. **派生而非硬编码**：`capabilities_of` 只读 Router，读不到 Router 里没有的工具。
//! 2. **白名单过滤**：并非所有本地工具都应该对外通报（有些只供内部链路使用，或
//!    暴露出去会成为攻击面提示）。白名单集中在 [`EXPOSED_TOOLS`]，新增工具若
//!    需要申报必须显式加进去 —— 这个「显式」是刻意的，加一行代码 + 写一条注释，
//!    比「忘了申报」容易在评审里被看见。
//!
//! ## hash 为什么自己手写
//!
//! 需求是「同集合不同顺序 → 同 hash；增删一项 → hash 变」。这是一个纯确定性的
//! 字符串摘要问题，FNV-1a 64bit 足够，且不需要为它引入 `sha2` 这类依赖进端侧
//! 二进制（端侧分发包体积是硬指标）。算法与样例值写死在单测里，改动即红。

use hd_protocol::payload::Capability;

use crate::router::Router;

/// 对外申报的工具白名单。
///
/// 🔴 只列「服务端物理上做不到、且暴露出去无副作用」的工具：
/// - `fs.list`：列举白名单内的子目录（只读目录名、不读文件内容、跳过软链），
///   是工作区目录选择的必要能力。服务端本身跑在服务器上，看不到用户机器的目录，
///   故必须由端侧提供。
///
/// 未列入的工具（如将来可能出现的 `fs.read` / `process`）**不会**出现在能力清单里：
/// 对外通报即等于向服务端与日志暴露本机可执行面，需要单独评审后再加。
const EXPOSED_TOOLS: &[&str] = &["fs.list"];

/// 所有对外能力的版本号。
///
/// 与 Go 侧参考实现（`cmd/device-e2e/client.go` 的 `fs.read@1.0` 风格）保持一致：
/// 版本变化意味着**语义**变化，服务端可据此拒绝跨版本的派发。
const CAPABILITY_VERSION: &str = "1.0";

/// hash 前缀：说明摘要算法，便于服务端/排障时一眼看出这是什么。
///
/// 服务端只做「字符串是否相等」的比较，前缀不参与语义，但能避免把 16 位 hex
/// 误读成 `sha256:` 截断值。
const HASH_PREFIX: &str = "fnv1a64:";

/// 从 Router 已注册工具派生能力清单。
///
/// 输出按 `name` 升序（稳定顺序便于断言与日志比对）；`device_id` 留空
/// （端侧上报时不知道自己的服务端分配 ID），`updated_at` 固定 0
/// （与 Go 侧 `omitempty` 缺失语义一致）。
pub fn capabilities_of(router: &Router) -> Vec<Capability> {
    let mut caps: Vec<Capability> = router
        .tool_names()
        .into_iter()
        // 🔴 白名单过滤：Router 里有的 ≠ 对外通报的。
        .filter(|name| EXPOSED_TOOLS.contains(name))
        .map(|name| Capability {
            device_id: String::new(),
            name: name.to_string(),
            version: CAPABILITY_VERSION.to_string(),
            updated_at: 0,
        })
        .collect();
    caps.sort_by(|a, b| a.name.cmp(&b.name));
    caps.dedup_by(|a, b| a.name == b.name);
    caps
}

/// 计算能力清单摘要，形如 `fnv1a64:1a2b3c4d5e6f7788`。
///
/// 不变式（均有单测钉死）：
/// - 集合相同、顺序不同 → 同 hash；
/// - 增/删任意一项 → hash 变化；
/// - 空集合有确定值（FNV-1a 64 的 offset basis）且不 panic。
///
/// 实现要点：先对 `name@version` 排序再逐个喂字节，每项之间插入 `0x1f`
/// 分隔符 —— 否则 `("ab","c")` 与 `("a","bc")` 这类拼接歧义会撞出同一个 hash。
pub fn capabilities_hash(caps: &[Capability]) -> String {
    let mut items: Vec<String> = caps
        .iter()
        .map(|c| format!("{}@{}", c.name, c.version))
        .collect();
    items.sort_unstable();

    let mut h: u64 = FNV_OFFSET_BASIS;
    for item in &items {
        for b in item.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(FNV_PRIME);
        }
        h ^= u64::from(0x1f_u8);
        h = h.wrapping_mul(FNV_PRIME);
    }
    format!("{HASH_PREFIX}{h:016x}")
}

/// 由 Router 一步算出清单与摘要（`hello` / `ping` 都从这里取，保证两者恒等）。
pub fn snapshot(router: &Router) -> (Vec<Capability>, String) {
    let caps = capabilities_of(router);
    let hash = capabilities_hash(&caps);
    (caps, hash)
}

/// FNV-1a 64bit 的 offset basis。
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64bit 的质数。
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use hd_core::{
        AuditSink, ExecCtx, ExecError, ExecOutput, Executor, Limits, Policy, ProgressSink,
    };

    use super::*;
    use crate::idempot::IdempotStore;

    /// 只申报名、不做任何事的假 executor（用来验证「派生自 Router」）。
    struct NamedTool(&'static str);

    #[async_trait]
    impl Executor for NamedTool {
        fn tool_name(&self) -> &'static str {
            self.0
        }

        fn limits(&self) -> Limits {
            Limits {
                timeout: std::time::Duration::from_secs(1),
                max_output_bytes: 1024,
            }
        }

        async fn execute(
            &self,
            _ctx: &ExecCtx,
            _args: &serde_json::Value,
            _sink: &dyn ProgressSink,
        ) -> Result<ExecOutput, ExecError> {
            Ok(ExecOutput::untrusted(serde_json::Value::Null))
        }
    }

    fn empty_router() -> Router {
        Router::new(
            Arc::new(Policy::new(Vec::new(), Vec::new())),
            Arc::new(hd_core::NullAuditSink) as Arc<dyn AuditSink>,
            Arc::new(IdempotStore::with_defaults()),
        )
    }

    fn cap(name: &str, version: &str) -> Capability {
        Capability {
            device_id: String::new(),
            name: name.to_string(),
            version: version.to_string(),
            updated_at: 0,
        }
    }

    #[test]
    fn fs_list_is_reported_when_registered() {
        // 用真实 ListDirsExecutor：它就是 cli.rs 里注册的那个，名字必须一致。
        let policy = Arc::new(Policy::new(Vec::new(), Vec::new()));
        let mut router = empty_router();
        router.register(hd_core::ListDirsExecutor::new(
            Arc::clone(&policy),
            None,
            500,
        ));

        let caps = capabilities_of(&router);
        assert_eq!(caps.len(), 1, "默认只应申报 fs.list，实际 {caps:?}");
        assert_eq!(caps[0].name, "fs.list");
        assert_eq!(caps[0].version, CAPABILITY_VERSION);
        assert!(caps[0].device_id.is_empty(), "端侧上报不带 device_id");
        assert_eq!(caps[0].updated_at, 0);
    }

    #[test]
    fn empty_router_reports_no_capability() {
        assert!(capabilities_of(&empty_router()).is_empty());
    }

    /// 🔴 关键回归：能力集必须来自 Router，而不是硬编码数组。
    ///   注册一个非白名单工具 → 清单不变；再注册 fs.list → 清单出现。
    #[test]
    fn capabilities_are_derived_from_router_not_hardcoded() {
        let mut router = empty_router();
        // 未注册任何工具时，即便白名单里有 fs.list，也不应凭空申报
        assert!(capabilities_of(&router).is_empty());

        // 注册一个白名单外的工具：不申报
        router.register(NamedTool("process"));
        assert!(
            capabilities_of(&router).is_empty(),
            "白名单外工具不得对外通报"
        );

        // 注册 fs.list：立即出现在清单里（无需改本模块任何常量）
        router.register(NamedTool("fs.list"));
        let caps = capabilities_of(&router);
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].name, "fs.list");
    }

    #[test]
    fn hash_is_order_independent() {
        let a = vec![cap("fs.list", "1.0"), cap("workspace.list", "1.0")];
        let b = vec![cap("workspace.list", "1.0"), cap("fs.list", "1.0")];
        assert_eq!(capabilities_hash(&a), capabilities_hash(&b));
    }

    #[test]
    fn hash_changes_when_capability_added_or_removed() {
        let one = vec![cap("fs.list", "1.0")];
        let two = vec![cap("fs.list", "1.0"), cap("workspace.list", "1.0")];
        assert_ne!(capabilities_hash(&one), capabilities_hash(&two));
        assert_ne!(capabilities_hash(&one), capabilities_hash(&[]));

        // 版本变化也必须改变 hash（语义变了，服务端应重拉）
        let bumped = vec![cap("fs.list", "1.1")];
        assert_ne!(capabilities_hash(&one), capabilities_hash(&bumped));
    }

    #[test]
    fn hash_of_empty_set_is_stable_and_does_not_panic() {
        let h = capabilities_hash(&[]);
        assert_eq!(h, "fnv1a64:cbf29ce484222325", "空集合 = FNV offset basis");
        assert_eq!(h, capabilities_hash(&[]));
    }

    /// 拼接歧义防护：`("ab","c")` 与 `("a","bc")` 不得撞 hash。
    #[test]
    fn hash_is_not_confused_by_concatenation_ambiguity() {
        let a = vec![cap("ab", "c")];
        let b = vec![cap("a", "bc")];
        assert_ne!(capabilities_hash(&a), capabilities_hash(&b));
    }

    #[test]
    fn hash_format_is_prefixed_16_hex() {
        let h = capabilities_hash(&[cap("fs.list", "1.0")]);
        // 钉死样例值：算法或输入编码一变，这里立刻红（服务端会看到摘要变化）
        assert_eq!(h, "fnv1a64:87e9223a0f3a6136", "仅 fs.list@1.0 的摘要");
        assert_eq!(
            capabilities_hash(&[cap("fs.list", "1.0"), cap("workspace.list", "1.0")]),
            "fnv1a64:b3b6fbc0d4054d0b",
            "新增一项后摘要必须变化"
        );
        let hex = h
            .strip_prefix("fnv1a64:")
            .unwrap_or_else(|| panic!("应以 fnv1a64: 开头，实际 {h}"));
        assert_eq!(hex.len(), 16, "应为 16 位 hex，实际 {hex}");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn snapshot_returns_consistent_pair() {
        let mut router = empty_router();
        router.register(NamedTool("fs.list"));
        let (caps, hash) = snapshot(&router);
        assert_eq!(caps, capabilities_of(&router));
        assert_eq!(hash, capabilities_hash(&caps));
    }
}
