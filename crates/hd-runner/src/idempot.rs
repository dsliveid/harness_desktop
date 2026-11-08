//! 幂等缓存：「断线重派只回放，不重跑」（设计文档 §16，端侧副作用不可执行两次）。
//!
//! ## 为什么必须有这一层
//!
//! 连接抖动时服务端会把同一个 `tool_event_id` 的派发帧再发一遍（`attempt` 递增）。
//! 若端侧照单全收，用户就会看到「点一次、建了两个目录」这类事故。幂等**不能**靠
//! executor 自觉实现——第三个 executor 一定会漏；必须放在路由层，因为路由层是
//! **所有**工具的唯一必经之路（`router.rs` 的 `dispatch` 第一件事就是查这里）。
//!
//! ## 两个刻意的设计
//!
//! - **时钟可注入**（[`Clock`]）：TTL 是 24 小时，测试不可能真等一天。把时钟做成
//!   依赖后，单测里把时间往前拨 25 小时就能验证过期，且一个毫秒都不用 sleep。
//! - **容量上限 + 淘汰最旧**：缓存全在内存里，任其增长就是一条缓慢的内存泄漏。
//!   4096 条对小结果体（单条约几十字节到几 KB）是桌面进程完全可接受的水位。
//!
//! ## 为什么用 `std::sync::Mutex` 而不是 `tokio::sync::Mutex`
//!
//! 临界区里只有哈希表操作，**没有任何 `.await`**；用异步锁反而要求调用方 `await`
//! 一个本来瞬时完成的动作，并在持锁期间禁止跨 await（否则可能死锁）。
//!
//! ## 🔴 「已完成缓存」不够用：还需要「在飞占位」（防并发双跑）
//!
//! 只做 `get` → 执行 → `put` 的缓存，**挡不住并发**：
//!
//! ```text
//! 时刻 t1  帧A: get(id) == None
//! 时刻 t2  帧B: get(id) == None      ← 两个都读到空，都会去执行
//! 时刻 t3  A 执行完 put(id)
//! 时刻 t4  B 也执行完 put(id)        ← 副作用发生了两次
//! ```
//!
//! 断线重派是**串行**的（旧连接死了新连接才重派），缓存足够；但服务端在两条通道
//! 之间重派、或本地并发派发时，两帧可以同时在手上 —— 那时缓存形同虚设。
//!
//! 因此本模块额外维护一个 `claims` 集合（在飞占位），[`IdempotStore::claim`] 在
//! **同一把锁内**完成「查缓存 → 查占位 → 写入占位」三步，保证 N 个并发调用者
//! 里**恰好一个**拿到 `Acquired`，其余拿到 `Cached`（已有终态）或 `InFlight`
//! （别人正在跑）。原子性来自单调的 `Mutex` 临界区，而不是任何时序巧合。

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use hd_protocol::payload::TaskResultPayload;

/// 默认 TTL：24 小时。要长于服务端「同一次派发可能重试的窗口」，又要短到
/// 不会让缓存成为长期隐私留存（结果体里可能有用户目录名）。
pub const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// 默认容量上限。
pub const DEFAULT_CAPACITY: usize = 4096;

/// 可注入时钟。
///
/// 只要求 `now`，因为缓存判定只需要「当前时刻」这一个能力；让 trait 长得更小，
/// 测试实现（[`tests::ManualClock`]）也就更短。
pub trait Clock: Send + Sync {
    /// 当前时刻。
    fn now(&self) -> SystemTime;
}

/// 生产用时钟。
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// 一条缓存记录。
struct Entry {
    /// 已序列化语义的终态结果（直接存类型而非 JSON 串：回放时不必再解析）。
    result: TaskResultPayload,
    /// 写入时刻（用注入时钟取的，便于测试回拨）。
    stored_at: SystemTime,
    /// 写入序号。容量淘汰按它判「最旧」而不是按 `stored_at`：
    /// 时钟被回拨时 `stored_at` 会失去单调性，序号不会。
    seq: u64,
}

impl Entry {
    fn is_expired(&self, now: SystemTime, ttl: Duration) -> bool {
        match now.duration_since(self.stored_at) {
            // 时钟回拨（now 早于 stored_at）：视为未过期。
            // 宁可多留一会儿，也不要因为一次 NTP 校正把幂等记录全判过期 ——
            // 那会直接退化成「重派就重跑」。容量上限兜住了这种情况的内存风险。
            Err(_) => false,
            Ok(age) => age >= ttl,
        }
    }
}

/// 哈希表 + 序号计数器 + 在飞占位集合（锁保护的整体）。
struct Inner {
    map: HashMap<String, Entry>,
    /// 正在执行中的 id（防并发双跑）。与 `map` 共用一把锁，是 claim 原子性的来源。
    claims: HashSet<String>,
    seq: u64,
}

/// [`IdempotStore::claim`] 的判定结果。
///
/// 抢到执行权时**直接给出** [`ClaimGuard`]（而不是一个裸 bool），因为「占位」
/// 与「释放义务」是同一次决策的两面：把它们拆成两个调用，一定会有人在
/// `executor` 出错的分支上忘记 `release`，占位泄漏后该 id 永久返回 `InFlight`。
#[derive(Debug)]
pub enum ClaimResult {
    /// 抢占成功，**调用方是唯一有权执行该 id 的人**。执行完必须
    /// [`IdempotStore::put`]；guard 的 `Drop` 会自动释放占位（panic 也覆盖）。
    Acquired(ClaimGuard),
    /// 已有终态结果，直接回放，不得再执行。
    Cached(TaskResultPayload),
    /// 另一个并发派发正在执行同一个 id。调用方应等待其终态。
    InFlight,
}

impl ClaimResult {
    /// 是否拿到执行权。
    pub fn is_acquired(&self) -> bool {
        matches!(self, ClaimResult::Acquired(_))
    }
}

/// 占位守卫：`Drop` 时自动 [`IdempotStore::release`]。
///
/// 为什么需要它：executor 里若有 `panic!`（或超时后 future 被 drop），
/// 显式 `release` 那一行永远执行不到，占位就会**永久泄漏** —— 之后同一个
/// `tool_event_id` 的任何重派都会得到 `InFlight`，任务从此卡死。
/// 把释放绑定到 `Drop` 上，panic / 取消（future drop）两条路径都会自动清理。
pub struct ClaimGuard {
    store: Arc<IdempotStore>,
    id: String,
    /// 显式放弃控制权，避免在「已 release」后被 Drop 二次释放（虽无害但语义混乱）。
    armed: bool,
}

impl ClaimGuard {
    /// 主动释放（正常路径：结果已 `put` 进去）。
    pub fn release(mut self) {
        self.armed = false;
        self.store.release(&self.id);
    }

    /// 被占位的 id。
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        if self.armed {
            // panic / 取消路径：静默释放，让后续重派还能重新执行
            self.store.release(&self.id);
        }
    }
}

impl fmt::Debug for ClaimGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaimGuard")
            .field("id", &self.id)
            .field("armed", &self.armed)
            .finish()
    }
}

/// 幂等缓存。
pub struct IdempotStore {
    inner: Mutex<Inner>,
    ttl: Duration,
    capacity: usize,
    clock: Arc<dyn Clock>,
}

/// 手写 `Debug`：`dyn Clock` 不实现 `Debug`，且缓存内容（结果体）不该进日志。
impl fmt::Debug for IdempotStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.lock().map.len();
        f.debug_struct("IdempotStore")
            .field("len", &len)
            .field("capacity", &self.capacity)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl IdempotStore {
    /// 全参数构造（测试与特殊部署用）。
    pub fn new(capacity: usize, ttl: Duration, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                claims: HashSet::new(),
                seq: 0,
            }),
            // 容量至少为 1：为 0 的缓存等于「每次重派都重跑」，那是个静默的语义漏洞，
            // 不如把它夹到最小值，让调用方的错配置变成「略紧」而不是「失效」。
            capacity: capacity.max(1),
            ttl,
            clock,
        }
    }

    /// 生产默认：4096 容量 + 24h TTL + 系统时钟。
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_CAPACITY, DEFAULT_TTL, Arc::new(SystemClock))
    }

    /// 查询已完成的终态。
    ///
    /// 命中过期项时**顺手删除**：否则过期垃圾要等下一次容量淘汰才会走，
    /// 而容量淘汰触发的前提是「已经满了」，等于过期项会一直占着名额。
    pub fn get(&self, id: &str) -> Option<TaskResultPayload> {
        let now = self.clock.now();
        let mut inner = self.lock();
        match inner.map.get(id) {
            None => None,
            Some(e) if e.is_expired(now, self.ttl) => {
                inner.map.remove(id);
                None
            }
            Some(e) => Some(e.result.clone()),
        }
    }

    /// 写入（或覆盖）一个终态结果。
    ///
    /// 覆盖同一 id 不占额外名额：重跑同一事件（理论上不该发生，但防御）只应让结果更新，
    /// 而不是把别的历史记录挤出去。
    pub fn put(&self, id: String, result: TaskResultPayload) {
        let now = self.clock.now();
        let mut inner = self.lock();
        if !inner.map.contains_key(&id) && inner.map.len() >= self.capacity {
            // 淘汰最旧的一条（按序号）。`min_by_key` 而不是 `BTreeMap`：
            // 只在满载时才走这条线性扫描，4096 次比较的代价远小于维护第二份索引的复杂度。
            let victim = inner
                .map
                .iter()
                .min_by_key(|(_, e)| e.seq)
                .map(|(k, _)| k.clone());
            if let Some(victim) = victim {
                inner.map.remove(&victim);
            }
        }
        inner.seq += 1;
        let seq = inner.seq;
        inner.map.insert(
            id,
            Entry {
                result,
                stored_at: now,
                seq,
            },
        );
    }

    /// 🔴 抢占执行权（**防并发双跑**，不是单纯缓存查询）。
    ///
    /// 「查缓存 → 查在飞占位 → 写入占位」三步在**同一个 `Mutex` 临界区内完成**，
    /// 因此 N 个并发调用者里**有且仅有一个**得到 [`ClaimResult::Acquired`]：
    ///
    /// ```text
    /// 帧A ─┐                    ┌─ Acquired（去执行）
    ///      ├─ lock() 排队 ──────┤
    /// 帧B ─┘                    └─ InFlight（等结果）
    /// ```
    ///
    /// 与 `get` 的关键差别：`get` 只回答「跑完了吗」，本方法回答「**现在由谁跑**」。
    /// 并发派发下两者必须具备原子性差异，否则两个调用者都会拿到 `None` 然后都去执行。
    ///
    /// 🚫 刻意**不**提供「返回裸 bool 的 claim 再单独 release」这种两段式 API：
    /// 那样一定有人在出错分支漏掉 release，占位泄漏 → 该 id 永久 `InFlight`。
    /// 这里把执行权与释放义务打包成一个 [`ClaimGuard`]。
    pub fn claim(self: &Arc<Self>, id: &str) -> ClaimResult {
        let now = self.clock.now();
        let ttl = self.ttl;
        let mut inner = self.lock();

        // 1) 已完成 → 回放（顺手清理过期项，与 get 同口径）
        if let Some(e) = inner.map.get(id) {
            if e.is_expired(now, ttl) {
                inner.map.remove(id);
            } else {
                return ClaimResult::Cached(e.result.clone());
            }
        }

        // 2) 有人在跑 → 拒绝（这是并发双跑的**唯一**拦截点）
        if inner.claims.contains(id) {
            return ClaimResult::InFlight;
        }

        // 3) 占位成功。返回 guard 而非裸 bool：让释放在 Drop 里兜底。
        inner.claims.insert(id.to_string());
        ClaimResult::Acquired(ClaimGuard {
            store: Arc::clone(self),
            id: id.to_string(),
            armed: true,
        })
    }

    /// 释放在飞占位。结果已经 [`IdempotStore::put`] 之后调用。
    ///
    /// 重复释放是无害的（`HashSet::remove` 幂等），因为 panic 路径 + 显式路径
    /// 有可能都想释放一次。
    pub fn release(&self, id: &str) {
        self.lock().claims.remove(id);
    }

    /// 当前在飞（执行中）的任务数，供观测/自检。
    pub fn in_flight(&self) -> usize {
        self.lock().claims.len()
    }

    /// 清理所有过期项，返回清理条数（供自检/巡检任务调用）。
    pub fn sweep(&self) -> usize {
        let now = self.clock.now();
        let ttl = self.ttl;
        let mut inner = self.lock();
        let before = inner.map.len();
        inner.map.retain(|_, e| !e.is_expired(now, ttl));
        before - inner.map.len()
    }

    /// 当前条目数（含尚未清扫的过期项），供观测使用。
    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 取锁：仅防「持锁线程 panic 导致整个 Runner 后续派发全部失败」。
    /// 缓存不参与一致性保证，毒化后继续用旧数据是安全的（最坏是少回放一次）。
    fn lock(&self) -> MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use hd_protocol::payload::{SourceTrust, TaskResultPayload};

    use super::*;

    /// 手动时钟：测试自己决定「现在几点」，从而零等待验证 24h TTL。
    struct ManualClock {
        offset_ms: AtomicU64,
    }

    impl ManualClock {
        fn new() -> Self {
            Self {
                offset_ms: AtomicU64::new(0),
            }
        }

        fn advance(&self, d: Duration) {
            self.offset_ms
                .fetch_add(d.as_millis() as u64, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH + Duration::from_millis(self.offset_ms.load(Ordering::SeqCst))
        }
    }

    fn result_for(id: &str) -> TaskResultPayload {
        TaskResultPayload {
            task_id: id.to_string(),
            run_id: "run-1".to_string(),
            tool_event_id: id.to_string(),
            status: "success".to_string(),
            result: Some(serde_json::json!({ "id": id })),
            error: String::new(),
            source_trust: SourceTrust::Untrusted,
        }
    }

    fn store_with_clock() -> (IdempotStore, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new());
        let store = IdempotStore::new(8, Duration::from_secs(24 * 60 * 60), clock.clone());
        (store, clock)
    }

    #[test]
    fn put_then_get_returns_same_result() {
        let (store, _clock) = store_with_clock();
        store.put("evt-1".to_string(), result_for("evt-1"));
        let got = store.get("evt-1").expect("写入后必须能取到");
        assert_eq!(got.status, "success");
        assert_eq!(got.tool_event_id, "evt-1");
        assert_eq!(got.source_trust, SourceTrust::Untrusted);
    }

    #[test]
    fn missing_id_returns_none() {
        let (store, _clock) = store_with_clock();
        assert!(store.get("nope").is_none());
    }

    #[test]
    fn expired_entry_is_not_returned_and_is_dropped() {
        let (store, clock) = store_with_clock();
        store.put("evt-1".to_string(), result_for("evt-1"));
        // TTL 恰好 24h：拨到 24h 那一刻就该判过期（`>=`，不留边界模糊）
        clock.advance(DEFAULT_TTL);
        assert!(store.get("evt-1").is_none(), "过期后不得回放");
        assert_eq!(store.len(), 0, "取到过期项时应顺手删除");
    }

    #[test]
    fn fresh_entry_survives_before_ttl() {
        let (store, clock) = store_with_clock();
        store.put("evt-1".to_string(), result_for("evt-1"));
        clock.advance(DEFAULT_TTL - Duration::from_secs(1));
        assert!(store.get("evt-1").is_some(), "TTL 内必须仍可回放");
    }

    #[test]
    fn sweep_removes_only_expired() {
        let (store, clock) = store_with_clock();
        store.put("old".to_string(), result_for("old"));
        clock.advance(DEFAULT_TTL - Duration::from_secs(60));
        store.put("new".to_string(), result_for("new"));
        clock.advance(Duration::from_secs(61)); // old 过期 1s，new 还差 59s

        let removed = store.sweep();

        assert_eq!(removed, 1, "只该清理掉 old");
        assert!(store.get("old").is_none());
        assert!(store.get("new").is_some());
        assert_eq!(store.len(), 1);
        // 再扫一次无可清理
        assert_eq!(store.sweep(), 0);
    }

    #[test]
    fn capacity_limit_evicts_oldest() {
        let clock = Arc::new(ManualClock::new());
        let store = IdempotStore::new(3, DEFAULT_TTL, clock);
        for i in 0..5 {
            let id = format!("evt-{i}");
            store.put(id.clone(), result_for(&id));
        }
        assert_eq!(store.len(), 3, "容量上限必须生效，不能无限增长");
        assert!(store.get("evt-0").is_none(), "最旧的应被淘汰");
        assert!(store.get("evt-1").is_none());
        assert!(store.get("evt-2").is_some());
        assert!(store.get("evt-4").is_some());
    }

    #[test]
    fn overwriting_same_id_does_not_consume_extra_slot() {
        let clock = Arc::new(ManualClock::new());
        let store = IdempotStore::new(2, DEFAULT_TTL, clock);
        store.put("a".to_string(), result_for("a"));
        store.put("b".to_string(), result_for("b"));
        // 覆盖 a：条目数不该涨，b 也不该被挤出去
        store.put("a".to_string(), result_for("a"));
        assert_eq!(store.len(), 2);
        assert!(store.get("b").is_some());
        assert!(store.get("a").is_some());
    }

    #[test]
    fn different_ids_do_not_interfere() {
        let (store, _clock) = store_with_clock();
        store.put("a".to_string(), result_for("a"));
        store.put("b".to_string(), result_for("b"));
        assert_eq!(
            store.get("a").expect("a 应存在").tool_event_id,
            "a".to_string()
        );
        assert_eq!(
            store.get("b").expect("b 应存在").tool_event_id,
            "b".to_string()
        );
    }

    #[test]
    fn clock_rollback_does_not_expire_entries() {
        // 用户的钟被 NTP 往回校了一次：此时不能把幂等记录判成过期，
        // 否则「重派」立刻退化为「重跑」。
        let (store, clock) = store_with_clock();
        clock.advance(Duration::from_secs(3600));
        store.put("evt-1".to_string(), result_for("evt-1"));
        clock.advance(Duration::from_secs(0)); // 保持不动
        let rolled_back = Arc::new(ManualClock::new()); // 新钟从 0 开始 = 回拨 1h
        let store2 = IdempotStore::new(8, DEFAULT_TTL, rolled_back);
        store2.put("evt-1".to_string(), result_for("evt-1"));
        assert!(store2.get("evt-1").is_some());
        assert!(store.get("evt-1").is_some());
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let clock = Arc::new(ManualClock::new());
        let store = IdempotStore::new(0, DEFAULT_TTL, clock);
        store.put("a".to_string(), result_for("a"));
        store.put("b".to_string(), result_for("b"));
        assert_eq!(store.len(), 1, "容量 0 被夹到 1，而不是彻底丢掉缓存");
        assert!(store.get("b").is_some());
    }

    // ------------------------------------------------------------------
    // 在飞占位（防并发双跑）
    // ------------------------------------------------------------------

    /// 🔴 核心用例：两个「并发」claim 只能有一个成功。
    ///
    /// 用多线程真并发（而非顺序调用）来断言，因为要抓的正是「两个读同时发生在
    /// 写入之前」这个竞态；顺序调用的测试对 claim 的实现毫无约束力。
    #[test]
    fn concurrent_claim_allows_exactly_one_winner() {
        use std::sync::Barrier;

        let clock = Arc::new(ManualClock::new());
        let store = Arc::new(IdempotStore::new(64, DEFAULT_TTL, clock));

        const THREADS: usize = 8;
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();

        for _ in 0..THREADS {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                // 屏障让 8 个线程尽可能同时冲进 claim，最大化撞车概率
                barrier.wait();
                match store.claim("evt-race") {
                    // 🔴 必须把 guard **带出线程**持有到 join 之后：
                    // 若让它在 if 表达式结束时被 drop，占位就会被立刻释放，
                    // 后面的线程自然能再次抢到 —— 那样测的就不是并发互斥了。
                    ClaimResult::Acquired(g) => Some(g),
                    _ => None,
                }
            }));
        }

        // 先收集全部 guard（此期间占位一直有效），再统计赢家数量。
        let winners: Vec<_> = handles
            .into_iter()
            .filter_map(|h| h.join().expect("线程不应 panic"))
            .collect();

        assert_eq!(
            winners.len(),
            1,
            "8 个并发 claim 里必须恰好 1 个赢家，否则同一副作用会被执行多次"
        );
        assert_eq!(store.in_flight(), 1);
    }

    /// 结果落盘后，重派得到的是回放而不是 `InFlight`。
    #[test]
    fn claim_after_put_replays_instead_of_in_flight() {
        let clock = Arc::new(ManualClock::new());
        let store = Arc::new(IdempotStore::new(8, DEFAULT_TTL, clock));

        let guard = match store.claim("evt-1") {
            ClaimResult::Acquired(g) => g,
            other => panic!("首次 claim 必须成功，实际: {other:?}"),
        };
        // 执行中再来一次 → InFlight
        assert!(matches!(store.claim("evt-1"), ClaimResult::InFlight));

        store.put("evt-1".to_string(), result_for("evt-1"));
        guard.release();
        assert_eq!(store.in_flight(), 0, "释放后不应残留占位");

        match store.claim("evt-1") {
            ClaimResult::Cached(r) => assert_eq!(r.tool_event_id, "evt-1"),
            other => panic!("已有终态时必须回放，实际: {other:?}"),
        }
    }

    /// `ClaimGuard` 被 drop（等价于 executor panic / future 取消）时必须自动
    /// 释放占位，否则该 id 会永久卡在 `InFlight`（「重启 Runner 才能用」的玄学故障）。
    #[test]
    fn dropping_claim_guard_releases_placeholder() {
        let clock = Arc::new(ManualClock::new());
        let store = Arc::new(IdempotStore::new(8, DEFAULT_TTL, clock));

        {
            let _g = match store.claim("evt-panic") {
                ClaimResult::Acquired(g) => g,
                other => panic!("首次 claim 必须成功，实际: {other:?}"),
            };
            assert_eq!(store.in_flight(), 1);
        } // ← guard 在这里 drop

        assert_eq!(store.in_flight(), 0, "Drop 必须自动释放占位");
        assert!(
            store.claim("evt-panic").is_acquired(),
            "崩溃后重派必须还能重新执行（占位不能泄漏）"
        );
    }

    /// 不同 id 互不干扰：一个在飞不影响另一个 claim。
    #[test]
    fn claims_of_different_ids_are_independent() {
        let clock = Arc::new(ManualClock::new());
        let store = Arc::new(IdempotStore::new(8, DEFAULT_TTL, clock));

        let _a = match store.claim("evt-a") {
            ClaimResult::Acquired(g) => g,
            other => panic!("evt-a 应成功，实际: {other:?}"),
        };
        let _b = match store.claim("evt-b") {
            ClaimResult::Acquired(g) => g,
            other => panic!("不同 id 必须能并行执行，实际: {other:?}"),
        };
        assert_eq!(store.in_flight(), 2);
    }
}
