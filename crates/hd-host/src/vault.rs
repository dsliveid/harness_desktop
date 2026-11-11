//! 设备令牌的安全载体与 OS 密钥链存储（对齐 `docs/桌面端架构与功能设计.md` §17.1）。
//!
//! ## 三条硬性约束（写进类型系统，不靠纪律）
//!
//! 1. **令牌不以裸 `String` 流动**：一律包成 [`DeviceToken`]，它的 `Debug` 打码成
//!    `hgd_***`、**刻意不实现** `Clone` / `Display` / `Serialize`。
//!    裸 `String` 一旦在代码里四处传递，`println!` / `tracing::info!("{:?}", x)` /
//!    `serde_json::to_value` 随手一写就把长期凭证写进了日志文件或崩溃上报。
//! 2. **取出必须显式**：只有 [`DeviceToken::expose`] 能拿到 `&str`。方法名故意起得刺眼，
//!    便于 grep 出「谁真的需要明文」——合法调用点只有两处：写 runner stdin、
//!    拼 `Authorization` 头。
//! 3. **用完清零**：`Drop` 走 `zeroize`，令牌不会被释放的内存块留给后续分配复用。
//!
//! ## 为什么 vault 做成 trait
//!
//! 真实后端打的是 OS 密钥链（Windows Credential Manager / macOS Keychain），在 CI 与
//! 无桌面会话的机器上不可用，而且写入会真的落到用户密钥链里。把存储抽成
//! [`TokenVault`] 后，单测注入 [`MemoryVault`] 就能验证「读写清」语义与
//! 「不泄露」约束，不必碰真实系统资源。

use std::fmt;
use std::sync::{Arc, Mutex};

use thiserror::Error;
use zeroize::Zeroize;

/// 密钥链服务名（与 `docs/桌面端架构与功能设计.md` §17.1 约定一致）。
pub const KEYRING_SERVICE: &str = "harness_desktop";
/// 密钥链条目名。
pub const KEYRING_USER: &str = "device_token";
/// 用户会话令牌的密钥链条目名（与 [`KEYRING_USER`] 分开存放）。
///
/// 🔴 两条凭据必须**物理分离**：设备令牌证明「这台机器被授权接入」，用户令牌证明
/// 「这个人是谁、能做什么」。混在同一个条目里会导致「登出账号」不得不动设备绑定，
/// 与「登出保留绑定、解绑清空全部」的正交设计直接冲突（对齐移动端语义）。
pub const KEYRING_USER_SESSION: &str = "user_token";

/// 明文的唯一持有者：把「用完清零 / `{:?}` 打码 / 不实现 `Clone`」三条约束
/// 集中到**一处**实现，避免 [`DeviceToken`] 与 [`UserToken`] 各写一份而日后漂移
/// （安全代码的复制粘贴是最典型的漂移源：改了一处忘了另一处，另一处就成了漏点）。
struct Secret(String);

impl Secret {
    fn new(raw: String) -> Self {
        Self(raw)
    }

    fn expose(&self) -> &str {
        &self.0
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for Secret {
    /// 🔴 打码：保证 `{:?}` / `{:#?}` 都拿不到明文。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 复用 hd-runner 的规则（保留 `hgd_` 这类前缀，其余全替换），
        // 这样宿主壳与 Runner 的日志口径一致，排查时不会一边有前缀一边没有。
        f.write_str(&hd_runner::ipc::redact_token(&self.0))
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// 设备令牌的安全包装。
///
/// 刻意**不实现** `Clone`：多一份明文必须显式调用内部方法 [`DeviceToken::duplicate`]，
/// review 时能看见。也刻意不实现 `Display`/`Serialize`，堵掉顺手打印/上报的路径。
pub struct DeviceToken(Secret);

impl DeviceToken {
    /// 从原始字符串接管所有权（不复制，避免明文在内存里多留一份）。
    pub fn new(raw: String) -> Self {
        Self(Secret::new(raw))
    }

    /// 取出明文。
    ///
    /// 🔴 调用点必须只有「写 runner stdin」与「拼 Authorization 头」两处。
    /// 任何日志/错误信息/上报结构体都不许调用它。
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// 空令牌没有任何意义，且写进密钥链后会让「已配对」判断出错。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 长度（不含内容）。排障时确认「令牌被完整写入/传输」用。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 复制一份令牌。仅供 [`TokenVault`] 实现从内部存储取出值使用。
    ///
    /// 之所以是 `pub(crate)` 而不是 `Clone`：让「多一份明文」永远是一个需要显式写出的动作。
    pub(crate) fn duplicate(&self) -> Self {
        Self(self.0.duplicate())
    }
}

impl fmt::Debug for DeviceToken {
    /// 🔴 打码：保证 `{:?}` / `{:#?}` 都拿不到明文。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DeviceToken").field(&self.0).finish()
    }
}

/// 用户会话令牌的安全包装（配对响应里 `user_token` 字段）。
///
/// ## 为什么单独一个类型，而不是复用 [`DeviceToken`]
///
/// 两者用途截然不同，混用会让「谁需要明文」的 grep 失去意义：
/// - `DeviceToken` → 只给 Runner 的 `auth` 帧用（证明「这台机器被授权接入」）；
/// - `UserToken` → 只写进 WebView 的 `hg_sess` Cookie（证明「这个人是谁」），
///   Runner 永远不该拿到它。
///
/// ## 规格与 `DeviceToken` **完全一致**
///
/// zeroize 清零、手写 `Debug` 打码、不实现 `Clone`/`Display`/`Serialize`。
/// 对外只多一个 [`UserToken::expose`]，合法调用点只有「写 Cookie」一处。
pub struct UserToken(Secret);

impl UserToken {
    /// 从原始字符串接管所有权（不复制）。
    pub fn new(raw: String) -> Self {
        Self(Secret::new(raw))
    }

    /// 🔴 取出明文。唯一合法调用点：写 WebView 的 `hg_sess` Cookie。
    ///
    /// 任何日志/错误信息/进度上报都**不许**调用它 —— 用户令牌一旦落进日志，
    /// 等同于把该账号的会话直接交出去。
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// 空令牌没有意义：写进 Cookie 只会让服务端把请求当作未登录。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 长度（不含内容），排障用。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 复制一份。仅供 [`UserTokenVault`] 实现从内部存储取值使用。
    pub(crate) fn duplicate(&self) -> Self {
        Self(self.0.duplicate())
    }
}

impl fmt::Debug for UserToken {
    /// 🔴 打码：`{:?}` 拿不到明文（与 `DeviceToken` 同一口径）。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("UserToken").field(&self.0).finish()
    }
}

/// vault 层错误。
#[derive(Debug, Error)]
pub enum VaultError {
    /// 当前平台没有实现原生密钥链后端。
    #[error("当前平台 {0} 未实现密钥链后端（非 Windows/macOS），不接受明文落盘的替代方案")]
    Unsupported(&'static str),
    /// 后端读写失败（密钥链被锁、权限不足等）。
    #[error("密钥链操作失败：{0}")]
    Backend(String),
    /// 拒绝写入空令牌。
    #[error("拒绝写入空令牌：空值会让「是否已配对」判断失真")]
    EmptyToken,
}

/// 令牌存储抽象（可注入，便于单测）。
///
/// `Send + Sync` 是硬要求：它会挂在 Tauri 的 `State` 里被多线程 command 并发访问。
pub trait TokenVault: Send + Sync {
    /// 读取令牌；`Ok(None)` 表示「未配对」，与「读失败」严格区分。
    fn get(&self) -> Result<Option<DeviceToken>, VaultError>;
    /// 写入（覆盖）令牌。
    fn set(&self, token: &DeviceToken) -> Result<(), VaultError>;
    /// 清除令牌（解除配对）。条目本就不存在时视为成功。
    fn clear(&self) -> Result<(), VaultError>;
}

/// 用户会话令牌的存储抽象（**与 [`TokenVault`] 分离**，见 [`KEYRING_USER_SESSION`] 的文档）。
///
/// ## 为什么是独立 trait 而不是给 `TokenVault` 加两个方法
///
/// 1. **正交语义**：登出（清用户令牌）与解绑（清设备令牌）是两个不同动作。
///    合成一个 trait 后，「只清用户令牌」必须新增一个 `clear_user()`，
///    而所有既有实现方与单测都要跟着改；分成两个 trait 则各自独立演进。
/// 2. **注入粒度**：`Bootstrap` 只需要设备令牌（Runner 的 `auth` 帧），
///    把用户令牌也塞给它等于扩大「谁能读会话凭据」的范围。
///    两条凭据两条通道，是最小权限的直接体现。
///
/// `Send + Sync` 同样是硬要求（挂在 Tauri `State` 里被并发 command 访问）。
pub trait UserTokenVault: Send + Sync {
    /// 读取用户令牌；`Ok(None)` 表示「未登录（或未拿到会话授权）」，与读失败区分。
    fn get_user_token(&self) -> Result<Option<UserToken>, VaultError>;
    /// 写入（覆盖）用户令牌。
    fn set_user_token(&self, token: &UserToken) -> Result<(), VaultError>;
    /// 清除用户令牌（登出 / 解绑）。条目本就不存在时视为成功（幂等）。
    fn clear_user_token(&self) -> Result<(), VaultError>;
}

/// 内存实现：单测与「无桌面会话」场景用（语义与真实后端严格对齐）。
#[derive(Default)]
pub struct MemoryUserVault {
    inner: Mutex<Option<UserToken>>,
}

impl MemoryUserVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前是否存有用户令牌（不暴露内容）。
    pub fn is_empty(&self) -> bool {
        self.lock().is_none()
    }

    /// 中毒的锁按「内容已不可信」处理（同 [`MemoryVault::lock`] 的理由）。
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<UserToken>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl fmt::Debug for MemoryUserVault {
    /// 🔴 手写 Debug：`{:?}` 不能把用户令牌打出来。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryUserVault(<masked>)")
    }
}

impl UserTokenVault for MemoryUserVault {
    fn get_user_token(&self) -> Result<Option<UserToken>, VaultError> {
        Ok(self.lock().as_ref().map(UserToken::duplicate))
    }

    fn set_user_token(&self, token: &UserToken) -> Result<(), VaultError> {
        if token.is_empty() {
            return Err(VaultError::EmptyToken);
        }
        *self.lock() = Some(token.duplicate());
        Ok(())
    }

    fn clear_user_token(&self) -> Result<(), VaultError> {
        // `None` 覆盖会 drop 旧 UserToken → 触发 zeroize。
        *self.lock() = None;
        Ok(())
    }
}

/// 内存实现：单测与「无桌面会话」场景用。
///
/// 语义与真实后端严格对齐（含「空令牌拒写」），这样单测覆盖到的分支在真机上同样成立。
#[derive(Default)]
pub struct MemoryVault {
    inner: Mutex<Option<DeviceToken>>,
}

impl MemoryVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前是否存有令牌（不暴露内容）。
    pub fn is_empty(&self) -> bool {
        self.lock().is_none()
    }

    /// 中毒的锁按「内容已不可信」处理：这里存的是单个 `Option`，不存在跨字段不一致，
    /// 因此取回内部值比 panic 更安全 —— Host 因一次日志线程 panic 就整个崩掉毫无收益。
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<DeviceToken>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl fmt::Debug for MemoryVault {
    /// 🔴 手写 Debug：`{:?}` 不能把令牌内容打出来（这正是 `derive(Debug)` 会犯的错）。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryVault(<masked>)")
    }
}

impl TokenVault for MemoryVault {
    fn get(&self) -> Result<Option<DeviceToken>, VaultError> {
        Ok(self.lock().as_ref().map(DeviceToken::duplicate))
    }

    fn set(&self, token: &DeviceToken) -> Result<(), VaultError> {
        if token.is_empty() {
            return Err(VaultError::EmptyToken);
        }
        *self.lock() = Some(token.duplicate());
        Ok(())
    }

    fn clear(&self) -> Result<(), VaultError> {
        // `None` 覆盖会 drop 旧 DeviceToken → 触发 zeroize。
        *self.lock() = None;
        Ok(())
    }
}

/// 真实实现：OS 密钥链（Windows Credential Manager / macOS Keychain）。
#[cfg(any(windows, target_os = "macos"))]
#[derive(Debug, Default)]
pub struct KeyringVault {
    service: &'static str,
    user: &'static str,
}

#[cfg(any(windows, target_os = "macos"))]
impl KeyringVault {
    pub fn new() -> Self {
        Self {
            service: KEYRING_SERVICE,
            user: KEYRING_USER,
        }
    }

    fn entry(&self) -> Result<keyring::Entry, VaultError> {
        keyring::Entry::new(self.service, self.user).map_err(|e| VaultError::Backend(e.to_string()))
    }
}

#[cfg(any(windows, target_os = "macos"))]
impl TokenVault for KeyringVault {
    fn get(&self) -> Result<Option<DeviceToken>, VaultError> {
        // 用密码语义的 get_password（不是 get_secret 二进制接口）：
        // 令牌是 ASCII 文本，且密钥链 GUI 里要能被用户看懂。
        match self.entry()?.get_password() {
            Ok(raw) => Ok(Some(DeviceToken::new(raw))),
            // 「条目不存在」不是错误，是「未配对」这个正常状态。
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(VaultError::Backend(e.to_string())),
        }
    }

    fn set(&self, token: &DeviceToken) -> Result<(), VaultError> {
        if token.is_empty() {
            return Err(VaultError::EmptyToken);
        }
        self.entry()?
            .set_password(token.expose())
            .map_err(|e| VaultError::Backend(e.to_string()))
    }

    fn clear(&self) -> Result<(), VaultError> {
        match self.entry()?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(VaultError::Backend(e.to_string())),
        }
    }
}

/// 用户令牌的原生密钥链实现（条目名 [`KEYRING_USER_SESSION`]）。
#[cfg(any(windows, target_os = "macos"))]
#[derive(Debug, Default)]
pub struct KeyringUserVault {
    service: &'static str,
    user: &'static str,
}

#[cfg(any(windows, target_os = "macos"))]
impl KeyringUserVault {
    pub fn new() -> Self {
        Self {
            service: KEYRING_SERVICE,
            // 🔴 与设备令牌分开的条目名：两条凭据各自可独立吊销。
            user: KEYRING_USER_SESSION,
        }
    }

    fn entry(&self) -> Result<keyring::Entry, VaultError> {
        keyring::Entry::new(self.service, self.user).map_err(|e| VaultError::Backend(e.to_string()))
    }
}

#[cfg(any(windows, target_os = "macos"))]
impl UserTokenVault for KeyringUserVault {
    fn get_user_token(&self) -> Result<Option<UserToken>, VaultError> {
        match self.entry()?.get_password() {
            Ok(raw) => Ok(Some(UserToken::new(raw))),
            // 「条目不存在」= 「未登录」，是正常状态而非错误。
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(VaultError::Backend(e.to_string())),
        }
    }

    fn set_user_token(&self, token: &UserToken) -> Result<(), VaultError> {
        if token.is_empty() {
            return Err(VaultError::EmptyToken);
        }
        self.entry()?
            .set_password(token.expose())
            .map_err(|e| VaultError::Backend(e.to_string()))
    }

    fn clear_user_token(&self) -> Result<(), VaultError> {
        match self.entry()?.delete_credential() {
            Ok(()) => Ok(()),
            // 幂等：登出两次不该报错（否则「登出」按钮会误报失败）。
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(VaultError::Backend(e.to_string())),
        }
    }
}

/// 未实现原生密钥链的平台（Linux/其它）。
///
/// 刻意**不**退回「明文文件」：把长期凭证写进 `~/.config/xxx` 是比不做更坏的安全退化，
/// 用户以为被系统密钥链保护了，实际上任何同机进程都能读。宁可明确报错。
#[cfg(not(any(windows, target_os = "macos")))]
#[derive(Debug, Default)]
pub struct UnsupportedVault;

#[cfg(not(any(windows, target_os = "macos")))]
impl TokenVault for UnsupportedVault {
    fn get(&self) -> Result<Option<DeviceToken>, VaultError> {
        Err(VaultError::Unsupported(std::env::consts::OS))
    }

    fn set(&self, _token: &DeviceToken) -> Result<(), VaultError> {
        Err(VaultError::Unsupported(std::env::consts::OS))
    }

    fn clear(&self) -> Result<(), VaultError> {
        Err(VaultError::Unsupported(std::env::consts::OS))
    }
}

/// 平台默认实现别名：调用方（main/commands）不需要写 `cfg`。
#[cfg(any(windows, target_os = "macos"))]
pub type PlatformVault = KeyringVault;
/// 平台默认实现别名：调用方（main/commands）不需要写 `cfg`。
#[cfg(not(any(windows, target_os = "macos")))]
pub type PlatformVault = UnsupportedVault;

/// 用户令牌 vault 的平台默认实现别名。
#[cfg(any(windows, target_os = "macos"))]
pub type PlatformUserVault = KeyringUserVault;

/// 用户令牌 vault 的平台默认实现别名（无密钥链平台）。
#[cfg(not(any(windows, target_os = "macos")))]
pub type PlatformUserVault = UnsupportedUserVault;

/// 无密钥链平台上的用户令牌 vault：显式报错，绝不退化为写明文文件。
#[cfg(not(any(windows, target_os = "macos")))]
#[derive(Debug, Default)]
pub struct UnsupportedUserVault;

#[cfg(not(any(windows, target_os = "macos")))]
impl UserTokenVault for UnsupportedUserVault {
    fn get_user_token(&self) -> Result<Option<UserToken>, VaultError> {
        Err(VaultError::Unsupported(std::env::consts::OS))
    }

    fn set_user_token(&self, _token: &UserToken) -> Result<(), VaultError> {
        Err(VaultError::Unsupported(std::env::consts::OS))
    }

    fn clear_user_token(&self) -> Result<(), VaultError> {
        Err(VaultError::Unsupported(std::env::consts::OS))
    }
}

/// 生产环境入口：返回平台原生 vault。
pub fn default_vault() -> Arc<dyn TokenVault> {
    Arc::new(PlatformVault::new())
}

/// 生产环境入口：返回平台原生**用户令牌** vault。
pub fn default_user_vault() -> Arc<dyn UserTokenVault> {
    Arc::new(PlatformUserVault::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(raw: &str) -> DeviceToken {
        DeviceToken::new(raw.to_string())
    }

    #[test]
    fn memory_vault_starts_unpaired() {
        let v = MemoryVault::new();
        assert!(v.is_empty());
        // 「未配对」必须是 Ok(None) 而不是 Err：两者在前端语义完全不同。
        assert!(matches!(v.get(), Ok(None)));
    }

    #[test]
    fn set_then_get_roundtrips_the_token() {
        let v = MemoryVault::new();
        v.set(&token("hgd_abcdef123456")).expect("写入应成功");
        let got = v.get().expect("读取应成功").expect("应已配对");
        assert_eq!(got.expose(), "hgd_abcdef123456");
        assert_eq!(got.len(), 16);
        assert!(!v.is_empty());
    }

    #[test]
    fn clear_returns_to_unpaired_state() {
        let v = MemoryVault::new();
        v.set(&token("hgd_abcdef")).unwrap();
        v.clear().expect("清除应成功");
        assert!(v.is_empty());
        assert!(matches!(v.get(), Ok(None)));
        // 清两次也必须成功：条目不存在不算错误，否则「解除配对」会被误报为失败。
        v.clear().expect("重复清除应幂等");
    }

    #[test]
    fn empty_token_is_rejected() {
        let v = MemoryVault::new();
        let err = v.set(&token("")).expect_err("空令牌必须被拒绝");
        assert!(matches!(err, VaultError::EmptyToken), "实际：{err:?}");
        assert!(v.is_empty());
    }

    #[test]
    fn overwrite_replaces_previous_token() {
        let v = MemoryVault::new();
        v.set(&token("hgd_old")).unwrap();
        v.set(&token("hgd_new")).unwrap();
        assert_eq!(v.get().unwrap().unwrap().expose(), "hgd_new");
    }

    /// 🔴 安全回归：令牌的 Debug 必须打码，绝不出现明文。
    #[test]
    fn debug_never_leaks_token_plaintext() {
        let t = token("hgd_super_secret_value");
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("super_secret_value"), "Debug 泄露明文：{dbg}");
        assert!(dbg.contains("hgd_***"), "Debug 应保留打码前缀：{dbg}");
        // 结构体展开形态同样不能泄露
        assert!(!format!("{t:#?}").contains("super_secret_value"));
    }

    /// 🔴 安全回归：`{:?}` 整个 vault 也不能看到令牌（derive(Debug) 会踩的坑）。
    #[test]
    fn vault_debug_never_leaks_token_plaintext() {
        let v = MemoryVault::new();
        v.set(&token("hgd_leaky_candidate")).unwrap();
        let dbg = format!("{v:?}");
        assert!(
            !dbg.contains("leaky_candidate"),
            "vault Debug 泄露明文：{dbg}"
        );
        assert!(
            dbg.contains("<masked>"),
            "vault Debug 应显式标注已打码：{dbg}"
        );
    }

    /// 「不落盘明文」语义：内存实现对磁盘零写入，且 drop 时明文被清零。
    ///
    /// 这里能验证的是「不产生任何文件」这一半（真实磁盘扫描不该出现在单测里）；
    /// keyring 后端不落盘明文由 OS 密钥链本身保证。
    #[test]
    fn memory_vault_writes_nothing_observable_to_disk() {
        let dir = tempfile::tempdir().expect("临时目录");
        // CWD 无关性：MemoryVault 没有任何文件路径字段，结构上就不可能写盘。
        let v = MemoryVault::new();
        v.set(&token("hgd_no_disk_trace")).unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("读取临时目录")
            .map(|e| e.expect("目录项").file_name())
            .collect();
        assert!(
            entries.is_empty(),
            "内存 vault 不应产生任何文件：{entries:?}"
        );
    }

    #[test]
    fn default_vault_is_send_and_sync() {
        // 编译期断言：vault 要能挂进 Tauri State 被多线程 command 共享。
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn TokenVault>();
        // 用户令牌 vault 同样要能挂进 State。
        assert_send_sync::<dyn UserTokenVault>();
    }

    /* ============ 用户令牌（user_token）专项 ============ */

    fn user_token(raw: &str) -> UserToken {
        UserToken::new(raw.to_string())
    }

    #[test]
    fn memory_user_vault_starts_signed_out() {
        let v = MemoryUserVault::new();
        assert!(v.is_empty());
        // 未登录必须是 Ok(None)：与「读失败」语义完全不同。
        assert!(matches!(v.get_user_token(), Ok(None)));
    }

    #[test]
    fn user_token_roundtrips_through_vault() {
        let v = MemoryUserVault::new();
        v.set_user_token(&user_token("hgt_abcdef123456"))
            .expect("写入应成功");
        let got = v
            .get_user_token()
            .expect("读取应成功")
            .expect("应已登录");
        assert_eq!(got.expose(), "hgt_abcdef123456");
        assert_eq!(got.len(), 16);
        assert!(!v.is_empty());
    }

    #[test]
    fn clear_user_token_is_idempotent() {
        let v = MemoryUserVault::new();
        v.set_user_token(&user_token("hgt_abcdef")).unwrap();
        v.clear_user_token().expect("清除应成功");
        assert!(v.is_empty());
        assert!(matches!(v.get_user_token(), Ok(None)));
        // 登出两次不该报错（否则按钮会误报失败）。
        v.clear_user_token().expect("重复清除应幂等");
    }

    #[test]
    fn empty_user_token_is_rejected() {
        let v = MemoryUserVault::new();
        let err = v
            .set_user_token(&user_token(""))
            .expect_err("空令牌必须被拒绝");
        assert!(matches!(err, VaultError::EmptyToken), "实际：{err:?}");
        assert!(v.is_empty());
    }

    /// 🔴 安全回归：用户令牌的 Debug 也必须打码。
    #[test]
    fn user_token_debug_never_leaks_plaintext() {
        let t = user_token("hgt_super_secret_session");
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("super_secret_session"), "泄露明文：{dbg}");
        assert!(dbg.contains("hgt_***"), "应保留打码前缀：{dbg}");
        assert!(!format!("{t:#?}").contains("super_secret_session"));
        // 结构体名要能区分两条凭据（排障时不会误认成设备令牌）。
        assert!(dbg.contains("UserToken"), "应标注类型：{dbg}");
    }

    /// 🔴 安全回归：用户令牌 vault 的 `{:?}` 也不能看到明文。
    #[test]
    fn user_vault_debug_never_leaks_plaintext() {
        let v = MemoryUserVault::new();
        v.set_user_token(&user_token("hgt_leaky_candidate")).unwrap();
        let dbg = format!("{v:?}");
        assert!(!dbg.contains("leaky_candidate"), "vault Debug 泄露：{dbg}");
        assert!(dbg.contains("<masked>"), "应显式标注打码：{dbg}");
    }

    /// 正交语义回归：**清用户令牌不得影响设备令牌**（「登出保留绑定」）。
    #[test]
    fn clearing_user_token_does_not_touch_device_token() {
        let devices = MemoryVault::new();
        let users = MemoryUserVault::new();
        devices.set(&token("hgd_device")).unwrap();
        users.set_user_token(&user_token("hgt_user")).unwrap();

        users.clear_user_token().unwrap();

        // 登出后设备仍是已配对状态 —— 这正是「登出保留绑定」的实现证据。
        assert!(
            devices.get().unwrap().is_some(),
            "登出不应清掉设备令牌"
        );
    }
}
