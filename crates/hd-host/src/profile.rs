//! 本地配对档案：记住「连哪台服务端」「本机是哪个设备」。
//!
//! ## 🔴 这里绝不存令牌
//!
//! 令牌（`device_token`）只放 OS 密钥链（见 [`crate::vault`]）。本档案是**明文
//! JSON 文件**，落在 `%APPDATA%\harness_desktop\profile.json`，任何本机程序都能读。
//!
//! 两者的分工必须分清：
//! - **档案**回答「连哪台机器、我是哪台设备」→ 非敏感，明文可读无妨；
//! - **密钥链**回答「我凭什么被信任」→ 敏感，泄露即设备被永久接管。
//!
//! 混放的后果很具体：备份工具、云同步、崩溃转储都会顺手带走明文 JSON。
//! 因此 [`Profile`] 刻意**没有** token 字段，且有单测断言序列化结果不含它。
//!
//! ## 为什么需要它
//!
//! 之前 `bootstrap::ensure_running` 把 ws 地址硬编码成 `ws://127.0.0.1:5611`，
//! 导致连非默认服务端的用户**重启后自动连回默认地址**（连不上且不知为何）。
//! 档案把配对时得到的真实地址记住，重启即可连回同一台。
//!
//! ## 容错原则
//!
//! 档案损坏（JSON 非法、字段缺失、文件被删）一律**降级为「无档案」**而不是报错：
//! 这是缓存类数据，丢了最多重新配对一次，不值得让整个宿主起不来。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 档案文件名。
pub const PROFILE_FILE_NAME: &str = "profile.json";

/// 本地配对档案。
///
/// 🔴 **不得增加任何令牌字段**。若将来需要记住更多凭据，一律走 [`crate::vault`]。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// 服务端 HTTP 基址（如 `http://127.0.0.1:5611`），用于重新配对/展示。
    #[serde(default)]
    pub server_base_url: String,
    /// 配对后得到的完整 WS 地址（如 `ws://127.0.0.1:5611/api/v1/devices/ws`）。
    ///
    /// 存完整地址而非只存 `ws_path`：服务端可能返回绝对路径，拼接规则变化时
    /// 存完整地址不会失效。
    #[serde(default)]
    pub ws_url: String,
    /// 服务端分配的设备 ID（用于 UI 展示与排障，不是凭据）。
    #[serde(default)]
    pub device_id: String,
    /// 协议版本（重连时要带上，避免握手再协商一次）。
    #[serde(default)]
    pub protocol_version: i32,
    /// 上次配对时间（毫秒）。
    #[serde(default)]
    pub paired_at_ms: u64,
}

impl Profile {
    /// 构造一条完整记录。
    pub fn new(
        server_base_url: impl Into<String>,
        ws_url: impl Into<String>,
        device_id: impl Into<String>,
        protocol_version: i32,
        paired_at_ms: u64,
    ) -> Self {
        Self {
            server_base_url: server_base_url.into(),
            ws_url: ws_url.into(),
            device_id: device_id.into(),
            protocol_version,
            paired_at_ms,
        }
    }

    /// 是否足够用于「重启后自动连回」（ws_url 非空即可）。
    pub fn is_usable(&self) -> bool {
        !self.ws_url.trim().is_empty()
    }
}

/// 档案读取/写入失败。
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    /// IO 失败（无权限、磁盘满）。
    #[error("档案读写失败：{0}")]
    Io(String),
}

/// 档案存储抽象（可注入，便于单测）。
pub trait ProfileStore: Send + Sync {
    /// 读取档案；`Ok(None)` 表示「从未配对过」或「档案损坏已降级」。
    fn load(&self) -> Result<Option<Profile>, ProfileError>;
    /// 写入（覆盖）档案。
    fn save(&self, profile: &Profile) -> Result<(), ProfileError>;
    /// 清除档案（解除配对时用）。
    fn clear(&self) -> Result<(), ProfileError>;
}

/// 基于文件的档案存储。
#[derive(Debug, Clone)]
pub struct FileProfileStore {
    path: PathBuf,
}

impl FileProfileStore {
    /// 指定完整文件路径。
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// 按平台约定推导默认路径：`<配置目录>/harness_desktop/profile.json`。
    ///
    /// 用 `dirs::config_dir()` 而不是当前目录：当前目录可能是用户随便点开的
    /// 位置（甚至只读），配置必须落在系统约定的可写位置。
    pub fn default_path() -> PathBuf {
        let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("harness_desktop").join(PROFILE_FILE_NAME)
    }

    /// 默认存储。
    pub fn with_default_path() -> Self {
        Self::new(Self::default_path())
    }

    /// 档案文件路径（测试与排障用）。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ProfileStore for FileProfileStore {
    fn load(&self) -> Result<Option<Profile>, ProfileError> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            // 文件不存在 = 从未配对，是正常路径，不是错误。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ProfileError::Io(e.to_string())),
        };

        // 解析失败一律降级为「无档案」：宁可让用户重新配对一次，
        // 也不要让一个损坏的缓存文件把宿主卡死在启动阶段。
        match serde_json::from_str::<Profile>(&raw) {
            Ok(p) => Ok(Some(p)),
            Err(e) => {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "档案解析失败，按「未配对」处理"
                );
                Ok(None)
            }
        }
    }

    fn save(&self, profile: &Profile) -> Result<(), ProfileError> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| ProfileError::Io(e.to_string()))?;
        }
        let json = serde_json::to_string_pretty(profile)
            .map_err(|e| ProfileError::Io(format!("序列化失败：{e}")))?;
        std::fs::write(&self.path, json).map_err(|e| ProfileError::Io(e.to_string()))
    }

    fn clear(&self) -> Result<(), ProfileError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            // 本来就不存在 → 视为成功（幂等）。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ProfileError::Io(e.to_string())),
        }
    }
}

/// 内存实现（单测用）。
#[derive(Debug, Default)]
pub struct MemoryProfileStore {
    inner: std::sync::Mutex<Option<Profile>>,
}

impl MemoryProfileStore {
    /// 新建空存储。
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Profile>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl ProfileStore for MemoryProfileStore {
    fn load(&self) -> Result<Option<Profile>, ProfileError> {
        Ok(self.lock().clone())
    }

    fn save(&self, profile: &Profile) -> Result<(), ProfileError> {
        *self.lock() = Some(profile.clone());
        Ok(())
    }

    fn clear(&self) -> Result<(), ProfileError> {
        *self.lock() = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Profile {
        Profile::new(
            "http://127.0.0.1:5611",
            "ws://127.0.0.1:5611/api/v1/devices/ws",
            "dev_abc",
            1,
            1_700_000_000_000,
        )
    }

    #[test]
    fn roundtrip_through_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = FileProfileStore::new(dir.path().join("profile.json"));

        store.save(&sample()).expect("写档案");
        let loaded = store.load().expect("读档案").expect("应存在");
        assert_eq!(loaded, sample());
    }

    #[test]
    fn missing_file_is_not_an_error() {
        // 「从未配对」是正常路径：报错会让宿主把首次启动当异常处理
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = FileProfileStore::new(dir.path().join("nope.json"));
        assert!(store.load().expect("不应报错").is_none());
    }

    #[test]
    fn corrupt_file_degrades_to_none() {
        // 损坏的档案必须降级而不是让宿主起不来
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("profile.json");
        std::fs::write(&path, "{ this is not json").expect("写坏文件");

        let store = FileProfileStore::new(&path);
        assert!(store.load().expect("不应报错").is_none());
    }

    #[test]
    fn clear_is_idempotent() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = FileProfileStore::new(dir.path().join("profile.json"));
        // 从未写过就 clear，也应成功
        store.clear().expect("首次 clear");
        store.save(&sample()).expect("写");
        store.clear().expect("有档案时 clear");
        assert!(store.load().expect("读").is_none());
    }

    /// 🔴 安全断言：档案序列化结果里绝不能出现令牌字段。
    ///
    /// 档案是明文文件，一旦混入令牌就等于把长期凭证写在磁盘上。
    #[test]
    fn serialized_profile_never_contains_token() {
        let json = serde_json::to_string(&sample()).expect("序列化");
        let lower = json.to_lowercase();
        assert!(!lower.contains("token"), "档案里出现了 token 字段：{json}");
        assert!(!lower.contains("hgd_"), "档案里出现了令牌值：{json}");
        assert!(
            !lower.contains("secret"),
            "档案里出现了 secret 字段：{json}"
        );
    }

    #[test]
    fn is_usable_requires_ws_url() {
        let mut p = sample();
        assert!(p.is_usable());
        p.ws_url.clear();
        assert!(!p.is_usable());
    }

    #[test]
    fn default_path_lives_under_app_config_dir() {
        let p = FileProfileStore::default_path();
        assert!(p.ends_with(PROFILE_FILE_NAME));
        // 必须在 harness_desktop 子目录里，不能污染配置根目录
        assert!(
            p.parent()
                .and_then(|d| d.file_name())
                .map(|n| n == "harness_desktop")
                .unwrap_or(false),
            "默认路径不符合约定：{}",
            p.display()
        );
    }
}
