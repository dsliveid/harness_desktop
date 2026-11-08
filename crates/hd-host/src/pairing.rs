//! 真实配对客户端（`POST /api/v1/devices/pair`）。
//!
//! ## 为什么配对要放在 Rust 侧，而不是让前端调
//!
//! 配对响应里带 `device_token` 明文——它是**长期凭证**，泄露即设备被永久接管。
//! 若由前端 JS 发起，令牌必然经过 WebView 的 JS 堆与网络栈（可被 XSS、恶意依赖、
//! 被注入的 devtools 拿到）。放在 Rust 侧则令牌从 HTTP 响应直接进
//! [`DeviceToken`]（zeroize）→ 密钥链 / Runner stdin，**中间不存在裸 String**。
//!
//! 这也解释了为什么 `hd-host` 是唯一允许出网的进程（设计文档 §14.3 已许可
//! reqwest 仅用于配对）。
//!
//! ## 服务端契约（已核实 `internal/service/device_service.go:207`）
//!
//! 请求：`{code, name, kind, platform, app_version, capabilities[]}`
//! 响应（201）：`{device_id, device_token, ws_path, protocol_version}`
//! 失败：统一 `{code, message}`，如 `device.pair_code_invalid` / `device.disabled`

use hd_runner::ipc::redact_token;
use serde::{Deserialize, Serialize};

use crate::vault::DeviceToken;

/// 配对成功的结果。
///
/// 🔴 `token` 刻意是 [`DeviceToken`] 而非 `String`：这样它在整个宿主内部
/// 都只能以「不可打印、不可 Clone、不可序列化」的形态存在。
pub struct PairedDevice {
    /// 设备 ID（服务端分配）。
    pub device_id: String,
    /// 设备令牌（长期凭证，仅此一次下发）。
    pub token: DeviceToken,
    /// 完整 WS 地址（已由 `ws_path` 与 base_url 拼好）。
    pub ws_url: String,
    /// 服务端协议版本。
    pub protocol_version: i32,
    /// 服务端 HTTP 基址（配对时使用的地址，记入档案供重启后重连/重新配对）。
    pub server_base_url: String,
}

/// 手写 `Debug`：`DeviceToken` 故意不实现 `Debug`（防顺手打印），
/// 这里用打码形式输出，保证「日志里不出现明文令牌」。
impl std::fmt::Debug for PairedDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairedDevice")
            .field("device_id", &self.device_id)
            .field("token", &"<redacted>")
            .field("ws_url", &self.ws_url)
            .field("protocol_version", &self.protocol_version)
            .finish()
    }
}

/// 配对失败。
#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    /// 网络层失败（连不上/超时/TLS）。
    #[error("连接服务端失败：{0}")]
    Http(String),
    /// 服务端明确拒绝（配对码无效、设备域关闭等）。
    ///
    /// `code` 是 `apperr` 的错误码，调用方可据此显示不同文案；
    /// 消息里**绝不含令牌**（拒绝时压根没有令牌）。
    #[error("服务端拒绝配对（{code}）：{message}")]
    Rejected {
        /// `apperr` 错误码。
        code: String,
        /// 可读消息。
        message: String,
    },
    /// 响应结构不符合预期（字段缺失/JSON 非法）。
    #[error("服务端响应异常：{0}")]
    BadResponse(String),
}

/// 配对请求体（对齐服务端 `pairDeviceReq`）。
#[derive(Debug, Serialize)]
struct PairRequestBody<'a> {
    code: &'a str,
    name: &'a str,
    kind: &'a str,
    platform: &'a str,
    app_version: &'a str,
    capabilities: Vec<CapabilityInput<'a>>,
}

/// 能力申报项。
#[derive(Debug, Serialize)]
struct CapabilityInput<'a> {
    name: &'a str,
    version: &'a str,
}

/// 配对响应体（对齐服务端 `PairResult`）。
#[derive(Debug, Deserialize)]
struct PairResponseBody {
    device_id: String,
    device_token: String,
    ws_path: String,
    protocol_version: i32,
}

/// 服务端错误体（对齐 `apperr.Body`）。
#[derive(Debug, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

/// 配对客户端。
pub struct PairingClient {
    /// 服务端 HTTP 基址，如 `http://127.0.0.1:5611`（**不含尾斜杠**）。
    base_url: String,
    http: reqwest::Client,
}

impl PairingClient {
    /// 构造客户端。
    ///
    /// `base_url` 尾部斜杠会被剥掉：拼接 `ws_path` 时多一个斜杠会变成
    /// `//api/v1/...`，部分反代会 301，而 WS 升级不接受重定向。
    pub fn new(base_url: impl Into<String>) -> Self {
        let base = base_url.into();
        let base = base.trim_end_matches('/').to_string();
        Self {
            base_url: base,
            http: reqwest::Client::builder()
                // 配对是用户主动等待的短操作，超时不宜长；10s 足够跨公网。
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// 用配对码换设备令牌。
    pub async fn pair(
        &self,
        code: &str,
        name: &str,
        platform: &str,
        app_version: &str,
    ) -> Result<PairedDevice, PairingError> {
        let url = format!("{}/api/v1/devices/pair", self.base_url);

        let body = PairRequestBody {
            code,
            name,
            kind: "desktop",
            platform,
            app_version,
            // 申报 `workspace.list`：桌面端已实现 fs.list（hd-core 的 ListDirsExecutor）。
            // 少申报会让前端把本机空间置灰，多申报会让用户点了必然失败。
            capabilities: vec![CapabilityInput {
                name: "workspace.list",
                version: "1",
            }],
        };

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| PairingError::Http(e.to_string()))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| PairingError::Http(e.to_string()))?;

        if !status.is_success() {
            // 服务端统一错误体；解析失败也不能 panic（不要把服务端 HTML 当地址用）。
            let parsed: Option<ErrorBody> = serde_json::from_str(&text).ok();
            let (code, message) = match parsed {
                Some(b) if !b.code.is_empty() => (b.code, b.message),
                _ => (
                    "unknown".to_string(),
                    format!("HTTP {status}（{}）", truncate(&text, 200)),
                ),
            };
            return Err(PairingError::Rejected { code, message });
        }

        let parsed: PairResponseBody = serde_json::from_str(&text)
            .map_err(|e| PairingError::BadResponse(format!("JSON 解析失败：{e}")))?;

        if parsed.device_token.trim().is_empty() {
            return Err(PairingError::BadResponse("响应缺少 device_token".into()));
        }
        if parsed.ws_path.trim().is_empty() {
            return Err(PairingError::BadResponse("响应缺少 ws_path".into()));
        }

        // 日志里只出现打码令牌：这一步是「日志不泄露长期凭证」的可见证据。
        tracing::info!(
            device_id = %parsed.device_id,
            token = %redact_token(&parsed.device_token),
            ws_path = %parsed.ws_path,
            protocol_version = parsed.protocol_version,
            "配对成功"
        );

        let ws_url = ws_url_from(&self.base_url, &parsed.ws_path)?;

        Ok(PairedDevice {
            device_id: parsed.device_id,
            token: DeviceToken::new(parsed.device_token),
            ws_url,
            protocol_version: parsed.protocol_version,
            server_base_url: self.base_url.clone(),
        })
    }
}

/// 把 HTTP base + `ws_path` 拼成 WS 地址。
///
/// `http` → `ws`、`https` → `wss`。**不能**用字符串拼接直接替换前缀：
/// 那样 `http://` 会被 `https://` 干扰，且协议名大小写不敏感。
pub fn ws_url_from(base_url: &str, ws_path: &str) -> Result<String, PairingError> {
    let base = url::Url::parse(base_url)
        .map_err(|e| PairingError::BadResponse(format!("服务端地址非法：{e}")))?;
    let scheme = match base.scheme() {
        "http" => "ws",
        "https" => "wss",
        other => {
            return Err(PairingError::BadResponse(format!(
                "服务端地址协议不支持：{other}"
            )))
        }
    };
    let host = base
        .host_str()
        .ok_or_else(|| PairingError::BadResponse("服务端地址缺少主机名".into()))?;
    let port = base.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path = if ws_path.starts_with('/') {
        ws_path.to_string()
    } else {
        format!("/{ws_path}")
    };
    Ok(format!("{scheme}://{host}{port}{path}"))
}

/// 截断长文本用于错误信息（避免把整页 HTML 塞进 UI）。
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_upgrades_http_to_ws() {
        let u = ws_url_from("http://127.0.0.1:5611", "/api/v1/devices/ws").unwrap();
        assert_eq!(u, "ws://127.0.0.1:5611/api/v1/devices/ws");
    }

    #[test]
    fn ws_url_upgrades_https_to_wss() {
        // 生产必须 wss：明文 ws 会让 ?token= 在网络上裸奔
        let u = ws_url_from("https://harness.example.com", "/api/v1/devices/ws").unwrap();
        assert_eq!(u, "wss://harness.example.com/api/v1/devices/ws");
    }

    #[test]
    fn ws_url_handles_missing_leading_slash() {
        let u = ws_url_from("http://127.0.0.1:5611", "api/v1/devices/ws").unwrap();
        assert_eq!(u, "ws://127.0.0.1:5611/api/v1/devices/ws");
    }

    #[test]
    fn ws_url_rejects_unsupported_scheme() {
        assert!(ws_url_from("ftp://example.com", "/ws").is_err());
    }

    #[test]
    fn base_url_trailing_slash_is_stripped() {
        let c = PairingClient::new("http://127.0.0.1:5611/");
        assert_eq!(c.base_url, "http://127.0.0.1:5611");
    }

    #[test]
    fn truncate_keeps_short_text_intact() {
        assert_eq!(truncate("short", 10), "short");
    }

    #[test]
    fn truncate_cuts_long_text() {
        let out = truncate(&"x".repeat(300), 10);
        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), 11);
    }
}
