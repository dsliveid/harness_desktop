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
//!
//! ## 会话授权附加字段（免二次登录）
//!
//! 新服务端在配对响应里**额外**返回 `user_token` / `user` / `session_ttl_s`。
//! 三者**要么全有、要么全无**（服务端若签发会话失败会整体省略，只 Warn 不失败）。
//! 缺失是**合法降级**：客户端必须保留「配对成功但仍需登录」的旧行为，
//! 绝不能因为免登录字段缺失就让配对整体失败 —— 那会把一个可选增强变成破坏性变更。

use hd_runner::ipc::redact_token;
use serde::{Deserialize, Serialize};

use crate::vault::{DeviceToken, UserToken};

/// 配对成功后附带的**用户会话授权**（免二次登录用）。
///
/// 🔴 `token` 是 [`UserToken`]（zeroize + Debug 打码），不是裸 `String`。
pub struct SessionGrant {
    /// 用户会话令牌（写入 WebView 的 `hg_sess` Cookie）。
    pub token: UserToken,
    /// 该会话所属用户（用于 UI 展示「已以 xx 身份登录」）。
    pub user: PairedUser,
    /// 会话有效期（秒，服务端下发；仅用于展示/排障，客户端不据此做本地过期判断）。
    pub ttl_s: Option<i64>,
}

/// 手写 `Debug`：`UserToken` 不实现 `Debug` 明文输出，这里打码。
impl std::fmt::Debug for SessionGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionGrant")
            .field("token", &self.token)
            .field("user", &self.user)
            .field("ttl_s", &self.ttl_s)
            .finish()
    }
}

/// 会话所属用户（配对响应 `user` 字段）。
///
/// 字段全部给默认值：旧服务端/私有部署可能返回残缺对象，缺字段不应导致解析失败。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PairedUser {
    /// 用户 ID。
    #[serde(default)]
    pub id: String,
    /// 登录名。
    #[serde(default)]
    pub username: String,
    /// 展示名（UI 优先用它）。
    #[serde(default)]
    pub display_name: String,
    /// 角色（如 `owner`）。
    #[serde(default)]
    pub role: String,
}

impl PairedUser {
    /// 给人看的称呼：优先展示名，其次登录名，都没有时给出中性占位。
    pub fn label(&self) -> &str {
        let display = self.display_name.trim();
        if !display.is_empty() {
            return display;
        }
        let name = self.username.trim();
        if !name.is_empty() {
            return name;
        }
        "该账号"
    }
}

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
    /// 用户会话授权（免二次登录）。
    ///
    /// `None` = 服务端未签发（旧服务端 / historical 配对码）→ **合法降级**，
    /// 保持「配对成功但仍需登录」的既有行为。
    pub session: Option<SessionGrant>,
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
            .field("session", &self.session)
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
///
/// 除四个必填字段外，其余全部 `#[serde(default)]`：**对未知/缺失字段宽容** ——
/// 服务端演进（新增字段、临时省略会话授权）都不该让客户端解析失败。
#[derive(Debug, Deserialize)]
struct PairResponseBody {
    device_id: String,
    device_token: String,
    ws_path: String,
    protocol_version: i32,
    /// 用户会话令牌（免登录）。缺失 = 旧服务端，合法降级。
    #[serde(default)]
    user_token: Option<String>,
    /// 会话所属用户。
    #[serde(default)]
    user: Option<PairedUser>,
    /// 会话有效期（秒）。
    #[serde(default)]
    session_ttl_s: Option<i64>,
}

/// 设备令牌续期会话的响应体（对齐 `POST /api/v1/devices/session`）。
///
/// 🔴 与配对响应**刻意分开建模**而不是复用 [`PairResponseBody`]：续期接口只回
/// 「会话三件套」，没有 `device_id`/`device_token`/`ws_path` 等必填字段。共用结构体
/// 会让那些必填字段变成"其实可能缺失"，从而把一个清晰契约搅浑。
/// 这里全部 `#[serde(default)]`，缺失交给分级宽容的 [`parse_session_grant`] 判定。
#[derive(Debug, Deserialize)]
struct DeviceSessionResponseBody {
    /// 新签发的用户会话令牌（续期的唯一必要产物）。
    #[serde(default)]
    user_token: Option<String>,
    /// 会话所属用户（展示用）。
    #[serde(default)]
    user: Option<PairedUser>,
    /// 会话有效期（秒）。
    #[serde(default)]
    session_ttl_s: Option<i64>,
}

/// 服务端错误体（对齐 `apperr.Body`）。
#[derive(Debug, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

/// 把「非 2xx 的状态码 + 响应体」归一成 [`PairingError::Rejected`]（纯函数，可单测）。
///
/// ## 为什么必须纯函数
///
/// 401（令牌被吊销/无效）与 403（`device.owner_unknown`，设备没绑定账号）在
/// **调用方处置上完全不同**：前者要用户重新配对，后者在服务端补齐归属前怎么重试都没用。
/// 保留服务端 `code` 是唯一能让上层说清楚原因的手段，故这段解析必须能被穷举验证。
///
/// 解析失败**绝不 panic**：服务端可能经由反代返回一段 HTML 错误页，
/// 此时给出 `unknown` + 截断后的原文，够排障也不会把整页塞进 UI。
fn parse_error_body(status: u16, text: &str) -> PairingError {
    let parsed: Option<ErrorBody> = serde_json::from_str(text).ok();
    match parsed {
        Some(b) if !b.code.is_empty() => PairingError::Rejected {
            code: b.code,
            message: b.message,
        },
        _ => PairingError::Rejected {
            code: "unknown".to_string(),
            message: format!("HTTP {status}（{}）", truncate(text, 200)),
        },
    }
}

/// 解析设备令牌续期响应（纯函数，供 [`PairingClient::renew_session`] 与单测共用）。
///
/// 🔴 **复用** [`parse_session_grant`]，绝不另写一套字段判定：续期响应与配对响应的
/// 会话字段完全同构（`user_token` / `user` / `session_ttl_s`），宽容策略必须一致 ——
/// 否则会出现「配对时能降级、续期时直接失败」的口径分裂。
fn parse_device_session_body(text: &str) -> Result<SessionGrant, PairingError> {
    let parsed: DeviceSessionResponseBody = serde_json::from_str(text)
        .map_err(|e| PairingError::BadResponse(format!("JSON 解析失败：{e}")))?;
    // 续期接口的 200 响应**必须**带 token：没有 token 的续期等于什么都没换到，
    // 此时按 BadResponse 上报，让调用方走「清会话、提示重新配对」的兜底路径。
    parse_session_grant(parsed.user_token, parsed.user, parsed.session_ttl_s).ok_or_else(|| {
        PairingError::BadResponse("续期响应缺少 user_token（无法建立会话）".into())
    })
}

/// 允许多次 `pair()` 调用共享的会话授权解析逻辑（纯函数，可穷举单测）。
///
/// ## 「全有或全无」怎么落地
///
/// 契约规定三字段要么全有、要么全无。客户端按**分级宽容**处理，理由是
/// 三类字段的价值完全不同：
///
/// - `user_token` 是**唯一必要条件**：没有它，免登录根本无从谈起 → 缺失即
///   [`None`]（走「配对成功但仍需登录」的旧路径）。
/// - `user` / `session_ttl_s` 只是**展示信息**（界面上显示「已以 xx 身份登录」）。
///   它们缺失时若连会话一起丢掉，等于让用户因为一个纯装饰字段去手动登录一次 ——
///   代价远大于收益。故降级为占位用户 + `ttl_s = None`，并记 warn 便于排障。
/// - 反过来，**有 user/ttl 却没有 token** 是危险的残缺：绝不能凭它渲染「已登录」，
///   否则界面显示已登录而 Web UI 实际还在登录页。此时 warn 并返回 [`None`]。
pub fn parse_session_grant(
    user_token: Option<String>,
    user: Option<PairedUser>,
    ttl_s: Option<i64>,
) -> Option<SessionGrant> {
    let raw = user_token.unwrap_or_default();
    if raw.trim().is_empty() {
        if user.is_some() || ttl_s.is_some() {
            // 残缺授权：字段都给了却唯独没有令牌，说明服务端实现有 bug。
            tracing::warn!("配对响应含 user/session_ttl_s 但缺少 user_token，按未登录降级");
        }
        return None;
    }
    // 🔴 只打码后的长度级信息，绝不打印令牌内容。
    tracing::info!(
        user_token = %redact_token(&raw),
        token_len = raw.len(),
        "配对响应包含用户会话授权（将注入 WebView 会话 Cookie）"
    );

    // 🔴 服务端就绪后「全有」是常态；此处仅为防御性降级（旧补丁版本可能只回 token）。
    if user.is_none() || ttl_s.is_none() {
        tracing::warn!("配对响应的会话授权字段不完整（缺 user 或 session_ttl_s），按已有字段降级使用");
    }

    let user = user.unwrap_or_default();

    Some(SessionGrant {
        token: UserToken::new(raw),
        user,
        ttl_s,
    })
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
            return Err(parse_error_body(status.as_u16(), &text));
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

        // 会话授权解析：三字段缺失是**合法降级**（返回 None），绝不让配对失败。
        let session = parse_session_grant(parsed.user_token, parsed.user, parsed.session_ttl_s);

        let ws_url = ws_url_from(&self.base_url, &parsed.ws_path)?;

        Ok(PairedDevice {
            device_id: parsed.device_id,
            token: DeviceToken::new(parsed.device_token),
            ws_url,
            protocol_version: parsed.protocol_version,
            server_base_url: self.base_url.clone(),
            session,
        })
    }

    /// 用设备令牌换一份**新的**用户会话（`POST /api/v1/devices/session`）。
    ///
    /// ## 为什么需要它（本文件新增能力的唯一动机）
    ///
    /// 用户会话默认只有 7 天（服务端 `session_ttl_h=168`），而**设备令牌是长期的**。
    /// 若只有旧会话，7 天后启动时把过期 `user_token` 原样重放进 `hg_sess`
    /// Cookie，WebView 会拿着失效凭据撞登录墙 —— 用户看到的是"莫名其妙要我登录"，
    /// 而不是"会话过期，正在自动续期"。
    ///
    /// 设备令牌是「这台机器被授权」的长期事实，用它换新会话是唯一不需要人工介入的
    /// 修复路径。契约（权威，勿改字段名）：
    ///
    /// ```text
    /// POST /api/v1/devices/session
    ///   Authorization: Bearer <device_token>
    ///   200 { user_token, user{id,username,display_name,role}, session_ttl_s }
    ///   401 设备令牌无效 / 已吊销 / 缺失
    ///   403 归属账号未知（device.owner_unknown）
    /// ```
    ///
    /// 只认设备令牌，**不接受 Cookie**；幂等可重试。
    ///
    /// ## 凭证红线
    ///
    /// 令牌只出现在 `Authorization` 头里（不经 URL、不进 body），日志一律经
    /// [`redact_token`] 打码。返回的 [`SessionGrant`] 内是 zeroize 的 [`UserToken`]，
    /// 从 HTTP 响应到 vault 之间不存在裸 `String`。
    pub async fn renew_session(
        &self,
        device_token: &DeviceToken,
    ) -> Result<SessionGrant, PairingError> {
        let url = format!("{}/api/v1/devices/session", self.base_url);

        let resp = self
            .http
            .post(&url)
            // 🔴 只进请求头：URL 会被 reqwest/tracing 打印，body 会被反代日志记录。
            .bearer_auth(device_token.expose())
            .send()
            .await
            .map_err(|e| PairingError::Http(e.to_string()))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| PairingError::Http(e.to_string()))?;

        if !status.is_success() {
            let err = parse_error_body(status.as_u16(), &text);
            // 排障只打「错误码 + 打码后的设备令牌」，绝不打印令牌正文。
            tracing::warn!(
                status = status.as_u16(),
                device_token = %redact_token(device_token.expose()),
                error = %err,
                "设备令牌换取用户会话被拒绝"
            );
            return Err(err);
        }

        let grant = parse_device_session_body(&text)?;
        tracing::info!(
            base_url = %self.base_url,
            device_token = %redact_token(device_token.expose()),
            user_token = %redact_token(grant.token.expose()),
            user = %grant.user.label(),
            ttl_s = ?grant.ttl_s,
            "已用设备令牌换取新的用户会话"
        );
        Ok(grant)
    }

    /// 签发一次性 WebView 免登票据（`POST /api/v1/auth/webview-ticket`）。
    ///
    /// ## 三段式主路径（对齐移动端 prepareAuth，2026-11 桌面接入）
    ///
    /// 服务端契约（已核实 harness_go `internal/api/webview_ticket_handler.go`）：
    ///
    /// ```text
    /// POST /api/v1/auth/webview-ticket   需用户会话（Bearer user_token）
    ///   Body: { device_id, ttl_s? }       （ttl_s 缺省=60s，客户端只能请求更短）
    ///   200 { ticket, expires_at }
    ///   401 用户会话无效 → 调用方走「设备令牌续期」段
    /// ```
    ///
    /// ## 凭证红线
    ///
    /// ticket 是一次性短时凭据：**绝不写日志、不放进错误文案**，签出后立即以
    /// String 形态返回给调用方（马上拼进 URL fragment，生命周期以秒计）。
    pub async fn issue_webview_ticket(
        &self,
        user_token: &UserToken,
        device_id: &str,
    ) -> Result<String, PairingError> {
        let url = format!("{}/api/v1/auth/webview-ticket", self.base_url);

        let body = TicketRequestBody { device_id };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(user_token.expose())
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
            let err = parse_error_body(status.as_u16(), &text);
            tracing::info!(
                status = status.as_u16(),
                error = %err,
                "ticket 签发被拒（走降级路径）"
            );
            return Err(err);
        }

        let parsed: TicketResponseBody = serde_json::from_str(&text)
            .map_err(|e| PairingError::BadResponse(format!("JSON 解析失败：{e}")))?;
        let ticket = parsed
            .ticket
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| PairingError::BadResponse("ticket 响应缺少 ticket 字段".into()))?;
        // 🔴 只打「已签发 + 打码形态」，绝不打 ticket 明文（一次性凭据红线）。
        tracing::info!(
            user_token = %redact_token(user_token.expose()),
            ticket_len = ticket.len(),
            expires_at = ?parsed.expires_at,
            "已签发 WebView 免登票据"
        );
        Ok(ticket)
    }

    /// 通知服务端**解除本设备绑定**（`POST /api/v1/devices/unpair`）。
    ///
    /// ## 为什么必须有这一步（本轮修的真实 bug）
    ///
    /// 桌面端点「解除配对」原先只清本地密钥链，**全程没有任何 HTTP 调用** ——
    /// 服务端 `devices` 记录原封不动，用户在服务端设备列表里仍看得到这台机器。
    /// 「解绑」两侧各说一套，等于只有客户端单方面认为解除成功。
    ///
    /// ## 契约（权威，勿改）
    ///
    /// ```text
    /// POST /api/v1/devices/unpair
    ///   Authorization: Bearer <device_token>
    ///   204 已吊销（**幂等**：无效 / 已吊销令牌也回 204）
    ///   401 缺少令牌
    /// ```
    ///
    /// 免用户令牌：设备令牌就是「我代表这台设备」的凭据，足以自解约。
    ///
    /// ## 凭证红线
    ///
    /// 令牌只进 `Authorization` 头，绝不进 URL / body；日志经 [`redact_token`] 打码。
    pub async fn unpair_self(&self, device_token: &DeviceToken) -> Result<(), PairingError> {
        let url = format!("{}/api/v1/devices/unpair", self.base_url);

        let resp = self
            .http
            .post(&url)
            .bearer_auth(device_token.expose())
            .send()
            .await
            .map_err(|e| PairingError::Http(e.to_string()))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| PairingError::Http(e.to_string()))?;

        if !status.is_success() {
            let err = parse_error_body(status.as_u16(), &text);
            tracing::warn!(
                status = status.as_u16(),
                device_token = %redact_token(device_token.expose()),
                error = %err,
                "服务端拒绝解除本设备绑定"
            );
            return Err(err);
        }

        tracing::info!(
            base_url = %self.base_url,
            device_token = %redact_token(device_token.expose()),
            "服务端已确认解除本设备绑定"
        );
        Ok(())
    }

    /// 校验 `user_token` 是否仍被服务端认可（`GET /api/v1/auth/me`）。
    ///
    /// ## 三种返回的语义必须分清
    ///
    /// - `Ok(true)`：会话仍有效 → 调用方直接重放 Cookie 即可（无需续期）。
    /// - `Ok(false)`：服务端**明确否认**（401/403）→ 会话已失效，该续期了。
    /// - `Err(_)`：连不通 / 服务端 5xx 等**不确定**状态。调用方要把它当"不确定"
    ///   而非"失效"——把它当失效会让一次网络抖动变成一次不必要的重新配对风险。
    ///
    /// 之所以不解析响应体：这里只关心"是否还认这条会话"，用户资料在续期响应里
    /// 已经有了。多解析一层就多一处能因字段改名而误判的地方。
    pub async fn check_user_session(
        &self,
        user_token: &UserToken,
    ) -> Result<bool, PairingError> {
        let url = format!("{}/api/v1/auth/me", self.base_url);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(user_token.expose())
            .send()
            .await
            .map_err(|e| PairingError::Http(e.to_string()))?;

        let status = resp.status();
        if status.is_success() {
            return Ok(true);
        }
        // 401/403 是服务端对"这条会话不认"的明确表态。
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN
        {
            // 丢弃 body 前先读掉，避免连接池里留下未消费的响应。
            let _ = resp.text().await;
            tracing::info!(
                status = status.as_u16(),
                user_token = %redact_token(user_token.expose()),
                "服务端不认可当前用户会话，需要续期"
            );
            return Ok(false);
        }
        let text = resp.text().await.unwrap_or_default();
        Err(parse_error_body(status.as_u16(), &text))
    }

    /// 表单登录（`POST /api/v1/auth/login`，免鉴权端点）。
    ///
    /// ## 为什么壳要自己发登录请求（对齐移动端「登录只在原生」铁律）
    ///
    /// 服务端 Web UI 不放登录表单（§6.1 决策 2），且网页里登录产生的会话只进
    /// WebView Cookie、不回写密钥链 —— 原生与页面两套账。由壳发起：密码不经过
    /// JS 堆，令牌从 HTTP 响应直接进 [`UserToken`]（zeroize）→ vault，
    /// **中间不存在裸 String**。
    ///
    /// ## 契约（已核实 harness_go `internal/api/auth_handler.go`）
    ///
    /// ```text
    /// POST /api/v1/auth/login   免鉴权
    ///   Body: { username, password }          （键集合必须恰为这两个）
    ///   200 { user:{id,username,display_name,role}, token }
    ///   4xx/5xx 统一错误体 { code, message }
    /// ```
    ///
    /// ## 凭证红线
    ///
    /// 令牌装入 [`UserToken`]（zeroize）；**绝不打印令牌与密码**（日志只打
    /// 打码长度级信息与用户名）。
    pub async fn auth_login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<SessionGrant, PairingError> {
        let url = format!("{}/api/v1/auth/login", self.base_url);

        let body = LoginRequestBody { username, password };

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
            let err = parse_error_body(status.as_u16(), &text);
            // 密码绝不进日志；只打打码长度级信息，便于排障（401 还是 5xx）。
            tracing::warn!(
                status = status.as_u16(),
                username = %username,
                password_len = password.len(),
                error = %err,
                "表单登录被拒绝"
            );
            return Err(err);
        }

        let grant = parse_login_body(&text)?;
        tracing::info!(
            base_url = %self.base_url,
            username = %username,
            user_token = %redact_token(grant.token.expose()),
            user = %grant.user.label(),
            "表单登录成功"
        );
        Ok(grant)
    }
}

/// 表单登录请求体（对齐服务端 `loginReq`：键集合必须恰为 {username, password}，
/// 服务端 DisallowUnknownFields）。
#[derive(Debug, Serialize)]
struct LoginRequestBody<'a> {
    username: &'a str,
    password: &'a str,
}

/// 登录响应体（对齐 `auth_handler.go` 的 login 响应）。
///
/// `user` 可能残缺（旧服务端/私有部署），全部 `#[serde(default)]` 交给
/// [`parse_login_body`] 分级判定；`token` 是唯一必要字段。
#[derive(Debug, Deserialize)]
struct LoginResponseBody {
    /// 用户会话令牌。
    #[serde(default)]
    token: Option<String>,
    /// 会话所属用户。
    #[serde(default)]
    user: Option<PairedUser>,
}

/// 解析登录响应（纯函数，供 [`PairingClient::auth_login`] 与单测共用）。
///
/// 与 [`parse_session_grant`] 同一宽容策略：token 必需，user 缺失降级为占位。
/// 有 user 却没有 token 是危险残缺 —— 绝不能凭它渲染「已登录」。
fn parse_login_body(text: &str) -> Result<SessionGrant, PairingError> {
    let parsed: LoginResponseBody = serde_json::from_str(text)
        .map_err(|e| PairingError::BadResponse(format!("JSON 解析失败：{e}")))?;
    let token = parsed
        .token
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| PairingError::BadResponse("登录响应缺少 token（无法建立会话）".into()))?;
    let user = parsed.user.unwrap_or_default();
    Ok(SessionGrant {
        token: UserToken::new(token),
        user,
        // 登录端点不回 TTL（会话时效由 Cookie 表达）；此处 None = 仅展示语义。
        ttl_s: None,
    })
}

/// ticket 签发请求体（对齐 `WebviewTicketReq`；ttl 省略取服务端默认 60s）。
#[derive(Debug, Serialize)]
struct TicketRequestBody<'a> {
    device_id: &'a str,
}

/// ticket 签发响应体（对齐 `webview_ticket_handler.go`）。
///
/// 🔴 `expires_at` 不落日志明文，仅记形态；`ticket` 字段绝不能进任何日志。
#[derive(Debug, Deserialize)]
struct TicketResponseBody {
    /// 一次性票据明文（消费完立即丢弃）。
    #[serde(default)]
    ticket: Option<String>,
    /// 过期时刻（Unix 毫秒）。缺失不致命：桌面端不做本地过期判定。
    #[serde(default)]
    expires_at: Option<i64>,
}

/// 把一次性 ticket 拼进入口 URL 的 **fragment**（纯函数，对齐移动端
/// `appendTicketFragment` 与 Web 端 `readTicketFromHash` 的双向契约）。
///
/// ## 为什么走 fragment 而不是 query
///
/// fragment 按规范**不会发到服务端**（不进 Referer、不落 access log），只有
/// 页面 JS 自己能读到 —— 兑换由 Web 前端 `authStore.boot()` 完成。
///
/// ## 拼接规则（与两端既有实现逐字对齐，勿改）
///
/// - 无 hash 路由：`http://host/#ticket=xxx`
/// - 有 hash 路由：在原 fragment 后以 `&` 追加：`#/route&ticket=xxx`
/// - ticket 经 `encode`（percent-encoding）编码，与移动端 `Uri.encodeComponent`、
///   Web 端 `decodeURIComponent` 三方一致。
pub fn append_ticket_fragment(entry_url: &str, ticket: &str) -> String {
    // ticket 是 32 字节随机值（hex/base64 视服务端实现），编码保证任意字符安全；
    // 空值不该被调用（签发已判空），这里仍防御性返回原 URL。
    if ticket.is_empty() {
        return entry_url.to_string();
    }
    let encoded: String = ticket
        .bytes()
        .map(|b| {
            // 简单安全字符集：字母数字与 `-._~` 不编码（RFC 3986 unreserved），
            // 其余逐字节 %XX，与 encodeURIComponent 对 ASCII 的行为一致。
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    match entry_url.find('#') {
        Some(pos) => {
            let (head, hash) = entry_url.split_at(pos);
            let bare = &hash[1..];
            if bare.is_empty() {
                format!("{head}#ticket={encoded}")
            } else {
                format!("{head}#{bare}&ticket={encoded}")
            }
        }
        None => format!("{entry_url}#ticket={encoded}"),
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

    /* ============ 表单登录响应解析 ============ */

    #[test]
    fn login_body_parses_full_response() {
        let text = r#"{"user":{"id":"u1","username":"op","display_name":"操作员","role":"owner"},"token":"hgt_abc123"}"#;
        let grant = parse_login_body(text).unwrap();
        assert_eq!(grant.user.label(), "操作员");
    }

    #[test]
    fn login_body_missing_token_is_bad_response() {
        // 有 user 却没有 token 是危险残缺：绝不能凭它渲染「已登录」。
        let text = r#"{"user":{"id":"u1","username":"op"}}"#;
        assert!(parse_login_body(text).is_err());
    }

    #[test]
    fn login_body_empty_token_is_bad_response() {
        let text = r#"{"token":"   "}"#;
        assert!(parse_login_body(text).is_err());
    }

    #[test]
    fn login_body_user_defaults_to_placeholder_label() {
        let grant = parse_login_body(r#"{"token":"hgt_x"}"#).unwrap();
        assert_eq!(grant.user.label(), "该账号");
        assert_eq!(grant.ttl_s, None);
    }

    #[test]
    fn login_body_invalid_json_is_bad_response() {
        assert!(parse_login_body("<html>err</html>").is_err());
    }

    /* ============ ticket fragment 拼接（与移动端/Web 端双向契约） ============ */

    #[test]
    fn ticket_fragment_appends_to_bare_url() {
        // 无 hash 路由：`http://host/#ticket=xxx`（移动端 webEntryUri 产物形态）
        let u = append_ticket_fragment("http://127.0.0.1:5611/", "abc123");
        assert_eq!(u, "http://127.0.0.1:5611/#ticket=abc123");
    }

    #[test]
    fn ticket_fragment_appends_after_existing_hash_route() {
        // 有 hash 路由：在原 fragment 后以 `&` 追加（对齐移动端拼接规则）
        let u = append_ticket_fragment("http://127.0.0.1:5611/#/route", "abc");
        assert_eq!(u, "http://127.0.0.1:5611/#/route&ticket=abc");
    }

    #[test]
    fn ticket_fragment_encodes_special_chars() {
        // 空格 → %20；`=` 等保留字也被编码，Web 端 decodeURIComponent 能还原。
        let u = append_ticket_fragment("http://h/", "a b=c");
        assert_eq!(u, "http://h/#ticket=a%20b%3Dc");
    }

    #[test]
    fn ticket_fragment_empty_ticket_returns_original() {
        let u = append_ticket_fragment("http://h/", "");
        assert_eq!(u, "http://h/");
    }

    #[test]
    fn ticket_fragment_bare_hash_gets_ticket_directly() {
        // 入口 URL 带 `#` 但 fragment 为空（webEntryUri 的 `?#` 历史形态）
        let u = append_ticket_fragment("http://h/?#", "t");
        assert_eq!(u, "http://h/?#ticket=t");
    }

    /* ============ 会话授权（user_token）解析 ============ */

    /// 完整响应：三字段齐全 → 解析出会话授权。
    #[test]
    fn full_response_body_parses_session_grant() {
        let json = r#"{
            "device_id": "dev-1",
            "device_token": "hgd_device_abc",
            "ws_path": "/api/v1/devices/ws",
            "protocol_version": 1,
            "user_token": "hgt_user_abc",
            "user": {"id":"u1","username":"alice","display_name":"爱丽丝","role":"owner"},
            "session_ttl_s": 604800
        }"#;
        let body: PairResponseBody = serde_json::from_str(json).expect("应能解析");
        let grant = parse_session_grant(body.user_token, body.user, body.session_ttl_s)
            .expect("三字段齐全应有会话授权");
        assert_eq!(grant.token.expose(), "hgt_user_abc");
        assert_eq!(grant.user.id, "u1");
        assert_eq!(grant.user.username, "alice");
        assert_eq!(grant.user.label(), "爱丽丝");
        assert_eq!(grant.ttl_s, Some(604800));
    }

    /// 🔴 缺失降级（核心验收点）：整组字段缺失 → None，且**不是错误**。
    #[test]
    fn legacy_response_without_session_fields_degrades_silently() {
        let json = r#"{
            "device_id": "dev-1",
            "device_token": "hgd_device_abc",
            "ws_path": "/api/v1/devices/ws",
            "protocol_version": 1
        }"#;
        // 老服务端响应里根本没有这三个字段：解析必须成功（宽容），不是 BadResponse。
        let body: PairResponseBody = serde_json::from_str(json).expect("旧响应必须仍可解析");
        assert!(body.user_token.is_none());
        assert!(body.user.is_none());
        assert!(body.session_ttl_s.is_none());
        assert!(
            parse_session_grant(body.user_token, body.user, body.session_ttl_s).is_none(),
            "旧服务端必须降级为「需登录」而非报错"
        );
    }

    /// 只给了 user/ttl 却没有 token：绝不渲染「已登录」。
    #[test]
    fn session_without_token_is_rejected() {
        let grant = parse_session_grant(
            None,
            Some(PairedUser {
                id: "u1".into(),
                ..Default::default()
            }),
            Some(3600),
        );
        assert!(grant.is_none(), "无 user_token 不得视为已登录");
    }

    /// 空白令牌等同缺失（服务端偶发空串时不能把空串写进 Cookie）。
    #[test]
    fn blank_user_token_is_treated_as_absent() {
        assert!(parse_session_grant(Some("   ".to_string()), None, None).is_none());
        assert!(parse_session_grant(Some(String::new()), None, None).is_none());
    }

    /// 只缺展示字段时仍保留免登录（纯装饰字段缺失不该逼用户手动登录）。
    #[test]
    fn missing_display_fields_keep_session_usable() {
        let grant = parse_session_grant(Some("hgt_only_token".into()), None, None)
            .expect("有令牌即免登录");
        assert_eq!(grant.token.expose(), "hgt_only_token");
        assert_eq!(grant.ttl_s, None);
        // 无展示名时给中性占位，不 panic。
        assert_eq!(grant.user.label(), "该账号");
    }

    /// 用户展示名的兜底顺序：display_name → username → 占位。
    #[test]
    fn user_label_falls_back_to_username_then_placeholder() {
        let mut u = PairedUser {
            username: "alice".into(),
            ..Default::default()
        };
        assert_eq!(u.label(), "alice");
        u.username = "  ".into();
        assert_eq!(u.label(), "该账号");
        u.display_name = " 爱丽丝 ".into();
        assert_eq!(u.label(), "爱丽丝");
    }

    /// 🔴 安全回归：`{:?}` 整个 `PairedDevice` / `SessionGrant` 都不得出现令牌明文。
    /// （`DeviceToken: Debug` 打码 + `SessionGrant` 手写 Debug，两者缺一个就会漏。）
    #[test]
    fn paired_device_debug_never_leaks_any_token() {
        let session = parse_session_grant(
            Some("hgt_super_secret_session".into()),
            Some(PairedUser {
                display_name: "爱丽丝".into(),
                ..Default::default()
            }),
            Some(600),
        );
        let device = PairedDevice {
            device_id: "dev-1".into(),
            token: DeviceToken::new("hgd_super_secret_device".into()),
            ws_url: "ws://127.0.0.1:5611/api/v1/devices/ws".into(),
            protocol_version: 1,
            server_base_url: "http://127.0.0.1:5611".into(),
            session,
        };
        let dbg = format!("{device:?}");
        assert!(!dbg.contains("super_secret_device"), "泄露设备令牌：{dbg}");
        assert!(!dbg.contains("super_secret_session"), "泄露用户令牌：{dbg}");
        // 但排障需要的信息要保留。
        assert!(dbg.contains("dev-1"), "应保留 device_id：{dbg}");
        assert!(dbg.contains("爱丽丝"), "应保留账号展示名：{dbg}");

        let grant_dbg = format!("{:?}", device.session.as_ref().expect("应有会话"));
        assert!(
            !grant_dbg.contains("super_secret_session"),
            "SessionGrant Debug 泄露：{grant_dbg}"
        );
    }

    /* ============ 设备令牌续期会话（POST /api/v1/devices/session） ============ */

    /// 成功：三字段齐全 → 复用 `parse_session_grant` 解析出完整授权。
    #[test]
    fn device_session_response_parses_full_grant() {
        let json = r#"{
            "user_token": "hgt_renewed_session",
            "user": {"id":"u9","username":"bob","display_name":"鲍勃","role":"owner"},
            "session_ttl_s": 604800
        }"#;
        let grant = parse_device_session_body(json).expect("续期响应应能解析");
        assert_eq!(grant.token.expose(), "hgt_renewed_session");
        assert_eq!(grant.user.id, "u9");
        assert_eq!(grant.user.label(), "鲍勃");
        assert_eq!(grant.ttl_s, Some(604800));
    }

    /// 宽容：只回 token（缺 user/ttl）→ 仍可用，展示名降级为占位。
    /// 与配对响应保持同一套分级宽容策略，避免「配对能降级、续期直接失败」的口径分裂。
    #[test]
    fn device_session_response_with_only_token_still_usable() {
        let grant = parse_device_session_body(r#"{"user_token":"hgt_only"}"#)
            .expect("有令牌即应可续期");
        assert_eq!(grant.token.expose(), "hgt_only");
        assert_eq!(grant.ttl_s, None);
        assert_eq!(grant.user.label(), "该账号");
    }

    /// 200 却没有 user_token：必须报 BadResponse（什么都没换到，不能当成功）。
    #[test]
    fn device_session_response_without_token_is_bad_response() {
        let err = parse_device_session_body(r#"{"user": {"id":"u1"}, "session_ttl_s": 60}"#)
            .expect_err("无令牌不得视为续期成功");
        assert!(
            matches!(err, PairingError::BadResponse(_)),
            "应为 BadResponse，实际：{err:?}"
        );
    }

    /// 非法 JSON：不得 panic，归一成 BadResponse。
    #[test]
    fn device_session_response_with_invalid_json_is_bad_response() {
        assert!(matches!(
            parse_device_session_body("<html>502 Bad Gateway</html>"),
            Err(PairingError::BadResponse(_))
        ));
    }

    /// 403 `device.owner_unknown`：保留服务端错误码（上层据此区分"补齐归属前重试无用"）。
    #[test]
    fn error_body_keeps_owner_unknown_code() {
        let err = parse_error_body(
            403,
            r#"{"code":"device.owner_unknown","message":"设备归属账号未知"}"#,
        );
        match err {
            PairingError::Rejected { code, message } => {
                assert_eq!(code, "device.owner_unknown");
                assert_eq!(message, "设备归属账号未知");
            }
            other => panic!("应为 Rejected，实际：{other:?}"),
        }
    }

    /// 401 吊销：同样保留服务端码，且消息里不得出现任何令牌。
    #[test]
    fn error_body_keeps_revoked_code_without_token() {
        let err = parse_error_body(401, r#"{"code":"device.token_revoked"}"#);
        let shown = err.to_string();
        assert!(shown.contains("device.token_revoked"), "应保留错误码：{shown}");
        assert!(!shown.contains("hgt_"), "错误文案不得含令牌痕迹：{shown}");
    }

    /// 非 JSON 错误体（反代 HTML）：降级为 unknown + 截断原文，绝不 panic。
    #[test]
    fn error_body_falls_back_for_non_json() {
        match parse_error_body(502, "<html>502 Bad Gateway</html>") {
            PairingError::Rejected { code, message } => {
                assert_eq!(code, "unknown");
                assert!(message.contains("502"), "应带上状态码：{message}");
            }
            other => panic!("应为 Rejected，实际：{other:?}"),
        }
    }

    /// 401/403 语义分流的纯函数证据：两者归一后 code 不同（上层据此走不同恢复路径）。
    #[test]
    fn error_body_distinguishes_401_and_403() {
        let unauthorized = parse_error_body(401, r#"{"code":"unauthorized","message":"未授权"}"#);
        let forbidden = parse_error_body(
            403,
            r#"{"code":"device.owner_unknown","message":"归属未知"}"#,
        );
        let code_of = |e: PairingError| match e {
            PairingError::Rejected { code, .. } => code,
            other => panic!("应为 Rejected，实际：{other:?}"),
        };
        assert_eq!(code_of(unauthorized), "unauthorized");
        assert_eq!(code_of(forbidden), "device.owner_unknown");
    }
}
