//! stdin JSONL 控制协议（对齐 `docs/桌面端架构与功能设计.md` §17.2）。
//!
//! ## 为什么走 stdin 而不是命令行参数/环境变量
//!
//! 设备令牌（`hgd_...`）是长期凭证，一旦进 `argv` 或环境变量，同机任何进程都能
//! 通过 `ps`/任务管理器/`/proc/<pid>/environ` 读到；进日志后还会随日志文件长期留存、
//! 被崩溃上报带走。stdin 是**一次性单向管道**：父进程写一条 `auth` 就关掉写端，
//! 子进程读完即销毁内存中的明文，攻击面最小。
//!
//! 因此本模块的三条硬性约束（代码里逐条落地，不靠记忆）：
//! 1. [`AuthConfig`] 只有**手写 `Debug`**（打码成 `hgd_***`），不 `derive(Debug)`；
//! 2. 刻意**不实现 `Serialize`**，避免有人顺手把含 token 的结构塞进日志/上报；
//! 3. [`IpcError`] 的所有变体都不携带原始行文本（`serde_json::Error` 自带的是
//!    行号/列号信息，不含 token 值）。
//!
//! ## 协议形状
//!
//! ```jsonl
//! {"op":"auth","token":"hgd_xxx","ws_url":"wss://host/api/v1/devices/ws","protocol_version":1}
//! {"op":"reload_policy","roots":["C:\\Users\\me\\work"],"exec_allowlist":["git","node"]}
//! {"op":"shutdown"}
//! ```
//!
//! **首行必须是 `auth`** —— 服务端地址与令牌是后续一切工作的前提，先跑再鉴权会让
//! 「连不上」和「没授权」两件事混在一起。之后的行是增量控制命令，**未知 `op` 一律
//! 容忍**（返回可忽略的 [`IpcError::UnknownOp`]），因为宿主壳版本可能比 Runner 新，
//! 端侧不能因为一条看不懂的命令就自杀。

use std::io::BufRead;

use serde::Deserialize;

/// 把令牌打码成 `hgd_***` 形式，供日志/Debug 使用。
///
/// 只保留 `_` 之前的前缀（`hgd_` 这类前缀本身不是秘密，它的作用是让人一眼看出
/// 「这是个设备令牌」），其余全部替换。没有 `_` 的凭证直接整体隐藏 —— 宁可少一条
/// 有用的日志，也不能赌它是不是敏感值。
pub fn redact_token(token: &str) -> String {
    if token.is_empty() {
        return "<empty>".to_string();
    }
    match token.split_once('_') {
        Some((prefix, _)) if !prefix.is_empty() => format!("{prefix}_***"),
        _ => "***".to_string(),
    }
}

/// `auth` 命令携带的启动配置。
///
/// 手写 `Debug` 而非 derive：一旦 derive，`tracing::debug!("{:?}", cfg)` 就会把
/// 令牌原样写进日志文件。这个错误在评审里几乎看不出来，所以从类型层面断掉它。
#[derive(Clone, Deserialize)]
pub struct AuthConfig {
    /// 设备令牌（🔴 只经 stdin 传输，绝不出现在 argv/环境变量/日志）。
    pub token: String,
    /// WS 端点，形如 `wss://host/api/v1/devices/ws`，**不含** token 查询参数。
    pub ws_url: String,
    /// 端侧期望的协议版本（缺省取当前版本）。
    #[serde(default = "default_protocol_version")]
    pub protocol_version: i32,
}

fn default_protocol_version() -> i32 {
    hd_protocol::CURRENT_PROTOCOL_VERSION
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("token", &redact_token(&self.token))
            .field("ws_url", &self.ws_url)
            .field("protocol_version", &self.protocol_version)
            .finish()
    }
}

/// 控制命令。
///
/// 内部标签枚举（`tag = "op"`）：线上形状就是 `{"op":"...", ...字段}`，不需要多包一层。
/// `#[serde(other)]` 是「未知 op 不 panic」的类型级保障 —— 没有它，新增一条命令就会
/// 让旧 Runner 解析失败。
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcCommand {
    /// 首行启动配置。
    Auth(AuthConfig),
    /// 热更新守卫策略（工作区根目录白名单 + 可执行文件白名单）。
    ReloadPolicy {
        /// 允许访问的工作区根目录。
        roots: Vec<String>,
        /// 允许执行的命令名（如 `git` / `node`）。
        exec_allowlist: Vec<String>,
    },
    /// 请求优雅退出。
    Shutdown,
    /// 无法识别的 `op`（宿主壳比 Runner 新时会出现）。
    #[serde(other)]
    Unknown,
}

/// IPC 层错误。
#[derive(Debug)]
pub enum IpcError {
    /// 行不是合法 JSON。
    Json(serde_json::Error),
    /// 首行不是 `auth`（含首行为空/EOF）。
    MissingAuth,
    /// 无法识别的 `op`。**可忽略**：宿主新增命令不应打断既有会话。
    UnknownOp(String),
    /// stdin 读取失败。
    Io(std::io::Error),
}

impl IpcError {
    /// 是否属于「可以忽略并继续读下一行」的错误。
    ///
    /// 只把未知 `op` 归为此类：JSON 解析失败说明管道里进了非协议内容，继续读下去
    /// 只会把脏数据混进控制流。
    pub fn is_ignorable(&self) -> bool {
        matches!(self, IpcError::UnknownOp(_))
    }
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // serde_json 的 Display 只含行列号与期望类型，不含字段值 → 不会泄 token
            IpcError::Json(e) => write!(f, "IPC 行不是合法 JSON: {e}"),
            IpcError::MissingAuth => write!(f, "首行必须是 auth 命令"),
            IpcError::UnknownOp(op) => write!(f, "忽略未知控制命令 op={op}"),
            IpcError::Io(e) => write!(f, "读取 stdin 失败: {e}"),
        }
    }
}

impl std::error::Error for IpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IpcError::Json(e) => Some(e),
            IpcError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for IpcError {
    fn from(e: serde_json::Error) -> Self {
        IpcError::Json(e)
    }
}

impl From<std::io::Error> for IpcError {
    fn from(e: std::io::Error) -> Self {
        IpcError::Io(e)
    }
}

/// 解析首行，**必须**是 `auth`。
///
/// 空行/纯空白同样判为错误：放过它会让人以为已经鉴权，而实际令牌没送到。
pub fn parse_auth_first_line(line: &str) -> Result<AuthConfig, IpcError> {
    // 空白先判：空白串交给 serde_json 只会得到「EOF while parsing」，
    // 那会把「宿主压根没送 auth」伪装成「JSON 写坏了」，排查时方向全错。
    if line.trim().is_empty() {
        return Err(IpcError::MissingAuth);
    }
    match parse_command(line)? {
        IpcCommand::Auth(cfg) => Ok(cfg),
        _ => Err(IpcError::MissingAuth),
    }
}

/// 解析任意一行控制命令。
///
/// 未知 `op` 返回 [`IpcError::UnknownOp`]（携带 op 名，便于日志定位），
/// 而不是 panic 或断开 —— 调用方可用 [`IpcError::is_ignorable`] 判断是否跳过。
pub fn parse_command(line: &str) -> Result<IpcCommand, IpcError> {
    let cmd: IpcCommand = serde_json::from_str(line)?;
    match cmd {
        // serde 的 `other` 分支拿不到 op 名，故此处再取一次；只在未知命令路径付出这点成本。
        IpcCommand::Unknown => Err(IpcError::UnknownOp(
            op_name_of(line).unwrap_or_else(|| "<未声明>".to_string()),
        )),
        other => Ok(other),
    }
}

/// 从原始行里取出 `op` 字段（仅用于给未知命令的日志补上名字）。
fn op_name_of(line: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()?
        .get("op")?
        .as_str()
        .map(str::to_string)
}

/// JSONL 读取器：把 stdin 的逐行字节流翻译成命令。
///
/// 刻意做在 `BufRead`（同步）而不是 tokio 异步流上：控制命令频率极低（一次启动 +
/// 偶发策略热更新），为它把整个 Runner 的 stdin 变成异步任务只会增加复杂度；
/// 同步阻塞读发生在专职线程里，不影响网络侧的重连与心跳。
pub struct IpcReader<R: BufRead> {
    inner: R,
    auth_done: bool,
}

impl<R: BufRead> IpcReader<R> {
    /// 包装一个缓冲读取器（生产用 `std::io::stdin().lock()`）。
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            auth_done: false,
        }
    }

    /// 读下一行非空内容；`None` 表示 EOF。
    fn next_non_empty_line(&mut self) -> Result<Option<String>, IpcError> {
        loop {
            let mut buf = String::new();
            if self.inner.read_line(&mut buf)? == 0 {
                return Ok(None);
            }
            let line = buf.trim();
            if !line.is_empty() {
                return Ok(Some(line.to_string()));
            }
            // 空行跳过：父进程的写入缓冲可能与命令边界不对齐，不值得因此报错。
        }
    }

    /// 读首行 `auth`。
    ///
    /// 必须在读任何控制命令之前调用；`auth_done` 会在成功后置位，避免重复鉴权
    /// （运行中途换令牌属于「改配置」，应重启 Runner）。
    ///
    /// 版本兼容性在这里**不判定**：`AuthConfig` 只是传输结构，是否接受某个协议版本
    /// 由连接层（`hd_protocol::compatible_version`）决定。在此重复判定会把
    /// 「版本不兼容」伪装成「IPC 格式错误」，排查时找错方向。
    pub fn read_auth(&mut self) -> Result<AuthConfig, IpcError> {
        let line = self.next_non_empty_line()?.ok_or(IpcError::MissingAuth)?;
        let cfg = parse_auth_first_line(&line)?;
        self.auth_done = true;
        Ok(cfg)
    }

    /// 是否已完成首行鉴权。
    pub fn auth_done(&self) -> bool {
        self.auth_done
    }

    /// 读下一条控制命令。
    ///
    /// `Ok(None)` 表示 **stdin 已关闭（EOF）** —— 这是宿主壳退出的信号，调用方
    /// 应据此走优雅退出（对齐 §17.2「EOF 自杀」），否则会留下孤儿进程占着端口。
    pub fn next_command(&mut self) -> Result<Option<IpcCommand>, IpcError> {
        match self.next_non_empty_line()? {
            None => Ok(None),
            Some(line) => parse_command(&line).map(Some),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn reader(src: &str) -> IpcReader<Cursor<Vec<u8>>> {
        IpcReader::new(Cursor::new(src.as_bytes().to_vec()))
    }

    #[test]
    fn parses_auth_first_line() {
        let line = r#"{"op":"auth","token":"hgd_secret_value","ws_url":"wss://host/api/v1/devices/ws","protocol_version":1}"#;
        let cfg = parse_auth_first_line(line).expect("应当解析成功");
        assert_eq!(cfg.token, "hgd_secret_value");
        assert_eq!(cfg.ws_url, "wss://host/api/v1/devices/ws");
        assert_eq!(cfg.protocol_version, 1);
    }

    #[test]
    fn protocol_version_defaults_when_omitted() {
        // 旧宿主壳可能不传 protocol_version，不能因此拒绝启动
        let line = r#"{"op":"auth","token":"hgd_x","ws_url":"wss://h/ws"}"#;
        let cfg = parse_auth_first_line(line).expect("缺省版本应可解析");
        assert_eq!(cfg.protocol_version, hd_protocol::CURRENT_PROTOCOL_VERSION);
    }

    #[test]
    fn first_line_must_be_auth() {
        // 先发 reload_policy 再发 auth 是危险顺序：策略先落地、连接后鉴权，
        // 一旦鉴权失败就留下一个「有策略没身份」的进程。
        let err = parse_auth_first_line(r#"{"op":"shutdown"}"#).expect_err("首行非 auth 必须报错");
        assert!(matches!(err, IpcError::MissingAuth));

        // 空行同样不算 auth
        let err = parse_auth_first_line("   ").expect_err("空行必须报错");
        assert!(matches!(err, IpcError::MissingAuth));
    }

    #[test]
    fn parses_reload_policy() {
        let line = r#"{"op":"reload_policy","roots":["C:\\Users\\me\\work"],"exec_allowlist":["git","node"]}"#;
        match parse_command(line).expect("应当解析成功") {
            IpcCommand::ReloadPolicy {
                roots,
                exec_allowlist,
            } => {
                assert_eq!(roots, vec!["C:\\Users\\me\\work".to_string()]);
                assert_eq!(exec_allowlist, vec!["git".to_string(), "node".to_string()]);
            }
            other => panic!("应解析为 reload_policy，实际 {other:?}"),
        }
    }

    #[test]
    fn parses_shutdown() {
        assert!(matches!(
            parse_command(r#"{"op":"shutdown"}"#).expect("应当解析成功"),
            IpcCommand::Shutdown
        ));
    }

    #[test]
    fn unknown_op_is_tolerated_not_panicking() {
        let err =
            parse_command(r#"{"op":"future_command","x":1}"#).expect_err("未知 op 应返回错误");
        assert!(
            err.is_ignorable(),
            "未知 op 必须是可忽略错误，否则新增命令会让旧 Runner 断开"
        );
        assert!(
            err.to_string().contains("future_command"),
            "日志要能定位未知 op"
        );
    }

    #[test]
    fn malformed_json_is_not_ignorable() {
        // 非 JSON 说明管道进了脏数据，继续读只会把错误叠加下去
        let err = parse_command("not json at all").expect_err("非法 JSON 应报错");
        assert!(matches!(err, IpcError::Json(_)));
        assert!(!err.is_ignorable());
    }

    #[test]
    fn debug_does_not_leak_token() {
        let line = r#"{"op":"auth","token":"hgd_super_secret_123","ws_url":"wss://h/ws"}"#;
        let cfg = parse_auth_first_line(line).expect("应当解析成功");
        let shown = format!("{cfg:?}");
        assert!(
            !shown.contains("super_secret"),
            "Debug 输出泄露了令牌正文: {shown}"
        );
        assert!(shown.contains("hgd_***"), "应打码成 hgd_*** 形式: {shown}");
        // 命令枚举同样不能借 Auth 变体把令牌带出去
        let cmd = parse_command(line).expect("应当解析成功");
        let shown = format!("{cmd:?}");
        assert!(!shown.contains("super_secret"), "IpcCommand Debug 泄露令牌");
    }

    #[test]
    fn redact_token_keeps_only_prefix() {
        assert_eq!(redact_token("hgd_abcdef"), "hgd_***");
        assert_eq!(redact_token("noprefix"), "***");
        assert_eq!(redact_token(""), "<empty>");
    }

    #[test]
    fn reader_consumes_auth_then_commands_until_eof() {
        let src = concat!(
            r#"{"op":"auth","token":"hgd_x","ws_url":"wss://h/ws"}"#,
            "\n",
            "\n", // 空行必须被跳过
            r#"{"op":"reload_policy","roots":["C:\\w"],"exec_allowlist":["git"]}"#,
            "\n",
            r#"{"op":"shutdown"}"#,
            "\n"
        );
        let mut r = reader(src);
        assert!(!r.auth_done());
        r.read_auth().expect("首行应解析成功");
        assert!(r.auth_done());

        assert!(matches!(
            r.next_command().expect("应解析成功"),
            Some(IpcCommand::ReloadPolicy { .. })
        ));
        assert!(matches!(
            r.next_command().expect("应解析成功"),
            Some(IpcCommand::Shutdown)
        ));
        // EOF 是宿主壳退出的唯一信号 → 必须返回 None 让调用方优雅自杀
        assert!(
            r.next_command().expect("EOF 不是错误").is_none(),
            "EOF 必须返回 None 以触发优雅退出"
        );
    }

    #[test]
    fn reader_reports_missing_auth_on_empty_stdin() {
        let mut r = reader("");
        assert!(matches!(r.read_auth(), Err(IpcError::MissingAuth)));
    }
}
