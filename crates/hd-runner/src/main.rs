//! `hd-runner` 真实可执行入口（对齐 `docs/桌面端架构与功能设计.md` §17.2）。
//!
//! ## 启动协议：三句话讲完
//!
//! ```text
//! 父进程（宿主外壳）
//!   │  ① stdin 第一行：{"op":"auth","token":"hgd_...","ws_url":"wss://..."}
//!   ├─────────────────────────────────────────────▶ Runner
//!   │  ② 之后任意时刻：{"op":"reload_policy",...} / {"op":"shutdown"}
//!   │  ③ 关闭 stdin（EOF）
//!   ▼
//! Runner 自行退出（EOF 自杀）
//! ```
//!
//! ## 🔴 为什么 token 只从 stdin 读
//!
//! `argv` 对同机任何进程可见（`ps`、任务管理器、「进程命令行」列），环境变量在
//! `/proc/<pid>/environ` 里可读，两者还会被崩溃上报与日志顺带带走。stdin 是
//! **一次性单向管道**：父进程写完即关，Runner 读完就只留在自己的内存里。
//! 因此本文件里**刻意没有**任何 `std::env::args()` 读取 token 的路径 ——
//! 参数解析只认 `--dev` 这一个不带敏感值的开关。
//!
//! ## EOF 自杀的意义（防孤儿进程）
//!
//! 宿主外壳崩溃/被强杀时不会有机会通知子进程。若 Runner 不把「stdin 关闭」
//! 当成死亡信号，它就会变成一个连不上服务端、也没有人管理的僵尸进程，
//! 长期占着设备槽位（服务端以为该设备在线，一直往上派发任务）。读 stdin 得到
//! `Ok(None)` 即视为宿主已亡，立刻退出。

use std::io::BufReader;
use std::process::ExitCode;

use hd_runner::idempot::IdempotStore;
use hd_runner::ipc::{redact_token, IpcCommand, IpcReader};
use hd_runner::reconnect::ReconnectPolicy;
use hd_runner::router::Router;
use hd_runner::supervisor::{NoopObserver, Supervisor, WsConnector};

/// 未收到合法 `auth` 首行时的退出码。
///
/// 单独约定一个非 0 值（而不是泛泛的 1）：宿主外壳据此能区分
/// 「启动协议没谈成（§17.2 E_NO_AUTH，可能是父进程写错了）」与
/// 「连上后被服务端拒绝（那是业务错误，Runner 会自己重试到放弃）」。
const EXIT_NO_AUTH: u8 = 2;

/// 宿主下发的运行期信号（由 stdin 读线程转发给主循环）。
enum ControlSignal {
    /// 热更新策略。**当前仅记录日志**：`Router` 持有的 `Policy` 是不可变的
    /// `Arc`，真正生效需要重建 Router（见交付报告「已知限制」）。
    ReloadPolicy {
        roots: Vec<String>,
        exec_allowlist: Vec<String>,
    },
    /// 请求优雅退出。
    Shutdown,
}

#[tokio::main]
async fn main() -> ExitCode {
    // 日志走 stderr：stdout 可能被宿主当作协议通道，绝不能混入日志。
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    // `--dev` 只放宽**地址校验**，不放宽令牌来源：它在编译期/启动期都不携带任何秘密。
    let dev_mode = std::env::args().skip(1).any(|a| a == "--dev");

    let mut reader = IpcReader::new(BufReader::new(std::io::stdin()));

    // ① 首行必须是 auth。缺失/超时/格式错 → 非 0 退出（§17.2 E_NO_AUTH）。
    //    这里用阻塞读而不是 spawn_blocking：启动阶段只读一行，且此时还没有
    //    任何并发任务需要 runtime 线程去调度。
    let auth = match reader.read_auth() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hd-runner: 未收到合法 auth 首行（{e}），退出");
            return ExitCode::from(EXIT_NO_AUTH);
        }
    };

    // 打码记录：AuthConfig 的 Debug 已手写打码，这里再显式过一次 redact_token，
    // 让「日志里不出现明文令牌」这件事在本文件里也是肉眼可查的。
    tracing::info!(
        ws_url = %auth.ws_url,
        token = %redact_token(&auth.token),
        protocol_version = auth.protocol_version,
        dev_mode,
        "已从 stdin 取得启动配置"
    );

    // ② 地址安全闸门：生产强制 wss，只有 --dev 才允许明文 ws。
    //    为什么必须卡这一条：明文 ws 会让设备令牌在局域网上裸奔（`?token=` 在
    //    查询串里），一条 ARP 欺骗就能拿到长期凭证。
    if let Err(msg) = check_ws_url(&auth.ws_url, dev_mode) {
        eprintln!("hd-runner: {msg}");
        return ExitCode::from(EXIT_NO_AUTH);
    }

    // ③ 控制指令读线程。stdin 是阻塞 IO，用独立 OS 线程读（而不是 spawn_blocking
    //    占 runtime 的 blocking 池：那池子默认 512 个许可，被一个永不返回的
    //    stdin 读长期占用虽不致命，但语义上「一直阻塞」就该用专属线程）。
    let (sig_tx, mut sig_rx) = tokio::sync::mpsc::unbounded_channel::<ControlSignal>();
    std::thread::Builder::new()
        .name("hd-runner-stdin".into())
        .spawn(move || loop {
            match reader.next_command() {
                Ok(Some(IpcCommand::Shutdown)) => {
                    let _ = sig_tx.send(ControlSignal::Shutdown);
                    return;
                }
                Ok(Some(IpcCommand::ReloadPolicy {
                    roots,
                    exec_allowlist,
                })) => {
                    if sig_tx
                        .send(ControlSignal::ReloadPolicy {
                            roots,
                            exec_allowlist,
                        })
                        .is_err()
                    {
                        return; // 主循环已退出
                    }
                }
                // auth 已在前面消费；Unknown 是宿主版本更新的正常情况
                Ok(Some(IpcCommand::Auth(_))) | Ok(Some(IpcCommand::Unknown)) => {}
                // EOF：宿主已亡 → 立刻通知主循环退出（防孤儿进程）
                Ok(None) => {
                    tracing::info!("stdin 已 EOF（宿主退出），Runner 随之退出");
                    let _ = sig_tx.send(ControlSignal::Shutdown);
                    return;
                }
                // 可忽略的错误继续读；其余（脏协议）也继续 —— 一条坏行不该让
                // 一个已经连上服务端的 Runner 自杀。
                Err(e) => {
                    if !e.is_ignorable() {
                        tracing::warn!(error = %e, "忽略无法解析的控制行");
                    }
                }
            }
        })
        .ok();

    // ④ 组装 Router 并注册内置工具。
    //
    // 工具集刻意保持最小：端侧只补「服务端物理上做不到」的能力（§6.1 原则），
    // 而非把服务端能做的事搬过来。当前注册 `fs.list` —— 它是工作区宿主
    // （C3–C6）的入口，也是 `device-e2e` 联调验证真实执行链的工具。
    //
    // 🔴 注册必须走 `Router::register`（内部包一层 `Guarded`），绝不直接插裸 executor：
    // 路径白名单、工具白名单、超时、结果脱敏都由 `Guarded` 统一兜住。
    let build_router = |roots: Vec<std::path::PathBuf>| {
        let policy = std::sync::Arc::new(hd_core::Policy::new(roots, Vec::new()));
        let mut router = Router::new(
            std::sync::Arc::clone(&policy),
            std::sync::Arc::new(hd_core::NullAuditSink),
            std::sync::Arc::new(IdempotStore::with_defaults()),
        );
        router.register(hd_core::ListDirsExecutor::new(
            std::sync::Arc::clone(&policy),
            None,
            500, // 对齐服务端 fs_handler.go 的 fsMaxDirs
        ));
        router
    };

    // 初始白名单根：优先用 auth 未提供时的进程当前目录（保证开箱可用），
    // 后续由宿主经 `reload_policy` 精确下发。
    let initial_roots = initial_roots();
    let mut sup = Supervisor::new(
        WsConnector::new(auth.ws_url.clone(), auth.token.clone()),
        ReconnectPolicy::default(),
    )
    .with_router(std::sync::Arc::new(build_router(initial_roots)));
    // 令牌用完即弃：`WsConnector` 内部需要它建连接，故这里无法清零；
    // 但 `auth` 这个局部变量后续不再被引用，作用域结束即释放。
    let mut observer = NoopObserver;

    // ⑤ 主循环：supervisor 长驻。
    //
    // 🔴 **必须是循环，不能只 select! 一次**：宿主下发 `reload_policy` 是正常操作
    // （用户改设置就会发），若该分支执行完就返回，Runner 会当场退出——联调实测
    // 曾因此在「设备上线前就死掉」。只有 shutdown / stdin EOF / supervisor 自身
    // 终止这三种情况才允许离开循环。
    loop {
        tokio::select! {
            reason = sup.run(&mut observer) => {
                tracing::warn!(reason = %reason, "supervisor 终止，Runner 退出");
                return ExitCode::SUCCESS;
            }
            sig = sig_rx.recv() => {
                match sig {
                    // stdin EOF（None）与显式 shutdown 等价：宿主已亡，本进程必须跟着走。
                    Some(ControlSignal::Shutdown) | None => {
                        tracing::info!("收到 shutdown 或 stdin EOF，优雅退出");
                        return ExitCode::SUCCESS;
                    }
                    Some(ControlSignal::ReloadPolicy { roots, exec_allowlist }) => {
                        // 真正生效，而不是记一条 warn 就完事：重建 Router 并替换进 supervisor。
                        // 重建而非原地改 Policy，是因为 `Guarded` 持有 `Arc<Policy>` 快照，
                        // 原地改需要内部可变性，反而更容易漏掉某条路径的重新校验。
                        let paths: Vec<std::path::PathBuf> =
                            roots.iter().map(std::path::PathBuf::from).collect();
                        tracing::info!(
                            roots = ?roots,
                            exec_allowlist = ?exec_allowlist,
                            "reload_policy：重建 Router 并继续运行"
                        );
                        sup = sup.with_router(std::sync::Arc::new(build_router(paths)));
                        // 不 return：继续下一轮，连接与心跳不受影响。
                    }
                }
            }
        }
    }
}

/// 初始白名单根：当前工作目录。
///
/// 为什么不用用户主目录：Windows 上主目录可能极大，而 Runner 启动时通常已经
/// 在工作区内（由宿主以工作区为 cwd 拉起）。给一个「够用且不会误放大范围」的默认。
/// 宿主的 `reload_policy` 会很快把它替换成精确白名单。
fn initial_roots() -> Vec<std::path::PathBuf> {
    std::env::current_dir().map(|p| vec![p]).unwrap_or_default()
}

/// 校验 WS 地址：生产必须 `wss://`，只有 `--dev` 才豁免。
fn check_ws_url(url: &str, dev_mode: bool) -> Result<(), String> {
    if url.starts_with("wss://") {
        return Ok(());
    }
    if dev_mode && url.starts_with("ws://") {
        return Ok(());
    }
    Err(format!(
        "拒绝不安全的 ws 地址（{url}）：生产必须使用 wss://，仅 --dev 允许 ws://"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wss_is_always_accepted() {
        assert!(check_ws_url("wss://example.com/api/v1/devices/ws", false).is_ok());
    }

    #[test]
    fn plain_ws_is_rejected_without_dev_flag() {
        // 明文 ws 会让 `?token=` 在网络上裸奔，必须默认拒绝
        assert!(check_ws_url("ws://example.com/ws", false).is_err());
    }

    #[test]
    fn plain_ws_is_allowed_in_dev_mode() {
        assert!(check_ws_url("ws://127.0.0.1:8080/api/v1/devices/ws", true).is_ok());
    }

    #[test]
    fn garbage_url_is_rejected() {
        assert!(check_ws_url("http://example.com", true).is_err());
    }
}
