//! `hd-runner` 的运行入口（库函数形态）。
//!
//! ## 为什么要从 `main.rs` 抽到这里
//!
//! 单文件交付（`docs/桌面端架构与功能设计.md` §3.2）要求宿主 `hd-host.exe` 能
//! **自己派生自己**跑 Runner：`hd-host.exe --runner`。这条路径需要复用完全相同的
//! 启动逻辑（stdin auth → supervisor 主循环 → EOF 自杀），而不是抄一份。
//! 抄一份就会立刻分叉：令牌打码、`--dev` 校验、`reload_policy` 重建 Router
//! 这些细节迟早只在一处被修复。
//!
//! 因此本模块提供 [`run_cli`]，由两处调用：
//! 1. `src/main.rs`（独立 `hd-runner` 二进制，供无 GUI 的服务器 / headless 场景）
//! 2. `hd-host` 的 `--runner` 分支（单文件模式下的自派生）
//!
//! ## 启动协议（三句话）
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
//! 因此本模块**刻意没有**任何从 args/env 读取 token 的路径 ——
//! 参数解析只认 `--dev` 这一个不带敏感值的开关。
//!
//! ## EOF 自杀的意义（防孤儿进程）
//!
//! 宿主外壳崩溃/被强杀时不会有机会通知子进程。若 Runner 不把「stdin 关闭」
//! 当成死亡信号，它就会变成一个连不上服务端、也没有人管理的僵尸进程，
//! 长期占着设备槽位（服务端以为该设备在线，一直往上派发任务）。读 stdin 得到
//! `Ok(None)` 即视为宿主已亡，立刻退出。

use std::io::BufReader;

use hd_protocol::payload::HelloPayload;

use crate::capabilities;
use crate::idempot::IdempotStore;
use crate::ipc::{redact_token, IpcCommand, IpcReader};
use crate::reconnect::ReconnectPolicy;
use crate::router::Router;
use crate::supervisor::{NoopObserver, Supervisor, WsConnector};

/// 未收到合法 `auth` 首行时的退出码。
///
/// 契约的权威定义在 `hd_protocol::exit_code::EXIT_NO_AUTH`；此处保留同名再导出，
/// 是为了让 `hd_runner::EXIT_NO_AUTH` 这个既有公开路径不失效（下游已有引用）。
///
/// 单独约定一个非 0 值（而不是泛泛的 1）：宿主外壳据此能区分
/// 「启动协议没谈成（§17.2 E_NO_AUTH，可能是父进程写错了）」与
/// 「连上后被服务端拒绝（那是业务错误，由 `StopReason::exit_code` 编码）」。
pub const EXIT_NO_AUTH: u8 = hd_protocol::exit_code::EXIT_NO_AUTH;

/// 宿主下发的运行期信号（由 stdin 读线程转发给主循环）。
enum ControlSignal {
    /// 热更新策略：重建 Router（`Guarded` 持有 `Arc<Policy>` 快照，只能重建）。
    ReloadPolicy {
        roots: Vec<String>,
        exec_allowlist: Vec<String>,
    },
    /// 请求优雅退出。
    Shutdown,
}

/// 以 Runner 模式运行，返回进程退出码。
///
/// `args` 是**不含程序名**的后续参数（例：`["--dev"]`）。
/// 与 `fn main()` 的差别只有两处：接受参数注入（便于 `hd-host --runner` 复用），
/// 以及返回 `u8` 而非 `ExitCode`（`ExitCode` 不适合作为库 API 暴露）。
///
/// 🔴 本函数**只能从主线程的同步上下文调用**（它内部自建 tokio runtime）。
/// 不要在已有 runtime 里调它 —— 那会 panic。
pub fn run_cli<I, S>(args: I) -> u8
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();

    // 日志走 stderr：stdout 可能被宿主当作协议通道，绝不能混入日志。
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    // `--dev` 只放宽**地址校验**，不放宽令牌来源：它在编译期/启动期都不携带任何秘密。
    let dev_mode = args.iter().any(|a| a == "--dev");

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("hd-runner: 创建 tokio runtime 失败（{e}），退出");
            return hd_protocol::exit_code::EXIT_GENERIC_FAILURE;
        }
    };
    rt.block_on(run_async(dev_mode))
}

/// 真正的异步主体（原 `#[tokio::main] fn main` 的内容）。
async fn run_async(dev_mode: bool) -> u8 {
    let mut reader = IpcReader::new(BufReader::new(std::io::stdin()));

    // ① 首行必须是 auth。缺失/格式错 → EXIT_NO_AUTH（§17.2 E_NO_AUTH）。
    //
    // ⚠️ 这里**没有**超时：`read_auth` 是阻塞读，宿主不写就会一直等；若宿主已死
    // 或未接管道，读到的是 EOF → 立即返回 MissingAuth。历史上本行注释写「缺失/超时」
    // 但实现中并无 timeout 包装，已更正以免误导排障方向。
    let auth = match reader.read_auth() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hd-runner: 未收到合法 auth 首行（{e}），退出");
            return EXIT_NO_AUTH;
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
        return EXIT_NO_AUTH;
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

    // 初始白名单根：进程当前目录（保证开箱可用），后续由宿主经 `reload_policy` 精确下发。
    let initial_roots = initial_roots();
    let router = std::sync::Arc::new(build_router(initial_roots));

    // 🔴 能力申报必须与 Router 同源：hello 的 capabilities / capabilities_hash 全部由
    //    `capabilities::snapshot(&router)` 派生，禁止手写能力清单。
    //    此前这里根本没有 hello（`WsConnector::new` 不带首帧），服务端因此永远收不到
    //    能力清单，判断不了该设备是否具备 `fs.list`（目录列举）能力。
    let (caps, caps_hash) = capabilities::snapshot(&router);
    tracing::info!(
        capabilities = caps.len(),
        names = ?caps.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        capabilities_hash = %caps_hash,
        "申报设备能力（hello 首帧）"
    );
    let hello = HelloPayload {
        name: std::env::var("HD_DEVICE_NAME").unwrap_or_else(|_| default_device_name()),
        platform: platform_tag(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities_hash: caps_hash,
        protocol_version: auth.protocol_version,
        capabilities: caps,
    };

    let mut sup = Supervisor::new(
        WsConnector::new(auth.ws_url.clone(), auth.token.clone()).with_hello(hello),
        ReconnectPolicy::default(),
    )
    .with_router(std::sync::Arc::clone(&router));
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
                // 🔴 必须按原因返回不同退出码：宿主靠它决定「重启 / 不重启 / 清令牌重配对」。
                // 若统一 return 0，令牌被服务端吊销时宿主无法与「用户主动退出」区分，
                // 轻则永不恢复，重则变成每秒一次的重启风暴。
                let code = reason.exit_code();
                tracing::warn!(reason = %reason, exit_code = code, "supervisor 终止，Runner 退出");
                return code;
            }
            sig = sig_rx.recv() => {
                match sig {
                    // stdin EOF（None）与显式 shutdown 等价：宿主已亡，本进程必须跟着走。
                    Some(ControlSignal::Shutdown) | None => {
                        tracing::info!("收到 shutdown 或 stdin EOF，优雅退出");
                        return 0;
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

/// 缺省设备名：`<主机名>-desktop`，取不到主机名就退化成固定字面量。
///
/// 只用于「服务端设备列表里给人看」，不参与鉴权。宿主可用 `HD_DEVICE_NAME`
/// 环境变量覆盖（方便多设备联调时区分）。
fn default_device_name() -> String {
    match std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) {
        Ok(host) if !host.trim().is_empty() => format!("{}-desktop", host.trim()),
        _ => "harness-desktop".to_string(),
    }
}

/// 平台标识（服务端用于展示与排障，不参与鉴权；与 hd-host 的 `platform_tag` 同口径）。
fn platform_tag() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    format!("{os}-{arch}")
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

    #[test]
    fn exit_no_auth_is_distinct_from_generic_failure() {
        // 宿主据此区分「启动协议没谈成」与「业务失败」，不能退化成 1
        assert_ne!(EXIT_NO_AUTH, 1);
        assert_ne!(EXIT_NO_AUTH, 0);
    }
}
