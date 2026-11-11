# harness_desktop

AI Agent 系统的**桌面端重执行工位**（Tauri 2 + Rust）。

它不是一个聊天客户端：它跑在开发者自己的机器上，把服务端（`harness_go`）下发的
任务在**本地真实环境**里执行，并把结果回传。所有高风险动作受服务端租约（lease）
与本地策略（工作区白名单）双重约束。

> 架构、安全模型、协议细节、体积预算等长篇内容不在本文件重复，
> 统一以 `docs/桌面端架构与功能设计.md` 为准。

---

## 项目进度与下一步

**进度快照详见设计文档 §20；下一步计划见 §21。** 此处只放速查表。

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| P0 | 单包分发收口（只发一个 `hd-host.exe`） | ✅ |
| P1 | 退出码契约（`hd-protocol::exit_code`） | ✅ |
| P2 | 生命周期状态收口（`lifecycle.rs` 为唯一事实源） | ✅ |
| P3 | 修通 `reload_policy`（白名单真正下发到执行引擎） | ✅ |
| P4 | 单实例锁（不重复拉起 Runner） | ✅ |
| P5 | 守护循环（Runner 宕机自动拉起） | ✅ |
| P6 | 解约闭环（`unpair_device`） | ✅ |
| P9 | Go 侧 `device-e2e` 适配单包 | ✅ |
| **P7** | **UI 状态透出**（执行引擎状态卡 + 解除配对入口） | ✅ |
| **P8** | **前端 devUrl 热更**（可选，开发体验） | ⬜ 待做 |

**最近一次全量门禁**：后端 `cargo test` 分包跑全绿（`hd-host` 109 + e2e 14 + 其余）；
前端 `npx tsc --noEmit` 通过、`npm test` **31 通过 / 0 失败**、产物 15.7 KB（预算 614 KB）。

**下一步（按优先级）**：

1. **P8 前端热更**（可选）—— 开发态用 Tauri `devUrl` 指向 vite，免去 build + sync-web。
2. **待观察项**（不影响当前功能）：`mark_heartbeat` 仍无生产调用点，
   `device_status.online` 走「未收到心跳视为在线」的乐观分支（详见设计文档 §21.3）。

---

## Crate 结构

| Crate | 职责 | 关键红线 |
| --- | --- | --- |
| `hd-protocol` | 设备协议线格式唯一来源（Rust 镜像），`fixtures/*.json` 由 Go 侧真实序列化产出 | 禁止依赖 tokio / reqwest / keyring / std::fs —— 协议包不许碰 IO |
| `hd-core` | 执行器地基：`Executor` trait、`Guarded` 安全闸门、`Policy` 路径三闸、结果脱敏、`fs.list` 只读列举 | 无网络依赖；安全逻辑必须可离线单测 |
| `hd-runner` | 执行器进程：连服务端、收 `task.dispatch`、跑工具、回 `task.result`；含退避重连、幂等缓存、并发派发 | 唯一能执行外部进程的 crate，一律经 `Guarded` |
| `hd-host` | 桌面宿主壳：token vault、配对、runner 守护、启动编排、GUI | GUI 层由 `gui` feature 控制，默认不编译 |
| `hd-testkit` | 测试替身：假服务端 | 仅 `[dev-dependencies]` 使用 |

### `hd-host` 的 feature 分层

```
default = []
gui             = ["tauri", "tauri-plugin-single-instance"]
custom-protocol = ["tauri/custom-protocol"]   # release 必需，见下
```

`cargo test -p hd-host` 默认**不编译任何 GUI 库**，因此在无 WebView2 的环境也能秒级跑完。

---

## 🔴 构建 GUI 二进制必须知道的三个坑

这三条都是**真实踩过**的，症状极具误导性，列在这里是为了不再重演。

### 坑 1：缺 `custom-protocol` → exe 一启动就静默退出

```bash
# 错误：release 构建"成功"，但双击即死
cargo build -p hd-host --release --features gui

# 正确
cargo build -p hd-host --release --features gui,custom-protocol
```

Tauri 2 的 release 构建不开 `custom-protocol` 时**不会把前端资源嵌入二进制**，
exe 启动后找不到 `frontendDist` 直接退出，报 `0xC0000139`。配合
`windows_subsystem = "windows"`（不弹控制台），表现为「无任何提示的闪退」。

### 坑 2：缺 `build.rs` → 弹「无法找到入口 TaskDialogIndirect」

```
hd-host.exe - 无法找到入口
无法定位程序输入点 TaskDialogIndirect 于动态链接库 hd-host.exe 上。
```

`TaskDialogIndirect` 只存在于 **Common-Controls v6**，而 v6 需要 exe 内嵌 manifest
才会激活。`crates/hd-host/build.rs` 调用 `tauri_build::build()` 就是编入这份 manifest 的步骤。

**不要删除这个 build.rs。** 它的内容按 `cfg(feature = "gui")` 门控：
纯逻辑构建（`cargo test`）下它什么都不做，因此不影响分层隔离。

> 历史教训：本仓库曾以「避免 tauri-build 无条件执行破坏纯逻辑分层」为理由**刻意
> 不设 build.rs**。分层是保住了，代价是 GUI 二进制根本跑不起来。用 feature 门控
> 才是正确解法。

### 坑 3：`crates/hd-host/ui/` 必须非空

`tauri::generate_context!()` 在**编译期**读 `ui/index.html`。该目录是构建产物、
不入库（只有 `.gitkeep`），所以手工 `cargo build --features gui` 前必须先同步：

```bash
cd web && npm ci && npm run build && cd ..
./scripts/sync-web.ps1     # Windows
./scripts/sync-web.sh      # bash
```

---

## 一次性构建可执行程序（推荐路径）

```powershell
# 封装了正确的 feature 组合，并校验产物体积
.\scripts\build-exe.ps1
```

或走根目录一键脚本（等价封装，额外提供 `--with-web` / `--out`）：

```bash
./build.sh                 # = .\scripts\build-exe.ps1
./build.sh --with-web      # 先重建前端并同步，再打包
./run.sh                   # = .\scripts\dev.ps1（build + launch）
./run.sh --no-launch       # 只构建不启动（IDE 调试用）
```

Windows 用户可直接 `build.cmd` / `run.cmd`（自动找 bash，无需先开 Git Bash）。

> 两个 `.sh` 是 `scripts/*.ps1` 的**薄封装**，不重写构建逻辑：
> `--features gui` 为何必需、为何不用 `cargo run`、20MB 预算与 stray `hd-runner.exe`
> 告警全部留在 ps1 里，避免两份会漂移的真相。脚本只服务 **Windows**。

产物：

```
target\release\hd-host.exe     唯一分发文件。GUI 宿主 + 内置执行引擎
```

> ⚠️ 首次 `release` 构建要跑 LTO，可能耗时数分钟。若命令超时被中断，
> 重新执行一次即可（增量续建）。

### 单包分发：一个文件，两个进程

**用户只拿到 `hd-host.exe` 一个文件。** 它在配对完成后用 `--runner` 参数
**拉起自己的第二个进程**作为执行引擎：

```
hd-host.exe           → GUI / 守护进程（窗口、令牌、生命周期）
hd-host.exe --runner  → 风险执行进程（无窗口，跑命令/动文件）
```

文件数量 1（runner 代码静态链接进同一 exe），进程数量 2（执行面必须与界面隔离）。
详见设计文档 §2。

> 🔴 **历史误解澄清**：README 旧版曾写「自派生在 Windows 上实测失败（`0xC0000139`）」。
> 2026-11 用真实 spawn 探针复测证明：**该结论只适用于 `windows` 子系统**；
> 本项目采用的 `console` 子系统下自派生完全正常（进入 `main()`、读 stdin、
> 退出码 2，约 51ms）。代价是 GUI 双击时闪一下控制台窗口，已确认接受。
> 详见设计文档 §2.4。

### 开发联调（不必关心「编两个包」）

```powershell
.\scripts\dev.ps1              # 构建 + 启动
.\scripts\dev.ps1 -NoLaunch    # 只构建（IDE 调试前）
.\scripts\dev.ps1 -WithWeb     # 连前端一起重建
```

单包后不再存在「改了 runner 却跑旧 exe」的静默错配问题。详见设计文档 §2.5。

---

## 构建前置

| 依赖 | 版本 | 说明 |
| --- | --- | --- |
| Rust | 见 `rust-toolchain.toml`（1.98.1，含 rustfmt + clippy） | 用 rustup 自动跟随 |
| Node.js | ≥ 18 | 仅 `web/` 基线 UI 构建需要 |
| WebView2 Runtime | Win10 1803+ / Win11 预装 | 缺了 `hd-host.exe` 起不来 |
| NSIS | 由 `tauri-cli` 自动下载 | 仅打安装包时需要；裸 exe 不需要 |

Linux/macOS 需要系统 webkit2gtk / WKWebView；本项目主目标平台是 **Windows**。

---

## 常用命令

```bash
# 静态检查（CI 门禁同款）
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p hd-host --features gui --all-targets -- -D warnings   # GUI 层单独跑

# 测试
cargo test --workspace
cargo test -p hd-protocol      # 只验协议 golden fixture
cargo test -p hd-core          # 只验安全闸门（路径越界/软链/脱敏）

# 构建
cargo build -p hd-runner --bin hd-runner --release
cargo build -p hd-host --release --features gui,custom-protocol

# 基线 UI 构建 + 同步进宿主壳
cd web && npm ci && npm run build && cd ..
./scripts/sync-web.ps1
```

---

## 运行时数据与配置

| 项目 | 位置 | 说明 |
| --- | --- | --- |
| 设备令牌 | **OS 密钥链**（Windows 凭据管理器） | 🔴 唯一存放处，绝不写明文文件、绝不下发前端 |
| 配对档案 | `%APPDATA%\harness_desktop\profile.json` | 明文，只存 `ws_url` / `device_id` / `protocol_version` |

**档案与密钥链的分工必须分清**：

- 档案回答「连哪台机器、我是哪台设备」→ 非敏感，明文可读无妨；
- 密钥链回答「我凭什么被信任」→ 泄露即设备被永久接管。

档案损坏（JSON 非法/文件被删）会自动降级为「未配对」，不会让宿主起不来。

---

## 配对与启动链路

```
双击 hd-host.exe
   │
   ├─ GUI 起来（先出窗口，不阻塞）
   │
   └─ 后台异步执行启动编排
        ├─ 密钥链有令牌？
        │    ├─ 是 → 读 profile.json 拿 ws_url → 自派生 --runner → 设备上线
        │    └─ 否 → 状态=NeedsPairing，UI 显示配对引导
        └─ 连自派生都拿不到 current_exe → 状态=RunnerMissing（程序自身异常）
```

前端通过 `get_boot_state` command 读取当前启动状态，据 `state` 字段决定显示哪块 UI：

| `state` | 含义 | 用户该做什么 |
| --- | --- | --- |
| `unknown` | 启动流程还没跑完 | 稍候 |
| `needs_pairing` | 密钥链无令牌 | 输入配对码 |
| `started` | Runner 已拉起 | 无需操作 |
| `runner_missing` | 无法启动执行引擎（程序内部异常） | 重启客户端；持续出现则联系支持 |
| `failed` | 启动出错 | 看 `detail` 里的原因 |

> 注：单包分发下不再存在「漏拷第二个文件」这种情况，故 `runner_missing`
> 的文案已改为指向程序自身异常，避免把用户引去找一个不存在的 `hd-runner.exe`。

### 本地（ws://127.0.0.1）服务端的配对

自托管服务端默认监听 `http://127.0.0.1:5611`，配对后档案里的 `ws_url` 是明文
`ws://`。Runner 的地址安全闸门默认拒绝明文 ws（防 `?token=` 在局域网裸奔），
宿主因此按**回环判定**自动补 `--dev`：仅当 ws_url 指向 `127.0.0.1` / `localhost`
/ `[::1]`（流量不出本机、无嗅探面）才豁免，其余明文地址维持拒绝（见
`daemon.rs` 的 `needs_dev_flag`）。2026-11-11 之前该场景会在配对后数十秒内
触发守护循环 repair 把令牌清空（Runner NO_AUTH 退出 → repair），表现为
「配对成功但设备永不在线」——已修复并留回归单测。

### 守护循环的等待语义（2026-11-11 修复）

`Daemon::wait_exit` 曾在 `child.wait()` 前 `drop(stdin)`，而 Runner 以
「stdin EOF = 宿主已死」自杀，导致 supervise 循环启动即把 Runner 杀死
（31ms 内退出码 0，设备永不在线且无任何日志）。现语义为：**等待期间写端
保持打开**，`supervise` 用 `select` 让「子进程退出」与「shutdown 标志」竞速，
退出时先走优雅收尾（关写端 → 自杀 → 1s kill 兜底）。回归用例：
`daemon_e2e::wait_exit_records_exit_code`、`supervise_e2e::*`。

### GUI 日志

GUI 进程日志走 **stderr**（console 子系统随宿主控制台输出；被管道拉起时
由父进程 ring 收集），级别可用 `RUST_LOG` 覆盖，默认 `info`。守护循环结束时
以 warn 记录 `last_exit`（退出码是判断 Runner 死因的唯一线索：0=优雅退出、
2/4=需重配对、3=重试耗尽、6=协议不匹配）。

配对流程（`pair_device` command，**异步**）：

```
输入配对码 → 本地校验 → POST /api/v1/devices/pair（免登录，凭码即凭据）
   → 拿到 device_token → 写密钥链 → 写 profile.json → 拉起 Runner
```

🔴 配对的 HTTP 请求**必须由 Rust 侧发出**：响应带 `device_token` 明文，若让前端发，
令牌必然经过 WebView 的 JS 堆与网络栈（XSS / 恶意依赖 / 注入的 devtools 都能拿到）。

---

## Tauri command 能力清单

`list_commands` 是能力探测锚点（**永不删除**）：前端先探测 `supported` 数组，
再决定哪些按钮可点、哪些走降级路径。老客户端 + 新前端是常态。

| command | 作用 |
| --- | --- |
| `list_commands` | 能力探测（锚点） |
| `device_status` | 设备/配对状态 |
| `runner_status` | 子进程生命周期快照（含 `restarts`、`last_heartbeat_ms`） |
| `get_boot_state` | 启动流程走到哪一步 |
| `get_workspace_roots` / `set_workspace_roots` | 工作区白名单读写（写路径会**同步下发**给执行引擎） |
| `pair_device` | 真实配对（异步） |
| `unpair_device` | 解除配对：停 Runner → 清令牌 → 切「需要配对」 |

🔴 **永不实现**（写死在 `FORBIDDEN_COMMANDS`，有单测断言）：`get_device_token` /
`raw_ws_send` / `exec_shell`。远程 UI 握有 `invoke` 权限，这三条一旦存在，
「服务端被攻破也不会丢令牌」的保证就没了。

> `start_pairing` 也注册在 `invoke_handler` 里（便于前端联调），但**刻意不列入**
> `SUPPORTED_COMMANDS`：它只做本地校验与排队，宣称「支持」会让 UI 显示一个必然失败的功能。

---

## 如何验证应用真的能跑

🔴 **只看进程存活是不够的** —— Windows 的错误对话框本身就是一个存活窗口。
曾因此把「弹着『无法找到入口』的进程」误判为启动成功。

正确做法是同时检查三项：

```powershell
$ex = "target\debug\hd-host.exe"
$p = Start-Process -FilePath $ex -PassThru
Start-Sleep -Seconds 7

# ① 有无错误对话框
$err = Get-Process | Where-Object { $_.MainWindowTitle -match "无法找到入口|TaskDialog" }
# ② 进程是否存活
# ③ 窗口标题是否符合预期
"err=$($err.MainWindowTitle) exited=$($p.HasExited) title='$($p.MainWindowTitle)'"
if (-not $err -and -not $p.HasExited -and $p.MainWindowTitle) { "✅ OK" }

Stop-Process -Id $p.Id -Force
```

期望输出：`err= exited=False title='harness_desktop'`。

### 与真实服务端联调

服务端侧有专门的联调脚本（跨仓，位于 `harness_go`）：

```bash
cd ../harness_go
go run ./cmd/device-e2e                 # 自包含：进程内起真实 Router+Gateway+临时 sqlite
go run ./cmd/device-e2e -mode runner    # 拉起 hd-host.exe --runner 做两端对撞
```

> `-mode runner` 拉的是 `hd-host.exe --runner`（单包分发后没有独立的
> `hd-runner.exe`）。若该脚本仍硬编码旧路径，需同步调整——属于待办项。

输出 `PASS n / FAIL 0` 即表示「配对 → WS → 心跳 → 派发 → 回执」全链通过。

---

## 图标

`crates/hd-host/icons/` 内是 Tauri 打包强制要求的图标集：

| 文件 | 用途 |
| --- | --- |
| `32x32.png` / `128x128.png` / `128x128@2x.png` | 窗口 / 任务栏 / 高 DPI |
| `icon.ico` | Windows 可执行文件与安装包图标（**必需**） |
| `icon.png`（512×512） | Linux / 通用 |
| `Square*Logo.png` | Microsoft Store 尺寸族 |

图标是真实可解析的 RGBA PNG 与单图像 ICO（内嵌 PNG 帧），`tauri.conf.json` 的
`bundle.icon` 已指向它们。换图时建议用 `cargo tauri icon <源图>` 一次生成全套。

---

## 如何跑一次安装包（可选）

裸二进制已够日常使用；需要安装包时：

```bash
# 1) 前端产物就位
cd web && npm ci && npm run build && cd .. && ./scripts/sync-web.ps1

# 2) 装打包 CLI（只需一次）
cargo install tauri-cli --version "^2"

# 3) 出 NSIS 安装包
cd crates/hd-host
cargo tauri build -- --features gui
# 产物：target/release/bundle/nsis/harness_desktop_<version>_x64-setup.exe
```

体积预算见设计文档 §18.4：主安装包目标 ≤ 16 MB，验收线 ≤ 20 MB
（实测 host 2.66 MB + runner 1.19 MB ≈ 3.85 MB）。

---

## 协议漂移门禁

`crates/hd-protocol/fixtures/*.json` **不是手写的**，全部由 Go 侧真实序列化产出。
改动服务端协议后必须重新生成：

```bash
# 在 harness_go 根目录
./scripts/gen-protocol-fixtures.ps1     # Windows
./scripts/gen-protocol-fixtures.sh      # bash
```

CI 会重新生成并 `git diff --exit-code`：有 diff 说明「改了协议但没提交 fixture」，
直接判红。这是防止 Rust/Go 双写静默漂移的唯一机制。

---

## CI

`.github/workflows/ci.yml` 实现四门禁，串行推进（快失败先跑）：

1. **protocol-gate** — 校验 `crates/hd-protocol/fixtures/` 未漂移，并跑
   `cargo test -p hd-protocol`。
2. **lint** — `cargo fmt --check` + clippy（含 `gui` feature），警告即失败。
3. **test** — `cargo test --workspace`。
4. **build** — 同步前端产物后出 release 二进制并上传 artifact。

全部跑在 `windows-latest`：主目标平台是 Windows，避免「Linux 绿、Windows 红」的假绿。

---

## 关联仓库

| 仓库 | 关系 |
| --- | --- |
| `harness_go` | 服务端（协议与 fixture 的权威来源），另有联调脚本 `cmd/device-e2e` |
| `harness_mobile` | 移动端客户端 |
