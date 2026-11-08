# harness_desktop

AI Agent 系统的**桌面端重执行工位**（Tauri 2 + Rust）。

它不是一个聊天客户端：它跑在开发者自己的机器上，把服务端（`harness_go`）下发的
任务在**本地真实环境**里执行，并把结果回传。所有高风险动作受服务端租约（lease）
与本地策略（工作区白名单）双重约束。

> 架构、安全模型、协议细节、体积预算等长篇内容不在本文件重复，
> 统一以 `docs/桌面端架构与功能设计.md` 为准。

---

## Crate 结构

| Crate | 职责 | 关键红线 |
| --- | --- | --- |
| `hd-protocol` | 设备协议线格式唯一来源（Rust 镜像），`fixtures/*.json` 由 Go 侧真实序列化产出 | 禁止依赖 tokio / reqwest / keyring / std::fs —— 协议包不许碰 IO |
| `hd-core` | 纯逻辑地基：工作区白名单策略 `Policy`、路径校验 | 零 IO、零网络，可任意单测 |
| `hd-runner` | 执行器进程：连服务端、收 `task.dispatch`、跑工具、回 `task.result`；含退避重连策略与 token 打码 | 唯一能执行外部进程的 crate，必须逐项过白名单 |
| `hd-host` | 桌面宿主壳（Tauri 2）：token vault（系统密钥链）、runner 守护、IPC 控制面、托盘 | GUI 层由 `gui` feature 控制，默认不编译 |
| `hd-testkit` | 测试替身：假服务端、假 runner | 仅 `[dev-dependencies]` 使用 |

### `hd-host` 的 feature 分层（重要）

```
default = []            # 纯逻辑层：vault / daemon / commands
gui     = ["tauri", "tauri-plugin-single-instance"]
```

`cargo test -p hd-host` 默认**不编译任何 GUI 库**，因此在无 WebView2 的环境也能秒级跑完。
只有真正要出二进制时才加 `--features gui`。
这也是为什么 `Cargo.toml` 里刻意不设 `build.rs` / `tauri-build`：`tauri-build` 的
build script 会无条件执行，会破坏这层隔离。

---

## 构建前置

| 依赖 | 版本 | 说明 |
| --- | --- | --- |
| Rust | 见 `rust-toolchain.toml`（1.98.1，含 rustfmt + clippy） | 用 rustup 自动跟随 |
| Node.js | ≥ 18 | 仅 `web/` 前端构建需要 |
| WebView2 Runtime | 随 Win10 1803+ / Win11 预装 | 缺了 `hd-host.exe` 启动会白屏 |
| NSIS | 由 `tauri-cli` 自动下载 | 仅打安装包时需要 |

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

# 构建
cargo build -p hd-runner --bin hd-runner --release
cargo build -p hd-host --features gui --release

# 前端产物构建 + 同步进宿主壳
cd web && npm ci && npm run build
cd .. && ./scripts/sync-web.ps1        # Windows
cd .. && ./scripts/sync-web.sh         # bash
```

### 关于 `crates/hd-host/ui/`

`tauri.conf.json` 的 `build.frontendDist` 指向 `ui`，而 `tauri::generate_context!()`
在**编译期**就要读这个目录里的 `index.html`。因此：

- `ui/` 是**构建产物目录**，不入库（只有 `.gitkeep` 占位）；
- 手工 `cargo build --features gui` 前若 `ui/` 为空，编译会直接失败；
- 正规流程是跑 `scripts/sync-web.*` 把 `web/dist`（或 `web/dist-baseline`）同步进去。

---

## 如何跑一次打包

```bash
# 1) 前端产物就位（这一步不能省，否则 tauri 找不到 index.html）
cd web && npm ci && npm run build && cd ..
./scripts/sync-web.ps1

# 2) 装打包 CLI（只需一次）
cargo install tauri-cli --version "^2"

# 3) 出 NSIS 安装包
cd crates/hd-host
cargo tauri build -- --features gui
# 产物：target/release/bundle/nsis/harness_desktop_<version>_x64-setup.exe
```

只想要裸二进制、不要安装包时，直接：

```bash
cargo build -p hd-host --features gui --release
# target/release/hd-host.exe
```

体积预算见设计文档 §18.4：主安装包目标 ≤ 16 MB，验收线 ≤ 20 MB。

---

## 图标

`crates/hd-host/icons/` 内是 Tauri 打包强制要求的图标集：

| 文件 | 用途 |
| --- | --- |
| `32x32.png` / `128x128.png` / `128x128@2x.png` | 窗口 / 任务栏 / 高 DPI |
| `icon.ico` | Windows 可执行文件与安装包图标（**必需**） |
| `icon.png`（512×512） | Linux / 通用 |
| `Square*Logo.png` | Microsoft Store 尺寸族 |

图标是真实可解析的 RGBA PNG（`png` crate 编码）与单图像 ICO（内嵌 PNG 帧），
`tauri.conf.json` 的 `bundle.icon` 已指向它们。换图时建议用
`cargo tauri icon <源图>` 一次生成全套，再覆盖本目录。

---

## CI

`.github/workflows/ci.yml` 实现四门禁，串行推进（快失败先跑）：

1. **protocol-gate** — 守 Go/Rust 协议双写漂移：校验 `crates/hd-protocol/fixtures/`
   未被手改（改动须带 `protocol-sync` 标签）；配置了 `HARNESS_GO_TOKEN` 时
   额外拉取 `harness_go` 重新生成 fixture 并 `git diff --exit-code`；最后跑
   `cargo test -p hd-protocol`。
2. **lint** — `cargo fmt --check` + clippy（含 `gui` feature），警告即失败。
3. **test** — `cargo test --workspace`。
4. **build** — 先同步前端产物到 `crates/hd-host/ui/`，再出两个 release 二进制并上传 artifact。

全部跑在 `windows-latest`：主目标平台是 Windows，避免「Linux 绿、Windows 红」的假绿。

---

## 关联仓库

| 仓库 | 关系 |
| --- | --- |
| `harness_go` | 服务端（协议与 fixture 的权威来源） |
| `harness_mobile` | 移动端客户端 |
