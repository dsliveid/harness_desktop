# hd-protocol

`harness_desktop` 设备协议的**线格式唯一来源**（Rust 镜像）。

对照源：`harness_go/internal/device/protocol.go`、`internal/model/device.go`、
`internal/apperr/apperr.go`。

## 依赖红线

本 crate **禁止**引入 `tokio` / `reqwest` / `keyring` / 任何 `std::fs` 能力。
协议包一旦能碰 IO，就会有人把执行逻辑写进去，最终 Runner 与 Host 的边界腐烂。
当前依赖仅 `serde` + `serde_json`。

## 黄金 fixture 门禁（防 Go/Rust 双写漂移）

`fixtures/*.json` **不是手写的**，全部由 Go 侧真实序列化产出：

```bash
# 在 harness_go 根目录
go run scripts/gen-fixtures.go -out ../harness_desktop/crates/hd-protocol/fixtures
# 或
./scripts/gen-protocol-fixtures.sh          # bash
.\scripts\gen-protocol-fixtures.ps1         # Windows PowerShell
```

然后验证：

```bash
cd ../harness_desktop
cargo test -p hd-protocol
```

### 何时必须重新生成

- 改动 `internal/device/protocol.go` 的任何结构体或字段；
- 改动 `internal/model/device.go` 的 `Capability` / 协议版本常量；
- 改动 `internal/apperr` 中 `fs.*` 或 `device.*` 错误码。

CI 的 `protocol-gate` 会先重新生成、再 `git diff --exit-code`：若有 diff 说明
「改了协议但没提交 fixture」，直接判红。这一条是防止静默漂移的关键。

## 设计要点

| 决策 | 原因 |
| --- | --- |
| `MessageType::Unknown` + `#[serde(other)]` | 服务端新增帧类型时，旧客户端必须**丢弃而非断连** |
| `TaskDispatchPayload` 不设 `task_id` 字段 | Go 侧 `TaskID` 与 `ToolEventID` 值恒等；只解析后者可从类型层杜绝分叉 |
| `SourceTrust` 只有一个变体 `Untrusted` | 不变量 4 的**编译期**保证，而非口头纪律 |
| 所有字段 `#[serde(default)]` | 旧服务端缺字段、新服务端多字段，双向可解析 |
| `Capability.updated_at` 无 `skip_serializing_if` | Go 侧无 omitempty，固定输出 0；否则双向序列化不一致 |

## 已知的协议事实

`device.revoked` 与 `device.protocol_mismatch` 在服务端被定义了两次
（`device/protocol.go` 的帧级码、`apperr.go` 的业务码），**字面量完全相同**。
已实测确认，故 `error_code::is_terminal` 不重复匹配这两个字面量（否则 clippy
报 unreachable pattern）。
