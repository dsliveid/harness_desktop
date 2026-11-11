#!/usr/bin/env bash
#
# harness_desktop 启动脚本（调试）
# 用法：./run.sh [选项] [-- 透传给 hd-host 的参数...]   （Windows：run.cmd）
#
# ⚠️ 本脚本**只服务 Windows**。harness_desktop 是 Tauri 2 应用，Windows 侧依赖
#    Edge WebView2 / MSVC；macOS（WKWebView）与 Linux（WebKitGTK）需要各自
#    的原生依赖与会话，本脚本不做假装跨平台的半吊子封装。
#
# ⚠️ 本脚本是 scripts/dev.ps1 的**薄封装**，不是第二套构建逻辑。
#    dev.ps1 是唯一真相源，里面沉淀了这些血泪结论：
#      · `--features gui` 是硬性要求（默认 features 为空 → 起来没窗口）
#      · 故意不用 `cargo run`（无法表达「只构建不启动」，且每次都重解析包图）
#      · hd-host 的 self-derive runner 依赖 console subsystem（0xC0000139 教训）
#    所以这里绝不重写构建参数，只做「参数风格归一 + 转发」。
#
# 选项：
#   --release         release 构建（更慢，产物更小）
#   --no-launch       只构建，不启动（想在 IDE 里调试时用）
#   --with-web        先把 web UI 重新构建并同步到 crates/hd-host/ui
#   --out DIR         构建完成后把 target/<profile>/hd-host.exe 复制到 DIR
#   --dry-run         只打印将要执行的 powershell 命令，不真正执行
#   -h, --help        显示本帮助
#
# 其余参数放在 `--` 之后会原样透传给 hd-host.exe（启动时才有意义）：
#   ./run.sh --release -- --log-level debug
#
# 等价的手敲命令（脚本内部就是转发它们）：
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/dev.ps1 [-Release] [-NoLaunch] [-WithWeb]
#
# 注意：GUI 进程启动后脚本立即返回，控制台留给你看日志。
#       hd-host 会自己再 spawn 一个 `--runner` 子进程，这是设计如此。

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

say()  { printf '%s\n' "$*"; }
warn() { printf '[警告] %s\n' "$*" >&2; }
die()  { printf '[错误] %s\n' "$*" >&2; exit 1; }

usage() {
  awk 'NR>1 && /^set -uo pipefail/ {exit} NR>1 {sub(/^# ?/, ""); print}' "${BASH_SOURCE[0]}"
  exit 0
}

# ---------------------------------------------------------------------------
# 平台与工具校验（本脚本只承诺 Windows）
# ---------------------------------------------------------------------------
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) : ;;
  *)
    die "本脚本只支持 Windows（当前：$(uname -s)）。
       harness_desktop 在 macOS / Linux 需要各自的 WebView 依赖与签名流程，
       请直接看 README，用 cargo build -p hd-host --features gui 手动构建。" ;;
esac

[ -f scripts/dev.ps1 ] || die "缺少 scripts/dev.ps1（构建真相源）。请确认仓库完整。"

PWSH=""
for c in powershell pwsh; do
  command -v "$c" >/dev/null 2>&1 && { PWSH="$c"; break; }
done
[ -n "$PWSH" ] || die "找不到 powershell / pwsh。这不是 Linux 环境吗？本脚本只支持 Windows。"

# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------
RELEASE=""
NO_LAUNCH=""
WITH_WEB=""
OUT_DIR=""
DRY_RUN=""
PASSTHRU=()

while [ $# -gt 0 ]; do
  case "$1" in
    --release)   RELEASE=1 ;;
    --no-launch) NO_LAUNCH=1 ;;
    --with-web)  WITH_WEB=1 ;;
    --debug)     RELEASE="" ;;
    --out)       [ $# -ge 2 ] || die "--out 需要一个目录参数。"; OUT_DIR="$2"; shift ;;
    --out=*)     OUT_DIR="${1#*=}" ;;
    --dry-run)   DRY_RUN=1 ;;
    -h|--help)   usage ;;
    --)          shift; PASSTHRU=("$@"); break ;;
    *) die "未知参数：$1（用 --help 看用法；要透传给 hd-host 请放在 -- 之后）" ;;
  esac
  shift
done

if [ ${#PASSTHRU[@]} -gt 0 ]; then
  # 明确告知：透传参数 dev.ps1 不支持，避免用户以为被吞了
  warn "dev.ps1 不接受透传参数，以下参数不会生效：${PASSTHRU[*]}"
  warn "（脚本是构建+启动封装，不是 hd-host 的参数总线）"
fi

# ---------------------------------------------------------------------------
# 组装并执行 powershell
# ---------------------------------------------------------------------------
PS_ARGS=(-NoProfile -ExecutionPolicy Bypass -File scripts/dev.ps1)
[ -n "$RELEASE" ]   && PS_ARGS+=(-Release)
[ -n "$NO_LAUNCH" ] && PS_ARGS+=(-NoLaunch)
[ -n "$WITH_WEB" ]  && PS_ARGS+=(-WithWeb)

PROFILE="debug"
[ -n "$RELEASE" ] && PROFILE="release"
EXE="target/$PROFILE/hd-host.exe"

say "harness_desktop：$PWSH ${PS_ARGS[*]}"

if [ -n "$DRY_RUN" ]; then
  say "[dry-run] 到此为止，未真正构建/启动。"
  say "[dry-run] 预期产物：$EXE"
  exit 0
fi

"$PWSH" "${PS_ARGS[@]}"
rc=$?
[ "$rc" -eq 0 ] || die "构建/启动失败（退出码 $rc）。"

# ---------------------------------------------------------------------------
# 可选：复制产物到 --out
#
# 只拷 hd-host.exe 是对的：它自己 derive runner 子进程（见 build-exe.ps1 注释），
# 不需要第二个二进制。运行前提是目标机有 Edge WebView2 Runtime。
# ---------------------------------------------------------------------------
if [ -n "$OUT_DIR" ]; then
  [ -f "$EXE" ] || die "构建成功但找不到产物：$EXE"
  mkdir -p "$OUT_DIR" || die "无法创建输出目录：$OUT_DIR"
  cp "$EXE" "$OUT_DIR/" || die "复制到 $OUT_DIR 失败。"
  say "已复制 $(basename "$EXE") → $OUT_DIR"
fi

say ''
if [ -n "$NO_LAUNCH" ]; then
  say '完成（只构建，未启动）。'
else
  say '完成。GUI 进程已在后台运行（脚本不会等它退出）。'
fi
