#!/usr/bin/env bash
#
# harness_desktop 打包脚本（release exe）
# 用法：./build.sh [选项]   （Windows：build.cmd）
#
# ⚠️ 本脚本**只服务 Windows**（Tauri 2 + WebView2 + MSVC）。
#
# ⚠️ 本脚本是 scripts/build-exe.ps1 的**薄封装**。
#    真正的构建命令是：cargo build -p hd-host --release --features gui,custom-protocol
#    两个 feature 缺一不可：
#      · gui              不加 → 产物没有窗口、没有 Tauri
#      · custom-protocol  不加 → Tauri 不内嵌前端资源，exe 静默秒退
#    20MB 体积预算、stray hd-runner.exe 告警、WebView2 运行时提示都留在 ps1 里，
#    这里不重复实现（重复实现 = 两份会漂移的真相）。
#
# 选项：
#   --with-web      打包前先把 web UI 重新构建并同步到 crates/hd-host/ui
#   --out DIR       构建完成后把 target/release/hd-host.exe 复制到 DIR
#   --dry-run       只打印将要执行的命令，不真正构建
#   -h, --help      显示本帮助
#
# 产物说明：只需要 hd-host.exe 一个文件。
#   它会在配对后 spawn 一个自己的 `--runner` 子进程（自派生），
#   所以不再单独发布 hd-runner.exe。
#   运行前提：目标机装了 Microsoft Edge WebView2 Runtime。

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

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) : ;;
  *)
    die "本脚本只支持 Windows（当前：$(uname -s)）。
       macOS / Linux 请按 README 手动构建（依赖各自的 WebView 与签名流程）。" ;;
esac

[ -f scripts/build-exe.ps1 ] || die "缺少 scripts/build-exe.ps1（构建真相源）。请确认仓库完整。"

PWSH=""
for c in powershell pwsh; do
  command -v "$c" >/dev/null 2>&1 && { PWSH="$c"; break; }
done
[ -n "$PWSH" ] || die "找不到 powershell / pwsh。"

# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------
WITH_WEB=""
OUT_DIR=""
DRY_RUN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --with-web) WITH_WEB=1 ;;
    --out)      [ $# -ge 2 ] || die "--out 需要一个目录参数。"; OUT_DIR="$2"; shift ;;
    --out=*)    OUT_DIR="${1#*=}" ;;
    --dry-run)  DRY_RUN=1 ;;
    -h|--help)  usage ;;
    *) die "未知参数：$1（用 --help 看用法）" ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# 可选：先重建前端并同步
#
# 复用 dev.ps1 -NoLaunch -WithWeb 而不是自己拼 npm/同步命令：
#   · 它已经处理「node_modules 缺失才 npm install」的省时逻辑
#   · 它调 sync-web.ps1 做镜像同步，并保护 crates/hd-host/ui/.gitkeep
# dev.ps1 这一步会顺带做一次 debug 构建（无害，随后 build-exe.ps1 会做 release）。
# ---------------------------------------------------------------------------
if [ -n "$WITH_WEB" ]; then
  say '[1/3] 重建 web UI 并同步到 crates/hd-host/ui ...'
  if [ -n "$DRY_RUN" ]; then
    say "[dry-run] $PWSH -NoProfile -ExecutionPolicy Bypass -File scripts/dev.ps1 -NoLaunch -WithWeb"
  else
    "$PWSH" -NoProfile -ExecutionPolicy Bypass -File scripts/dev.ps1 -NoLaunch -WithWeb
    rc=$?
    [ "$rc" -eq 0 ] || die "web UI 重建/同步失败（退出码 $rc）。"
  fi
fi

# ---------------------------------------------------------------------------
# 打包
# ---------------------------------------------------------------------------
PS_ARGS=(-NoProfile -ExecutionPolicy Bypass -File scripts/build-exe.ps1)
say "[2/3] $PWSH ${PS_ARGS[*]}"

if [ -n "$DRY_RUN" ]; then
  say '[dry-run] 到此为止，未真正构建。'
  say '[dry-run] 预期产物：target/release/hd-host.exe'
  exit 0
fi

"$PWSH" "${PS_ARGS[@]}"
rc=$?
[ "$rc" -eq 0 ] || die "release 构建失败（退出码 $rc）。"

EXE="target/release/hd-host.exe"
[ -f "$EXE" ] || die "构建成功但找不到产物：$EXE"

# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------
bytes="$(wc -c < "$EXE" | tr -d ' ')"
mb="$(awk -v b="${bytes:-0}" 'BEGIN { printf "%.2f", b/1048576 }')"
say "[3/3] 产物：$EXE（$mb MB）"
if command -v sha256sum >/dev/null 2>&1; then
  say "      sha256 $(sha256sum "$EXE" | awk '{print $1}')"
fi

# ---------------------------------------------------------------------------
# 可选：复制到 --out
# ---------------------------------------------------------------------------
if [ -n "$OUT_DIR" ]; then
  mkdir -p "$OUT_DIR" || die "无法创建输出目录：$OUT_DIR"
  cp "$EXE" "$OUT_DIR/" || die "复制到 $OUT_DIR 失败。"
  say "      已复制到 $OUT_DIR"
fi

say ''
say '完成。分发时只需 hd-host.exe（它自派生 runner 进程）。'
say '目标机运行前提：Microsoft Edge WebView2 Runtime。'
