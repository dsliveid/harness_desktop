#!/usr/bin/env bash
# ============================================================================
# sync-web.sh —— 把基线 UI 构建产物同步进 Tauri 的 frontendDist
#
# 源目录：web/dist-baseline      （由 `cd web && npm install && npm run build` 生成）
# 目标  ：crates/hd-host/ui      （Tauri 的 "frontendDist"，见 crates/hd-host/tauri.conf.json）
#
# 行为：
#   1. 源目录不存在或为空 → 打印提示并以非 0 退出
#   2. 保留源目录结构，覆盖同名文件
#   3. 删除目标中多余的旧产物（但**不删** .gitkeep —— 它是 git 跟踪锚点）
#   4. 结束时打印同步/删除的文件清单，便于 CI 日志排查
#
# 为什么不直接用 rsync：
#   Windows / 精简 CI 镜像常常没有 rsync，而本项目要在 Windows 开发机与 Linux CI
#   双端跑同一套流程。因此这里用「纯 POSIX shell + find + cp」实现，保证零外部依赖。
#   若将来确定只在有 rsync 的环境跑，可换成 `rsync -a --delete --exclude .gitkeep`。
# ============================================================================
set -euo pipefail

# --- 1. 定位仓库根（脚本位于 <root>/scripts/） ------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

SRC="$REPO_ROOT/web/dist-baseline"
DST="$REPO_ROOT/crates/hd-host/ui"

echo "[sync-web] repo root : $REPO_ROOT"
echo "[sync-web] source    : $SRC"
echo "[sync-web] target    : $DST"

# --- 2. 校验源目录 ----------------------------------------------------------
if [ ! -d "$SRC" ]; then
  echo "[sync-web] ERROR: 源目录不存在：$SRC" >&2
  echo "[sync-web] 提示：请先执行 cd web && npm install && npm run build" >&2
  exit 1
fi

if [ -z "$(find "$SRC" -type f -print -quit)" ]; then
  echo "[sync-web] ERROR: 源目录为空：$SRC" >&2
  echo "[sync-web] 提示：请先执行 cd web && npm run build 产出基线 UI" >&2
  exit 1
fi

# --- 3. 确保目标目录存在 ----------------------------------------------------
mkdir -p "$DST"

# 说明：这里刻意不用 `sed -z`（BSD/macOS 的 sed 没有 -z），
# 改用纯 bash 参数扩展剥掉 "./" 前缀，保证 GNU / BSD / Git-Bash 三端一致。
strip_dot_slash() {
  local p="$1"
  printf '%s' "${p#./}"
}

# --- 4. 复制：保留相对结构，覆盖同名文件 ------------------------------------
copied_count=0
while IFS= read -r -d '' rel_raw; do
  rel="$(strip_dot_slash "$rel_raw")"
  target_path="$DST/$rel"
  target_dir="$(dirname -- "$target_path")"
  [ -d "$target_dir" ] || mkdir -p "$target_dir"
  cp -f -- "$SRC/$rel" "$target_path"
  copied_count=$((copied_count + 1))
  printf '  + %s\n' "$rel"
done < <(cd -- "$SRC" && find . -type f -print0)

# --- 5. 删除目标中多余的旧产物（保护 .gitkeep） -----------------------------
removed_count=0
while IFS= read -r -d '' rel_raw; do
  rel="$(strip_dot_slash "$rel_raw")"
  case "$rel" in
    .gitkeep) continue ;;   # git 跟踪锚点，永不删除
  esac
  if [ ! -f "$SRC/$rel" ]; then
    rm -f -- "$DST/$rel"
    removed_count=$((removed_count + 1))
    printf '  - %s\n' "$rel"
  fi
done < <(cd -- "$DST" && find . -type f -print0)

# --- 6. 清理变空的子目录（不动目标根） --------------------------------------
find "$DST" -mindepth 1 -type d -empty -delete 2>/dev/null || true

# --- 7. 汇报 ----------------------------------------------------------------
echo ""
echo "[sync-web] 已复制 ${copied_count} 个文件，删除 ${removed_count} 个旧产物"
echo "[sync-web] 完成，frontendDist 就绪：$DST"
