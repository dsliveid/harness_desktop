# ============================================================================
# sync-web.ps1 - copy the baseline web UI build into the Tauri frontendDist.
#
# Source : web/dist-baseline      (produced by: cd web; npm install; npm run build)
# Target : crates/hd-host/ui      (Tauri "frontendDist", see crates/hd-host/tauri.conf.json)
#
# Behavior:
#   * abort with exit code 1 when the source directory is missing or empty
#   * mirror the source tree into the target (overwrite same-name files)
#   * delete stale files in the target that no longer exist in the source
#   * NEVER delete .gitkeep (it keeps the ui/ directory tracked by git)
#   * print every copied / removed file so CI logs stay auditable
#
# NOTE (encoding): this file is intentionally pure ASCII.
# Windows PowerShell 5.1 reads a UTF-8 file WITHOUT a BOM as ANSI; multi-byte
# characters (e.g. Chinese comments) would corrupt the script and break parsing.
# Keep all comments and output strings ASCII-only. Do not "beautify" them.
#
# NOTE (why not robocopy): robocopy reports SUCCESS with exit codes 0..7 (1 means
# "files copied"), so a naive `if ($LASTEXITCODE -ne 0) { fail }` would mark a
# successful sync as failure. robocopy /MIR would also wipe .gitkeep. A plain
# Copy-Item implementation keeps the exit-code semantics obvious and portable.
# ============================================================================

$ErrorActionPreference = 'Stop'

# --- 1. resolve paths relative to this script (repo root = scripts/..) -------
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir
$src       = Join-Path $repoRoot 'web\dist-baseline'
$dst       = Join-Path $repoRoot 'crates\hd-host\ui'

Write-Host "[sync-web] repo root : $repoRoot"
Write-Host "[sync-web] source    : $src"
Write-Host "[sync-web] target    : $dst"

# --- 2. validate the source directory ---------------------------------------
if (-not (Test-Path -LiteralPath $src -PathType Container)) {
    Write-Host "[sync-web] ERROR: source directory not found: $src" -ForegroundColor Red
    Write-Host "[sync-web] hint : run 'cd web; npm install; npm run build' first." -ForegroundColor Yellow
    exit 1
}

$srcFull = (Resolve-Path -LiteralPath $src).Path.TrimEnd('\')

# Relative paths of every source file (kept in the same shape as the tree).
$srcFiles = @(
    Get-ChildItem -LiteralPath $srcFull -Recurse -File |
        ForEach-Object { $_.FullName.Substring($srcFull.Length + 1) }
)

if ($srcFiles.Count -eq 0) {
    Write-Host "[sync-web] ERROR: source directory is empty: $src" -ForegroundColor Red
    Write-Host "[sync-web] hint : run 'cd web; npm run build' to produce the baseline UI." -ForegroundColor Yellow
    exit 1
}

# --- 3. make sure the target directory exists -------------------------------
if (-not (Test-Path -LiteralPath $dst -PathType Container)) {
    New-Item -ItemType Directory -Path $dst -Force | Out-Null
    Write-Host "[sync-web] created target directory"
}
$dstFull = (Resolve-Path -LiteralPath $dst).Path.TrimEnd('\')

# --- 4. copy every source file, preserving the relative structure -----------
$copied = @()
foreach ($rel in $srcFiles) {
    $srcPath = Join-Path $srcFull $rel
    $dstPath = Join-Path $dstFull $rel
    $dstDir  = Split-Path -Parent $dstPath
    if (-not (Test-Path -LiteralPath $dstDir -PathType Container)) {
        New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
    }
    Copy-Item -LiteralPath $srcPath -Destination $dstPath -Force
    $copied += $rel
}

# --- 5. remove stale files (present in target, absent from source) ----------
# .gitkeep is protected: it is a git tracking anchor, not a build artifact.
$protected = @('.gitkeep')

$removed = @()
$dstFiles = @(
    Get-ChildItem -LiteralPath $dstFull -Recurse -File -Force |
        ForEach-Object { $_.FullName.Substring($dstFull.Length + 1) }
)
foreach ($rel in $dstFiles) {
    if ($srcFiles -contains $rel) { continue }
    if ($protected -contains $rel) { continue }
    Remove-Item -LiteralPath (Join-Path $dstFull $rel) -Force
    $removed += $rel
}

# --- 6. prune directories that became empty (never remove the target root) --
$emptyDirs = @(
    Get-ChildItem -LiteralPath $dstFull -Recurse -Directory -Force |
        Sort-Object { $_.FullName.Length } -Descending |
        Where-Object { -not (Get-ChildItem -LiteralPath $_.FullName -Force) }
)
foreach ($dir in $emptyDirs) {
    if ($dir.FullName.TrimEnd('\') -eq $dstFull) { continue }
    Remove-Item -LiteralPath $dir.FullName -Force -Recurse
}

# --- 7. report ---------------------------------------------------------------
Write-Host ""
Write-Host "[sync-web] copied $($copied.Count) file(s):"
foreach ($rel in $copied) { Write-Host "  + $rel" }

if ($removed.Count -gt 0) {
    Write-Host "[sync-web] removed $($removed.Count) stale file(s):"
    foreach ($rel in $removed) { Write-Host "  - $rel" }
} else {
    Write-Host "[sync-web] removed 0 stale file(s)"
}

Write-Host "[sync-web] done. frontendDist is ready at: $dstFull"
exit 0
