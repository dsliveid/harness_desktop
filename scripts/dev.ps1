# ============================================================================
# dev.ps1 - one-command build + launch for local development.
#
# WHY THIS EXISTS
# Single-package mode means there is now exactly ONE build target (hd-host).
# Before, forgetting to rebuild hd-runner.exe silently ran stale code: the GUI
# would spawn an old runner binary while `cargo test` stayed green (tests link
# the fresh lib). That failure mode is gone, but you still have to remember the
# feature flags. This script encodes them so you never type them wrong.
#
# USAGE
#   .\scripts\dev.ps1              # build + launch GUI
#   .\scripts\dev.ps1 -Release     # release build (slower, smaller)
#   .\scripts\dev.ps1 -NoLaunch    # build only (e.g. before debugging in an IDE)
#   .\scripts\dev.ps1 -WithWeb     # also rebuild the web UI into crates/hd-host/ui
#
# WHY `--features gui` IS MANDATORY
# hd-host's GUI layer is feature-gated (default = []). A plain `cargo build
# -p hd-host` produces a binary with NO window and NO Tauri at all, which looks
# like "the app does not start". The flag is not optional for a GUI build.
#
# WHY NOT `cargo run`
# `cargo run -p hd-host` works, but it re-resolves the package graph on every
# invocation and cannot express the "build only" mode. Running the exe directly
# also keeps the console window lifecycle predictable.
#
# NOTE (encoding): ASCII-only. Windows PowerShell 5.1 reads BOM-less UTF-8 as
# ANSI; multibyte CJK bytes would corrupt this script.

param(
    [switch]$Release,
    [switch]$NoLaunch,
    [switch]$WithWeb
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# --- 0. optional: rebuild the embedded web UI -------------------------------
if ($WithWeb) {
    Write-Host '[0/3] Rebuilding web UI (web -> crates/hd-host/ui)...'
    Push-Location web
    try {
        # `npm ci` only when node_modules is missing: it is slow and rewrites
        # the lockfile state, which we do not want on every dev iteration.
        if (-not (Test-Path 'node_modules')) {
            Write-Host '      node_modules missing, running npm install...'
            npm install
            if ($LASTEXITCODE -ne 0) { throw "npm install failed (exit $LASTEXITCODE)" }
        }
        npm run build
        if ($LASTEXITCODE -ne 0) { throw "npm run build failed (exit $LASTEXITCODE)" }
    }
    finally {
        Pop-Location
    }

    & "$PSScriptRoot\sync-web.ps1"
    if ($LASTEXITCODE -ne 0) { throw "sync-web.ps1 failed (exit $LASTEXITCODE)" }
}

# --- 1. build ---------------------------------------------------------------
$profileArgs = @()
$profileLabel = 'debug'
if ($Release) {
    $profileArgs = @('--release')
    $profileLabel = 'release'
}

Write-Host "[1/2] Building hd-host ($profileLabel, gui)..."
# NOTE: `custom-protocol` is only meaningful for release builds; passing it in
# debug is harmless but adds nothing, so keep the flag set minimal and explicit.
cargo build -p hd-host --features gui @profileArgs
if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }

$exe = if ($Release) { 'target\release\hd-host.exe' } else { 'target\debug\hd-host.exe' }
if (-not (Test-Path $exe)) {
    throw "Build reported success but $exe is missing. Check the feature flags above."
}

$mb = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "[2/2] Built: $exe ($mb MB)"

if ($NoLaunch) {
    Write-Host 'Done (build only).'
    exit 0
}

# --- 2. launch --------------------------------------------------------------
# Launch WITHOUT -Wait so this script returns immediately and the console stays
# usable for logs. The GUI process owns the runner child process, so killing
# this shell does not kill the app.
Write-Host ''
Write-Host "Launching $exe ..."
Write-Host 'Tip: the runner is a child process of this same exe (--runner).'
Write-Host '     Check it with:  Get-Process hd-host | Select-Object Id,MainWindowTitle'
Write-Host ''
Start-Process -FilePath $exe
