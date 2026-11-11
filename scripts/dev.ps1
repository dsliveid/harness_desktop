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
#   .\scripts\dev.ps1 -EmbeddedWeb # build with custom-protocol (NO port 1420 needed)
#
# WHY A DEV BUILD NEEDS A SERVER ON PORT 1420
# A build WITHOUT `custom-protocol` is a Tauri *development* build:
# `tauri/build.rs` sets `dev = !custom_protocol`, and `Manager::get_app_url()`
# under `#[cfg(dev)]` returns `build.devUrl` (http://localhost:1420) instead of
# the assets embedded in the binary. tauri.conf.json's `beforeDevCommand` is
# executed by the `tauri dev` CLI only -- and this repo deliberately launches the
# exe directly (see header), so *nothing* used to start dev-server.mjs. The
# window then opened on a dead port and showed "localhost refused to connect".
# Step [1/4] below therefore guarantees a live dev server before building.
# `-EmbeddedWeb` is the opt-out: it compiles with `custom-protocol`, which makes
# Tauri treat the build as production and load the embedded `ui/` assets, so port
# 1420 does not matter at all.
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
    [switch]$WithWeb,
    [switch]$EmbeddedWeb
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

# --- 1. dev server on port 1420 ---------------------------------------------
# WHY THIS STEP EXISTS AT ALL
# See the header: a build without `custom-protocol` loads `build.devUrl`
# (http://localhost:1420) and nothing else. tauri.conf.json's
# `beforeDevCommand` is only honored by the `tauri dev` CLI, which this script
# deliberately does not use -- so without this step the window opens on a dead
# port and the user sees "localhost refused to connect".
#
# `-EmbeddedWeb` skips the whole step: that build carries `custom-protocol`, so
# Tauri treats it as production and serves the embedded `ui/` assets.
$devPort = 1420
$devServerProc = $null

function Test-PortOpen([int]$Port) {
    # TcpClient + WaitOne(300ms) instead of Test-NetConnection: the latter costs
    # ~1s per call, prints a progress bar, and also tries ICMP. This is a plain
    # "is something listening on 127.0.0.1:port" probe.
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(300)) { return $false }
        $client.EndConnect($iar)
        return $true
    }
    catch { return $false }
    finally { $client.Close() }
}

if ($EmbeddedWeb) {
    # Nothing to serve: the assets live inside the exe. Still assert they exist,
    # otherwise `custom-protocol` fails at RUNTIME (asset 404) rather than here.
    $uiEntry = Join-Path $root 'crates\hd-host\ui\main.js'
    $uiIndex = Join-Path $root 'crates\hd-host\ui\index.html'
    Write-Host '[1/4] Embedded web mode: no dev server needed (custom-protocol).'
    if ((-not (Test-Path $uiIndex)) -or (-not (Test-Path $uiEntry))) {
        throw ("-EmbeddedWeb needs the built UI at crates\hd-host\ui (index.html + main.js), " +
               "but it is missing. Run with -WithWeb (npm build + sync) or drop -EmbeddedWeb.")
    }
}
elseif (Test-PortOpen $devPort) {
    # Already running (previous run, or a manual `cd web; npm run dev`): reuse it
    # rather than racing a second server onto the same port (EADDRINUSE is fatal
    # in dev-server.mjs by design -- it refuses to silently pick another port).
    Write-Host "[1/4] Dev server already listening on $devPort (reusing it)."
}
else {
    Write-Host "[1/4] Starting dev server on port $devPort ..."
    $node = Get-Command node -ErrorAction SilentlyContinue
    if (-not $node) {
        throw ("node not found on PATH. A dev build loads http://localhost:$devPort and " +
               "needs the local dev server; install Node.js, or build with -EmbeddedWeb " +
               "to embed the UI and skip the server entirely.")
    }

    # esbuild is the only build dependency of dev-server.mjs; `npm install` is the
    # recovery for a fresh clone (node_modules is gitignored).
    if (-not (Test-Path (Join-Path $root 'web\node_modules\esbuild'))) {
        Write-Host '      web/node_modules/esbuild missing, running npm install ...'
        Push-Location (Join-Path $root 'web')
        try {
            npm install
            if ($LASTEXITCODE -ne 0) { throw "npm install failed (exit $LASTEXITCODE)" }
        }
        finally { Pop-Location }
    }

    # Log into target/ (gitignored, always exists after a build) -- NOT into
    # web/.dev-out/, because dev-server.mjs wipes that directory on startup.
    $logDir = Join-Path $root 'target'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $devLog = Join-Path $logDir 'dev-server.log'

    $devServerProc = Start-Process -FilePath $node.Source `
        -ArgumentList @('dev-server.mjs') `
        -WorkingDirectory (Join-Path $root 'web') `
        -WindowStyle Hidden `
        -RedirectStandardOutput $devLog `
        -RedirectStandardError "$devLog.err" `
        -PassThru
    Write-Host "      started node dev-server.mjs (PID $($devServerProc.Id)), log: $devLog"

    # Wait for the port to actually accept connections. Polling beats a fixed
    # sleep: the first esbuild bundle is async, and a blind `sleep 5` either
    # wastes time or -- worse -- returns before the port is up and we launch a
    # window that still says "refused to connect".
    $deadline = (Get-Date).AddSeconds(25)
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        if ($devServerProc.HasExited) { break }
        if (Test-PortOpen $devPort) { $ready = $true; break }
        Start-Sleep -Milliseconds 250
    }

    if (-not $ready) {
        $tail = ''
        foreach ($f in @($devLog, "$devLog.err")) {
            if (Test-Path $f) { $tail += (Get-Content $f -Tail 20 | Out-String) }
        }
        if ($null -ne $devServerProc -and -not $devServerProc.HasExited) {
            # Only touch the process WE started (precise PID, never by name).
            Stop-Process -Id $devServerProc.Id -Force -ErrorAction SilentlyContinue
        }
        throw ("dev server did not come up on port $devPort within 25s. " +
               "See $devLog.`n$tail`n" +
               "Hint: use .\scripts\dev.ps1 -EmbeddedWeb to build a self-contained exe " +
               "that does not need port $devPort.")
    }
    Write-Host "      port $devPort is ready."
}

# --- 2. build ---------------------------------------------------------------
# The windows-gnu toolchain (rust-toolchain.toml pins 1.98.1-gnu) needs MinGW
# gcc/as/dlltool for ring / windows-sys / tauri-winres(windres); the rustup
# self-contained dir ships dlltool+ld but NOT gcc or as.
# 2026-11-11: on this machine MSYS2 lives in C:\msys64 -- prepend mingw64/bin.
# Probed dynamically (machine-specific path); missing probe is not fatal and
# falls back to whatever PATH the caller already has.
$mingwCandidates = @('C:\msys64\mingw64\bin', 'D:\msys64\mingw64\bin')
foreach ($cand in $mingwCandidates) {
    if ((Test-Path (Join-Path $cand 'gcc.exe')) -and
        ($env:Path -notlike "*$cand*")) {
        Write-Host "[env] Prepending $cand to PATH (windows-gnu needs gcc/as)"
        $env:Path = "$cand;$env:Path"
        break
    }
}

$profileArgs = @()
$profileLabel = 'debug'
if ($Release) {
    $profileArgs = @('--release')
    $profileLabel = 'release'
}

# `custom-protocol` is what flips Tauri from dev to production (see header).
# Adding it ONLY in -EmbeddedWeb keeps the default hot-reload path intact:
# with custom-protocol the binary ignores devUrl and embeds the ui/ snapshot,
# so edits to web/src/** would no longer show up without a rebuild + sync.
$features = 'gui'
if ($EmbeddedWeb) { $features = 'gui,custom-protocol' }

Write-Host "[2/4] Building hd-host ($profileLabel, features: $features)..."
cargo build -p hd-host --features $features @profileArgs
if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }

$exe = if ($Release) { 'target\release\hd-host.exe' } else { 'target\debug\hd-host.exe' }
if (-not (Test-Path $exe)) {
    throw "Build reported success but $exe is missing. Check the feature flags above."
}

$mb = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "[3/4] Built: $exe ($mb MB)"

if ($NoLaunch) {
    # Be explicit about the dev server we may have just started: it stays alive on
    # purpose (an IDE-launched dev build needs it), but the user must know.
    if ($null -ne $devServerProc -and -not $devServerProc.HasExited) {
        Write-Host "[3/4] Dev server left running (PID $($devServerProc.Id)) for your IDE launch."
        Write-Host "      Stop it with:  Stop-Process -Id $($devServerProc.Id)"
    }
    Write-Host 'Done (build only).'
    exit 0
}

# --- 3. launch --------------------------------------------------------------
# Launch WITHOUT -Wait so this script returns immediately and the console stays
# usable for logs. The GUI process owns the runner child process, so killing
# this shell does not kill the app.
Write-Host ''
Write-Host "[4/4] Launching $exe ..."
if ($null -ne $devServerProc -and -not $devServerProc.HasExited) {
    Write-Host "      dev server PID $($devServerProc.Id) stays alive (the window loads port $devPort)."
    Write-Host "      Stop it with:  Stop-Process -Id $($devServerProc.Id)"
}
Write-Host 'Tip: the runner is a child process of this same exe (--runner).'
Write-Host '     Check it with:  Get-Process hd-host | Select-Object Id,MainWindowTitle'
Write-Host ''
Start-Process -FilePath $exe
