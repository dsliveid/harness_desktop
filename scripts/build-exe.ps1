# Build release executable for harness_desktop.
#
# Usage:
#   .\scripts\build-exe.ps1
#
# Produces ONE executable in target\release\:
#   hd-host.exe   - desktop host shell (UI embedded) + Runner (self-derived)
#
# STARTUP UX: users only ever launch hd-host.exe. It spawns a SECOND PROCESS of
# ITSELF with the --runner flag after pairing (see crates/hd-host/src/main.rs).
# One file, two processes: the GUI/lifecycle process and the sandboxed execution
# process stay separate for crash isolation, but there is nothing else to ship.
#
# WHY SELF-DERIVE WORKS (this used to say the opposite -- that claim was wrong):
# An earlier version of this script claimed that an exe linking Tauri "dies at
# load time with 0xC0000139 when launched by a parent via Stdio::piped()".
# Measured again (2026-11) with a spawn probe that replicates the exact
# Stdio::piped() + write-stdin sequence:
#
#   subsystem         GUI double-click    self-derive
#   ----------------- ------------------- ------------------------------------
#   windows           no console window   CRASHES at load (0xC0000139)
#   console           flashes a console   WORKS (enters main(), reads stdin,
#                                          exits 2, ~51ms)
#
# So the failure was specific to the WINDOWS subsystem, not to self-derive.
# crates/hd-host/src/main.rs deliberately keeps the console subsystem, which
# makes self-derive reliable. The trade-off is a brief console flash on launch;
# an NSIS shortcut with ShowWindow=Hidden can hide it.
#
# IMPORTANT: hd-host requires BOTH `gui` AND `custom-protocol` features.
# Without `custom-protocol`, Tauri 2 does NOT embed the frontend assets and the
# exe exits immediately (silently, since console output is suppressed).
#
# NOTE: ASCII-only on purpose. Windows PowerShell 5.1 reads BOM-less UTF-8 as
# ANSI, and multibyte CJK bytes break the parser.

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host '[1/2] Building hd-host (release, gui + custom-protocol)...'
cargo build -p hd-host --release --features gui,custom-protocol
if ($LASTEXITCODE -ne 0) { throw "hd-host build failed (exit $LASTEXITCODE)" }

Write-Host '[2/2] Verifying artifact...'
$exePath = 'target\release\hd-host.exe'
if (-not (Test-Path $exePath)) {
    throw "Missing artifact: $exePath"
}
$f = Get-Item $exePath
$mb = [math]::Round($f.Length / 1MB, 2)

# Budget from docs: main package target <= 16 MB, acceptance line <= 20 MB.
Write-Host ("  {0,-28} {1,7} MB   {2}" -f 'hd-host.exe (launch this)', $mb, $f.LastWriteTime)
if ($mb -gt 20) {
    Write-Warning "Package size exceeds the 20 MB acceptance line (docs section 18.4)."
}

# Guard against a stale second binary being shipped by mistake.
$stray = 'target\release\hd-runner.exe'
if (Test-Path $stray) {
    Write-Host ''
    Write-Warning "Found $stray from an OLDER build. It is no longer part of the package."
    Write-Warning "Users need ONLY hd-host.exe. Delete the stray file to avoid confusion:"
    Write-Warning "  Remove-Item $stray"
}

Write-Host ''
Write-Host 'Done. Ship hd-host.exe alone; it derives its own runner process.'
Write-Host 'Runtime prerequisite: Microsoft Edge WebView2 Runtime on Windows.'
