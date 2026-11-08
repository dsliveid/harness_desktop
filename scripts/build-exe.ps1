# Build release executables for harness_desktop.
#
# Usage:
#   .\scripts\build-exe.ps1
#
# Produces two executables in target\release\:
#   hd-host.exe   - desktop host shell (UI embedded)   <- THIS is the one users launch
#   hd-runner.exe - execution engine (spawned automatically)
#
# STARTUP UX: users only ever launch hd-host.exe. It spawns hd-runner.exe itself
# after pairing. The second file is an implementation detail, like the helper
# processes most desktop apps ship.
#
# WHY NOT a single self-spawning exe (hd-host.exe --runner)?
# Measured on Windows: an exe that links Tauri (GUI deps) and is launched by a
# parent via Stdio::piped() dies at load time with 0xC0000139
# (STATUS_ENTRYPOINT_NOT_FOUND), with EMPTY stderr - it never reaches main().
# A standalone hd-runner.exe under the identical spawn path works fine.
# Root cause is Tauri's load-time initialization vs. the piped-stdio child
# context, not our logic. Verified with a real Rust spawn probe, not a shell pipe.
#
# IMPORTANT: hd-host requires BOTH `gui` AND `custom-protocol` features.
# Without `custom-protocol`, Tauri 2 does NOT embed the frontend assets and the
# exe exits immediately with 0xC0000139 (silently, since console is suppressed).
#
# NOTE: ASCII-only on purpose. Windows PowerShell 5.1 reads BOM-less UTF-8 as
# ANSI, and multibyte CJK bytes break the parser.

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host '[1/3] Building hd-runner (release)...'
cargo build -p hd-runner --bin hd-runner --release
if ($LASTEXITCODE -ne 0) { throw "hd-runner build failed (exit $LASTEXITCODE)" }

Write-Host '[2/3] Building hd-host (release, gui + custom-protocol)...'
cargo build -p hd-host --release --features gui,custom-protocol
if ($LASTEXITCODE -ne 0) { throw "hd-host build failed (exit $LASTEXITCODE)" }

Write-Host '[3/3] Verifying artifacts...'
$targets = @(
    @{ Path = 'target\release\hd-host.exe';   Name = 'hd-host (launch this one)' },
    @{ Path = 'target\release\hd-runner.exe'; Name = 'hd-runner (auto-spawned)' }
)

$total = 0
foreach ($t in $targets) {
    if (-not (Test-Path $t.Path)) {
        throw "Missing artifact: $($t.Path)"
    }
    $f = Get-Item $t.Path
    $mb = [math]::Round($f.Length / 1MB, 2)
    $total += $mb
    Write-Host ("  {0,-28} {1,7} MB   {2}" -f $t.Name, $mb, $f.LastWriteTime)
}

# Budget from docs: main package target <= 16 MB, acceptance line <= 20 MB.
Write-Host ("  {0,-28} {1,7} MB" -f 'TOTAL', [math]::Round($total, 2))
if ($total -gt 20) {
    Write-Warning "Total size exceeds the 20 MB acceptance line (docs section 18.4)."
}

Write-Host ''
Write-Host "Done. Ship both files in the same directory; users double-click hd-host.exe only."
Write-Host "Runtime prerequisite: Microsoft Edge WebView2 Runtime on Windows."
