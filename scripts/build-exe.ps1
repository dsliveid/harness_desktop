# Build release executables for harness_desktop.
#
# Usage:
#   .\scripts\build-exe.ps1
#
# Produces two standalone executables (no installer needed):
#   target\release\hd-host.exe   - desktop host shell (UI embedded)
#   target\release\hd-runner.exe - execution engine
#
# IMPORTANT: hd-host REQUIRES BOTH `gui` AND `custom-protocol` features.
# Without `custom-protocol`, Tauri 2 does NOT embed the frontend assets, and the
# resulting exe exits immediately on launch with 0xC0000139 (and, because
# windows_subsystem="windows" suppresses the console, it looks like a silent
# crash with no error message). This actually happened once and cost hours.
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
    @{ Path = 'target\release\hd-host.exe';   Name = 'hd-host' },
    @{ Path = 'target\release\hd-runner.exe'; Name = 'hd-runner' }
)

$total = 0
foreach ($t in $targets) {
    if (-not (Test-Path $t.Path)) {
        throw "Missing artifact: $($t.Path)"
    }
    $f = Get-Item $t.Path
    $mb = [math]::Round($f.Length / 1MB, 2)
    $total += $mb
    Write-Host ("  {0,-12} {1,7} MB   {2}" -f $t.Name, $mb, $f.LastWriteTime)
}

# Budget from docs: main package target <= 16 MB, acceptance line <= 20 MB.
Write-Host ("  {0,-12} {1,7} MB" -f 'TOTAL', [math]::Round($total, 2))
if ($total -gt 20) {
    Write-Warning "Total size exceeds the 20 MB acceptance line (docs section 18.4)."
}

Write-Host ''
Write-Host "Done. Ship both exe files in the same directory (no installer required)."
Write-Host "Runtime prerequisite: Microsoft Edge WebView2 Runtime on Windows."
