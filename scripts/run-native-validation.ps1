<#
.SYNOPSIS
  RustWard Phase 1 native Windows validation.

.DESCRIPTION
  READ-ONLY with respect to Windows configuration. It:
    - records tool versions and the current device-installation and
      removable-storage policy values (scripts\check-prereqs.ps1, read-only);
    - runs cargo fmt/check/clippy/test/build (build output goes to .\target);
    - runs the read-only rustward-inventory tool (SetupAPI queries only).
  It does NOT change Group Policy, the registry, devices, drivers or services,
  and it does not mount, eject or touch storage media.

  All output goes to .\evidence\native\<timestamp>\ which is excluded from git.
  Files named *raw* contain serial numbers: keep them on this computer.

  Run from a normal (unelevated) PowerShell window in the repository root:
      powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-native-validation.ps1
#>
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
if ($root -match '\s') {
    Write-Host "Repository path contains spaces; this script expects a path without spaces: $root"
    exit 2
}
Set-Location $root
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = Join-Path $root "evidence\native\$stamp"
$raw = Join-Path $out 'raw'
New-Item -ItemType Directory -Force -Path $raw | Out-Null
$summary = Join-Path $out 'summary.txt'
"RustWard native validation $stamp" | Out-File -FilePath $summary -Encoding ascii

function Step([string]$Name, [string]$Command) {
    $log = Join-Path $out "$Name.txt"
    Write-Host "==> $Name"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    cmd.exe /d /c "$Command > $log 2>&1"
    $code = $LASTEXITCODE
    $sw.Stop()
    $line = "{0,-26} exit={1,-5} {2,7:N1}s  {3}" -f $Name, $code, $sw.Elapsed.TotalSeconds, $Command
    Add-Content -Path $summary -Value $line -Encoding ascii
    Write-Host "    exit=$code"
}

# 1. Environment (read-only)
Step 'env-prereqs'      'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\check-prereqs.ps1'
Step 'env-rustc'        'rustc -vV'
Step 'env-rustc-cfg'    'rustc --print cfg'
Step 'env-cargo'        'cargo -vV'
Step 'env-rustup'       'rustup show'
Step 'env-targets'      'rustup target list --installed'
Step 'env-node'         'node -v'
Step 'env-npm'          'npm -v'
Step 'env-git'          'git --version'
Step 'git-head'         'git rev-parse HEAD'
Step 'git-status'       'git status --short'

# 2. Native Rust validation
Step 'cargo-fmt'        'cargo fmt --all -- --check'
Step 'cargo-check'      'cargo check --workspace --all-targets'
Step 'cargo-clippy'     'cargo clippy --workspace --all-targets -- -D warnings'
Step 'cargo-test'       'cargo test --workspace'
Step 'cargo-test-native' 'cargo test -p rustward-windows --test native_windows -- --nocapture --test-threads=1'
Step 'cargo-build-rel'  'cargo build --workspace --release'

# 3. Read-only inventory with the release binary
$exe = Join-Path $root 'target\release\rustward-inventory.exe'
if (Test-Path $exe) {
    Step 'inv-help'          "$exe help"
    Step 'inv-capture-present' "$exe capture --out $raw\snapshot-present-raw.json"
    Step 'inv-capture-all'   "$exe capture --include-non-present --out $raw\snapshot-all-raw.json"
    Step 'inv-report-all'    "$exe report --snapshot $raw\snapshot-all-raw.json --out-dir $out\report-all"
    Step 'inv-report-present' "$exe report --snapshot $raw\snapshot-present-raw.json --out-dir $out\report-present"
    Step 'inv-plan'          "$exe plan --snapshot $raw\snapshot-all-raw.json"
    Step 'inv-scan-sanitized' "$exe scan --sanitize"
} else {
    Add-Content -Path $summary -Value 'inventory: SKIPPED (release binary missing)' -Encoding ascii
}

Write-Host ''
Write-Host "Done. Results: $out"
Write-Host 'Nothing on this computer was changed. Files with "raw" in the name contain serial numbers; keep them local.'
Get-Content $summary
