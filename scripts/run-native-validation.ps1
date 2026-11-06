<#
.SYNOPSIS
  RustWard native Windows validation: acceptance Stage A (native compilation)
  plus the read-only inventory (Stage B1/B2). Extended in Phase 11.

.DESCRIPTION
  READ-ONLY with respect to Windows configuration. It:
    - records tool versions and the current device-installation and
      removable-storage policy values (scripts\check-prereqs.ps1, read-only);
    - runs cargo fmt/check/clippy/test/build (build output goes to .\target);
    - runs the read-only rustward-inventory tool (SetupAPI queries only).
    - (Phase 11) runs the frontend checks, the UI <-> real-backend integration
      tests, the Tauri shell tests, checks that rustward-service.exe embeds the
      Event Log MESSAGETABLE, and with -TauriBuild builds the MSI.
  It does NOT change Group Policy, the registry, devices, drivers or services,
  and it does not mount, eject or touch storage media. It does not install
  anything: building an MSI is not installing it.

  STATUS: written and reviewed on Linux; NOT YET EXECUTED on Windows. Every
  step records an exit code; a Linux type-check is never a native result.

  -TauriBuild needs network access on the build machine (tauri-bundler sends a
  HEAD request for WebView2 and downloads WiX if not cached; docs\OFFLINE-DEPLOYMENT.md).

  All output goes to .\evidence\native\<timestamp>\ which is excluded from git.
  Files named *raw* contain serial numbers: keep them on this computer.

  Run from a normal (unelevated) PowerShell window in the repository root:
      powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-native-validation.ps1 [-TauriBuild] [-SkipFrontend]
#>
param(
    [switch]$TauriBuild,
    [switch]$SkipFrontend
)
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

Step 'env-cl'           'where cl.exe'
Step 'env-rc'           'where rc.exe'
Step 'env-dumpbin'      'where dumpbin.exe'
Step 'env-webview2'     'reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" /v pv'

# 2. Native Rust validation (A2-A5)
Step 'cargo-fmt'        'cargo fmt --all -- --check'
Step 'cargo-check'      'cargo check --workspace --all-targets --locked'
Step 'cargo-clippy'     'cargo clippy --workspace --all-targets --locked -- -D warnings'
Step 'cargo-clippy-all' 'cargo clippy --workspace --all-targets --all-features --locked -- -D warnings'
Step 'cargo-test'       'cargo test --workspace --all-features --locked'
Step 'cargo-test-native' 'cargo test -p rustward-windows --test native_windows --locked -- --nocapture --test-threads=1'
Step 'cargo-test-bridge-rel' 'cargo test -p rustward-ui-bridge --release --locked'
Step 'cargo-build-rel'  'cargo build --workspace --release --locked'
# A5: the service must embed the MESSAGETABLE (resource type 11). dumpbin is in the
# "x64 Native Tools" prompt; when it is missing the step is recorded as failed.
Step 'dumpbin-service'  'dumpbin /headers target\release\rustward-service.exe'
Step 'dumpbin-imports'  'dumpbin /imports target\release\rustward-service.exe target\release\rustward-inventory.exe'

# 3. Frontend, integration and Tauri shell (A6-A9)
if (-not $SkipFrontend) {
    $app = 'apps\rustward-desktop'
    Step 'npm-ci'           "cd /d $app && npm ci"
    Step 'tsc'              "cd /d $app && npx tsc -b --noEmit"
    Step 'vitest'           "cd /d $app && npx vitest run"
    Step 'vite-build'       "cd /d $app && npx vite build"
    Step 'offline-assets'   'node scripts\check-offline-assets.mjs'
    Step 'harness-build'    'cargo build -p rustward-ui-bridge --features dev-backend --example stdio_backend --locked'
    Step 'tsc-integration'  "cd /d $app && npx tsc -p tsconfig.integration.json --noEmit"
    Step 'vitest-integration' "cd /d $app && set RUSTWARD_STDIO_BACKEND=$root\target\debug\examples\stdio_backend.exe&& npx vitest run --config vitest.integration.config.ts"
    Step 'tauri-fmt'        "cd /d $app\src-tauri && cargo fmt --check"
    Step 'tauri-clippy'     "cd /d $app\src-tauri && cargo clippy --all-targets --locked -- -D warnings"
    Step 'tauri-test'       "cd /d $app\src-tauri && cargo test --locked"
    if ($TauriBuild) {
        # A10 (UI-only MSI). The acceptance MSI with the service is built by
        # scripts\build-release.ps1 -WithService. Building is not installing.
        Step 'tauri-build'  "cd /d $app && npx tauri build --bundles msi"
    }
}
Step 'cargo-deny'       'cargo deny check'
Step 'cargo-deny-tauri' 'cargo deny --manifest-path apps\rustward-desktop\src-tauri\Cargo.toml check'

# 4. Read-only inventory with the release binary (B1/B2)
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
