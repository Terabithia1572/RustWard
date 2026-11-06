<#
.SYNOPSIS
  Build RustWard release artifacts on a Windows 10/11 x64 BUILD machine.

.DESCRIPTION
  STATUS: WRITTEN, NOT RUN. Never executed by the developers' tooling yet.

  Builds; never installs. This script does NOT install the MSI, register or
  start the service, or change any device, driver, registry policy or Group
  Policy. Installing the produced MSI is a separate, manual step performed only
  on the isolated acceptance VM (docs/OFFLINE-DEPLOYMENT.md).

  Steps:
    1. Checks toolchain versions (read-only).
    2. cargo build --release --locked (service + inventory CLI), optionally offline
       from ./vendor (scripts/vendor-offline.sh).
    3. npm ci (optionally offline from ./.npm-offline-cache), typecheck, tests.
    4. tauri build --bundles msi. With -WithService the draft WiX fragment
       packaging/wix/rustward-service.wxs is merged (service + data directory).
    5. Copies artifacts, BUILD-INFO.txt and DEPENDENCY-INVENTORY.md to
       .\release-out and writes SHA256SUMS.txt over all of them.

  Network: with webviewInstallMode=offlineInstaller, tauri-bundler 2.10.x
  resolves the WebView2 installer URL with a HEAD request and downloads WiX 3.14
  if %LOCALAPPDATA%\tauri\WixTools314 is missing. A fully air-gapped build
  machine therefore needs a pre-provisioned WixTools314 directory AND the
  fixedVersion WebView2 mode. See docs/OFFLINE-DEPLOYMENT.md.

.PARAMETER Offline
  Use vendored crates and the offline npm cache. Fails if they are missing.

.PARAMETER WithService
  Merge the draft service fragment into the MSI (acceptance builds only).
#>
[CmdletBinding()]
param(
    [switch]$Offline,
    [switch]$WithService
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
$App = Join-Path $Root 'apps\rustward-desktop'
$Out = Join-Path $Root 'release-out'

function Invoke-Checked([string]$What, [scriptblock]$Block) {
    Write-Host "== $What" -ForegroundColor Cyan
    & $Block
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
}

if (-not [Environment]::Is64BitOperatingSystem) { throw 'x64 Windows is required.' }

# 1. Toolchain (read-only)
Invoke-Checked 'rustc version' { rustc --version }
Invoke-Checked 'cargo version' { cargo --version }
Invoke-Checked 'node version' { node --version }
Invoke-Checked 'npm version' { npm --version }

$cargoOffline = @()
$npmOffline = @()
if ($Offline) {
    $cfg = Join-Path $Root '.cargo-offline\config.toml'
    $cache = Join-Path $Root '.npm-offline-cache'
    if (-not (Test-Path $cfg) -or -not (Test-Path (Join-Path $Root 'vendor'))) { throw 'vendor/ or .cargo-offline/config.toml missing: run scripts/vendor-offline.sh on a connected machine.' }
    if (-not (Test-Path $cache)) { throw '.npm-offline-cache missing: run scripts/vendor-offline.sh on a connected machine.' }
    $cargoOffline = @('--offline', '--config', $cfg)
    $npmOffline = @('--offline', '--cache', $cache)
}

Push-Location $Root
try {
    # 2. Rust workspace
    Invoke-Checked 'cargo test (workspace)' { cargo test --workspace --locked @cargoOffline }
    Invoke-Checked 'cargo build --release (service, inventory)' {
        cargo build --release --locked @cargoOffline -p rustward-service -p rustward-inventory
    }
    $serviceExe = Join-Path $Root 'target\release\rustward-service.exe'
    if (-not (Test-Path $serviceExe)) { throw "missing $serviceExe" }
}
finally { Pop-Location }

Push-Location $App
try {
    # 3. Frontend
    Invoke-Checked 'npm ci' { npm ci @npmOffline }
    Invoke-Checked 'typecheck' { npm run typecheck }
    Invoke-Checked 'vitest' { npm test }

    # 4. Desktop app + MSI. Release builds never contain the dev backend
    # (compile-time gate on debug_assertions in rustward-ui-bridge).
    $tauriArgs = @('tauri', 'build', '--bundles', 'msi')
    if ($WithService) {
        # Read by the WiX fragment as $(env.TAURI_RUSTWARD_SERVICE_EXE).
        $env:TAURI_RUSTWARD_SERVICE_EXE = $serviceExe
        $tauriArgs += @('--config', (Join-Path $Root 'packaging\tauri.acceptance.conf.json'))
    }
    if ($Offline) {
        # Arguments after `--` go to `cargo build` for the Tauri shell.
        $tauriArgs += @('--', '--locked', '--offline', '--config', (Join-Path $Root '.cargo-offline\config.toml'))
    }
    Invoke-Checked 'tauri build (msi)' { npx @tauriArgs }
}
finally {
    Remove-Item Env:\TAURI_RUSTWARD_SERVICE_EXE -ErrorAction SilentlyContinue
    Pop-Location
}

# 5. Collect artifacts + hashes
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$artifacts = @(
    (Join-Path $Root 'target\release\rustward-service.exe'),
    (Join-Path $Root 'target\release\rustward-inventory.exe')
) + (Get-ChildItem (Join-Path $App 'src-tauri\target\release\bundle\msi\*.msi') | ForEach-Object FullName)
foreach ($a in $artifacts) { Copy-Item $a $Out -Force }
# Build provenance (no secrets, no workstation data).
@(
    "RustWard $((Get-Content (Join-Path $App 'src-tauri\tauri.conf.json') -Raw | ConvertFrom-Json).version)",
    "git commit: $(git -C $Root rev-parse HEAD)",
    "git dirty: $([bool](git -C $Root status --porcelain))",
    "rustc: $(rustc --version)",
    "cargo: $(cargo --version)",
    "node: $(node --version)",
    "target: x86_64-pc-windows-msvc",
    "with service fragment: $([bool]$WithService)",
    "offline build: $([bool]$Offline)",
    "ACTIVATION_ENABLED: false (dry-run build)"
) | Set-Content -Encoding ascii (Join-Path $Out 'BUILD-INFO.txt')
Copy-Item (Join-Path $Root 'docs\DEPENDENCY-INVENTORY.md') $Out -Force
Get-ChildItem $Out -File | Where-Object Name -ne 'SHA256SUMS.txt' |
    ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name } |
    Set-Content -Encoding ascii (Join-Path $Out 'SHA256SUMS.txt')
Write-Host "Artifacts in $Out (unsigned). Nothing was installed or registered." -ForegroundColor Green
