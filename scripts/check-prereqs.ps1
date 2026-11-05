<#
.SYNOPSIS
  RustWard Phase 0 prerequisite and baseline report. READ-ONLY.

.DESCRIPTION
  Prints OS edition/build, development tool versions, and the current values
  of device-installation and removable-storage policy keys. It changes nothing.
  Run from a normal (unelevated) PowerShell:
      powershell -ExecutionPolicy Bypass -File .\scripts\check-prereqs.ps1
#>
$ErrorActionPreference = 'Continue'

function Show-Tool([string]$Name, [string[]]$VersionArgs) {
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { "{0,-14} MISSING" -f $Name; return }
    try { $v = (& $Name @VersionArgs 2>&1 | Select-Object -First 1) } catch { $v = "error: $_" }
    "{0,-14} {1}" -f $Name, $v
}

"== Operating system =="
$os = Get-CimInstance Win32_OperatingSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
"Caption        $($os.Caption)"
"Version        $($os.Version)  DisplayVersion=$($cv.DisplayVersion)  Build=$($cv.CurrentBuild).$($cv.UBR)"
"Architecture   $($os.OSArchitecture)"

"`n== Development tools =="
Show-Tool 'rustc'  @('-V')
Show-Tool 'cargo'  @('-V')
Show-Tool 'rustup' @('-V')
Show-Tool 'node'   @('-v')
Show-Tool 'npm'    @('-v')
Show-Tool 'git'    @('--version')
if (Get-Command rustup -ErrorAction SilentlyContinue) { "rustup toolchains:"; rustup toolchain list }

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path $vswhere) {
    "Visual Studio with MSVC x64 tools:"
    & $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format value -property displayName
} else { "vswhere         MISSING" }

$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Include'
if (Test-Path $kits) {
    Get-ChildItem $kits -Directory | ForEach-Object {
        $wdk = if (Test-Path (Join-Path $_.FullName 'km')) { 'WDK present' } else { 'SDK only' }
        "Windows Kit    $($_.Name)  ($wdk)"
    }
} else { "Windows SDK    MISSING" }

$wv = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' -ErrorAction SilentlyContinue
"WebView2       $(if ($wv) { $wv.pv } else { 'not found in machine-wide EdgeUpdate key' })"

"`n== Current device installation policy (baseline, read-only) =="
$di = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall'
if (Test-Path $di) { Get-ChildItem $di -Recurse | ForEach-Object { $_.Name; Get-ItemProperty $_.PSPath | Format-List | Out-String } }
else { "(no DeviceInstall policy key)" }

"`n== Current removable storage policy (baseline, read-only) =="
$rs = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
if (Test-Path $rs) { Get-ChildItem $rs -Recurse | ForEach-Object { $_.Name; Get-ItemProperty $_.PSPath | Format-List | Out-String } }
else { "(no RemovableStorageDevices policy key)" }

"`nDone. Nothing was modified."
