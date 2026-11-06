<#
.SYNOPSIS
  RustWard acceptance Stage E: read-only Device Installation Restrictions
  inspection and assessment of already-installed storage devices.

.DESCRIPTION
  STATUS: written and syntax-checked on Linux; NOT YET EXECUTED on Windows.

  READ-ONLY. It:
    - exports HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall with
      "reg export" BEFORE and AFTER (export writes only the .reg file);
    - reads the USBSTOR and UASPStor service start values ("reg query");
    - runs rustward-inventory policy-capture / policy-inspect / assess-installed
      (RegOpenKeyExW with KEY_READ only; SetupAPI queries only);
    - compares the two exports byte for byte (E10). This is the only result the
      script decides itself: identical = PASS, different = FAIL.

  It never creates, changes or deletes a registry value, never refreshes
  policy, never uninstalls or disables a device and never enables enforcement.
  Do NOT create test values in the Restrictions key on this checkpoint: the
  values present must be those of the image as delivered.

  E5/E6 (list-entry layout, *Retroactive names) stay UNRESOLVED unless the
  delivered image or official documentation shows them. Record what the
  "before" export contains; do not create values to find out.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Invoke-StageE-PolicyInspection.ps1 -BinDir .\release-out -DisposableVm
#>
param(
    [Parameter(Mandatory)][string]$BinDir,
    [switch]$DisposableVm,
    [switch]$PhysicalTestMachine,
    [string]$EvidenceRoot = 'C:\rw-evidence'
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RustWardAcceptance.psm1') -Force
$null = Assert-RwTestMachine -DisposableVm:$DisposableVm -PhysicalTestMachine:$PhysicalTestMachine
$ErrorActionPreference = 'Continue'

$inv = Join-Path $BinDir 'rustward-inventory.exe'
if (-not (Test-Path $inv)) { throw "missing $inv" }
$ev = Initialize-RwEvidence -Stage 'E' -Root $EvidenceRoot
$raw = Join-Path $ev.Dir 'raw'
New-Item -ItemType Directory -Force -Path $raw | Out-Null
$key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall'

function Export-RwPolicy([string]$Name) {
    $file = Join-Path $raw "$Name.reg"
    $code = Invoke-RwStep $ev "E-$Name" "reg export `"$key`" `"$file`" /y"
    if ($code -ne 0 -or -not (Test-Path $file)) { return 'absent' }
    (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash
}

# E1: before.
$before = Export-RwPolicy 'deviceinstall-before'
Add-RwNote $ev "E1: DeviceInstall policy key export (before): $before"

# OS facts for E2 (compare with policy-capture's os block) and storage services.
$null = Invoke-RwStep $ev 'E2-winver' 'cmd /c ver'
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Add-RwNote $ev ("E2: CurrentBuild={0} UBR={1} EditionID={2} DisplayVersion={3}" -f $cv.CurrentBuild, $cv.UBR, $cv.EditionID, $cv.DisplayVersion)
$null = Invoke-RwStep $ev 'E-usbstor-start' 'reg query "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start'
$null = Invoke-RwStep $ev 'E-uaspstor-start' 'reg query "HKLM\SYSTEM\CurrentControlSet\Services\UASPStor" /v Start'

# E2-E4, E7: RustWard read-only tools.
$cap = Join-Path $raw 'policy-capture.json'
$null = Invoke-RwStep $ev 'E2-policy-capture' "`"$inv`" policy-capture --out `"$cap`""
$null = Invoke-RwStep $ev 'E4-capture-inventory' "`"$inv`" capture --include-non-present --out `"$raw\raw-inventory.json`""
$null = Invoke-RwStep $ev 'E4-policy-inspect' "`"$inv`" policy-inspect --policy-capture `"$cap`" --snapshot `"$raw\raw-inventory.json`""
$null = Invoke-RwStep $ev 'E4-policy-inspect-json' "`"$inv`" policy-inspect --policy-capture `"$cap`" --snapshot `"$raw\raw-inventory.json`" --json"
$null = Invoke-RwStep $ev 'E7-assess-installed' "`"$inv`" assess-installed --snapshot `"$raw\raw-inventory.json`" --policy-capture `"$cap`" --sanitize --out-dir `"$($ev.Dir)\assess`""

# E10: after, and the exact comparison.
$after = Export-RwPolicy 'deviceinstall-after'
Add-RwNote $ev "E10: DeviceInstall policy key export (after): $after"
if ($before -eq $after) {
    Add-RwNote $ev 'E10 RESULT: PASS - the DeviceInstall policy key is identical before and after Stage E.'
}
else {
    Add-RwNote $ev 'E10 RESULT: FAIL - the DeviceInstall policy key changed during Stage E. Stop and investigate; restore the checkpoint.'
}

Add-RwNote $ev ''
Add-RwNote $ev 'Manual next steps: E3 (compare raw\deviceinstall-before.reg with raw\policy-capture.json value by value), E5/E6 (record list layout and *Retroactive names seen, or "not observed"), E8 (readiness page), E9 (native test from Stage A).'
Get-Content $ev.Summary
