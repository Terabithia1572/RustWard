<#
.SYNOPSIS
  RustWard acceptance Stage B: read-only system and device inspection.

.DESCRIPTION
  STATUS: written and syntax-checked on Linux; NOT YET EXECUTED on Windows.

  READ-ONLY. Runs the RustWard inventory (SetupAPI queries only) and the
  console service with a temporary database, and records PnP facts with
  Get-PnpDevice / Get-PnpDeviceProperty. It does not install, uninstall,
  disable, eject or mount anything and does not change any policy.

  Real USB storage needs physical hardware or a hypervisor with USB
  pass-through (Hyper-V has none: docs\WINDOWS-VM-ACCEPTANCE.md).

  Checklist items: B1-B8. B9 (offline run) = run this again with the network
  disconnected and -Label offline.

  Files under raw\ contain serial numbers. Keep them on the test machine; only
  the sanitized report may leave it.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Invoke-StageB-DeviceInspection.ps1 -BinDir .\release-out -PhysicalTestMachine
#>
param(
    [Parameter(Mandatory)][string]$BinDir,
    [switch]$DisposableVm,
    [switch]$PhysicalTestMachine,
    [string]$EvidenceRoot = 'C:\rw-evidence',
    [string]$Label = 'online'
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RustWardAcceptance.psm1') -Force
$null = Assert-RwTestMachine -DisposableVm:$DisposableVm -PhysicalTestMachine:$PhysicalTestMachine
$ErrorActionPreference = 'Continue'

$inv = Join-Path $BinDir 'rustward-inventory.exe'
$svc = Join-Path $BinDir 'rustward-service.exe'
foreach ($f in @($inv, $svc)) { if (-not (Test-Path $f)) { throw "missing $f" } }

$ev = Initialize-RwEvidence -Stage "B-$Label" -Root $EvidenceRoot
$raw = Join-Path $ev.Dir 'raw'
New-Item -ItemType Directory -Force -Path $raw | Out-Null

# B1-B2: inventory and sanitized report.
$null = Invoke-RwStep $ev 'B1-capture-present' "`"$inv`" capture --out `"$raw\inventory-present.json`""
$null = Invoke-RwStep $ev 'B1-capture-all' "`"$inv`" capture --include-non-present --out `"$raw\raw-inventory.json`""
$null = Invoke-RwStep $ev 'B2-report' "`"$inv`" report --snapshot `"$raw\raw-inventory.json`" --out-dir `"$($ev.Dir)\report`""
$null = Invoke-RwStep $ev 'B2-scan-sanitized' "`"$inv`" scan --sanitize"
$null = Invoke-RwStep $ev 'B3-plan' "`"$inv`" plan --snapshot `"$raw\raw-inventory.json`""

# B3-B7: Windows' own view, for comparison with RustWard's classification.
# Get-PnpDevice and Get-PnpDeviceProperty only read.
$classes = 'DiskDrive', 'USB', 'HIDClass', 'Keyboard', 'Mouse', 'Printer', 'CDROM', 'WPD', 'SCSIAdapter'
$pnp = Get-PnpDevice -PresentOnly:$false -ErrorAction SilentlyContinue |
    Where-Object { $classes -contains $_.Class } |
    Select-Object Class, FriendlyName, Status, Problem, InstanceId
$pnp | Export-Csv -NoTypeInformation -Encoding utf8 -Path (Join-Path $raw 'pnp-devices.csv')
$keys = 'DEVPKEY_Device_HardwareIds', 'DEVPKEY_Device_CompatibleIds', 'DEVPKEY_Device_Parent', 'DEVPKEY_Device_Service', 'DEVPKEY_Device_BusReportedDeviceDesc', 'DEVPKEY_Device_ProblemCode'
$props = foreach ($d in ($pnp | Where-Object { $_.Class -eq 'DiskDrive' })) {
    foreach ($k in $keys) {
        $p = Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName $k -ErrorAction SilentlyContinue
        [pscustomobject]@{ InstanceId = $d.InstanceId; Key = $k; Data = ($p.Data -join ' | ') }
    }
}
$props | Export-Csv -NoTypeInformation -Encoding utf8 -Path (Join-Path $raw 'disk-properties.csv')
Add-RwNote $ev ("Windows PnP view: {0} devices in classes {1}; disk properties in raw\disk-properties.csv" -f @($pnp).Count, ($classes -join ','))

# B8: console service with a temporary database (no pipes, no SCM, no Event Log).
$db = Join-Path $ev.Dir 'console-b8.db'
$null = Invoke-RwStep $ev 'B8-console-synthetic' "`"$svc`" console --db `"$db`" --synthetic --iterations 3"
$db2 = Join-Path $ev.Dir 'console-b8-live.db'
$null = Invoke-RwStep $ev 'B8-console-live' "`"$svc`" console --db `"$db2`" --iterations 1"

Add-RwNote $ev ''
Add-RwNote $ev 'Next: compare report\ and raw\pnp-devices.csv per device (B3-B7) and record PASS/FAIL in the checklist.'
Add-RwNote $ev 'Nothing on this machine was changed (apart from the evidence folder and the two temporary databases in it).'
Get-Content $ev.Summary
