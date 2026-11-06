<#
.SYNOPSIS
  RustWard acceptance Stage D: install, repair or uninstall the acceptance MSI
  on the DISPOSABLE VM only, after explicit confirmation.

.DESCRIPTION
  STATUS: written and syntax-checked on Linux; NOT YET EXECUTED on Windows.
  No RustWard MSI has been built yet.

  THIS SCRIPT CHANGES THE MACHINE: it runs msiexec for the RustWard MSI. That
  installs or removes rustward-service.exe as a service, the RustWard Event Log
  source and %ProgramData%\RustWard. It does not change any device, driver,
  USB policy, Device Installation Restrictions value or Group Policy, and the
  build it installs has enforcement compiled out (ACTIVATION_ENABLED = false).

  Safeguards:
    - refuses to run unless this computer is detected as a virtual machine
      and -DisposableVm is given;
    - asks the operator to type the computer name;
    - for Install/Repair, verifies the MSI against SHA256SUMS.txt first (D1)
      and refuses on a mismatch;
    - logs msiexec verbosely into the evidence folder.

  Take a VM checkpoint first (CP-C / CP-D: docs\WINDOWS-VM-ACCEPTANCE.md).

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Invoke-AcceptanceMsi.ps1 -Action Install -Msi .\release-out\RustWard_0.1.0_x64_en-US.msi -DisposableVm
#>
param(
    [Parameter(Mandatory)][ValidateSet('Install', 'Repair', 'Uninstall')][string]$Action,
    [Parameter(Mandatory)][string]$Msi,
    [switch]$DisposableVm,
    [string]$EvidenceRoot = 'C:\rw-evidence'
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RustWardAcceptance.psm1') -Force
if (-not (Test-RwElevated)) { throw 'Run this from an elevated PowerShell (msiexec per-machine install).' }
$msiPath = (Resolve-Path -LiteralPath $Msi).Path
# Explicit confirmation (typed computer name) on a detected VM only, before
# anything is written or run.
$null = Assert-RwTestMachine -DisposableVm:$DisposableVm -SystemChange

$ev = Initialize-RwEvidence -Stage "D-$($Action.ToLowerInvariant())" -Root $EvidenceRoot
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $msiPath).Hash.ToLowerInvariant()
Add-RwNote $ev "MSI: $msiPath"
Add-RwNote $ev "SHA-256: $hash"

if ($Action -ne 'Uninstall') {
    $sums = Join-Path (Split-Path -Parent $msiPath) 'SHA256SUMS.txt'
    if (-not (Test-Path $sums)) { throw "D1: $sums not found; refusing to install an unverified MSI." }
    $leaf = Split-Path -Leaf $msiPath
    $expected = Get-Content $sums | Where-Object { $_ -match [regex]::Escape($leaf) } |
        ForEach-Object { ($_ -split '\s+')[0].ToLowerInvariant() } | Select-Object -First 1
    if ($expected -ne $hash) { throw "D1: hash mismatch for $leaf (expected '$expected'). Nothing was installed." }
    Add-RwNote $ev 'D1: MSI hash matches SHA256SUMS.txt'
}

$log = Join-Path $ev.Dir "msiexec-$($Action.ToLowerInvariant()).log"
$msiArgs = switch ($Action) {
    'Install' { @('/i', "`"$msiPath`"", '/qn', '/norestart', '/l*v', "`"$log`"") }
    'Repair' { @('/fa', "`"$msiPath`"", '/qn', '/norestart', '/l*v', "`"$log`"") }
    'Uninstall' { @('/x', "`"$msiPath`"", '/qn', '/norestart', '/l*v', "`"$log`"") }
}
$p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
Add-RwNote $ev ("msiexec {0}: exit code {1} (0 = success, 3010 = success, restart required)" -f $Action, $p.ExitCode)
Add-RwNote $ev 'Next: run Invoke-StageC-ServiceInspection.ps1 (read-only) and record D-items in the checklist.'
Get-Content $ev.Summary
