<#
.SYNOPSIS
  RustWard acceptance Stages C/D: read-only inspection of the installed service,
  named pipes, data folder and Event Log source.

.DESCRIPTION
  STATUS: written and syntax-checked on Linux; NOT YET EXECUTED on Windows.

  READ-ONLY. Run it AFTER the acceptance MSI was installed with
  Invoke-AcceptanceMsi.ps1 (which asks for confirmation) on the disposable VM.
  It only queries: sc.exe qc/qfailure/query/qsidtype/sdshow, Get-Service,
  Get-Acl, the EventLog registry source (read), Get-WinEvent, AccessChk if it
  is present, and the read-only "rustward-service verify-checkpoint".

  It does not start, stop, configure or delete the service, does not change
  ACLs and does not write the registry. The interactive items (C5, C6, C8-C18,
  C22-C27) remain manual: docs\WINDOWS-ACCEPTANCE-CHECKLIST.md.

  Run elevated so the protected data folder and pipe ACLs can be read.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Invoke-StageC-ServiceInspection.ps1 -DisposableVm
#>
param(
    [switch]$DisposableVm,
    [string]$EvidenceRoot = 'C:\rw-evidence',
    [string]$AccessChk = 'accesschk64.exe',
    [string]$CheckpointHeadId = '',
    [string]$CheckpointHash = ''
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RustWardAcceptance.psm1') -Force
$null = Assert-RwTestMachine -DisposableVm:$DisposableVm
$ErrorActionPreference = 'Continue'
if (-not (Test-RwElevated)) { Write-Host 'Warning: not elevated; data-folder and pipe ACL reads may fail.' -ForegroundColor Yellow }

$ev = Initialize-RwEvidence -Stage 'C' -Root $EvidenceRoot
$name = 'RustWardService'

# C1, C2, C4 and the service security descriptor (all read-only queries).
$null = Invoke-RwStep $ev 'C1-sc-qc' "sc.exe qc $name"
$null = Invoke-RwStep $ev 'C2-sc-qfailure' "sc.exe qfailure $name"
$null = Invoke-RwStep $ev 'C4-sc-query' "sc.exe query $name"
$null = Invoke-RwStep $ev 'C15-sc-qsidtype' "sc.exe qsidtype $name"
$null = Invoke-RwStep $ev 'C1-sc-sdshow' "sc.exe sdshow $name"
Get-Service -Name $name -ErrorAction SilentlyContinue | Format-List * |
    Out-File -Encoding utf8 (Join-Path $ev.Dir 'C4-get-service.txt')

# C3: data folder ACL and the database file.
$data = Join-Path $env:ProgramData 'RustWard'
try {
    (Get-Acl -Path $data).Sddl | Out-File -Encoding utf8 (Join-Path $ev.Dir 'C3-data-acl-sddl.txt')
    Get-Acl -Path $data | Format-List | Out-File -Encoding utf8 (Join-Path $ev.Dir 'C3-data-acl.txt')
    Get-ChildItem -Force -Path $data | Select-Object Name, Length, LastWriteTime |
        Out-File -Encoding utf8 (Join-Path $ev.Dir 'C4-data-files.txt')
    Add-RwNote $ev "C3: data folder ACL recorded. Expected protected DACL with SYSTEM and Administrators only (D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)). Phase 11 risk R-11-3: the MSI template declares InstallerVersion 450 while this ACL uses MsiLockPermissionsEx (Windows Installer 5.0); confirm here that it was applied."
}
catch { Add-RwNote $ev "C3: could not read $data ($_)" }

# C7: pipe ACLs. AccessChk (Sysinternals) if present; otherwise .NET, which opens
# no pipe instance for writing (GetAccessControl reads the security descriptor).
foreach ($pipe in 'RustWard.Admin.v1', 'RustWard.Status.v1') {
    $out = Join-Path $ev.Dir "C7-pipe-$pipe.txt"
    if (Get-Command $AccessChk -ErrorAction SilentlyContinue) {
        $null = Invoke-RwStep $ev "C7-accesschk-$pipe" "$AccessChk -accepteula -nobanner -l \pipe\$pipe"
    }
    else {
        try {
            [System.IO.Directory]::GetAccessControl("\\.\pipe\$pipe").GetSecurityDescriptorSddlForm('All') |
                Out-File -Encoding utf8 $out
        }
        catch { "not readable: $_" | Out-File -Encoding utf8 $out }
    }
}
Add-RwNote $ev 'C7: expected admin pipe O:SY with SY+BA only; status pipe: AU read + write-data only, no FILE_CREATE_PIPE_INSTANCE (F-18).'

# C19: Event Log source registration (registry READ).
$src = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\RustWard'
if (Test-Path $src) {
    Get-ItemProperty -Path $src | Format-List | Out-File -Encoding utf8 (Join-Path $ev.Dir 'C19-eventlog-source.txt')
}
else { Add-RwNote $ev "C19: $src not present" }

# C20/C21: RustWard events. "description cannot be found" in a message means
# the MESSAGETABLE is missing (C20 FAIL).
$events = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'RustWard' } -MaxEvents 500 -ErrorAction SilentlyContinue
$events | Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Export-Csv -NoTypeInformation -Encoding utf8 -Path (Join-Path $ev.Dir 'C20-events.csv')
$ids = @($events | ForEach-Object { $_.Id } | Sort-Object -Unique)
$unformatted = @($events | Where-Object { $_.Message -match 'cannot be found|bulunamad' }).Count
Add-RwNote $ev ("C21: event IDs seen: {0}" -f ($ids -join ', '))
Add-RwNote $ev ("C20: events without a formatted description: {0}" -f $unformatted)

# C24: read-only checkpoint verification, if the tester supplied values from a 5008 event.
if ($CheckpointHeadId -and $CheckpointHash) {
    $exe = (Get-CimInstance Win32_Service -Filter "Name='$name'").PathName -replace '^"([^"]+)".*$', '$1'
    $null = Invoke-RwStep $ev 'C24-verify-checkpoint' "`"$exe`" verify-checkpoint --head-id $CheckpointHeadId --hash $CheckpointHash"
}

Add-RwNote $ev ''
Add-RwNote $ev 'Nothing on this machine was changed. Record PASS/FAIL per item in docs\WINDOWS-ACCEPTANCE-CHECKLIST.md.'
Get-Content $ev.Summary
