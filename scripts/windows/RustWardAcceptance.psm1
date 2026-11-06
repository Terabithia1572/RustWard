<#
.SYNOPSIS
  Shared helpers for the RustWard Windows acceptance scripts (Phase 11).

.DESCRIPTION
  NOT EXECUTED BY THE DEVELOPERS. Written and syntax-checked on Linux only; the
  project owner runs these scripts on the authorized disposable Windows 10 Pro VM
  or a dedicated physical test machine.

  Nothing in this module changes Windows. It only:
    - reports whether this computer looks like a virtual machine;
    - refuses to continue unless the operator confirms the machine is a
      disposable test machine (never a production workstation, never the
      development PC);
    - creates evidence folders and records each step's exit code.

  A recorded exit code is NOT a PASS. The tester decides PASS / FAIL / BLOCKED /
  NOT RUN against docs\WINDOWS-ACCEPTANCE-CHECKLIST.md. The only result these
  scripts decide themselves is an exact file comparison (Stage E, E10).
#>
Set-StrictMode -Version 3.0

function Get-RwMachineKind {
    <# Returns @{ IsVirtual; Manufacturer; Model; Hint }. Read-only (CIM query). #>
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $man = [string]$cs.Manufacturer
    $model = [string]$cs.Model
    $hint = switch -Regex ("$man|$model") {
        'Microsoft Corporation\|Virtual Machine' { 'Hyper-V'; break }
        'VMware' { 'VMware'; break }
        'innotek|VirtualBox' { 'VirtualBox'; break }
        'QEMU|KVM|Standard PC' { 'QEMU/KVM'; break }
        'Parallels' { 'Parallels'; break }
        'Xen' { 'Xen'; break }
        default { '' }
    }
    [pscustomobject]@{
        IsVirtual    = ($hint -ne '')
        Manufacturer = $man
        Model        = $model
        Hint         = $hint
    }
}

function Assert-RwTestMachine {
    <#
      Stops the script unless this is an authorized test machine.

      -DisposableVm          : the caller says this is a disposable VM with a checkpoint.
      -PhysicalTestMachine   : the caller says this is a dedicated physical test machine
                               (allowed only for read-only stages; needed for real USB).
      -SystemChange          : the script changes this machine (install/uninstall). Only
                               allowed on a detected VM, and the operator must type the
                               computer name.
    #>
    param(
        [switch]$DisposableVm,
        [switch]$PhysicalTestMachine,
        [switch]$SystemChange
    )
    $kind = Get-RwMachineKind
    Write-Host ("Machine: {0} / {1}  (virtual: {2} {3})" -f $kind.Manufacturer, $kind.Model, $kind.IsVirtual, $kind.Hint)
    if (-not ($DisposableVm -or $PhysicalTestMachine)) {
        throw 'Refusing to run: pass -DisposableVm (disposable VM with a checkpoint) or -PhysicalTestMachine (dedicated test hardware). Never run on a production workstation or the development PC.'
    }
    if ($DisposableVm -and -not $kind.IsVirtual) {
        throw 'Refusing to run: -DisposableVm was given but this computer does not look like a virtual machine.'
    }
    if ($SystemChange) {
        if (-not $kind.IsVirtual) {
            throw 'Refusing to run: this script changes the machine and is only allowed on a detected disposable VM.'
        }
        Write-Host ''
        Write-Host 'This step CHANGES this machine (it installs, repairs or removes RustWard).' -ForegroundColor Yellow
        Write-Host 'It does not change any device, driver, USB policy or Group Policy.' -ForegroundColor Yellow
        Write-Host 'Take or confirm a VM checkpoint before continuing.' -ForegroundColor Yellow
        $typed = Read-Host "Type this computer's name ($env:COMPUTERNAME) to confirm, anything else to stop"
        if ($typed -cne $env:COMPUTERNAME) {
            throw 'Not confirmed. Nothing was changed.'
        }
    }
    else {
        $typed = Read-Host "Read-only stage. Type YES if $env:COMPUTERNAME is an authorized test machine"
        if ($typed -cne 'YES') { throw 'Not confirmed. Nothing was run.' }
    }
    $kind
}

function Test-RwElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-RwEvidence {
    <# Creates <root>\<stage>\<timestamp>\ and a summary.txt header. #>
    param(
        [Parameter(Mandatory)][string]$Stage,
        [string]$Root = 'C:\rw-evidence'
    )
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $dir = Join-Path (Join-Path $Root $Stage) $stamp
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $summary = Join-Path $dir 'summary.txt'
    @(
        "RustWard acceptance evidence - stage $Stage - $stamp"
        "Computer: $env:COMPUTERNAME  User: $env:USERNAME  Elevated: $(Test-RwElevated)"
        'Exit codes are recorded facts, not PASS/FAIL. Decide results with docs\WINDOWS-ACCEPTANCE-CHECKLIST.md.'
        ''
    ) | Out-File -FilePath $summary -Encoding utf8
    [pscustomobject]@{ Dir = $dir; Summary = $summary }
}

function Invoke-RwStep {
    <# Runs one command line through cmd.exe, logs its output and records the exit code. #>
    param(
        [Parameter(Mandatory)]$Evidence,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Command
    )
    $log = Join-Path $Evidence.Dir "$Name.txt"
    Write-Host "==> $Name"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    cmd.exe /d /c "$Command > `"$log`" 2>&1"
    $code = $LASTEXITCODE
    $sw.Stop()
    $line = '{0,-30} exit={1,-6} {2,8:N1}s  {3}' -f $Name, $code, $sw.Elapsed.TotalSeconds, $Command
    Add-Content -Path $Evidence.Summary -Value $line -Encoding utf8
    Write-Host "    exit=$code"
    $code
}

function Add-RwNote {
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)][string]$Text)
    Add-Content -Path $Evidence.Summary -Value $Text -Encoding utf8
    Write-Host $Text
}

Export-ModuleMember -Function Get-RwMachineKind, Assert-RwTestMachine, Test-RwElevated, Initialize-RwEvidence, Invoke-RwStep, Add-RwNote
