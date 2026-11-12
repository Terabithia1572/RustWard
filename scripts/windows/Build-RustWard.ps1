<#
.SYNOPSIS
  Builds the RustWard Windows desktop application (Tauri 2, MSVC) and puts the
  verified executables into dist\. Started by BUILD-RUSTWARD.cmd.

.DESCRIPTION
  What it does, in order:
    1. Checks the prerequisites (Windows x64, Rust with the MSVC toolchain,
       Visual Studio C++ Build Tools, Windows SDK, Node.js, npm, WebView2).
       Nothing is installed and no administrator rights are requested.
    2. npm ci in apps\rustward-desktop.
    3. Release build:  npx tauri build --no-bundle
         -> the real RustWard application. It talks to the RustWard Windows
            service; when the service is not installed it says so.
    4. Preview build:  npx tauri build --debug --no-bundle --features gui-subsystem
         -> the same application with the in-process development backend
            (temporary SQLite database in %TEMP%\rustward-dev-ui, read-only
            device inventory, labelled synthetic data on request). Isolated
            from the release configuration: the development backend only
            exists in debug builds.
    5. Service build:  cargo build --release -p rustward-service -p rustward-inventory
         -> the RustWard Windows service executable (Event Log MESSAGETABLE
            embedded with rc.exe) and the read-only inventory CLI.
    6. Verifies every file (PE32+ x64, expected subsystem, the service's
       MESSAGETABLE resource, size, SHA-256) and copies them to dist\
       (RustWard.exe, RustWard-Onizleme.exe, service\rustward-service.exe,
       service\rustward-inventory.exe) with START-*.cmd and BUILD-INFO.txt.
    7. Complete MSI (default on, -SkipMsi to skip): desktop app + Windows
       service (LocalSystem, auto start, restart on failure) + Event Log
       source + protected %ProgramData%\RustWard + offline WebView2 installer,
       from packaging\wix\rustward-service.wxs. The finished MSI is opened
       READ-ONLY (Windows Installer COM) to confirm the service is inside.
       The MSI is NOT installed. Install it only on a disposable test VM.

  It does NOT change Windows: no service installation, no registry or Group
  Policy change, no device or driver change. USB enforcement stays disabled
  (ACTIVATION_ENABLED = false); the application cannot block USB devices.

  Logs: build-logs\<timestamp>\ (kept). Exit code 0 = everything built and
  verified; 3 = executables ready but the MSI failed; anything else = failure
  (see the Turkish message and the logs).
#>
param(
    [switch]$SkipMsi,
    [switch]$SkipPreview
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { $null = $_ }

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$App = Join-Path $Root 'apps\rustward-desktop'
$Tauri = Join-Path $App 'src-tauri'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Logs = Join-Path $Root "build-logs\$Stamp"
$Dist = Join-Path $Root 'dist'
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$Summary = Join-Path $Logs 'ozet.txt'

function Write-Info([string]$Text) {
    Write-Host $Text
    Add-Content -Path $Summary -Value $Text -Encoding UTF8
}

function Exit-Build([int]$Code, [string]$Message, [string]$Hint) {
    Write-Host ''
    Write-Host "HATA: $Message" -ForegroundColor Red
    if ($Hint) { Write-Host "Çözüm: $Hint" -ForegroundColor Yellow }
    Write-Host "Günlükler: $Logs"
    Add-Content -Path $Summary -Value "HATA ($Code): $Message" -Encoding UTF8
    if ($Hint) { Add-Content -Path $Summary -Value "Çözüm: $Hint" -Encoding UTF8 }
    exit $Code
}

function Invoke-Logged([string]$Name, [string]$WorkDir, [string]$Command) {
    $log = Join-Path $Logs "$Name.log"
    Write-Info "==> $Name  ($Command)"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Push-Location $WorkDir
    try {
        # cmd.exe merges stderr into stdout, so PowerShell 5.1 does not turn
        # compiler messages into error records. Output is shown and logged.
        # Out-Host: show the output without returning it from the function
        # (otherwise the exit-code comparison would see the whole log).
        cmd.exe /d /c "$Command 2>&1" | Tee-Object -FilePath $log | Out-Host
        $code = $LASTEXITCODE
    }
    finally { Pop-Location }
    $sw.Stop()
    Write-Info ('    çıkış kodu {0}, {1:N0} sn, günlük: {2}' -f $code, $sw.Elapsed.TotalSeconds, $log)
    $code
}

function Get-Version([string]$Text) {
    $m = [regex]::Match($Text, '(\d+)\.(\d+)\.(\d+)')
    if (-not $m.Success) { return $null }
    [version]('{0}.{1}.{2}' -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value)
}

function Test-PeX64([string]$Path, [int]$Subsystem) {
    # Reads the PE header: MZ, PE\0\0, machine AMD64 (0x8664), PE32+ (0x20B)
    # and the subsystem (2 = Windows GUI, 3 = console, used by the service).
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 1024 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { return 'MZ başlığı yok' }
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($bytes[$pe] -ne 0x50 -or $bytes[$pe + 1] -ne 0x45 -or $bytes[$pe + 2] -ne 0 -or $bytes[$pe + 3] -ne 0) { return 'PE imzası yok' }
    $machine = [BitConverter]::ToUInt16($bytes, $pe + 4)
    $opt = $pe + 24
    $magic = [BitConverter]::ToUInt16($bytes, $opt)
    $sub = [BitConverter]::ToUInt16($bytes, $opt + 68)
    if ($machine -ne 0x8664) { return ('makine türü 0x{0:X4} (x64 değil)' -f $machine) }
    if ($magic -ne 0x20B) { return 'PE32+ değil' }
    if ($sub -ne $Subsystem) { return "alt sistem $sub (beklenen $Subsystem)" }
    'OK'
}

function Test-MessageTable([string]$Path) {
    # True when the .rsrc section's root directory has a type-11 (RT_MESSAGETABLE)
    # entry: Event Viewer needs it to format RustWard events.
    $bytes = [IO.File]::ReadAllBytes($Path)
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    $sections = [BitConverter]::ToUInt16($bytes, $pe + 6)
    $optSize = [BitConverter]::ToUInt16($bytes, $pe + 20)
    $table = $pe + 24 + $optSize
    for ($i = 0; $i -lt $sections; $i++) {
        $h = $table + 40 * $i
        $name = [Text.Encoding]::ASCII.GetString($bytes, $h, 8).TrimEnd([char]0)
        if ($name -ne '.rsrc') { continue }
        $root = [BitConverter]::ToInt32($bytes, $h + 20)
        $count = [BitConverter]::ToUInt16($bytes, $root + 12) + [BitConverter]::ToUInt16($bytes, $root + 14)
        for ($e = 0; $e -lt $count; $e++) {
            $id = [BitConverter]::ToUInt32($bytes, $root + 16 + 8 * $e)
            if ($id -eq 11) { return $true }
        }
    }
    $false
}

function Get-MsiRow([string]$MsiPath, [string]$Sql) {
    # Opens the MSI database READ-ONLY (mode 0) and returns the rows of one
    # query as string arrays. Nothing is installed or changed.
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $rows = @()
    $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($MsiPath, 0))
    try {
        $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @($Sql))
        $null = $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
        while ($true) {
            $rec = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
            if ($null -eq $rec) { break }
            $n = $rec.GetType().InvokeMember('FieldCount', 'GetProperty', $null, $rec, $null)
            $cols = @()
            for ($k = 1; $k -le $n; $k++) { $cols += $rec.GetType().InvokeMember('StringData', 'GetProperty', $null, $rec, @($k)) }
            $rows += , $cols
        }
        $null = $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)
    }
    finally {
        $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($db)
        $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
    , $rows
}

Write-Info "RustWard Windows derlemesi - $Stamp"
Write-Info "Depo: $Root"
Write-Info 'Bu betik yalnızca derleme yapar; bu makinede hizmet kurmaz ve Windows ilkesini değiştirmez.'
Write-Info ''

# ---------------------------------------------------------------- 1. Checks
Write-Info '== Ön koşullar'
if ($env:OS -ne 'Windows_NT') { Exit-Build 10 'Bu betik yalnızca Windows üzerinde çalışır.' '' }
if (-not [Environment]::Is64BitOperatingSystem) { Exit-Build 11 '64 bit Windows gerekli.' '' }
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Write-Info ("Windows: {0} {1}, derleme {2}.{3}" -f $cv.ProductName, $cv.DisplayVersion, $cv.CurrentBuild, $cv.UBR)

# Programs started from Explorer may not see PATH changes made by the Rust or
# Node.js installers until the user signs out. Look in the standard install
# locations and add them to PATH for THIS build process only (nothing is
# installed and the user/system PATH is not changed).
function Add-BuildPath([string[]]$Candidates, [string]$Exe) {
    if (Get-Command $Exe -ErrorAction SilentlyContinue) { return }
    foreach ($dir in $Candidates) {
        if ($dir -and (Test-Path (Join-Path $dir "$Exe.exe"))) {
            $env:PATH = "$dir;$env:PATH"
            Write-Info "PATH'e yalnızca bu derleme için eklendi: $dir"
            return
        }
    }
}
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
Add-BuildPath @((Join-Path $cargoHome 'bin')) 'cargo'
Add-BuildPath @(
    (Join-Path $env:ProgramFiles 'nodejs'),
    (Join-Path ${env:ProgramFiles(x86)} 'nodejs'),
    (Join-Path $env:LOCALAPPDATA 'Programs\nodejs'),
    $env:NVM_SYMLINK
) 'node'

if (-not (Get-Command cargo -ErrorAction SilentlyContinue) -or -not (Get-Command rustc -ErrorAction SilentlyContinue)) {
    Exit-Build 20 'Rust (cargo/rustc) bulunamadı.' 'https://rustup.rs adresinden rustup-init.exe ile Rust kurun, sonra yeni bir komut penceresi açın.'
}
$rustcInfo = (& rustc -vV) -join "`n"
Write-Info ("rustc: " + (($rustcInfo -split "`n")[0]))
$rustHost = ([regex]::Match($rustcInfo, 'host:\s*(\S+)')).Groups[1].Value
if ($rustHost -notmatch 'msvc') {
    Exit-Build 21 "Rust araç zinciri MSVC değil ($rustHost)." 'rustup default stable-x86_64-pc-windows-msvc'
}
$rv = Get-Version $rustcInfo
if ($null -eq $rv -or $rv -lt [version]'1.90.0') {
    Exit-Build 22 "Rust 1.90 veya daha yenisi gerekli (bulunan: $rv)." 'rustup update stable'
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsPath = $null
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
}
if (-not $vsPath) {
    Exit-Build 30 'Visual Studio C++ derleme araçları (MSVC x64) bulunamadı.' 'Visual Studio Build Tools kurulumunda "C++ ile masaüstü geliştirme" iş yükünü seçin (MSVC v143 ve Windows 10/11 SDK dahil).'
}
$link = Get-ChildItem -Path (Join-Path $vsPath 'VC\Tools\MSVC') -Recurse -Filter link.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match 'Hostx64\\x64' } | Select-Object -First 1
if (-not $link) { Exit-Build 31 "MSVC x64 bağlayıcı (link.exe) bulunamadı: $vsPath" 'Build Tools içinde "MSVC v143 - VS 2022 C++ x64/x86 derleme araçları" bileşenini ekleyin.' }
Write-Info "MSVC: $($link.FullName)"

$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$rc = Get-ChildItem -Path (Join-Path $kits 'bin') -Recurse -Filter rc.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\rc\.exe$' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $rc -or -not (Get-ChildItem -Path (Join-Path $kits 'Include\*\um\windows.h') -ErrorAction SilentlyContinue | Select-Object -First 1)) {
    Exit-Build 32 'Windows 10/11 SDK (rc.exe, windows.h) bulunamadı.' 'Visual Studio Installer ile "Windows 11 SDK" veya "Windows 10 SDK" bileşenini kurun.'
}
Write-Info "Windows SDK: $($rc.FullName)"

if (-not (Get-Command node -ErrorAction SilentlyContinue) -or -not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Exit-Build 40 'Node.js / npm bulunamadı.' 'https://nodejs.org adresinden Node.js 22 LTS kurun, sonra yeni bir komut penceresi açın.'
}
$nodeV = Get-Version ((& node -v) -join '')
Write-Info "Node.js: $nodeV, npm: $((& cmd.exe /d /c 'npm -v') -join '')"
$nodeOk = $null -ne $nodeV -and (($nodeV.Major -eq 20 -and $nodeV -ge [version]'20.19.0') -or ($nodeV.Major -eq 22 -and $nodeV -ge [version]'22.12.0') -or $nodeV.Major -ge 23)
if (-not $nodeOk) { Exit-Build 41 "Node.js 20.19+ veya 22.12+ gerekli (bulunan: $nodeV)." 'Node.js 22 LTS kurun.' }

$wv = $null
foreach ($k in 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
    'HKCU:\Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}') {
    $p = Get-ItemProperty -Path $k -Name pv -ErrorAction SilentlyContinue
    if ($p -and $p.pv -and $p.pv -ne '0.0.0.0') { $wv = $p.pv; break }
}
if ($wv) { Write-Info "WebView2 Runtime: $wv" }
else {
    Write-Host 'UYARI: WebView2 Runtime bulunamadı. Derleme yapılır, ancak uygulamayı açmak için WebView2 Runtime gerekir (https://developer.microsoft.com/microsoft-edge/webview2/).' -ForegroundColor Yellow
    Add-Content -Path $Summary -Value 'UYARI: WebView2 Runtime bulunamadı.' -Encoding UTF8
}
Write-Info ''

# Copying over a running executable fails, so stop early with a clear message.
$running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and $_.Path.StartsWith($Dist, [StringComparison]::OrdinalIgnoreCase)
    })
if ($running.Count -gt 0) {
    Exit-Build 15 ("dist klasöründeki RustWard çalışıyor: " + (($running | ForEach-Object { $_.ProcessName }) -join ', ')) 'Açık RustWard pencerelerini kapatıp BUILD-RUSTWARD.cmd dosyasını yeniden çalıştırın.'
}

# Non-destructive read-only isolation check: detect any external RustWard service
# or process on this machine (for example from an earlier workspace or VM test)
# without stopping, modifying or touching it.
$extSvc = Get-Service -Name 'RustWardService' -ErrorAction SilentlyContinue
if ($extSvc) {
    Write-Info ("UYARI (yalıtım denetimi): Bu makinede harici 'RustWardService' Windows hizmeti algılandı (Durum: {0}). Bu derleme hizmete DOKUNMAZ ve üzerine kurulum yapmaz." -f $extSvc.Status)
}
else {
    Write-Info 'Yalıtım denetimi: Bu makinede kurulu RustWardService hizmeti yok (temiz).'
}
$extProc = @(Get-Process -Name 'rustward-service', 'RustWard', 'rustward-desktop', 'RustWard-Onizleme' -ErrorAction SilentlyContinue | Where-Object {
        -not $_.Path -or -not $_.Path.StartsWith($Dist, [StringComparison]::OrdinalIgnoreCase)
    })
if ($extProc.Count -gt 0) {
    $extList = ($extProc | ForEach-Object { "{0}(PID={1})" -f $_.ProcessName, $_.Id }) -join ', '
    Write-Info "UYARI (yalıtım denetimi): Çalışma alanı dışında çalışan RustWard süreci algılandı: $extList. Bu derleme bu süreçlere dokunmaz."
}

# ---------------------------------------------------------------- 2. npm ci
if ((Invoke-Logged 'npm-ci' $App 'npm ci --no-audit --no-fund') -ne 0) {
    Exit-Build 50 'npm ci başarısız oldu.' 'İnternet bağlantısını ve günlükteki npm hatasını kontrol edin.'
}

# ---------------------------------------------------------------- 3. Release
if ((Invoke-Logged 'tauri-build-release' $App 'npx tauri build --no-bundle') -ne 0) {
    Exit-Build 60 'Sürüm (release) derlemesi başarısız oldu.' "Günlük: $Logs\tauri-build-release.log"
}

# ---------------------------------------------------------------- 4. Preview
if (-not $SkipPreview) {
    if ((Invoke-Logged 'tauri-build-preview' $App 'npx tauri build --debug --no-bundle --features gui-subsystem') -ne 0) {
        Exit-Build 61 'Önizleme (debug) derlemesi başarısız oldu.' "Günlük: $Logs\tauri-build-preview.log"
    }
}

# ---------------------------------------------------------------- 5. Service
if ((Invoke-Logged 'cargo-build-service' $Root 'cargo build --release --locked -p rustward-service -p rustward-inventory') -ne 0) {
    Exit-Build 62 'Hizmet (rustward-service) derlemesi başarısız oldu.' "Günlük: $Logs\cargo-build-service.log (rc.exe için Windows SDK gerekir)"
}
$serviceSrc = Join-Path $Root 'target\release\rustward-service.exe'
$inventorySrc = Join-Path $Root 'target\release\rustward-inventory.exe'

# ---------------------------------------------------------------- 6. Verify + copy
$targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $Tauri 'target' }
$builds = @(@{ Kind = 'release'; Src = Join-Path $targetDir 'release\rustward-desktop.exe'; Dst = 'RustWard.exe'; Sub = 2 })
if (-not $SkipPreview) {
    $builds += @{ Kind = 'preview'; Src = Join-Path $targetDir 'debug\rustward-desktop.exe'; Dst = 'RustWard-Onizleme.exe'; Sub = 2 }
}
$builds += @{ Kind = 'service'; Src = $serviceSrc; Dst = 'service\rustward-service.exe'; Sub = 3 }
$builds += @{ Kind = 'inventory'; Src = $inventorySrc; Dst = 'service\rustward-inventory.exe'; Sub = 3 }
New-Item -ItemType Directory -Force -Path (Join-Path $Dist 'service') | Out-Null
New-Item -ItemType Directory -Force -Path $Dist | Out-Null
$dumpbin = Get-ChildItem -Path (Join-Path $vsPath 'VC\Tools\MSVC') -Recurse -Filter dumpbin.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match 'Hostx64\\x64' } | Select-Object -First 1
$commit = 'bilinmiyor'
try { $commit = (& cmd.exe /d /c "git -C `"$Root`" rev-parse --short HEAD 2>nul") -join '' } catch { $null = $_ }
$info = @(
    'RustWard Windows derleme bilgisi'
    "Tarih: $Stamp   Commit: $commit"
    ("Windows: {0} {1} {2}.{3}" -f $cv.ProductName, $cv.DisplayVersion, $cv.CurrentBuild, $cv.UBR)
    ("rustc: " + (($rustcInfo -split "`n")[0]))
    "Node.js: $nodeV   WebView2 Runtime: $wv"
    ''
    'Yönetici onaylı Windows Grup İlkesi uygulama desteği içeren V1.0.0 derlemesi. Tam USB zorlaması için RustWardService hizmeti ve yönetici yetkisi gerekir.'
    ''
)
foreach ($b in $builds) {
    if (-not (Test-Path $b.Src)) { Exit-Build 70 "Derleme çıktısı bulunamadı: $($b.Src)" 'Günlükleri kontrol edin.' }
    $pe = Test-PeX64 $b.Src $b.Sub
    if ($pe -ne 'OK') { Exit-Build 71 "$($b.Src) beklenen Windows x64 dosyası değil: $pe" '' }
    if ($b.Kind -eq 'service' -and -not (Test-MessageTable $b.Src)) {
        Exit-Build 72 'rustward-service.exe içinde Olay Günlüğü ileti tablosu (MESSAGETABLE) yok.' 'Windows SDK rc.exe ile yeniden derleyin; günlükte embed-resource hatasına bakın.'
    }
    $dst = Join-Path $Dist $b.Dst
    try { Copy-Item -LiteralPath $b.Src -Destination $dst -Force -ErrorAction Stop }
    catch { Exit-Build 73 "$dst kopyalanamadı (dosya kullanımda olabilir): $($_.Exception.Message)" 'Açık RustWard pencerelerini kapatıp yeniden çalıştırın.' }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $dst).Hash.ToLowerInvariant()
    $size = (Get-Item -LiteralPath $dst).Length
    $deps = ''
    if ($dumpbin) {
        $deps = ((& $dumpbin.FullName /nologo /dependents $dst) | Where-Object { $_ -match '^\s+\S+\.dll\s*$' } | ForEach-Object { $_.Trim() }) -join ', '
        & $dumpbin.FullName /nologo /dependents $dst | Out-File -FilePath (Join-Path $Logs "$($b.Kind)-dependents.txt") -Encoding UTF8
    }
    $line = "{0}: {1}  boyut {2:N0} bayt  SHA-256 {3}  (kaynak: {4})" -f $b.Kind, $dst, $size, $hash, $b.Src
    Write-Info $line
    $info += $line
    if ($deps) { $info += "  bağımlı DLL'ler: $deps"; Write-Info "  bağımlı DLL'ler: $deps" }
}
$info += ''
$info += 'RustWard.exe          : gerçek uygulama; RustWard Windows hizmetine bağlanır. Hizmet kurulu değilse bunu gösterir.'
$info += 'RustWard-Onizleme.exe : geliştirme önizlemesi; geçici SQLite veritabanı (%TEMP%\rustward-dev-ui), salt okunur aygıt envanteri, etiketli sentetik veri.'
$info += 'service\rustward-service.exe : RustWard Windows hizmeti (Olay Günlüğü ileti tablosu gömülü). Yalnızca MSI ile, yalnızca test sanal makinesinde kurun.'
$info += 'service\rustward-inventory.exe : salt okunur envanter ve politika inceleme aracı.'
$info += 'Taşınabilirlik doğrulanmadı: WebView2 Runtime gerekir; yukarıdaki DLL listesi dışındaki bağımlılıklar denetlenmedi.'
$info | Out-File -FilePath (Join-Path $Dist 'BUILD-INFO.txt') -Encoding UTF8

@(
    '@echo off'
    'rem RustWard - gercek uygulama (RustWard Windows hizmetine baglanir).'
    'rem RustWard - yonetici onayli Windows USB erisim denetimi arayuzu.'
    'start "" "%~dp0RustWard.exe"'
) | Out-File -FilePath (Join-Path $Dist 'START-RUSTWARD.cmd') -Encoding ASCII
if (-not $SkipPreview) {
    @(
        '@echo off'
        'rem RustWard - gelistirme onizlemesi (gecici veritabani, etiketli sentetik veri).'
        'rem RustWard - yonetici onayli Windows USB erisim denetimi arayuzu.'
        'start "" "%~dp0RustWard-Onizleme.exe"'
    ) | Out-File -FilePath (Join-Path $Dist 'START-RUSTWARD-ONIZLEME.cmd') -Encoding ASCII
}

# ---------------------------------------------------------------- 7. Complete MSI
$msiNote = 'MSI: atlandı (-SkipMsi).'
$msiOk = $true
if (-not $SkipMsi) {
    $msiOk = $false
    # Read by packaging\wix\rustward-service.wxs as $(env.TAURI_RUSTWARD_SERVICE_EXE).
    $env:TAURI_RUSTWARD_SERVICE_EXE = $serviceSrc
    $conf = Join-Path $Root 'packaging\tauri.acceptance.conf.json'
    try { $code = Invoke-Logged 'tauri-build-msi' $App "npx tauri build --bundles msi --config `"$conf`"" }
    finally { Remove-Item Env:\TAURI_RUSTWARD_SERVICE_EXE -ErrorAction SilentlyContinue }
    $msi = Get-ChildItem -Path (Join-Path $targetDir 'release\bundle\msi') -Filter *.msi -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($code -eq 0 -and $msi) {
        # Read-only check of the finished package.
        $checks = @()
        try {
            $svc = Get-MsiRow $msi.FullName 'SELECT `Name`, `StartName`, `Arguments`, `StartType` FROM `ServiceInstall`'
            $files = Get-MsiRow $msi.FullName 'SELECT `FileName`, `FileSize` FROM `File`'
            $ctl = Get-MsiRow $msi.FullName 'SELECT `Name`, `Event` FROM `ServiceControl`'
            $reg = Get-MsiRow $msi.FullName 'SELECT `Key`, `Name` FROM `Registry`'
            $hasSvc = @($svc | Where-Object { $_[0] -eq 'RustWardService' -and $_[1] -eq 'LocalSystem' -and $_[2] -eq 'service' }).Count -eq 1
            $hasExe = @($files | Where-Object { $_[0] -like '*rustward-service.exe' }).Count -eq 1
            $hasApp = @($files | Where-Object { $_[0] -like '*.exe' -and $_[0] -notlike '*rustward-service.exe' }).Count -ge 1
            $hasCtl = @($ctl | Where-Object { $_[0] -eq 'RustWardService' }).Count -ge 1
            $hasEvt = @($reg | Where-Object { $_[0] -like '*EventLog\Application\RustWard*' }).Count -ge 1
            $acl = @()
            try { $acl = Get-MsiRow $msi.FullName 'SELECT `SDDLText` FROM `MsiLockPermissionsEx`' } catch { $null = $_ }
            $checks += "ServiceInstall RustWardService/LocalSystem/'service': $hasSvc"
            $checks += "File rustward-service.exe: $hasExe; masaüstü uygulaması: $hasApp"
            $checks += "ServiceControl: $hasCtl; EventLog kaynağı (Registry): $hasEvt"
            $checks += "MsiLockPermissionsEx (veri klasörü ACL): $(@($acl | ForEach-Object { $_[0] }) -join '; ')"
            $msiOk = $hasSvc -and $hasExe -and $hasApp -and $hasCtl -and $hasEvt
        }
        catch { $checks += "MSI tabloları okunamadı: $_" }
        foreach ($c in $checks) { Write-Info "  $c" }
        $inst = Join-Path $Dist 'installer'
        New-Item -ItemType Directory -Force -Path $inst | Out-Null
        Copy-Item -LiteralPath $msi.FullName -Destination $inst -Force
        $mh = (Get-FileHash -Algorithm SHA256 -LiteralPath $msi.FullName).Hash.ToLowerInvariant()
        if ($msiOk) {
            $msiNote = "MSI (TAM: uygulama + Windows hizmeti + Olay Günlüğü kaynağı + WebView2; KURULMADI): $inst\$($msi.Name)  boyut $('{0:N0}' -f $msi.Length) bayt  SHA-256 $mh"
        }
        else {
            $msiNote = "MSI oluşturuldu ancak hizmet bileşeni doğrulanamadı: $inst\$($msi.Name)  SHA-256 $mh"
        }
        Add-Content -Path (Join-Path $Dist 'BUILD-INFO.txt') -Value ($checks + $msiNote) -Encoding UTF8
    }
    else {
        $msiNote = "MSI oluşturulamadı (çıkış kodu $code). EXE dosyaları geçerlidir. Günlük: $Logs\tauri-build-msi.log"
        Add-Content -Path (Join-Path $Dist 'BUILD-INFO.txt') -Value $msiNote -Encoding UTF8
    }
}
Write-Info $msiNote

Write-Host ''
Write-Host 'TAMAMLANDI.' -ForegroundColor Green
Write-Info "Uygulama: $Dist\RustWard.exe  (başlatmak için: $Dist\START-RUSTWARD.cmd)"
if (-not $SkipPreview) { Write-Info "Önizleme: $Dist\RustWard-Onizleme.exe  (başlatmak için: $Dist\START-RUSTWARD-ONIZLEME.cmd)" }
Write-Info "Hizmet: $Dist\service\rustward-service.exe (kurulmadı)"
Write-Info 'Derleme tamamlandı. Bu makinenin Windows ayarlarında değişiklik yapılmadı.'
if (-not $msiOk) {
    Write-Host 'UYARI: EXE dosyaları hazır, ancak tam MSI oluşturulamadı veya doğrulanamadı.' -ForegroundColor Yellow
    exit 3
}
exit 0
