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
    5. Verifies both files (PE32+ x64 Windows GUI executable, size, SHA-256)
       and copies them to dist\RustWard.exe and dist\RustWard-Onizleme.exe,
       with START-*.cmd launchers and BUILD-INFO.txt.
    6. Optionally (default on, -SkipMsi to skip) builds the UI-only MSI with
       npx tauri build --bundles msi. A failure here does not fail the build.
       The MSI is NOT installed.

  It does NOT change Windows: no service installation, no registry or Group
  Policy change, no device or driver change. USB enforcement stays disabled
  (ACTIVATION_ENABLED = false); the application cannot block USB devices.

  Logs: build-logs\<timestamp>\ (kept). Exit code 0 = executables built and
  verified; anything else = failure (see the Turkish message and the logs).
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

function Test-PeGuiX64([string]$Path) {
    # Reads the PE header: MZ, PE\0\0, machine AMD64 (0x8664), PE32+ (0x20B),
    # subsystem 2 = Windows GUI.
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 1024 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { return 'MZ başlığı yok' }
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($bytes[$pe] -ne 0x50 -or $bytes[$pe + 1] -ne 0x45 -or $bytes[$pe + 2] -ne 0 -or $bytes[$pe + 3] -ne 0) { return 'PE imzası yok' }
    $machine = [BitConverter]::ToUInt16($bytes, $pe + 4)
    $opt = $pe + 24
    $magic = [BitConverter]::ToUInt16($bytes, $opt)
    $subsystem = [BitConverter]::ToUInt16($bytes, $opt + 68)
    if ($machine -ne 0x8664) { return ('makine türü 0x{0:X4} (x64 değil)' -f $machine) }
    if ($magic -ne 0x20B) { return 'PE32+ değil' }
    if ($subsystem -ne 2) { return "alt sistem $subsystem (Windows GUI = 2 değil)" }
    'OK'
}

Write-Info "RustWard Windows derlemesi - $Stamp"
Write-Info "Depo: $Root"
Write-Info 'Bu betik Windows ayarlarını değiştirmez; hizmet kurmaz; USB koruması etkinleştirilmez.'
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

# ---------------------------------------------------------------- 5. Verify + copy
$targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $Tauri 'target' }
$builds = @(@{ Kind = 'release'; Src = Join-Path $targetDir 'release\rustward-desktop.exe'; Dst = 'RustWard.exe' })
if (-not $SkipPreview) {
    $builds += @{ Kind = 'preview'; Src = Join-Path $targetDir 'debug\rustward-desktop.exe'; Dst = 'RustWard-Onizleme.exe' }
}
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
    'USB KORUMASI ETKİN DEĞİLDİR. Bu uygulama USB aygıtlarını engellemez (ACTIVATION_ENABLED = false).'
    ''
)
foreach ($b in $builds) {
    if (-not (Test-Path $b.Src)) { Exit-Build 70 "Derleme çıktısı bulunamadı: $($b.Src)" 'Günlükleri kontrol edin.' }
    $pe = Test-PeGuiX64 $b.Src
    if ($pe -ne 'OK') { Exit-Build 71 "$($b.Src) geçerli bir Windows x64 GUI uygulaması değil: $pe" '' }
    $dst = Join-Path $Dist $b.Dst
    Copy-Item -LiteralPath $b.Src -Destination $dst -Force
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
$info += 'Taşınabilirlik doğrulanmadı: WebView2 Runtime gerekir; yukarıdaki DLL listesi dışındaki bağımlılıklar denetlenmedi.'
$info | Out-File -FilePath (Join-Path $Dist 'BUILD-INFO.txt') -Encoding UTF8

@(
    '@echo off'
    'rem RustWard - gercek uygulama (RustWard Windows hizmetine baglanir).'
    'rem USB korumasi etkin degildir.'
    'start "" "%~dp0RustWard.exe"'
) | Out-File -FilePath (Join-Path $Dist 'START-RUSTWARD.cmd') -Encoding ASCII
if (-not $SkipPreview) {
    @(
        '@echo off'
        'rem RustWard - gelistirme onizlemesi (gecici veritabani, etiketli sentetik veri).'
        'rem USB korumasi etkin degildir.'
        'start "" "%~dp0RustWard-Onizleme.exe"'
    ) | Out-File -FilePath (Join-Path $Dist 'START-RUSTWARD-ONIZLEME.cmd') -Encoding ASCII
}

# ---------------------------------------------------------------- 6. MSI (secondary)
$msiNote = 'MSI: atlandı (-SkipMsi).'
if (-not $SkipMsi) {
    $code = Invoke-Logged 'tauri-build-msi' $App 'npx tauri build --bundles msi'
    $msi = Get-ChildItem -Path (Join-Path $targetDir 'release\bundle\msi') -Filter *.msi -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($code -eq 0 -and $msi) {
        $inst = Join-Path $Dist 'installer'
        New-Item -ItemType Directory -Force -Path $inst | Out-Null
        Copy-Item -LiteralPath $msi.FullName -Destination $inst -Force
        $mh = (Get-FileHash -Algorithm SHA256 -LiteralPath $msi.FullName).Hash.ToLowerInvariant()
        $msiNote = "MSI (yalnızca arayüz, hizmet içermez, KURULMADI): $inst\$($msi.Name)  SHA-256 $mh"
    }
    else {
        $msiNote = "MSI oluşturulamadı (çıkış kodu $code). EXE dosyaları geçerlidir. Günlük: $Logs\tauri-build-msi.log"
    }
    Add-Content -Path (Join-Path $Dist 'BUILD-INFO.txt') -Value $msiNote -Encoding UTF8
}
Write-Info $msiNote

Write-Host ''
Write-Host 'TAMAMLANDI.' -ForegroundColor Green
Write-Info "Uygulama: $Dist\RustWard.exe  (başlatmak için: $Dist\START-RUSTWARD.cmd)"
if (-not $SkipPreview) { Write-Info "Önizleme: $Dist\RustWard-Onizleme.exe  (başlatmak için: $Dist\START-RUSTWARD-ONIZLEME.cmd)" }
Write-Info 'USB koruması henüz etkinleştirilmemiştir. Windows ayarlarında değişiklik yapılmadı.'
exit 0
