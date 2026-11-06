@echo off
rem RustWard - Windows masaustu uygulamasini derler (Tauri 2, MSVC).
rem Cift tiklayin veya bir komut penceresinde calistirin. Yonetici yetkisi gerekmez.
rem Hicbir sey kurulmaz; Windows ayarlari degismez; USB korumasi etkinlestirilmez.
rem Cikti: dist\RustWard.exe ve dist\RustWard-Onizleme.exe   Gunlukler: build-logs\
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\Build-RustWard.ps1" %*
set "RW_EXIT=%ERRORLEVEL%"
echo.
if not "%RW_EXIT%"=="0" (
  echo DERLEME BASARISIZ ^(cikis kodu %RW_EXIT%^). Ayrintilar icin build-logs klasorune bakin.
) else (
  echo Derleme tamamlandi. Uygulamayi acmak icin: dist\START-RUSTWARD-ONIZLEME.cmd veya dist\START-RUSTWARD.cmd
)
pause
exit /b %RW_EXIT%
