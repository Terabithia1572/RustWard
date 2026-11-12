@echo off
if "%RUSTWARD_VMX_PATH%"=="" (
  echo Set RUSTWARD_VMX_PATH to the isolated test VM .vmx file before running this helper.
  exit /b 1
)
vmrun -T ws start "%RUSTWARD_VMX_PATH%"
