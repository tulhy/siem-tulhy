@echo off
setlocal
pushd "%~dp0"
"%~dp0.venv\Scripts\python.exe" -m scripts.validate_policies
if errorlevel 1 echo Corrija o JSON antes de continuar.
popd
pause
