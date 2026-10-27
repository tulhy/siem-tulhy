@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0.venv\Scripts\python.exe" (
    set "SIEM_PYTHON=%~dp0.venv\Scripts\python.exe"
    goto run
)
if exist "%~dp0..\..\work\venv\Scripts\python.exe" (
    set "SIEM_PYTHON=%~dp0..\..\work\venv\Scripts\python.exe"
    goto run
)
echo Ambiente do Tulhy nao encontrado nesta pasta.
pause
exit /b 1
:run
"%SIEM_PYTHON%" -m scripts.export_events %*
if errorlevel 1 echo Nao foi possivel exportar. Leia o erro acima.
pause
