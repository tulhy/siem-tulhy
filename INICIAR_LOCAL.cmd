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
where py >nul 2>nul
if errorlevel 1 goto missing
py -3 -c "import sys; assert sys.version_info >= (3,12), 'Python 3.12+ required'"
if errorlevel 1 goto missing
py -3 -m venv .venv
if errorlevel 1 goto failed
set "SIEM_PYTHON=%~dp0.venv\Scripts\python.exe"
"%SIEM_PYTHON%" -m pip install -r requirements-dev.txt
if errorlevel 1 goto failed
:run
"%SIEM_PYTHON%" -m scripts.local_lab
if errorlevel 1 goto failed
echo SIEM encerrado. Os dados foram preservados.
pause
exit /b 0
:missing
echo Instale Python 3.12 ou superior com o Python Launcher e tente novamente.
pause
exit /b 1
:failed
echo Nao foi possivel iniciar. Leia o erro acima e os logs em data\local-lab.
pause
exit /b 1
