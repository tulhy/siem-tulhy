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
echo Primeiro inicie o servidor com INICIAR_REDE.cmd.
pause
exit /b 1
:run
"%SIEM_PYTHON%" -m scripts.enroll_remote
if errorlevel 1 echo Cadastro falhou. Leia o erro acima.
pause
