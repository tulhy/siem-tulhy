@echo off
setlocal
cd /d "%~dp0.."
if exist ".venv\Scripts\python.exe" (
    set "SIEM_PYTHON=%CD%\.venv\Scripts\python.exe"
    goto run
)
if exist "..\..\work\venv\Scripts\python.exe" (
    set "SIEM_PYTHON=%CD%\..\..\work\venv\Scripts\python.exe"
    goto run
)
echo Execute primeiro INICIAR_LOCAL.cmd para preparar o ambiente e depois pare com Ctrl+C.
pause
exit /b 1
:run
"%SIEM_PYTHON%" -m scripts.background %1
if errorlevel 1 echo Houve uma falha. Leia a mensagem acima. Nenhuma janela precisa permanecer aberta apos iniciar com sucesso.
pause
