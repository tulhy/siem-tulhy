@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 goto missing
py -3 "%~dp0scripts\service_manager.py" Diagnose
if errorlevel 1 echo Falha: leia o erro acima ou execute DIAGNOSTICAR_AGENTE.cmd.
pause
exit /b
:missing
echo Instale Python 3.12+ para todos os usuarios com Python Launcher.
pause
exit /b 1
