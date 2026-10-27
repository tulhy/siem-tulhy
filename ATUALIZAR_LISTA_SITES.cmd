@echo off
setlocal
cd /d "%~dp0"
"%~dp0.venv\Scripts\python.exe" -m scripts.import_phishing_domains --openphish
if errorlevel 1 echo Falha na atualizacao. A lista anterior foi preservada; consulte a mensagem acima.
pause
