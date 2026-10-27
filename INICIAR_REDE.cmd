@echo off
setlocal
cd /d "%~dp0"
echo Pare o INICIAR_LOCAL antes de continuar, usando Ctrl+C na janela dele.
echo Este modo recebe agentes na rede local pelo cabo e pelo Wi-Fi ao mesmo tempo;
echo o dashboard continua somente neste computador.
set "SIEM_LAN=1"
call "%~dp0INICIAR_LOCAL.cmd"
