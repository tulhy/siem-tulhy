@echo off
setlocal
rem Libera a porta 8443 do SIEM somente para a rede local, no perfil de rede Particular.
net session >nul 2>nul
if errorlevel 1 goto admin
netsh advfirewall firewall show rule name="SIEM Tulhy - rede local" >nul 2>nul
if not errorlevel 1 goto exists
netsh advfirewall firewall add rule name="SIEM Tulhy - rede local" dir=in action=allow protocol=TCP localport=8443 remoteip=localsubnet profile=private
if errorlevel 1 goto failed
echo Regra criada: porta 8443, somente rede local, perfil Particular.
goto check
:exists
echo A regra "SIEM Tulhy - rede local" ja existe; nada foi alterado.
:check
echo.
echo Importante: o cabo e o Wi-Fi deste computador precisam estar como rede PARTICULAR
echo (Configuracoes ^> Rede e Internet ^> propriedades da conexao ^> Perfil de rede: Particular).
echo Em rede Publica a regra nao vale.
echo Para remover: netsh advfirewall firewall delete rule name="SIEM Tulhy - rede local"
pause
exit /b 0
:admin
echo Clique com o botao direito neste arquivo e escolha Executar como administrador.
pause
exit /b 1
:failed
echo Nao foi possivel criar a regra. Nada foi alterado.
pause
exit /b 1
