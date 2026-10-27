"""Install a new, empty Tulhy server for one company unit; starts with Windows.

Run by the bundled runtime in C:\\Program Files\\Tulhy Servidor (see installer_bootstrap.py).
"""
import argparse
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

APP = Path(__file__).resolve().parents[1]
TARGET = APP.parent
RUNTIME = TARGET/'runtime'/'python.exe'
DATA = APP/'data'/'local-lab'
TASK = 'Tulhy Servidor'
RULE = 'SIEM Tulhy - rede local'

LAUNCHER = r'''@echo off
setlocal
rem Started by the "Tulhy Servidor" scheduled task at Windows startup (SYSTEM account).
set "SIEM_SITE_NAME={unit}"
cd /d "%~dp0"
if not exist "data\local-lab" mkdir "data\local-lab"
:loop
"%~dp0..\runtime\python.exe" -m scripts.local_lab --lan >> "data\servidor-tarefa.log" 2>&1
if exist "data\parar-servidor.flag" goto end
rem Unexpected exit: wait 30 seconds and start again.
ping -n 31 127.0.0.1 >nul
goto loop
:end
del /q "data\parar-servidor.flag"
'''

ADMIN_CHECK = '''@echo off
setlocal
cd /d "%~dp0"
net session >nul 2>nul
if errorlevel 1 (
  echo Clique com o botao direito e escolha Executar como administrador.
  pause
  exit /b 1
)
'''

TOOLS = {
    'ABRIR_PAINEL.cmd': '@echo off\nstart "" http://127.0.0.1:8000/\n',
    'VER_SENHA_DO_PAINEL.cmd': ADMIN_CHECK + 'type "data\\local-lab\\admin-token.txt" | clip\n'
        'echo A senha (token) do painel foi copiada. Cole no painel com Ctrl+V.\necho Nao envie essa senha por e-mail ou chat.\npause\n',
    'VER_TOKEN_DE_EXCLUSAO.cmd': ADMIN_CHECK + 'type "data\\local-lab\\exclusion-token.txt" | clip\n'
        'echo O token de exclusao (aba Exclusoes do painel) foi copiado. Cole com Ctrl+V.\necho Ele e diferente da senha do painel. Nao envie por e-mail ou chat.\npause\n',
    'CRIAR_CODIGO_CADASTRO.cmd': ADMIN_CHECK + '"%~dp0..\\runtime\\python.exe" -m scripts.enrollment_code %*\npause\n',
    'LISTAR_CODIGOS_CADASTRO.cmd': ADMIN_CHECK + '"%~dp0..\\runtime\\python.exe" -m scripts.enrollment_code --listar\npause\n',
    'VALIDAR_REGRAS.cmd': ADMIN_CHECK + '"%~dp0..\\runtime\\python.exe" -m scripts.validate_policies\npause\n',
    'EXPORTAR_EVENTOS.cmd': ADMIN_CHECK + '"%~dp0..\\runtime\\python.exe" -m scripts.export_events %*\npause\n',
    'STATUS_SERVIDOR.cmd': '@echo off\nschtasks /Query /TN "' + TASK + '" /FO LIST | findstr /i "Status Estado TaskName Nome"\n'
        'netstat -ano | findstr ":8443" | findstr /i "LISTENING ESCUTANDO" >nul && echo SIEM recebendo agentes na porta 8443. || echo SIEM NAO esta recebendo agentes agora.\npause\n',
    'REINICIAR_SERVIDOR.cmd': ADMIN_CHECK + 'echo stop> "data\\local-lab\\runtime.stop"\n'
        'echo Reiniciando: o SIEM volta em cerca de 1 minuto. Dados preservados.\npause\n',
    'PARAR_SERVIDOR.cmd': ADMIN_CHECK + 'echo stop> "data\\parar-servidor.flag"\necho stop> "data\\local-lab\\runtime.stop"\n'
        'echo SIEM parando. Ele volta sozinho no proximo reinicio do Windows, ou use INICIAR_SERVIDOR.cmd.\npause\n',
    'INICIAR_SERVIDOR.cmd': ADMIN_CHECK + 'schtasks /Run /TN "' + TASK + '"\necho Iniciando: o painel responde em cerca de 1 minuto.\npause\n',
    'DESINSTALAR_SERVIDOR.cmd': ADMIN_CHECK +
        'echo Remove o inicio automatico, a regra de firewall e os atalhos. OS DADOS FICAM em "%~dp0data".\n'
        'set /p "OK=Digite SIM para continuar: "\n'
        'if /i not "%OK%"=="SIM" exit /b 1\n'
        'echo stop> "data\\parar-servidor.flag"\necho stop> "data\\local-lab\\runtime.stop"\n'
        'echo Aguardando o SIEM parar...\nping -n 31 127.0.0.1 >nul\n'
        'schtasks /End /TN "' + TASK + '" >nul 2>nul\nschtasks /Delete /TN "' + TASK + '" /F\n'
        'netsh advfirewall firewall delete rule name="' + RULE + '" >nul\n'
        'del /q "%PUBLIC%\\Desktop\\Tulhy * - Painel.url" "%PUBLIC%\\Desktop\\Tulhy * - Ferramentas.lnk" 2>nul\n'
        'echo Removido. Reinstalar com o mesmo .exe mantem os dados e as regras.\n'
        'echo Para apagar tudo, inclusive os dados, apague a pasta "%~dp0.." como administrador.\npause\n',
}


def task_xml(unit):
    command = str(APP/'iniciar-servidor.cmd')
    return f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Servidor do SIEM Tulhy - unidade {unit}. Inicia com o Windows, antes de qualquer login.</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled><Delay>PT30S</Delay></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>{os.environ.get('ComSpec', r'C:\Windows\System32\cmd.exe')}</Command><Arguments>/c "{command}"</Arguments><WorkingDirectory>{APP}</WorkingDirectory></Exec></Actions>
</Task>
'''


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def protect(path):
    # Only SYSTEM and Administrators: ordinary users cannot delete or change the SIEM.
    run('icacls.exe', path, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F',
        stdout=subprocess.DEVNULL)


def firewall():
    exists = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=' + RULE], capture_output=True)
    if exists.returncode != 0:
        run('netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=' + RULE, 'dir=in', 'action=allow',
            'protocol=TCP', 'localport=8443', 'remoteip=localsubnet', 'profile=private,domain', stdout=subprocess.DEVNULL)


def wait_ready(started, timeout=180):
    info_file = DATA/'server-info.json'
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if info_file.is_file() and info_file.stat().st_mtime >= started - 5:
            info = json.loads(info_file.read_text(encoding='utf-8'))
            context = ssl.create_default_context(cafile=info['certificate'])
            try:
                with urllib.request.urlopen('https://127.0.0.1:8443/health', context=context, timeout=5) as response:
                    if response.status == 200:
                        return info
            except OSError:
                pass
        time.sleep(2)
    raise RuntimeError('O SIEM nao respondeu em 3 minutos. Veja ' + str(APP/'data'/'servidor-tarefa.log'))


def shortcuts(unit):
    desktop = Path(os.environ.get('PUBLIC', r'C:\Users\Public'))/'Desktop'
    (desktop/f'Tulhy {unit} - Painel.url').write_text('[InternetShortcut]\nURL=http://127.0.0.1:8000/\n', encoding='ascii')
    try:
        from win32com.client import Dispatch
        link = Dispatch('WScript.Shell').CreateShortCut(str(desktop/f'Tulhy {unit} - Ferramentas.lnk'))
        link.TargetPath = str(APP)
        link.Save()
    except Exception:
        pass  # the panel shortcut is enough; tools stay in the program folder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unidade', required=True)
    args = parser.parse_args()
    unit = args.unidade.strip()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 -]{0,39}', unit):
        raise ValueError('Nome da unidade invalido (use letras, numeros, espaco ou hifen).')
    print('Protegendo a pasta do programa (somente administradores)...')
    protect(TARGET)
    (APP/'data').mkdir(exist_ok=True)
    (APP/'iniciar-servidor.cmd').write_text(LAUNCHER.format(unit=unit).replace('\n', '\r\n'), encoding='ascii')
    for name, text in TOOLS.items():
        (APP/name).write_text(text.replace('\n', '\r\n'), encoding='ascii')
    print('Liberando a porta 8443 no firewall, somente para a rede local...')
    firewall()
    print('Registrando o inicio automatico com o Windows...')
    with tempfile.TemporaryDirectory() as folder:
        xml = Path(folder)/'tarefa.xml'
        xml.write_text(task_xml(unit), encoding='utf-16')
        run('schtasks.exe', '/Create', '/TN', TASK, '/XML', xml, stdout=subprocess.DEVNULL)
    started = time.time()
    run('schtasks.exe', '/Run', '/TN', TASK, stdout=subprocess.DEVNULL)
    print('Iniciando o SIEM pela primeira vez (pode levar 1 minuto)...')
    info = wait_ready(started)
    shortcuts(unit)
    print(f'\nPRONTO: SIEM da unidade {unit} instalado e rodando.')
    print('- Inicia sozinho sempre que o Windows ligar, mesmo sem ninguem fazer login.')
    print('- Painel: atalho na Area de Trabalho ou http://127.0.0.1:8000 (somente neste computador).')
    print('- Senha do painel: VER_SENHA_DO_PAINEL.cmd (como administrador), em', APP)
    print('- Agentes: CRIAR_CODIGO_CADASTRO.cmd (como administrador) gera o codigo para o instalador do agente.')
    print('- Enderecos para os agentes:', ', '.join([info['server_url'], *info.get('server_urls', [])]))
    print('- Deixe a rede deste computador como PARTICULAR para os agentes conseguirem conectar.')
    print('- Guarde uma copia privada de', DATA/'tls'/'tulhy-ca-key.pem', '(pendrive), nunca em pasta compartilhada.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print('\nERRO:', exc)
        sys.exit(1)
