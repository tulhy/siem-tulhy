"""Prepare a private agent enrollment for LAN, VPN or a public HTTPS endpoint."""
import argparse
import json
from urllib.parse import urlparse
from pathlib import Path
import re
import ssl
import os
import zipfile
import httpx
import yaml
from agent.config.settings import Config
from scripts.local_lab import ROOT, protect_directory

AGENT_START = r'''@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto run
where py >nul 2>nul
if errorlevel 1 goto missing
py -3 -c "import sys; assert sys.version_info >= (3,12), 'Python 3.12+ required'"
if errorlevel 1 goto missing
py -3 -m venv .venv
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install -r requirements-agent.txt
if errorlevel 1 goto failed
:run
".venv\Scripts\python.exe" -m scripts.remote_agent
if errorlevel 1 goto failed
pause
exit /b 0
:missing
echo Instale Python 3.12 ou superior com o Python Launcher e tente novamente.
pause
exit /b 1
:failed
echo Houve uma falha. Leia o erro acima ou data\agent.log.
pause
exit /b 1
'''

SERVICE_ACTIONS = {'INSTALAR_SERVICO':'Install', 'DIAGNOSTICAR_AGENTE':'Diagnose', 'INICIAR_SERVICO':'Start',
                   'PARAR_SERVICO':'Stop', 'STATUS_SERVICO':'Status', 'DESINSTALAR_SERVICO':'Uninstall'}

def service_commands():
    commands = {name+'.cmd': '@echo off\r\nsetlocal\r\ncd /d "%~dp0"\r\nwhere py >nul 2>nul\r\nif errorlevel 1 goto missing\r\npy -3 "%~dp0scripts\\service_manager.py" '+action+'\r\nif errorlevel 1 echo Falha: leia o erro acima ou execute DIAGNOSTICAR_AGENTE.cmd.\r\npause\r\nexit /b\r\n:missing\r\necho Instale Python 3.12+ para todos os usuarios com Python Launcher.\r\npause\r\nexit /b 1\r\n'
            for name, action in SERVICE_ACTIONS.items()}
    install = commands['INSTALAR_SERVICO.cmd']
    install = install.replace('if errorlevel 1 echo Falha:', 'if errorlevel 1 goto failed\r\n'
        'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\\enable_network_audit.ps1"\r\n'
        'if errorlevel 1 goto failed\r\n'
        'echo Servico instalado e auditoria configurada.\r\npause\r\nexit /b 0\r\n:failed\r\necho Falha:')
    commands['INSTALAR_SERVICO.cmd'] = install
    return commands


PACKAGE_FILES = ('agent/collectors/pdf_library.zip','scripts/enable_network_audit.ps1','requirements-agent.txt','scripts/__init__.py','scripts/remote_agent.py',
                 'scripts/prepare_service.py','scripts/service_manager.py')

def package_sources(certificate):
    sources = [ROOT/name for name in PACKAGE_FILES] + [Path(certificate)]
    for package in ('agent','shared'):
        sources.extend(source for source in sorted((ROOT/package).rglob('*.py'))
                       if '__pycache__' not in source.parts)
    sources.extend(ROOT/name for name in ('agent/main.py','agent/windows_service.py','shared/events.py','agent/collectors/downloads.py','agent/collectors/link_worker.py','agent/collectors/download_locations.py'))
    missing = [str(path) for path in sources if not path.is_file()]
    if missing:
        raise FileNotFoundError('Projeto incompleto. Restaure o projeto antes de cadastrar: ' + ', '.join(missing))
    with zipfile.ZipFile(ROOT/'agent/collectors/pdf_library.zip') as library:
        if library.testzip() is not None or 'pypdf/__init__.py' not in library.namelist():
            raise ValueError('Biblioteca PDF invalida; nenhum cadastro criado')
    return sources

def build_package(target, credentials, server_url, certificate, profile='local', server_urls=()):
    package_sources(certificate)  # Never create a partial ZIP if the source is incomplete.
    config = Config(server_url=server_url,server_urls=list(server_urls),agent_name=credentials['hostname'],data_dir='data',
        connection_profile=profile,file_inventory_interval=900 if profile=='remote' else 300,
        send_idle_interval=600 if profile=='remote' else 300, send_batch_interval=2)
    target = Path(target)
    if target.exists():raise FileExistsError('Pacote ja existe; credenciais existentes nao serao substituidas.')
    temporary = target.with_name('.' + target.name + '.creating')
    if temporary.exists():
        temporary.unlink()  # Our own incomplete staging artifact, never a credential package.
    try:
      with zipfile.ZipFile(temporary,'x',zipfile.ZIP_DEFLATED) as archive:
        for package in ('agent','shared'):
            for source in sorted((ROOT/package).rglob('*.py')):
                if '__pycache__' not in source.parts:
                    archive.write(source,source.relative_to(ROOT).as_posix())
        for source in PACKAGE_FILES:
            archive.write(ROOT/source,source)
        archive.write(certificate,'server-ca.pem')
        archive.writestr('credentials.json',json.dumps(credentials))
        archive.writestr('config.yaml',yaml.safe_dump(config.model_dump()))
        archive.writestr('INICIAR_AGENTE.cmd',AGENT_START.replace('\n','\r\n'))
        for name, content in service_commands().items():
            archive.writestr(name, content)
        archive.writestr('LEIA-ME.txt',
            'Pacote individual e privado. Nao reutilize em outra maquina.\n'
            'Instale Python 3.12+ para TODOS os usuarios (Program Files), com Python Launcher.\n'
            'Extraia tudo. Se o agente antigo estiver aberto, pare com Ctrl+C e espere encerrar.\n'
            'Clique com o botao direito em INSTALAR_SERVICO.cmd e Executar como administrador.\n'
            'Confirme Running. Pode fechar o terminal: o servico inicia automaticamente com o Windows.\n'
            'Use STATUS_SERVICO.cmd, PARAR_SERVICO.cmd, INICIAR_SERVICO.cmd e DESINSTALAR_SERVICO.cmd como administrador.\n'
            'INICIAR_AGENTE.cmd e somente para execucao manual; nao execute junto com o servico.\n'
            'Configuracao e fila do servico: C:\\ProgramData\\Tulhy. Desinstalar preserva esses dados.\n'
            'Os comandos CMD usam Python diretamente; nao exigem liberar scripts PowerShell.\n'
            'Se ocorrer erro, execute DIAGNOSTICAR_AGENTE.cmd como administrador. Nao compartilhe credentials.json.\n'
            'Este agente envia para '+server_url+'. Nao e necessario instalar o servidor neste computador.\n'
            'Perfil '+profile+': inventario de arquivos a cada '+str(config.file_inventory_interval)+' segundos apos terminar o ciclo; heartbeat continua a cada 30 segundos.\n'
            'Se a Internet cair, a fila local persiste e sera reenviada dentro dos limites de armazenamento.\n'
            'O arquivo credentials.json contem somente a credencial deste agente. Nao compartilhe o ZIP publicamente.\n'
            'Se o certificado do servidor for renovado ou seu IP mudar, solicite ao administrador a CA/endereco atualizados.\n')
      with zipfile.ZipFile(temporary) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Falha na verificacao do ZIP do agente')
        required = {'credentials.json','config.yaml','server-ca.pem','INSTALAR_SERVICO.cmd',
                    'scripts/service_manager.py','requirements-agent.txt','agent/collectors/pdf_library.zip','agent/collectors/download_locations.py'}
        if not required.issubset(archive.namelist()):
            raise RuntimeError('ZIP do agente incompleto')
      os.replace(temporary,target)
    except BaseException:
      temporary.unlink(missing_ok=True)
      raise
    target.chmod(0o600)

def reachable_server(client, info):
    """First address of this server that answers; the computer name may not resolve on itself."""
    port = urlparse(info['server_url']).port or 443
    for url in dict.fromkeys([info['server_url'], *info.get('server_urls', []), f'https://127.0.0.1:{port}']):
        try:
            if client.get(url+'/health').status_code == 200:
                return url
        except httpx.HTTPError:
            continue
    raise RuntimeError('Servidor SIEM nao respondeu. Inicie o servidor (INICIAR_SEGUNDO_PLANO.cmd) e tente novamente.')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name')
    parser.add_argument('--data-dir',default=str(ROOT/'data/local-lab'))
    parser.add_argument('--internet',action='store_true',help='Create remote profile; requires reachable HTTPS address or VPN')
    parser.add_argument('--public-url',help='HTTPS origin reachable by the remote machine')
    parser.add_argument('--public-ca',type=Path,help='Optional trusted CA for a private VPN endpoint; default public CA roots')
    args = parser.parse_args()
    name = args.name or input('Nome para identificar o outro computador (exemplo PC-ESCRITORIO): ').strip()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',name):
        raise ValueError('Use somente letras, numeros, hifen ou sublinhado, ate 64 caracteres')
    data = Path(args.data_dir).resolve()
    info = json.loads((data/'server-info.json').read_text(encoding='utf-8'))
    if not info['lan'] and not args.internet:
        raise ValueError('Inicie primeiro INICIAR_REDE.cmd no computador servidor')
    output = data/'enrollments'
    protect_directory(output)
    target = output/(name+'.zip')
    if target.exists():
        try:
            with zipfile.ZipFile(target) as existing:
                complete = existing.testzip() is None and {'credentials.json','config.yaml','server-ca.pem'}.issubset(existing.namelist())
        except zipfile.BadZipFile:
            complete = False
        reason = ('Ja existe um pacote completo com esse nome. Use esse ZIP para essa maquina ou escolha outro nome.'
                  if complete else
                  'Existe um ZIP incompleto com esse nome, criado por uma tentativa anterior. Renomeie-o para .bak e exclua o cadastro incompleto no painel antes de tentar novamente.')
        raise FileExistsError(reason)
    token = (data/'admin-token.txt').read_text(encoding='utf-8').strip()
    if len(token)<32 or any(ch.isspace() for ch in token):raise ValueError('Token administrativo invalido; confira somente o arquivo local, sem compartilha-lo.')
    certificate = Path(info['certificate'])
    package_sources(certificate)  # Preflight before issuing a server credential.
    package_url,package_ca,package_urls=info['server_url'],certificate,info.get('server_urls',[])
    if args.internet:
        import certifi
        package_url=Config(server_url=args.public_url or input('Endereco HTTPS acessivel pela outra rede (exemplo https://siem.suaempresa.com): ').strip()).server_url
        package_urls=[]
        package_ca=args.public_ca or Path(certifi.where())
        package_sources(package_ca)
        public_context=ssl.create_default_context(cafile=str(package_ca))
        # Probe without any administrator or agent credential before registering.
        with httpx.Client(verify=public_context,timeout=15,trust_env=False,follow_redirects=False) as public_client:
            health=public_client.get(package_url+'/health')
            health.raise_for_status()
            if health.json().get('status')!='ok':raise RuntimeError('Endpoint remoto indisponivel; nenhum cadastro criado.')
    context = ssl.create_default_context(cafile=str(certificate))
    with httpx.Client(verify=context,timeout=15,trust_env=False) as client:
        server = reachable_server(client, info)
        response = client.post(server+'/api/v1/agents/register',json={'hostname':name},
                               headers={'Authorization':'Bearer '+token})
        response.raise_for_status()
        credentials = response.json()
        try:
            build_package(target,credentials,package_url,package_ca,profile='remote' if args.internet else 'local',
                          server_urls=package_urls)
        except BaseException:
            cleanup = client.request('DELETE',server+'/api/v1/agents/'+credentials['agent_id'],
                json={'confirm_name':credentials['hostname']},headers={'Authorization':'Bearer '+token})
            if cleanup.status_code != 200:
                raise RuntimeError('Falha ao montar o ZIP e ao remover o cadastro incompleto; exclua-o no painel')
            raise
    print(f'Pacote criado: {target}')
    print('Transfira esse ZIP por um meio privado para o computador correspondente, extraia tudo e execute INSTALAR_SERVICO.cmd como administrador.')
    print('Nao envie admin-token.txt nem localhost-key.pem para a outra maquina.')

if __name__ == '__main__':
    main()
