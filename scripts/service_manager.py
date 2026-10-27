"""Local Windows service installer. No PowerShell or execution-policy changes."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
SERVICE = 'TulhyAgent'


def read_identity(path):
    value = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    UUID(value['agent_id'])
    if not isinstance(value['agent_token'], str) or len(value['agent_token']) < 32:
        raise ValueError('Credencial invalida. Solicite o pacote individual original.')
    return value


def check_identity(incoming, state):
    existing = Path(state)/'credentials.json'
    if existing.exists() and read_identity(existing)['agent_id'] != incoming['agent_id']:
        raise ValueError('Ja existe OUTRO cadastro nesta maquina. Nada foi substituido. '
                         'Use o pacote original instalado; nao apague ProgramData\\Tulhy. '
                         'Execute DIAGNOSTICAR_AGENTE.cmd e informe os IDs ao administrador.')


def run(*args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def service_exists():
    result = subprocess.run(['sc.exe','query',SERVICE], capture_output=True)
    if result.returncode not in (0,1060):
        raise RuntimeError('Nao foi possivel consultar o servico. Execute como administrador.')
    return result.returncode == 0


def global_python():
    import winreg
    candidates = [Path(sys.executable)]
    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Python\PythonCore', 0, winreg.KEY_READ | view) as key:
                for index in range(winreg.QueryInfoKey(key)[0]):
                    version = winreg.EnumKey(key,index)
                    try:
                        with winreg.OpenKey(key, version+r'\InstallPath') as install:
                            candidates.append(Path(winreg.QueryValueEx(install,'')[0])/'python.exe')
                    except FileNotFoundError:
                        continue
        except FileNotFoundError:
            continue
    for candidate in candidates:
        if not candidate.is_file() or not candidate.resolve().is_relative_to(Path(os.environ['ProgramFiles']).resolve()):
            continue
        probe = subprocess.run([str(candidate),'-c','import sys; sys.exit(0 if sys.version_info >= (3,12) and sys.prefix == sys.base_prefix else 1)'],capture_output=True)
        if probe.returncode == 0:
            return candidate
    raise ValueError('Instale Python 3.12+ para TODOS os usuarios em Program Files, com pip e Python Launcher. Depois execute novamente.')


def diagnose(state):
    print('Python:',sys.version.split()[0], sys.executable)
    print('Administrador:',bool(ctypes.windll.shell32.IsUserAnAdmin()))
    print('Servico instalado:',service_exists())
    if service_exists():
        subprocess.run(['sc.exe','query',SERVICE],check=False)
        subprocess.run(['sc.exe','qc',SERVICE],check=False)
    for title, path in [('Pacote',ROOT/'credentials.json'),('Instalado',state/'credentials.json')]:
        if path.exists():
            identity=read_identity(path)
            print(title,'agent_id:',identity['agent_id'])
    print('Log do agente:',state/'data/agent.log')
    print('Tokens e senhas nao sao exibidos. IDs diferentes indicam pacotes de cadastros diferentes.')
    config_path=(state/'config.yaml') if (state/'config.yaml').exists() else ROOT/'config.yaml'
    ca=(state/'ca.pem') if (state/'ca.pem').exists() else ROOT/'server-ca.pem'
    try:
        import yaml
    except ImportError:
        print('Diagnostico HTTPS indisponivel neste Python: dependencias ainda nao instaladas.')
        return
    if not config_path.exists() or not ca.exists():
        print('Config ou certificado ausente. Extraia todo o pacote.')
        return
    import ssl
    import urllib.request
    import urllib.error
    settings=yaml.safe_load(config_path.read_text(encoding='utf-8-sig'))
    urls=list(dict.fromkeys([settings['server_url'],*(settings.get('server_urls') or [])]))
    context=ssl.create_default_context(cafile=str(ca))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
    working=0
    for url in urls:
        try:
            with opener.open(url.rstrip('/')+'/health',timeout=10) as response:
                print('Servidor',url,'- HTTPS e certificado OK; status:',response.status)
                working+=1
        except (OSError,urllib.error.URLError,ValueError) as exc:
            print('Servidor',url,'- falha HTTPS:',type(exc).__name__)
    if not working:
        print('Nenhum endereco respondeu: confira rede (cabo/Wi-Fi), firewall do servidor, relogio e certificado.')
    elif working<len(urls):
        print('Pelo menos um endereco funciona; o agente usa automaticamente o que responder.')
    print('Esse teste nao confirma autenticacao nem coleta; confira heartbeat e agent.log.')


def install(state, install_root, prepared=False):
    credentials=read_identity(ROOT/'credentials.json')
    check_identity(credentials,state)  # Refuse other identity BEFORE any mutation.
    for name in ('config.yaml','server-ca.pem','requirements-agent.txt'):
        if not (ROOT/name).is_file():
            raise ValueError('Pacote incompleto: falta '+name+'. Extraia TODO o ZIP antes de instalar.')
    python=global_python()
    if Path(sys.executable).resolve() != python.resolve():
        run(python,Path(__file__).resolve(),'Install')
        return
    if not prepared:
        print('Pare INICIAR_AGENTE.cmd com Ctrl+C antes de continuar.')
        if input('O agente manual esta parado? Digite SIM: ').strip().upper() != 'SIM':
            raise ValueError('Instalacao cancelada. Nenhum dado alterado.')
        if service_exists():
            # Release pythonservice/DLL handles before pip or post-install copies.
            run(python,'-c',
                "import win32service,win32serviceutil as s; "
                "name='TulhyAgent'; "
                "state=s.QueryServiceStatus(name)[1]; "
                "s.StopService(name) if state not in (win32service.SERVICE_STOPPED,win32service.SERVICE_STOP_PENDING) else None; "
                "s.WaitForServiceStatus(name,win32service.SERVICE_STOPPED,90)")
        run(python,'-m','pip','install','-r',ROOT/'requirements-agent.txt')
        # Reload Python after pip so newly installed pywin32 .pth files take effect.
        postinstall=Path(sys.prefix)/'Scripts/pywin32_postinstall.py'
        if not postinstall.is_file():
            raise FileNotFoundError('pywin32_postinstall.py nao encontrado na instalacao global do Python.')
        run(python,postinstall,'-install')
        run(python,Path(__file__).resolve(),'Install','--prepared')
        return
    sys.path.insert(0,str(ROOT))
    import yaml
    import win32service
    import win32serviceutil
    from agent.config.settings import Config
    from scripts.prepare_service import migrate_queue
    import ssl
    config=Config.model_validate(yaml.safe_load((ROOT/'config.yaml').read_text(encoding='utf-8-sig')))
    if credentials.get('hostname') and credentials['hostname'] != config.agent_name:
        raise ValueError('Nome do config.yaml difere do cadastro. Use o pacote original, sem editar o nome.')
    ssl.create_default_context(cafile=str(ROOT/'server-ca.pem'))
    existed=service_exists()
    if existed and win32serviceutil.QueryServiceStatus(SERVICE)[1] != win32service.SERVICE_STOPPED:
        win32serviceutil.StopService(SERVICE)
        win32serviceutil.WaitForServiceStatus(SERVICE,win32service.SERVICE_STOPPED,90)
    for directory in (install_root,state):
        directory.mkdir(parents=True,exist_ok=True)
        run('icacls.exe',directory,'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F',stdout=subprocess.DEVNULL)
    migrate_queue(ROOT/'config.yaml',state)
    for package in ('agent','shared'):
        shutil.copytree(ROOT/package,install_root/package,dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    import site
    (Path(site.getsitepackages()[0])/'tulhy-service.pth').write_text(str(install_root)+'\n',encoding='utf-8')
    config.data_dir=str(state/'data')
    (state/'config.yaml').write_text(yaml.safe_dump(config.model_dump()),encoding='utf-8')
    (state/'credentials.json').write_text(json.dumps(credentials),encoding='utf-8')
    shutil.copyfile(ROOT/'server-ca.pem',state/'ca.pem')
    kwargs=dict(pythonClassString='agent.windows_service.TulhyService',serviceName=SERVICE,
                displayName='SIEM Tulhy Agent',startType=win32service.SERVICE_AUTO_START,
                description='Coleta defensiva de metadados. Sem controle remoto.')
    if existed:
        win32serviceutil.ChangeServiceConfig(**kwargs)
    else:
        win32serviceutil.InstallService(**kwargs)
    run('sc.exe','failure',SERVICE,'reset=','86400','actions=','restart/60000/restart/120000/restart/300000')
    run('sc.exe','failureflag',SERVICE,'1')
    win32serviceutil.StartService(SERVICE)
    win32serviceutil.WaitForServiceStatus(SERVICE,win32service.SERVICE_RUNNING,60)
    print('Running: servico iniciado, inicializacao automatica. Pode fechar a janela.')
    print('Confirme a comunicacao no dashboard apos 30 segundos. Running nao confirma conexao com o servidor.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['Install','Start','Stop','Status','Uninstall','Diagnose'])
    parser.add_argument('--prepared',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args()
    action=args.action
    if os.name != 'nt':
        raise RuntimeError('Este instalador e exclusivo para Windows.')
    state=Path(os.environ['ProgramData'])/'Tulhy'
    if action=='Diagnose':
        diagnose(state)
        return
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError('Clique com o botao direito no arquivo CMD e escolha Executar como administrador.')
    if action=='Install':
        install(state,Path(os.environ['ProgramFiles'])/'Tulhy',args.prepared)
        return
    if action=='Status':
        diagnose(state)
        return
    if not service_exists():
        raise ValueError('Servico nao instalado nesta maquina.')
    python=global_python()
    if Path(sys.executable).resolve() != python.resolve():
        run(python,Path(__file__).resolve(),action)
        return
    import win32service
    import win32serviceutil
    current=win32serviceutil.QueryServiceStatus(SERVICE)[1]
    if action=='Uninstall':
        if current != win32service.SERVICE_STOPPED:
            win32serviceutil.StopService(SERVICE)
            win32serviceutil.WaitForServiceStatus(SERVICE,win32service.SERVICE_STOPPED,90)
        win32serviceutil.RemoveService(SERVICE)
        print('Servico removido. Configuracao, credenciais e fila preservadas em',state)
    elif action=='Start':
        if current != win32service.SERVICE_RUNNING:
            win32serviceutil.StartService(SERVICE)
            win32serviceutil.WaitForServiceStatus(SERVICE,win32service.SERVICE_RUNNING,60)
        print('Running')
    elif action=='Stop':
        if current != win32service.SERVICE_STOPPED:
            win32serviceutil.StopService(SERVICE)
            win32serviceutil.WaitForServiceStatus(SERVICE,win32service.SERVICE_STOPPED,90)
        print('Stopped; fila preservada.')


if __name__=='__main__':
    try:
        main()
    except (OSError,ValueError,RuntimeError,subprocess.CalledProcessError) as exc:
        # No credentials in exception values from our validation; never dump config.
        print('ERRO:',exc,file=sys.stderr)
        sys.exit(1)
