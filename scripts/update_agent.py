"""Update an installed Tulhy agent service in place. Keeps credentials and queue; restores on failure."""
import ctypes
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.service_manager import SERVICE, global_python, read_identity, service_exists  # noqa: E402


def reachable(urls, cafile):
    context = ssl.create_default_context(cafile=str(cafile))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    working = []
    for url in urls:
        try:
            with opener.open(url+'/health', timeout=10) as response:
                if response.status == 200:
                    working.append(url)
        except (OSError, urllib.error.URLError, ValueError):
            continue
    return working


def stop(win32service, win32serviceutil):
    if win32serviceutil.QueryServiceStatus(SERVICE)[1] != win32service.SERVICE_STOPPED:
        win32serviceutil.StopService(SERVICE)
        win32serviceutil.WaitForServiceStatus(SERVICE, win32service.SERVICE_STOPPED, 90)


def start(win32service, win32serviceutil):
    win32serviceutil.StartService(SERVICE)
    win32serviceutil.WaitForServiceStatus(SERVICE, win32service.SERVICE_RUNNING, 60)


def replace_tree(source, target):
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))


def update(state, install_root):
    import yaml
    import win32service
    import win32serviceutil
    from agent.config.settings import Config  # validates with the NEW agent code from this package
    read_identity(state/'credentials.json')  # installed identity must exist; it is never modified
    endpoints = json.loads((ROOT/'endpoints.json').read_text(encoding='utf-8'))
    current = yaml.safe_load((state/'config.yaml').read_text(encoding='utf-8-sig'))
    current.update(server_url=endpoints['server_url'], server_urls=endpoints['server_urls'])
    config = Config.model_validate(current)
    working = reachable(config.endpoints, ROOT/'server-ca.pem')
    if not working:
        raise RuntimeError('Nenhum endereco do servidor respondeu: ' + ', '.join(config.endpoints)
                           + '. Confira a rede e se o SIEM esta ligado. Nada foi alterado.')
    print('Servidor alcancado em:', ', '.join(working))
    backup = state/'update-backups'/uuid4().hex
    backup.mkdir(parents=True)
    for package in ('agent', 'shared'):
        if (install_root/package).exists():
            shutil.copytree(install_root/package, backup/package)
    for name in ('config.yaml', 'ca.pem'):
        if (state/name).exists():
            shutil.copy2(state/name, backup/name)
    print('Backup criado em:', backup)
    stop(win32service, win32serviceutil)
    try:
        for package in ('agent', 'shared'):
            replace_tree(ROOT/package, install_root/package)
        (state/'config.yaml').write_text(yaml.safe_dump(config.model_dump()), encoding='utf-8')
        shutil.copyfile(ROOT/'server-ca.pem', state/'ca.pem')
        start(win32service, win32serviceutil)
    except BaseException:
        print('Falha ao atualizar; restaurando a versao anterior...')
        for package in ('agent', 'shared'):
            if (backup/package).exists():
                replace_tree(backup/package, install_root/package)
        for name in ('config.yaml', 'ca.pem'):
            if (backup/name).exists():
                shutil.copy2(backup/name, state/name)
        try:
            start(win32service, win32serviceutil)
        except Exception:
            print('O servico nao reiniciou sozinho; execute INICIAR_SERVICO.cmd do pacote original.')
        raise
    print('Agente atualizado e em execucao. Cadastro e fila preservados.')
    print('Confira no painel do servidor, em ate 1 minuto, a versao 1.4.0 desta maquina.')


def main():
    if os.name != 'nt':
        raise RuntimeError('Este atualizador e exclusivo para Windows.')
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError('Clique com o botao direito em ATUALIZAR_AGENTE.cmd e escolha Executar como administrador.')
    if not service_exists():
        raise ValueError('O agente nao esta instalado como servico nesta maquina. Use o pacote individual e INSTALAR_SERVICO.cmd.')
    python = global_python()
    if Path(sys.executable).resolve() != python.resolve():
        # Same interpreter the service uses, where its dependencies are installed.
        subprocess.run([str(python), str(Path(__file__).resolve())], check=True)
        return
    update(Path(os.environ['ProgramData'])/'Tulhy', Path(os.environ['ProgramFiles'])/'Tulhy')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print('ERRO:', exc, file=sys.stderr)
        sys.exit(1)
