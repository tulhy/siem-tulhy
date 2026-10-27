"""Install this machine's agent from an enrollment code: no file to carry, starts with Windows.

Run by the bundled runtime in C:\\Program Files\\Tulhy (see installer_bootstrap.py).
"""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import unicodedata
import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from shared import enrollment  # noqa: E402

HOSTNAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}')


def clean_name(text):
    """Panel name from free text: accents removed, spaces and symbols become hyphens."""
    ascii_text = unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode('ascii')
    name = re.sub(r'-{2,}', '-', re.sub(r'[^A-Za-z0-9_-]', '-', ascii_text.strip())).strip('-_')[:64]
    return name if HOSTNAME.fullmatch(name) else ''


def machine_name():
    return clean_name(socket.gethostname().split('.')[0])


def panel_name(suggested, ask=input):
    """The person at the machine chooses how it appears in the panel; Enter keeps the suggestion."""
    while True:
        typed = ask(f'Nome desta maquina no painel [{suggested}]: ' if suggested else 'Nome desta maquina no painel: ').strip()
        name = clean_name(typed or suggested)
        if name:
            if typed and name != typed:
                print('Nome ajustado para:', name)
            return name
        print('Use letras, numeros, hifen ou sublinhado (ate 64 caracteres).')


def fetch_ca(value):
    """CA from the first server address whose certificate matches the code's fingerprint."""
    unverified = ssl.create_default_context()
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE  # only to READ the CA; it is trusted by fingerprint below
    for url in enrollment.endpoints(value):
        try:
            with httpx.Client(verify=unverified, timeout=10, trust_env=False) as client:
                response = client.get(url + '/api/v1/ca')
        except httpx.HTTPError:
            continue
        if response.status_code == 200 and enrollment.ca_fingerprint(response.text) == value['f']:
            return response.text
        if response.status_code == 200:
            raise RuntimeError('O servidor em ' + url + ' NAO corresponde ao codigo (certificado diferente). Nada foi instalado.')
    raise RuntimeError('Nenhum endereco do servidor respondeu: ' + ', '.join(enrollment.endpoints(value))
                       + '. Confira se o SIEM esta ligado e se esta maquina esta na mesma rede.')


def register(value, ca_pem, hostname):
    context = ssl.create_default_context(cadata=ca_pem)
    last = None
    with httpx.Client(verify=context, timeout=15, trust_env=False) as client:
        for url in enrollment.endpoints(value):
            try:
                response = client.post(url + '/api/v1/agents/enroll', json={'secret':value['s'], 'hostname':hostname})
            except httpx.HTTPError as exc:
                last = exc
                continue
            if response.status_code == 401:
                raise RuntimeError('Codigo recusado: vencido, revogado ou ja usado no limite de maquinas. Gere outro no servidor.')
            response.raise_for_status()
            return response.json()
    raise RuntimeError('Falha ao cadastrar: ' + type(last).__name__)


def write_package(value, ca_pem, credentials):
    from agent.config.settings import Config
    urls = enrollment.endpoints(value)
    config = Config(server_url=urls[0], server_urls=urls[1:], agent_name=credentials['hostname'], data_dir='data')
    (ROOT/'config.yaml').write_text(yaml.safe_dump(config.model_dump()), encoding='utf-8')
    (ROOT/'server-ca.pem').write_text(ca_pem, encoding='ascii')
    (ROOT/'credentials.json').write_text(json.dumps(credentials), encoding='utf-8')


def install_service():
    from scripts import service_manager
    postinstall = Path(sys.prefix)/'Scripts/pywin32_postinstall.py'
    subprocess.run([sys.executable, str(postinstall), '-install', '-quiet'], check=True, stdout=subprocess.DEVNULL)
    service_manager.install(Path(os.environ['ProgramData'])/'Tulhy', Path(os.environ['ProgramFiles'])/'Tulhy', prepared=True)


TOOLS = {
    'STATUS_AGENTE.cmd': 'Status', 'DIAGNOSTICAR_AGENTE.cmd': 'Diagnose', 'PARAR_AGENTE.cmd': 'Stop',
    'INICIAR_AGENTE.cmd': 'Start', 'DESINSTALAR_AGENTE.cmd': 'Uninstall',
}


def write_tools():
    target = ROOT.parent  # C:\Program Files\Tulhy
    for name, action in TOOLS.items():
        text = ('@echo off\r\nnet session >nul 2>nul\r\nif errorlevel 1 (\r\n  echo Clique com o botao direito e escolha Executar como administrador.\r\n'
                '  pause\r\n  exit /b 1\r\n)\r\n"%~dp0runtime\\python.exe" "%~dp0pacote\\scripts\\service_manager.py" ' + action + '\r\npause\r\n')
        (target/name).write_text(text, encoding='ascii')


def reuse_identity(state):
    """Reinstall after an uninstall: same agent identity and queue, no new code needed."""
    for name, packaged in (('credentials.json', 'credentials.json'), ('config.yaml', 'config.yaml'), ('ca.pem', 'server-ca.pem')):
        (ROOT/packaged).write_bytes((state/name).read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--codigo')
    parser.add_argument('--nome', help='Nome no painel (sem perguntar)')
    args = parser.parse_args()
    from scripts.service_manager import service_exists
    if service_exists():
        raise RuntimeError('Ja existe um agente Tulhy instalado nesta maquina. Nada foi alterado.')
    state = Path(os.environ['ProgramData'])/'Tulhy'
    try:
        if all((state/name).is_file() for name in ('credentials.json', 'config.yaml', 'ca.pem')):
            print('Cadastro anterior encontrado nesta maquina: reinstalando com a mesma identidade.')
            reuse_identity(state)
        else:
            hostname = clean_name(args.nome) if args.nome else panel_name(machine_name())
            if not hostname:
                raise ValueError('Nome invalido: use letras, numeros, hifen ou sublinhado.')
            print('Esta maquina vai aparecer no painel como:', hostname)
            code = args.codigo or input('Cole o codigo de cadastro e aperte Enter: ')
            value = enrollment.decode(code)
            print('Conferindo o servidor...')
            ca_pem = fetch_ca(value)
            print('Servidor confirmado. Cadastrando esta maquina...')
            credentials = register(value, ca_pem, hostname)
            write_package(value, ca_pem, credentials)
        print('Instalando o servico (inicia sozinho com o Windows)...')
        install_service()
    finally:
        # The credential now lives only in C:\ProgramData\Tulhy (administrators and SYSTEM).
        (ROOT/'credentials.json').unlink(missing_ok=True)
    write_tools()
    print('\nPronto: agente instalado e em execucao. Em ate 1 minuto esta maquina aparece no painel.')
    print('Ferramentas (status, diagnostico, desinstalar) em', ROOT.parent)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, httpx.HTTPError, subprocess.CalledProcessError) as exc:
        print('\nERRO:', exc)
        sys.exit(1)
