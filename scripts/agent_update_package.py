"""Build one update ZIP for every installed agent: new code, server addresses and CA. No credentials."""
import argparse
import re
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from urllib.parse import urlparse
import zipfile
from cryptography import x509
from scripts.dev_certificate import ensure_ca
from scripts.enroll_remote import package_sources
from scripts.local_lab import ROOT, protect_directory
from scripts.server_endpoints import local_hostname, private_ipv4s, endpoints

FILES = ('requirements-agent.txt', 'agent/collectors/pdf_library.zip', 'scripts/__init__.py',
         'scripts/service_manager.py', 'scripts/prepare_service.py', 'scripts/update_agent.py')

COMMAND = r'''@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 goto missing
py -3 "%~dp0scripts\update_agent.py"
if errorlevel 1 echo Falha: leia a mensagem acima. Nada foi alterado ou a versao anterior foi restaurada.
pause
exit /b
:missing
echo Instale Python 3.12+ para todos os usuarios com Python Launcher.
pause
exit /b 1
'''

README = '''ATUALIZACAO DOS AGENTES TULHY - cabo e Wi-Fi
Um unico pacote para todas as maquinas que ja tem o agente instalado como servico.
Nao contem credenciais: cada maquina mantem o proprio cadastro e a fila.

O QUE MUDA NO AGENTE
- Procura o servidor pelo nome {name} e, se nao responder, pelos IPs conhecidos:
  {urls}
  Funciona com o servidor no cabo, no Wi-Fi ou nos dois.
- Passa a confiar na nova autoridade de certificados do SIEM (valida por 10 anos),
  mantendo o certificado atual ate o servidor ser reiniciado.

COMO APLICAR (em cada maquina monitorada)
1. Extraia o ZIP em qualquer pasta.
2. Clique com o botao direito em ATUALIZAR_AGENTE.cmd > Executar como administrador.
   - Testa a conexao com o servidor antes de alterar qualquer coisa.
   - Faz backup em C:\\ProgramData\\Tulhy\\update-backups\\ e restaura sozinho se falhar.
3. Confira no painel do servidor: a maquina deve aparecer online com versao 1.4.0.

Depois que TODAS as maquinas estiverem atualizadas, reinicie o servidor
(PARAR_SIEM.cmd e INICIAR_SEGUNDO_PLANO.cmd). Maquinas nao atualizadas param de
conectar quando o servidor for reiniciado.
'''


def trust_bundle(tls):
    """New CA plus the certificate the running server still uses, so updated agents work before and after restart."""
    ca, _ = ensure_ca(tls)
    parts = [ca.read_bytes()]
    current = tls/'localhost.pem'
    if current.exists():
        cert = x509.load_pem_x509_certificate(current.read_bytes())
        if cert.issuer == cert.subject and cert.not_valid_after_utc > datetime.now(timezone.utc):
            parts.append(current.read_bytes())
    return b''.join(part if part.endswith(b'\n') else part+b'\n' for part in parts)


def server_endpoints(info):
    port = urlparse(info['server_url']).port or 8443
    if info.get('server_ips') is not None:
        return [info['server_url'], *info.get('server_urls', [])], info['server_ips']
    # Server not restarted since the update: discover now and keep the address agents use today.
    previous = urlparse(info['server_url']).hostname
    ips = private_ipv4s()
    if previous and previous[0].isdigit() and previous not in ips:
        ips.append(previous)
    return endpoints(port, local_hostname(), ips), ips


def build(data, target):
    if not (data/'server-info.json').is_file():
        raise ValueError('O servidor ainda nao foi iniciado em modo rede. Inicie com INICIAR_REDE.cmd antes.')
    info = json.loads((data/'server-info.json').read_text(encoding='utf-8'))
    if not info.get('lan'):
        raise ValueError('O servidor nao esta em modo rede. Inicie com INICIAR_REDE.cmd antes.')
    urls, ips = server_endpoints(info)
    bundle = trust_bundle(data/'tls')
    package_sources(data/'tls/tulhy-ca.pem')
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name('.'+target.name+'.creating')
    temporary.unlink(missing_ok=True)
    try:
        with zipfile.ZipFile(temporary, 'x', zipfile.ZIP_DEFLATED) as archive:
            for package in ('agent', 'shared'):
                for source in sorted((ROOT/package).rglob('*.py')):
                    if '__pycache__' not in source.parts:
                        archive.write(source, source.relative_to(ROOT).as_posix())
            for name in FILES:
                archive.write(ROOT/name, name)
            archive.writestr('server-ca.pem', bundle)
            archive.writestr('endpoints.json', json.dumps({'server_url':urls[0], 'server_urls':urls[1:]}, indent=2))
            archive.writestr('ATUALIZAR_AGENTE.cmd', COMMAND.replace('\n', '\r\n'))
            archive.writestr('LEIA-ME.txt', README.format(name=urlparse(urls[0]).hostname,
                urls='\n  '.join(urls)).replace('\n', '\r\n'))
        with zipfile.ZipFile(temporary) as archive:
            names = archive.namelist()
            if archive.testzip() is not None or not {'scripts/update_agent.py', 'agent/main.py', 'server-ca.pem'} <= set(names):
                raise RuntimeError('Pacote de atualizacao incompleto')
            if any(re.search(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----', archive.read(n)) for n in names) or 'credentials.json' in names:
                raise RuntimeError('Pacote conteria segredo; nada foi criado')
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return target, urls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', default=str(ROOT/'data/local-lab'))
    parser.add_argument('--output')
    args = parser.parse_args()
    data = Path(args.data_dir).resolve()
    protect_directory(data/'enrollments')
    target = Path(args.output) if args.output else data/'enrollments/ATUALIZAR-AGENTES.zip'
    target, urls = build(data, target)
    print('Pacote de atualizacao dos agentes criado:')
    print(' ', target)
    print('Enderecos do servidor gravados no pacote:', ', '.join(urls))
    print('Aplique em cada maquina monitorada (ATUALIZAR_AGENTE.cmd como administrador) e so depois reinicie o servidor.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as exc:
        print('ERRO:', exc)
        raise SystemExit(1)
