"""Local Windows/Linux lab launcher. Never expose this loopback setup to the Internet."""
import argparse
from datetime import datetime, timezone, timedelta
import json
from ipaddress import ip_address
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import time

import httpx
import yaml
from cryptography import x509
from agent.config.settings import Config
from agent.normalizers import Normalizer
from agent.transport.client import Transport
from scripts.dev_certificate import generate, ensure_ca, issue_server
from scripts.server_endpoints import local_hostname, private_ipv4s, endpoints
from scripts.synthetic_events import synthetic

ROOT = Path(__file__).resolve().parents[1]

# SIEM Tulhy demo: simple tokens. Change them by editing data/local-lab/admin-token.txt and exclusion-token.txt.
DEMO_ADMIN_TOKEN = '123'
DEMO_EXCLUSION_TOKEN = '456'


def protect_directory(path):
    path.mkdir(parents=True, exist_ok=True)
    if os.name == 'nt':
        import win32api
        import win32security
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(),win32security.TOKEN_QUERY)
        try:
            sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token,win32security.TokenUser)[0])
        finally:
            token.Close()
        subprocess.run(['icacls.exe', str(path), '/inheritance:r', '/grant:r',
                        '*'+sid+':(OI)(CI)F', '*S-1-5-18:(OI)(CI)F',
                        '*S-1-5-32-544:(OI)(CI)F'], check=True, stdout=subprocess.DEVNULL)
    else:
        path.chmod(0o700)

def save_private(path, text):
    with open(path, 'x', encoding='utf-8') as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)

def available_port(port, host='127.0.0.1'):
    with socket.socket() as probe:
        probe.bind((host, port))

def wait_ready(client, url, process, log_path):
    deadline = time.monotonic()+30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f'Server exited; inspect {log_path}')
        try:
            response = client.get(url+'/health')
            if response.status_code == 200:
                return
        except (httpx.ConnectError, httpx.TimeoutException):
            time.sleep(0.2)
            continue
        time.sleep(0.2)
    raise RuntimeError(f'Server startup timeout; inspect {log_path}')

def stop_child(process):
    if process.poll() is not None:
        return
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=10)

def disable_local_registration(client, api_url, data, admin_token):
    """Disable only the launcher's own identity; never remove history or queue."""
    from uuid import UUID
    path = data/'agent-credentials.json'
    if not path.exists():
        return
    credentials = json.loads(path.read_text(encoding='utf-8'))
    agent_id = str(UUID(credentials['agent_id']))
    response = client.patch(api_url+'/api/v1/agents/'+agent_id,
        json={'enabled':False}, headers={'Authorization':'Bearer '+admin_token})
    if response.status_code != 404:
        response.raise_for_status()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', default=str(ROOT/'data/local-lab'))
    parser.add_argument('--http-port', type=int, default=8000)
    parser.add_argument('--https-port', type=int, default=8443)
    parser.add_argument('--lan-ip', default=os.getenv('SIEM_LAN_IP'), help='Also include this private IPv4 address; implies --lan')
    parser.add_argument('--lan', action='store_true', default=os.getenv('SIEM_LAN')=='1',
                        help='Receive agents on every private network adapter (cable and Wi-Fi); HTTP dashboard remains loopback-only')
    parser.add_argument('--background-ready',help=argparse.SUPPRESS)
    parser.add_argument('--check', action='store_true', help='Exercise synthetic end-to-end flow, then stop; do not collect real machine telemetry')
    parser.add_argument('--collect-host', action='store_true', help='Opt in to collecting the server host; default is server only')
    args = parser.parse_args()
    if args.http_port == args.https_port:
        raise ValueError('HTTP and HTTPS ports must differ')
    if args.lan_ip:
        address = ip_address(args.lan_ip)
        if address.version != 4 or not address.is_private or address.is_loopback or address.is_unspecified or address.is_link_local or address.is_multicast:
            raise ValueError('Use the private IPv4 address of this computer, shown by ipconfig')
    lan = args.lan or bool(args.lan_ip)
    # LAN mode listens on all adapters so cable and Wi-Fi work at the same time.
    # Exposure is limited by the Windows firewall rule (private profile, local subnet).
    listen_address = '0.0.0.0' if lan else '127.0.0.1'
    available_port(args.http_port)
    available_port(args.https_port, listen_address)
    data = Path(args.data_dir).resolve()
    protect_directory(data)
    stop_file = data/'runtime.stop'
    stop_file.unlink(missing_ok=True)
    ready_file = Path(args.background_ready) if args.background_ready else None
    token_path = data/'admin-token.txt'
    if not token_path.exists():
        save_private(token_path, DEMO_ADMIN_TOKEN)
    token = token_path.read_text(encoding='utf-8').strip()
    if not token:
        raise ValueError('Invalid local administrator token')
    # Separate secret for the panel's Exclusions tab; distinct from the administrator token.
    exclusion_path = data/'exclusion-token.txt'
    if not exclusion_path.exists():
        save_private(exclusion_path, DEMO_EXCLUSION_TOKEN)
    exclusion_token = exclusion_path.read_text(encoding='utf-8').strip()
    if not exclusion_token or exclusion_token == token:
        raise ValueError('Invalid exclusion token in '+str(exclusion_path))
    cert, key = data/'tls/localhost.pem', data/'tls/localhost-key.pem'
    if lan:
        hostname_dns = local_hostname()
        lan_ips = sorted(set(private_ipv4s()) | ({args.lan_ip} if args.lan_ip else set()), key=ip_address)
        trust, ca_key = ensure_ca(data/'tls')
        names = [hostname_dns, hostname_dns+'.local'] if hostname_dns else []
        cert, key = issue_server(data/'tls', trust, ca_key, names, lan_ips)
        agent_urls = endpoints(args.https_port, hostname_dns, lan_ips)
        api_url = f'https://127.0.0.1:{args.https_port}'
    else:
        renew = not cert.exists() or not key.exists()
        if not renew:
            existing = x509.load_pem_x509_certificate(cert.read_bytes())
            renew = existing.not_valid_after_utc < datetime.now(timezone.utc)+timedelta(days=1)
            # A CA-issued LAN certificate cannot be its own trust anchor in loopback mode.
            renew = renew or existing.issuer != existing.subject
        if renew:
            cert, key = generate(data/'tls')
        trust = cert
        api_url = f'https://localhost:{args.https_port}'
    ui_url = f'http://127.0.0.1:{args.http_port}'
    environment = dict(os.environ)
    environment.update(SIEM_ADMIN_TOKEN=token, SIEM_EXCLUSION_TOKEN=exclusion_token,
                       DATABASE_URL='sqlite:///'+(data/'server.db').as_posix(),
                       PYTHONUNBUFFERED='1', SIEM_STOP_FILE=str(stop_file),
                       SIEM_CA_FILE=str(trust) if lan else '')
    children, logs = [], []

    def start(command, env, filename):
        log_path = data/filename
        # Bound launcher logs across repeated starts. Application agent.log rotates independently.
        if log_path.exists() and log_path.stat().st_size > 5_000_000:
            log_path.replace(log_path.with_suffix('.previous.log'))
        stream = open(log_path, 'a', encoding='utf-8')
        logs.append(stream)
        process = subprocess.Popen([sys.executable, *command], cwd=ROOT, env=env, stdout=stream,
            stderr=subprocess.STDOUT, creationflags=(subprocess.CREATE_NO_WINDOW if ready_file else subprocess.CREATE_NEW_PROCESS_GROUP) if os.name=='nt' else 0)
        children.append(process)
        return process, log_path

    try:
        tls_process, tls_log = start(['-m','scripts.run_server','--host',listen_address,'--port',str(args.https_port),
            '--ssl-certfile',str(cert),'--ssl-keyfile',str(key),'--no-access-log'],environment,'server-https.log')
        context = ssl.create_default_context(cafile=str(trust))
        with httpx.Client(verify=context, timeout=3, trust_env=False) as client:
            wait_ready(client, api_url, tls_process, tls_log)
            http_process, http_log = start(['-m','scripts.run_server','--host','127.0.0.1','--port',
                str(args.http_port),'--no-access-log'],environment,'server-http.log')
            wait_ready(client, ui_url, http_process, http_log)
            info = ({'server_url':agent_urls[0],'server_urls':agent_urls[1:],'server_ips':lan_ips,'lan':True}
                    if lan else {'server_url':api_url,'lan':False})
            info['certificate'] = str(trust)
            (data/'server-info.json').write_text(json.dumps(info),encoding='utf-8')
            if not args.check and not args.collect_host:
                disable_local_registration(client, api_url, data, token)
                if ready_file:
                    ready_file.write_text(json.dumps({'pid':os.getpid(),'dashboard':ui_url,'server_url':api_url}),encoding='utf-8')
                print(f'Servidor iniciado: {ui_url}. Coleta da host desativada; historico e fila preservados.',flush=True)
                print(f'Token administrativo: {token_path}',flush=True)
                print(f'Token de exclusao (aba Exclusoes): {exclusion_path}',flush=True)
                while all(p.poll() is None for p in children) and not stop_file.exists():
                    time.sleep(1)
                if not stop_file.exists():
                    raise RuntimeError(f'Um componente encerrou. Consulte os logs em {data}')
                return
            credentials_path = data/('check-credentials.json' if args.check else 'agent-credentials.json')
            hostname = 'TULHY-SYNTHETIC-CHECK' if args.check else socket.gethostname()
            if credentials_path.exists():
                credentials = json.loads(credentials_path.read_text(encoding='utf-8'))
                if credentials['hostname'] != hostname:
                    raise ValueError('Stored identity belongs to another machine; use a different data directory')
            else:
                response = client.post(api_url+'/api/v1/agents/register',json={'hostname':hostname},
                    headers={'Authorization':'Bearer '+token})
                response.raise_for_status()
                credentials = response.json()
                save_private(credentials_path,json.dumps(credentials))
            if args.collect_host and not args.check:
                response = client.patch(api_url+'/api/v1/agents/'+credentials['agent_id'],
                    json={'enabled':True}, headers={'Authorization':'Bearer '+token})
                response.raise_for_status()
            config_path = data/'agent-config.yaml'
            if not config_path.exists():
                config = Config(server_url=api_url,agent_name=hostname,data_dir=str(data/'agent'))
                save_private(config_path,yaml.safe_dump(config.model_dump()))
            if args.check:
                transport = Transport(Config(server_url=api_url),credentials['agent_id'],credentials['agent_token'],client)
                events = synthetic(Normalizer(credentials['agent_id'],hostname))
                ack = transport.post('/api/v1/events/batch',{'events':[e.model_dump(mode='json') for e in events]})
                if set(ack['accepted_ids']) != {str(e.event_id) for e in events}:
                    raise RuntimeError('Invalid acknowledgment in local check')
                transport.post('/api/v1/agents/heartbeat',{'hostname':hostname,'os':'synthetic','version':'1.0.0','pending':0})
                deadline = time.monotonic()+15
                while time.monotonic() < deadline:
                    response = client.get(api_url+'/api/v1/alerts',headers={'Authorization':'Bearer '+token},
                                          params={'agent_id':credentials['agent_id']})
                    response.raise_for_status()
                    found = {a['rule_id'] for a in response.json()}
                    if {'AUTH_FAILURE_BURST','TEMP_THEN_NETWORK','FILE_CHANGE'} <= found:
                        print('CHECK OK: HTTPS, registration, batch, heartbeat, detection and HTTP dashboard.')
                        if ready_file:
                            ready_file.write_text(json.dumps({'pid':os.getpid(),'dashboard':ui_url,'mode':'synthetic-check'}),encoding='utf-8')
                            while not stop_file.exists() and all(p.poll() is None for p in children):
                                time.sleep(.25)
                        return
                    time.sleep(0.2)
                raise RuntimeError('Detection did not produce expected synthetic alerts')
            agent_environment = dict(environment)
            agent_environment.pop('SIEM_ADMIN_TOKEN',None)
            agent_environment.pop('SIEM_EXCLUSION_TOKEN',None)
            agent_environment.pop('DATABASE_URL',None)
            agent_environment.update(SIEM_AGENT_ID=credentials['agent_id'],SIEM_AGENT_TOKEN=credentials['agent_token'],
                SIEM_AGENT_CONFIG=str(config_path),SIEM_SERVER_URL=api_url,SIEM_CA_BUNDLE=str(trust))
            start(['-m','agent.main'],agent_environment,'agent-console.log')
            if ready_file:
                ready_file.write_text(json.dumps({'pid':os.getpid(),'dashboard':ui_url,'server_url':api_url}),encoding='utf-8')
            print(f'Tulhy local started. Dashboard: {ui_url}/',flush=True)
            print(f'Agent: {hostname}; transport: {api_url}',flush=True)
            print(f'Copy dashboard token from: {token_path}',flush=True)
            print(f'Logs and persistent data: {data}',flush=True)
            print('Use PARAR_SIEM.cmd to stop background operation.' if ready_file else 'Keep this terminal open. Ctrl+C stops this lab; queued telemetry is preserved.',flush=True)
            while all(p.poll() is None for p in children):
                if stop_file.exists():
                    print('Local stop requested; preserving data.',flush=True)
                    return
                time.sleep(1)
            raise RuntimeError(f'A component exited unexpectedly. Inspect logs in {data}')
    except KeyboardInterrupt:
        print('\nStopping local lab; preserving persistent data.',flush=True)
    finally:
        stop_file.write_text('stop',encoding='utf-8')
        for child in reversed(children):
            stop_child(child)
        if ready_file:
            ready_file.unlink(missing_ok=True)
        for stream in logs:
            stream.close()

if __name__ == '__main__':
    main()
