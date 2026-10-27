import json
import socket
import ssl
import threading
import time
import zipfile
from ipaddress import ip_address
from uuid import uuid4
import httpx
import pytest
import uvicorn
import yaml
from cryptography import x509
from agent.config.settings import Config
from agent.transport.client import Transport
from scripts.dev_certificate import ensure_ca, generate, issue_server, server_names
from tests.conftest import ADMIN

CLOSE = {'Connection':'close'}  # let the test server stop between certificate phases


def test_ca_is_created_once_and_server_certificate_reissued_only_when_needed(tmp_path):
    ca, ca_key = ensure_ca(tmp_path)
    original = ca.read_bytes()
    assert ensure_ca(tmp_path) == (ca, ca_key) and ca.read_bytes() == original
    cert, _ = issue_server(tmp_path, ca, ca_key, ['PC-SERVIDOR'], ['192.168.1.65'])
    first = cert.read_bytes()
    dns, ips, _ = server_names(cert)
    assert {'pc-servidor','localhost'} <= dns and {'192.168.1.65','127.0.0.1'} <= ips
    # Same names: kept. New Wi-Fi address: reissued by the same CA, agents keep trusting it.
    issue_server(tmp_path, ca, ca_key, ['PC-SERVIDOR'], ['192.168.1.65'])
    assert cert.read_bytes() == first
    issue_server(tmp_path, ca, ca_key, ['PC-SERVIDOR'], ['192.168.1.65','192.168.1.80'])
    assert cert.read_bytes() != first and '192.168.1.80' in server_names(cert)[1]
    assert ca.read_bytes() == original
    context = ssl.create_default_context(cafile=str(ca))
    leaf = x509.load_pem_x509_certificate(cert.read_bytes())
    assert leaf.issuer == x509.load_pem_x509_certificate(original).subject and context.cert_store_stats()['x509_ca'] == 1


def test_incomplete_ca_is_never_replaced(tmp_path):
    ca, ca_key = ensure_ca(tmp_path)
    ca_key.unlink()
    with pytest.raises(ValueError, match='CA incompleta'):
        ensure_ca(tmp_path)
    assert ca.exists()


def test_transport_fails_over_only_when_nothing_was_delivered():
    calls = []
    def endpoint(request):
        calls.append(request.url.host)
        if request.url.host == 'cabo.invalid':
            raise httpx.ConnectError('unreachable')
        return httpx.Response(200, json={'ok':True})
    config = Config(server_url='https://cabo.invalid:8443', server_urls=['https://192.168.1.80:8443'])
    t = Transport(config, uuid4(), 't'*40, httpx.Client(transport=httpx.MockTransport(endpoint)))
    assert t.post('/api/v1/agents/heartbeat', {}) == {'ok':True}
    assert calls == ['cabo.invalid','192.168.1.80'] and t.active == 1
    # The working address is kept for the next request.
    t.post('/api/v1/agents/heartbeat', {})
    assert calls[-1] == '192.168.1.80' and len(calls) == 3
    # A server answer (even an error) means delivery happened: no failover, no duplicate send.
    def failing(request):
        calls.append(request.url.host)
        return httpx.Response(503)
    t.client = httpx.Client(transport=httpx.MockTransport(failing))
    with pytest.raises(httpx.HTTPStatusError):
        t.post('/api/v1/agents/heartbeat', {})
    assert calls[-1] == '192.168.1.80' and len(calls) == 4


def test_all_addresses_down_raises_connect_error():
    def offline(request):
        raise httpx.ConnectError('offline')
    config = Config(server_url='https://a.invalid:8443', server_urls=['https://b.invalid:8443'])
    t = Transport(config, uuid4(), 't'*40, httpx.Client(transport=httpx.MockTransport(offline)))
    with pytest.raises(httpx.ConnectError):
        t.post('/api/v1/agents/heartbeat', {})


def serve(tmp_path, cert, key, port, name):
    from server.main import create_app
    from server.settings import Settings
    app = create_app(Settings(database_url='sqlite:///'+str(tmp_path/'migration.db'), admin_token=ADMIN), background=False)
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=port, ssl_certfile=str(cert),
                                           ssl_keyfile=str(key), log_level='warning', access_log=False))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True, name=name)
    thread.start()
    deadline = time.monotonic()+10
    while not server.started and time.monotonic() < deadline:
        time.sleep(.05)
    assert server.started
    def stop():
        server.should_exit = True
        thread.join(10)
        sock.close()
        assert not thread.is_alive()
    return stop


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def test_agent_update_survives_server_certificate_migration(tmp_path, monkeypatch):
    old_cert, old_key = generate(tmp_path/'old')  # current self-signed server certificate
    ca, ca_key = ensure_ca(tmp_path/'tls')
    bundle = tmp_path/'bundle.pem'
    bundle.write_bytes(old_cert.read_bytes()+ca.read_bytes())
    port, closed = free_port(), free_port()
    # Primary address unreachable (e.g. the server is on Wi-Fi now); fallback works.
    config = Config(server_url=f'https://127.0.0.1:{closed}', server_urls=[f'https://localhost:{port}'])
    monkeypatch.setenv('SIEM_CA_BUNDLE', str(bundle))
    updated = Transport(config, uuid4(), 't'*40)
    monkeypatch.setenv('SIEM_CA_BUNDLE', str(old_cert))
    legacy = Transport(Config(server_url=f'https://localhost:{port}'), uuid4(), 't'*40)
    stop = serve(tmp_path, old_cert, old_key, port, 'old-certificate')
    try:
        # Before the server restarts: both still work with the old certificate.
        assert updated.send('/health', b'', CLOSE).status_code in (200, 405)
        assert updated.active == 1
        assert legacy.send('/health', b'', CLOSE).status_code in (200, 405)
    finally:
        stop()
    new_cert, new_key = issue_server(tmp_path/'tls', ca, ca_key, ['localhost'], [])
    stop = serve(tmp_path, new_cert, new_key, port, 'ca-certificate')
    try:
        # After the restart: the updated agent trusts the CA; an agent without the update cannot connect.
        assert updated.send('/health', b'', CLOSE).status_code in (200, 405)
        with pytest.raises(httpx.ConnectError):
            legacy.send('/health', b'', CLOSE)
    finally:
        stop()
        updated.close()
        legacy.close()


def test_enrollment_package_carries_fallback_addresses(tmp_path):
    from scripts.enroll_remote import build_package
    ca, _ = ensure_ca(tmp_path/'tls')
    credentials = {'agent_id':str(uuid4()),'agent_token':'synthetic-test-'+'x'*40,'hostname':'PC-WIFI'}
    target = tmp_path/'PC-WIFI.zip'
    build_package(target, credentials, 'https://PC-SERVIDOR:8443', ca,
                  server_urls=['https://192.168.1.65:8443','https://192.168.1.80:8443'])
    with zipfile.ZipFile(target) as archive:
        config = yaml.safe_load(archive.read('config.yaml'))
        assert config['server_url'] == 'https://PC-SERVIDOR:8443'
        assert config['server_urls'] == ['https://192.168.1.65:8443','https://192.168.1.80:8443']
        assert archive.read('server-ca.pem') == ca.read_bytes()
        assert not any(b'PRIVATE KEY' in archive.read(n) for n in archive.namelist())


def test_enrollment_registers_through_first_reachable_address():
    from scripts.enroll_remote import reachable_server
    def endpoint(request):
        if request.url.host == 'pc-servidor':
            raise httpx.ConnectError('name not resolved on itself')
        return httpx.Response(200, json={'status':'ok'})
    info = {'server_url':'https://PC-SERVIDOR:8443','server_urls':['https://192.168.1.65:8443']}
    with httpx.Client(transport=httpx.MockTransport(endpoint)) as client:
        assert reachable_server(client, info) == 'https://192.168.1.65:8443'


def test_server_addresses_include_every_lan_ip(tmp_path, monkeypatch):
    from server.detection import network_policy
    (tmp_path/'data/local-lab').mkdir(parents=True)
    (tmp_path/'data/local-lab/server-info.json').write_text(json.dumps({
        'server_url':'https://PC-SERVIDOR:8443','server_urls':[],'server_ips':['192.168.1.65','192.168.1.80'],'lan':True}))
    (tmp_path/'rules/default_rules').mkdir(parents=True)
    monkeypatch.setattr(network_policy, 'ROOT', tmp_path)
    settings = type('S', (), {'rules_dir':str(tmp_path/'rules/default_rules')})()
    assert network_policy.server_addresses(settings) == {ip_address('192.168.1.65'), ip_address('192.168.1.80')}


def test_endpoint_order_prefers_computer_name():
    from scripts.server_endpoints import endpoints
    assert endpoints(8443, 'PC-SERVIDOR', ['192.168.1.65']) == ['https://PC-SERVIDOR:8443','https://192.168.1.65:8443']
    assert endpoints(8443, None, ['192.168.1.65']) == ['https://192.168.1.65:8443']
    with pytest.raises(ValueError):
        endpoints(8443, None, [])
