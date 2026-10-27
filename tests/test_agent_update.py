import json
import os
import shutil
import zipfile
from pathlib import Path
from uuid import uuid4
import pytest
import yaml
from cryptography import x509

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows service update')
REPO = Path(__file__).resolve().parents[1]


def installed(tmp_path):
    """Synthetic installed agent: old code, identity, queue, config and old trust file."""
    state, install_root = tmp_path/'ProgramData', tmp_path/'ProgramFiles'
    for package in ('agent', 'shared'):
        (install_root/package).mkdir(parents=True)
        (install_root/package/'old_version.py').write_text('# old')
    state.mkdir()
    credentials = {'agent_id':str(uuid4()), 'agent_token':'x'*48, 'hostname':'PC-TEST'}
    (state/'credentials.json').write_text(json.dumps(credentials))
    (state/'config.yaml').write_text(yaml.safe_dump({'server_url':'https://192.168.1.65:8443',
        'agent_name':'PC-TEST', 'data_dir':str(state/'data')}))
    (state/'ca.pem').write_text('old trust')
    (state/'data').mkdir()
    (state/'data/queue.db').write_bytes(b'queue')
    package = tmp_path/'pacote'
    for name in ('agent', 'shared'):
        shutil.copytree(REPO/name, package/name, ignore=shutil.ignore_patterns('__pycache__'))
    (package/'server-ca.pem').write_text('new bundle')
    (package/'endpoints.json').write_text(json.dumps({'server_url':'https://PC-SERVIDOR:8443',
        'server_urls':['https://192.168.1.65:8443']}))
    return state, install_root, package, credentials


@pytest.fixture
def service(monkeypatch):
    import win32service
    import win32serviceutil
    calls = []
    status = {'value':win32service.SERVICE_RUNNING}
    monkeypatch.setattr(win32serviceutil, 'QueryServiceStatus', lambda name: (0, status['value']))
    def stop(name):
        calls.append('stop'); status['value'] = win32service.SERVICE_STOPPED
    def start(name):
        calls.append('start'); status['value'] = win32service.SERVICE_RUNNING
    monkeypatch.setattr(win32serviceutil, 'StopService', stop)
    monkeypatch.setattr(win32serviceutil, 'StartService', start)
    monkeypatch.setattr(win32serviceutil, 'WaitForServiceStatus', lambda *a: None)
    return calls


def test_update_replaces_code_config_and_trust_but_keeps_identity_and_queue(tmp_path, monkeypatch, service):
    import scripts.update_agent as updater
    state, install_root, package, credentials = installed(tmp_path)
    monkeypatch.setattr(updater, 'ROOT', package)
    monkeypatch.setattr(updater, 'reachable', lambda urls, cafile: urls[1:])
    updater.update(state, install_root)
    assert service == ['stop', 'start']
    config = yaml.safe_load((state/'config.yaml').read_text())
    assert config['server_url'] == 'https://PC-SERVIDOR:8443' and config['server_urls'] == ['https://192.168.1.65:8443']
    assert config['agent_name'] == 'PC-TEST' and config['data_dir'] == str(state/'data')
    assert (state/'ca.pem').read_text() == 'new bundle'
    assert (install_root/'agent/transport/client.py').exists() and not (install_root/'agent/old_version.py').exists()
    assert json.loads((state/'credentials.json').read_text()) == credentials
    assert (state/'data/queue.db').read_bytes() == b'queue'
    backup = next((state/'update-backups').iterdir())
    assert (backup/'ca.pem').read_text() == 'old trust' and (backup/'agent/old_version.py').exists()


def test_unreachable_server_changes_nothing(tmp_path, monkeypatch, service):
    import scripts.update_agent as updater
    state, install_root, package, _ = installed(tmp_path)
    before = (state/'config.yaml').read_bytes()
    monkeypatch.setattr(updater, 'ROOT', package)
    monkeypatch.setattr(updater, 'reachable', lambda urls, cafile: [])
    with pytest.raises(RuntimeError, match='Nada foi alterado'):
        updater.update(state, install_root)
    assert service == [] and (state/'config.yaml').read_bytes() == before
    assert (install_root/'agent/old_version.py').exists() and not (state/'update-backups').exists()


def test_failed_start_restores_previous_version(tmp_path, monkeypatch, service):
    import win32serviceutil
    import scripts.update_agent as updater
    state, install_root, package, _ = installed(tmp_path)
    before = (state/'config.yaml').read_bytes()
    monkeypatch.setattr(updater, 'ROOT', package)
    monkeypatch.setattr(updater, 'reachable', lambda urls, cafile: urls)
    attempts = []
    original = win32serviceutil.StartService
    def flaky(name):
        attempts.append(name)
        if len(attempts) == 1:
            raise RuntimeError('service failed to start')
        original(name)
    monkeypatch.setattr(win32serviceutil, 'StartService', flaky)
    with pytest.raises(RuntimeError, match='failed to start'):
        updater.update(state, install_root)
    assert (state/'config.yaml').read_bytes() == before and (state/'ca.pem').read_text() == 'old trust'
    assert (install_root/'agent/old_version.py').exists() and not (install_root/'agent/main.py').exists()
    assert len(attempts) == 2  # restored version started again


def test_update_package_has_no_secrets_and_trusts_old_and_new_certificate(tmp_path, monkeypatch):
    import scripts.agent_update_package as builder
    from scripts.dev_certificate import generate
    data = tmp_path/'data'
    old_cert, _ = generate(data/'tls', ['192.168.1.65'])
    (data/'server-info.json').write_text(json.dumps({'server_url':'https://192.168.1.65:8443', 'lan':True,
                                                    'certificate':str(old_cert)}))
    monkeypatch.setattr(builder, 'private_ipv4s', lambda: ['192.168.1.80'])
    monkeypatch.setattr(builder, 'local_hostname', lambda: 'PC-SERVIDOR')
    target, urls = builder.build(data, tmp_path/'out/ATUALIZAR-AGENTES.zip')
    assert urls == ['https://PC-SERVIDOR:8443', 'https://192.168.1.80:8443', 'https://192.168.1.65:8443']
    with zipfile.ZipFile(target) as archive:
        names = archive.namelist()
        assert {'ATUALIZAR_AGENTE.cmd', 'scripts/update_agent.py', 'agent/transport/client.py',
                'agent/collectors/pdf_library.zip', 'endpoints.json'} <= set(names)
        assert 'credentials.json' not in names and not any(n.startswith('server/') for n in names)
        assert not any(b'PRIVATE KEY' in archive.read(n) for n in names)
        assert b'powershell' not in archive.read('ATUALIZAR_AGENTE.cmd').lower()
        bundle = archive.read('server-ca.pem')
        subjects = {c.subject.rfc4514_string() for c in x509.load_pem_x509_certificates(bundle)}
        assert subjects == {'CN=SIEM Tulhy private CA', 'CN=Tulhy localhost development'}
        assert json.loads(archive.read('endpoints.json'))['server_url'] == 'https://PC-SERVIDOR:8443'
    assert (data/'tls/tulhy-ca-key.pem').exists()  # CA key stays on the server only
