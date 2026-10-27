import json
import os
import shutil
from pathlib import Path
import pytest
import yaml
from scripts.dev_certificate import ensure_ca, generate, issue_server
from shared import enrollment
from tests.conftest import ADMIN
from tests.test_network_endpoints import serve, free_port, CLOSE

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows agent installer')


def lan_server(tmp_path, monkeypatch):
    """Real HTTPS server signed by its own CA and publishing it, like a Filial server."""
    ca, ca_key = ensure_ca(tmp_path/'tls')
    cert, key = issue_server(tmp_path/'tls', ca, ca_key, ['localhost'], [])
    monkeypatch.setenv('SIEM_CA_FILE', str(ca))
    monkeypatch.setenv('SIEM_ADMIN_TOKEN', ADMIN)
    port = free_port()
    stop = serve(tmp_path, cert, key, port, 'filial')
    return ca, port, stop


def test_installer_trusts_only_the_server_named_in_the_code(tmp_path, monkeypatch):
    import httpx
    import scripts.agent_installer as installer
    ca, port, stop = lan_server(tmp_path, monkeypatch)
    try:
        with httpx.Client(verify=str(ca), trust_env=False) as admin:
            created = admin.post(f'https://localhost:{port}/api/v1/enrollment-codes', headers={
                'Authorization':'Bearer '+ADMIN, **CLOSE}, json={'max_uses':1}).json()
        fp = enrollment.ca_fingerprint(ca.read_text())
        value = enrollment.decode(enrollment.encode('localhost', [], port, fp, created['secret']))
        ca_pem = installer.fetch_ca(value)
        assert ca_pem == ca.read_text()
        credentials = installer.register(value, ca_pem, 'PC-FILIAL')
        assert credentials['hostname'] == 'PC-FILIAL' and credentials['agent_id']
        with pytest.raises(RuntimeError, match='Codigo recusado'):
            installer.register(value, ca_pem, 'PC-OUTRO')  # single-use code already spent
        other, _ = generate(tmp_path/'other')
        impostor = enrollment.decode(enrollment.encode('localhost', [], port,
                                                       enrollment.ca_fingerprint(other.read_text()), created['secret']))
        with pytest.raises(RuntimeError, match='NAO corresponde'):
            installer.fetch_ca(impostor)
        offline = enrollment.decode(enrollment.encode('localhost', [], free_port(), fp, created['secret']))
        with pytest.raises(RuntimeError, match='Nenhum endereco'):
            installer.fetch_ca(offline)
    finally:
        stop()


def test_package_written_for_the_existing_service_installer(tmp_path, monkeypatch):
    import scripts.agent_installer as installer
    from scripts.service_manager import read_identity
    monkeypatch.setattr(installer, 'ROOT', tmp_path)
    ca, _ = ensure_ca(tmp_path/'tls')
    value = enrollment.decode(enrollment.encode('SRV-FILIAL', ['192.168.10.5'], 8443,
                                                enrollment.ca_fingerprint(ca.read_text()), 'c'*22))
    credentials = {'agent_id':'4b0d2a4e-8a0f-4d55-9d0b-3c1f2e5a6b7c', 'agent_token':'t'*64, 'hostname':'PC-FILIAL'}
    installer.write_package(value, ca.read_text(), credentials)
    config = yaml.safe_load((tmp_path/'config.yaml').read_text())
    assert config['server_url'].lower() == 'https://srv-filial:8443'
    assert config['server_urls'] == ['https://192.168.10.5:8443'] and config['agent_name'] == 'PC-FILIAL'
    assert read_identity(tmp_path/'credentials.json') == credentials
    assert (tmp_path/'server-ca.pem').read_text() == ca.read_text()


def test_machine_name_is_sanitized(monkeypatch):
    import scripts.agent_installer as installer
    monkeypatch.setattr(installer.socket, 'gethostname', lambda: 'PC Financeiro.dominio.local')
    assert installer.machine_name() == 'PC-Financeiro'


def test_person_at_the_machine_chooses_the_panel_name():
    import scripts.agent_installer as installer
    answers = iter([''])
    assert installer.panel_name('DESKTOP-7Q2X', lambda prompt: next(answers)) == 'DESKTOP-7Q2X'  # Enter keeps it
    answers = iter(['Recepção 1'])
    assert installer.panel_name('DESKTOP-7Q2X', lambda prompt: next(answers)) == 'Recepcao-1'
    answers = iter(['***', '', 'Financeiro'])
    assert installer.panel_name('', lambda prompt: next(answers)) == 'Financeiro'  # asks again until valid
    assert installer.clean_name('a' * 80) == 'a' * 64 and installer.clean_name('---') == ''
