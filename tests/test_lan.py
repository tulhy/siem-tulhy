import json
from ipaddress import ip_address
import zipfile
from uuid import uuid4
import yaml
from cryptography import x509
from scripts.dev_certificate import generate
from scripts.enroll_remote import build_package

def test_lan_certificate_and_agent_only_package(tmp_path):
    cert,key = generate(tmp_path/'tls',['192.168.1.10'])
    parsed = x509.load_pem_x509_certificate(cert.read_bytes())
    names = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ip_address('192.168.1.10') in names.get_values_for_type(x509.IPAddress)
    assert ip_address('127.0.0.1') in names.get_values_for_type(x509.IPAddress)
    credentials = {'agent_id':str(uuid4()),'agent_token':'synthetic-test-'+'x'*40,'hostname':'PC-TEST'}
    target = tmp_path/'PC-TEST.zip'
    build_package(target,credentials,'https://192.168.1.10:8443',cert)
    with zipfile.ZipFile(target) as archive:
        assert archive.testzip() is None
        names = archive.namelist()
        assert 'INICIAR_AGENTE.cmd' in names and 'agent/main.py' in names
        assert 'INSTALAR_SERVICO.cmd' in names
        assert 'scripts/prepare_service.py' in names and 'STATUS_SERVICO.cmd' in names
        assert 'scripts/service_manager.py' in names and 'DIAGNOSTICAR_AGENTE.cmd' in names
        assert b'powershell' not in archive.read('INSTALAR_SERVICO.cmd').lower()
        assert not any(n.startswith('server/') or 'admin-token' in n or 'key.pem' in n for n in names)
        assert not any(b'PRIVATE KEY' in archive.read(n) for n in names)
        assert json.loads(archive.read('credentials.json')) == credentials
        config = yaml.safe_load(archive.read('config.yaml'))
        assert config['server_url']=='https://192.168.1.10:8443' and config['agent_name']=='PC-TEST'
        assert archive.read('server-ca.pem')==cert.read_bytes()


def test_missing_source_does_not_leave_partial_zip(tmp_path, monkeypatch):
    import scripts.enroll_remote as enrollment
    cert,_ = generate(tmp_path/'tls')
    credentials = {'agent_id':str(uuid4()),'agent_token':'x'*48,'hostname':'PC-TEST'}
    monkeypatch.setattr(enrollment,'ROOT',tmp_path/'missing-project')
    target=tmp_path/'agent.zip'
    try:
        enrollment.build_package(target,credentials,'https://192.168.1.10:8443',cert)
    except FileNotFoundError as error:
        assert 'requirements-agent.txt' in str(error)
    else:
        raise AssertionError('missing package source was accepted')
    assert not target.exists()
    assert not (tmp_path/'.agent.zip.creating').exists()
