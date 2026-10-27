import json
import time
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
from server.main import create_app
from server.settings import Settings
from shared import enrollment
from scripts.dev_certificate import ensure_ca, generate
from tests.conftest import ADMIN

HEADERS = {'Authorization':'Bearer '+ADMIN}


def new_code(client, **body):
    r = client.post('/api/v1/enrollment-codes', headers=HEADERS, json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_code_registers_until_limit_and_is_never_listed(client):
    code = new_code(client, label='Filial', max_uses=2)
    for name in ('PC-01', 'PC-02'):
        r = client.post('/api/v1/agents/enroll', json={'secret':code['secret'], 'hostname':name})
        assert r.status_code == 200 and r.json()['hostname'] == name and len(r.json()['agent_token']) > 40
    assert client.post('/api/v1/agents/enroll', json={'secret':code['secret'], 'hostname':'PC-03'}).status_code == 401
    listed = client.get('/api/v1/enrollment-codes', headers=HEADERS).json()
    assert listed[0]['uses'] == 2 and 'secret' not in listed[0] and 'secret_hash' not in listed[0]
    names = {a['hostname'] for a in client.get('/api/v1/agents', headers=HEADERS).json()}
    assert names == {'PC-01', 'PC-02'}


def test_wrong_revoked_and_expired_codes_are_refused(client):
    assert client.post('/api/v1/agents/enroll', json={'secret':'x'*22, 'hostname':'PC-01'}).status_code == 401
    code = new_code(client)
    assert client.delete('/api/v1/enrollment-codes/'+code['id'], headers=HEADERS).status_code == 200
    assert client.post('/api/v1/agents/enroll', json={'secret':code['secret'], 'hostname':'PC-01'}).status_code == 401
    expired = new_code(client)
    from server.models.tables import EnrollmentCode
    with client.app.state.sessions() as db:
        db.get(EnrollmentCode, expired['id']).expires_at = time.time() - 1
        db.commit()
    assert client.post('/api/v1/agents/enroll', json={'secret':expired['secret'], 'hostname':'PC-01'}).status_code == 401


def test_code_management_requires_administrator(client):
    assert client.post('/api/v1/enrollment-codes', json={}).status_code == 401
    assert client.get('/api/v1/enrollment-codes').status_code == 401


def test_invalid_hostname_is_refused(client):
    code = new_code(client)
    for bad in ('../x', 'a'*65, '', 'PC 01'):
        assert client.post('/api/v1/agents/enroll', json={'secret':code['secret'], 'hostname':bad}).status_code == 422


def test_concurrent_enrollment_never_exceeds_limit(client):
    code = new_code(client, max_uses=3)
    with ThreadPoolExecutor(max_workers=6) as pool:
        codes = list(pool.map(lambda i: client.post('/api/v1/agents/enroll',
            json={'secret':code['secret'], 'hostname':f'PC-{i}'}).status_code, range(6)))
    assert codes.count(200) == 3 and codes.count(401) == 3


def test_ca_endpoint_publishes_only_the_public_certificate(tmp_path):
    ca, _ = ensure_ca(tmp_path/'tls')
    settings = Settings(database_url='sqlite:///'+str(tmp_path/'s.db'), admin_token=ADMIN, ca_file=str(ca))
    with TestClient(create_app(settings, background=False)) as c:
        r = c.get('/api/v1/ca')
        assert r.status_code == 200 and r.text == ca.read_text() and 'PRIVATE' not in r.text
    key = tmp_path/'tls/tulhy-ca-key.pem'
    settings = Settings(database_url='sqlite:///'+str(tmp_path/'k.db'), admin_token=ADMIN, ca_file=str(key))
    with TestClient(create_app(settings, background=False)) as c:
        assert c.get('/api/v1/ca').status_code == 404  # a key file is never served
    settings = Settings(database_url='sqlite:///'+str(tmp_path/'n.db'), admin_token=ADMIN)
    with TestClient(create_app(settings, background=False)) as c:
        assert c.get('/api/v1/ca').status_code == 404


def test_unit_name_beside_central_de_seguranca(tmp_path):
    plain = Settings(database_url='sqlite:///'+str(tmp_path/'a.db'), admin_token=ADMIN)
    with TestClient(create_app(plain, background=False)) as c:
        page = c.get('/').text
        assert 'CENTRAL DE SEGURANÇA</span>' in page and 'FILIAL' not in page
    named = Settings(database_url='sqlite:///'+str(tmp_path/'b.db'), admin_token=ADMIN, site_name='Filial')
    with TestClient(create_app(named, background=False)) as c:
        page = c.get('/').text
        assert page.count('CENTRAL DE SEGURANÇA · FILIAL') == 2 and 'Central de Segurança · Filial</title>' in page
    hostile = Settings(database_url='sqlite:///'+str(tmp_path/'c.db'), admin_token=ADMIN, site_name='<script>x')
    with TestClient(create_app(hostile, background=False)) as c:
        assert '<SCRIPT>' not in c.get('/').text.upper().replace('&LT;SCRIPT&GT;', '')


def test_code_round_trip_and_validation(tmp_path):
    ca, _ = ensure_ca(tmp_path)
    fp = enrollment.ca_fingerprint(ca.read_text())
    code = enrollment.encode('SRV-FILIAL', ['192.168.10.5'], 8443, fp, 'a'*22)
    pasted = code[:30] + '\n  ' + code[30:]  # line break from copy/paste
    value = enrollment.decode(pasted)
    assert enrollment.endpoints(value) == ['https://SRV-FILIAL:8443', 'https://192.168.10.5:8443']
    for bad in ('', 'SNT1-xxxx', code[:-10], code.replace('SNT1-', 'XXX1-')):
        with pytest.raises(ValueError):
            enrollment.decode(bad)
    with pytest.raises(ValueError):
        enrollment.encode('SRV', ['8.8.8.8'], 8443, fp, 'a'*22)  # public address never accepted
    other, _ = generate(tmp_path/'other')
    assert enrollment.ca_fingerprint(other.read_text()) != fp


def test_enrollment_code_cli_builds_a_code_for_this_server(tmp_path):
    from scripts.enrollment_code import build_code
    ca, _ = ensure_ca(tmp_path)
    info = {'server_url':'https://SRV-FILIAL:8443', 'server_urls':['https://192.168.10.5:8443'],
            'server_ips':['192.168.10.5', '192.168.56.1'], 'certificate':str(ca)}
    value = enrollment.decode(build_code(info, 'b'*22))
    assert value['h'].upper() == 'SRV-FILIAL' and value['i'] == ['192.168.10.5'] and value['s'] == 'b'*22
    assert value['f'] == enrollment.ca_fingerprint(ca.read_text())
