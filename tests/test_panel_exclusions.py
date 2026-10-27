import json
import shutil
from pathlib import Path
import pytest
from server.detection.engine import DetectionEngine
from shared.events import Event
from tests.conftest import ADMIN, signed

EXCLUSION = 'token-de-exclusao-' + 'y'*40
HEADERS = {'Authorization':'Bearer '+ADMIN, 'X-Exclusion-Token':EXCLUSION}
RULES = Path(__file__).resolve().parents[1]/'rules'


@pytest.fixture(autouse=True)
def own_rules(tmp_path, monkeypatch):
    """Each test edits a private copy of the policy files, never the project's rules."""
    folder = tmp_path/'rules'
    folder.mkdir()
    for name in ('regras_de_usuarios.json', 'regras_de_alertas.json', 'regras_de_eventos.json'):
        shutil.copy(RULES/name, folder/name)
    monkeypatch.setenv('SIEM_POLICY_DIR', str(folder))
    monkeypatch.setenv('SIEM_EXCLUSION_TOKEN', EXCLUSION)
    return folder


def register(client, name):
    r = client.post('/api/v1/agents/register', json={'hostname':name}, headers=HEADERS)
    assert r.status_code == 200
    return r.json()


def file_event(agent, path, severity='MEDIUM', kind='file.created'):
    return Event(agent_id=agent['agent_id'], hostname=agent['hostname'], event_type=kind, source='teste',
                 severity=severity, file={'path':path}, raw_event={'directory':False}).model_dump(mode='json')


def send(client, agent, events):
    r = signed(client, agent, '/api/v1/events/batch', {'events':events})
    assert r.status_code == 200, r.text
    DetectionEngine(client.app.state.settings).process_pending(client.app.state.sessions)
    return r.json()


def add(client, **body):
    return client.post('/api/v1/exclusions', headers=HEADERS, json=body)


def test_folder_name_on_one_machine_keeps_events_without_alerts(client, own_rules):
    maria, simone = register(client, 'Maria_Silva'), register(client, 'Joao_Souza')
    r = add(client, kind='folder', value='123', machine='maria_silva', description='pasta de backup')
    assert r.status_code == 200 and r.json()['keep_events'] is True  # folders keep events by default
    inside = file_event(maria, r'C:\Users\Maria\Desktop\123\sub\script.py', 'CRITICAL')
    elsewhere = file_event(maria, r'C:\Users\Maria\Desktop\outra\script.py', 'CRITICAL')
    other_pc = file_event(simone, r'C:\Users\Joao\123\script.py', 'CRITICAL')
    send(client, maria, [inside, elsewhere])
    send(client, simone, [other_pc])
    alerted = {e for a in client.get('/api/v1/alerts', headers=HEADERS).json() for e in a['event_ids']}
    shown = {e['event_id']:e for e in client.get('/api/v1/events', headers=HEADERS).json()}
    assert inside['event_id'] in shown and inside['event_id'] not in alerted
    assert shown[inside['event_id']]['excluded_by_policy'] is True and 'pasta de backup' in shown[inside['event_id']]['exclusion_reason']
    assert elsewhere['event_id'] in alerted and other_pc['event_id'] in alerted
    saved = json.loads((own_rules/'regras_de_alertas.json').read_text(encoding='utf-8'))['path_exclusions'][-1]
    assert saved['paths'] == ['123'] and saved['agent_name'] == 'Maria_Silva' and saved['description'] == 'pasta de backup'
    assert list((own_rules/'backups').glob('regras_de_alertas-*.json'))  # previous version saved


def test_full_path_for_all_machines_can_discard(client):
    maria = register(client, 'Maria_Silva')
    assert add(client, kind='folder', value=r'C:\Dados\903', machine='*', keep_events=False).status_code == 200
    result = send(client, maria, [file_event(maria, r'C:\Dados\903\a.py', 'CRITICAL'),
                                  file_event(maria, r'D:\Dados\903\a.py', 'CRITICAL')])
    assert len(result['discarded_ids']) == 1 and result['inserted'] == 1  # only the exact path was excluded


def test_creating_an_exclusion_resolves_alerts_it_covers(client):
    maria = register(client, 'Maria_Silva')
    covered = file_event(maria, r'C:\Users\Maria\123\a.py', 'CRITICAL')
    kept = file_event(maria, r'C:\Users\Maria\docs\b.py', 'CRITICAL')
    send(client, maria, [covered, kept])
    r = add(client, kind='folder', value='123', machine='Maria_Silva')
    assert r.json()['resolved_alerts'] >= 1
    alerts = client.get('/api/v1/alerts', headers=HEADERS).json()
    by_event = {}
    for alert in alerts:
        for event_id in alert['event_ids']:
            by_event.setdefault(event_id, set()).add(alert['status'])
    assert by_event[covered['event_id']] == {'resolved'}
    assert 'active' in by_event[kept['event_id']]


def test_extension_program_and_remote_ip_from_panel(client):
    maria = register(client, 'Maria_Silva')
    assert add(client, kind='extension', value='py, .VBS', machine='Maria_Silva').status_code == 200
    r = add(client, kind='program', value=r'C:\Program Files\Backup\backup.exe', machine='*')
    assert r.status_code == 200 and r.json()['keep_events'] is False  # programs discard by default
    assert client.post('/api/v1/exclusions/remote-ips', headers=HEADERS, json={'ips':['203.0.113.7', '::ffff:198.51.100.2']}).json()['added'] == 2
    listed = client.get('/api/v1/exclusions', headers=HEADERS).json()
    kinds = {(row['kind'], row['value'], row['machine']) for row in listed['exclusions']}
    assert ('extension', '.py, .vbs', 'Maria_Silva') in kinds
    assert ('program', r'C:\Program Files\Backup\backup.exe', 'Todas as máquinas') in kinds
    ips = {row['ip']:row['fixed'] for row in listed['remote_ips']}
    assert ips['203.0.113.7'] is False and ips['198.51.100.2'] is False and ips['224.0.0.251'] is True
    assert 'Maria_Silva' in listed['machines']
    assert client.delete('/api/v1/exclusions/remote-ips/203.0.113.7', headers=HEADERS).status_code == 200
    assert client.delete('/api/v1/exclusions/remote-ips/224.0.0.251', headers=HEADERS).status_code == 404  # fixed ones stay


def test_disable_and_remove(client):
    maria = register(client, 'Maria_Silva')
    created = add(client, kind='folder', value='123', machine='Maria_Silva').json()['id']
    assert client.patch(f'/api/v1/exclusions/{created}', headers=HEADERS, json={'enabled':False}).status_code == 200
    result = send(client, maria, [file_event(maria, r'C:\x\123\a.py', 'CRITICAL')])
    assert result['inserted'] == 1
    alerted = {e for a in client.get('/api/v1/alerts', headers=HEADERS).json() for e in a['event_ids']}
    assert alerted  # disabled exclusion: alerts again
    assert client.delete(f'/api/v1/exclusions/{created}', headers=HEADERS).status_code == 200
    assert all(row['id'] != created for row in client.get('/api/v1/exclusions', headers=HEADERS).json()['exclusions'])


def test_invalid_input_writes_nothing(client, own_rules):
    register(client, 'Maria_Silva')
    before = (own_rules/'regras_de_alertas.json').read_bytes()
    assert add(client, kind='folder', value='12/3', machine='*').status_code == 422
    assert add(client, kind='folder', value='123', machine='PC-QUE-NAO-EXISTE').status_code == 422
    assert add(client, kind='program', value='backup.exe', machine='*').status_code == 422
    assert client.post('/api/v1/exclusions/remote-ips', headers=HEADERS, json={'ips':['999.1.1.1']}).status_code == 422
    assert (own_rules/'regras_de_alertas.json').read_bytes() == before


def test_hand_written_entries_get_ids_and_appear(client, own_rules):
    path = own_rules/'regras_de_alertas.json'
    data = json.loads(path.read_text(encoding='utf-8'))
    data['extension_exclusions'] = [{'extensions':['.tmp'], 'agent_name':'PC-EXEMPLO'}]  # written by hand, no id
    path.write_text(json.dumps(data), encoding='utf-8')
    import server.services.policy_files as policy_files
    for store in policy_files._stores.values():
        store.next_check = 0  # read the hand-edited file now instead of within 2 seconds
    rows = client.get('/api/v1/exclusions', headers=HEADERS).json()['exclusions']
    assert rows and all(row['id'] for row in rows)


def test_requires_administrator(client):
    assert client.get('/api/v1/exclusions').status_code == 401
    assert client.post('/api/v1/exclusions', json={'kind':'folder', 'value':'1', 'machine':'*'}).status_code == 401


def test_exclusion_token_is_required_besides_the_administrator_token(client):
    admin_only = {'Authorization':'Bearer '+ADMIN}
    assert client.get('/api/v1/exclusions', headers=admin_only).status_code == 403
    wrong = {**admin_only, 'X-Exclusion-Token':'errado-'+'z'*40}
    assert client.get('/api/v1/exclusions', headers=wrong).status_code == 403
    assert client.post('/api/v1/exclusions', headers=wrong, json={'kind':'folder', 'value':'1', 'machine':'*'}).status_code == 403
    assert client.post('/api/v1/exclusions/remote-ips', headers=wrong, json={'ips':['8.8.4.4']}).status_code == 403
    assert client.get('/api/v1/exclusions', headers={'X-Exclusion-Token':EXCLUSION}).status_code == 401  # admin still required
    assert client.get('/api/v1/exclusions', headers=HEADERS).status_code == 200
    assert client.get('/api/v1/alerts', headers=admin_only).status_code == 200  # the rest of the panel is unchanged


def test_server_without_exclusion_token_explains(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from server.main import create_app
    from server.settings import Settings
    monkeypatch.delenv('SIEM_EXCLUSION_TOKEN')
    settings = Settings(database_url='sqlite:///'+str(tmp_path/'s.db'), admin_token=ADMIN)
    with TestClient(create_app(settings, background=False)) as c:
        r = c.get('/api/v1/exclusions', headers=HEADERS)
        assert r.status_code == 503 and 'Reinicie' in r.json()['detail']
