import json
from datetime import datetime, timedelta, timezone
from tests.conftest import ADMIN
from tests.test_panel_exclusions import EXCLUSION, HEADERS, add, file_event, own_rules, register, send  # noqa: F401 (fixture)


def history(client):
    return client.get('/api/v1/exclusions/history', headers=HEADERS).json()


def test_every_change_is_recorded_with_what_changed(client):
    register(client, 'Maria_Silva')
    created = add(client, kind='folder', value='903', machine='*', description='backup', days=7).json()['id']
    client.patch(f'/api/v1/exclusions/{created}', headers=HEADERS, json={'enabled':False})
    client.patch(f'/api/v1/exclusions/{created}', headers=HEADERS, json={'renew_days':0})
    client.delete(f'/api/v1/exclusions/{created}', headers=HEADERS)
    client.post('/api/v1/exclusions/remote-ips', headers=HEADERS, json={'ips':['203.0.113.7']})
    client.delete('/api/v1/exclusions/remote-ips/203.0.113.7', headers=HEADERS)
    rows = history(client)
    assert [row['action'] for row in rows] == ['remote_ip_removed', 'remote_ips_added', 'exclusion_deleted',
                                               'exclusion_renewed', 'exclusion_disabled', 'exclusion_created']
    created_row = rows[-1]['detail']
    assert 'pasta "903" (Todas as máquinas)' in created_row and 'vale até' in created_row and 'motivo: backup' in created_row
    assert 'sem prazo' in rows[3]['detail'] and 'Removeu pasta "903"' in rows[2]['detail']
    assert rows[0]['ip'] == 'testclient'


def test_history_needs_both_tokens_and_cannot_be_deleted(client):
    assert client.get('/api/v1/exclusions/history', headers={'Authorization':'Bearer '+ADMIN}).status_code == 403
    assert client.delete('/api/v1/exclusions/history', headers=HEADERS).status_code in (404, 405)


def test_wrong_tokens_are_recorded_and_lock_the_computer(client):
    wrong_exclusion = {'Authorization':'Bearer '+ADMIN, 'X-Exclusion-Token':'errado-'+'z'*40}
    for _ in range(4):
        assert client.get('/api/v1/exclusions', headers=wrong_exclusion).status_code == 403
    assert client.get('/api/v1/alerts', headers={'Authorization':'Bearer '+'x'*40}).status_code == 401
    locked = client.get('/api/v1/exclusions', headers=HEADERS)  # even the right tokens wait now
    assert locked.status_code == 429 and 'Aguarde 15 minuto' in locked.json()['detail'] and locked.headers['retry-after']
    assert client.get('/api/v1/alerts', headers={'Authorization':'Bearer '+ADMIN}).status_code == 429
    with client.app.state.sessions() as db:
        from server.models.tables import SecurityLog
        rows = db.query(SecurityLog).order_by(SecurityLog.timestamp).all()
    assert [row.action for row in rows].count('exclusion_token_failed') == 4
    assert 'bloqueado por 15 minutos' in rows[-1].detail and rows[-1].action == 'admin_token_failed'


def test_lock_ends_after_fifteen_minutes(client, monkeypatch):
    import time
    for _ in range(5):
        client.get('/api/v1/alerts', headers={'Authorization':'Bearer '+'x'*40})
    assert client.get('/api/v1/alerts', headers={'Authorization':'Bearer '+ADMIN}).status_code == 429
    later = time.time() + 15 * 60 + 1
    monkeypatch.setattr(time, 'time', lambda: later)
    assert client.get('/api/v1/alerts', headers={'Authorization':'Bearer '+ADMIN}).status_code == 200


def test_expired_exclusion_alerts_again(client, own_rules):
    maria = register(client, 'Maria_Silva')
    created = add(client, kind='folder', value='123', machine='Maria_Silva', days=1).json()['id']
    path = own_rules/'regras_de_alertas.json'
    saved = json.loads(path.read_text(encoding='utf-8'))
    entry = next(item for item in saved['path_exclusions'] if item.get('id') == created)
    assert datetime.fromisoformat(entry['expires_at']) - datetime.now(timezone.utc) > timedelta(hours=23)
    entry['expires_at'] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(timespec='seconds')
    path.write_text(json.dumps(saved, indent=2), encoding='utf-8')
    from server.services.policy_files import policies
    import server.services.policy_files as pf
    for store in pf._stores.values():
        store.next_check = 0
    policies()
    listed = {row['id']:row for row in client.get('/api/v1/exclusions', headers=HEADERS).json()['exclusions']}
    assert listed[created]['status'] == 'expired'
    event = file_event(maria, r'C:\Users\Maria\123\a.py', 'CRITICAL')
    send(client, maria, [event])
    alerted = {e for a in client.get('/api/v1/alerts', headers=HEADERS).json() for e in a['event_ids']}
    assert event['event_id'] in alerted
    notices = client.get('/api/v1/security/notices', headers={'Authorization':'Bearer '+ADMIN}).json()
    assert notices['expired'] == 1
    assert client.patch(f'/api/v1/exclusions/{created}', headers=HEADERS, json={'renew_days':30}).json()['expires_at']
    listed = {row['id']:row for row in client.get('/api/v1/exclusions', headers=HEADERS).json()['exclusions']}
    assert listed[created]['status'] == 'active'


def test_notices_summarize_the_last_day_with_the_admin_token_only(client):
    register(client, 'Maria_Silva')
    add(client, kind='folder', value='777', machine='*', days=2)
    add(client, kind='folder', value='888', machine='*')
    client.get('/api/v1/exclusions', headers={'Authorization':'Bearer '+ADMIN, 'X-Exclusion-Token':'errado-'+'z'*40})
    notices = client.get('/api/v1/security/notices', headers={'Authorization':'Bearer '+ADMIN}).json()
    assert notices['changes_24h'] == 2 and notices['failures_24h'] == 1 and notices['latest']
    assert [item['value'] for item in notices['expiring']] == ['777']
    assert client.get('/api/v1/security/notices').status_code == 401


def test_invalid_validity_is_refused(client):
    register(client, 'Maria_Silva')
    assert add(client, kind='folder', value='1', machine='*', days=0).status_code == 422
    assert add(client, kind='folder', value='1', machine='*', days=400).status_code == 422
