import csv
import hashlib
import time
from fastapi.testclient import TestClient
from server.main import create_app
from server.settings import Settings
from server.detection.engine import DetectionEngine
from shared.events import Event
from tests.conftest import ADMIN, signed


def seeded(folder):
    """Panel database with two machines, visible and hidden events, and one alert."""
    folder.mkdir(parents=True)
    db = folder/'server.db'
    with TestClient(create_app(Settings(database_url='sqlite:///'+str(db), admin_token=ADMIN), background=False)) as c:
        ids = {}
        for name in ('Pedro_Lima', 'Joao_Souza'):
            agent = c.post('/api/v1/agents/register', json={'hostname':name}, headers={'Authorization':'Bearer '+ADMIN}).json()
            events = [Event(agent_id=agent['agent_id'], hostname=name, event_type='process.start', source='teste',
                            severity='MEDIUM', user='=HYPERLINK("x")', process={'name':'app.exe', 'path':r'C:\Temp\app.exe'}),
                      Event(agent_id=agent['agent_id'], hostname=name, event_type='process.start', source='teste',
                            severity='LOW', process={'name':'quiet.exe', 'path':r'C:\Program Files\quiet.exe'})]
            assert signed(c, agent, '/api/v1/events/batch', {'events':[e.model_dump(mode='json') for e in events]}).status_code == 200
            ids[name] = [str(e.event_id) for e in events]
        DetectionEngine(c.app.state.settings).process_pending(c.app.state.sessions)
    return db, ids


def rows(path):
    with open(path, encoding='utf-8-sig', newline='') as stream:
        return list(csv.reader(stream, delimiter=';'))


def test_export_matches_the_panel_and_never_writes(tmp_path):
    from scripts import export_events
    db, ids = seeded(tmp_path/'pasta com espaco')
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    out = tmp_path/'saida'
    out.mkdir()
    engine = export_events.read_only(db)
    from sqlalchemy.orm import Session
    with Session(engine) as session:
        n_events = export_events.write_csv(out/'e.csv', export_events.EVENT_COLUMNS, export_events.events(session, time.time()-86400, None))
        n_alerts = export_events.write_csv(out/'a.csv', export_events.ALERT_COLUMNS, export_events.alerts(session, time.time()-86400, 'pedro_lima'))
    engine.dispose()
    exported = rows(out/'e.csv')
    assert exported[0] == export_events.EVENT_COLUMNS and n_events == 2
    assert {r[-1] for r in exported[1:]} == {ids['Pedro_Lima'][0], ids['Joao_Souza'][0]}  # LOW was discarded, like the panel
    assert all(r[5].startswith("'=") for r in exported[1:])  # formula text stays plain text in Excel
    alerts = rows(out/'a.csv')
    assert n_alerts == 1 and alerts[1][1] == 'Pedro_Lima' and alerts[1][3] == 'TEMP_EXECUTION'
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before


def test_read_only_connection_refuses_writes(tmp_path):
    import pytest
    from sqlalchemy import text
    from sqlalchemy.exc import OperationalError
    from scripts import export_events
    db, _ = seeded(tmp_path/'db')
    engine = export_events.read_only(db)
    with engine.connect() as connection:
        with pytest.raises(OperationalError):
            connection.execute(text('DELETE FROM events'))
    engine.dispose()


def test_command_line_export_with_filters(tmp_path, monkeypatch, capsys):
    from scripts import export_events
    db, _ = seeded(tmp_path/'data')
    monkeypatch.setattr('sys.argv', ['export_events', '--data-dir', str(tmp_path/'data'), '--dias', '1',
                                     '--maquina', 'Joao_Souza', '--saida', str(tmp_path/'out')])
    export_events.main()
    files = sorted((tmp_path/'out').glob('*.csv'))
    assert [f.name.split('_')[0] for f in files] == ['alertas', 'eventos'] and all('Joao_Souza' in f.name for f in files)
    events = rows([f for f in files if f.name.startswith('eventos')][0])
    assert len(events) == 2 and events[1][1] == 'Joao_Souza'
    assert '1 eventos e 1 alertas exportados' in capsys.readouterr().out


def test_missing_database_is_a_clear_error(tmp_path):
    import pytest
    from scripts import export_events
    with pytest.raises(ValueError, match='Banco de dados nao encontrado'):
        export_events.read_only(tmp_path/'server.db')
