from sqlalchemy import select, func
from server.models.tables import EventRow
from server.detection.engine import DetectionEngine
from tests.conftest import ADMIN, signed
from shared.events import Event
from tests.test_api import event

HEADERS = {'Authorization':'Bearer '+ADMIN}


def typed(registered, event_type, **kw):
    return Event(agent_id=registered['agent_id'],hostname='test',event_type=event_type,source='test',**kw).model_dump(mode='json')


def batch(client, registered, events):
    r = signed(client,registered,'/api/v1/events/batch',{'events':events})
    assert r.status_code == 200, r.text
    return r.json()


def stored(client):
    with client.app.state.sessions() as db:
        return db.execute(select(func.count()).select_from(EventRow)).scalar()


def test_low_without_matching_rule_is_acked_and_discarded(client, registered):
    e = event(registered,severity='LOW',process={'name':'safe.exe','path':r'C:\Program Files\safe.exe'})
    result = batch(client,registered,[e])
    # ACK prevents the agent queue from retrying a deliberate discard.
    assert result['accepted_ids'] == [e['event_id']] and result['discarded_ids'] == [e['event_id']]
    assert result['inserted'] == 0 and stored(client) == 0


def test_low_matching_stateless_rule_is_kept_and_alerted_at_ingestion(client, registered):
    e = event(registered,severity='LOW',process={'path':r'C:\Temp\benign.exe'})
    result = batch(client,registered,[e])
    assert result['inserted'] == 1 and result['discarded_ids'] == []
    alerts = client.get('/api/v1/alerts',headers=HEADERS).json()
    assert [a['rule_id'] for a in alerts] == ['TEMP_EXECUTION']
    assert alerts[0]['evidence']['classification_policy'] == 'rules_before_low_discard'
    assert alerts[0]['evidence']['reported_severity'] == 'LOW'
    # Already matched at ingestion; the engine must not alert it again.
    assert DetectionEngine(client.app.state.settings).process_pending(client.app.state.sessions) == 0


def test_low_events_do_not_feed_threshold_rules(client, registered):
    events = [typed(registered,'auth.failure',severity='LOW',user='lab') for _ in range(5)]
    assert batch(client,registered,events)['inserted'] == 0
    DetectionEngine(client.app.state.settings).process_pending(client.app.state.sessions)
    assert client.get('/api/v1/alerts',headers=HEADERS).json() == []


def test_telemetry_lost_discarded_unless_high(client, registered):
    medium = typed(registered,'telemetry.lost',severity='MEDIUM')
    high = typed(registered,'telemetry.lost',severity='HIGH')
    result = batch(client,registered,[medium,high])
    assert result['discarded_ids'] == [medium['event_id']] and result['inserted'] == 1


def test_telemetry_integrity_is_medium_without_priority_fallback(client, registered):
    e = typed(registered,'telemetry.integrity',severity='HIGH',raw_event={'reason':'queue_capacity_exceeded'})
    assert batch(client,registered,[e])['inserted'] == 1
    DetectionEngine(client.app.state.settings).process_pending(client.app.state.sessions)
    alerts = client.get('/api/v1/alerts',headers=HEADERS).json()
    # Agent still reports HIGH; policy shows MEDIUM and adds no EVENT_PRIORITY_HIGH.
    assert [(a['rule_id'],a['severity']) for a in alerts] == [('TELEMETRY_INTEGRITY','MEDIUM')]
    shown = client.get('/api/v1/events',headers=HEADERS).json()[0]
    assert shown['severity'] == 'MEDIUM' and shown['reported_severity'] == 'HIGH'
