from datetime import timedelta
from shared.events import Event, utcnow
from server.detection.engine import DetectionEngine
from tests.conftest import signed, ADMIN

def submit(client, registered, events):
    r = signed(client,registered,'/api/v1/events/batch',{'events':[e.model_dump(mode='json') for e in events]})
    assert r.status_code == 200, r.text
    engine = DetectionEngine(client.app.state.settings)
    engine.process_pending(client.app.state.sessions)
    return client.get('/api/v1/alerts',headers={'Authorization':'Bearer '+ADMIN}).json()

def test_threshold_and_explanation(client, registered):
    events = [Event(agent_id=registered['agent_id'],hostname='test',event_type='auth.failure',source='synthetic',severity='MEDIUM',user='lab') for _ in range(5)]
    assert not submit(client,registered,events[:4])
    alerts = submit(client,registered,events[4:])
    assert len(alerts) == 1 and alerts[0]['rule_id']=='AUTH_FAILURE_BURST'
    assert len(alerts[0]['event_ids'])==5 and alerts[0]['risk_score']==50

def test_late_sequence_and_risk(client, registered):
    now = utcnow()
    common = dict(agent_id=registered['agent_id'],hostname='test',source='synthetic',severity='MEDIUM',
                  process={'pid':55,'created_at':1,'name':'safe.exe','path':r'C:\Temp\safe.exe'})
    network = Event(**common,event_type='network.connection',timestamp=now,network={'remote_ip':'192.0.2.1','remote_port':443})
    start = Event(**common,event_type='process.start',timestamp=now-timedelta(seconds=30))
    assert not submit(client,registered,[network])
    alerts = submit(client,registered,[start])
    assert {a['rule_id'] for a in alerts} == {'TEMP_EXECUTION','TEMP_THEN_NETWORK'}
    correlation = next(a for a in alerts if a['rule_id']=='TEMP_THEN_NETWORK')
    assert correlation['risk_score']==75 and len(correlation['event_ids'])==2

def test_baseline_new_destination(client, registered):
    settings = client.app.state.settings
    settings.baseline_min_events = 2
    settings.baseline_warmup_seconds = 10
    now = utcnow()
    common = dict(agent_id=registered['agent_id'],hostname='test',source='synthetic',severity='MEDIUM',event_type='network.connection',process={'name':'safe'})
    events = [Event(**common,timestamp=now-timedelta(seconds=30-i),network={'remote_ip':'192.0.2.1'}) for i in range(2)]
    assert not submit(client,registered,events)
    # A new outbound destination is learned but is not an alert by itself.
    assert not submit(client,registered,[Event(**common,network={'remote_ip':'192.0.2.2'},raw_event={'direction':'outbound'})])
    alerts = submit(client,registered,[Event(**common,network={'remote_ip':'192.0.2.3'},raw_event={'direction':'inbound'})])
    assert [a['rule_id'] for a in alerts]==['NEW_NETWORK_DESTINATION']

def test_matched_evidence_still_gets_own_detection_pass(client,registered):
    from server.models.tables import EventRow
    events=[Event(agent_id=registered['agent_id'],hostname='test',event_type='auth.failure',source='synthetic',severity='MEDIUM',user='lab') for _ in range(5)]
    assert signed(client,registered,'/api/v1/events/batch',{'events':[e.model_dump(mode='json') for e in events]}).status_code==200
    engine=DetectionEngine(client.app.state.settings)
    assert engine.process_pending(client.app.state.sessions,limit=1)==1
    assert engine.process_pending(client.app.state.sessions,limit=100)==4
    with client.app.state.sessions() as db:
        assert all(db.get(EventRow,str(e.event_id)).processed_at is not None for e in events)

def test_time_window_and_user_isolation(client,registered):
    now=utcnow()
    events=[Event(agent_id=registered['agent_id'],hostname='test',event_type='auth.failure',source='synthetic',severity='MEDIUM',user='a' if i<4 else 'b',timestamp=now) for i in range(5)]
    assert not submit(client,registered,events)
    late=Event(agent_id=registered['agent_id'],hostname='test',event_type='auth.failure',source='synthetic',severity='MEDIUM',user='a',timestamp=now-timedelta(seconds=600))
    assert not submit(client,registered,[late])
