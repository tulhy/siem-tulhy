from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4
from agent.normalizers import Normalizer
from agent.queue.persistent import PersistentQueue
from server.detection.engine import DetectionEngine
from server.models.tables import EventRow
from tests.conftest import signed, ADMIN
from tests.test_api import event

def test_queue_concurrent_producers_and_byte_limit(tmp_path):
    n=Normalizer(uuid4(),'test')
    q=PersistentQueue(tmp_path/'q.db',n,max_events=1000)
    events=[n.event('process.start','synthetic') for _ in range(100)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(q.put,events))
    assert q.metrics()['events_pending']==100
    q.ack([str(e.event_id) for e in events[:50]])
    assert q.metrics()['events_pending']==50
    assert q.db.execute('SELECT count FROM totals').fetchone()[0]==50
    q.close()
    q=PersistentQueue(tmp_path/'tiny.db',n,max_bytes=1)
    assert not q.put(events[0])
    assert q.peek()[0].event_type=='telemetry.integrity'
    q.close()

def test_detection_failure_keeps_pending(client,registered,monkeypatch):
    e=event(registered,process={'path':r'C:\Temp\benign.exe'})
    assert signed(client,registered,'/api/v1/events',e).status_code==200
    engine=DetectionEngine(client.app.state.settings)
    def failure(db,event):
        raise ValueError('synthetic rule processing failure')
    monkeypatch.setattr(engine,'evaluate',failure)
    import pytest
    with pytest.raises(ValueError):
        engine.process_pending(client.app.state.sessions)
    with client.app.state.sessions() as db:
        assert db.get(EventRow,e['event_id']).processed_at is None
    fresh=DetectionEngine(client.app.state.settings)
    assert fresh.process_pending(client.app.state.sessions)==1
    assert client.get('/api/v1/alerts',headers={'Authorization':'Bearer '+ADMIN}).json()

def test_concurrent_duplicate_ingestion(client,registered):
    e=event(registered)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses=list(pool.map(lambda _:signed(client,registered,'/api/v1/events',e),range(2)))
    assert all(r.status_code==200 for r in responses)
    assert sum(r.json()['inserted'] for r in responses)==1
