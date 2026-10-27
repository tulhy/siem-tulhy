from uuid import uuid4
from agent.normalizers import Normalizer
from agent.queue.persistent import PersistentQueue

def test_offline_restart_ack_and_overflow(tmp_path):
    n = Normalizer(uuid4(), 'test')
    path = tmp_path / 'queue.db'
    q = PersistentQueue(path, n, max_events=1)
    e = n.event('process.start','test')
    assert q.put(e) and q.put(e)
    assert not q.put(n.event('process.start','test'))
    q.close()
    q = PersistentQueue(path, n, max_events=1)
    batch = q.peek()
    assert len(batch) == 2 and batch[0].raw_event['events_lost'] == 1
    assert q.peek()[0].event_id == batch[0].event_id
    q.ack([str(e.event_id)])
    assert len(q.peek()) == 1
    q.ack([str(batch[0].event_id)])
    assert not q.peek()
    assert q.metrics()['events_dropped_capacity'] == 1
    q.close()

def test_new_loss_while_integrity_in_flight(tmp_path):
    n = Normalizer(uuid4(), 'test')
    q = PersistentQueue(tmp_path/'q.db', n, 1)
    q.put(n.event('process.start','test'))
    q.put(n.event('process.start','test'))
    first = q.peek()[0]
    q.put(n.event('process.start','test'))
    q.ack([str(first.event_id)])
    assert q.peek()[0].event_id != first.event_id
    assert q.peek()[0].raw_event['events_lost'] == 1
    q.close()
