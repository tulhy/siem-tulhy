from uuid import uuid4
from agent.normalizers import Normalizer
from agent.collectors.windows import parse_event
from agent.collectors.system import SystemCollector
from agent.config.settings import Config
from agent.utils.hashing import executable_hash

def test_windows_metadata_only():
    xml = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4104</EventID><EventRecordID>1</EventRecordID><TimeCreated SystemTime="2026-09-24T10:00:00Z"/></System><EventData><Data Name="ScriptBlockText">secret-personal frombase64string</Data></EventData></Event>'''
    n = Normalizer(uuid4(), 'test')
    record, e = parse_event(xml, 'PowerShell', n)
    assert record == 1 and e.raw_event['powershell_signals'] == 'frombase64string'
    assert 'secret-personal' not in e.model_dump_json()
    assert parse_event(xml, 'PowerShell', n)[1].event_id == e.event_id

def test_hash(tmp_path):
    p = tmp_path / 'safe.exe'
    p.write_bytes(b'benign')
    assert len(executable_hash(str(p), 100)) == 64
    assert executable_hash(str(p), 1) is None

def test_process_poll(monkeypatch):
    class P:
        info = dict(pid=1, ppid=0, name='benign', exe=None, username='test', create_time=1)
    import psutil
    monkeypatch.setattr(psutil, 'process_iter', lambda *a, **kw: [P()])
    events = []
    c = SystemCollector(Normalizer(uuid4(), 'test'), Config(), events.append)
    monkeypatch.setattr(c, 'network', lambda: None)
    monkeypatch.setattr(c, 'resources', lambda: None)
    monkeypatch.setattr(c, 'service_changes', lambda: None)
    c.poll()
    c.poll()
    assert sum(e.event_type == 'process.start' for e in events) == 1
    monkeypatch.setattr(psutil, 'process_iter', lambda *a, **kw: [])
    c.poll()
    assert events[-1].event_type == 'process.stop'
