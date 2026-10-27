import pytest
from server.services.host_path_exclusions import executable_key, ignored_host_path
from server.services.policy_files import ProcessExclusion
from tests.conftest import ADMIN, signed
from tests.test_api import event
from tests.policy_copy import policy_copy


@pytest.fixture(autouse=True)
def printer_services(tmp_path, monkeypatch):
    """Example: Windows services and the print spooler, only at their original Windows paths."""
    policy_copy(tmp_path, monkeypatch, process_exclusions=[{'paths':[r'C:\Windows\System32\svchost.exe',
        r'C:\Windows\SysWOW64\svchost.exe', r'C:\Windows\System32\spoolsv.exe'], 'enabled':True}])

SVCHOST = r'C:\Windows\System32\svchost.exe'


@pytest.mark.parametrize('path', [
    r'C:\Windows\System32\svchost.exe',
    r'c:\windows\system32\SVCHOST.EXE',
    r'\Device\HarddiskVolume3\Windows\System32\svchost.exe',  # Windows Filtering Platform form
    r'\\?\C:\Windows\System32\svchost.exe',
    r'C:\Windows\SysWOW64\svchost.exe',
    r'C:\Windows\System32\spoolsv.exe',
])
def test_original_windows_executables_are_ignored(path):
    assert ignored_host_path('192.168.1.50', {'event_type':'network.connection', 'process':{'path':path}})


@pytest.mark.parametrize('path', [
    r'C:\Users\lab\Downloads\svchost.exe',  # impostor outside System32
    r'C:\Windows\Temp\spoolsv.exe',
    r'C:\Windows\System32\..\Temp\svchost.exe',
    r'D:\Windows\System32\svchost.exe',  # another drive is not the Windows installation
    r'svchost.exe',
    None,
])
def test_impostors_and_unknown_paths_are_kept(path):
    assert not ignored_host_path('192.168.1.50', {'event_type':'process.start', 'process':{'path':path}})


def test_antivirus_and_collection_health_are_never_ignored():
    for kind in ('antivirus.detected', 'telemetry.integrity'):
        assert not ignored_host_path('192.168.1.50', {'event_type':kind, 'process':{'path':SVCHOST}})


def test_agent_scoped_exclusion(monkeypatch):
    from server.services import policy_files
    users, alerts, events = policy_files.policies()
    scoped = alerts.model_copy(update={'process_exclusions':[ProcessExclusion(paths=[SVCHOST], agent_ip='192.168.1.20')]})
    monkeypatch.setattr(policy_files, 'policies', lambda: (users, scoped, events))
    body = {'event_type':'network.connection', 'process':{'path':SVCHOST}}
    assert ignored_host_path('192.168.1.20', body) and not ignored_host_path('192.168.1.21', body)


def test_executable_key_rejects_relative_and_network_paths():
    assert executable_key('svchost.exe') is None
    assert executable_key(r'\\servidor\share\svchost.exe') is None
    assert executable_key(r'C:\Windows\System32\svchost.exe') == ('c', r'\windows\system32\svchost.exe')


def test_ingestion_acknowledges_and_discards_excluded_process(client, registered):
    from server.detection.engine import DetectionEngine
    ignored = event(registered, severity='HIGH', process={'name':'spoolsv.exe', 'path':r'C:\Windows\System32\spoolsv.exe'})
    impostor = event(registered, severity='MEDIUM', process={'name':'svchost.exe', 'path':r'C:\Users\Public\svchost.exe'})
    r = signed(client, registered, '/api/v1/events/batch', {'events':[ignored, impostor]})
    assert r.status_code == 200
    result = r.json()
    assert set(result['accepted_ids']) == {ignored['event_id'], impostor['event_id']}
    assert result['discarded_ids'] == [ignored['event_id']] and result['inserted'] == 1
    DetectionEngine(client.app.state.settings).process_pending(client.app.state.sessions)
    stored = client.get('/api/v1/events', headers={'Authorization':'Bearer '+ADMIN}).json()
    assert [e['event_id'] for e in stored] == [impostor['event_id']]


def test_policy_rejects_folders_and_non_executables():
    for bad in ('svchost.exe', r'C:\Windows', r'C:\Windows\System32\..\Temp\svchost.exe', r'C:\Windows\a.dll'):
        with pytest.raises(ValueError):
            ProcessExclusion(paths=[bad])
