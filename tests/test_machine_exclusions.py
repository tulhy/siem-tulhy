import pytest
from server.services.host_path_exclusions import ignored_host_path
from server.services.policy_files import PathExclusion, ExtensionExclusion


@pytest.fixture
def policy(monkeypatch):
    from server.services import policy_files
    users, alerts, events = policy_files.policies()
    def use(extension=(), path=()):
        scoped = alerts.model_copy(update={'extension_exclusions':list(extension), 'path_exclusions':list(path),
                                           'process_exclusions':[]})
        monkeypatch.setattr(policy_files, 'policies', lambda: (users, scoped, events))
    return use


def py_file(hostname, path=r'C:\Users\orige\script.py'):
    return {'event_type':'file.created', 'hostname':hostname, 'file':{'path':path}, 'raw_event':{'directory':False}}


def test_name_exclusion_follows_the_machine_across_ip_changes(policy):
    policy(extension=[ExtensionExclusion(agent_name='Pedro_Lima', extensions=['.py'])])
    for ip in ('192.168.1.77', '192.168.1.76', '192.168.1.150', None):  # old IP, cable, Wi-Fi, unknown
        assert ignored_host_path(ip, py_file('Pedro_Lima'))
    assert ignored_host_path('192.168.1.76', py_file('pedro_lima'))  # panel names are not case sensitive


def test_another_machine_with_the_same_ip_does_not_inherit_it(policy):
    policy(extension=[ExtensionExclusion(agent_name='Pedro_Lima', extensions=['.py'])])
    assert not ignored_host_path('192.168.1.76', py_file('Joao_Souza'))
    assert not ignored_host_path('192.168.1.76', {**py_file('Pedro_Lima'), 'file':{'path':r'C:\x\a.vbs'}})


def test_folder_exclusion_by_name(policy):
    policy(path=[PathExclusion(agent_name='Pedro_Lima', paths=[r'C:\Users\orige\Documents\Codex'])])
    body = {'event_type':'process.start', 'hostname':'Pedro_Lima', 'process':{'path':r'C:\Users\orige\Documents\Codex\x.exe'}}
    assert ignored_host_path('192.168.1.150', body)
    assert not ignored_host_path('192.168.1.150', {**body, 'hostname':'Outro_PC'})


def test_ip_exclusions_keep_working(policy):
    policy(extension=[ExtensionExclusion(agent_ip='192.168.1.77', extensions=['.py'])])
    assert ignored_host_path('192.168.1.77', py_file('Qualquer'))
    assert not ignored_host_path('192.168.1.76', py_file('Qualquer'))


def test_exclusion_needs_exactly_one_machine_scope():
    with pytest.raises(ValueError):
        ExtensionExclusion(extensions=['.py'])
    with pytest.raises(ValueError):
        PathExclusion(agent_ip='192.168.1.77', agent_name='Pedro_Lima', paths=[r'C:\x\y'])
