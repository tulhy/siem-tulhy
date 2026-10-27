import json
import os
from uuid import uuid4
import pytest
from scripts.service_manager import read_identity, check_identity
from scripts.enroll_remote import service_commands


def test_two_packages_do_not_overwrite_installed_identity(tmp_path):
    previous={'agent_id':str(uuid4()),'agent_token':'x'*48}
    path=tmp_path/'credentials.json'
    path.write_text(json.dumps(previous))
    original=path.read_bytes()
    check_identity(previous,tmp_path)
    with pytest.raises(ValueError,match='OUTRO cadastro'):
        check_identity({'agent_id':str(uuid4())},tmp_path)
    assert path.read_bytes()==original


def test_bad_credentials_are_not_exposed(tmp_path):
    path=tmp_path/'credentials.json'
    path.write_text(json.dumps({'agent_id':str(uuid4()),'agent_token':'secret-short'}))
    with pytest.raises(ValueError) as error:
        read_identity(path)
    assert 'secret-short' not in str(error.value)


def test_windows_commands_use_native_python_without_policy_override():
    commands=service_commands()
    assert 'DIAGNOSTICAR_AGENTE.cmd' in commands
    for command in commands.values():
        assert 'service_manager.py' in command
        assert 'powershell' not in command.lower()
        assert 'bypass' not in command.lower()


@pytest.mark.skipif(os.name != 'nt',reason='Windows named mutex')
def test_duplicate_collectors_blocked_and_lock_released(monkeypatch):
    from agent.utils.instance import single_instance
    import win32event
    # Unique test name prevents touching any real collector.
    original=win32event.CreateMutex
    name='Local\\TulhyTest-'+str(uuid4())
    monkeypatch.setattr(win32event,'CreateMutex',lambda security,owner,_:original(security,owner,name))
    with single_instance():
        with pytest.raises(RuntimeError,match='Ja existe'):
            with single_instance():
                pytest.fail('second collector acquired the lock')
    with single_instance():
        assert True


@pytest.mark.skipif(os.name != 'nt',reason='Windows service API mocks')
def test_install_then_repair_preserves_identity_and_configures_auto_start(tmp_path, monkeypatch):
    import sys
    import site
    import win32service
    import win32serviceutil
    import yaml
    from pathlib import Path
    from scripts import service_manager as manager
    from scripts.dev_certificate import generate
    package=tmp_path/'pacote (2)'
    package.mkdir()
    for folder in ('agent','shared'):
        (package/folder).mkdir()
        (package/folder/'__init__.py').write_text('# synthetic')
    credentials={'agent_id':str(uuid4()),'agent_token':'x'*48,'hostname':'PC-TEST'}
    (package/'credentials.json').write_text(json.dumps(credentials))
    (package/'config.yaml').write_text('server_url: https://localhost:8443\nagent_name: PC-TEST\ndata_dir: data\n')
    (package/'requirements-agent.txt').write_text('')
    cert,_=generate(tmp_path/'tls')
    (package/'server-ca.pem').write_bytes(cert.read_bytes())
    fake_site=tmp_path/'site-packages'
    fake_site.mkdir()
    monkeypatch.setattr(manager,'ROOT',package)
    monkeypatch.setattr(manager,'global_python',lambda:Path(sys.executable))
    monkeypatch.setattr(site,'getsitepackages',lambda:[str(fake_site)])
    monkeypatch.setattr(manager,'run',lambda *a,**k:None)
    calls=[]
    monkeypatch.setattr(win32serviceutil,'InstallService',lambda **kw:calls.append(('install',kw)))
    monkeypatch.setattr(win32serviceutil,'ChangeServiceConfig',lambda **kw:calls.append(('repair',kw)))
    monkeypatch.setattr(win32serviceutil,'StartService',lambda *a:None)
    monkeypatch.setattr(win32serviceutil,'WaitForServiceStatus',lambda *a:None)
    monkeypatch.setattr(win32serviceutil,'QueryServiceStatus',lambda *a:(0,win32service.SERVICE_STOPPED))
    state=tmp_path/'state'
    target=tmp_path/'installed'
    monkeypatch.setattr(manager,'service_exists',lambda:False)
    manager.install(state,target,prepared=True)
    monkeypatch.setattr(manager,'service_exists',lambda:True)
    manager.install(state,target,prepared=True)
    assert [c[0] for c in calls]==['install','repair']
    assert all(c[1]['startType']==win32service.SERVICE_AUTO_START for c in calls)
    assert all(c[1]['pythonClassString']=='agent.windows_service.TulhyService' for c in calls)
    assert read_identity(state/'credentials.json')==credentials
    assert yaml.safe_load((state/'config.yaml').read_text())['data_dir']==str(state/'data')
    assert (target/'agent/__init__.py').exists()
    assert not (target/'agent/agent').exists()
