import json
import os
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
import pytest

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows installers')


def bootstrap_env(tmp_path, monkeypatch, config, files):
    import scripts.installer_bootstrap as boot
    base = tmp_path/'exe'
    base.mkdir()
    (base/'installer.json').write_text(json.dumps(config))
    with zipfile.ZipFile(base/'payload.zip', 'w') as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    monkeypatch.setattr(boot, 'BASE', base)
    monkeypatch.setenv('ProgramFiles', str(tmp_path/'pf'))
    monkeypatch.setattr(boot.ctypes.windll.shell32, 'IsUserAnAdmin', lambda: True)
    calls = []
    monkeypatch.setattr(boot.subprocess, 'run', lambda args, **k: calls.append(args) or type('R', (), {'returncode':0})())
    return boot, calls


SERVER = {'kind':'servidor', 'title':'t', 'folder':'Tulhy Servidor', 'parts':['runtime', 'app'],
          'script':'app/scripts/server_installer.py', 'args':['--unidade', 'Filial'], 'task':'Tulhy Servidor',
          'preserve':['app/data', 'app/rules']}


def test_reinstall_keeps_data_and_edited_rules(tmp_path, monkeypatch):
    boot, calls = bootstrap_env(tmp_path, monkeypatch, SERVER, {
        'runtime/python.exe':'new', 'app/rules/regras.json':'{"new":1}', 'app/server/main.py':'new code'})
    monkeypatch.setattr(boot, 'installed', lambda config: False)
    app = tmp_path/'pf'/'Tulhy Servidor'/'app'
    (app/'data'/'local-lab').mkdir(parents=True)
    (app/'data'/'local-lab'/'server.db').write_text('history')
    (app/'rules').mkdir()
    (app/'rules'/'regras.json').write_text('{"edited":1}')
    (app/'server').mkdir()
    (app/'server'/'old.py').write_text('stale')
    assert boot.main() == 0
    assert (app/'data'/'local-lab'/'server.db').read_text() == 'history'
    assert (app/'rules'/'regras.json').read_text() == '{"edited":1}'
    assert (app/'server'/'main.py').read_text() == 'new code' and not (app/'server'/'old.py').exists()
    assert not (tmp_path/'pf'/'Tulhy Servidor'/'_preservado').exists()
    assert calls[-1][1].endswith('server_installer.py') and calls[-1][-1] == 'Filial'


def test_existing_installation_is_never_touched(tmp_path, monkeypatch):
    boot, calls = bootstrap_env(tmp_path, monkeypatch, SERVER, {'runtime/python.exe':'new'})
    monkeypatch.setattr(boot, 'installed', lambda config: True)
    assert boot.main() == 0 and calls == [] and not (tmp_path/'pf').exists()


def test_without_administrator_nothing_happens(tmp_path, monkeypatch):
    boot, calls = bootstrap_env(tmp_path, monkeypatch, SERVER, {'runtime/python.exe':'new'})
    monkeypatch.setattr(boot.ctypes.windll.shell32, 'IsUserAnAdmin', lambda: False)
    assert boot.main() == 1 and calls == [] and not (tmp_path/'pf').exists()


def test_scheduled_task_definition_is_valid_and_runs_as_system():
    import scripts.server_installer as server
    root = ET.fromstring(server.task_xml('Filial').split('?>', 1)[1])
    ns = {'t':'http://schemas.microsoft.com/windows/2004/02/mit/task'}
    assert root.find('t:Principals/t:Principal/t:UserId', ns).text == 'S-1-5-18'
    assert root.find('t:Triggers/t:BootTrigger', ns) is not None
    assert root.find('t:Settings/t:ExecutionTimeLimit', ns).text == 'PT0S'
    assert 'iniciar-servidor.cmd' in root.find('t:Actions/t:Exec/t:Arguments', ns).text


def test_server_tools_are_plain_ascii_batch_files():
    import scripts.server_installer as server
    for name, text in {**server.TOOLS, 'iniciar-servidor.cmd': server.LAUNCHER.format(unit='Filial')}.items():
        text.encode('ascii')
        assert text.startswith('@echo off'), name
    assert 'set "SIEM_SITE_NAME=Filial"' in server.LAUNCHER.format(unit='Filial')
    assert 'set /p "OK=' in server.TOOLS['DESINSTALAR_SERVIDOR.cmd']  # confirmation before removing


def test_agent_reinstall_reuses_identity_without_code(tmp_path, monkeypatch):
    import scripts.agent_installer as installer
    from scripts.service_manager import read_identity
    package = tmp_path/'pacote'
    package.mkdir()
    state = tmp_path/'ProgramData'/'Tulhy'
    state.mkdir(parents=True)
    credentials = {'agent_id':'4b0d2a4e-8a0f-4d55-9d0b-3c1f2e5a6b7c', 'agent_token':'t'*64, 'hostname':'PC-01'}
    (state/'credentials.json').write_text(json.dumps(credentials))
    (state/'config.yaml').write_text('server_url: https://srv:8443\nagent_name: PC-01\n')
    (state/'ca.pem').write_text('ca')
    monkeypatch.setattr(installer, 'ROOT', package)
    installer.reuse_identity(state)
    assert read_identity(package/'credentials.json') == credentials and (package/'server-ca.pem').read_text() == 'ca'
    installer.write_tools()
    tool = (tmp_path/'DESINSTALAR_AGENTE.cmd').read_text()
    assert 'service_manager.py" Uninstall' in tool and 'net session' in tool
