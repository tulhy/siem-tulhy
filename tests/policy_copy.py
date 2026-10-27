"""Private copy of the policy files with example entries, so tests never depend on a site's own rules."""
import json
import shutil
from pathlib import Path

RULES = Path(__file__).resolve().parents[1]/'rules'
NAMES = ('regras_de_usuarios.json', 'regras_de_alertas.json', 'regras_de_eventos.json')


def policy_copy(tmp_path, monkeypatch, **alert_changes):
    folder = tmp_path/'rules'
    folder.mkdir()
    for name in NAMES:
        shutil.copy(RULES/name, folder/name)
    if alert_changes:
        path = folder/'regras_de_alertas.json'
        data = json.loads(path.read_text(encoding='utf-8-sig'))
        data.update(alert_changes)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
    monkeypatch.setenv('SIEM_POLICY_DIR', str(folder))
    return folder
