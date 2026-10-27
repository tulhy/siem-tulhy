"""Entry point frozen into the Tulhy .exe installers (agent and server).

Extracts the bundled Python runtime and program into C:\\Program Files and hands over to the
real installer script. Refuses to touch an existing installation.
"""
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

BASE = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))


def installed(config):
    if config['kind'] == 'agente':
        return subprocess.run(['sc.exe', 'query', 'TulhyAgent'], capture_output=True).returncode == 0
    return subprocess.run(['schtasks.exe', '/Query', '/TN', config['task']], capture_output=True).returncode == 0


def main():
    config = json.loads((BASE/'installer.json').read_text(encoding='utf-8'))
    print(config['title'])
    print('=' * len(config['title']))
    if os.name != 'nt' or not ctypes.windll.shell32.IsUserAnAdmin():
        print('Abra este arquivo com o botao direito > Executar como administrador.')
        return 1
    if installed(config):
        print('\nO Tulhy ja esta instalado neste computador. Nada foi alterado.')
        return 0
    target = Path(os.environ['ProgramFiles'])/config['folder']
    print('Copiando arquivos para', target, '...')
    # A reinstall after an uninstall keeps the unit's data and edited rules.
    kept = target/'_preservado'
    for item in config.get('preserve', []):
        if (target/item).exists():
            (kept/item).parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(target/item), str(kept/item))
            print('Preservando', item)
    for part in config['parts']:
        shutil.rmtree(target/part, ignore_errors=True)  # program files only; data was moved aside above
    with zipfile.ZipFile(BASE/'payload.zip') as payload:
        payload.extractall(target)
    for item in config.get('preserve', []):
        if (kept/item).exists():
            shutil.rmtree(target/item, ignore_errors=True)
            shutil.move(str(kept/item), str(target/item))
    shutil.rmtree(kept, ignore_errors=True)
    python = target/'runtime'/'python.exe'
    return subprocess.run([str(python), str(target/config['script']), *config['args']]).returncode


if __name__ == '__main__':
    try:
        code = main()
    except Exception as exc:  # last resort: the window must explain, not vanish
        print('\nERRO:', exc)
        code = 1
    input('\nPressione Enter para fechar...')
    sys.exit(code)
