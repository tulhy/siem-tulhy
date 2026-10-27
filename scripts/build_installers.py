"""Build the single-file installers: the server of one company unit and the generic agent.

Development machine only. Bundles a clean copy of this machine's Python (core only, never
its site-packages or service files) plus the project's libraries, so the target computer
needs nothing installed.
"""
import argparse
import fnmatch
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BASE = Path(sys.base_prefix)            # the real Python installation behind the venv
SITE = Path(sys.prefix)/'Lib'/'site-packages'

RUNTIME_FILES = ('python.exe', 'pythonw.exe', 'python3*.dll', 'vcruntime140*.dll', 'LICENSE.txt')
LIB_SKIP = {'site-packages', 'test', 'idlelib', 'tkinter', 'turtledemo', 'ensurepip', '__pycache__'}
# Build and test tools never shipped; the agent also leaves out server-only libraries.
SITE_SKIP = ['pip', 'pip-*', 'PyInstaller', 'pyinstaller*', '_pyinstaller_hooks_contrib*', 'altgraph*', 'pefile*',
             'pywin32_ctypes*', 'win32ctypes', 'setuptools*', '_distutils_hack', 'distutils-precedence.pth',
             'pkg_resources', 'pytest*', '_pytest', 'py.py', 'pluggy*', 'iniconfig*', 'pygments*', 'psycopg*',
             '__pycache__', 'tulhy-service.pth']
AGENT_SKIP = SITE_SKIP + ['sqlalchemy*', 'SQLAlchemy*', 'fastapi*', 'starlette*', 'uvicorn*', 'cryptography*',
                          'greenlet*', 'click*']
AGENT_FILES = ['agent', 'shared', 'scripts/__init__.py', 'scripts/service_manager.py', 'scripts/prepare_service.py',
               'scripts/agent_installer.py', 'requirements-agent.txt']
SERVER_SKIP = {'data', 'update-backups', 'tests', '.venv', '__pycache__', '.pytest_cache', 'build', 'dist'}


POLICY = 'rules/regras_de_alertas.json'
# Exclusions tied to this unit's machines and IPs; another unit starts without them.
SITE_SPECIFIC = ('path_exclusions', 'extension_exclusions', 'ignored_remote_ips')


def unit_policy():
    raw = (ROOT/POLICY).read_bytes()
    policy = json.loads(raw.decode('utf-8-sig'))
    for key in SITE_SPECIFIC:
        if key in policy:
            policy[key] = []
    newline = '\r\n' if b'\r\n' in raw else '\n'
    return (json.dumps(policy, indent=2, ensure_ascii=False) + '\n').replace('\n', newline).encode('utf-8')


def skipped(name, patterns):
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def add_tree(archive, source, prefix, skip=lambda p: False):
    for path in sorted(source.rglob('*')):
        relative = path.relative_to(source)
        if path.is_file() and '__pycache__' not in relative.parts and not path.suffix == '.pyc' and not skip(relative):
            archive.write(path, f'{prefix}/{relative.as_posix()}')


def add_runtime(archive, site_skip):
    for pattern in RUNTIME_FILES:
        for path in BASE.glob(pattern):
            archive.write(path, f'runtime/{path.name}')
    add_tree(archive, BASE/'DLLs', 'runtime/DLLs')
    add_tree(archive, BASE/'Lib', 'runtime/Lib', lambda r: r.parts[0] in LIB_SKIP)
    for entry in sorted(SITE.iterdir()):
        if skipped(entry.name, site_skip):
            continue
        if entry.is_dir():
            add_tree(archive, entry, f'runtime/Lib/site-packages/{entry.name}')
        else:
            archive.write(entry, f'runtime/Lib/site-packages/{entry.name}')
    archive.write(Path(sys.prefix)/'Scripts'/'pywin32_postinstall.py', 'runtime/Scripts/pywin32_postinstall.py')


def payload(path, kind):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        add_runtime(archive, AGENT_SKIP if kind == 'agente' else SITE_SKIP)
        if kind == 'agente':
            for name in AGENT_FILES:
                source = ROOT/name
                if source.is_dir():
                    add_tree(archive, source, f'pacote/{name}')
                else:
                    archive.write(source, f'pacote/{name}')
        else:
            # Root .cmd tools expect the developer .venv; the installer writes its own tools.
            add_tree(archive, ROOT, 'app', lambda r: r.parts[0] in SERVER_SKIP or (len(r.parts) == 1 and r.suffix == '.cmd')
                     or r.as_posix() == POLICY)
            archive.writestr('app/'+POLICY, unit_policy())
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('payload corrompido')
        names = archive.namelist()
        # Libraries may carry public CA bundles (certifi); the project's own certificates and keys never ship.
        project = [n for n in names if not n.startswith('runtime/')]
        bad = [n for n in project if n.endswith(('.pem', 'admin-token.txt', 'credentials.json', '.db'))]
        bad += [n for n in names if n.endswith('-key.pem') or 'tulhy-service.pth' in n]
        bad += [n for n in names if n.endswith('.pem') and archive.read(n).count(b'PRIVATE KEY')]
        if bad:
            raise RuntimeError('payload conteria arquivos sensiveis: ' + ', '.join(bad[:5]))
    return len(names)


def build(kind, out, unit, work):
    stage = work/kind
    stage.mkdir(parents=True)
    count = payload(stage/'payload.zip', kind)
    if kind == 'agente':
        config = {'kind':'agente', 'title':'Tulhy - Instalador do agente', 'folder':'Tulhy',
                  'parts':['runtime', 'pacote'], 'script':'pacote/scripts/agent_installer.py', 'args':[]}
        name = 'Tulhy-Instalar-Agente'
    else:
        config = {'kind':'servidor', 'title':f'Tulhy - Instalador do servidor ({unit})', 'folder':'Tulhy Servidor',
                  'parts':['runtime', 'app'], 'script':'app/scripts/server_installer.py', 'args':['--unidade', unit],
                  'task':'Tulhy Servidor', 'preserve':['app/data', 'app/rules']}
        name = 'Tulhy-Servidor-' + unit.replace(' ', '-')
    (stage/'installer.json').write_text(json.dumps(config), encoding='utf-8')
    subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--onefile', '--console', '--uac-admin',
                    '--name', name, '--distpath', str(out), '--workpath', str(stage/'build'), '--specpath', str(stage),
                    '--add-data', f'{stage/"payload.zip"};.', '--add-data', f'{stage/"installer.json"};.',
                    str(ROOT/'scripts/installer_bootstrap.py')], check=True)
    exe = out/(name+'.exe')
    print(f'{exe}  ({exe.stat().st_size/1e6:.0f} MB, {count} arquivos no pacote)')
    return exe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unidade', default='Filial')
    parser.add_argument('--saida', default=str(ROOT.parent/'atualizacoes'/'instaladores'))
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 -]{0,39}', args.unidade):
        raise SystemExit('Nome da unidade invalido')
    out = Path(args.saida)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as folder:
        for kind in ('servidor', 'agente'):
            build(kind, out, args.unidade, Path(folder))


if __name__ == '__main__':
    main()
