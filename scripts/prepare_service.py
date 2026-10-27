"""Preserve a stopped foreground agent's durable outbox on first service installation."""
from pathlib import Path
import sqlite3
import json
import os
import sys
import yaml


def migrate_queue(config_path, state_root):
    config_path = Path(config_path).resolve()
    config = yaml.safe_load(config_path.read_text(encoding='utf-8-sig'))
    source = Path(config.get('data_dir', 'data/agent'))
    if not source.is_absolute():
        source = config_path.parent / source
    source = (source / 'queue.db').resolve()
    destination = Path(state_root).resolve() / 'data' / 'queue.db'
    if not source.exists() or source == destination:
        return
    if destination.exists():
        marker = destination.with_suffix('.migration.json')
        if marker.exists() and json.loads(marker.read_text(encoding='utf-8'))['source'] == str(source):
            return  # Retry/repair: the installed queue is authoritative after migration.
        raise FileExistsError('Both foreground and service queues exist; reconcile them before installation. Neither was overwritten.')
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = destination.with_suffix('.migrating')
    with sqlite3.connect(source.as_uri() + '?mode=ro', uri=True) as origin:
        with sqlite3.connect(staging) as target:
            origin.backup(target)
            if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('Queue integrity check failed')
        target.close()
    origin.close()
    os.replace(staging,destination)
    destination.with_suffix('.migration.json').write_text(json.dumps({'source':str(source)}),encoding='utf-8')


if __name__ == '__main__':
    migrate_queue(sys.argv[1], sys.argv[2])
