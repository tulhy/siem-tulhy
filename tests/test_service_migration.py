import sqlite3
import pytest
from scripts.prepare_service import migrate_queue


def test_service_migration_preserves_pending_and_cursor(tmp_path):
    source = tmp_path/'old'
    source.mkdir()
    config = source/'config.yaml'
    config.write_text('data_dir: data\n')
    (source/'data').mkdir()
    with sqlite3.connect(source/'data/queue.db') as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE pending (id TEXT PRIMARY KEY, payload TEXT)')
        db.execute("INSERT INTO pending VALUES ('unique-id', 'pending-event')")
        db.execute('CREATE TABLE cursor (bookmark INTEGER)')
        db.execute('INSERT INTO cursor VALUES (42)')
        db.commit()
        migrate_queue(config, tmp_path/'service')
    with sqlite3.connect(tmp_path/'service/data/queue.db') as migrated:
        assert migrated.execute('SELECT * FROM pending').fetchall() == [('unique-id','pending-event')]
        assert migrated.execute('SELECT * FROM cursor').fetchall() == [(42,)]
    migrate_queue(config, tmp_path/'service')  # Repair must not overwrite installed data.
    (tmp_path/'service/data/queue.migration.json').unlink()
    with pytest.raises(FileExistsError):
        migrate_queue(config, tmp_path/'service')
    assert (source/'data/queue.db').exists()


def test_no_foreground_queue_is_allowed(tmp_path):
    config = tmp_path/'config.yaml'
    config.write_text('data_dir: data\n')
    migrate_queue(config, tmp_path/'service')
    assert not (tmp_path/'service/data/queue.db').exists()
