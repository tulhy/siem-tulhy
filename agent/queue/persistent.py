"""Durable outbox. An acknowledged ID is the only normal deletion path."""
import json
import sqlite3
import threading
from pathlib import Path
from shared.events import Event

class PersistentQueue:
    def __init__(self, path, normalizer, max_events=100_000, max_bytes=256_000_000):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock, self.n = threading.RLock(), normalizer
        self.max_events, self.max_bytes = max_events, max_bytes
        self.db = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA wal_autocheckpoint=256')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS outbox (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, body TEXT NOT NULL, size INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS metrics (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS integrity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), body TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS totals (singleton INTEGER PRIMARY KEY CHECK(singleton=1), count INTEGER NOT NULL, bytes INTEGER NOT NULL);
          INSERT OR IGNORE INTO totals SELECT 1,COUNT(*),COALESCE(SUM(size),0) FROM outbox;
          CREATE TRIGGER IF NOT EXISTS outbox_insert AFTER INSERT ON outbox BEGIN UPDATE totals SET count=count+1,bytes=bytes+NEW.size WHERE singleton=1; END;
          CREATE TRIGGER IF NOT EXISTS outbox_delete AFTER DELETE ON outbox BEGIN UPDATE totals SET count=count-1,bytes=bytes-OLD.size WHERE singleton=1; END;
        ''')
        self.db.commit()

    def _increment(self, key, amount=1):
        self.db.execute('INSERT INTO metrics VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=value+excluded.value', (key, amount))

    def increment(self, key, amount=1):
        with self.lock, self.db:
            self._increment(key, amount)

    def put(self, event):
        body = event.model_dump_json()
        size = len(body.encode('utf-8'))
        with self.lock, self.db:
            if self.db.execute('SELECT 1 FROM outbox WHERE id=?', (str(event.event_id),)).fetchone():
                return True
            count, used = self.db.execute('SELECT count,bytes FROM totals WHERE singleton=1').fetchone()
            if count >= self.max_events or used + size > self.max_bytes:
                self._increment('events_dropped_capacity')
                self._increment('loss_unreported')
                return False
            self.db.execute('INSERT INTO outbox(id,body,size) VALUES (?,?,?)', (str(event.event_id), body, size))
            self._increment('events_collected')
            return True

    def _integrity(self):
        row = self.db.execute('SELECT body FROM integrity WHERE singleton=1').fetchone()
        if row:
            return Event.model_validate_json(row[0])
        losses = self.db.execute("SELECT value FROM metrics WHERE key='loss_unreported'").fetchone()
        if losses and losses[0]:
            event = self.n.event('telemetry.integrity', 'queue', severity='HIGH',
                raw_event={'reason':'queue_capacity_exceeded', 'events_lost':losses[0]})
            self.db.execute('INSERT INTO integrity VALUES (1,?)', (event.model_dump_json(),))
            self.db.execute("UPDATE metrics SET value=0 WHERE key='loss_unreported'")
            return event
        return None

    def peek(self, limit=100):
        with self.lock, self.db:
            integrity = self._integrity()
            events = [Event.model_validate_json(row[0]) for row in self.db.execute(
                'SELECT body FROM outbox ORDER BY seq LIMIT ?', (limit - bool(integrity),))]
            return ([integrity] if integrity else []) + events

    def ack(self, ids):
        with self.lock, self.db:
            integrity = self.db.execute('SELECT body FROM integrity WHERE singleton=1').fetchone()
            if integrity and json.loads(integrity[0])['event_id'] in ids:
                self.db.execute('DELETE FROM integrity WHERE singleton=1')
                self._increment('events_sent')
            for event_id in ids:
                removed = self.db.execute('DELETE FROM outbox WHERE id=?', (str(event_id),)).rowcount
                self._increment('events_sent', removed)

    def metrics(self):
        with self.lock:
            metrics = dict(self.db.execute('SELECT key,value FROM metrics').fetchall())
            metrics['events_pending'] = self.db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0]
            metrics['events_pending'] += self.db.execute('SELECT COUNT(*) FROM integrity').fetchone()[0]
            for key in ('events_collected','events_sent','events_failed'):
                metrics.setdefault(key, 0)
            return metrics

    def get_state(self, key):
        with self.lock:
            row = self.db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
            return row[0] if row else None

    def set_state(self, key, value):
        with self.lock, self.db:
            self.db.execute('INSERT INTO state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, value))

    def close(self):
        with self.lock:
            self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            self.db.close()
