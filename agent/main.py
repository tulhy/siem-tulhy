"""Autonomous agent. No dependency on dashboard availability."""
import logging
import os
import platform
import signal
import socket
import sqlite3
import threading
import time
from pathlib import Path
from uuid import UUID
import httpx
from agent.config.settings import load
from agent.normalizers import Normalizer
from agent.queue.persistent import PersistentQueue
from agent.transport.client import Transport, ProtocolError
from agent.collectors.system import SystemCollector
from agent.collectors.files import FileCollector
from agent.collectors.windows import WindowsCollector
from shared.logging import configure

VERSION = '1.4.0'
log = logging.getLogger('agent')

def run(stop=None):
    from agent.utils.instance import single_instance
    with single_instance():
        return _run(stop)

def _run(stop=None):
    config = load()
    agent_id = UUID(os.environ['SIEM_AGENT_ID'])
    token = os.environ['SIEM_AGENT_TOKEN']
    if len(token) < 32:
        raise ValueError('agent token must contain at least 32 characters')
    root = Path(config.data_dir)
    if any(root.resolve().is_relative_to(Path(path).resolve()) for path in config.monitor_paths):
        raise ValueError('monitor_paths must not contain data_dir: this would create a telemetry feedback loop')
    root.mkdir(parents=True, exist_ok=True)
    configure(config.log_level, root/'agent.log')
    stop = stop or threading.Event()
    if threading.current_thread() is threading.main_thread():
        signals = [signal.SIGINT, signal.SIGTERM]
        if os.name == 'nt':
            signals.append(signal.SIGBREAK)
        for sig in signals:
            signal.signal(sig, lambda *_: stop.set())
    n = Normalizer(agent_id, config.agent_name or socket.gethostname(), config.collect_command_lines)
    queue = PersistentQueue(root/'queue.db', n, config.queue_max_size, config.queue_max_bytes)
    def emit(event):
        try:
            accepted = queue.put(event)
        except sqlite3.Error:
            log.error('queue_storage_failed_collection_cannot_continue')
            raise
        if not accepted:
            log.warning('queue_capacity_exceeded')
        return accepted
    system = SystemCollector(n, config, emit)
    files = FileCollector(n, emit, config.monitor_paths, state=queue, config=config)
    windows = WindowsCollector(n, emit, queue, config.windows_lookback_seconds)
    transport = Transport(config, agent_id, token)
    failures = []

    def sender():
        # Spread startup delivery across the configured interval so all machines
        # do not drain their queues into the host at exactly the same instant.
        next_send = time.monotonic() + agent_id.int % max(1,int(config.send_idle_interval))
        next_heartbeat = 0
        while not stop.is_set():
            now = time.monotonic()
            if now >= next_heartbeat:
                try:
                    metrics = queue.metrics()
                    transport.post('/api/v1/agents/heartbeat', {'hostname':n.hostname, 'version':VERSION,
                        'os':platform.platform(), 'pending':metrics['events_pending'], 'metrics':metrics})
                except httpx.HTTPStatusError as exc:
                    log.warning('heartbeat_rejected status=%d',exc.response.status_code)
                except (httpx.HTTPError, ProtocolError):
                    log.warning('heartbeat_delivery_failed')
                next_heartbeat = time.monotonic() + config.heartbeat_interval
            if now >= next_send:
                try:
                    count = transport.flush(queue)
                    next_send = time.monotonic() + (config.send_batch_interval if count else config.send_idle_interval)
                except httpx.HTTPStatusError as exc:
                    queue.increment('events_failed')
                    next_send = time.monotonic() + transport.backoff()
                    log.warning('batch_rejected_retry_scheduled status=%d',exc.response.status_code)
                except (httpx.HTTPError, ProtocolError):
                    queue.increment('events_failed')
                    next_send = time.monotonic() + transport.backoff()
                    log.warning('batch_delivery_failed_retry_scheduled')
            stop.wait(0.25)

    def thread_failure(args):
        # Fatal errors are not swallowed: stop collectors, preserve queue and exit nonzero.
        failures.append(args.exc_value)
        log.error('worker_failed type=%s', args.exc_type.__name__)
        stop.set()
    old_hook = threading.excepthook
    threading.excepthook = thread_failure
    worker = threading.Thread(target=sender, name='siem-sender')
    stop_path = os.getenv('SIEM_STOP_FILE')
    def watch_stop():
        while not stop.wait(.25):
            if Path(stop_path).exists():
                stop.set()
    watcher = threading.Thread(target=watch_stop,name='local-stop-signal',daemon=True) if stop_path else None
    try:
        log.info('agent_started version=%s',VERSION)
        emit(n.event('telemetry.started', 'agent', raw_event={'version':VERSION}))
        files.start()
        if watcher:
            watcher.start()
        worker.start()
        while not stop.is_set():
            system.poll()
            files.poll()
            if config.windows_events:
                windows.poll()
            stop.wait(config.collection_interval)
    finally:
        stop.set()
        files.stop()
        if worker.ident:
            worker.join()
        if watcher and watcher.ident:
            watcher.join(2)
        transport.close()
        queue.close()
        threading.excepthook = old_hook
        log.info('agent_stopped')
    if failures:
        raise RuntimeError('agent worker failed; see structured log') from failures[0]

if __name__ == '__main__':
    run()
