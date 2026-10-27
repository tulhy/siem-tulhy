import logging
import os
import threading
import time
from sqlalchemy.exc import SQLAlchemyError
from server.services.telemetry import check_telemetry

log = logging.getLogger('server.worker')

class Worker:
    def __init__(self, sessions, engine, settings):
        self.sessions, self.engine, self.settings = sessions, engine, settings
        self.stop_event = threading.Event()
        self.last_success = time.time()
        self.database_errors = 0
        self.detection_interval = float(os.getenv('SIEM_DETECTION_INTERVAL','300'))
        if not 1 <= self.detection_interval <= 3600:
            raise ValueError('SIEM_DETECTION_INTERVAL must be between 1 and 3600 seconds')
        self.thread = threading.Thread(target=self.run, name='detection-worker', daemon=True)

    def run(self):
        next_monitor = 0
        next_detection = time.monotonic() + self.detection_interval
        while not self.stop_event.is_set():
            try:
                count = 0
                if time.monotonic() >= next_detection:
                    count = self.engine.process_pending(self.sessions)
                    next_detection = time.monotonic() + (2 if count >= 100 else self.detection_interval)
                now = time.time()
                if now >= next_monitor:
                    lost = check_telemetry(self.sessions,self.settings)
                    if lost:
                        log.warning('telemetry_loss_alerts_generated count=%d',lost)
                    next_monitor = now + self.settings.monitor_interval
                self.last_success = now
                if count:
                    log.info('events_processed count=%d',count)
            except SQLAlchemyError:
                # Transactions roll back. Pending events remain retryable.
                self.database_errors += 1
                log.error('database_operation_failed_pending_events_preserved')
                self.stop_event.wait(5)
                continue
            self.stop_event.wait(1)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=60)
        if self.thread.is_alive():
            raise RuntimeError('detection worker failed to stop')

    def healthy(self):
        return self.thread.is_alive() and time.time()-self.last_success<120
