"""Logs accept constant messages and non-sensitive numeric/error-code metadata."""
import json
import logging
from logging.handlers import RotatingFileHandler
from shared.events import utcnow

class JsonFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({'time': utcnow().isoformat(), 'level': record.levelname,
                           'component': record.name, 'message': record.getMessage()}, ensure_ascii=False)

def configure(level='INFO', path=None):
    handler = RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, encoding='utf-8') if path else logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logging.basicConfig(level=level, handlers=[handler], force=True)
    for name in ('uvicorn','uvicorn.error'):
        for existing in logging.getLogger(name).handlers:
            existing.setFormatter(JsonFormatter())
    for name in ('httpx', 'httpcore', 'uvicorn.access'):
        logging.getLogger(name).setLevel(logging.WARNING)
