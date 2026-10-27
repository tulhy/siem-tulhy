"""All collectors produce the shared schema through Normalizer."""
import re
from shared.events import Event

# Command lines can contain arbitrary secrets. They are opt-in, with best-effort redaction.
SECRET = re.compile(r'(?i)((?:password|passwd|pwd|token|secret|api[_-]?key|authorization)[\s=:]+)(?:"[^"]*"|\S+)')
URL_AUTH = re.compile(r'(https?://)[^/@\s]+:[^/@\s]+@', re.I)

def redact(text):
    return URL_AUTH.sub(r'\1[REDACTED]@', SECRET.sub(r'\1[REDACTED]', text))[:4096]

class Normalizer:
    def __init__(self, agent_id, hostname, command_lines=False):
        self.agent_id, self.hostname, self.command_lines = agent_id, hostname, command_lines

    def event(self, event_type, source, **fields):
        if fields.get('process'):
            process = dict(fields['process'])
            line = process.get('command_line')
            process['command_line'] = redact(line) if line and self.command_lines else None
            fields['process'] = process
        return Event(agent_id=self.agent_id, hostname=self.hostname,
                     event_type=event_type, source=source, **fields)
