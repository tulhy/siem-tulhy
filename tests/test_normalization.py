from uuid import uuid4
import pytest
from pydantic import ValidationError
from agent.normalizers import Normalizer
from shared.events import Event

def test_normalize_and_redact():
    n = Normalizer(uuid4(), 'test', True)
    e = n.event('process.start', 'test', process={'name':'safe.exe', 'command_line':'safe --password=hello token abc'})
    assert 'hello' not in e.process.command_line and 'abc' not in e.process.command_line
    assert Event.model_validate_json(e.model_dump_json()) == e
    assert n.event('process.start', 'test').event_id != e.event_id

def test_private_defaults_and_validation():
    n = Normalizer(uuid4(), 'test')
    assert n.event('process.start', 'test', process={'command_line':'secret'}).process.command_line is None
    with pytest.raises(ValidationError):
        n.event('network.connection', 'test', network={'remote_port':99999})
    with pytest.raises(ValidationError):
        n.event('process.start', 'test', timestamp='2026-01-01T00:00:00')
