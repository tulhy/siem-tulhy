"""Versioned, bounded event schema. Raw data contains metadata only."""
import json
from datetime import datetime, timezone
from typing import Literal, Annotated
from uuid import UUID, uuid4
from pydantic import BaseModel, ConfigDict, Field, AwareDatetime, field_validator

Severity = Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

def utcnow():
    return datetime.now(timezone.utc)

class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', str_max_length=4096, allow_inf_nan=False)

class Process(Strict):
    name: str | None = Field(default=None, max_length=255)
    pid: int | None = Field(default=None, ge=0)
    ppid: int | None = Field(default=None, ge=0)
    path: str | None = None
    command_line: str | None = None
    sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')
    created_at: float | None = None

class Network(Strict):
    local_ip: str | None = None
    remote_ip: str | None = None
    local_port: int | None = Field(default=None, ge=0, le=65535)
    remote_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Literal['TCP', 'UDP'] | None = None
    @field_validator('local_ip', 'remote_ip')
    @classmethod
    def valid_ip(cls, value):
        if value:
            from ipaddress import ip_address
            ip_address(value.split('%')[0])
        return value

class File(Strict):
    path: str
    destination: str | None = None
    sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')

class Event(Strict):
    schema_version: Literal[1] = 1
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: AwareDatetime = Field(default_factory=utcnow)
    agent_id: UUID
    hostname: str = Field(min_length=1, max_length=255)
    event_type: str = Field(pattern=r'^[a-z][a-z0-9_.]{1,63}$')
    severity: Severity = 'LOW'
    source: str = Field(min_length=1, max_length=128)
    process: Process | None = None
    network: Network | None = None
    file: File | None = None
    user: str | None = Field(default=None, max_length=255)
    raw_event: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    @field_validator('raw_event')
    @classmethod
    def bounded_metadata(cls, value):
        if len(value) > 32 or len(json.dumps(value).encode()) > 8192:
            raise ValueError('metadata too large')
        return value

class Batch(Strict):
    events: list[Event] = Field(min_length=1, max_length=200)

class Heartbeat(Strict):
    hostname: str = Field(min_length=1, max_length=255)
    version: str = Field(max_length=32)
    os: str = Field(max_length=255)
    pending: int = Field(ge=0)
    metrics: dict[Literal['events_collected','events_sent','events_failed','events_pending','events_dropped_capacity','loss_unreported'], Annotated[int,Field(ge=0)]] = Field(default_factory=dict)
