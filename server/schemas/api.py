from pydantic import Field
from shared.events import Strict

class Register(Strict):
    hostname: str = Field(min_length=1, max_length=255)

class AgentUpdate(Strict):
    enabled: bool

class AgentDelete(Strict):
    confirm_name: str = Field(min_length=1, max_length=255)

class AlertUpdate(Strict):
    status: str = Field(pattern=r'^(active|resolved)$')

# Windows computer names; the same characters CRIAR_AGENTE accepts.
HOSTNAME = r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'

class EnrollmentCodeCreate(Strict):
    label: str = Field(default='', max_length=100)
    hours: int = Field(default=168, ge=1, le=720)
    max_uses: int = Field(default=50, ge=1, le=500)

class Enroll(Strict):
    secret: str = Field(min_length=16, max_length=64, pattern=r'^[A-Za-z0-9_-]+$')
    hostname: str = Field(pattern=HOSTNAME)
