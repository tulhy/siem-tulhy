from sqlalchemy import String, Integer, Float, Text, Boolean, JSON, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from shared.events import utcnow

def epoch():
    return utcnow().timestamp()

class Base(DeclarativeBase):
    """SQLAlchemy metadata root."""

class Agent(Base):
    __tablename__ = 'agents'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64))
    hostname: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    os: Mapped[str] = mapped_column(String(255), default='unknown')
    version: Mapped[str] = mapped_column(String(32), default='unknown')
    ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[float] = mapped_column(Float, default=epoch)
    last_seen: Mapped[float] = mapped_column(Float, default=epoch, index=True)
    last_heartbeat: Mapped[float | None] = mapped_column(Float, index=True)
    pending: Mapped[int] = mapped_column(Integer, default=0)
    rate_window: Mapped[int] = mapped_column(Integer, default=0)
    rate_count: Mapped[int] = mapped_column(Integer, default=0)
    telemetry_lost: Mapped[bool] = mapped_column(Boolean, default=False)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)

class EventRow(Base):
    __tablename__ = 'events'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey('agents.id'), index=True)
    timestamp: Mapped[float] = mapped_column(Float, index=True)
    received_at: Mapped[float] = mapped_column(Float, default=epoch, index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    user: Mapped[str | None] = mapped_column(String(255), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    process: Mapped[str | None] = mapped_column(String(4096), index=True)
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    ip: Mapped[str | None] = mapped_column(String(64), index=True)
    local_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    port: Mapped[int | None] = mapped_column(Integer, index=True)
    local_port: Mapped[int | None] = mapped_column(Integer, index=True)
    detection_status: Mapped[str] = mapped_column(String(16), default='pending', index=True)
    processed_at: Mapped[float | None] = mapped_column(Float, index=True)
    body_hash: Mapped[str] = mapped_column(String(64))
    body: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (Index('ix_event_agent_time', 'agent_id','timestamp'),)

class RuleRow(Base):
    __tablename__ = 'rules'
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    definition: Mapped[dict] = mapped_column(JSON)
    enabled: Mapped[bool] = mapped_column(Boolean)

class Alert(Base):
    __tablename__ = 'alerts'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey('agents.id'), index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16))
    risk_score: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[float] = mapped_column(Float, default=epoch, index=True)
    user: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default='active', index=True)
    event_ids: Mapped[list] = mapped_column(JSON)
    evidence: Mapped[dict] = mapped_column(JSON)
    dedup_key: Mapped[str] = mapped_column(String(64), unique=True)

class RuleMatch(Base):
    __tablename__ = 'rule_matches'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey('agents.id'), index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    event_id: Mapped[str] = mapped_column(ForeignKey('events.id'), index=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey('alerts.id'))
    timestamp: Mapped[float] = mapped_column(Float, index=True)
    score: Mapped[int] = mapped_column(Integer)
    __table_args__ = (UniqueConstraint('rule_id','event_id'),)

class HeartbeatRow(Base):
    __tablename__ = 'heartbeats'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey('agents.id'), index=True)
    timestamp: Mapped[float] = mapped_column(Float, default=epoch, index=True)
    pending: Mapped[int] = mapped_column(Integer)
    metrics: Mapped[dict] = mapped_column(JSON)

class Nonce(Base):
    __tablename__ = 'nonces'
    agent_id: Mapped[str] = mapped_column(ForeignKey('agents.id'), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(36), primary_key=True)
    expires: Mapped[float] = mapped_column(Float, index=True)

class Baseline(Base):
    __tablename__ = 'baselines'
    agent_id: Mapped[str] = mapped_column(ForeignKey('agents.id'), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), primary_key=True)
    value: Mapped[str] = mapped_column(String(128), primary_key=True)
    first_seen: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float)
    count: Mapped[int] = mapped_column(Integer, default=1)

class EnrollmentCode(Base):
    """Limited code that lets a new machine register itself; only its SHA-256 is stored."""
    __tablename__ = 'enrollment_codes'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    secret_hash: Mapped[str] = mapped_column(String(64), unique=True)
    label: Mapped[str] = mapped_column(String(100), default='')
    created_at: Mapped[float] = mapped_column(Float, default=epoch)
    expires_at: Mapped[float] = mapped_column(Float)
    max_uses: Mapped[int] = mapped_column(Integer)
    uses: Mapped[int] = mapped_column(Integer, default=0)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

class SecurityLog(Base):
    """Append-only history of exclusion changes and wrong tokens; the panel has no way to delete it."""
    __tablename__ = 'security_log'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp: Mapped[float] = mapped_column(Float, default=epoch, index=True)
    ip: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(40))
    detail: Mapped[str] = mapped_column(Text, default='')
    __table_args__ = (Index('ix_security_log_ip_action_time', 'ip', 'action', 'timestamp'),)
