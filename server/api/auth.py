import hmac
import time
from uuid import UUID
from fastapi import Request, HTTPException, Depends
from sqlalchemy import update, delete
from shared.protocol import token_hash, signature
from server.models.tables import Agent, Nonce

def session(request: Request):
    with request.app.state.sessions() as db:
        yield db

def bearer(request):
    value = request.headers.get('authorization', '')
    if not value.startswith('Bearer ') or len(value) > 1024:
        raise HTTPException(401, 'authentication required')
    return value[7:]

def admin(request: Request):
    from server.api.security_log import refuse_if_locked, failed
    refuse_if_locked(request)
    if not hmac.compare_digest(bearer(request).encode(), request.app.state.settings.admin_token.encode()):
        failed(request, 'admin_token_failed', 'Token de administrador incorreto')
        raise HTTPException(401, 'invalid credential')

def signed_agent(request: Request, db=Depends(session)):
    token = bearer(request)
    try:
        agent_id = str(UUID(request.headers['x-agent-id']))
        nonce = str(UUID(request.headers['x-nonce']))
        timestamp = request.headers['x-timestamp']
        request_time = int(timestamp)
    except (KeyError, ValueError):
        raise HTTPException(401, 'invalid authentication headers') from None
    settings, now = request.app.state.settings, time.time()
    if abs(now - request_time) > settings.replay_window:
        raise HTTPException(401, 'request timestamp outside allowed window')
    agent = db.get(Agent, agent_id)
    if not agent or not agent.enabled or not hmac.compare_digest(agent.token_hash, token_hash(token)):
        raise HTTPException(401, 'invalid credential')
    expected = signature(token, request.method, request.url.path, timestamp, nonce, request.state.wire_body)
    if not hmac.compare_digest(expected.encode(), request.headers.get('x-signature','').encode()):
        raise HTTPException(401, 'invalid signature')
    # Serialize agent writes across workers, including idempotency/correlation/rate counters.
    locked = db.execute(update(Agent).where(Agent.id == agent_id).values(last_seen=Agent.last_seen))
    if not locked.rowcount:
        raise HTTPException(401, 'credential revoked')
    db.refresh(agent)
    if not agent.enabled or not hmac.compare_digest(agent.token_hash,token_hash(token)):
        raise HTTPException(401,'credential revoked')
    db.execute(delete(Nonce).where(Nonce.expires < now))
    if db.get(Nonce, (agent_id, nonce)):
        raise HTTPException(409, 'replayed request')
    minute = int(now // 60)
    if agent.rate_window != minute:
        agent.rate_window, agent.rate_count = minute, 0
    if agent.rate_count >= settings.requests_per_minute:
        raise HTTPException(429, 'agent rate limit', headers={'Retry-After':'60'})
    agent.rate_count += 1
    agent.last_seen = now
    agent.ip = request.client.host if request.client else None
    db.add(Nonce(agent_id=agent_id, nonce=nonce, expires=request_time + settings.replay_window + 1))
    return agent
