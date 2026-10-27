"""History of exclusion changes and wrong tokens, plus the lockout after repeated wrong tokens."""
import time
from uuid import uuid4
from fastapi import HTTPException
from sqlalchemy import func, select
from server.models.tables import SecurityLog

MAX_FAILURES = 5
LOCK_SECONDS = 15 * 60
FAILURES = ('admin_token_failed', 'exclusion_token_failed')


def client_ip(request):
    return request.client.host if request.client else None


def record(request, action, detail=''):
    with request.app.state.sessions() as db:
        db.add(SecurityLog(id=str(uuid4()), timestamp=time.time(), ip=client_ip(request), action=action, detail=detail[:2000]))
        db.commit()


def recent_failures(db, ip, now):
    rows = select(func.count(), func.min(SecurityLog.timestamp)).where(
        SecurityLog.ip == ip, SecurityLog.action.in_(FAILURES), SecurityLog.timestamp >= now - LOCK_SECONDS)
    return db.execute(rows).one()


def refuse_if_locked(request):
    """After MAX_FAILURES wrong tokens from one address, that address waits LOCK_SECONDS (even with the right token)."""
    now = time.time()
    with request.app.state.sessions() as db:
        count, oldest = recent_failures(db, client_ip(request), now)
    if count >= MAX_FAILURES:
        wait = max(1, int(oldest + LOCK_SECONDS - now))
        raise HTTPException(429, f'Muitas tentativas com token errado deste computador. Aguarde {(wait + 59) // 60} minuto(s) e tente de novo.',
                            headers={'Retry-After': str(wait)})


def failed(request, action, label):
    with request.app.state.sessions() as db:
        count = recent_failures(db, client_ip(request), time.time())[0] + 1
    detail = label + (f' ({count}ª tentativa errada: computador bloqueado por {LOCK_SECONDS // 60} minutos)' if count == MAX_FAILURES else '')
    record(request, action, detail)
