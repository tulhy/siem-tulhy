"""Explicit administrator-only, transactional telemetry history deletion."""
import hmac
import logging
from typing import Literal
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete, select, update
from sqlalchemy.exc import SQLAlchemyError
from server.api.auth import admin, session
from server.models.tables import Agent, Alert, EventRow, RuleMatch

router = APIRouter()

class PurgeConfirmation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    confirmation: Literal['APAGAR EVENTOS E ALERTAS']

@router.post('/admin/emergency/purge-history', dependencies=[Depends(admin)])
def purge_history(body: PurgeConfirmation, request: Request, db=Depends(session),
                  emergency_token: str = Header(default='', alias='X-Emergency-Token')):
    expected = request.app.state.settings.admin_token
    if not emergency_token or len(emergency_token)>1024 or not hmac.compare_digest(emergency_token.encode(),expected.encode()):
        raise HTTPException(401, 'Digite novamente o token administrativo correto.')
    try:
        # Same locks as ingestion, detection and deletion; fixed order avoids
        # competing bulk operations acquiring agent locks in opposite orders.
        for agent_id in db.scalars(select(Agent.id).order_by(Agent.id)).all():
            db.execute(update(Agent).where(Agent.id==agent_id).values(last_seen=Agent.last_seen))
        counts={}
        for label,model in (('rule_matches',RuleMatch),('alerts',Alert),('events',EventRow)):
            counts[label]=db.execute(delete(model)).rowcount
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logging.getLogger('server.audit').error('emergency_purge_failed_transaction_rolled_back')
        raise HTTPException(503, 'Limpeza não concluída; transação revertida. Verifique a saúde do banco antes de tentar novamente.') from None
    logging.getLogger('server.audit').warning('emergency_history_purged events=%d alerts=%d rule_matches=%d',
        counts['events'],counts['alerts'],counts['rule_matches'])
    return {'deleted':counts, 'agents_preserved':True}
