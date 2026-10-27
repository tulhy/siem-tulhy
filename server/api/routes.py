from server.services.visibility import visible_events, visible_alerts
import secrets
import logging
import time
from uuid import uuid4
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, Depends, Request, Query, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy import select, func, or_, and_, case, update, delete
from shared.events import Event, Batch, Heartbeat
from shared.protocol import token_hash
from server.api.auth import admin, signed_agent, session
from server.models.tables import Agent, EventRow, Alert, HeartbeatRow, RuleRow, RuleMatch, Nonce, Baseline, EnrollmentCode
from server.schemas.api import Register, AgentUpdate, AgentDelete, AlertUpdate, EnrollmentCodeCreate, Enroll
from server.services.ingestion import ingest
from server.services.incident_counts import critical_occurrences

router = APIRouter(prefix='/api/v1')

def columns(row, exclude=()):
    return {c.name:getattr(row,c.name) for c in row.__table__.columns if c.name not in exclude}

@router.post('/agents/register', dependencies=[Depends(admin)])
def register(body: Register, db=Depends(session)):
    token = secrets.token_urlsafe(48)
    agent = Agent(id=str(uuid4()), hostname=body.hostname, token_hash=token_hash(token))
    db.add(agent)
    db.commit()
    return {'agent_id':agent.id, 'agent_token':token, 'hostname':agent.hostname}

ENROLL_REFUSED = 'invalid, expired or exhausted enrollment code'

@router.post('/enrollment-codes', dependencies=[Depends(admin)])
def create_enrollment_code(body: EnrollmentCodeCreate, db=Depends(session)):
    secret = secrets.token_urlsafe(16)  # 128 random bits; only its hash is stored
    code = EnrollmentCode(id=str(uuid4()), secret_hash=token_hash(secret), label=body.label,
                          expires_at=time.time()+body.hours*3600, max_uses=body.max_uses)
    db.add(code)
    db.commit()
    logging.getLogger('server.audit').warning('enrollment_code_created id=%s max_uses=%d hours=%d', code.id, body.max_uses, body.hours)
    return {'id':code.id, 'secret':secret, 'expires_at':code.expires_at, 'max_uses':code.max_uses}

@router.get('/enrollment-codes', dependencies=[Depends(admin)])
def list_enrollment_codes(db=Depends(session)):
    rows = db.scalars(select(EnrollmentCode).order_by(EnrollmentCode.created_at.desc()))
    return [columns(row, exclude=('secret_hash',)) for row in rows]

@router.delete('/enrollment-codes/{code_id}', dependencies=[Depends(admin)])
def revoke_enrollment_code(code_id: str, db=Depends(session)):
    code = db.get(EnrollmentCode, code_id)
    if not code:
        raise HTTPException(404, 'enrollment code not found')
    code.revoked = True
    db.commit()
    logging.getLogger('server.audit').warning('enrollment_code_revoked id=%s', code_id)
    return {'revoked':True}

@router.post('/agents/enroll')
def enroll(body: Enroll, db=Depends(session)):
    code = db.scalar(select(EnrollmentCode).where(EnrollmentCode.secret_hash == token_hash(body.secret)))
    if not code or code.revoked or code.expires_at <= time.time():
        raise HTTPException(401, ENROLL_REFUSED)
    # Conditional increment: concurrent installs can never exceed max_uses.
    taken = db.execute(update(EnrollmentCode).where(EnrollmentCode.id == code.id,
        EnrollmentCode.uses < EnrollmentCode.max_uses, EnrollmentCode.revoked.is_(False))
        .values(uses=EnrollmentCode.uses + 1)).rowcount
    if not taken:
        db.rollback()
        raise HTTPException(401, ENROLL_REFUSED)
    token = secrets.token_urlsafe(48)
    agent = Agent(id=str(uuid4()), hostname=body.hostname, token_hash=token_hash(token))
    db.add(agent)
    db.commit()
    logging.getLogger('server.audit').warning('agent_enrolled agent_id=%s code_id=%s', agent.id, code.id)
    return {'agent_id':agent.id, 'agent_token':token, 'hostname':agent.hostname}

@router.get('/ca')
def ca_certificate(request: Request):
    """Public CA certificate only; agents accept it only if it matches their code's fingerprint."""
    path = request.app.state.settings.ca_file
    text = Path(path).read_text(encoding='ascii') if path and Path(path).is_file() else ''
    if 'BEGIN CERTIFICATE' not in text or 'PRIVATE KEY' in text:
        raise HTTPException(404, 'CA certificate not published')
    return PlainTextResponse(text, media_type='application/x-pem-file')

@router.patch('/agents/{agent_id}', dependencies=[Depends(admin)])
def agent_update(agent_id: str, body: AgentUpdate, db=Depends(session)):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(404,'agent not found')
    agent.enabled = body.enabled
    db.commit()
    return {'enabled':agent.enabled}

@router.post('/agents/{agent_id}/rotate-token', dependencies=[Depends(admin)])
def rotate(agent_id: str, db=Depends(session)):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(404,'agent not found')
    token = secrets.token_urlsafe(48)
    agent.token_hash = token_hash(token)
    db.commit()
    return {'agent_token':token}

@router.delete('/agents/{agent_id}', dependencies=[Depends(admin)])
def delete_agent(agent_id: str, body: AgentDelete, db=Depends(session)):
    # Use the same per-agent write lock as ingestion and detection. Everything
    # below commits atomically; no partial deletion on failure.
    locked = db.execute(update(Agent).where(Agent.id == agent_id).values(last_seen=Agent.last_seen))
    if not locked.rowcount:
        raise HTTPException(404, 'agent not found')
    agent = db.get(Agent, agent_id)
    if body.confirm_name != agent.hostname:
        raise HTTPException(409, 'confirmation name does not match')
    removed = {}
    for model in (RuleMatch, Alert, HeartbeatRow, Nonce, Baseline, EventRow):
        result = db.execute(delete(model).where(model.agent_id == agent_id))
        removed[model.__tablename__] = result.rowcount
    db.delete(agent)
    db.commit()
    logging.getLogger('server.audit').warning('agent_deleted agent_id=%s removed=%s', agent_id, removed)
    return {'deleted':agent_id, 'removed':removed}

@router.post('/events')
def post_event(event: Event, request: Request, agent=Depends(signed_agent), db=Depends(session)):
    return ingest(db, agent, [event], request.app.state.settings)

@router.post('/events/batch')
def post_batch(batch: Batch, request: Request, agent=Depends(signed_agent), db=Depends(session)):
    return ingest(db, agent, batch.events, request.app.state.settings)

@router.post('/agents/heartbeat')
def heartbeat(body: Heartbeat, agent=Depends(signed_agent), db=Depends(session)):
    if body.hostname != agent.hostname:
        raise HTTPException(403,'hostname differs from registration')
    agent.os, agent.version, agent.pending = body.os, body.version, body.pending
    agent.metrics = body.metrics
    agent.last_heartbeat = time.time()
    agent.telemetry_lost = False
    db.add(HeartbeatRow(id=str(uuid4()), agent_id=agent.id, pending=body.pending, metrics=body.metrics))
    for alert in db.scalars(select(Alert).where(Alert.agent_id==agent.id, Alert.rule_id=='TELEMETRY_LOST', Alert.status=='active')):
        alert.status = 'resolved'
    db.commit()
    return {'ok':True}

@router.get('/agents', dependencies=[Depends(admin)])
def agents(request: Request, db=Depends(session), offset: int=Query(0,ge=0), limit: int=Query(100,ge=1,le=500)):
    result = []
    for agent in db.scalars(select(Agent).order_by(Agent.hostname).offset(offset).limit(limit)):
        value = columns(agent, ('token_hash','rate_window','rate_count'))
        value['status'] = 'disabled' if not agent.enabled else ('online' if agent.last_heartbeat and time.time()-agent.last_heartbeat < request.app.state.settings.heartbeat_timeout else 'offline')
        result.append(value)
    return result

def displayed_event_severity():
    from server.detection.ignored_network_ips import ignored_network_sql
    from server.detection.http_exceptions import http_exception_sql
    # Read-time classification also covers historical events without rewriting their
    # signed payload/hash, which must remain stable for offline retry idempotency.
    state = EventRow.body['raw_event']
    disabled = or_(EventRow.event_type == 'antivirus.protection_disabled',
        and_(EventRow.event_type == 'antivirus.status',
             or_(state['realtime_enabled'].as_boolean().is_(False),
                 state['antivirus_enabled'].as_boolean().is_(False))))
    file_data = EventRow.body['file']
    path, destination = func.lower(file_data['path'].as_string()), func.lower(file_data['destination'].as_string())
    file_policy = and_(state['directory'].as_boolean().is_(False), or_(
        and_(EventRow.event_type.in_(['file.present','file.created','file.modified','file.moved']),
             or_(path.endswith('.vbs'), path.endswith('.htm'))),
        and_(EventRow.event_type == 'file.moved',
             or_(destination.endswith('.vbs'), destination.endswith('.htm')))))
    sensitive_listener = and_(EventRow.event_type.in_(['network.listen','network.bind']),
        EventRow.local_port.in_([3389,4444,22,23,137,138,139,445,20,21,3306,1433,5432,31337,6660,6669]))
    inbound_medium = and_(EventRow.event_type == 'network.connection',
        state['direction'].as_string() == 'inbound', EventRow.local_port == 64668)
    executable = func.lower(EventRow.body['process']['path'].as_string())
    suspicious_remote = and_(EventRow.event_type == 'network.connection',
        func.lower(EventRow.body['network']['protocol'].as_string()) == 'tcp',
        EventRow.port == 4444, EventRow.ip.is_not(None),
        or_(*(executable.contains(part) for part in ('\\downloads\\','/downloads/','\\temp\\','/temp/'))))
    possible_http = and_(EventRow.event_type == 'network.connection',
        ~http_exception_sql(),
        func.lower(EventRow.body['network']['protocol'].as_string()) == 'tcp',
        EventRow.port.in_([80,8080]),
        or_(state['direction'].as_string().is_(None),
            func.lower(state['direction'].as_string()).in_(['outbound','unknown'])))
    return case((ignored_network_sql(), EventRow.severity), (EventRow.event_type == 'antivirus.detected', 'CRITICAL'),
                (suspicious_remote, 'CRITICAL'),
                (file_policy, 'CRITICAL'),
                (and_(EventRow.severity.in_(['LOW','MEDIUM']), possible_http), 'HIGH'),
                (and_(EventRow.severity.in_(['LOW','MEDIUM']), sensitive_listener), 'HIGH'),
                (and_(EventRow.severity.in_(['LOW','MEDIUM']), disabled), 'HIGH'),
                (and_(EventRow.severity == 'LOW', inbound_medium), 'MEDIUM'),
                (and_(EventRow.severity == 'HIGH', EventRow.event_type == 'telemetry.integrity'), 'MEDIUM'),
                else_=EventRow.severity)


def displayed_event(row, severity):
    result = dict(row.body, severity=severity, detection_status=row.detection_status,
                  received_at=row.received_at, reported_severity=row.body.get('severity', row.severity))
    if severity != row.severity:
        if row.event_type == 'antivirus.detected':
            reason = 'Detecção informada pelo antivírus; classificação CRITICAL pela política de prioridade da organização.'
        elif row.event_type.startswith('file.'):
            reason = 'Extensão .vbs ou .htm observada; classificação CRITICAL pela política da organização. A extensão sozinha não comprova malware.'
        elif row.event_type in ('network.listen','network.bind'):
            reason = 'Porta local da lista de atenção elevada observada em escuta ou vinculada; classificação HIGH pela política da organização.'
        elif row.event_type == 'network.connection':
            reason = ('Programa em Downloads ou pasta temporária com conexão TCP à porta remota 4444; prioridade CRITICAL por política. A direção pode ser desconhecida e a combinação exige investigação.'
                      if severity == 'CRITICAL' else
                      'Possível HTTP: conexão TCP à porta remota 80 ou 8080; prioridade HIGH pela política. Não confirma página acessada, conteúdo sem criptografia ou ausência de redirecionamento para HTTPS.'
                      if severity == 'HIGH' else 'Conexão de entrada na porta local 64668; classificação MEDIUM pela política da organização.')
        elif row.event_type == 'telemetry.integrity':
            reason = 'Limitação de coleta informada pelo agente como HIGH; classificação MEDIUM pela política da organização.'
        else:
            reason = 'Proteção do Defender informada como desativada neste registro; classificação elevada pelo servidor para HIGH.'
        result['severity_reason'] = reason
    from server.detection.ignored_network_ips import ignored_network_event
    if ignored_network_event(row.body):
        result['network_alerts_ignored'] = True
        result['exclusion_reason'] = 'IP remoto excluido dos alertas de rede por politica administrativa; evento original preservado.'
    if row.detection_status == 'excluded':
        result['excluded_by_policy'] = True
        from server.services.host_path_exclusions import matching_exclusion
        current = matching_exclusion(None, row.body)
        motive = f' Motivo: {current.description}' if current is not None and current.description else ''
        result['exclusion_reason'] = 'Ignorado por uma exclusao configurada no painel: guardado, mas nao gera alerta.' + motive
    return result


@router.get('/events', dependencies=[Depends(admin)])
def events(db=Depends(session), start: datetime | None=None, end: datetime | None=None,
           agent_id: str | None=None, hostname: str | None=None, user: str | None=None,
           event_type: str | None=None, severity: str | None=None, process: str | None=None,
           sha256: str | None=None, ip: str | None=None, port: int | None=Query(None,ge=0,le=65535),
           detection_status: str | None=None, offset: int=Query(0,ge=0), limit: int=Query(100,ge=1,le=500)):
    classification = displayed_event_severity()
    query = select(EventRow, classification).where(visible_events())
    for key, value in {'agent_id':agent_id,'hostname':hostname,'user':user,'event_type':event_type,
                       'process':process,'sha256':sha256,'detection_status':detection_status}.items():
        if value is not None:
            query = query.where(getattr(EventRow,key)==value)
    if severity is not None:
        query = query.where(classification == severity)
    if ip:
        query = query.where(or_(EventRow.ip==ip, EventRow.local_ip==ip))
    if port is not None:
        query = query.where(or_(EventRow.port==port, EventRow.local_port==port))
    if start:
        if not start.tzinfo:
            raise HTTPException(422,'start requires timezone')
        query = query.where(EventRow.timestamp>=start.timestamp())
    if end:
        if not end.tzinfo:
            raise HTTPException(422,'end requires timezone')
        query = query.where(EventRow.timestamp<=end.timestamp())
    return [displayed_event(r, level) for r, level in db.execute(query.order_by(EventRow.timestamp.desc(),EventRow.id).offset(offset).limit(limit))]

@router.get('/agents/{agent_id}/protection', dependencies=[Depends(admin)])
def agent_protection(agent_id: str, db=Depends(session)):
    agent=db.get(Agent,agent_id)
    if agent is None:
        raise HTTPException(404,'agent not found')
    row=db.scalar(select(EventRow).where(EventRow.agent_id==agent_id,EventRow.event_type=='antivirus.status').order_by(EventRow.timestamp.desc(),EventRow.id).limit(1))
    return {'agent_id':agent.id,'version':agent.version,'collection_enabled':agent.enabled,
            'observed_at':row.timestamp if row else None,
            'stale':not row or time.time()-row.timestamp>900,
            'status':row.body.get('raw_event',{}) if row else None}

@router.get('/alerts', dependencies=[Depends(admin)])
def alerts(db=Depends(session), status: str | None=None, severity: str | None=None, agent_id: str | None=None,
           offset: int=Query(0,ge=0), limit: int=Query(100,ge=1,le=500)):
    query = select(Alert).where(visible_alerts())
    for key, value in {'status':status,'severity':severity,'agent_id':agent_id}.items():
        if value:
            query = query.where(getattr(Alert,key)==value)
    rows = list(db.scalars(query.order_by(Alert.created_at.desc(), Alert.id).offset(offset).limit(limit)))
    occurrences = critical_occurrences(db, rows)
    names = dict(db.execute(select(Agent.id, Agent.hostname).where(Agent.id.in_({row.agent_id for row in rows}))).all())
    result = []
    for row in rows:
        result.append(dict(columns(row), hostname=names[row.agent_id], **occurrences.get(row.id, {})))
    return result

@router.get('/alerts/{alert_id}', dependencies=[Depends(admin)])
def alert_detail(alert_id: str, db=Depends(session)):
    row = db.get(Alert, alert_id)
    if not row or db.scalar(select(Alert.id).where(Alert.id==alert_id,visible_alerts())) is None:
        raise HTTPException(404,'alert not found')
    related = db.execute(select(EventRow, displayed_event_severity()).where(EventRow.id.in_(row.event_ids), visible_events()))
    return dict(columns(row), hostname=db.get(Agent,row.agent_id).hostname,
                **critical_occurrences(db, [row]).get(row.id, {}),
                events=[displayed_event(e, level) for e, level in related])

@router.patch('/alerts/{alert_id}', dependencies=[Depends(admin)])
def alert_update(alert_id: str, body: AlertUpdate, db=Depends(session)):
    row = db.get(Alert, alert_id)
    if not row:
        raise HTTPException(404,'alert not found')
    row.status = body.status
    db.commit()
    return {'status':row.status}

@router.get('/rules', dependencies=[Depends(admin)])
def rules(db=Depends(session)):
    return [columns(r) for r in db.scalars(select(RuleRow))]

@router.get('/dashboard/stats', dependencies=[Depends(admin)])
def stats(request: Request, db=Depends(session)):
    now = time.time()
    count = lambda model, *filters: db.scalar(select(func.count()).select_from(model).where(*filters, *([visible_events()] if model is EventRow else [visible_alerts()] if model is Alert else [])))
    def grouped(field):
        return [{'name':key,'value':value} for key,value in db.execute(select(field,func.count()).where(visible_events(), EventRow.timestamp>=now-86400).group_by(field))]
    online = count(Agent, Agent.enabled.is_(True),Agent.last_heartbeat>=now-request.app.state.settings.heartbeat_timeout)
    total = count(Agent)
    # Fixed 24 buckets use DB aggregation; no full event-body scans.
    bucket = func.floor((EventRow.timestamp-(now-86400))/3600)
    hourly = dict(db.execute(select(bucket,func.count()).where(visible_events(), EventRow.timestamp>=now-86400,EventRow.timestamp<=now).group_by(bucket)).all())
    machines = [{'name':name,'value':value} for name,value in db.execute(select(Agent.hostname,func.count(Alert.id)).join(Alert,Alert.agent_id==Agent.id).where(visible_alerts()).group_by(Agent.hostname).order_by(func.count(Alert.id).desc()).limit(10))]
    return {'agents_total':total,'agents_online':online,'agents_offline':count(Agent,Agent.enabled.is_(True))-online,
        'events_24h':count(EventRow,EventRow.timestamp>=now-86400),'alerts_active':count(Alert,Alert.status=='active'),
        'alerts_critical':count(Alert,Alert.status=='active',Alert.severity=='CRITICAL'),
        'by_severity':grouped(displayed_event_severity()),'by_type':grouped(EventRow.event_type),'top_machines':machines,
        'timeline':[{'name':str(i),'value':hourly.get(i,0)} for i in range(24)]}

@router.get('/metrics', dependencies=[Depends(admin)])
def metrics(db=Depends(session)):
    return {'events_processed':db.scalar(select(func.count()).select_from(EventRow).where(EventRow.processed_at.is_not(None))),
        'events_detection_pending':db.scalar(select(func.count()).select_from(EventRow).where(EventRow.processed_at.is_(None))),
        'alerts_generated':db.scalar(select(func.count()).select_from(Alert)),
        'agents':[{**a.metrics,'agent_id':a.id,'agent_last_seen':a.last_seen} for a in db.scalars(select(Agent))]}


@router.post('/alerts/{alert_id}/complete', dependencies=[Depends(admin)])
def alert_complete(alert_id: str, db=Depends(session)):
    row = db.get(Alert, alert_id)
    if not row:
        raise HTTPException(404, 'alert not found')
    agent_id, rule_id = row.agent_id, row.rule_id
    # Share ingestion/detection's per-agent lock, including on SQLite. A later
    # detection transaction is a new occurrence and must remain visible.
    db.execute(update(Agent).where(Agent.id == agent_id).values(last_seen=Agent.last_seen))
    row = db.get(Alert, alert_id, populate_existing=True)
    if not row:
        raise HTTPException(404, 'alert already completed')
    scope = select(Alert.id).where(Alert.agent_id == agent_id, Alert.rule_id == rule_id)
    db.execute(delete(RuleMatch).where(RuleMatch.alert_id.in_(scope)))
    removed = db.execute(delete(Alert).where(Alert.agent_id == agent_id, Alert.rule_id == rule_id)).rowcount
    db.commit()
    logging.getLogger('server.alerts').info('alerts_completed agent_id=%s rule_id=%s removed=%d',agent_id,rule_id,removed)
    return {'status':'completed','deleted_alerts':removed,'events_preserved':True,
            'agent_id':agent_id,'rule_id':rule_id}


from server.api.emergency import router as emergency_router
router.include_router(emergency_router)
