"""Panel management of exclusions (folders, extensions, programs, remote IPs). Administrator only."""
from datetime import datetime, timedelta, timezone
import hmac
import time
import logging
from typing import Literal
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import func, select
from server.api.auth import admin, session
from server.api.security_log import FAILURES, failed, record
from server.models.tables import Agent, Alert, EventRow, SecurityLog

def exclusion_token(request: Request):
    """Besides the administrator token, the exclusions tab requires its own secret (X-Exclusion-Token)."""
    expected = request.app.state.settings.exclusion_token
    if not expected:
        raise HTTPException(503, 'Token de exclusao nao configurado no servidor. Reinicie o SIEM para gera-lo.')
    given = request.headers.get('x-exclusion-token', '')
    if len(given) > 1024 or not hmac.compare_digest(given.encode(), expected.encode()):
        failed(request, 'exclusion_token_failed', 'Token de exclusão incorreto')
        raise HTTPException(403, 'Token de exclusao incorreto.')


router = APIRouter(prefix='/api/v1/exclusions', dependencies=[Depends(admin), Depends(exclusion_token)])
SECTIONS = {'folder':'path_exclusions', 'extension':'extension_exclusions', 'program':'process_exclusions'}
KINDS = {'path_exclusions':'folder', 'extension_exclusions':'extension', 'process_exclusions':'program'}
MATCH_KIND = {'folder':'path', 'extension':'extension', 'program':'process'}
DEFAULT_KEEP = {'folder':True, 'extension':True, 'program':False}  # programs are noisy: discard by default
ALL = '*'


class NewExclusion(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['folder', 'extension', 'program']
    value: str = Field(min_length=1, max_length=1024)
    machine: str = Field(min_length=1, max_length=255)  # '*' = every machine
    keep_events: bool | None = None
    description: str = Field(default='', max_length=500)
    days: int | None = Field(default=None, ge=1, le=365)  # None = no end date


class Change(BaseModel):
    """Enable/disable, or renew the validity (renew_days: 0 = no end date)."""
    model_config = ConfigDict(extra='forbid')
    enabled: bool | None = None
    renew_days: int | None = Field(default=None, ge=0, le=365)


class RemoteIps(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ips: list[str] = Field(min_length=1, max_length=500)


def friendly(error):
    if isinstance(error, ValidationError):
        messages = [str(item.get('msg', '')).removeprefix('Value error, ') for item in error.errors()]
        return '; '.join(dict.fromkeys(messages))
    return str(error)


def edit(change):
    from server.services.policy_files import edit_alert_policy
    try:
        return edit_alert_policy(change)
    except ValueError as error:  # ValidationError is a ValueError: nothing was written
        raise HTTPException(422, friendly(error)) from None


def with_ids(data):
    for section in SECTIONS.values():
        for item in data.get(section) or []:
            item.setdefault('id', uuid4().hex[:12])


def scope(item):
    if item.get('all_agents') or (item.get('agent_ip') is None and item.get('agent_name') is None):
        return 'Todas as máquinas'
    return item.get('agent_name') or 'IP ' + item['agent_ip']


KIND_NAMES = {'folder':'pasta', 'extension':'extensão', 'program':'programa'}


def value_of(item):
    return ', '.join(item.get('extensions') or item.get('paths') or [])


def until(days):
    return None if not days else (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec='seconds')


def moment(value):
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def validity(item):
    return f'vale até {moment(item["expires_at"]).astimezone().strftime("%d/%m/%Y %H:%M")}' if item.get('expires_at') else 'sem prazo'


def described(section, item):
    return f'{KIND_NAMES[KINDS[section]]} "{value_of(item)}" ({scope(item)})'


def status(item, now):
    if not item.get('enabled', True):
        return 'disabled'
    if item.get('expires_at') and moment(item['expires_at']) <= now:
        return 'expired'
    return 'active'


def listing(data):
    rows, now = [], datetime.now(timezone.utc)
    for section, kind in KINDS.items():
        for item in data.get(section) or []:
            rows.append({'id':item.get('id'), 'kind':kind, 'value':value_of(item), 'machine':scope(item),
                         'keep_events':item.get('keep_events', False), 'enabled':item.get('enabled', True),
                         'description':item.get('description', ''), 'created_at':item.get('created_at'),
                         'expires_at':item.get('expires_at'), 'status':status(item, now)})
    return rows


def machine_scope(db, machine):
    if machine.strip() == ALL:
        return {'all_agents':True}
    names = {name.casefold():name for name in db.scalars(select(Agent.hostname))}
    name = names.get(machine.strip().casefold())
    if name is None:
        raise HTTPException(422, f'Maquina "{machine}" nao encontrada no painel. Use o nome exato da aba Agentes.')
    return {'agent_name':name}


def entry_for(body, db):
    value = body.value.strip()
    if body.kind == 'extension':
        extensions = [part.strip().casefold() for part in value.replace(';', ',').replace(' ', ',').split(',') if part.strip()]
        target = {'extensions':['.'+e.lstrip('.') for e in extensions]}
    else:
        target = {'paths':[value.rstrip('\\') if body.kind == 'folder' and len(value) > 3 else value]}
    keep = DEFAULT_KEEP[body.kind] if body.keep_events is None else body.keep_events
    return {'id':uuid4().hex[:12], **target, **machine_scope(db, body.machine), 'keep_events':keep,
            'description':body.description.strip(), 'created_at':datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'enabled':True, 'expires_at':until(body.days)}


def resolve_covered(db, covered):
    """Mark active alerts as resolved when every related event is covered by the new exclusion."""
    hosts = {agent_id:ip for agent_id, ip in db.execute(select(Agent.id, Agent.ip))}
    resolved = 0
    for alert in db.scalars(select(Alert).where(Alert.status == 'active')):
        if not alert.event_ids:
            continue
        events = list(db.scalars(select(EventRow).where(EventRow.id.in_(alert.event_ids))))
        if events and all(covered(hosts.get(row.agent_id), row.body) for row in events):
            alert.status = 'resolved'
            resolved += 1
    db.commit()
    return resolved


@router.get('')
def list_exclusions(db=Depends(session)):
    from server.services.policy_files import policies
    from server.detection.ignored_network_ips import BUILTIN_IPS
    policy = policies()[1]
    if any(item.id is None for section in SECTIONS.values() for item in getattr(policy, section)):
        edit(with_ids)  # entries written by hand get an id once, so the panel can manage them
        policy = policies()[1]
    data = policy.model_dump(mode='json')
    return {'exclusions':listing(data),
            'remote_ips':[{'ip':ip, 'fixed':False} for ip in policy.ignored_remote_ips]
                         + [{'ip':ip, 'fixed':True} for ip in sorted(BUILTIN_IPS)],
            'machines':sorted(db.scalars(select(Agent.hostname)), key=str.casefold)}


@router.post('')
def create_exclusion(body: NewExclusion, request: Request, db=Depends(session)):
    entry = entry_for(body, db)
    section = SECTIONS[body.kind]
    def change(data):
        with_ids(data)
        data.setdefault(section, []).append(entry)
    edit(change)
    from server.services.policy_files import PathExclusion, ExtensionExclusion, ProcessExclusion
    from server.services.host_path_exclusions import covers, sender
    model = {'folder':PathExclusion, 'extension':ExtensionExclusion, 'program':ProcessExclusion}[body.kind](**entry)
    resolved = resolve_covered(db, lambda ip, event: covers(MATCH_KIND[body.kind], model, sender(ip), event))
    logging.getLogger('server.audit').warning('exclusion_created id=%s kind=%s resolved_alerts=%d', entry['id'], body.kind, resolved)
    detail = (f'Adicionou {described(section, entry)} - {"guardar eventos, sem alerta" if entry["keep_events"] else "descartar eventos"}'
              f' - {validity(entry)}' + (f' - motivo: {entry["description"]}' if entry['description'] else '')
              + f' - {resolved} alerta(s) resolvido(s)')
    record(request, 'exclusion_created', detail)
    return {'id':entry['id'], 'resolved_alerts':resolved, 'keep_events':entry['keep_events']}


def find(data, exclusion_id):
    for section in SECTIONS.values():
        for index, item in enumerate(data.get(section) or []):
            if item.get('id') == exclusion_id:
                return section, index
    raise HTTPException(404, 'exclusion not found')


@router.patch('/{exclusion_id}')
def change_exclusion(exclusion_id: str, body: Change, request: Request):
    if body.enabled is None and body.renew_days is None:
        raise HTTPException(422, 'Nada para alterar.')
    def change(data):
        section, index = find(data, exclusion_id)
        item = data[section][index]
        if body.enabled is not None:
            item['enabled'] = body.enabled
        if body.renew_days is not None:
            item['expires_at'] = until(body.renew_days)
        return section, dict(item)
    section, item = edit(change)
    logging.getLogger('server.audit').warning('exclusion_changed id=%s enabled=%s renew_days=%s', exclusion_id, body.enabled, body.renew_days)
    if body.enabled is not None:
        record(request, 'exclusion_enabled' if body.enabled else 'exclusion_disabled',
               f'{"Reativou" if body.enabled else "Desativou"} {described(section, item)}')
    if body.renew_days is not None:
        record(request, 'exclusion_renewed', f'Renovou {described(section, item)} - {validity(item)}')
    return {'enabled':item.get('enabled', True), 'expires_at':item.get('expires_at')}


@router.delete('/{exclusion_id}')
def delete_exclusion(exclusion_id: str, request: Request):
    def change(data):
        section, index = find(data, exclusion_id)
        return section, data[section].pop(index)
    section, item = edit(change)
    logging.getLogger('server.audit').warning('exclusion_deleted id=%s', exclusion_id)
    record(request, 'exclusion_deleted', f'Removeu {described(section, item)}')
    return {'deleted':True}


@router.post('/remote-ips')
def add_remote_ips(body: RemoteIps, request: Request, db=Depends(session)):
    from server.detection.ignored_network_ips import normalized
    try:
        wanted = list(dict.fromkeys(normalized(ip) for ip in body.ips))
    except ValueError:
        raise HTTPException(422, 'IP invalido: use enderecos como 8.8.8.8 ou 2606:4700::1111') from None
    def change(data):
        current = data.get('ignored_remote_ips') or []
        data['ignored_remote_ips'] = list(dict.fromkeys(current + wanted))
    edit(change)
    targets = set(wanted)
    def covered(ip, event):
        value = (event.get('network') or {}).get('remote_ip')
        try:
            return str(event.get('event_type', '')).startswith('network.') and normalized(value) in targets
        except (ValueError, TypeError):
            return False
    resolved = resolve_covered(db, covered)
    logging.getLogger('server.audit').warning('remote_ips_ignored added=%d resolved_alerts=%d', len(wanted), resolved)
    shown = ', '.join(wanted[:20]) + (f' e mais {len(wanted) - 20}' if len(wanted) > 20 else '')
    record(request, 'remote_ips_added', f'Ignorou {len(wanted)} IP(s) remoto(s): {shown} - {resolved} alerta(s) resolvido(s)')
    return {'added':len(wanted), 'resolved_alerts':resolved}


@router.delete('/remote-ips/{ip}')
def remove_remote_ip(ip: str, request: Request):
    from server.detection.ignored_network_ips import normalized
    try:
        target = normalized(ip)
    except ValueError:
        raise HTTPException(422, 'IP invalido') from None
    def change(data):
        current = data.get('ignored_remote_ips') or []
        if target not in current:
            raise HTTPException(404, 'IP nao esta na lista editavel')
        data['ignored_remote_ips'] = [item for item in current if item != target]
    edit(change)
    logging.getLogger('server.audit').warning('remote_ip_unignored')
    record(request, 'remote_ip_removed', f'Removeu o IP remoto {target} da lista de ignorados')
    return {'deleted':True}


@router.get('/history')
def history(limit: int = 200, db=Depends(session)):
    rows = db.scalars(select(SecurityLog).order_by(SecurityLog.timestamp.desc()).limit(max(1, min(limit, 1000))))
    return [{'timestamp':row.timestamp, 'ip':row.ip, 'action':row.action, 'detail':row.detail} for row in rows]


# Summary shown on every panel page (administrator token only): recent changes, wrong tokens, validity ending soon.
notices_router = APIRouter(prefix='/api/v1/security', dependencies=[Depends(admin)])
SOON = timedelta(days=3)


@notices_router.get('/notices')
def notices(db=Depends(session)):
    from server.services.policy_files import policies
    counts = dict(db.execute(select(SecurityLog.action, func.count()).where(SecurityLog.timestamp >= time.time() - 86400)
                             .group_by(SecurityLog.action)).all())
    now, expiring, expired = datetime.now(timezone.utc), [], 0
    data = policies()[1].model_dump(mode='json')
    for section in SECTIONS.values():
        for item in data.get(section) or []:
            if not item.get('enabled', True) or not item.get('expires_at'):
                continue
            if moment(item['expires_at']) <= now:
                expired += 1
            elif moment(item['expires_at']) - now <= SOON:
                expiring.append({'value':value_of(item), 'machine':scope(item), 'expires_at':item['expires_at']})
    return {'changes_24h':sum(n for action, n in counts.items() if action not in FAILURES),
            'failures_24h':sum(counts.get(action, 0) for action in FAILURES),
            'latest':db.scalar(select(func.max(SecurityLog.timestamp))), 'expiring':expiring, 'expired':expired}
