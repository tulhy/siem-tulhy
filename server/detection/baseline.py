import hashlib
from sqlalchemy import select, func
from server.models.tables import Baseline
from server.detection.rules import Rule

BASELINE_RULE = Rule(id='NEW_NETWORK_DESTINATION',name='Destino novo após período de aprendizagem',
    description='Combinação processo/destino não observada no baseline local. Mudanças legítimas são possíveis; investigue o contexto.',
    category='anomaly',severity='MEDIUM',confidence='LOW',tags=['baseline','network'],
    conditions=[{'field':'event_type','value':'network.connection'}])

def observe(db, settings, event):
    if event.event_type != 'network.connection' or not event.ip:
        return False
    raw = str(event.process) + '|' + event.ip
    value = hashlib.sha256(raw.encode()).hexdigest()
    row = db.get(Baseline,(event.agent_id,'destination',value))
    count, first = db.execute(select(func.coalesce(func.sum(Baseline.count),0),func.min(Baseline.first_seen)).where(
        Baseline.agent_id==event.agent_id,Baseline.kind=='destination')).one()
    unusual = row is None and count>=settings.baseline_min_events and first is not None and event.timestamp-first>=settings.baseline_warmup_seconds
    if row:
        row.count += 1
        row.first_seen = min(row.first_seen,event.timestamp)
        row.last_seen = max(row.last_seen,event.timestamp)
    else:
        db.add(Baseline(agent_id=event.agent_id,kind='destination',value=value,first_seen=event.timestamp,last_seen=event.timestamp,count=1))
    # Learn all destinations, but a new outbound destination alone is not an alert.
    return unusual and event.body.get('raw_event',{}).get('direction') == 'inbound'
