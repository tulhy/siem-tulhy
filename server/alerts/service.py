import hashlib
import json
from uuid import uuid4
from sqlalchemy import select
from server.models.tables import Alert

def create_alert(db, rule, evidence, score, confidence):
    from server.services.policy_files import suppress_rule
    if suppress_rule(rule):return None
    if suppress_rule(rule):return None
    from server.alerts.priority import remove_redundant
    remove_redundant(db, rule, evidence)
    ids = sorted(e.id for e in evidence)
    dedup = hashlib.sha256(json.dumps([rule.id,ids]).encode()).hexdigest()
    if db.scalar(select(Alert).where(Alert.dedup_key==dedup)):
        return None
    alert = Alert(id=str(uuid4()),agent_id=evidence[0].agent_id,rule_id=rule.id,title=rule.name,
        description=rule.description,reason=f'{len(ids)} evento(s) satisfazem a regra {rule.id} em uma janela de {rule.window_seconds}s. Evidência comportamental; requer investigação.',
        severity=rule.severity,confidence=confidence,risk_score=score,user=evidence[-1].user,
        event_ids=ids,dedup_key=dedup,evidence={'conditions':[c.model_dump() for c in rule.conditions],
          'sequence':[[c.model_dump() for c in stage] for stage in rule.sequence], 'threshold':rule.threshold,
          'window_seconds':rule.window_seconds,'group_by':rule.group_by,'mitre':rule.mitre,'tags':rule.tags,
          'distinct_field':rule.distinct_field,'distinct_threshold':rule.distinct_threshold,
          'event_time_start':min(e.timestamp for e in evidence),'event_time_end':max(e.timestamp for e in evidence)})
    db.add(alert)
    db.flush()
    return alert
