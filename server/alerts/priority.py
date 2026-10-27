"""Ensure high-priority observations have an explanatory alert after analysis."""
from uuid import uuid4
from sqlalchemy import select, delete
from server.models.tables import Alert, EventRow, RuleMatch, RuleRow

IDS = ('EVENT_PRIORITY_HIGH', 'EVENT_PRIORITY_CRITICAL')

def remove_redundant(db, rule, evidence):
    if rule.id in IDS or rule.severity not in ('HIGH', 'CRITICAL'):
        return
    levels = ['HIGH', 'CRITICAL'] if rule.severity == 'CRITICAL' else ['HIGH']
    ids = list(db.scalars(select(Alert.id).join(RuleMatch, RuleMatch.alert_id == Alert.id).where(
        Alert.rule_id.in_(IDS), Alert.severity.in_(levels),
        RuleMatch.event_id.in_([e.id for e in evidence]))))
    if ids:
        db.execute(delete(RuleMatch).where(RuleMatch.alert_id.in_(ids)))
        db.execute(delete(Alert).where(Alert.id.in_(ids)))

def ensure_priority(db, settings, event):
    # Reuse the same classification the Events panel shows, including policy
    # promotions of retained MEDIUM observations. No LOW event is recovered.
    from server.api.routes import displayed_event_severity
    from server.detection.rules import Rule
    from server.alerts.service import create_alert
    from server.correlation.risk import risk_score
    level = db.scalar(select(displayed_event_severity()).where(EventRow.id == event.id))
    from server.services.policy_files import policies, discard_event
    from server.detection.ignored_network_ips import ignored_network_event
    # A peer the organization ignores never alerts, not even through this fallback.
    if discard_event(event.body) or ignored_network_event(event.body) or level not in policies()[1].mandatory_severities:
        return
    levels = ['HIGH', 'CRITICAL'] if level == 'HIGH' else ['CRITICAL']
    existing = db.scalar(select(Alert.id).join(RuleMatch, RuleMatch.alert_id == Alert.id).where(
        RuleMatch.event_id == event.id, Alert.agent_id == event.agent_id,
        Alert.severity.in_(levels)).limit(1))
    if existing:
        event.detection_status = 'matched'
        return
    rule = Rule(id='EVENT_PRIORITY_'+level, name='Evento de prioridade '+('alta' if level == 'HIGH' else 'crítica'),
        description='A classificação deste evento exige revisão pelo administrador, mesmo sem uma regra específica. A severidade não confirma malware ou invasão.',
        category='priority', severity=level, confidence='LOW',
        conditions=[{'field':'event_type','value':event.event_type}], tags=['priority-policy'])
    db.merge(RuleRow(id=rule.id, definition=rule.model_dump(), enabled=True))
    alert = create_alert(db, rule, [event], risk_score(db, settings, event.agent_id, event.timestamp, level), 'LOW')
    if alert:
        alert.reason = f'Evento {event.event_type}, fonte {event.body.get("source", "não informada")}, classificado como {level} no painel. Nenhum alerta específico de severidade igual ou maior estava associado a este registro.'
        alert.evidence = {**alert.evidence, 'reported_severity':event.severity, 'displayed_severity':level,
                          'classification_policy':'mandatory_high_critical_alert'}
        # Visibility fallback does not inflate cumulative risk when a later
        # specific correlation evaluates the same evidence.
        db.add(RuleMatch(id=str(uuid4()), agent_id=event.agent_id, rule_id=rule.id,
            event_id=event.id, alert_id=alert.id, timestamp=event.timestamp, score=0))
        event.detection_status = 'matched'
