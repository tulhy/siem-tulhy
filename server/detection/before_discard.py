"""Evaluate stateless rules before discarding LOW observations; no raw window."""
from uuid import uuid4
import time
from server.detection.rules import load_rules, all_match
from server.services.policy_files import policies, suppress_rule
from server.detection.ignored_network_ips import ignored_network_event
from server.detection.http_exceptions import exempt_http
from server.detection.network_policy import server_addresses, exempt_remote_access


def prepare(settings):
    return load_rules(settings.rules_dir), server_addresses(settings)


def matching_rules(body, settings, prepared=None):
    policy = policies()[2]
    if body.get('severity') != 'LOW' or str(body.get('event_type', '')).casefold() in policy.discard_types:
        return []
    if ignored_network_event(body):
        return []
    rules, allowed = prepared or prepare(settings)
    return [r for r in rules
            if r.enabled and not suppress_rule(r) and r.severity != 'LOW'
            and r.threshold == 1 and not r.sequence and not r.distinct_field
            and all_match(r.conditions, body)
            and not exempt_http(r.id, body)
            and not exempt_remote_access(r.id, body, allowed)
            and not (r.id == 'PERSISTENCE_CHANGE' and body.get('source') == 'windows.registry'
                     and (body.get('raw_event') or {}).get('value_count') == 0)]


def alert_matches(db, row, rules, settings):
    from server.models.tables import RuleRow, RuleMatch
    from server.alerts.service import create_alert
    from server.correlation.risk import risk_score, confidence
    for rule in rules:
        db.merge(RuleRow(id=rule.id, definition=rule.model_dump(), enabled=True))
        score = risk_score(db, settings, row.agent_id, row.timestamp, rule.severity)
        alert = create_alert(db, rule, [row], score, confidence(settings, score, rule.confidence))
        if alert:
            alert.evidence = {**alert.evidence, 'reported_severity':row.body['severity'],
                              'classification_policy':'rules_before_low_discard'}
            db.add(RuleMatch(id=str(uuid4()), agent_id=row.agent_id, rule_id=rule.id,
                event_id=row.id, alert_id=alert.id, timestamp=row.timestamp,
                score=settings.risk_weights[rule.severity]))
    row.detection_status = 'matched'
    row.processed_at = time.time()
