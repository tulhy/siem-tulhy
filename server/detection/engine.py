from uuid import uuid4
import time
from sqlalchemy import select, update
from server.models.tables import RuleRow, EventRow, Agent, RuleMatch
from server.detection.rules import load_rules
from server.alerts.service import create_alert
from server.correlation.temporal import correlated_evidence
from server.correlation.risk import risk_score, confidence
from server.detection.baseline import observe, BASELINE_RULE
from server.detection.network_policy import server_addresses, exempt_remote_access

class DetectionEngine:
    def __init__(self, settings):
        self.settings = settings
        self.rules = load_rules(settings.rules_dir)
        self.server_addresses = server_addresses(settings)

    def sync_rules(self, db):
        from server.services.policy_files import suppress_rule
        live = {r.id for r in self.rules}
        for old in db.scalars(select(RuleRow)):
            if old.id not in live:
                old.enabled = False
        for rule in self.rules:
            db.merge(RuleRow(id=rule.id, definition=rule.model_dump(),enabled=rule.enabled and not suppress_rule(rule)))
        db.commit()

    def evidence(self, db, rule, event):
        from server.detection.http_exceptions import exempt_http
        if exempt_http(rule.id, event.body):
            return []
        if exempt_remote_access(rule.id,event.body,self.server_addresses):
            return []
        # Empty RunOnce snapshots alone are informational, not evidence of a new
        # startup entry. Retain the event and let other correlation rules inspect it.
        raw = event.body.get('raw_event') or {}
        empty_runonce = (
            event.body.get('event_type') == 'persistence.change'
            and event.body.get('source') == 'windows.registry'
            and event.body.get('severity') in ('LOW', 'MEDIUM')
            and type(raw.get('value_count')) is int and raw['value_count'] == 0
            and str(raw.get('key', '')).casefold() in {
                f'{hive}:{view}:software\\microsoft\\windows\\currentversion\\runonce'
                for hive in ('hklm', 'hkcu') for view in (256, 512)
            })
        if rule.id == 'PERSISTENCE_CHANGE' and empty_runonce:
            return []
        return correlated_evidence(db, rule, event)

    def evaluate(self, db, event):
        self._evaluate_rules(db, event)
        from server.alerts.priority import ensure_priority
        ensure_priority(db, self.settings, event)

    def _evaluate_rules(self, db, event):
        from server.services.policy_files import discard_event, suppress_rule
        if discard_event(event.body):
            event.detection_status='clear'
            event.processed_at=time.time()
            return
        if discard_event(event.body):
            if event.detection_status == 'pending':event.detection_status = 'clear'
            event.processed_at = time.time()
            return
        from server.detection.ignored_network_ips import ignored_network_event
        if ignored_network_event(event.body):
            if event.detection_status == 'pending':
                event.detection_status = 'clear'
            event.processed_at = time.time()
            return
        rules = list(self.rules)
        if observe(db,self.settings,event):
            rules.append(BASELINE_RULE)
        for rule in rules:
            if not rule.enabled or suppress_rule(rule):
                continue
            evidence = self.evidence(db, rule, event)
            if not evidence:
                continue
            weight = self.settings.risk_weights[rule.severity]
            when = max(item.timestamp for item in evidence)
            score = risk_score(db,self.settings,event.agent_id,when,rule.severity)
            alert = create_alert(db, rule, evidence, score, confidence(self.settings,score,rule.confidence))
            if alert:
                for item in evidence:
                    old = db.scalar(select(RuleMatch).where(RuleMatch.rule_id==rule.id,RuleMatch.event_id==item.id))
                    if not old:
                        db.add(RuleMatch(id=str(uuid4()),agent_id=item.agent_id,rule_id=rule.id,event_id=item.id,
                            alert_id=alert.id,timestamp=item.timestamp,score=weight if item.id==evidence[-1].id else 0))
                    item.detection_status = 'matched'
        if event.detection_status == 'pending':
            event.detection_status = 'clear'
        event.processed_at = time.time()

    def process_pending(self, sessions, limit=100):
        fresh=load_rules(self.settings.rules_dir)
        if [r.model_dump() for r in fresh]!=[r.model_dump() for r in self.rules]:
            self.rules=fresh
            with sessions() as db:self.sync_rules(db)
        # Short per-agent transactions share ingestion's lock. Retry remains possible after failure.
        with sessions() as db:
            ids = list(db.scalars(select(EventRow.agent_id).where(EventRow.processed_at.is_(None)).distinct().limit(limit)))
        processed = 0
        for agent_id in ids:
            with sessions() as db:
                db.execute(update(Agent).where(Agent.id==agent_id).values(last_seen=Agent.last_seen))
                events = list(db.scalars(select(EventRow).where(EventRow.agent_id==agent_id,EventRow.processed_at.is_(None)).order_by(EventRow.timestamp,EventRow.id).limit(limit-processed)))
                for event in events:
                    self.evaluate(db, event)
                    processed += 1
                db.commit()
            if processed >= limit:
                break
        return processed
