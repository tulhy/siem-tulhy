"""Panel policy shared by listings, details and aggregate charts."""
from sqlalchemy import and_, or_, func
from server.models.tables import EventRow, Alert

def visible_events():
    from server.services.policy_files import policies
    policy=policies()[2]
    return and_(EventRow.severity.not_in(policy.discard_severities),
                or_(EventRow.severity.in_(policy.keep_types_at_severities),
                    func.lower(EventRow.event_type).not_in(policy.discard_types)))

def visible_alerts():
    from server.services.policy_files import policies
    policy=policies()[1]
    return and_(Alert.severity.not_in(policy.suppress_severities), Alert.rule_id.not_in(policy.disabled_rule_ids))
