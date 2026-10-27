"""Count critical alert occurrences without modifying signed events or the schema."""
from sqlalchemy import and_, func, select
from server.models.tables import Alert

WINDOW_SECONDS = 86400


def critical_occurrences(db, alerts):
    """One grouped query for a page; count alerts, not packets or attack sessions.

    Each critical alert's window ends at its server creation time. Resolved alerts
    count too: resolution does not erase occurrence history. Event retransmission
    is excluded by ingestion/alert idempotency, before this read-only aggregation.
    """
    ids = [row.id for row in alerts if row.severity == 'CRITICAL']
    if not ids:
        return {}
    anchors = select(Alert.id, Alert.agent_id, Alert.rule_id, Alert.created_at).where(
        Alert.id.in_(ids), Alert.severity == 'CRITICAL').cte('critical_anchors')
    history = Alert.__table__.alias('critical_history')
    query = select(anchors.c.id, func.count(history.c.id)).select_from(
        anchors.join(history, and_(
            history.c.agent_id == anchors.c.agent_id,
            history.c.rule_id == anchors.c.rule_id,
            history.c.severity == 'CRITICAL',
            history.c.created_at >= anchors.c.created_at - WINDOW_SECONDS,
            history.c.created_at <= anchors.c.created_at,
        ))).group_by(anchors.c.id)
    counts = dict(db.execute(query).all())
    return {row.id: {
        'occurrence_count': counts.get(row.id, 1),
        'repeat_count': max(0, counts.get(row.id, 1) - 1),
        'occurrence_scope': 'same_rule_and_agent',
        'occurrence_window_seconds': WINDOW_SECONDS,
        'occurrence_window_start': row.created_at - WINDOW_SECONDS,
        'occurrence_window_end': row.created_at,
    } for row in alerts if row.id in counts}
