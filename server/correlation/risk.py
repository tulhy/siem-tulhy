from sqlalchemy import select, func
from server.models.tables import RuleMatch

def risk_score(db, settings, agent_id, timestamp, severity):
    previous = db.scalar(select(func.coalesce(func.sum(RuleMatch.score),0)).where(
        RuleMatch.agent_id==agent_id,RuleMatch.timestamp>=timestamp-settings.risk_window,RuleMatch.timestamp<=timestamp))
    return min(100, previous + settings.risk_weights[severity])

def confidence(settings, score, floor='LOW'):
    levels = ('LOW','MEDIUM','HIGH','CRITICAL')
    level = sum(score>=threshold for threshold in settings.risk_thresholds)
    return levels[max(level,levels.index(floor))]
