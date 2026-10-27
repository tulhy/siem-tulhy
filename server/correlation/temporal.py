from sqlalchemy import select
from server.models.tables import EventRow
from server.detection.rules import all_match, get_field

def correlated_evidence(db, rule, event):
    from server.detection.discovery import eligible
    if not eligible(rule, event.body):return []
    from server.detection.ignored_network_ips import ignored_network_event
    if ignored_network_event(event.body):
        return []
    if not all_match(rule.conditions,event.body):
        return []
    if rule.threshold == 1 and not rule.sequence and not rule.distinct_field:
        return [event]
    group = [get_field(event.body, key) for key in rule.group_by]
    if any(value is None for value in group):
        return []  # Never correlate unrelated processes under a missing PID/user.
    query = select(EventRow).where(EventRow.agent_id==event.agent_id,
        EventRow.timestamp>=event.timestamp-rule.window_seconds,
        EventRow.timestamp<=event.timestamp+rule.window_seconds).order_by(EventRow.timestamp,EventRow.id)
    # Events kept by a panel exclusion never become evidence of another alert.
    candidates = [r for r in db.scalars(query) if r.detection_status != 'excluded' and eligible(rule, r.body)
                  and not ignored_network_event(r.body) and all_match(rule.conditions,r.body)
                  and [get_field(r.body,key) for key in rule.group_by] == group]
    if rule.sequence:
        # Dynamic subsequences support interleaved noise and late arriving events.
        paths = {0:[]}
        for row in candidates:
            for stage in range(len(rule.sequence)-1,-1,-1):
                previous = paths.get(stage)
                if previous is None or not all_match(rule.sequence[stage],row.body):
                    continue
                proposed = previous + [row]
                if row.timestamp-proposed[0].timestamp > rule.window_seconds:
                    continue
                paths[stage+1] = proposed
                if stage+1 == len(rule.sequence) and any(r.id==event.id for r in proposed):
                    return proposed
        return []
    index = next(i for i,r in enumerate(candidates) if r.id==event.id)
    if rule.distinct_field:
        # A repeated hit on one port is not a port scan; count distinct ports/IPs.
        from collections import Counter
        counts=Counter()
        start=0
        for end,row in enumerate(candidates):
            value=get_field(row.body,rule.distinct_field)
            if value is not None:counts[value]+=1
            while row.timestamp-candidates[start].timestamp>rule.window_seconds:
                old=get_field(candidates[start].body,rule.distinct_field)
                if old is not None:
                    counts[old]-=1
                    if not counts[old]:del counts[old]
                start+=1
            if start<=index<=end and end-start+1>=rule.threshold and len(counts)>=rule.distinct_threshold:
                return candidates[start:end+1]
        return []
    for start in range(max(0,index-rule.threshold+1), index+1):
        evidence = candidates[start:start+rule.threshold]
        if len(evidence) == rule.threshold and evidence[-1].timestamp-evidence[0].timestamp<=rule.window_seconds:
            return evidence
    return []
