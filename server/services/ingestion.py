import hashlib
import json
import time
import logging
from fastapi import HTTPException
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.dialects.postgresql import insert as pg_insert
from server.models.tables import EventRow

def ingest(db, agent, events, settings=None):
    from server.settings import Settings
    settings = settings or Settings()
    accepted, inserted, discarded = [], [], []
    prepared = None
    insert = sqlite_insert if db.bind.dialect.name == 'sqlite' else pg_insert
    for e in events:
        if str(e.agent_id) != agent.id or e.hostname != agent.hostname:
            raise HTTPException(403, 'event identity does not match registered agent')
        if e.timestamp.timestamp() > time.time() + 300:
            raise HTTPException(422, 'event timestamp too far in future')
        body = e.model_dump(mode='json')
        from server.services.host_path_exclusions import matching_exclusion
        from server.services.policy_files import discard_event
        # Authenticated sender address, not a peer IP supplied in the event.
        exclusion = matching_exclusion(agent.ip, body)
        if exclusion is not None and (not exclusion.keep_events or discard_event(body)):
            # ACK a deliberate discard so the offline queue does not retry it.
            accepted.append(str(e.event_id))
            discarded.append(str(e.event_id))
            continue
        # keep_events: stored and shown in Events, but marked processed so detection never alerts on it.
        excluded = exclusion is not None
        from server.detection.before_discard import matching_rules, alert_matches, prepare
        rescued = []
        if not excluded and discard_event(body):
            if prepared is None:
                prepared = prepare(settings)
            rescued = matching_rules(body, settings, prepared)
            if not rescued:
                accepted.append(str(e.event_id))
                discarded.append(str(e.event_id))
                continue
        level = max((r.severity for r in rescued), key=('LOW','MEDIUM','HIGH','CRITICAL').index) if rescued else e.severity
        digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',',':')).encode()).hexdigest()
        values = dict(id=str(e.event_id), agent_id=agent.id, timestamp=e.timestamp.timestamp(), hostname=e.hostname,
            user=e.user, event_type=e.event_type, severity=level, process=e.process.name if e.process else None,
            sha256=(e.process.sha256 if e.process else None) or (e.file.sha256 if e.file else None),
            ip=e.network.remote_ip if e.network else None, port=e.network.remote_port if e.network else None,
            local_ip=e.network.local_ip if e.network else None, local_port=e.network.local_port if e.network else None,
            body=body, body_hash=digest, detection_status='excluded' if excluded else 'pending',
            processed_at=time.time() if excluded else None)
        result = db.execute(insert(EventRow).values(**values).on_conflict_do_nothing(index_elements=['id']))
        if result.rowcount:
            inserted.append(str(e.event_id))
            if rescued:
                alert_matches(db, db.get(EventRow, str(e.event_id)), rescued, settings)
        else:
            existing = db.get(EventRow, str(e.event_id))
            if existing.agent_id != agent.id or existing.body_hash != digest:
                raise HTTPException(409, 'event ID conflicts with stored content')
        accepted.append(str(e.event_id))
    db.commit()  # ACK means stored OR deliberately discarded by this policy.
    logging.getLogger('server.ingestion').info('batch_committed received=%d inserted=%d discarded=%d',len(accepted),len(inserted),len(discarded))
    return {'accepted_ids':accepted, 'inserted':len(inserted), 'discarded_ids':discarded}
