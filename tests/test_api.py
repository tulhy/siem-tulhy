from uuid import uuid4
import time
from shared.events import Event
from tests.conftest import ADMIN, signed

def event(registered, **kw):
    # LOW observations are discarded at ingestion by policy; MEDIUM is stored.
    kw.setdefault('severity','MEDIUM')
    return Event(agent_id=registered['agent_id'],hostname='test',event_type='process.start',source='test',**kw).model_dump(mode='json')

def test_authentication(client, registered):
    assert client.get('/api/v1/events').status_code == 401
    assert client.post('/api/v1/agents/register',json={'hostname':'bad'}).status_code == 401
    payload = {'events':[event(registered)]}
    assert signed(client,registered,'/api/v1/events/batch',payload,token='wrong').status_code == 401
    assert signed(client,registered,'/api/v1/events/batch',payload,timestamp=int(time.time())-500).status_code == 401

def test_batch_dedup_and_replay(client, registered):
    e = event(registered)
    nonce = str(uuid4())
    payload = {'events':[e]}
    r = signed(client,registered,'/api/v1/events/batch',payload,nonce=nonce)
    assert r.status_code == 200, r.text
    assert r.json()['inserted'] == 1
    assert signed(client,registered,'/api/v1/events/batch',payload,nonce=nonce).status_code == 409
    assert signed(client,registered,'/api/v1/events/batch',payload).json()['inserted'] == 0
    e['severity'] = 'HIGH'
    assert signed(client,registered,'/api/v1/events/batch',payload).status_code == 409
    result = client.get('/api/v1/events',headers={'Authorization':'Bearer '+ADMIN}).json()
    assert len(result) == 1

def test_agent_identity_and_atomicity(client, registered):
    first, second = event(registered), event(registered)
    second['agent_id'] = str(uuid4())
    assert signed(client,registered,'/api/v1/events/batch',{'events':[first,second]}).status_code == 403
    assert client.get('/api/v1/events',headers={'Authorization':'Bearer '+ADMIN}).json() == []

def test_body_limit_and_rate(client, registered):
    assert client.post('/api/v1/events',content=b'x'*1_100_000).status_code == 413
    client.app.state.settings.requests_per_minute = 1
    assert signed(client,registered,'/api/v1/events',event(registered)).status_code == 200
    assert signed(client,registered,'/api/v1/events',event(registered)).status_code == 429
