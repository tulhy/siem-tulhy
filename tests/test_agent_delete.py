from uuid import uuid4
import pytest
from sqlalchemy import select, func
from sqlalchemy.exc import OperationalError
from server.models.tables import Agent, Alert, RuleMatch, EventRow, HeartbeatRow, Baseline, Nonce
from tests.conftest import ADMIN, signed
from tests.test_api import event

HEADERS = {'Authorization':'Bearer '+ADMIN}


def remove(client, agent, **kw):
    return client.request('DELETE', '/api/v1/agents/'+agent['agent_id'],
                          json={'confirm_name':'test'}, **kw)


def seed(client, agent):
    payload = event(agent)
    assert signed(client,agent,'/api/v1/events',payload).status_code == 200
    assert signed(client,agent,'/api/v1/agents/heartbeat',{
        'hostname':'test','os':'test','version':'1','pending':0}).status_code == 200
    with client.app.state.sessions() as db:
        alert = Alert(id=str(uuid4()),agent_id=agent['agent_id'],rule_id='test',title='Test',
            description='Synthetic',reason='Synthetic',severity='LOW',confidence='LOW',risk_score=10,
            event_ids=[payload['event_id']],evidence={},dedup_key=str(uuid4()))
        db.add(alert)
        db.flush()
        db.add(RuleMatch(id=str(uuid4()),agent_id=agent['agent_id'],rule_id='test',
            event_id=payload['event_id'],alert_id=alert.id,timestamp=1,score=10))
        db.add(Baseline(agent_id=agent['agent_id'],kind='ip',value='192.0.2.1',first_seen=1,last_seen=1,count=1))
        db.commit()


def test_delete_requires_admin_and_exact_confirmation(client, registered):
    assert remove(client,registered).status_code == 401
    assert remove(client,registered,headers={'Authorization':'Bearer '+registered['agent_token']}).status_code == 401
    path='/api/v1/agents/'+registered['agent_id']
    assert client.request('DELETE',path,headers=HEADERS).status_code == 422
    assert client.request('DELETE',path,headers=HEADERS,json={'confirm_name':'wrong'}).status_code == 409
    assert len(client.get('/api/v1/agents',headers=HEADERS).json()) == 1


def test_delete_removes_only_selected_identity_and_revokes_token(client, registered):
    # Duplicate names must never cause deletion of a second registration.
    other=client.post('/api/v1/agents/register',headers=HEADERS,json={'hostname':'test'}).json()
    seed(client,registered)
    seed(client,other)
    result=remove(client,registered,headers=HEADERS)
    assert result.status_code == 200, result.text
    assert all(result.json()['removed'][name] > 0 for name in
               ('events','alerts','rule_matches','heartbeats','baselines','nonces'))
    with client.app.state.sessions() as db:
        assert db.get(Agent,registered['agent_id']) is None
        assert db.get(Agent,other['agent_id']) is not None
        for model in (Alert,RuleMatch,EventRow,HeartbeatRow,Baseline,Nonce):
            assert db.scalar(select(func.count()).select_from(model).where(model.agent_id==registered['agent_id'])) == 0
            assert db.scalar(select(func.count()).select_from(model).where(model.agent_id==other['agent_id'])) > 0
    assert remove(client,registered,headers=HEADERS).status_code == 404
    assert signed(client,registered,'/api/v1/events',event(registered)).status_code == 401
    assert signed(client,other,'/api/v1/events',event(other)).status_code == 200
    assert client.get('/api/v1/dashboard/stats',headers=HEADERS).json()['agents_total'] == 1


def test_delete_transaction_rolls_back_on_failure(client, registered, monkeypatch):
    seed(client,registered)
    from sqlalchemy.orm import Session
    original = Session.execute
    def fail_events(self, statement, *args, **kwargs):
        if getattr(statement, 'is_delete', False) and statement.table.name == 'events':
            raise OperationalError('synthetic deletion failure', {}, RuntimeError('test'))
        return original(self, statement, *args, **kwargs)
    monkeypatch.setattr(Session,'execute',fail_events)
    with pytest.raises(OperationalError):
        remove(client,registered,headers=HEADERS)
    with client.app.state.sessions() as db:
        assert db.get(Agent,registered['agent_id']) is not None
        for model in (Alert,RuleMatch,EventRow,HeartbeatRow,Baseline,Nonce):
            assert db.scalar(select(func.count()).select_from(model)) > 0
