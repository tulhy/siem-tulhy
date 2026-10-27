import time
from server.services.telemetry import check_telemetry
from server.models.tables import Agent
from tests.conftest import ADMIN, signed

def test_loss_and_recovery(client, registered):
    sessions, settings = client.app.state.sessions, client.app.state.settings
    with sessions() as db:
        a = db.get(Agent,registered['agent_id'])
        a.created_at = time.time()-300
        db.commit()
    # TELEMETRY_LOST is disabled by policy: loss is shown only as offline status.
    assert check_telemetry(sessions,settings) == 0
    headers = {'Authorization':'Bearer '+ADMIN}
    assert client.get('/api/v1/agents',headers=headers).json()[0]['status']=='offline'
    assert client.get('/api/v1/alerts',headers=headers).json() == []
    r = signed(client,registered,'/api/v1/agents/heartbeat',{'hostname':'test','os':'Windows','version':'1.0.0','pending':5,'metrics':{'events_pending':5}})
    assert r.status_code == 200
    assert client.get('/api/v1/agents',headers=headers).json()[0]['status']=='online'
    assert client.get('/api/v1/alerts',headers=headers).json() == []
    assert client.get('/api/v1/metrics',headers=headers).json()['agents'][0]['events_pending']==5

def test_background_detection(tmp_path, monkeypatch):
    # Production default is 300 s; use the minimum so the test observes one cycle.
    monkeypatch.setenv('SIEM_DETECTION_INTERVAL','1')
    from fastapi.testclient import TestClient
    from server.main import create_app
    from server.settings import Settings
    from tests.test_api import event
    with TestClient(create_app(Settings(database_url='sqlite:///'+str(tmp_path/'live.db'),admin_token=ADMIN))) as c:
        headers = {'Authorization':'Bearer '+ADMIN}
        agent = c.post('/api/v1/agents/register',headers=headers,json={'hostname':'test'}).json()
        assert signed(c,agent,'/api/v1/events',event(agent,process={'path':r'C:\Temp\benign.exe'})).status_code==200
        deadline = time.monotonic()+5
        while time.monotonic()<deadline:
            if c.get('/api/v1/alerts',headers=headers).json():
                break
            time.sleep(0.1)
        assert c.get('/api/v1/alerts',headers=headers).json()
        assert c.get('/health').status_code==200
