import json
import time
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from server.main import create_app
from server.settings import Settings
from shared.protocol import signature

ADMIN = 'test-admin-' + 'x'*40

@pytest.fixture
def client(tmp_path):
    settings = Settings(database_url='sqlite:///' + str(tmp_path/'server.db'), admin_token=ADMIN)
    with TestClient(create_app(settings, background=False)) as client:
        yield client

@pytest.fixture
def registered(client):
    r = client.post('/api/v1/agents/register',json={'hostname':'test'},headers={'Authorization':'Bearer '+ADMIN})
    assert r.status_code == 200
    return r.json()

def signed(client, registered, path, payload, nonce=None, timestamp=None, token=None):
    body = json.dumps(payload).encode()
    token = token or registered['agent_token']
    timestamp = str(timestamp or int(time.time()))
    nonce = nonce or str(uuid4())
    headers = {'Authorization':'Bearer '+token, 'X-Agent-ID':registered['agent_id'],
               'X-Timestamp':timestamp,'X-Nonce':nonce,'Content-Type':'application/json'}
    headers['X-Signature'] = signature(token,'POST',path,timestamp,nonce,body)
    return client.post(path,content=body,headers=headers)
