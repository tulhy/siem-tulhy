import gzip
import json
import time
from uuid import uuid4
from shared.protocol import signature
from tests.conftest import signed, ADMIN
from tests.test_api import event

def test_compressed_signed_body_and_bomb(client,registered):
    path='/api/v1/events/batch'
    body=gzip.compress(json.dumps({'events':[event(registered)]}).encode())
    timestamp,nonce=str(int(time.time())),str(uuid4())
    headers={'Authorization':'Bearer '+registered['agent_token'],'X-Agent-ID':registered['agent_id'],
             'X-Timestamp':timestamp,'X-Nonce':nonce,'Content-Encoding':'gzip','Content-Type':'application/json'}
    headers['X-Signature']=signature(registered['agent_token'],'POST',path,timestamp,nonce,body)
    assert client.post(path,content=body,headers=headers).status_code==200
    assert client.post(path,content=gzip.compress(b'x'*3_000_000),headers=headers).status_code==413
    assert client.post(path,content=b'bad',headers=headers).status_code==400

def test_tampering_and_rotation(client,registered):
    e=event(registered)
    token=registered['agent_token']
    timestamp,nonce=str(int(time.time())),str(uuid4())
    headers={'Authorization':'Bearer '+token,'X-Agent-ID':registered['agent_id'],'X-Timestamp':timestamp,
             'X-Nonce':nonce,'X-Signature':signature(token,'POST','/api/v1/events',timestamp,nonce,b'other'),
             'Content-Type':'application/json'}
    assert client.post('/api/v1/events',json=e,headers=headers).status_code==401
    admin={'Authorization':'Bearer '+ADMIN}
    r=client.post('/api/v1/agents/'+registered['agent_id']+'/rotate-token',headers=admin)
    assert r.status_code==200
    assert signed(client,registered,'/api/v1/events',e).status_code==401
    registered['agent_token']=r.json()['agent_token']
    assert signed(client,registered,'/api/v1/events',e).status_code==200
    client.patch('/api/v1/agents/'+registered['agent_id'],headers=admin,json={'enabled':False})
    assert signed(client,registered,'/api/v1/events',event(registered)).status_code==401

def test_filters(client,registered):
    e=event(registered,user='synthetic-user',process={'name':'safe.exe','sha256':'a'*64},
            network={'remote_ip':'192.0.2.4','remote_port':443,'local_ip':'127.0.0.1','local_port':1234})
    assert signed(client,registered,'/api/v1/events',e).status_code==200
    headers={'Authorization':'Bearer '+ADMIN}
    for key,value in [('user','synthetic-user'),('process','safe.exe'),('sha256','a'*64),('ip','127.0.0.1'),('port',443)]:
        assert len(client.get('/api/v1/events',params={key:value},headers=headers).json())==1
    assert client.get('/api/v1/events',params={'user':'other'},headers=headers).json()==[]
    assert client.get('/api/v1/events',params={'start':'2026-01-01'},headers=headers).status_code==422
