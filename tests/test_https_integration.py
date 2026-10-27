import socket
import ssl
import threading
import time
import httpx
import pytest
import uvicorn
from server.main import create_app
from server.settings import Settings
from scripts.dev_certificate import generate
from agent.config.settings import Config
from agent.normalizers import Normalizer
from agent.queue.persistent import PersistentQueue
from agent.transport.client import Transport
from tests.conftest import ADMIN

def test_real_https_offline_ack_loss_and_retry(tmp_path,monkeypatch):
    cert,key=generate(tmp_path/'tls')
    monkeypatch.setenv('SIEM_CA_BUNDLE',str(cert))
    sock=socket.socket()
    sock.bind(('127.0.0.1',0))
    port=sock.getsockname()[1]
    app=create_app(Settings(database_url='sqlite:///'+str(tmp_path/'https.db'),admin_token=ADMIN))
    server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,ssl_certfile=str(cert),ssl_keyfile=str(key),log_level='warning',access_log=False))
    thread=threading.Thread(target=lambda:server.run(sockets=[sock]),daemon=True)
    thread.start()
    deadline=time.monotonic()+10
    while not server.started and time.monotonic()<deadline:
        time.sleep(.05)
    assert server.started
    base=f'https://localhost:{port}'
    context=ssl.create_default_context(cafile=str(cert))
    try:
        with httpx.Client(verify=context,trust_env=False) as client:
            registered=client.post(base+'/api/v1/agents/register',headers={'Authorization':'Bearer '+ADMIN},json={'hostname':'tls-lab'}).json()
            n=Normalizer(registered['agent_id'],'tls-lab')
            q=PersistentQueue(tmp_path/'queue.db',n)
            q.put(n.event('process.start','synthetic',process={'path':r'C:\Temp\benign.exe'}))
            # Offline transport cannot acknowledge; queue survives a close/reopen.
            offline=Transport(Config(server_url=base),registered['agent_id'],registered['agent_token'],
                httpx.Client(transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError('offline')))))
            with pytest.raises(httpx.ConnectError):
                offline.flush(q)
            offline.close()
            q.close()
            q=PersistentQueue(tmp_path/'queue.db',n)
            transport=Transport(Config(server_url=base),registered['agent_id'],registered['agent_token'])
            def lose_ack(response):
                if response.status_code==200:
                    raise httpx.ReadError('simulated lost acknowledgment after commit')
            transport.client.event_hooks['response']=[lose_ack]
            with pytest.raises(httpx.ReadError):
                transport.flush(q)
            assert len(q.peek())==1
            transport.client.event_hooks['response']=[]
            assert transport.flush(q)==1 and not q.peek()
            events=client.get(base+'/api/v1/events',headers={'Authorization':'Bearer '+ADMIN}).json()
            assert len(events)==1
            transport.close()
            q.close()
        # Untrusted certificate MUST fail, proving TLS validation is active.
        with httpx.Client(trust_env=False) as untrusted:
            with pytest.raises(httpx.ConnectError):
                untrusted.get(base+'/health')
    finally:
        server.should_exit=True
        thread.join(10)
        sock.close()
    assert not thread.is_alive()
