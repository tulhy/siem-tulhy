import gzip
import json
from uuid import uuid4
import httpx
import pytest
from agent.config.settings import Config
from agent.normalizers import Normalizer
from agent.queue.persistent import PersistentQueue
from agent.transport.client import Transport, ProtocolError
from shared.protocol import signature

def test_reconnect_and_signed_ack(tmp_path):
    agent = uuid4()
    n = Normalizer(agent, 'test')
    q = PersistentQueue(tmp_path/'q.db', n)
    q.put(n.event('process.start','test'))
    offline = [True]
    def endpoint(request):
        if offline[0]:
            raise httpx.ConnectError('offline')
        h = request.headers
        assert h['x-signature'] == signature('t'*40, 'POST', request.url.path, h['x-timestamp'], h['x-nonce'], request.content)
        body = gzip.decompress(request.content) if h.get('content-encoding') == 'gzip' else request.content
        return httpx.Response(200, json={'accepted_ids':[e['event_id'] for e in json.loads(body)['events']]})
    t = Transport(Config(), agent, 't'*40, httpx.Client(transport=httpx.MockTransport(endpoint)))
    with pytest.raises(httpx.ConnectError):
        t.flush(q)
    assert len(q.peek()) == 1
    offline[0] = False
    assert t.flush(q) == 1 and not q.peek()
    q.close()
    t.close()

def test_https_required():
    with pytest.raises(ValueError):
        Config(server_url='http://example.org')

def test_bad_ack_preserves_queue(tmp_path):
    agent = uuid4()
    q = PersistentQueue(tmp_path/'q.db', Normalizer(agent,'test'))
    q.put(Normalizer(agent,'test').event('process.start','test'))
    t = Transport(Config(), agent, 'x'*40, httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200,json={'accepted_ids':[]}))))
    with pytest.raises(ProtocolError):
        t.flush(q)
    assert q.metrics()['events_pending'] == 1
    q.close()
    t.close()
