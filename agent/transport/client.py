import gzip
import json
import logging
import os
import random
import ssl
import time
from uuid import uuid4
import httpx
from shared.protocol import signature

log = logging.getLogger('agent.transport')

class ProtocolError(RuntimeError):
    """The server did not provide a valid, bounded acknowledgment."""

class Transport:
    def __init__(self, config, agent_id, token, client=None):
        self.config, self.agent_id, self.token = config, str(agent_id), token
        context = ssl.create_default_context(cafile=os.getenv('SIEM_CA_BUNDLE') or None)
        # Short connect timeout so an unreachable address (cable/Wi-Fi switch) fails over quickly.
        # IPv4 only: the server listens on IPv4, and firewalled IPv6 attempts would stall each send.
        self.client = client or httpx.Client(timeout=httpx.Timeout(config.timeout, connect=min(5.0, config.timeout)),
            follow_redirects=False, trust_env=False,
            transport=httpx.HTTPTransport(verify=context, local_address='0.0.0.0', retries=0))
        self.endpoints = config.endpoints
        self.active = 0
        self.failures = 0

    def post(self, path, payload):
        body = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode()
        headers = {'Content-Type':'application/json', 'Authorization':'Bearer ' + self.token,
                   'X-Agent-ID':self.agent_id, 'X-Timestamp':str(int(time.time())), 'X-Nonce':str(uuid4())}
        if len(body) > 4096:
            body = gzip.compress(body)
            headers['Content-Encoding'] = 'gzip'
        headers['X-Signature'] = signature(self.token, 'POST', path, headers['X-Timestamp'], headers['X-Nonce'], body)
        response = self.send(path, body, headers)
        response.raise_for_status()
        try:
            return response.json()
        except ValueError as exc:
            raise ProtocolError('invalid JSON acknowledgment') from exc

    def send(self, path, body, headers):
        last = None
        for step in range(len(self.endpoints)):
            index = (self.active + step) % len(self.endpoints)
            try:
                response = self.client.post(self.endpoints[index] + path, content=body, headers=headers)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                # Nothing reached the server, so the same signed request may try the next address.
                last = exc
                continue
            if index != self.active:
                log.info('server_endpoint_changed endpoint=%s', self.endpoints[index])
                self.active = index
            return response
        raise last

    def flush(self, queue):
        events, size = [], 0
        for event in queue.peek(self.config.batch_size):
            encoded = event.model_dump(mode='json')
            event_size = len(json.dumps(encoded, ensure_ascii=False).encode())
            if events and size + event_size > 512_000:
                break
            events.append(encoded)
            size += event_size
        if not events:
            return 0
        response = self.post('/api/v1/events/batch', {'events':events})
        expected = {e['event_id'] for e in events}
        received = response.get('accepted_ids') if isinstance(response, dict) else None
        if not isinstance(received, list) or any(not isinstance(x, str) for x in received) or set(received) != expected:
            raise ProtocolError('incomplete or unexpected acknowledgment')
        queue.ack(received)
        self.failures = 0
        return len(received)

    def backoff(self):
        self.failures += 1
        return min(300, 2 ** min(self.failures, 8)) * random.uniform(0.8, 1.2)

    def close(self):
        self.client.close()
