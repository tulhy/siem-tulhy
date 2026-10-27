"""ASGI limits apply to actual bytes, including chunked and compressed requests."""
import zlib
from starlette.responses import JSONResponse

class BodyLimits:
    def __init__(self, app, settings):
        self.app, self.settings = app, settings

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            chunk = message.get('body', b'')
            size += len(chunk)
            if size > self.settings.request_max_bytes:
                return await JSONResponse({'detail':'request too large'}, status_code=413)(scope, receive, send)
            chunks.append(chunk)
            if not message.get('more_body'):
                break
        raw = b''.join(chunks)
        scope.setdefault('state', {})['wire_body'] = raw
        headers = dict(scope['headers'])
        encoding = headers.get(b'content-encoding', b'identity')
        body = raw
        if encoding == b'gzip':
            try:
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                body = decoder.decompress(raw, self.settings.decompressed_max_bytes + 1)
                if len(body) > self.settings.decompressed_max_bytes or decoder.unconsumed_tail:
                    return await JSONResponse({'detail':'decompressed request too large'}, status_code=413)(scope, receive, send)
                if not decoder.eof or decoder.unused_data:
                    raise zlib.error('invalid gzip frame')
            except zlib.error:
                return await JSONResponse({'detail':'invalid gzip'}, status_code=400)(scope, receive, send)
        elif encoding != b'identity':
            return await JSONResponse({'detail':'unsupported encoding'}, status_code=415)(scope, receive, send)
        scope['headers'] = [(k,v) for k,v in scope['headers'] if k not in (b'content-encoding',b'content-length')] + [(b'content-length',str(len(body)).encode())]
        delivered = False
        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type':'http.request','body':body,'more_body':False}
            return await receive()
        async def secure_send(message):
            if message['type'] == 'http.response.start':
                message['headers'] += [(b'x-content-type-options', b'nosniff'), (b'cache-control',b'no-store'),
                    (b'content-security-policy', b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"),
                    (b'referrer-policy',b'no-referrer')]
            await send(message)
        await self.app(scope, replay, secure_send)
