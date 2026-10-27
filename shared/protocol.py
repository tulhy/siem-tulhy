import hashlib
import hmac

def signature(token, method, path, timestamp, nonce, body):
    message = '\n'.join((method.upper(), path, timestamp, nonce, hashlib.sha256(body).hexdigest()))
    return hmac.new(token.encode(), message.encode(), hashlib.sha256).hexdigest()

def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()
