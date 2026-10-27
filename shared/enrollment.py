"""Enrollment code: where the server is, how to recognise it, and a one-purpose secret.

The code is pasted on the new machine. Its CA fingerprint lets the agent trust the
server's private CA without carrying any file, and the secret only allows registering
agents while the code is valid on the server.
"""
import base64
import hashlib
import json
from ipaddress import ip_address
import re
import ssl

PREFIX = 'SNT1-'
HOST = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?')
SECRET = re.compile(r'[A-Za-z0-9_-]{16,64}')
FINGERPRINT = re.compile(r'[A-Za-z0-9_-]{22}')


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def ca_fingerprint(pem):
    """First 128 bits of the SHA-256 of the first certificate in a PEM text."""
    match = re.search(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', pem, re.S)
    if not match:
        raise ValueError('no certificate in PEM')
    return _b64(hashlib.sha256(ssl.PEM_cert_to_DER_cert(match.group(0))).digest()[:16])


def encode(host, ips, port, fingerprint, secret):
    value = {'h': host, 'i': list(ips), 'p': port, 'f': fingerprint, 's': secret}
    _validate(value)
    return PREFIX + _b64(json.dumps(value, separators=(',', ':')).encode())


def decode(code):
    text = ''.join(str(code).split())  # tolerate line breaks and spaces from copy/paste
    if not text.startswith(PREFIX):
        raise ValueError('Codigo invalido: deve comecar com ' + PREFIX)
    try:
        raw = text[len(PREFIX):]
        value = json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError('Codigo invalido ou incompleto; copie o codigo inteiro.') from exc
    _validate(value)
    return value


def endpoints(value):
    hosts = ([value['h']] if value.get('h') else []) + value['i']
    return [f"https://{host}:{value['p']}" for host in hosts]


def _validate(value):
    if not isinstance(value, dict) or set(value) != {'h', 'i', 'p', 'f', 's'}:
        raise ValueError('Codigo invalido.')
    if value['h'] is not None and not (isinstance(value['h'], str) and HOST.fullmatch(value['h'])):
        raise ValueError('Codigo invalido: nome do servidor.')
    if not isinstance(value['i'], list) or len(value['i']) > 8:
        raise ValueError('Codigo invalido: enderecos do servidor.')
    for item in value['i']:
        address = ip_address(item)
        if address.version != 4 or not address.is_private or address.is_loopback:
            raise ValueError('Codigo invalido: endereco do servidor.')
    if not value['h'] and not value['i']:
        raise ValueError('Codigo invalido: sem endereco do servidor.')
    if not isinstance(value['p'], int) or not 1 <= value['p'] <= 65535:
        raise ValueError('Codigo invalido: porta.')
    if not isinstance(value['f'], str) or not FINGERPRINT.fullmatch(value['f']):
        raise ValueError('Codigo invalido: certificado.')
    if not isinstance(value['s'], str) or not SECRET.fullmatch(value['s']):
        raise ValueError('Codigo invalido: segredo.')
