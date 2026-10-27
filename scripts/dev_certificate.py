"""Generate a short-lived localhost-only certificate without touching trust stores."""
import argparse
from datetime import datetime, timezone, timedelta
from ipaddress import ip_address
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

def generate(directory, extra_ips=()):
    root = Path(directory)
    root.mkdir(parents=True,exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Tulhy localhost development')])
    now = datetime.now(timezone.utc)
    addresses = [x509.DNSName('localhost'),x509.IPAddress(ip_address('127.0.0.1'))]
    addresses.extend(x509.IPAddress(ip_address(value)) for value in extra_ips if value != '127.0.0.1')
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
        .not_valid_after(now+timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(addresses),critical=False)
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(key,hashes.SHA256()))
    cert, secret = root/'localhost.pem', root/'localhost-key.pem'
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    secret.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    secret.chmod(0o600)
    return cert, secret

CA_DAYS = 3650
SERVER_DAYS = 397
RENEW_BEFORE = timedelta(days=30)


def _write_key(path, key):
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    path.chmod(0o600)


def ensure_ca(directory):
    """Long-lived private CA. Agents trust it, so server certificates can be reissued freely."""
    root = Path(directory)
    root.mkdir(parents=True,exist_ok=True)
    cert_path, key_path = root/'tulhy-ca.pem', root/'tulhy-ca-key.pem'
    if cert_path.exists() and key_path.exists():
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(),password=None)
        if cert.public_key().public_numbers() != key.public_key().public_numbers():
            raise ValueError('A chave da CA nao corresponde ao certificado; nada foi substituido.')
        return cert_path, key_path
    if cert_path.exists() or key_path.exists():
        raise ValueError('CA incompleta em '+str(root)+'; restaure o par certificado/chave antes de continuar.')
    key = rsa.generate_private_key(public_exponent=65537,key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SIEM Tulhy private CA')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
        .not_valid_after(now+timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,
            data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,
            encipher_only=False,decipher_only=False),critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
        .sign(key,hashes.SHA256()))
    _write_key(key_path,key)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def server_names(cert_path):
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return ({n.lower() for n in names.get_values_for_type(x509.DNSName)},
            {str(a) for a in names.get_values_for_type(x509.IPAddress)}, cert)


def issue_server(directory, ca_cert_path, ca_key_path, dns_names=(), ips=()):
    """Server certificate for every name/address agents may use; reissued only when needed."""
    root = Path(directory)
    cert_path, key_path = root/'localhost.pem', root/'localhost-key.pem'
    dns = {'localhost'} | {n.lower() for n in dns_names}
    addresses = {'127.0.0.1'} | {str(ip_address(a)) for a in ips}
    ca_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
    if cert_path.exists() and key_path.exists():
        have_dns, have_ips, current = server_names(cert_path)
        fresh = current.not_valid_after_utc - datetime.now(timezone.utc) > RENEW_BEFORE
        current_key = serialization.load_pem_private_key(key_path.read_bytes(),password=None)
        paired = current.public_key().public_numbers() == current_key.public_key().public_numbers()
        if paired and fresh and current.issuer == ca_cert.subject and dns <= have_dns and addresses <= have_ips:
            return cert_path, key_path
    ca_key = serialization.load_pem_private_key(Path(ca_key_path).read_bytes(),password=None)
    key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    now = datetime.now(timezone.utc)
    san = [x509.DNSName(n) for n in sorted(dns)] + [x509.IPAddress(ip_address(a)) for a in sorted(addresses)]
    cert = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SIEM Tulhy server')]))
        .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=SERVER_DAYS))
        .add_extension(x509.SubjectAlternativeName(san),critical=False)
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),critical=False)
        .sign(ca_key,hashes.SHA256()))
    # Key first: a crash between writes leaves a mismatched pair, which the next start replaces.
    _write_key(key_path,key)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM)+Path(ca_cert_path).read_bytes())
    return cert_path, key_path


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default='data/tls')
    args = parser.parse_args()
    cert, key = generate(args.output)
    print(f'Certificate: {cert}; key: {key}. Local development only. Protect the private key.')
