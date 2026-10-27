"""Addresses by which LAN agents can reach this server, over cable or Wi-Fi."""
from ipaddress import ip_address
import re
import socket


def local_hostname():
    """Computer name usable in a URL and certificate, or None (then agents use IPs only)."""
    name = socket.gethostname().split('.')[0]
    return name if re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', name) else None


def private_ipv4s():
    """Private IPv4 addresses of adapters that are up (cable, Wi-Fi), never loopback or link-local."""
    import psutil
    stats = psutil.net_if_stats()
    found = set()
    for name, addresses in psutil.net_if_addrs().items():
        if name in stats and not stats[name].isup:
            continue
        for item in addresses:
            if item.family != socket.AF_INET:
                continue
            address = ip_address(item.address)
            if address.is_private and not (address.is_loopback or address.is_link_local or address.is_unspecified):
                found.add(str(address))
    return sorted(found, key=ip_address)


def endpoints(port, hostname, ips):
    """Agent order: the computer name follows IP changes; known IPs are fallbacks."""
    urls = ([f'https://{hostname}:{port}'] if hostname else []) + [f'https://{ip}:{port}' for ip in ips]
    if not urls:
        raise ValueError('Nenhum endereco de rede privado encontrado neste computador.')
    return urls
