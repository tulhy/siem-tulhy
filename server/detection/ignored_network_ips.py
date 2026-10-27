"""Explicit organization policy: remote peers excluded from network detection.

The editable list lives in rules/regras_de_alertas.json ("ignored_remote_ips") and reloads
without a restart; the events themselves are kept and shown in the panel.
"""
from ipaddress import ip_address

BUILTIN_IPS = frozenset({'224.0.0.251'})  # mDNS multicast


def normalized(value):
    """Canonical text of an address: IPv6 zone (%12) dropped, IPv4-mapped IPv6 as IPv4."""
    address = ip_address(str(value).strip().split('%')[0])
    return str(getattr(address, 'ipv4_mapped', None) or address)


def ignored_ips():
    from server.services.policy_files import policies
    return BUILTIN_IPS | set(policies()[1].ignored_remote_ips)


def ignored_network_event(body):
    if not str(body.get('event_type','')).startswith('network.'):
        return False
    value = (body.get('network') or {}).get('remote_ip')
    if not isinstance(value,str):
        return False
    try:
        return normalized(value) in ignored_ips()
    except ValueError:
        return False


def ignored_network_sql():
    from sqlalchemy import and_, func
    from server.models.tables import EventRow
    addresses = sorted(ignored_ips())
    addresses += ['::ffff:'+value for value in addresses if '.' in value]
    return func.coalesce(and_(EventRow.event_type.startswith('network.'),
        func.lower(EventRow.ip).in_(addresses)),False)
