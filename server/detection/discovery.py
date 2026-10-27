"""Exact discovery destinations; never exempt a process name or all UDP."""
from ipaddress import ip_address

FLOOD_RULES = {'INBOUND_FLOOD', 'DISTRIBUTED_INBOUND_FLOOD'}

def discovery_event(body):
    network = body.get('network') or {}
    raw = body.get('raw_event') or {}
    if str(network.get('protocol', '')).upper() != 'UDP' or raw.get('direction') != 'inbound':
        return False
    try:
        destination = str(ip_address(str(network.get('local_ip', '')).split('%')[0]))
    except ValueError:
        return False
    return (destination, network.get('local_port')) in {
        ('224.0.0.251', 5353), ('ff02::fb', 5353),
        ('239.255.255.250', 3702), ('ff02::c', 3702),
    }

def eligible(rule, body):
    from server.services.policy_files import discard_event
    return not discard_event(body) and not (rule.id in FLOOD_RULES and discovery_event(body))
