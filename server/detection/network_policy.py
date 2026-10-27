"""Server-controlled exceptions limited to access-monitoring policy rules."""
import json
import logging
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse
from server.settings import ROOT

REMOTE_RULES={'REMOTE_ACCESS_INBOUND','REMOTE_ACCESS_OUTBOUND','REMOTE_ACCESS_TOOL_NETWORK'}

def address(value):
    result=ip_address(value.split('%')[0])
    return getattr(result,'ipv4_mapped',None) or result

def server_addresses(settings):
    result=set()
    path=Path(settings.rules_dir).parent/'network_policy.json'
    if path.is_file():
        data=json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data,dict) or set(data)!={'server_ips'} or not isinstance(data['server_ips'],list):
            raise ValueError('network_policy.json must contain server_ips as an IP list')
        for item in data['server_ips']:
            if not isinstance(item,str):raise ValueError('server_ips requires individual IP addresses')
            result.add(address(item))
    # The local host launcher already records its actual endpoint here. Read only
    # the host part; never copy credentials into a rule or trust agent metadata.
    info=ROOT/'data/local-lab/server-info.json'
    if info.is_file():
        data=json.loads(info.read_text(encoding='utf-8'))
        # LAN mode records every cable/Wi-Fi address; older files only the URL host.
        for item in data.get('server_ips') or []:
            result.add(address(item))
        host=urlparse(data['server_url']).hostname
        try:
            result.add(address(host or ''))
        except ValueError:
            if not data.get('server_ips'):
                logging.getLogger('server.detection').warning('server_endpoint_uses_hostname_configure_server_ips_for_remote_access_exception')
    return result

def exempt_remote_access(rule_id,body,allowed):
    if rule_id not in REMOTE_RULES:return False
    value=(body.get('network') or {}).get('remote_ip')
    if not value:return False
    try:
        peer=address(value)
    except ValueError:
        return False
    return peer.is_loopback or peer in allowed
