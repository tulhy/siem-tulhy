"""Explicit host/path exception evaluated after agent authentication."""
from ipaddress import ip_address, IPv6Address
import ntpath
import re
from pathlib import PureWindowsPath

def local_path(value):
    """Normalized absolute local path, or None. Never searches command lines or message text."""
    if not isinstance(value, str) or not value or '\x00' in value:
        return None
    # Defender can label a resource as file:_C:\path.
    if value.casefold().startswith('file:_'):
        value = value[6:]
    value = value.replace('/', '\\')
    # Normalize Windows drive namespaces without treating UNC shares as local.
    for prefix in ('\\\\?\\', '\\??\\'):
        if value.startswith(prefix) and len(value)>len(prefix)+2 and value[len(prefix)+1:len(prefix)+3]==':\\':
            value=value[len(prefix):]
    path = PureWindowsPath(ntpath.normpath(value))
    return path if path.is_absolute() else None

def within_path(value, root, directory=False):
    """Inside a full folder path, or below any folder with a bare name such as 123."""
    path = local_path(value)
    if path is None:
        return False
    from server.services.policy_files import is_folder_name
    if is_folder_name(root):
        # Folder components only: a file that happens to be called 123 is not a folder.
        folders = path.parts[1:] if directory else path.parts[1:-1]
        return root.casefold() in {part.casefold() for part in folders}
    # The directory itself is excluded even when the source omits its type.
    parts = path.parts
    root=PureWindowsPath(ntpath.normpath(str(root)))
    return tuple(p.casefold() for p in parts[:len(root.parts)]) == tuple(p.casefold() for p in root.parts)

def executable_key(value):
    """(drive or None, normalized path) of an executable; None when not an absolute local path.

    Windows Filtering Platform reports \\device\\harddiskvolumeN\\... instead of a drive
    letter; that form matches the same path on any drive letter.
    """
    if not isinstance(value, str) or not value or '\x00' in value:
        return None
    value = value.strip().strip('"').replace('/', '\\').casefold()
    for prefix in ('\\\\?\\', '\\??\\'):
        if value.startswith(prefix):
            value = value[len(prefix):]
    match = re.fullmatch(r'(?:([a-z]):|\\device\\harddiskvolume\d+)(\\.+)', value)
    if not match:
        return None
    return match.group(1), ntpath.normpath(match.group(2))

def for_machine(exclusion, address, hostname, default_all=False):
    """All machines, a machine name (as shown in the panel) or the authenticated sender IP."""
    if exclusion.all_agents:
        return True
    if exclusion.agent_name is not None:
        return exclusion.agent_name.casefold() == hostname
    if exclusion.agent_ip is not None:
        return address is not None and exclusion.agent_ip == str(address)
    return default_all

def covers(kind, exclusion, address, body):
    """Whether one enabled, unexpired exclusion applies to this event (address: authenticated sender IP or None)."""
    if not exclusion.active():
        return False
    # Ingestion already refused events whose hostname differs from the authenticated agent.
    hostname = str(body.get('hostname') or '').casefold()
    raw = body.get('raw_event') or {}
    file = body.get('file') or {}
    process = body.get('process') or {}
    if kind == 'process':
        # Antivirus and collection-health events are never dropped.
        if str(body.get('event_type', '')).casefold().startswith(('antivirus.', 'telemetry.')):
            return False
        key = executable_key(process.get('path'))
        if key is None or not for_machine(exclusion, address, hostname, default_all=True):
            return False
        for path in exclusion.paths:
            drive, rest = executable_key(path)
            if key[1] == rest and key[0] in (None, drive):
                return True
        return False
    if not for_machine(exclusion, address, hostname):
        return False
    if kind == 'extension':
        # File metadata only: mentioning a script in a command line does not exempt a process/network event.
        if not str(body.get('event_type','')).startswith('file.') or raw.get('directory') is True:
            return False
        value=file.get('destination') if body.get('event_type')=='file.moved' else file.get('path')
        if isinstance(value,str) and '\x00' not in value and PureWindowsPath(value).is_absolute():
            return PureWindowsPath(ntpath.normpath(value)).suffix.casefold() in exclusion.extensions
        return False
    directory = raw.get('directory') is True
    candidates = ((file.get('path'), directory), (file.get('destination'), directory), (process.get('path'), False),
                  (raw.get('affected_resource'), False), (raw.get('target_image'), False))
    return any(within_path(value, root, is_dir) for root in exclusion.paths for value, is_dir in candidates)

def sender(observed_ip):
    try:
        address = ip_address(observed_ip or '')
    except ValueError:
        return None
    if isinstance(address, IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address

def matching_exclusion(observed_ip, body):
    """First exclusion that applies to the event, or None: programs, then extensions, then folders."""
    from server.services.policy_files import policies
    policy = policies()[1]
    address = sender(observed_ip)
    for kind, exclusions in (('process', policy.process_exclusions), ('extension', policy.extension_exclusions),
                             ('path', policy.path_exclusions)):
        for exclusion in exclusions:
            if covers(kind, exclusion, address, body):
                return exclusion
    return None

def ignored_host_path(observed_ip, body):
    return matching_exclusion(observed_ip, body) is not None
