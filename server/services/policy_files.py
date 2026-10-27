"""Validated, atomic snapshots of editable JSON policy. Never executes code."""
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path, PureWindowsPath
from ipaddress import ip_address
import threading
import time
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from server.detection.rules import Rule
from shared.events import Severity

ROOT=Path(__file__).resolve().parents[2]
NAMES=('regras_de_usuarios.json','regras_de_alertas.json','regras_de_eventos.json')

class Strict(BaseModel):
    model_config=ConfigDict(extra='forbid')
    schema_version: int=Field(default=1,ge=1,le=1)

FOLDER_NAME_FORBIDDEN = set('<>:"/\\|?*')


def is_folder_name(value):
    """A bare folder name (e.g. 123) matches any folder with that name; anything else is a full path."""
    return not any(ch in value for ch in '\\/:')


def one_machine(exclusion):
    # The machine name shown in the panel survives DHCP and cable/Wi-Fi changes; an IP does not.
    chosen = (exclusion.agent_ip is not None) + (exclusion.agent_name is not None) + bool(exclusion.all_agents)
    if chosen != 1:
        raise ValueError('choose exactly one: agent_name (machine name as shown in the panel), agent_ip or all_agents')
    return exclusion


class ExclusionMeta(BaseModel):
    """Fields managed by the panel; files edited by hand may omit them."""
    model_config=ConfigDict(extra='forbid')
    id: str|None=Field(default=None,pattern=r'^[0-9a-f]{8,32}$')
    description: str=Field(default='',max_length=500)
    keep_events: bool=False  # True: events stay visible in Events but never alert
    created_at: str|None=Field(default=None,max_length=40)
    all_agents: bool=False
    agent_ip: str|None=None
    agent_name: str|None=Field(default=None,min_length=1,max_length=255)
    enabled: bool=True
    expires_at: datetime|None=None  # after this moment the exclusion stops applying (alerts come back)

    @field_validator('expires_at')
    @classmethod
    def aware(cls,value):
        return value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc)

    def expired(self,now=None):
        return self.expires_at is not None and self.expires_at<=(now or datetime.now(timezone.utc))

    def active(self,now=None):
        return self.enabled and not self.expired(now)

    @field_validator('agent_ip')
    @classmethod
    def valid_ip(cls,value):
        if value is None:
            return None
        address=ip_address(value)
        return str(getattr(address,'ipv4_mapped',None) or address)


class PathExclusion(ExclusionMeta):
    paths: list[str]=Field(min_length=1,max_length=100)

    @model_validator(mode='after')
    def machine_scope(self):
        return one_machine(self)

    @field_validator('paths')
    @classmethod
    def valid_paths(cls,values):
        for value in values:
            if is_folder_name(value):
                name=value.strip()
                if (not name or name in ('.','..') or len(name)>255 or name!=value
                        or any(ch in FOLDER_NAME_FORBIDDEN or ord(ch)<32 for ch in name)):
                    raise ValueError('folder name invalid: use only the name, e.g. 123, or a full path')
                continue
            p=PureWindowsPath(value)
            if not p.is_absolute() or len(p.parts)<2 or '..' in p.parts or '\x00' in value:
                raise ValueError('use a folder name (e.g. 123) or an absolute folder path, never a drive root')
        return values


class ExtensionExclusion(ExclusionMeta):
    extensions: list[str]=Field(min_length=1,max_length=20)

    @model_validator(mode='after')
    def machine_scope(self):
        return one_machine(self)

    @field_validator('extensions')
    @classmethod
    def valid_extensions(cls, values):
        import re
        if any(not re.fullmatch(r'\.[a-zA-Z0-9]{1,12}',v) for v in values):
            raise ValueError('use suffixes such as .py')
        return [v.casefold() for v in values]


class ProcessExclusion(ExclusionMeta):
    """Events whose process is exactly one of these executables; no machine given = every agent."""
    paths: list[str]=Field(min_length=1,max_length=100)

    @model_validator(mode='after')
    def machine_scope(self):
        chosen = (self.agent_ip is not None) + (self.agent_name is not None) + bool(self.all_agents)
        if chosen > 1:
            raise ValueError('choose at most one: agent_name, agent_ip or all_agents')
        return self

    @field_validator('paths')
    @classmethod
    def valid_paths(cls,values):
        for value in values:
            p=PureWindowsPath(value)
            if not p.drive or not p.is_absolute() or len(p.parts)<3 or '..' in p.parts or '\x00' in value or p.suffix.casefold()!='.exe':
                raise ValueError('use the full path of an .exe file, such as C:\\Windows\\System32\\spoolsv.exe')
        return values

class UserPolicies(Strict):
    rules: list[Rule]=Field(default_factory=list,max_length=1000)

    @model_validator(mode='after')
    def user_scope(self):
        for rule in self.rules:
            if not any(c.field=='user' and c.op in ('eq','in') for c in rule.conditions):
                raise ValueError('user rule requires a user eq/in condition')
        return self

class AlertPolicies(Strict):
    extension_exclusions: list[ExtensionExclusion]=Field(default_factory=list,max_length=100)
    process_exclusions: list[ProcessExclusion]=Field(default_factory=list,max_length=100)
    # Remote peers whose network events never feed detection; the events stay visible in the panel.
    ignored_remote_ips: list[str]=Field(default_factory=list,max_length=5000)

    @field_validator('ignored_remote_ips')
    @classmethod
    def valid_remote_ips(cls,values):
        from server.detection.ignored_network_ips import normalized
        return list(dict.fromkeys(normalized(value) for value in values))
    path_exclusions: list[PathExclusion]=Field(default_factory=list,max_length=100)
    rules: list[Rule]=Field(min_length=1,max_length=1000)
    suppress_severities: list[Severity]=Field(default_factory=lambda:['LOW'])
    disabled_rule_ids: list[str]=Field(default_factory=lambda:['TELEMETRY_LOST'])
    mandatory_severities: list[Literal['HIGH','CRITICAL']]=Field(default_factory=lambda:['HIGH','CRITICAL'])

class EventPolicies(Strict):
    discard_severities: list[Severity]=Field(default_factory=lambda:['LOW'])
    discard_types: list[str]=Field(default_factory=lambda:['telemetry_lost','telemetry.lost'])
    keep_types_at_severities: list[Severity]=Field(default_factory=lambda:['HIGH','CRITICAL'])

def validate_bundle(data):
    users=UserPolicies.model_validate(data[0]);alerts=AlertPolicies.model_validate(data[1]);events=EventPolicies.model_validate(data[2])
    rules=alerts.rules+users.rules
    if len({r.id for r in rules})!=len(rules):raise ValueError('duplicate rule IDs across policy files')
    return users,alerts,events

class PolicyStore:
    def __init__(self,directory,interval=2):
        self.directory=Path(directory);self.interval=interval;self.active=None
        self.signature=None;self.next_check=0;self.lock=threading.RLock()

    def get(self):
        with self.lock:
            now=time.monotonic()
            if self.active is not None and now<self.next_check:return self.active
            self.next_check=now+self.interval
            try:
                paths=[self.directory/name for name in NAMES]
                signature=tuple((p.stat().st_mtime_ns,p.stat().st_size) for p in paths)
                if self.active is not None and signature==self.signature:return self.active
                if any(size>2_000_000 for _,size in signature):raise ValueError('policy file too large')
                data=[json.loads(p.read_text(encoding='utf-8-sig')) for p in paths]
                candidate=validate_bundle(data)
                if signature!=tuple((p.stat().st_mtime_ns,p.stat().st_size) for p in paths):
                    raise ValueError('policy changed while reading')
            except (OSError,ValueError,UnicodeError):
                logging.getLogger('server.policy').error('policy_reload_rejected_previous_valid_kept')
                if self.active is None:raise
                return self.active
            self.active=candidate;self.signature=signature
            logging.getLogger('server.policy').info('policy_reload_applied')
            return self.active

_stores={}
_lock=threading.Lock()
_edit_lock=threading.Lock()
BACKUPS_KEPT=100

def policy_directory():
    return Path(os.getenv('SIEM_POLICY_DIR',str(ROOT/'rules'))).resolve()

def policies():
    directory=policy_directory()
    with _lock:
        store=_stores.setdefault(str(directory),PolicyStore(directory))
    return store.get()

def edit_alert_policy(change):
    """Apply change(data) to regras_de_alertas.json: validated first, previous file backed up, atomic write.

    Raises ValueError (nothing written) when the result would be an invalid policy.
    """
    directory=policy_directory()
    target=directory/NAMES[1]
    with _edit_lock:
        raw=target.read_bytes()
        newline='\r\n' if b'\r\n' in raw else '\n'
        data=json.loads(raw.decode('utf-8-sig'))
        result=change(data)
        others=[json.loads((directory/name).read_text(encoding='utf-8-sig')) for name in (NAMES[0],NAMES[2])]
        validate_bundle([others[0],data,others[1]])
        backups=directory/'backups'
        backups.mkdir(exist_ok=True)
        (backups/f'regras_de_alertas-{time.strftime("%Y%m%d-%H%M%S")}-{os.urandom(3).hex()}.json').write_bytes(raw)
        for old in sorted(backups.glob('regras_de_alertas-*.json'))[:-BACKUPS_KEPT]:
            old.unlink(missing_ok=True)
        temporary=target.with_name(target.name+'.'+os.urandom(6).hex()+'.panel')
        try:
            temporary.write_bytes((json.dumps(data,indent=2,ensure_ascii=False)+'\n').replace('\n',newline).encode('utf-8'))
            os.replace(temporary,target)
        finally:
            temporary.unlink(missing_ok=True)
        with _lock:
            store=_stores.get(str(directory))
        if store:
            with store.lock:
                store.next_check=0  # this process sees the change at once; others within 2 seconds
    logging.getLogger('server.audit').warning('alert_policy_changed_from_panel')
    return result

def discard_event(body):
    _,_,policy=policies()
    severity=body.get('severity');kind=str(body.get('event_type','')).casefold()
    return severity in policy.discard_severities or (severity not in policy.keep_types_at_severities and kind in policy.discard_types)

def suppress_rule(rule):
    _,policy,_=policies()
    return rule.severity in policy.suppress_severities or rule.id in policy.disabled_rule_ids
