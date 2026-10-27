"""Declarative rules; no eval, executable plugins, arbitrary imports or regex."""
import json
from functools import lru_cache
from pathlib import Path
from typing import Literal
import yaml
from pydantic import Field, model_validator
from shared.events import Strict, Severity

class Condition(Strict):
    field: str = Field(pattern=r'^(event_type|severity|source|user|hostname|process\.(name|path|pid|ppid|sha256|command_line|created_at)|network\.(remote_ip|local_ip|remote_port|local_port|protocol)|file\.(path|destination|sha256)|raw_event\.[a-zA-Z0-9_]+)$')
    op: Literal['eq','ne','contains','contains_any','in','gte','exists','cidr','ends_with','domain_suffix'] = 'eq'
    value: str | int | float | bool | list[str | int] | None = None

    @model_validator(mode='after')
    def valid_operator(self):
        if self.op in ('contains_any','in','ends_with','domain_suffix') and not isinstance(self.value, list):
            raise ValueError('list required')
        if self.op in ('ends_with','domain_suffix') and (not self.value or any(not isinstance(v,str) or not v for v in self.value)):
            raise ValueError('nonempty string list required')
        if self.op == 'domain_suffix':
            for domain in self.value:
                normalize_domain(domain)
        if self.op == 'cidr':
            from ipaddress import ip_network
            ip_network(self.value)
        if self.op == 'gte' and (isinstance(self.value,bool) or not isinstance(self.value,(int,float))):
            raise ValueError('numeric threshold required')
        return self

class Rule(Strict):
    id: str = Field(pattern=r'^[A-Z0-9_-]{1,128}$')
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    category: str
    severity: Severity
    confidence: Severity = 'MEDIUM'
    conditions: list[Condition] = Field(min_length=1, max_length=20)
    window_seconds: int = Field(default=300, ge=1, le=86400)
    threshold: int = Field(default=1, ge=1, le=1000)
    distinct_field: Literal['network.local_port','network.remote_port','network.remote_ip'] | None = None
    distinct_threshold: int = Field(default=1, ge=1, le=1000)
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    sequence: list[list[Condition]] = Field(default_factory=list, max_length=8)
    group_by: list[Literal['user','source','process.pid','process.created_at','process.name','network.remote_ip','raw_event.process_guid']] = Field(default_factory=list)

    @model_validator(mode='after')
    def valid_sequence(self):
        if self.sequence and (self.threshold != 1 or any(not stage for stage in self.sequence)):
            raise ValueError('sequence requires nonempty stages and threshold=1')
        if self.distinct_field and (self.sequence or self.distinct_threshold > self.threshold):
            raise ValueError('distinct counts require a threshold rule and cannot exceed its threshold')
        return self


@lru_cache(maxsize=32768)
def normalize_domain(value):
    import re
    value=value.rstrip('.').encode('idna').decode('ascii').lower()
    if len(value)>253 or '.' not in value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in value.split('.')):
        raise ValueError('invalid domain name')
    return value

def get_field(data, path):
    current = data
    for part in path.split('.'):
        if not isinstance(current,dict):
            return None
        current = current.get(part)
    return current

def matches(condition, data):
    actual, target = get_field(data, condition.field), condition.value
    if condition.op == 'exists':
        return (actual is not None) == (target is not False)
    if actual is None:
        return False
    a = actual.casefold() if isinstance(actual,str) else actual
    b = target.casefold() if isinstance(target,str) else target
    if condition.op == 'eq':
        return a == b
    if condition.op == 'ne':
        return a != b
    if condition.op == 'contains':
        return isinstance(a,str) and isinstance(b,str) and b in a
    if condition.op == 'contains_any':
        return isinstance(a,str) and any(str(x).casefold() in a for x in target)
    if condition.op == 'in':
        return a in [x.casefold() if isinstance(x,str) else x for x in target]
    if condition.op == 'ends_with':
        return isinstance(a,str) and a.endswith(tuple(x.casefold() for x in target))
    if condition.op == 'domain_suffix':
        if not isinstance(actual,str):return False
        try:
            domain=normalize_domain(actual)
        except (ValueError,UnicodeError):
            return False
        return any(domain==normalize_domain(x) or domain.endswith('.'+normalize_domain(x)) for x in target)
    if condition.op == 'gte':
        return isinstance(actual,(int,float)) and actual >= target
    if condition.op == 'cidr':
        from ipaddress import ip_address, ip_network
        try:
            return ip_address(actual) in ip_network(target)
        except ValueError:
            return False
    raise ValueError('unsupported operator')

def all_match(conditions, body):
    return all(matches(condition, body) for condition in conditions)

def load_rules(directory):
    from server.services.policy_files import ROOT, policies
    if Path(directory).resolve()==(ROOT/'rules/default_rules').resolve():
        users,alerts,_=policies()
        return list(alerts.rules)+list(users.rules)
    rules = []
    for path in sorted(Path(directory).glob('*')):
        if path.suffix not in ('.json','.yaml','.yml'):
            continue
        data = json.loads(path.read_text(encoding='utf-8')) if path.suffix == '.json' else yaml.safe_load(path.read_text(encoding='utf-8'))
        rules.extend(Rule.model_validate(item) for item in (data if isinstance(data,list) else [data]))
    if len({r.id for r in rules}) != len(rules):
        raise ValueError('duplicate rule IDs')
    if not rules:
        raise ValueError('no rules found')
    return rules
