import os
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse
import yaml
from pydantic import Field, field_validator
from shared.events import Strict

class Config(Strict):
    server_url: str = 'https://localhost:8443'
    # Fallbacks tried in order when server_url is unreachable (e.g. server moved from cable to Wi-Fi).
    server_urls: list[str] = Field(default_factory=list, max_length=8)
    agent_name: str = ''
    data_dir: str = 'data/agent'
    collection_interval: float = Field(default=5, ge=1, le=3600)
    batch_size: int = Field(default=100, ge=1, le=200)
    heartbeat_interval: float = Field(default=30, ge=5, le=3600)
    queue_max_size: int = Field(default=100_000, ge=1)
    queue_max_bytes: int = Field(default=256_000_000, ge=16384)
    timeout: float = Field(default=15, ge=1, le=120)
    log_level: str = 'INFO'
    monitor_paths: list[str] = Field(default_factory=list)
    connection_profile: Literal['local','remote'] = 'local'
    send_idle_interval: float = Field(default=300, ge=1, le=3600)
    send_batch_interval: float = Field(default=2, ge=0.1, le=60)
    file_inventory_enabled: bool = True
    file_inventory_interval: int = Field(default=300, ge=60, le=86400)
    file_inventory_step_entries: int = Field(default=300, ge=1, le=1000)
    file_inventory_max_entries: int = Field(default=100_000, ge=1, le=1_000_000)
    file_inventory_max_files: int = Field(default=10_000, ge=1, le=50_000)
    collect_command_lines: bool = False
    hash_max_bytes: int = Field(default=50_000_000, ge=0)
    windows_events: bool = True
    windows_lookback_seconds: int = Field(default=300, ge=1, le=86400)
    cpu_threshold: int = Field(default=90, ge=1, le=100)
    memory_threshold: int = Field(default=90, ge=1, le=100)
    disk_threshold: int = Field(default=95, ge=1, le=100)
    @field_validator('server_url')
    @classmethod
    def https_only(cls, value):
        u = urlparse(value)
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('', '/'):
            raise ValueError('server_url must be an HTTPS origin')
        return value.rstrip('/')

    @field_validator('server_urls')
    @classmethod
    def https_fallbacks(cls, values):
        return [cls.https_only(value) for value in values]

    @property
    def endpoints(self):
        return list(dict.fromkeys([self.server_url, *self.server_urls]))

def load():
    path = Path(os.getenv('SIEM_AGENT_CONFIG', 'config.yaml'))
    data = yaml.safe_load(path.read_text(encoding='utf-8')) if path.exists() else {}
    if os.getenv('SIEM_SERVER_URL'):
        data['server_url'] = os.environ['SIEM_SERVER_URL']
    return Config.model_validate(data or {})
