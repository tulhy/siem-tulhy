import os
from pathlib import Path
from dataclasses import dataclass, field

ROOT = Path(__file__).resolve().parents[1]

@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: os.getenv('DATABASE_URL', 'sqlite:///data/server.db'))
    admin_token: str = field(default_factory=lambda: os.getenv('SIEM_ADMIN_TOKEN',''))
    rules_dir: str = field(default_factory=lambda: os.getenv('SIEM_RULES_DIR', str(ROOT/'rules/default_rules')))
    request_max_bytes: int = 1_048_576
    decompressed_max_bytes: int = 2_097_152
    replay_window: int = 300
    requests_per_minute: int = 180
    heartbeat_timeout: int = field(default_factory=lambda: int(os.getenv('SIEM_HEARTBEAT_TIMEOUT', '120')))
    monitor_interval: int = 15
    risk_window: int = 3600
    risk_weights: dict = field(default_factory=lambda: {'LOW':10, 'MEDIUM':25, 'HIGH':50, 'CRITICAL':80})
    risk_thresholds: tuple = (25, 50, 80)
    baseline_min_events: int = 30
    baseline_warmup_seconds: int = 3600
    risk_config_path: str = field(default_factory=lambda: os.getenv('SIEM_RISK_CONFIG', str(ROOT/'rules/risk.json')))
    # Unit shown beside "Central de Seguranca" (e.g. Filial Norte); empty = unchanged panel.
    site_name: str = field(default_factory=lambda: os.getenv('SIEM_SITE_NAME', '').strip())
    # Second secret required, besides the administrator token, to manage exclusions in the panel.
    exclusion_token: str = field(default_factory=lambda: os.getenv('SIEM_EXCLUSION_TOKEN', ''))
    # Public CA certificate offered to enrolling agents; they pin it by the fingerprint in their code.
    ca_file: str = field(default_factory=lambda: os.getenv('SIEM_CA_FILE', ''))

    def validate(self):
        if not self.admin_token:
            raise ValueError('Set SIEM_ADMIN_TOKEN (demo default: 123)')
        if len(self.site_name) > 40 or any(not ch.isprintable() for ch in self.site_name):
            raise ValueError('SIEM_SITE_NAME must be printable text up to 40 characters')
        if Path(self.risk_config_path).exists():
            import json
            data = json.loads(Path(self.risk_config_path).read_text())
            self.risk_weights = data['weights']
            self.risk_thresholds = tuple(data['thresholds'])
            self.risk_window = int(data['window_seconds'])
            if set(self.risk_weights) != {'LOW','MEDIUM','HIGH','CRITICAL'} or any(not isinstance(v,int) or v<0 for v in self.risk_weights.values()):
                raise ValueError('invalid risk weights')
            if len(self.risk_thresholds)!=3 or tuple(sorted(self.risk_thresholds)) != self.risk_thresholds or self.risk_window <= 0:
                raise ValueError('invalid risk thresholds/window')
