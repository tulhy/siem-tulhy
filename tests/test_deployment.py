from pathlib import Path
import yaml
from sqlalchemy.schema import CreateTable
from sqlalchemy.dialects import postgresql
from server.models.tables import Base
from server.settings import ROOT

def test_compose_isolation_and_schema_compiles():
    compose=yaml.safe_load((ROOT/'docker-compose.yml').read_text())
    assert 'ports' not in compose['services']['db']
    assert 'ports' not in compose['services']['server']
    assert compose['services']['server']['read_only']
    assert compose['networks']['backend']['internal']
    for table in Base.metadata.sorted_tables:
        assert str(CreateTable(table).compile(dialect=postgresql.dialect()))

def test_default_agent_config():
    from agent.config.settings import Config
    config=Config.model_validate(yaml.safe_load((ROOT/'config.yaml').read_text()))
    assert config.server_url.startswith('https:') and not config.collect_command_lines
