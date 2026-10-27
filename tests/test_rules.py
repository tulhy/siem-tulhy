import pytest
from server.detection.rules import Condition, Rule, matches, load_rules
from server.settings import ROOT

def test_conditions_and_files():
    assert matches(Condition(field='process.path',op='contains',value='TEMP'),{'process':{'path':'C:/temp/a'}})
    assert not matches(Condition(field='process.path',op='ne',value='x'),{})
    assert matches(Condition(field='network.remote_ip',op='cidr',value='10.0.0.0/8'),{'network':{'remote_ip':'10.1.2.3'}})
    assert len(load_rules(ROOT/'rules/default_rules')) >= 6
    with pytest.raises(ValueError):
        Condition(field='__class__',value='x')
    with pytest.raises(ValueError):
        Condition(field='process.name',op='regex',value='.*')

def test_engine_explains_alert(client, registered):
    from tests.conftest import signed, ADMIN
    from tests.test_api import event
    from server.detection.engine import DetectionEngine
    e = event(registered,process={'path':r'C:\Temp\benign.exe'})
    assert signed(client,registered,'/api/v1/events',e).status_code == 200
    engine = DetectionEngine(client.app.state.settings)
    engine.sync_rules(client.app.state.sessions())
    assert engine.process_pending(client.app.state.sessions) == 1
    alerts = client.get('/api/v1/alerts',headers={'Authorization':'Bearer '+ADMIN}).json()
    assert alerts[0]['rule_id'] == 'TEMP_EXECUTION'
    assert alerts[0]['evidence']['conditions'] and alerts[0]['event_ids'] == [e['event_id']]
    assert engine.process_pending(client.app.state.sessions) == 0
