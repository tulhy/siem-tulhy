import pytest
from server.detection.engine import DetectionEngine
from server.detection.ignored_network_ips import ignored_network_event, normalized
from server.services.policy_files import AlertPolicies
from shared.events import Event
from tests.conftest import ADMIN, signed
from tests.policy_copy import policy_copy


@pytest.fixture(autouse=True)
def example_list(tmp_path, monkeypatch):
    policy_copy(tmp_path, monkeypatch, ignored_remote_ips=['8.8.8.8', '1.1.1.1', '2606:4700:7::1fd', 'fe80::6a55:d4ff:fe85:40fa'])


def http(registered, remote_ip):
    return Event(agent_id=registered['agent_id'], hostname='test', event_type='network.connection', source='teste',
                 severity='HIGH', process={'name':'chrome.exe', 'path':r'C:\Program Files\Google\Chrome\chrome.exe'},
                 network={'remote_ip':remote_ip, 'remote_port':80, 'protocol':'TCP'},
                 raw_event={'direction':'outbound'}).model_dump(mode='json')


def test_listed_remote_ip_never_alerts_but_event_stays_visible(client, registered):
    for ip in ('8.8.8.8', '203.0.113.9'):  # 8.8.8.8 is in the example list; 203.0.113.9 is not
        assert signed(client, registered, '/api/v1/events/batch', {'events':[http(registered, ip)]}).status_code == 200
    DetectionEngine(client.app.state.settings).process_pending(client.app.state.sessions)
    headers = {'Authorization':'Bearer '+ADMIN}
    alerted = {e for a in client.get('/api/v1/alerts', headers=headers).json() for e in a['event_ids']}
    shown = {e['network']['remote_ip']:e for e in client.get('/api/v1/events', headers=headers).json()}
    assert shown['8.8.8.8']['network_alerts_ignored'] is True and shown['8.8.8.8']['event_id'] not in alerted
    assert shown['203.0.113.9']['event_id'] in alerted and 'network_alerts_ignored' not in shown['203.0.113.9']


@pytest.mark.parametrize('written', ['fe80::6a55:d4ff:fe85:40fa%12', 'FE80::6A55:D4FF:FE85:40FA', '::ffff:1.1.1.1',
                                     '2606:4700:0007:0000:0000:0000:0000:01fd'])
def test_any_spelling_of_a_listed_address_matches(written):
    assert ignored_network_event({'event_type':'network.connection', 'network':{'remote_ip':written}})


def test_only_network_events_and_listed_addresses():
    assert not ignored_network_event({'event_type':'network.connection', 'network':{'remote_ip':'8.8.4.4'}})
    assert not ignored_network_event({'event_type':'process.start', 'network':{'remote_ip':'8.8.8.8'}})
    assert not ignored_network_event({'event_type':'network.connection', 'network':{'remote_ip':'not-an-ip'}})


def test_policy_list_is_validated_and_normalized():
    from server.services import policy_files
    base = policy_files.policies()[1].model_dump()
    checked = AlertPolicies.model_validate({**base, 'ignored_remote_ips':['::ffff:9.9.9.9', '9.9.9.9', 'fe80::1%3']})
    assert checked.ignored_remote_ips == ['9.9.9.9', 'fe80::1']
    with pytest.raises(ValueError):
        AlertPolicies.model_validate({**base, 'ignored_remote_ips':['8.8.8']})
    assert normalized(' 1.1.1.1 ') == '1.1.1.1'
