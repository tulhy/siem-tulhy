from tests.conftest import ADMIN

def test_dashboard_and_stats(client, registered):
    assert client.get('/').status_code==200
    script = client.get('/static/app.js')
    assert script.status_code==200
    assert 'innerHTML' not in script.text and 'localStorage' not in script.text
    assert "frame-ancestors 'none'" in script.headers['content-security-policy']
    result = client.get('/api/v1/dashboard/stats',headers={'Authorization':'Bearer '+ADMIN})
    assert result.status_code==200, result.text
    stats = result.json()
    assert stats['agents_total']==1 and len(stats['timeline'])==24
