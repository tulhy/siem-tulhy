import os
import threading
import pytest

@pytest.mark.skipif(os.name!='nt',reason='Windows Service API')
def test_service_stop_contract():
    from agent.windows_service import TulhyService
    service = object.__new__(TulhyService)
    service.stop_event = threading.Event()
    reported = []
    service.ReportServiceStatus = lambda *a, **kw: reported.append((a,kw))
    service.SvcStop()
    assert service.stop_event.is_set() and reported
