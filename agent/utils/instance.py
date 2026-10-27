"""One Windows collector per computer, including different enrollment folders."""
import os
from contextlib import contextmanager


@contextmanager
def single_instance():
    if os.name != 'nt':
        yield
        return
    import win32api
    import win32event
    import winerror
    handle=win32event.CreateMutex(None,False,r'Global\TulhyAgentCollector')
    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        handle.Close()
        raise RuntimeError('Ja existe um agente Tulhy em execucao nesta maquina. Pare o agente manual ou o servico antes de iniciar outro.')
    try:
        yield
    finally:
        handle.Close()
