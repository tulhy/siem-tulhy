"""Visible, administrator-managed Windows Service host."""
import json
import os
import threading
from pathlib import Path
import servicemanager
import win32service
import win32serviceutil

class TulhyService(win32serviceutil.ServiceFramework):
    _svc_name_ = 'TulhyAgent'
    _svc_display_name_ = 'SIEM Tulhy Agent'
    _svc_description_ = 'Coleta defensiva de metadados e envio autenticado ao servidor Tulhy. Não executa comandos remotos.'

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=30000)
        self.stop_event.set()

    def SvcDoRun(self):
        for key in ('SIEM_STOP_FILE', 'SIEM_SERVER_URL', 'SIEM_ADMIN_TOKEN', 'SIEM_CA_BUNDLE'):
            os.environ.pop(key, None)
        root = Path(os.environ['ProgramData'])/'Tulhy'
        credentials = json.loads((root/'credentials.json').read_text(encoding='utf-8-sig'))
        os.environ['SIEM_AGENT_ID'] = credentials['agent_id']
        os.environ['SIEM_AGENT_TOKEN'] = credentials['agent_token']
        os.environ['SIEM_AGENT_CONFIG'] = str(root/'config.yaml')
        if (root/'ca.pem').exists():
            os.environ['SIEM_CA_BUNDLE'] = str(root/'ca.pem')
        from agent.main import run
        servicemanager.LogInfoMsg('TulhyAgent starting defensive collection')
        run(self.stop_event)
        servicemanager.LogInfoMsg('TulhyAgent stopped')

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(TulhyService)
