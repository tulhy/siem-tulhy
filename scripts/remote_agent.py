"""Start a pre-enrolled remote agent without giving it the administrator credential."""
import json
import os
from pathlib import Path

def main():
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    if os.name == 'nt':
        import subprocess
        import win32api
        import win32security
        handle = win32security.OpenProcessToken(win32api.GetCurrentProcess(),win32security.TOKEN_QUERY)
        try:
            sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(handle,win32security.TokenUser)[0])
        finally:
            handle.Close()
        subprocess.run(['icacls.exe',str(root),'/inheritance:r','/grant:r','*'+sid+':(OI)(CI)F',
                        '*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F'],check=True,stdout=subprocess.DEVNULL)
    else:
        root.chmod(0o700)
    credentials = json.loads((root/'credentials.json').read_text(encoding='utf-8'))
    os.environ.pop('SIEM_ADMIN_TOKEN',None)
    os.environ.pop('SIEM_SERVER_URL',None)
    os.environ.pop('SIEM_STOP_FILE',None)
    os.environ.update(SIEM_AGENT_ID=credentials['agent_id'],SIEM_AGENT_TOKEN=credentials['agent_token'],
                      SIEM_AGENT_CONFIG=str(root/'config.yaml'),SIEM_CA_BUNDLE=str(root/'server-ca.pem'))
    print('Iniciando agente para o servidor configurado no config.yaml. Confirme a conexao pelo heartbeat no dashboard.')
    print('Mantenha esta janela aberta. Ctrl+C encerra o agente e preserva a fila local.')
    from agent.main import run
    run()

if __name__ == '__main__':
    main()
