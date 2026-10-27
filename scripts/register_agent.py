"""Register one agent over validated HTTPS; save the one-time token to a protected file."""
import argparse
import json
import os
import ssl
from pathlib import Path
import httpx
from agent.config.settings import Config

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server',required=True)
    parser.add_argument('--hostname',required=True)
    parser.add_argument('--output',default='data/agent-credentials.json')
    args=parser.parse_args()
    server=Config(server_url=args.server).server_url
    target=Path(args.output)
    target.parent.mkdir(parents=True,exist_ok=True)
    # Reserve path first so an existing credential is never overwritten.
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        if os.name=='nt':
            import subprocess
            import win32api
            import win32security
            process_token=win32security.OpenProcessToken(win32api.GetCurrentProcess(),win32security.TOKEN_QUERY)
            try:
                sid=win32security.ConvertSidToStringSid(win32security.GetTokenInformation(process_token,win32security.TokenUser)[0])
            finally:
                process_token.Close()
            subprocess.run(['icacls.exe',str(target),'/inheritance:r','/grant:r',
                '*'+sid+':F','*S-1-5-18:F','*S-1-5-32-544:F'],check=True,stdout=subprocess.DEVNULL)
        context=ssl.create_default_context(cafile=os.getenv('SIEM_CA_BUNDLE') or None)
        with httpx.Client(verify=context,timeout=15,trust_env=False) as client:
            response=client.post(server+'/api/v1/agents/register',json={'hostname':args.hostname},
                                 headers={'Authorization':'Bearer '+os.environ['SIEM_ADMIN_TOKEN']})
            response.raise_for_status()
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            fd=-1
            json.dump(response.json(),stream)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd>=0:
            os.close(fd)
    print(f'Agent credentials saved with restricted permissions to {target}. Never commit it.')

if __name__=='__main__':
    main()
