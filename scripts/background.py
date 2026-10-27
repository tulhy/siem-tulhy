"""Visible, user-controlled background launcher. No service or autostart registration."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import psutil
from scripts.local_lab import ROOT, protect_directory

@contextmanager
def controller_lock(path):
    with open(path,'a+b') as stream:
        stream.seek(0,os.SEEK_END)
        if not stream.tell():
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        if os.name=='nt':
            import msvcrt
            msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name=='nt':
                msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
            else:
                fcntl.flock(stream.fileno(),fcntl.LOCK_UN)

def managed_process(record):
    try:
        process = psutil.Process(record['pid'])
        if abs(process.create_time()-record['created_at']) > .01:
            return None
        command = process.cmdline()
        if 'scripts.local_lab' not in command or record['ready_file'] not in command:
            return None
        return process
    except psutil.NoSuchProcess:
        return None

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['start','status','stop'])
    parser.add_argument('--data-dir',default=str(ROOT/'data/local-lab'))
    parser.add_argument('--lan-ip')
    parser.add_argument('--http-port',type=int,default=8000)
    parser.add_argument('--https-port',type=int,default=8443)
    parser.add_argument('--check',action='store_true',help='Synthetic-only validation without real endpoint collection')
    args = parser.parse_args()
    data = Path(args.data_dir).resolve()
    if args.action!='start' and not data.exists():
        print('SIEM parado: nenhuma execucao em segundo plano registrada.')
        return
    protect_directory(data)
    with controller_lock(data/'background.lock'):
        state_file, ready_file = data/'background.json', data/'background-ready.json'
        record = json.loads(state_file.read_text(encoding='utf-8')) if state_file.exists() else None
        process = managed_process(record) if record else None
        if args.action=='status':
            if process:
                print(f'SIEM em execucao em segundo plano (PID {process.pid}).')
                print('Inicializacao concluida.' if ready_file.exists() else 'Inicializando ou encerrando componentes.')
            else:
                print('SIEM parado. Confira background-launcher.log se houve falha.')
            print(f'Logs: {data}')
            return
        if args.action=='stop':
            if not process:
                print('SIEM ja esta parado.')
                return
            (data/'runtime.stop').write_text('stop',encoding='utf-8')
            try:
                process.wait(timeout=110)
            except psutil.TimeoutExpired as exc:
                raise RuntimeError('Parada ainda pendente. Confira os logs; o controlador nao encerrou outros processos por PID.') from exc
            print('SIEM parado. Banco de dados e fila preservados.')
            return
        if process:
            print(f'SIEM ja esta em segundo plano (PID {process.pid}); nenhuma instancia duplicada foi iniciada.')
            return
        ready_file.unlink(missing_ok=True)
        lan = bool(args.lan_ip)
        info_file = data/'server-info.json'
        if not lan and info_file.exists():
            # Keep LAN mode across restarts; addresses are rediscovered because cable/Wi-Fi IPs change.
            lan = bool(json.loads(info_file.read_text(encoding='utf-8')).get('lan'))
        command = [sys.executable,'-m','scripts.local_lab','--data-dir',str(data),'--http-port',str(args.http_port),
                   '--https-port',str(args.https_port),'--background-ready',str(ready_file)]
        if args.lan_ip:
            command.extend(['--lan-ip',args.lan_ip])
        elif lan:
            command.append('--lan')
        if args.check:
            command.append('--check')
        environment = dict(os.environ)
        environment.pop('SIEM_LAN_IP',None)
        environment.pop('SIEM_LAN',None)
        environment['PYTHONUNBUFFERED'] = '1'
        log_path = data/'background-launcher.log'
        if log_path.exists() and log_path.stat().st_size>5_000_000:
            log_path.replace(data/'background-launcher.previous.log')
        with open(log_path,'a',encoding='utf-8') as log:
            child = subprocess.Popen(command,cwd=ROOT,env=environment,stdin=subprocess.DEVNULL,stdout=log,
                stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0,
                start_new_session=os.name!='nt')
        record = {'pid':child.pid,'created_at':psutil.Process(child.pid).create_time(),'ready_file':str(ready_file)}
        state_file.write_text(json.dumps(record),encoding='utf-8')
        deadline = time.monotonic()+60
        while time.monotonic()<deadline:
            if child.poll() is not None:
                raise RuntimeError(f'Nao foi possivel iniciar o SIEM. Leia {log_path}')
            if ready_file.exists():
                print('SIEM iniciado em segundo plano. Pode fechar esta janela.')
                print(f'Dashboard: http://127.0.0.1:{args.http_port}/')
                print('Use STATUS_SIEM.cmd para verificar ou PARAR_SIEM.cmd para encerrar.')
                return
            time.sleep(.25)
        # Do not leave a failed or ambiguous launch running without an explicit stop request.
        (data/'runtime.stop').write_text('stop',encoding='utf-8')
        raise RuntimeError(f'Inicializacao excedeu 60s; parada solicitada. Confira {log_path}')

if __name__=='__main__':
    main()
