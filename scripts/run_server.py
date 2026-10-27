"""Uvicorn entry point with a local stop-file signal for background operation."""
import argparse
import os
from pathlib import Path
import threading
import uvicorn

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=8000)
    parser.add_argument('--ssl-certfile')
    parser.add_argument('--ssl-keyfile')
    parser.add_argument('--no-access-log',action='store_true')
    args = parser.parse_args()
    server = uvicorn.Server(uvicorn.Config('server.main:app',host=args.host,port=args.port,
        ssl_certfile=args.ssl_certfile,ssl_keyfile=args.ssl_keyfile,access_log=not args.no_access_log))
    done = threading.Event()
    stop_path = os.getenv('SIEM_STOP_FILE')
    def watch_stop():
        while not done.wait(.25):
            if Path(stop_path).exists():
                server.should_exit = True
                return
    watcher = threading.Thread(target=watch_stop,name='local-stop-signal',daemon=True) if stop_path else None
    if watcher:
        watcher.start()
    try:
        server.run()
    finally:
        done.set()
        if watcher:
            watcher.join(2)

if __name__ == '__main__':
    main()
