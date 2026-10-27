from pathlib import Path
import hashlib
import json
import os
import time
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from agent.collectors.downloads import DownloadCollector
from agent.collectors.download_locations import redirected_downloads

POLICY_EXTENSIONS = {'.py', '.vbs', '.htm', '.bat'}

def policy_file(path):
    return Path(path).suffix.lower() in POLICY_EXTENSIONS

def default_inventory_paths():
    """Metadata inventory scopes; never read file contents or traverse every disk."""
    if os.name != 'nt':
        return []
    users = Path(os.environ.get('SystemDrive', 'C:') + '/Users')
    paths = []
    if users.is_dir():
        try:
            profiles = [p for p in users.iterdir() if p.is_dir() and not p.is_symlink() and not p.is_junction()]
        except OSError:
            profiles = []
        for profile in profiles:
            paths.extend(profile/relative for relative in ('Downloads','Desktop','Documents','AppData/Local/Temp',
                'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'))
    paths.append(Path(os.environ.get('ProgramData', 'C:/ProgramData'))/'Microsoft/Windows/Start Menu/Programs/Startup')
    return [p for p in paths if p.is_dir()]

class FileCollector(FileSystemEventHandler):
    def __init__(self, normalizer, emit, paths, state=None, config=None):
        self.n, self.emit = normalizer, emit
        self.state, self.config = state, config
        self.downloads = DownloadCollector(normalizer,emit,state,
            lambda:list(dict.fromkeys([p for p in default_inventory_paths() if p.name.casefold() in ('downloads','download')]
                                     + redirected_downloads())))
        self.paths = [Path(path) for path in paths]
        self.inventory = None
        self.next_inventory = 0
        self.inventory_entries = 0
        self.inventory_files = 0
        self.warned = set()
        self.known = json.loads(state.get_state('files:policy_inventory') or '{}') if state else {}
        self.observer = Observer()
        self.scheduled = False
        for path in paths:
            if Path(path).is_dir():
                self.observer.schedule(self, path, recursive=True)
                self.scheduled = True
            else:
                emit(self.n.event('telemetry.integrity', 'watchdog', severity='MEDIUM',
                                 raw_event={'reason':'monitor_path_unavailable', 'path':path}))

    def on_any_event(self, event):
        if event.event_type not in ('created', 'modified', 'deleted', 'moved'):
            return
        target=Path(event.dest_path if event.event_type=='moved' else event.src_path)
        if any(target.is_relative_to(root) for root in self.downloads.roots()):
            return  # Stable observations produce one severity, not per-write alerts.
        critical = not event.is_directory and event.event_type != 'deleted' and (policy_file(event.src_path) or (event.event_type == 'moved' and policy_file(event.dest_path)))
        self.emit(self.n.event('file.' + event.event_type, 'watchdog', severity='CRITICAL' if critical else 'LOW',
            file={'path':str(event.src_path), 'destination':str(event.dest_path) if event.event_type == 'moved' else None},
            raw_event={'directory':event.is_directory}))

    def integrity(self, reason, path=None):
        key = reason
        if key not in self.warned:
            fields = {'reason':reason}
            if path is not None:
                fields['path'] = str(path)[:4096]
            if self.emit(self.n.event('telemetry.integrity', 'file.inventory', severity='HIGH', raw_event=fields)) is not False:
                self.warned.add(key)

    def walk_inventory(self, roots):
        pending = list(roots)
        while pending:
            folder = pending.pop()
            try:
                with os.scandir(folder) as entries:
                    for entry in entries:
                        path = Path(entry.path)
                        if entry.is_dir(follow_symlinks=False):
                            if not path.is_junction():
                                pending.append(path)
                            yield None
                        elif entry.is_file(follow_symlinks=False):
                            yield path
                        else:
                            yield None
            except OSError as error:
                self.integrity('file_inventory_partial_visibility', error.filename)

    def poll(self):
        self.downloads.poll()
        download_roots=self.downloads.roots()
        if self.config is None or not self.config.file_inventory_enabled:
            return
        if self.inventory is None:
            if time.monotonic() < self.next_inventory:
                return
            roots = list(dict.fromkeys(self.paths + default_inventory_paths()))
            roots = [p for p in roots if p.is_dir() and not p.is_symlink() and not p.is_junction()]
            self.inventory = iter(self.walk_inventory(roots))
            self.inventory_entries = self.inventory_files = 0
            self.current = {}
            self.warned.clear()
        started = time.monotonic()
        changed = False
        for _ in range(self.config.file_inventory_step_entries):
            if time.monotonic()-started >= .05:
                break
            if self.inventory_entries >= self.config.file_inventory_max_entries or self.inventory_files >= self.config.file_inventory_max_files:
                self.integrity('file_inventory_capacity_reached')
                self.inventory = None
                self.next_inventory = time.monotonic()+self.config.file_inventory_interval
                break
            try:
                path = next(self.inventory)
            except StopIteration:
                self.inventory = None
                self.next_inventory = time.monotonic()+self.config.file_inventory_interval
                # Drop missing paths only after a complete sweep.
                self.known = self.current
                changed = True
                break
            self.inventory_entries += 1
            if path is None or not policy_file(path) or path.is_symlink():
                continue
            if any(path.is_relative_to(root) for root in download_roots):
                continue
            try:
                stat = path.stat()
            except OSError:
                self.integrity('file_inventory_partial_visibility', path)
                continue
            self.inventory_files += 1
            key = hashlib.sha256(str(path.resolve()).lower().encode('utf-8')).hexdigest()
            fingerprint = str(stat.st_mtime_ns)+':'+str(stat.st_size)
            self.current[key] = fingerprint
            if self.known.get(key) == fingerprint:
                continue
            accepted = self.emit(self.n.event('file.present', 'file.inventory', severity='CRITICAL', file={'path':str(path)[:4096]},
                raw_event={'directory':False,'extension':path.suffix.lower(),'size_bytes':stat.st_size,'modified_unix':stat.st_mtime,
                           'policy_signal':True,'contents_collected':False}))
            if accepted is False:
                # Leave unaccepted evidence unknown and restart the sweep on the next cycle.
                self.current.pop(key, None)
                self.inventory = None
                self.next_inventory = 0
                break
            self.known[key] = fingerprint
            while len(self.known) > self.config.file_inventory_max_files:
                self.known.pop(next(iter(self.known)))
            changed = True
        if changed and self.state:
            self.state.set_state('files:policy_inventory', json.dumps(self.known, separators=(',', ':')))

    def start(self):
        if self.scheduled:
            self.observer.start()

    def stop(self):
        if self.scheduled:
            self.observer.stop()
            self.observer.join(timeout=10)
