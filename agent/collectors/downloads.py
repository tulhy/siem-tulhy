"""Persistent metadata observations of new/changed files in Downloads."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from uuid import UUID, uuid5
import psutil

CRITICAL={'.py','.vbs','.htm','.bat'}
TEMP={'.crdownload','.part','.partial','.tmp','.download'}
STATE='downloads:observations:v3'
INITIAL_REVIEW=CRITICAL | {'.pdf', '.dll'}
INCOMPLETE={'analysis_timeout','memory_limit','analysis_failed','analysis_start_failed','read_failed',
            'pdf_decoder_missing','encrypted_pdf','size_limit','page_limit','invalid_pdf',
            'pdf_no_extractable_text','pdf_annotation_limit','pdf_action_limit','pdf_text_limit'}

def analyze(path):
    try:
        child=subprocess.Popen([sys.executable,'-I',str(Path(__file__).with_name('link_worker.py')),str(path)],
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    except OSError:
        return {'link_found':False,'analysis_status':'analysis_start_failed'}
    status=None;deadline=time.monotonic()+5
    try:
        while child.poll() is None:
            if time.monotonic()>deadline:status='analysis_timeout';break
            try:
                if psutil.Process(child.pid).memory_info().rss>256*1024*1024:status='memory_limit';break
            except psutil.NoSuchProcess:break
            time.sleep(.02)
        if status:
            child.kill();child.communicate()
            return {'link_found':False,'analysis_status':status}
        output,_=child.communicate(timeout=2)
        if child.returncode or len(output)>2048:return {'link_found':False,'analysis_status':'analysis_failed'}
        result=json.loads(output)
        if set(result)!={'link_found','analysis_status'} or type(result['link_found']) is not bool:
            return {'link_found':False,'analysis_status':'analysis_failed'}
        return result
    except (OSError,ValueError,subprocess.TimeoutExpired):
        return {'link_found':False,'analysis_status':'analysis_failed'}
    finally:
        if child.poll() is None:child.kill()
        child.communicate()

class DownloadCollector:
    def __init__(self,n,emit,state,roots):
        self.n,self.emit,self.state,self.roots=n,emit,state,roots
        saved=json.loads(state.get_state(STATE) or '{}') if state else {}
        self.known=saved.get('known',{});self.ready=saved.get('ready',False)
        self.iterator=None;self.seen=set();self.warned=set()

    def integrity(self,reason):
        if reason not in self.warned and self.emit(self.n.event('telemetry.integrity','downloads',severity='HIGH',raw_event={'reason':reason})) is not False:
            self.warned.add(reason)

    def is_new_observation(self,path):
        key=hashlib.sha256(str(Path(path).absolute()).casefold().encode()).hexdigest()
        return key in self.known and not self.known[key].get('initial',False)

    def walk(self):
        for root in self.roots():
            pending=[Path(root)]
            while pending:
                folder=pending.pop()
                if folder.is_symlink() or folder.is_junction():continue
                try:
                    with os.scandir(folder) as entries:
                        for entry in entries:
                            path=Path(entry.path)
                            if entry.is_dir(follow_symlinks=False):
                                if not path.is_junction() and len(pending)<10000:pending.append(path)
                                elif len(pending)>=10000:self.integrity('downloads_directory_limit')
                                yield None
                            elif entry.is_file(follow_symlinks=False):yield path
                            else:yield None
                except OSError:self.integrity('downloads_partial_visibility')

    def poll(self):
        if self.iterator is None:
            if not self.roots():return
            self.iterator=iter(self.walk());self.seen=set()
        analyzed=0;start=time.monotonic()
        for _ in range(200):
            if time.monotonic()-start>.05 or analyzed>=1:break
            try:path=next(self.iterator)
            except StopIteration:
                self.known={k:v for k,v in self.known.items() if k in self.seen}
                self.ready=True;self.iterator=None;break
            if path is None or path.suffix.lower() in TEMP:continue
            try:stat=path.stat()
            except OSError:self.integrity('downloads_partial_visibility');continue
            key=hashlib.sha256(str(path.absolute()).casefold().encode()).hexdigest()
            if key not in self.known and len(self.known)>=10000:
                self.integrity('downloads_capacity_reached');continue
            self.seen.add(key)
            fingerprint=f'{stat.st_size}:{stat.st_mtime_ns}'
            old=self.known.get(key)
            if old is None or old['fingerprint']!=fingerprint:
                self.known[key]={'fingerprint':fingerprint,'since':time.time(),'sent':not self.ready and path.suffix.lower() not in INITIAL_REVIEW,'initial':not self.ready}
                continue
            if old['sent'] or time.time()-old['since']<10:continue
            extension=path.suffix.lower()
            result=({'link_found':False,'analysis_status':'dll_metadata_only'} if extension=='.dll' else analyze(path))
            analyzed+=1
            try:after=path.stat()
            except OSError:continue
            if fingerprint!=f'{after.st_size}:{after.st_mtime_ns}':continue
            critical=extension in CRITICAL or result['link_found']
            incomplete=extension=='.pdf' and result['analysis_status'] in INCOMPLETE
            level='CRITICAL' if critical else 'HIGH' if extension=='.dll' or incomplete else 'MEDIUM'
            event=self.n.event('file.download_observed','downloads',severity=level,
                event_id=uuid5(UUID(str(self.n.agent_id)),STATE+key+fingerprint),file={'path':str(path)},
                raw_event={'directory':False,'extension':extension,'size_bytes':stat.st_size,'link_found':result['link_found'],
                    'analysis_status':result['analysis_status'],'analysis_incomplete':incomplete,
                    'initial_observation':old.get('initial',False),'download_confirmed':False,'contents_collected':False})
            if self.emit(event) is not False:old['sent']=True
        if self.state:self.state.set_state(STATE,json.dumps({'ready':self.ready,'known':self.known},separators=(',',':')))
