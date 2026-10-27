"""Read-only Windows Event Log and registry metadata. Never exports message bodies."""
import hashlib
import os
import json
import subprocess
import time
from pathlib import Path
import xml.etree.ElementTree as ET
from uuid import UUID, uuid5

NS = {'e':'http://schemas.microsoft.com/win/2004/08/events/event'}
CHANNELS = {
    'Security': '(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4697 or EventID=4698 or EventID=4663 or EventID=1102 or EventID=5152 or EventID=5156 or EventID=5157)',
    'System': '(EventID=7036 or EventID=7045 or EventID=104)',
    'Microsoft-Windows-PowerShell/Operational': '(EventID=4103 or EventID=4104)',
    'Microsoft-Windows-Sysmon/Operational': '(EventID=1 or EventID=3 or EventID=8 or EventID=11 or EventID=13 or EventID=22 or EventID=25)',
    'Microsoft-Windows-Windows Defender/Operational': '(EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119 or EventID=5001 or EventID=5007 or EventID=5010 or EventID=5012)',
}
# Read short-lived HTTP connections independently of a busy Security backlog.
# The original stream remains intact; deterministic IDs deduplicate overlap.
HTTP_QUERY = "*[System[EventID=5156 and ({predicate})] and EventData[Data[@Name='Protocol']='6' and Data[@Name='Direction']='%%14593' and (Data[@Name='DestPort']='80' or Data[@Name='DestPort']='8080')]]"
INBOUND_QUERY = "*[System[(EventID=5152 or EventID=5156 or EventID=5157) and ({predicate})] and EventData[Data[@Name='Direction']='%%14592']]"
DEFENDER_STATUS_SCRIPT = r'''$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $s=Get-MpComputerStatus; @{antivirus_enabled=[bool]$s.AntivirusEnabled; realtime_enabled=[bool]$s.RealTimeProtectionEnabled; signatures_age_days=[int]$s.AntivirusSignatureAge; running_mode=[string]$s.AMRunningMode} | ConvertTo-Json -Compress'''
DEFENDER_THREATS_SCRIPT = r'''$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $items=@(Get-MpThreat | Where-Object {$_.IsActive -eq $true} | Select-Object -First 101 | ForEach-Object { @{threat_id=[string]$_.ThreatID; threat_name=[string]$_.ThreatName} }); ConvertTo-Json -InputObject $items -Compress'''

def read_active_threats():
    powershell=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    result=subprocess.run([str(powershell),'-NoLogo','-NoProfile','-NonInteractive','-Command',DEFENDER_THREATS_SCRIPT],capture_output=True,timeout=15,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode:raise RuntimeError('defender_threats_unavailable')
    items=json.loads(result.stdout.decode('utf-8-sig'))
    if not isinstance(items,list) or len(items)>100:raise ValueError('defender_threats_invalid_or_exceeds_limit')
    for item in items:
        if not isinstance(item,dict) or any(not isinstance(item.get(k),str) or not item[k] for k in ('threat_id','threat_name')):
            raise ValueError('defender_threats_invalid')
    return [{'threat_id':i['threat_id'][:128],'threat_name':i['threat_name'][:512]} for i in items]

def dns_domain(value):
    import re
    try:value=value.rstrip('.').encode('idna').decode('ascii').lower()
    except UnicodeError:return None
    if len(value)>253 or '.' not in value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in value.split('.')):return None
    return value

def read_defender_status():
    # Fixed read-only query. No server input, command execution API or script content collection.
    powershell = Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    result = subprocess.run([str(powershell),'-NoLogo','-NoProfile','-NonInteractive','-Command',DEFENDER_STATUS_SCRIPT],
        capture_output=True,timeout=15,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode:
        raise RuntimeError('defender_status_unavailable')
    data=json.loads(result.stdout.decode('utf-8-sig'))
    if not isinstance(data,dict) or any(type(data.get(k)) is not bool for k in ('antivirus_enabled','realtime_enabled')):
        raise ValueError('invalid_defender_status')
    if type(data.get('signatures_age_days')) is not int or data['signatures_age_days']<0:
        raise ValueError('invalid_defender_signature_age')
    return {key:data[key] for key in ('antivirus_enabled','realtime_enabled','signatures_age_days')} | {'running_mode':str(data.get('running_mode',''))[:128]}

def defender_event(data, code):
    """Allowlisted metadata only. An action taken is NOT proof of remediation."""
    kinds = {1116:'antivirus.detected',1117:'antivirus.action',1118:'antivirus.remediation_failed',
             1119:'antivirus.remediation_failed',5001:'antivirus.protection_disabled',
             5010:'antivirus.protection_disabled',5012:'antivirus.protection_disabled',5007:'antivirus.configuration_changed'}
    fields = {'event_type':kinds[code], 'severity': 'CRITICAL' if code in (1116,1118,1119) else 'HIGH' if code in (5001,5010,5012) else 'MEDIUM'}
    metadata = {}
    for key, target in {'Threat Name':'threat_name','Threat ID':'threat_id','Severity Name':'vendor_severity',
                        'Category Name':'threat_category','Action Name':'action','Error Code':'error_code',
                        'Detection ID':'detection_id','Detection Time':'detection_time'}.items():
        if data.get(key):
            metadata[target] = data[key][:512]
    # No raw Defender payload, command lines, registry values, URLs or file contents.
    if data.get('Path'):
        metadata['affected_resource'] = data['Path'][:1024]
    if data.get('Process Name'):
        path = data['Process Name'][:4096]
        fields['process'] = {'path':path, 'name':path.replace('\\','/').rsplit('/',1)[-1][:255]}
    fields['user'] = (data.get('Detection User') or data.get('User') or '')[:255] or None
    return fields, metadata

def parse_event(xml, channel, n):
    root = ET.fromstring(xml)
    system = root.find('e:System', NS)
    event_code = int(system.findtext('e:EventID', namespaces=NS))
    record = int(system.findtext('e:EventRecordID', namespaces=NS))
    timestamp = system.find('e:TimeCreated', NS).attrib['SystemTime']
    data = {item.attrib.get('Name',''): item.text or '' for item in root.findall('e:EventData/e:Data', NS)}
    kind = {4624:'auth.success', 4625:'auth.failure', 4688:'process.start', 4697:'persistence.change',
            4698:'persistence.change', 7045:'persistence.change', 7036:'service.change',
            1102:'telemetry.integrity', 104:'telemetry.integrity', 4103:'powershell.observed',
            4104:'powershell.observed',4663:'file.access'}.get(event_code, 'windows.event')
    if 'Sysmon' in channel:
        kind = {1:'process.start',3:'network.connection',8:'process.remote_thread',11:'file.created',13:'persistence.change',22:'network.dns',25:'process.tampering'}[event_code]
    # Inspect known signals in memory; never persist script block/message contents.
    script = data.get('ScriptBlockText','').lower() + data.get('Payload','').lower()
    signals = [s for s in ('frombase64string', 'downloadstring', 'encodedcommand', 'invoke-expression', 'amsi') if s in script]
    metadata = {'event_code':event_code, 'record_id':record, 'channel':channel,
                'powershell_signals':','.join(signals)}
    if data.get('ProcessGuid'):
        metadata['process_guid'] = data['ProcessGuid']
    fields = {'raw_event':metadata, 'user':(data.get('TargetUserName') or data.get('User') or None), 'timestamp':timestamp}
    if 'Sysmon' in channel and event_code == 22:
        domain=dns_domain(data.get('QueryName',''))
        if domain:metadata['domain']=domain
        else:metadata['domain_parse_error']=True
    if channel=='Security' and event_code in (5152,5156,5157):
        kind='network.connection' if event_code==5156 else 'network.blocked'
        direction={'%%14592':'inbound','%%14593':'outbound'}.get(data.get('Direction'),'unknown')
        metadata.update(direction=direction,direction_evidence='windows_filtering_platform',action='allowed' if event_code==5156 else 'blocked')
        protocol={'6':'TCP','17':'UDP'}.get(data.get('Protocol'))
        if direction!='unknown' and protocol:
            local,remote=('Dest','Source') if direction=='inbound' else ('Source','Dest')
            fields['network']={'local_ip':data.get(local+'Address'),'local_port':int(data.get(local+'Port','0')),
                'remote_ip':data.get(remote+'Address'),'remote_port':int(data.get(remote+'Port','0')),'protocol':protocol}
        if data.get('Application'):
            path=data['Application'][:4096]
            fields['process']={'path':path,'name':path.replace('\\','/').rsplit('/',1)[-1][:255]}
    if channel == 'Microsoft-Windows-Windows Defender/Operational':
        defender_fields, extra = defender_event(data, event_code)
        kind = defender_fields.pop('event_type')
        fields.update(defender_fields)
        metadata.update(extra)
    if 'Sysmon' in channel and event_code == 8:
        for key, target in {'SourceProcessGUID':'process_guid','SourceProcessGuid':'process_guid',
                            'TargetImage':'target_image','TargetProcessId':'target_pid'}.items():
            if data.get(key):
                metadata[target] = data[key][:512]
        if data.get('SourceImage'):
            path = data['SourceImage']
            fields['process'] = {'path':path,'name':path.replace('\\','/').rsplit('/',1)[-1],
                                 'pid':int(data['SourceProcessId']) if data.get('SourceProcessId') else None}
    if event_code == 4663 and channel == 'Security':
        fields['user'] = data.get('SubjectUserName') or None
        if data.get('ObjectName'):
            fields['file'] = {'path':data['ObjectName'][:4096]}
        metadata['access_mask'] = data.get('AccessMask','')[:128]
        metadata['object_type'] = data.get('ObjectType','')[:128]
    if kind in ('process.remote_thread','process.tampering'):
        fields['severity'] = 'HIGH'
    image = data.get('Image') or data.get('NewProcessName') or data.get('ProcessName')
    if image:
        raw_pid = data.get('ProcessId') or data.get('NewProcessId')
        pid = int(raw_pid, 16 if raw_pid.startswith('0x') else 10) if raw_pid else None
        fields['process'] = {'path':image, 'name':image.replace('\\','/').rsplit('/',1)[-1], 'pid':pid,
                             'command_line':data.get('CommandLine')}
    if data.get('DestinationIp'):
        fields['network'] = {'remote_ip':data['DestinationIp'], 'remote_port':int(data['DestinationPort']),
                             'local_ip':data.get('SourceIp'), 'local_port':int(data.get('SourcePort',0)),
                             'protocol':data.get('Protocol','tcp').upper()}
        if 'Sysmon' in channel and event_code==3:
            direction={'true':'outbound','false':'inbound'}.get(data.get('Initiated','').lower(),'unknown')
            metadata.update(direction=direction,direction_evidence='sysmon_initiated')
            if direction=='inbound':
                net=fields['network']
                net['local_ip'],net['remote_ip']=net['remote_ip'],net['local_ip']
                net['local_port'],net['remote_port']=net['remote_port'],net['local_port']
    elif data.get('IpAddress') not in (None,'','-'):
        from ipaddress import ip_address
        try:
            ip_address(data['IpAddress'])
            fields['network'] = {'remote_ip':data['IpAddress']}
        except ValueError:
            metadata['address_parse_error'] = True
    if data.get('TargetFilename'):
        fields['file'] = {'path':data['TargetFilename']}
        metadata['directory']=False
    if kind=='network.connection' and metadata.get('direction')=='inbound' and fields.get('network',{}).get('local_port')==64668:
        fields['severity']='MEDIUM'
    fields['event_id'] = uuid5(UUID(str(n.agent_id)), channel + ':' + str(record) + ':' + timestamp)
    return record, n.event(kind, 'windows.eventlog', **fields)

class WindowsCollector:
    def __init__(self, n, emit, state, lookback=300):
        self.n, self.emit, self.state, self.lookback = n, emit, state, lookback
        self.warned = set()
        self.next_defender_status = 0
        self.next_defender_threats = 0

    def poll(self):
        if os.name != 'nt':
            return
        import win32evtlog as log
        import pywintypes
        streams = [('Security',None,'log:SecurityHTTP'), ('Security','inbound','log:SecurityInbound')] + [(channel,selected,'log:'+channel) for channel,selected in CHANNELS.items()]
        for channel, selected, cursor_key in streams:
            cursor = self.state.get_state(cursor_key)
            lookback = max(self.lookback,86400) if channel == 'Microsoft-Windows-Windows Defender/Operational' else self.lookback
            predicate = f'EventRecordID > {int(cursor)}' if cursor else f'TimeCreated[timediff(@SystemTime) <= {lookback*1000}]'
            try:
                # Detect reset/clear rather than waiting for record IDs to catch up.
                newest = log.EvtQuery(channel, log.EvtQueryChannelPath | log.EvtQueryReverseDirection, '*')
                tail = log.EvtNext(newest, 1, 0, 0)
                if cursor and tail:
                    last = ET.fromstring(log.EvtRender(tail[0], log.EvtRenderEventXml)).findtext('e:System/e:EventRecordID', namespaces=NS)
                    if int(last) < int(cursor):
                        self.emit(self.n.event('telemetry.integrity','windows.eventlog', severity='HIGH', raw_event={'reason':'log_reset','channel':channel}))
                        predicate = 'EventRecordID >= 0'
                query = (HTTP_QUERY.format(predicate=predicate) if selected is None else
                         INBOUND_QUERY.format(predicate=predicate) if selected == 'inbound' else
                         f'*[System[{selected} and ({predicate})]]')
                handle = log.EvtQuery(channel, log.EvtQueryChannelPath | log.EvtQueryForwardDirection, query)
                # Drain priority streams in bounded batches. Stop the cursor at
                # the first queue rejection; retry that record on the next poll.
                for _ in range(4 if selected in (None, 'inbound') else 1):
                    batch = log.EvtNext(handle, 128, 0, 0)
                    accepted = True
                    for native in batch:
                        xml = log.EvtRender(native, log.EvtRenderEventXml)
                        record, event = parse_event(xml, channel, self.n)
                        if not self.emit(event):
                            accepted = False
                            break
                        self.state.set_state(cursor_key, str(record))
                    if not accepted or len(batch) < 128:
                        break
                self.warned.discard(cursor_key)
            except pywintypes.error as exc:
                if exc.winerror == 259:  # no more items
                    continue
                if cursor_key not in self.warned:
                    self.emit(self.n.event('telemetry.integrity','windows.eventlog', severity='MEDIUM',
                        raw_event={'reason':'channel_unavailable', 'channel':channel, 'error_code':exc.winerror}))
                    self.warned.add(cursor_key)
        self.registry()
        self.defender_status()
        self.defender_threats()

    def defender_threats(self):
        if time.monotonic()<self.next_defender_threats:return
        self.next_defender_threats=time.monotonic()+300
        try:items=read_active_threats()
        except (OSError,RuntimeError,ValueError,UnicodeError,subprocess.TimeoutExpired):
            if 'defender_threats' not in self.warned and self.emit(self.n.event('telemetry.integrity','defender.threats',severity='HIGH',raw_event={'reason':'active_threat_query_unavailable'})):
                self.warned.add('defender_threats')
            return
        self.warned.discard('defender_threats')
        previous=json.loads(self.state.get_state('defender:active_threats') or '{}')
        accepted={}
        for item in items:
            key=item['threat_id']
            if previous.get(key)==item['threat_name'] or self.emit(self.n.event('antivirus.detected','defender.threats',severity='CRITICAL',raw_event={**item,'active_at_observation':True})):
                accepted[key]=item['threat_name']
        self.state.set_state('defender:active_threats',json.dumps(accepted))

    def defender_status(self):
        if time.monotonic() < self.next_defender_status:
            return
        self.next_defender_status = time.monotonic()+300
        try:
            status=read_defender_status()
        except (OSError,RuntimeError,ValueError,UnicodeError,subprocess.TimeoutExpired):
            if 'defender_status' not in self.warned:
                if self.emit(self.n.event('telemetry.integrity','defender.status',severity='HIGH',raw_event={'reason':'defender_status_unavailable'})):
                    self.warned.add('defender_status')
            return
        self.warned.discard('defender_status')
        health=json.dumps([status['antivirus_enabled'],status['realtime_enabled'],status['signatures_age_days']>=7,status['running_mode']])
        status['health_changed']=self.state.get_state('defender:health') != health
        level='HIGH' if not status['antivirus_enabled'] or not status['realtime_enabled'] else 'LOW'
        if self.emit(self.n.event('antivirus.status','defender.status',severity=level,raw_event=status)):
            self.state.set_state('defender:health',health)

    def registry(self):
        import winreg
        keys = (r'Software\Microsoft\Windows\CurrentVersion\Run', r'Software\Microsoft\Windows\CurrentVersion\RunOnce')
        for hive_name, hive in (('HKLM', winreg.HKEY_LOCAL_MACHINE), ('HKCU', winreg.HKEY_CURRENT_USER)):
            for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                for key in keys:
                    label = f'{hive_name}:{view}:{key}'
                    values = {}
                    try:
                        with winreg.OpenKey(hive, key, 0, winreg.KEY_READ | view) as handle:
                            for index in range(winreg.QueryInfoKey(handle)[1]):
                                name, value, kind = winreg.EnumValue(handle, index)
                                values[name] = hashlib.sha256(str(value).encode()).hexdigest()
                    except FileNotFoundError:
                        values = {}
                    except PermissionError:
                        if label not in self.warned:
                            self.emit(self.n.event('telemetry.integrity', 'windows.registry', raw_event={'reason':'registry_denied', 'key':label}))
                            self.warned.add(label)
                        continue
                    import json
                    snapshot = json.dumps(values, sort_keys=True)
                    previous = self.state.get_state(label)
                    if previous is not None and previous != snapshot:
                        if not self.emit(self.n.event('persistence.change', 'windows.registry', severity='MEDIUM', raw_event={'key':label, 'value_count':len(values)})):
                            continue
                    self.state.set_state(label, snapshot)
