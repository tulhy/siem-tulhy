"""Polling collectors: missing permissions are explicit integrity events."""
import os
import socket
from ipaddress import ip_address
import psutil
from agent.utils.hashing import executable_hash

SENSITIVE_PORTS = {3389, 4444, 22, 23, 137, 138, 139, 445, 20, 21, 3306, 1433, 5432, 31337, 6660, 6669}

def socket_exposure(address):
    ip = ip_address(address.split('%')[0])
    return 'loopback' if ip.is_loopback else 'all_interfaces' if ip.is_unspecified else 'interface'

def matches_listener(connection, listeners):
    """Direction inferred only from an observed TCP listener owned by the same PID."""
    if connection.pid is None:return False
    address = connection.laddr.ip.split('%')[0]
    return any(pid == connection.pid and port == connection.laddr.port and
               (host.split('%')[0] == address or ip_address(host.split('%')[0]).is_unspecified)
               for pid, host, port in listeners)

class SystemCollector:
    def __init__(self, normalizer, config, emit):
        self.n, self.c, self.emit = normalizer, config, emit
        self.processes, self.connections, self.services = {}, set(), {}
        self.warned = set()

    def warning(self, component, code):
        key = (component, code)
        if key not in self.warned:
            self.emit(self.n.event('telemetry.integrity', component, severity='MEDIUM',
                                   raw_event={'reason':code}))
            self.warned.add(key)

    def poll(self):
        current = {}
        denied = 0
        attrs = ['pid', 'ppid', 'name', 'exe', 'username', 'create_time']
        if self.c.collect_command_lines:
            attrs.append('cmdline')
        for item in psutil.process_iter(attrs, ad_value=None):
            try:
                p = item.info
                key = (p['pid'], p['create_time'])
                process = {'pid':p['pid'], 'ppid':p['ppid'], 'name':p['name'], 'path':p['exe'],
                           'created_at':p['create_time']}
                current[key] = (process, p['username'])
                if key not in self.processes:
                    process['sha256'] = executable_hash(p['exe'], self.c.hash_max_bytes)
                    process['command_line'] = ' '.join(p.get('cmdline') or []) or None
                    self.emit(self.n.event('process.start', 'psutil', process=process, user=p['username'],
                                           raw_event={'observed_by_polling':True}))
                if not p['exe']:
                    denied += 1
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except psutil.AccessDenied:
                denied += 1
        for key in self.processes.keys() - current.keys():
            process, user = self.processes[key]
            self.emit(self.n.event('process.stop', 'psutil', process=process, user=user))
        self.processes = current
        if denied:
            self.warning('process', 'partial_process_visibility')
        self.network()
        self.resources()
        if os.name == 'nt':
            self.service_changes()

    def network(self):
        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, OSError):
            self.warning('network', 'access_denied')
            return
        seen = set()
        by_pid = {key[0]:value for key, value in self.processes.items()}
        listeners = [(c.pid, c.laddr.ip, c.laddr.port) for c in connections
                     if c.type == socket.SOCK_STREAM and c.status == psutil.CONN_LISTEN and c.laddr]
        for c in connections:
            if not c.laddr:
                continue
            proc, user = by_pid.get(c.pid, ({'pid':c.pid}, None))
            is_listener = c.type == socket.SOCK_STREAM and c.status == psutil.CONN_LISTEN
            is_bound = c.type == socket.SOCK_DGRAM and not c.raddr
            if not c.raddr and not (is_listener or is_bound):
                continue
            kind = 'network.listen' if is_listener else 'network.bind' if is_bound else 'network.connection'
            key = (kind, c.pid, proc.get('created_at'), c.laddr, c.raddr, c.type, c.status)
            if key in self.connections:
                seen.add(key)
                continue
            direction = 'unknown'
            evidence = 'direction_unavailable'
            if is_listener or is_bound:
                direction, evidence = 'inbound', 'local_listener' if is_listener else 'local_udp_binding'
            elif c.type == socket.SOCK_STREAM and matches_listener(c, listeners):
                direction, evidence = 'inbound', 'matching_local_listener'
            elif c.type == socket.SOCK_STREAM and c.status == psutil.CONN_SYN_SENT:
                direction, evidence = 'outbound', 'tcp_syn_sent'
            severity = 'HIGH' if (is_listener or is_bound) and c.laddr.port in SENSITIVE_PORTS else 'MEDIUM' if direction == 'inbound' and c.laddr.port == 64668 and c.raddr else 'LOW'
            accepted = self.emit(self.n.event(kind, 'psutil', severity=severity, process=proc, user=user,
                network={'local_ip':c.laddr.ip, 'local_port':c.laddr.port,
                         'remote_ip':c.raddr.ip if c.raddr else None, 'remote_port':c.raddr.port if c.raddr else None,
                         'protocol':'TCP' if c.type == socket.SOCK_STREAM else 'UDP'},
                raw_event={'direction':direction, 'direction_evidence':evidence, 'state':c.status if not is_bound else 'BOUND',
                           'exposure':socket_exposure(c.laddr.ip)}))
            if accepted is not False:
                seen.add(key)
        self.connections = seen

    def resources(self):
        values = {'cpu':psutil.cpu_percent(), 'memory':psutil.virtual_memory().percent,
                  'disk':psutil.disk_usage(os.path.abspath(os.sep)).percent}
        for name, value in values.items():
            if value >= getattr(self.c, name + '_threshold'):
                self.emit(self.n.event('resource.anomaly', 'psutil', severity='MEDIUM',
                                      raw_event={'resource':name, 'percent':value}))

    def service_changes(self):
        current = {}
        try:
            for service in psutil.win_service_iter():
                try:
                    data = service.as_dict()
                    current[data['name']] = data['status']
                    if self.services.get(data['name']) != data['status']:
                        self.emit(self.n.event('service.change', 'windows.services',
                            raw_event={'service':data['name'], 'status':data['status']}))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    self.warning('services', 'partial_visibility')
        except OSError:
            self.warning('services', 'unavailable')
        self.services = current
