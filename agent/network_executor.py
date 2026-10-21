"""Opt-in, single-gateway Linux WireGuard transactions. No firewall heartbeat confirmation.

Local protected spool is a courier, never an authority. Execution and explicit confirmation are
manager-signed; independent verification uses a separate trust ring and signature domain.
"""
import base64
import contextlib
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import signal
import socket
import struct
import stat
import subprocess
import sys
import tempfile
import time

EXECUTION = 'heliopause-network-execution-v2'
TERMINAL_DOMAIN = 'heliopause-network-terminal-mtls-v1'
CANCEL = 'heliopause-network-cancel-v1'
CANCELLATION_RESULT_DOMAIN = 'heliopause-network-cancellation-mtls-v1'
CAPACITY_RESULT_DOMAIN = 'heliopause-network-capacity-stop-mtls-v1'
ADMISSION_RECORD_LIMIT = 1023
CAPACITY_IDENTITY_LIMIT = 512*1024
CONFIRM = 'heliopause-network-confirm-v1'
VERIFY = 'heliopause-network-verification-v1'
DRIVER = 'linux-wireguard-v1'
PERSISTENT_DRIVER = 'networkmanager-wireguard-1.56-v1'
TERMINAL = {'confirmed', 'rolled-back', 'cancelled-before-accept'}
CHECKS = ['interface', 'address', 'route', 'handshake', 'fib', 'forward', 'reverse', 'management', 'protected']


def capacity_rows(data, identity):
    """The emergency slot is part of replay identity, never a removable ledger entry."""
    if not isinstance(identity,dict) or set(identity) not in ({'journalId'},{'journalId','capacityCancellation'}) or identity.get('journalId')!=data.get('journalId'):
        raise ValueError('invalid transaction replay identity')
    rows=dict(data['transactions'])
    if 'capacityCancellation' not in identity:return rows
    if len(canonical(identity).encode())>CAPACITY_IDENTITY_LIMIT:raise ValueError('capacity identity too large')
    row=identity['capacityCancellation']
    exact(row,'authorization cancellation state history authorizationHash terminalResult')
    a=row['authorization'];c=row['cancellation'];r=row['terminalResult']
    if not isinstance(a,dict) or not isinstance(c,dict) or not isinstance(r,dict):raise ValueError('invalid capacity reservation')
    transaction=a.get('transactionId')
    if not re.fullmatch(r'[a-f0-9]{32}',str(transaction)) or transaction in rows or len(rows)>=1024 or any(v.get('state') not in {'rolled-back','cancelled-before-accept'} or any(k in v for k in ('bootRestore','before','paths')) for v in rows.values()):raise ValueError('capacity reservation requires closed primary ledger')
    exact(r,'schemaVersion domain transactionId fenceId target journalId authorizationHash artifactHash registryRevision state sequence stateHash proof')
    if a.get('schemaVersion')!=2 or a.get('journalId')!=data['journalId'] or row['state']!='cancelled-before-accept' or row['authorizationHash']!=digest(a) or r['schemaVersion']!=3 or r['domain']!=CAPACITY_RESULT_DOMAIN or r['sequence']!=data['terminalSequence']+1 or not integer(r['sequence'],1,1024) or r['state']!=row['state'] or r['authorizationHash']!=digest(a) or r['stateHash']!=digest({k:v for k,v in r.items() if k!='stateHash'}) or r['proof']!={'cancellationHash':digest(c),'acceptancePrevented':True,'maintenanceRequired':True}:
        raise ValueError('invalid capacity result commitment')
    for k in ('transactionId','target','journalId','artifactHash','registryRevision'):
        if r[k]!=a[k]:raise ValueError('capacity result binding mismatch')
    if r['fenceId']!=transaction:raise ValueError('capacity fence mismatch')
    rows[transaction]=row
    return rows


def current_boot_id():
    with open('/proc/sys/kernel/random/boot_id', 'r', encoding='ascii') as stream:
        value = stream.read(64).strip()
    if not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value):
        raise ValueError('boot identity unavailable')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def exact(value, required):
    if not isinstance(value, dict) or set(value) != set(required.split()):
        raise ValueError('unsupported or missing fields')


def safe_diagnostic(error):
    # Only our non-interpolated ValueError/RuntimeError messages; never command stderr or decoding
    # exceptions (which may contain rejected bytes from a malformed secret file).
    return str(error)[:160] if type(error) in {ValueError, RuntimeError} else type(error).__name__


def owner_group(owner):
    # IFLA_GROUP is installed by rtnl_create_link before registration (unlike IFLA_IFALIAS).
    return 0x80000000 | (int.from_bytes(hashlib.sha256(owner.encode()).digest()[:4],'big') & 0x7fffffff)


def kernel_multicast_route(row, dev):
    # Linux installs this local IPv6 multicast route even on an IPv4-only WG link.
    expected={'type':'multicast','dst':'ff00::/8','table':'local','protocol':'kernel','metric':256,'pref':'medium'}
    return row.get('dev',dev)==dev and row.get('flags',[])==[] and {k:v for k,v in row.items() if k not in {'dev','flags'}}==expected


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def name(value):
    return isinstance(value, str) and re.fullmatch(r'[a-zA-Z0-9_.-]{1,64}', value) is not None


def read_file(path, maximum=8*1024*1024, secret=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & (0o077 if secret else 0o022):
            raise ValueError('file must be owned protected regular file')
        data = stream.read(maximum+1)
        if len(data) > maximum:
            raise ValueError('file exceeds limit')
        return data


def decode_json(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError('duplicate key')
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def read_json(path):
    return decode_json(read_file(path))


def atomic(path, value):
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix='.network-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        d = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def journal_transition_pending(directory):
    if os.path.lexists(os.path.join(directory,'retired-journal.json')):
        return True
    try:marker=read_json(directory+'.transition.json')
    except FileNotFoundError:return False
    if not isinstance(marker,dict) or marker.get('phase') not in {'prepared','old-retired','old-preserved','successor-prepared','successor-published','config-bound','complete'}:
        raise ValueError('invalid offline journal transition marker')
    return marker['phase']!='complete'


def assert_active_journal(directory):
    if journal_transition_pending(directory):raise ValueError('journal retired or offline transition pending')


def crypto_helpers(directory):
    # Reuse the Agent's bounded trust loading and real OpenSSL Ed25519 verifier.
    spec = importlib.util.spec_from_file_location('network_signature_provider', os.path.join(os.path.dirname(__file__), 'heliopause-pull.py'))
    provider = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provider)
    provider.STATE_FILE = os.path.join(directory, 'signature-state')
    return provider


def network_trust_keys(keydir, provider):
    rows = provider._load_artifact_key_dir(keydir, 'manager')
    keys = {row[0]: row[2] for row in rows}
    if not keys or len(keys) != len(rows):
        raise ValueError('empty or duplicate network signing key identity')
    return keys


def verify(envelope, domain, keydir, provider):
    exact(envelope, 'version algorithm keyId payload signature')
    if envelope['version'] != 'heliopause-ed25519-v1' or envelope['algorithm'] != 'Ed25519':
        raise ValueError('unsupported envelope')
    keys = network_trust_keys(keydir, provider)
    key = keys.get(envelope['keyId'])
    payload = provider._b64url(envelope['payload'], 'payload', 128*1024)
    signature = provider._b64url(envelope['signature'], 'signature', 64)
    if not key or len(signature) != 64 or not provider._verify_ed25519(key, provider._frame(domain.encode()) + provider._frame(envelope['keyId'].encode()) + provider._frame(payload), signature):
        raise ValueError('invalid signature')
    value = provider._strict_json(payload)
    if payload != canonical(value).encode():
        raise ValueError('noncanonical message')
    return value


def independent_trust(config, provider):
    manager=set(network_trust_keys(config['managerKeys'], provider))
    verifier=set(network_trust_keys(config['verifierKeys'], provider))
    if not manager or not verifier or manager & verifier:
        raise ValueError('independent verifier trust must use distinct signing keys')


def host(value):
    if not isinstance(value, str):
        raise ValueError('invalid host route')
    address = ipaddress.ip_network(value, strict=True)
    if address.version != 4 or address.prefixlen != 32 or not address.network_address.is_global and (address.network_address.is_multicast or address.network_address.is_unspecified or address.network_address.is_loopback or address.network_address.is_link_local):
        raise ValueError('only IPv4 unicast host routes supported')
    return address


def key(value):
    try:
        return isinstance(value, str) and len(base64.b64decode(value, validate=True)) == 32 and base64.b64encode(base64.b64decode(value)).decode() == value
    except (ValueError, TypeError):
        return False


def validate_operation(op):
    persistent = isinstance(op, dict) and op.get('driver') == PERSISTENT_DRIVER
    exact(op, 'driver interfaceId interfaceName address mtu listenPort secretRef publicKey peers routes'+(' profileUuid bootPolicy' if persistent else ''))
    if persistent:
        from network_nm_profile import profile_uuid, BOOT_POLICY
        if op['bootPolicy'] != BOOT_POLICY or not isinstance(op['profileUuid'], str) or op['profileUuid'] != profile_uuid(op['profileUuid'].replace('-', '')) or op['interfaceName'] != 'hp'+op['profileUuid'].replace('-', '')[:12]:
            raise ValueError('persistent profile identity/policy mismatch')
    if op['driver'] not in {DRIVER, PERSISTENT_DRIVER} or not name(op['interfaceId']) or not re.fullmatch(r'hp[a-z0-9]{1,13}', str(op['interfaceName'])) or not name(op['secretRef']) or not key(op['publicKey']) or not integer(op['mtu'], 1280, 1500) or not integer(op['listenPort'], 1024, 65535):
        raise ValueError('unsupported WireGuard operation')
    address = host(op['address'])
    if not isinstance(op['peers'], list) or not 1 <= len(op['peers']) <= 8 or not isinstance(op['routes'], list) or not 1 <= len(op['routes']) <= 16:
        raise ValueError('invalid bounded peer/route list')
    allowed, pubs = [], set()
    for peer in op['peers']:
        exact(peer, 'publicKey endpoint allowedIps')
        if not key(peer['publicKey']) or peer['publicKey'] in pubs or peer['publicKey'] == op['publicKey']:
            raise ValueError('duplicate/invalid peer key')
        pubs.add(peer['publicKey'])
        if not isinstance(peer['endpoint'], str) or not re.fullmatch(r'[0-9.]+:[0-9]{1,5}', peer['endpoint']):
            raise ValueError('IPv4 literal endpoint required')
        ip, port = peer['endpoint'].split(':')
        host(ip+'/32')
        if not 1 <= int(port) <= 65535 or not isinstance(peer['allowedIps'], list) or not peer['allowedIps']:
            raise ValueError('invalid peer endpoint/AllowedIPs')
        for prefix in peer['allowedIps']:
            if host(prefix) == address or prefix in allowed:
                raise ValueError('overlapping peer ownership')
            allowed.append(prefix)
    for route in op['routes']:
        host(route)
    if sorted(allowed) != sorted(op['routes']) or len(set(op['routes'])) != len(op['routes']):
        raise ValueError('explicit routes must exactly match peer AllowedIPs')
    if any(peer['endpoint'].split(':')[0]+'/32' in allowed for peer in op['peers']):
        raise ValueError('endpoint recursion')


class LinuxWireGuard:
    """No shell, wg-quick hooks, FRR, NetworkManager profiles, or existing-interface adoption."""
    def __init__(self, secrets):
        self.secrets = secrets
        self.deadline = None
        self.command_deadline = None

    def command_timeout(self):
        limits = [value-time.monotonic() for value in [self.deadline, self.command_deadline] if value is not None]
        remaining = min([5] + limits)
        if remaining <= 0:
            raise RuntimeError('network operation budget elapsed')
        return remaining

    def run(self, args, data=None, pass_fds=()):
        if self.deadline is not None and time.monotonic()>=self.deadline:
            raise RuntimeError('apply deadline elapsed')
        try:
            p = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=self.command_timeout(), check=False, pass_fds=pass_fds)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError('network command unavailable or timed out: '+os.path.basename(args[0])+' '+os.path.basename(args[1])) from None
        if p.returncode:
            # Never include input, stdout, stderr, secret paths or full argv in error records.
            raise RuntimeError('network command failed: '+args[0]+' '+args[1])
        if len(p.stdout) > 1024*1024:
            raise RuntimeError('network command output exceeds limit')
        return p.stdout.decode().strip()

    def ip(self, *args):
        return json.loads(self.run(['ip', '-j'] + (['-N'] if 'link' in args else []) + list(args)))

    def snapshot(self):
        links = self.ip('-d', 'link', 'show')
        addresses = self.ip('address', 'show')
        routes = self.ip('-4', 'route', 'show', 'table', 'all')
        rules = self.ip('-4', 'rule', 'show')
        # Exclude counters, lifetimes and link operational status; preserve configured identity.
        return {'links': sorted([{'name': x['ifname'], 'index': x['ifindex'], 'mtu': x['mtu'], 'master': x.get('master'), 'alias': x.get('ifalias',x.get('alias')), 'kind': x.get('linkinfo', {}).get('info_kind'), 'group':x.get('group')} for x in links], key=lambda x:x['name']),
                'addresses': sorted([{'name': x['ifname'], 'addresses': sorted([a['local']+'/'+str(a['prefixlen']) for a in x.get('addr_info', [])])} for x in addresses], key=lambda x:x['name']),
                'routes': sorted([{k:v for k,v in r.items() if k not in {'expires', 'cache', 'flags'}} for r in routes], key=canonical), 'rules': rules,
                'routes6':sorted([{k:v for k,v in r.items() if k not in {'expires','cache','flags'}} for r in self.ip('-6','route','show','table','all')],key=canonical),
                'rules6':self.ip('-6','rule','show')}

    def route_get(self, address):
        rows = self.ip('route', 'get', address)
        if len(rows) != 1 or rows[0].get('type', 'unicast') != 'unicast':
            raise ValueError('underlay or management route unavailable')
        return {k:rows[0].get(k) for k in ('dev', 'gateway', 'prefsrc', 'table')}

    def preflight(self, op, protected):
        self.run(['wg', '--version'])
        snap = self.snapshot()
        if any(x['name'] == op['interfaceName'] for x in snap['links']):
            raise ValueError('existing interface refused')
        for route in op['routes']:
            if any(r.get('dst') == route or r.get('dst') == route.split('/')[0] for r in snap['routes']):
                raise ValueError('existing route refused')
            for row in snap['routes']:
                dst = row.get('dst', 'default')
                if row.get('type', 'unicast') != 'unicast' and dst != 'default':
                    try:
                        if host(route).network_address in ipaddress.ip_network(dst if '/' in dst else dst+'/32'):
                            raise ValueError('protected local route overlap')
                    except ipaddress.AddressValueError:
                        raise ValueError('unsupported route')
        for row in snap['routes']:
            if row.get('protocol')=='kernel' and row.get('dst','default')!='default':
                network=ipaddress.ip_network(row['dst'] if '/' in row['dst'] else row['dst']+'/32',strict=False)
                if any(host(dst).network_address in network for dst in op['routes']) or host(op['address']).network_address in network:
                    raise ValueError('connected/local prefix shadow refused')
        paths = {}
        for endpoint in [p['endpoint'].split(':')[0] for p in op['peers']] + protected:
            if endpoint+'/32' in op['routes'] or endpoint == op['address'].split('/')[0]:
                raise ValueError('management/underlay overlap')
            paths[endpoint] = self.route_get(endpoint)
            if not paths[endpoint]['dev'] or paths[endpoint]['dev'] == op['interfaceName']:
                raise ValueError('independent underlay required')
        # Validate key availability before durable preparation; no key goes in the journal.
        fd = self.secret(op)
        os.close(fd)
        return snap, paths

    def secret(self, op):
        fd = os.open(os.path.join(self.secrets, op['secretRef']+'.key'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 128:
                raise ValueError('secret must be owned 0600 regular file')
            raw = os.read(fd, 129).strip()
            if not key(raw.decode()):
                raise ValueError('invalid local key')
            public = self.run(['wg', 'pubkey'], raw+b'\n')
            if public != op['publicKey']:
                raise ValueError('secret reference public key mismatch')
            os.lseek(fd, 0, os.SEEK_SET)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def create_link(self, dev, group, mtu):
        """One exclusive RTM_NEWLINK installs identity/group/MTU before kernel registration.

        The iproute2 6.1 name-form create rejects `group`, although rtnl_create_link supports
        IFLA_GROUP. Keep this bounded request specific to creating a new WireGuard device.
        """
        def attr(kind, payload):
            size=4+len(payload)
            return struct.pack('=HH',size,kind)+payload+b'\0'*((-size)%4)
        attrs=attr(3,dev.encode()+b'\0')+attr(4,struct.pack('=I',mtu))+attr(27,struct.pack('=I',group))+attr(18|0x8000,attr(1,b'wireguard\0'))
        body=struct.pack('=BBHiII',0,0,0,0,0,0)+attrs
        sequence=int.from_bytes(os.urandom(4),'big') or 1
        try:
            with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,0) as channel:
                channel.bind((0,0))
                port=channel.getsockname()[0]
                request=struct.pack('=IHHII',16+len(body),16,0x605,sequence,port)+body
                channel.settimeout(self.command_timeout())
                channel.sendto(request,(0,0))
                response,sender=channel.recvfrom(65536)
                if sender[0]!=0 or len(response)<20:
                    raise RuntimeError('invalid kernel create acknowledgement')
                length,kind,_,seq,pid=struct.unpack_from('=IHHII',response)
                if length<20 or length>len(response) or kind!=2 or seq!=sequence or pid!=port or struct.unpack_from('=i',response,16)[0]!=0:
                    raise RuntimeError('kernel refused exclusive WireGuard create')
        except OSError:
            raise RuntimeError('WireGuard netlink create unavailable or timed out') from None

    def create(self, op, owner):
        self.create_link(op['interfaceName'],owner_group(owner),op['mtu'])
        self.run(['ip', 'link', 'set', 'dev', op['interfaceName'], 'alias', owner])

    def configure(self, op):
        dev = op['interfaceName']
        fd = self.secret(op)
        try:
            self.run(['wg', 'set', dev, 'private-key', '/proc/self/fd/'+str(fd), 'listen-port', str(op['listenPort'])], pass_fds=(fd,))
        finally:
            os.close(fd)
        for p in op['peers']:
            self.run(['wg', 'set', dev, 'peer', p['publicKey'], 'endpoint', p['endpoint'], 'allowed-ips', ','.join(p['allowedIps']), 'persistent-keepalive', '1'])
        self.run(['ip', 'address', 'add', op['address'], 'dev', dev])
        self.run(['ip', 'link', 'set', 'dev', dev, 'mtu', str(op['mtu']), 'up'])

    def routes(self, op):
        for dst in op['routes']:
            self.run(['ip', 'route', 'add', dst, 'dev', op['interfaceName'], 'proto', 'static', 'metric', '42760'])

    def ownership_marker(self, link, op, owner):
        alias=link.get('ifalias',link.get('alias'))
        transaction=owner.split(':')[1]
        group=link.get('group')
        # iproute2 can render IFLA_GROUP as signed decimal despite its kernel u32 type.
        group_value=int(group) if type(group) is int or (isinstance(group,str) and re.fullmatch(r'-?[0-9]+',group)) else None
        if group_value is None or not -(1<<31)<=group_value<(1<<32) or (group_value & 0xffffffff)!=owner_group(owner) or op['interfaceName']!='hp'+transaction[:12] or alias not in {None,owner} or link.get('linkinfo', {}).get('info_kind') != 'wireguard':
            raise ValueError('interface ownership conflict')
        return alias

    def owned(self, op, owner):
        links = self.ip('-d', 'link', 'show')
        matches = [x for x in links if x['ifname'] == op['interfaceName']]
        if not matches:
            return False
        link = matches[0]
        alias = self.ownership_marker(link, op, owner)
        # A root writer replacing a configuration must not have its objects deleted by rollback.
        public = self.run(['wg', 'show', op['interfaceName'], 'public-key'])
        if public not in {'', '(none)', op['publicKey']}:
            raise ValueError('key ownership conflict')
        if link['mtu'] != op['mtu'] or self.run(['wg','show',op['interfaceName'],'listen-port']) not in {'0',str(op['listenPort'])}:
            raise ValueError('link configuration ownership conflict')
        endpoints=self.run(['wg','show',op['interfaceName'],'endpoints'])
        for line in endpoints.splitlines():
            pub, endpoint=line.split()
            if endpoint!=next((p['endpoint'] for p in op['peers'] if p['publicKey']==pub), None):
                raise ValueError('endpoint ownership conflict')
        if any(row.get('addr_info') for row in self.ip('-6','address','show','dev',op['interfaceName'])) or any(not kernel_multicast_route(r,op['interfaceName']) for r in self.ip('-6','route','show','table','all','dev',op['interfaceName'])):
            raise ValueError('IPv6 ownership conflict')
        peers = self.run(['wg', 'show', op['interfaceName'], 'peers']).split()
        if alias is None and ('UP' in link.get('flags',[]) or public not in {'','(none)'} or peers or self.run(['wg','show',op['interfaceName'],'listen-port'])!='0' or any(row.get('addr_info') for row in self.ip('address','show','dev',op['interfaceName']))):
            raise ValueError('untagged interface is not an empty interrupted create')
        if not set(peers).issubset({p['publicKey'] for p in op['peers']}):
            raise ValueError('peer ownership conflict')
        allowed = self.run(['wg', 'show', op['interfaceName'], 'allowed-ips'])
        expected = {p['publicKey']:set(p['allowedIps']) for p in op['peers']}
        for line in allowed.splitlines():
            pub, prefixes = line.split('\t', 1)
            if set(prefixes.replace(',', ' ').split()) != expected.get(pub):
                raise ValueError('AllowedIPs ownership conflict')
        for row in self.ip('address', 'show', 'dev', op['interfaceName']):
            if any(a['local']+'/'+str(a['prefixlen']) != op['address'] for a in row.get('addr_info', []) if a['family']=='inet'):
                raise ValueError('address ownership conflict')
        if any(line.split()[1]!='(none)' for line in self.run(['wg','show',op['interfaceName'],'preshared-keys']).splitlines()):
            raise ValueError('PSK ownership conflict')
        current = self.ip('-4', 'route', 'show', 'table', 'all')
        if alias is None and any(r.get('dev')==op['interfaceName'] for r in current):
            raise ValueError('untagged interrupted create has unexpected routes')
        for r in current:
            dst=r.get('dst')
            normalized=dst+'/32' if dst and '/' not in dst and dst!='default' else dst
            if r.get('dev')==op['interfaceName']:
                fields=set(r)-{'dst','dev','protocol','metric','scope','table','type','prefsrc','flags'}
                local=(normalized==op['address'] and r.get('protocol')=='kernel' and r.get('type')=='local' and r.get('table') in {'local',255} and r.get('scope')=='host' and not fields and r.get('prefsrc')==op['address'].split('/')[0] and 'metric' not in r)
                own=(normalized in op['routes'] and r.get('protocol')=='static' and r.get('metric')==42760 and r.get('table','main') in {'main',254} and r.get('type','unicast')=='unicast' and r.get('scope')=='link' and 'prefsrc' not in r and set(r.get('flags',[])).issubset({'linkdown'}) and not fields)
                if not local and not own:
                    raise ValueError('route ownership conflict')
            elif normalized in op['routes']:
                raise ValueError('competing route ownership conflict')
        return True

    def fingerprint(self, op):
        dev=op['interfaceName']
        link=self.ip('-d','link','show','dev',dev)[0]
        return {'index':link['ifindex'],'mtu':link['mtu'],'alias':link.get('ifalias',link.get('alias')),'group':link.get('group'),
                'addresses':sorted(a['local']+'/'+str(a['prefixlen']) for a in self.ip('address','show','dev',dev)[0].get('addr_info',[])),
                'publicKey':self.run(['wg','show',dev,'public-key']),
                'listenPort':self.run(['wg','show',dev,'listen-port']),
                'peers':self.run(['wg','show',dev,'peers']),
                'allowedIps':self.run(['wg','show',dev,'allowed-ips']),
                'endpoints':self.run(['wg','show',dev,'endpoints'])}

    def remove(self, op, owner):
        if self.owned(op, owner):
            self.run(['ip', 'link', 'del', 'dev', op['interfaceName']])
        # No route deletion by destination: interface deletion removes only attached owned routes.
        if any(x['ifname']==op['interfaceName'] for x in self.ip('-d', 'link', 'show')):
            raise RuntimeError('interface removal unverified')

    def verify_presence(self, op, owner):
        if not self.owned(op, owner):
            raise ValueError('interface missing')

    def verify_local(self, op, owner, before, paths):
        self.verify_presence(op, owner)
        snap=self.snapshot()
        link=next(x for x in snap['links'] if x['name']==op['interfaceName'])
        if link['mtu']!=op['mtu']:
            raise ValueError('MTU mismatch')
        address=next(x for x in snap['addresses'] if x['name']==op['interfaceName'])
        if address['addresses'] != [op['address']]:
            raise ValueError('address mismatch')
        for dst in op['routes']:
            if self.route_get(dst.split('/')[0])['dev']!=op['interfaceName']:
                raise ValueError('FIB mismatch')
        if any(self.route_get(ip)!=path for ip,path in paths.items()):
            raise ValueError('protected path changed')
        base={k:v for k,v in snap.items()}
        base['links']=[x for x in base['links'] if x['name']!=op['interfaceName']]
        base['addresses']=[x for x in base['addresses'] if x['name']!=op['interfaceName']]
        base['routes']=[r for r in base['routes'] if r.get('dev')!=op['interfaceName']]
        base['routes6']=[r for r in base['routes6'] if not (r.get('dev')==op['interfaceName'] and kernel_multicast_route(r,op['interfaceName']))]
        if base!=before:
            raise ValueError('protected configuration changed')
        handshakes=self.run(['wg','show',op['interfaceName'],'latest-handshakes'])
        rows=[line.split() for line in handshakes.splitlines()]
        if len(rows)!=len(op['peers']) or any(len(x)!=2 or int(x[1])<=0 or abs(time.time()-int(x[1]))>120 for x in rows):
            raise ValueError('fresh handshake required')
        return {'configurationHash':digest(op), 'protectedHash':digest(before)}


def initialize_journal(directory):
    os.makedirs(directory,mode=0o700,exist_ok=True)
    info=os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:
        raise ValueError('journal requires an owned 0700 directory')
    if os.listdir(directory):
        raise ValueError('journal initialization requires an empty protected directory')
    journal_id=os.urandom(16).hex()
    fd=os.open(os.path.join(directory,'journal-identity.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        stream.write(canonical({'journalId':journal_id}));stream.flush();os.fsync(stream.fileno())
    atomic(os.path.join(directory,'transactions.json'),{'schemaVersion':2,'journalId':journal_id,'terminalSequence':0,'acceptedSequence':0,'transactions':{},'lastClock':0})
    return journal_id


def validate_execution_config(config):
    protected=config.get('protectedAddresses')
    if not isinstance(protected,list) or not 1<=len(protected)<=16 or len(set(protected))!=len(protected):
        raise ValueError('one to sixteen independent protected management addresses required')
    for address in protected:
        if not isinstance(address,str):raise ValueError('invalid protected management address')
        host(address+'/32')


class Executor:
    def __init__(self, config, directory, driver=None, event=None):
        self.config=config
        self.directory=directory
        self.path=os.path.join(directory, 'transactions.json')
        os.makedirs(directory, mode=0o700, exist_ok=True)
        info=os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode & 0o077:
            raise ValueError('state directory must be owned 0700 directory')
        self.provider=crypto_helpers(directory)
        self.injected_driver = driver is not None
        self.driver=driver or LinuxWireGuard(config['secrets'])
        self.drivers = {DRIVER: self.driver}
        self.event=event or (lambda _:None)
        self.boot_started=time.monotonic()

    def select_driver(self, operation, row=None):
        if not self.injected_driver:
            identity = operation['driver']
            if identity not in self.drivers:
                if identity != PERSISTENT_DRIVER:
                    raise ValueError('unsupported execution driver')
                from network_nm_wireguard import NetworkManagerWireGuard
                self.drivers[identity] = NetworkManagerWireGuard(self.config['secrets'])
            self.driver = self.drivers[identity]
        if hasattr(self.driver, 'bind'):
            self.driver.bind(row)
        return self.driver

    @contextlib.contextmanager
    def locked(self):
        fd=os.open(os.path.join(self.directory,'executor.lock'), os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def load(self):
        try:
            data=read_json(self.path)
        except FileNotFoundError:
            raise ValueError('transaction replay journal missing; explicit fresh provisioning required') from None
        if data.get('schemaVersion')==1:
            # Legacy journals may only recover existing debt; they cannot authorize schema2 work.
            exact(data,'schemaVersion transactions lastClock')
            if not isinstance(data['transactions'],dict):raise ValueError('invalid legacy journal')
            return data
        exact(data,'schemaVersion journalId terminalSequence acceptedSequence transactions lastClock')
        identity=read_json(os.path.join(self.directory,'journal-identity.json'))
        if data['schemaVersion']!=2 or not re.fullmatch(r'[a-f0-9]{32}',str(data['journalId'])) or (self.config.get('journalId') is not None and data['journalId']!=self.config['journalId']) or not integer(data['terminalSequence'],0,1024) or not isinstance(data['transactions'],dict) or len(data['transactions'])>1024 or data['acceptedSequence']!=len(data['transactions']):
            raise ValueError('invalid transaction replay journal')
        capacity_rows(data,identity)
        if 'capacityCancellation' in identity:self.cancellation_binding(identity['capacityCancellation']['cancellation'],identity['capacityCancellation']['authorization'])
        terminal=[]
        for transaction,row in data['transactions'].items():
            if row.get('authorization',{}).get('transactionId')!=transaction or row['authorization'].get('journalId')!=data['journalId'] or row.get('state') not in TERMINAL|{'prepared','applying','awaiting-verification','awaiting-confirm','rolling-back','rollback-failed'}:
                raise ValueError('invalid journal transaction')
            if row['state'] in TERMINAL:
                result=row.get('terminalResult',{});committed={k:v for k,v in result.items() if k!='stateHash'}
                if result.get('state')!=row['state'] or result.get('authorizationHash')!=digest(row['authorization']) or result.get('stateHash')!=digest(committed):raise ValueError('invalid terminal journal commitment')
                terminal.append(result.get('sequence'))
                if row['state']=='cancelled-before-accept':
                    self.cancellation_binding(row.get('cancellation'),row['authorization'])
                    if any(k in row for k in ('before','paths','owner','acceptedAt','mono')) or result.get('schemaVersion')!=2 or result.get('domain')!=CANCELLATION_RESULT_DOMAIN or result.get('proof')!={'cancellationHash':digest(row.get('cancellation')),'acceptancePrevented':True}:
                        raise ValueError('invalid never-accepted cancellation commitment')
                    self.cancellation_result_binding(result,row['authorization'])
            if ('cancelRequested' in row)!=('cancellationResponse' in row):raise ValueError('orphan accepted cancellation commitment')
            if row.get('cancelRequested') is not None:
                response=row.get('cancellationResponse',{})
                self.cancellation_result_binding(response,row['authorization'])
                if row['cancelRequested'] is not True or response.get('state')!='cancellation-rejected' or response.get('authorizationHash')!=digest(row['authorization']) or response.get('stateHash')!=digest({k:v for k,v in response.items() if k!='stateHash'}):
                    raise ValueError('invalid accepted cancellation commitment')
                exact(response['proof'],'cancellationHash acceptedState')
                if not re.fullmatch(r'[a-f0-9]{64}',str(response['proof']['cancellationHash'])) or response['proof']['acceptedState'] not in {'prepared','applying','awaiting-verification','awaiting-confirm','rolling-back','rollback-failed'}:raise ValueError('invalid accepted cancellation evidence')
        if sorted(terminal)!=list(range(1,data['terminalSequence']+1)):
            raise ValueError('terminal replay sequence missing')
        return data

    def save(self, data, row=None, state=None):
        backup=json.loads(canonical(data))
        transaction=row['authorization']['transactionId'] if row else None
        if transaction is not None:
            self.current_transaction=transaction
        if state:
            row['state']=state
            row.setdefault('history',[]).append({'state':state,'at':int(time.time()*1000)})
        if row and state in TERMINAL and data['schemaVersion']==2:
            data['terminalSequence']+=1
            a=row['authorization']
            proof={'confirmationHash':digest(row['confirmation']),'verificationHash':digest(row['verification'])} if state=='confirmed' else {'cancellationHash':digest(row['cancellation']),'acceptancePrevented':True} if state=='cancelled-before-accept' else {'removalVerified':True}
            result={'schemaVersion':1,'domain':TERMINAL_DOMAIN,'transactionId':a['transactionId'],'fenceId':a['transactionId'],'target':a['target'],'journalId':data['journalId'],'authorizationHash':digest(a),'artifactHash':a['artifactHash'],'registryRevision':a['registryRevision'],'state':state,'sequence':data['terminalSequence'],'proof':proof}
            if state=='cancelled-before-accept':result.update(schemaVersion=2,domain=CANCELLATION_RESULT_DOMAIN)
            row['terminalResult']={**result,'stateHash':digest(result)}
        if row and state in TERMINAL:
            row['authorizationHash']=digest(row['authorization'])
            row.pop('before',None)
            row.pop('paths',None)
            row.pop('confirmation',None)
            row.pop('verification',None)
        for item in data['transactions'].values():
            item['history']=item.get('history',[])[-16:]
        if len(canonical(data).encode())>8*1024*1024:
            raise ValueError('transaction journal capacity exceeded')
        try:atomic(self.path,data)
        except BaseException:
            if row is not None and transaction in backup['transactions']:
                row.clear();row.update(backup['transactions'][transaction]);backup['transactions'][transaction]=row
            data.clear();data.update(backup)
            raise
        if state:
            self.event(state)

    def rollback(self, data, row):
        self.select_driver(row['authorization']['operation'], row)
        self.driver.deadline=None
        self.driver.command_deadline=time.monotonic()+60
        self.save(data,row,'rolling-back')
        try:
            if row.get('configuredFingerprint') is not None and self.driver.owned(row['authorization']['operation'],row['owner']) and self.driver.fingerprint(row['authorization']['operation'])!=row['configuredFingerprint']:
                raise ValueError('configured object ownership conflict')
            self.driver.remove(row['authorization']['operation'],row['owner'])
            self.event('removed')
            self.save(data,row,'rolled-back')
        except Exception as error:
            row['diagnostic']='rollback: '+safe_diagnostic(error)
            self.save(data,row,'rollback-failed')
        finally:
            self.driver.command_deadline=None

    def recover(self):
        # Restart is an uncertainty boundary. Roll back *all* unconfirmed work immediately, even
        # when acceptance is disabled or the wall clock is unusable. Never resume an apply.
        with self.locked():
            data=self.load()
            for row in data['transactions'].values():
                if row['state'] not in TERMINAL:
                    self.rollback(data,row)

    def validate_restore_authority(self, row, journal_id):
        independent_trust(self.config, self.provider)
        evidence = row.get('restorationAuthority', {})
        a = verify(evidence.get('authorization'), EXECUTION, self.config['managerKeys'], self.provider)
        c = verify(evidence.get('confirmation'), CONFIRM, self.config['managerKeys'], self.provider)
        v = verify(c['verification'], VERIFY, self.config['verifierKeys'], self.provider)
        validate_operation(a['operation'])
        at = row.get('confirmedAt')
        proof = row['terminalResult']['proof']
        approval = a['approval']
        draft = {key:value for key,value in a.items() if key != 'approval'}
        if (a != row['authorization'] or a['target'] != self.config['identity'] or a['journalId'] != journal_id or
                a['operation']['driver'] != PERSISTENT_DRIVER or a['artifactHash'] != digest(a['operation']) or
                a['operation']['profileUuid'].replace('-', '') != a['transactionId'] or
                approval['mode'] != 'two-person' or approval['proposedBy'] == approval['approvedBy'] or
                approval['planHash'] != 'sha256:'+digest(draft) or
                not integer(at, a['issuedAt'], a['rollbackAt']-1) or
                c['transactionId'] != a['transactionId'] or c['authorizationHash'] != digest(a) or c['artifactHash'] != a['artifactHash'] or
                not integer(c['expiresAt'], at+1, a['rollbackAt']) or
                v['transactionId'] != a['transactionId'] or v['authorizationHash'] != digest(a) or v['artifactHash'] != a['artifactHash'] or
                not integer(v['observedAt'], a['issuedAt'], at) or not integer(v['expiresAt'], at+1, a['rollbackAt']) or
                v['checks'] != {key:True for key in CHECKS} or any(type(value) is not bool for value in v['checks'].values()) or
                proof != {'confirmationHash':digest(c), 'verificationHash':digest(v)}):
            raise ValueError('historical restoration authority mismatch')

    def restore_confirmed_boot(self):
        # Called only at startup, never by tick(), close(), or normal undo recovery.
        # Profile autoconnect remains false. No past authority is accepted as a new execution.
        with self.locked():
            data = self.load()
            candidates = [row for row in data['transactions'].values() if row['state'] == 'confirmed' and row['authorization']['operation']['driver'] == PERSISTENT_DRIVER]
            if not candidates:
                return
            boot = current_boot_id()
            deadline = time.monotonic()+120
            recovery_deadline = deadline+60
            failed = False
            for row in candidates:
                if row.get('bootIdAtConfirm') == boot:
                    continue
                previous = row.get('bootRestore', {})
                if previous.get('bootId') == boot:
                    if previous.get('state') != 'restored':
                        failed = True
                        if previous.get('recovery') in {'rolled-back', 'not-started', 'boot-cleared'}:
                            continue
                        if 'plan' not in previous:
                            previous.update(state='degraded', recovery='not-started', reason='interrupted-before-activation')
                            self.save(data)
                            continue
                        self.select_driver(row['authorization']['operation'], row)
                        try:
                            self.driver.command_deadline = recovery_deadline
                            if time.monotonic() >= recovery_deadline:
                                raise ValueError('boot recovery budget exhausted')
                            self.driver.undo_restore(row)
                            previous['recovery'] = 'rolled-back'
                        except Exception:
                            previous['recovery'] = 'rollback-failed'
                        finally:
                            self.driver.command_deadline = None
                            self.save(data)
                    continue
                row['bootRestore'] = {'bootId':boot, 'state':'attempting', 'currentConnectivity':'unknown'}
                self.save(data)
                plan_persisted = False
                try:
                    if time.monotonic() >= deadline:
                        raise ValueError('boot restoration budget exhausted')
                    self.validate_restore_authority(row, data['journalId'])
                    self.select_driver(row['authorization']['operation'], row)
                    self.driver.deadline = None
                    self.driver.command_deadline = deadline
                    # Preparation only reads ownership, secret and fresh boot state. A cold
                    # NM/libnm timeout may be retried, but never a mutation/activation.
                    for attempt in range(1,4):
                        row['bootRestore']['preparationAttempts'] = attempt
                        try:
                            row['bootRestore']['plan'] = self.driver.prepare_restore(row, self.config['protectedAddresses'])
                            break
                        except RuntimeError as error:
                            if not str(error).startswith('network command unavailable or timed out:') or attempt==3 or time.monotonic()>=deadline:
                                raise
                            row['bootRestore']['preparationDiagnostic'] = safe_diagnostic(error)
                            self.save(data)
                    if len(canonical(row['bootRestore']['plan']).encode()) > 1024*1024 or len(canonical(data).encode()) > 7*1024*1024:
                        raise ValueError('boot undo capacity unavailable')
                    self.save(data)
                    plan_persisted = True
                    self.driver.restore(row, self.config['protectedAddresses'])
                    plan = row['bootRestore'].pop('plan', None)
                    if plan is not None:
                        row['bootRestore']['undoHash'] = digest(plan)
                    row['bootRestore']['state'] = 'restored'
                except Exception as error:
                    row['bootRestore']['diagnostic'] = safe_diagnostic(error)
                    row['bootRestore']['state'] = 'degraded'
                    row['bootRestore']['reason'] = 'restoration-unresolved'
                    if not plan_persisted:
                        plan = row['bootRestore'].pop('plan', None)
                        if plan is not None:
                            row['bootRestore']['undoHash'] = digest(plan)
                        row['bootRestore']['recovery'] = 'not-started'
                    elif hasattr(self.driver, 'undo_restore'):
                        try:
                            # Undo gets its own budget even when activation exhausted its budget.
                            self.driver.command_deadline = recovery_deadline
                            if time.monotonic() >= recovery_deadline:
                                raise ValueError('boot recovery budget exhausted')
                            self.driver.undo_restore(row)
                            row['bootRestore']['recovery'] = 'rolled-back'
                        except Exception:
                            row['bootRestore']['recovery'] = 'rollback-failed'
                    failed = True
                finally:
                    self.driver.command_deadline = None
                    self.save(data)
            if failed:
                raise ValueError('confirmed boot restoration unresolved')

    def accept(self,envelope):
        with self.locked():
            assert_active_journal(self.directory)
            if self.config.get('enabled') is not True:
                raise ValueError('new network execution disabled')
            independent_trust(self.config,self.provider)
            a=verify(envelope,EXECUTION,self.config['managerKeys'],self.provider)
            exact(a,'schemaVersion journalId transactionId target registryRevision resources desiredDigest reviewHash artifactHash observation localPrecondition operation issuedAt expiresAt rollbackAt approval')
            now=int(time.time()*1000)
            if a['schemaVersion']!=2 or a['journalId']!=self.config.get('journalId') or not re.fullmatch(r'[a-f0-9]{32}',str(a['transactionId'])) or a['target']!=self.config['identity']:
                raise ValueError('target/schema mismatch')
            if not all(integer(a[k],1,2**53-1) for k in ('issuedAt','expiresAt','rollbackAt')) or not a['issuedAt']<=now<a['expiresAt']<a['rollbackAt'] or a['expiresAt']-a['issuedAt']>60000 or a['rollbackAt']-a['issuedAt']>180000:
                raise ValueError('expired/invalid execution window')
            approval=a['approval']
            exact(approval,'mode planHash proposedBy approvedBy approvedAt')
            draft={k:v for k,v in a.items() if k!='approval'}
            if approval['mode']!='two-person' or not name(approval['proposedBy']) or not name(approval['approvedBy']) or approval['proposedBy']==approval['approvedBy'] or approval['planHash']!='sha256:'+digest(draft) or not integer(approval['approvedAt'],a['issuedAt'],now):
                raise ValueError('two-person approval required separately from signature')
            if not integer(a['registryRevision'],1,2**53-1) or not isinstance(a['resources'],list) or not a['resources'] or any(not isinstance(r,dict) or set(r)!={'id','generation'} or not name(r['id']) or not integer(r['generation'],1,2**53-1) for r in a['resources']):
                raise ValueError('invalid registry commitment')
            for field in ('desiredDigest','reviewHash','artifactHash','localPrecondition'):
                if not isinstance(a[field],str) or not re.fullmatch(r'[a-f0-9]{64}',a[field]):
                    raise ValueError('invalid commitment')
            exact(a['observation'],'digest collectedAt maxAgeMs')
            e=a['observation']
            if not isinstance(e['digest'],str) or not re.fullmatch(r'[a-f0-9]{64}',e['digest']) or not integer(e['maxAgeMs'],1,600000) or not integer(e['collectedAt'],now-e['maxAgeMs'],now):
                raise ValueError('stale observation')
            validate_operation(a['operation'])
            self.select_driver(a['operation'])
            if a['operation']['interfaceName']!='hp'+a['transactionId'][:12]:
                raise ValueError('interface name must bind unique transaction identity')
            if digest(a['operation'])!=a['artifactHash']:
                raise ValueError('artifact hash mismatch')
            data=self.load()
            if data['schemaVersion']!=2 or a['journalId']!=data['journalId']:raise ValueError('journal identity requires fresh approval')
            prior=data['transactions'].get(a['transactionId'])
            if prior:
                if digest(prior['authorization'])!=digest(a):
                    raise ValueError('transaction identity reused with different content')
                if prior['state']=='cancelled-before-accept':raise ValueError('authority permanently cancelled before acceptance')
                return prior['state']
            if now<data['lastClock']:
                raise ValueError('clock moved behind durable replay watermark')
            if 'capacityCancellation' in read_json(os.path.join(self.directory,'journal-identity.json')):raise ValueError('capacity maintenance required; new acceptance refused')
            if len(data['transactions'])>=ADMISSION_RECORD_LIMIT:
                raise ValueError('transaction replay ledger capacity reached')
            if any(r['state'] not in TERMINAL or (r.get('bootRestore', {}).get('recovery') == 'rollback-failed' or r.get('bootRestore', {}).get('state') == 'attempting') for r in data['transactions'].values()):
                raise ValueError('unsettled network transaction')
            # Clear a stale process-local budget only after the durable ledger proves no debt.
            # This also reconciles a terminal rename whose directory fsync raised afterward.
            self.driver.deadline=None
            if len(canonical(data).encode())>6*1024*1024:
                raise ValueError('transaction journal capacity reached')
            started_mono=time.monotonic()
            self.driver.command_deadline=started_mono+(a['expiresAt']-now)/1000
            try:
                before,paths=self.driver.preflight(a['operation'],self.config['protectedAddresses'])
            finally:
                self.driver.command_deadline=None
            if digest(before)!=a['localPrecondition']:
                raise ValueError('local precondition changed: replan and reapprove')
            fresh_now=int(time.time()*1000)
            if fresh_now<now or fresh_now>=a['expiresAt'] or (time.monotonic()-started_mono)*1000>=a['expiresAt']-now:
                raise ValueError('authorization expired during preflight')
            row={'authorization':a,'state':'prepared','before':before,'paths':paths,'owner':'heliopause:'+a['transactionId']+':'+os.urandom(16).hex(),'acceptedAt':now,'mono':started_mono,'diagnostic':None,'history':[]}
            data['transactions'][a['transactionId']]=row
            data['acceptedSequence']+=1
            data['lastClock']=now
            if len(canonical(data).encode())>6*1024*1024:
                raise ValueError('prospective transaction exceeds reserved journal capacity')
            if a['operation']['driver'] == PERSISTENT_DRIVER:
                self.select_driver(a['operation'], row)
                row['persistence'] = self.driver.prepare(row)
                row['restorationAuthority'] = {'authorization': envelope}
            # Every undo input exists on disk before the first network write.
            self.save(data,row,'prepared')
            try:
                self.driver.deadline=started_mono+(a['rollbackAt']-now)/1000
                self.save(data,row,'applying')
                if int(time.time()*1000)<fresh_now or int(time.time()*1000)>=a['expiresAt'] or time.monotonic()-started_mono>=(a['expiresAt']-now)/1000:
                    raise ValueError('authorization expired before first write')
                self.driver.create(a['operation'],row['owner'])
                self.event('created')
                self.driver.configure(a['operation'])
                row['configuredFingerprint']=self.driver.fingerprint(a['operation'])
                self.save(data)
                self.event('configured')
                self.driver.routes(a['operation'])
                self.event('routes')
                self.save(data,row,'awaiting-verification')
                if int(time.time()*1000)>=a['rollbackAt'] or time.monotonic()>=self.driver.deadline:
                    self.rollback(data,row)
            except Exception as error:
                row['diagnostic']='apply: '+safe_diagnostic(error)
                self.rollback(data,row)
            return row['state']

    def cancellation_binding(self,c,a):
        exact(c,'schemaVersion transactionId fenceId target journalId authorizationHash artifactHash registryRevision requestedAt requestedBy authorization')
        if c['schemaVersion']!=1 or a['schemaVersion']!=2 or c['target']!=self.config['identity'] or c['journalId']!=self.config.get('journalId') or not re.fullmatch(r'[a-f0-9]{32}',str(c['transactionId'])) or not integer(c['requestedAt'],1,2**53-1) or not name(c['requestedBy']):
            raise ValueError('cancellation identity/schema mismatch')
        for k in ('transactionId','target','journalId','artifactHash','registryRevision'):
            if c[k]!=a[k]:raise ValueError('cancellation authorization binding mismatch')
        if c['fenceId']!=a['transactionId'] or c['authorizationHash']!=digest(a) or digest(a['operation'])!=a['artifactHash']:
            raise ValueError('cancellation commitment mismatch')

    def cancellation_result_binding(self,result,a):
        exact(result,'schemaVersion domain transactionId fenceId target journalId authorizationHash artifactHash registryRevision state sequence stateHash proof')
        if result['schemaVersion']!=2 or result['domain']!=CANCELLATION_RESULT_DOMAIN or result['authorizationHash']!=digest(a) or result['fenceId']!=a['transactionId'] or not integer(result['sequence'],1,1024):raise ValueError('invalid cancellation result')
        for k in ('transactionId','target','journalId','artifactHash','registryRevision'):
            if result[k]!=a[k]:raise ValueError('cancellation result binding mismatch')

    def cancel(self,envelope):
        # Ledger-only: safe while firewall is busy or new network execution is disabled.
        # Accepted work is marked for the existing tick/ownership-checked undo, never relabelled.
        with self.locked():
            assert_active_journal(self.directory)
            c=verify(envelope,CANCEL,self.config['managerKeys'],self.provider)
            exact(c,'schemaVersion transactionId fenceId target journalId authorizationHash artifactHash registryRevision requestedAt requestedBy authorization')
            a=verify(c['authorization'],EXECUTION,self.config['managerKeys'],self.provider)
            exact(a,'schemaVersion journalId transactionId target registryRevision resources desiredDigest reviewHash artifactHash observation localPrecondition operation issuedAt expiresAt rollbackAt approval')
            self.cancellation_binding(c,a)
            data=self.load()
            if data['schemaVersion']!=2 or data['journalId']!=c['journalId']:raise ValueError('cancellation journal binding mismatch')
            row=data['transactions'].get(c['transactionId'])
            if row:
                if digest(row['authorization'])!=c['authorizationHash']:raise ValueError('transaction identity reused')
                if row['state'] in TERMINAL:
                    if row['state']=='cancelled-before-accept' and digest(row['cancellation'])!=digest(c):raise ValueError('conflicting cancellation')
                    return row['state']
                if row.get('cancellationResponse'):
                    if row['cancellationResponse']['proof']['cancellationHash']!=digest(c):raise ValueError('conflicting accepted cancellation')
                    return 'cancellation-rejected'
                response={'schemaVersion':2,'domain':CANCELLATION_RESULT_DOMAIN,'transactionId':a['transactionId'],'fenceId':c['fenceId'],'target':a['target'],'journalId':data['journalId'],'authorizationHash':digest(a),'artifactHash':a['artifactHash'],'registryRevision':a['registryRevision'],'state':'cancellation-rejected','sequence':list(data['transactions']).index(a['transactionId'])+1,'proof':{'cancellationHash':digest(c),'acceptedState':row['state']}}
                row['cancelRequested']=True;row['cancellationResponse']={**response,'stateHash':digest(response)}
                self.save(data)
                return 'cancellation-rejected'
            identity=read_json(os.path.join(self.directory,'journal-identity.json'))
            reserved=identity.get('capacityCancellation')
            if reserved:
                if reserved['authorizationHash']==digest(a) and digest(reserved['cancellation'])==digest(c):return reserved['state']
                raise ValueError('capacity maintenance required; cancellation slot already reserved')
            row={'authorization':a,'cancellation':c,'state':'cancelled-before-accept','history':[]}
            # Include the complete terminal result and history in the admission measurement.
            result={'schemaVersion':2,'domain':CANCELLATION_RESULT_DOMAIN,'transactionId':a['transactionId'],'fenceId':a['transactionId'],'target':a['target'],'journalId':data['journalId'],'authorizationHash':digest(a),'artifactHash':a['artifactHash'],'registryRevision':a['registryRevision'],'state':row['state'],'sequence':data['terminalSequence']+1,'proof':{'cancellationHash':digest(c),'acceptancePrevented':True}}
            preview=json.loads(canonical(data));preview['transactions'][a['transactionId']]={**row,'authorizationHash':digest(a),'history':[{'state':row['state'],'at':2**53-1}],'terminalResult':{**result,'stateHash':digest(result)}};preview['acceptedSequence']+=1;preview['terminalSequence']+=1
            if len(data['transactions'])>=ADMISSION_RECORD_LIMIT or len(canonical(preview).encode())>6*1024*1024:
                if len(data['transactions'])>=1024 or any(r['state'] not in {'rolled-back','cancelled-before-accept'} or any(k in r for k in ('bootRestore','before','paths')) for r in data['transactions'].values()):raise ValueError('cancellation replay ledger capacity reached with recovery debt or confirmed resources')
                result.update(schemaVersion=3,domain=CAPACITY_RESULT_DOMAIN)
                result['proof']['maintenanceRequired']=True
                row.update(authorizationHash=digest(a),history=[{'state':row['state'],'at':int(time.time()*1000)}],terminalResult={**result,'stateHash':digest(result)})
                successor={'journalId':data['journalId'],'capacityCancellation':row}
                capacity_rows(data,successor)
                self.current_transaction=a['transactionId']
                self.event('before-capacity-save')
                atomic(os.path.join(self.directory,'journal-identity.json'),successor)
                self.event('capacity-reserved')
                return row['state']
            data['transactions'][a['transactionId']]=row
            data['acceptedSequence']+=1  # Counts replay identities, not proof of apply.
            self.event('before-cancel-save')
            self.save(data,row,'cancelled-before-accept')
            return row['state']

    def confirm(self,envelope):
        with self.locked():
            assert_active_journal(self.directory)
            data=self.load()
            independent_trust(self.config,self.provider)
            c=verify(envelope,CONFIRM,self.config['managerKeys'],self.provider)
            exact(c,'transactionId authorizationHash artifactHash expiresAt verification')
            row=data['transactions'].get(c['transactionId'])
            if row and row['state']=='confirmed' and row.get('terminalResult',{}).get('proof',{}).get('confirmationHash')==digest(c):
                return 'confirmed'
            if not row or row['state'] not in {'awaiting-verification','awaiting-confirm'}:
                raise ValueError('no confirmable transaction')
            if row.get('cancelRequested'):raise ValueError('cancellation requested; local rollback required')
            a=row['authorization']
            now=int(time.time()*1000)
            if now<a['issuedAt'] or now>=min(c['expiresAt'],a['rollbackAt']) or c['authorizationHash']!=digest(a) or c['artifactHash']!=a['artifactHash']:
                raise ValueError('stale/mismatched confirm')
            v=verify(c['verification'],VERIFY,self.config['verifierKeys'],self.provider)
            exact(v,'transactionId authorizationHash artifactHash observedAt expiresAt nonce checks')
            if v['transactionId']!=a['transactionId'] or v['authorizationHash']!=digest(a) or v['artifactHash']!=a['artifactHash'] or not integer(v['observedAt'],row['acceptedAt'],now) or not integer(v['expiresAt'],now+1,min(now+10000,a['rollbackAt'])) or not re.fullmatch(r'[a-f0-9]{32}',str(v['nonce'])) or v['checks']!={k:True for k in CHECKS} or any(type(value) is not bool for value in v['checks'].values()):
                raise ValueError('independent verification missing/stale/failed')
            self.select_driver(a['operation'], row)
            self.driver.verify_local(a['operation'],row['owner'],row['before'],row['paths'])
            self.save(data,row,'awaiting-confirm')
            row['verification']=v
            row['confirmation']=c
            if a['operation']['driver'] == PERSISTENT_DRIVER:
                row['restorationAuthority']['confirmation'] = envelope
                row['bootIdAtConfirm'] = current_boot_id()
                row['confirmedAt'] = int(time.time()*1000)
            final_now=int(time.time()*1000)
            if final_now<data['lastClock'] or final_now>=min(c['expiresAt'],v['expiresAt'],a['rollbackAt']) or (time.monotonic()-row['mono'])*1000>=a['rollbackAt']-row['acceptedAt']:
                self.rollback(data,row)
                raise ValueError('confirmation deadline elapsed')
            self.save(data,row,'confirmed')
            self.driver.deadline=None
            return row['state']

    def terminal_results(self):
        with self.locked():
            data=self.load()
            if data['schemaVersion']!=2:return []
            fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
            fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
            identity_path=os.path.join(self.directory,'journal-identity.json')
            fd=os.open(identity_path,os.O_RDONLY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
            rows=capacity_rows(data,read_json(identity_path))
            return [row['terminalResult'] if row['state'] in TERMINAL else row['cancellationResponse'] for row in rows.values() if row['state'] in TERMINAL or row.get('cancellationResponse')]

    def publish_results(self):
        # Protected local outbox only. A separate read-only courier owns all network I/O.
        atomic(os.path.join(self.directory,'terminal-results.json'),self.terminal_results())

    def tick(self):
        with self.locked():
            data=self.load()
            now=int(time.time()*1000)
            debts = [row for row in data['transactions'].values() if row['state'] == 'confirmed' and row.get('bootRestore', {}).get('recovery') == 'rollback-failed']
            if debts:
                cursor = getattr(self, 'boot_undo_cursor', 0) % len(debts)
                self.boot_undo_cursor = cursor+1
                row = debts[cursor]
                self.select_driver(row['authorization']['operation'], row)
                try:
                    self.driver.command_deadline = time.monotonic()+20
                    self.driver.undo_restore(row)
                    row['bootRestore']['recovery'] = 'rolled-back'
                except Exception:
                    pass
                finally:
                    self.driver.command_deadline = None
            for row in data['transactions'].values():
                if row['state'] in TERMINAL:
                    continue
                a=row['authorization']
                elapsed=time.monotonic()-row['mono']
                if row.get('cancelRequested') or row['state']=='rollback-failed' or now<data['lastClock'] or now>=a['rollbackAt'] or elapsed*1000>=a['rollbackAt']-row['acceptedAt']:
                    self.rollback(data,row)
            data['lastClock']=max(now,data['lastClock'])
            self.save(data)


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config')
    parser.add_argument('--initialize-journal',action='store_true')
    parser.add_argument('--state-dir',required=True)
    args=parser.parse_args(argv)
    if args.initialize_journal:
        print(initialize_journal(args.state_dir));return
    if not args.config:parser.error('--config required for execution')
    # Execution has one canonical process owner. Preserve the old CLI spelling, but never
    # launch a second network-only loop outside the persistent Agent's host writer lock.
    import sys
    entry=os.path.join(os.path.dirname(__file__),'heliopause-pull.py')
    os.execv(sys.executable,[sys.executable,entry,'--network-executor','--config',args.config,'--state-dir',args.state_dir])


if __name__=='__main__':
    main()
