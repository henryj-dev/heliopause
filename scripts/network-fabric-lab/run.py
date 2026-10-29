"""Disposable namespace lab for the BGP fabric planner (src/network-fabric.ts).

Consumes planBgpFabric output for four synthetic sites: per-peer native WireGuard interfaces with
AllowedIPs 0/0, a simulated external backbone (one interface, per-peer block AllowedIPs, like an
externally managed mesh), FRR on each gateway, and one in-site cluster speaker. Each check asserts
BGP selection, kernel FIB, WireGuard byte deltas and packets separately. Durations are measured,
never promised. No production transport, address or key is used.
"""
import json
import os
import pwd
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(tempfile.mkdtemp(prefix='hp-fabric-lab-'))
ROOT.chmod(0o755)
RESULTS = Path('/results')
REPORT = {'schemaVersion': 1, 'scope': 'isolated-synthetic-fabric-lab',
          'externalBackboneIsSimulated': True, 'kubernetesVerified': False,
          'checks': [], 'measurements': []}
PROCESSES = []
EXTERNAL_PORT = 51900


def command(*argv, input=None, check=True, timeout=15):
    return subprocess.run(argv, input=input, text=True, capture_output=True, timeout=timeout, check=check)


def ns(name, *argv, **kwargs):
    return command('ip', 'netns', 'exec', name, *argv, **kwargs)


def site(i):
    return f'site{i}'


def client(i):
    return f'client{i}'


def vty(name, cmd, daemon='bgpd'):
    out = ns(name, 'vtysh', '--vty_socket', str(ROOT/name), '-d', daemon, '-c', cmd).stdout
    return json.loads(out) if cmd.endswith('json') else out


def record(name, fn):
    started = time.monotonic()
    fn()
    REPORT['checks'].append({'name': name, 'passed': True, 'durationMs': round((time.monotonic()-started)*1000, 3)})


def eventually(fn, seconds=75):
    end = time.monotonic()+seconds
    last = None
    while time.monotonic() < end:
        try:
            return fn()
        except (AssertionError, subprocess.SubprocessError, ValueError, KeyError, IndexError) as error:
            last = str(error)
            time.sleep(0.25)
    raise AssertionError('convergence timeout: '+str(last))


def ping(src, address):
    return command('ip', 'netns', 'exec', src, 'ping', '-n', '-q', '-c', '1', '-W', '1', address,
                   check=False, timeout=3).returncode == 0


def transfer(name, interface):
    return sum(int(row.split()[2]) for row in ns(name, 'wg', 'show', interface, 'transfer').stdout.splitlines() if row)


def fib_dev(name, address):
    return json.loads(ns(name, 'ip', '-j', 'route', 'get', address).stdout)[0].get('dev')


def bgp_paths(name, prefix):
    return vty(name, f'show bgp ipv4 unicast {prefix} json').get('paths', [])


def best_nexthops(name, prefix):
    best = [p for p in bgp_paths(name, prefix) if p.get('bestpath', {}).get('overall')]
    assert len(best) == 1, ('no single selected path', name, prefix, best)
    return {n.get('ip') for n in best[0].get('nexthops', [])}


class Lab:
    def __init__(self, bundle):
        self.bundle = bundle
        self.sites = bundle['sites']
        self.plan = bundle['plan']
        self.gateways = {g['routerId']: g for g in self.plan['gateways']}
        self.cluster = bundle['clusterSite']

    def gw(self, i):
        return self.gateways[f'r{i}']

    def native_iface(self, i, j):
        return next(w['interfaceName'] for w in self.gw(i)['wireguard'] if w['peerRouterId'] == f'r{j}')

    # ---- setup -------------------------------------------------------------------------
    def setup(self):
        command('ip', 'link', 'add', 'lab-underlay', 'type', 'bridge')
        command('ip', 'link', 'set', 'lab-underlay', 'up')
        n = len(self.sites)
        native_keys = [command('wg', 'genkey').stdout.strip() for _ in range(n)]
        native_pubs = [command('wg', 'pubkey', input=k+'\n').stdout.strip() for k in native_keys]
        external_keys = [command('wg', 'genkey').stdout.strip() for _ in range(n)]
        external_pubs = [command('wg', 'pubkey', input=k+'\n').stdout.strip() for k in external_keys]
        for i, s in enumerate(self.sites):
            command('ip', 'netns', 'add', site(i))
            command('ip', 'netns', 'add', client(i))
            for name in (site(i), client(i)):
                ns(name, 'ip', 'link', 'set', 'lo', 'up')
                ns(name, 'sysctl', '-qw', 'net.ipv4.conf.all.rp_filter=0')
                ns(name, 'sysctl', '-qw', 'net.ipv4.conf.default.rp_filter=0')
            ns(site(i), 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
            command('ip', 'link', 'add', f'edge{i}', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', site(i))
            command('ip', 'link', 'set', f'edge{i}', 'master', 'lab-underlay')
            command('ip', 'link', 'set', f'edge{i}', 'up')
            ns(site(i), 'ip', 'addr', 'add', s['endpoint']+'/24', 'dev', 'eth0')
            ns(site(i), 'ip', 'link', 'set', 'eth0', 'up')
            command('ip', 'link', 'add', 'lan0', 'netns', site(i), 'type', 'veth', 'peer', 'name', 'eth0', 'netns', client(i))
            ns(site(i), 'ip', 'addr', 'add', s['gatewayLan']+'/24', 'dev', 'lan0')
            ns(site(i), 'ip', 'link', 'set', 'lan0', 'up')
            ns(client(i), 'ip', 'addr', 'add', s['clientLan']+'/24', 'dev', 'eth0')
            ns(client(i), 'ip', 'link', 'set', 'eth0', 'up')
            ns(client(i), 'ip', 'route', 'add', 'default', 'via', s['gatewayLan'])
            # The VPC router normally holds the site block; network import-check needs a RIB route.
            ns(site(i), 'ip', 'route', 'add', 'blackhole', s['block'])
            # Native backbone, exactly as planned: one interface per peer.
            for w in self.gw(i)['wireguard']:
                template = w['template']
                for j, peer in enumerate(self.sites):
                    template = template.replace(peer['placeholderKey'], native_pubs[j])
                lines = [l for l in template.splitlines() if not l.startswith(('Address =', 'Table =', 'MTU ='))]
                text = '\n'.join(lines).replace('[Interface]', '[Interface]\nPrivateKey = '+native_keys[i])+'\n'
                self.wg_conf(i, w['interfaceName'], text)
                ns(site(i), 'ip', 'addr', 'add', w['localAddress'], 'dev', w['interfaceName'])
                ns(site(i), 'ip', 'link', 'set', w['interfaceName'], 'mtu', str(w.get('mtu', 1420)), 'up')
                ns(site(i), 'ip', 'route', 'add', w['peerAddress'], 'dev', w['interfaceName'])
            # Simulated external backbone: one interface, peers keyed to their own blocks.
            ns(site(i), 'ip', 'link', 'add', 'cf0', 'type', 'wireguard')
            conf = ['[Interface]', 'PrivateKey = '+external_keys[i], f'ListenPort = {EXTERNAL_PORT}']
            for j, peer in enumerate(self.sites):
                if j != i:
                    conf += ['', '[Peer]', 'PublicKey = '+external_pubs[j], f'Endpoint = {peer["endpoint"]}:{EXTERNAL_PORT}',
                             f'AllowedIPs = {peer["external"]}/32, {peer["block"]}', 'PersistentKeepalive = 5']
            self.wg_conf(i, 'cf0', '\n'.join(conf)+'\n')
            ns(site(i), 'ip', 'addr', 'add', s['external']+'/32', 'dev', 'cf0')
            ns(site(i), 'ip', 'link', 'set', 'cf0', 'mtu', '1420', 'up')
            for j, peer in enumerate(self.sites):
                if j != i:
                    ns(site(i), 'ip', 'route', 'add', peer['external']+'/32', 'dev', 'cf0')
        REPORT['measurements'].append({'scenario': 'native 0->1 RTT before FRR', 'ping': self.rtt(0, 1)})
        for i in range(len(self.sites)):
            self.start_frr(site(i), self.gateway_config(i))
        self.setup_cluster()
        REPORT['measurements'].append({'scenario': 'native 0->1 RTT after FRR', 'ping': self.rtt(0, 1)})

    def rtt(self, i, j):
        time.sleep(6)
        iface = self.native_iface(i, j)
        hs = lambda: ns(site(i), 'wg', 'show', iface, 'latest-handshakes').stdout.split()[-1]
        before = hs()
        out = ns(site(i), 'ping', '-n', '-c', '10', '-i', '0.5', '-W', '3', self.sites[j]['native'], check=False, timeout=30).stdout
        return {'handshakeBefore': before, 'handshakeAfter': hs(), 'ping': out.strip().splitlines()[-12:]}

    def wg_conf(self, i, interface, text):
        if interface != 'cf0':
            ns(site(i), 'ip', 'link', 'add', interface, 'type', 'wireguard')
        path = ROOT/f'wg-{i}-{interface}.conf'
        path.write_text(text)
        path.chmod(0o600)
        ns(site(i), 'wg', 'setconf', interface, str(path))
        path.unlink()

    def gateway_config(self, i):
        # Lab-only timers, inserted before negotiation; the plan's text is otherwise used verbatim.
        lines = self.gw(i)['frr'].splitlines()
        neighbors = [l.split()[1] for l in lines if l.startswith(' neighbor ') and ' remote-as ' in l]
        # After the neighbor declarations, before the first address-family block.
        start = lines.index(f'router bgp {65001+i}')
        anchor = next(k for k in range(start, len(lines)) if lines[k] == ' !')
        timers = [x for n in neighbors for x in (f' neighbor {n} timers 1 3', f' neighbor {n} timers connect 1')]
        return '\n'.join(lines[:anchor]+timers+lines[anchor:])+'\n'

    def setup_cluster(self):
        # Stand-in for an in-site Cilium speaker: originates a load-balancer VIP, a Pod prefix, and
        # two prefixes the gateway must refuse (an infrastructure subnet, a Service aggregate).
        i = self.cluster
        s = self.sites[i]
        o = 40+i
        name = client(i)
        ns(name, 'ip', 'addr', 'add', s['vip']+'/32', 'dev', 'lo')
        ns(name, 'ip', 'addr', 'add', f'10.{o}.128.1/32', 'dev', 'lo')
        ns(name, 'ip', 'route', 'add', 'blackhole', f'10.{o}.128.0/24')
        ns(name, 'ip', 'route', 'add', 'blackhole', f'10.{o}.192.0/18')
        cluster_asn = 65100
        gateway_asn = 65001+i
        config = '\n'.join([
            'frr defaults traditional', f'router bgp {cluster_asn}', f' bgp router-id {s["clientLan"]}',
            ' no bgp ebgp-requires-policy', ' no bgp default ipv4-unicast',
            f' neighbor {s["gatewayLan"]} remote-as {gateway_asn}',
            f' neighbor {s["gatewayLan"]} timers 1 3', f' neighbor {s["gatewayLan"]} timers connect 1',
            ' address-family ipv4 unicast',
            f'  network {s["vip"]}/32', f'  network 10.{o}.128.0/24', f'  network 10.{o}.0.0/24', f'  network 10.{o}.192.0/18',
            f'  neighbor {s["gatewayLan"]} activate', ' exit-address-family', 'exit', ''])
        self.start_frr(name, config)

    def start_frr(self, name, config):
        directory = ROOT/name
        directory.mkdir(mode=0o750)
        account = pwd.getpwnam('frr')
        os.chown(directory, account.pw_uid, account.pw_gid)
        conf = directory/'bgpd.conf'
        conf.write_text(config)
        common = ['-z', str(directory/'zserv.api'), '--vty_socket', str(directory)]
        self.daemon(name, '/usr/lib/frr/zebra', directory, '-f', '/dev/null', '-i', str(directory/'zebra.pid'), *common)
        eventually(lambda: (directory/'zserv.api').exists() or (_ for _ in ()).throw(AssertionError('zserv')), 10)
        self.daemon(name, '/usr/lib/frr/bgpd', directory, '-S', '-f', str(conf), '-i', str(directory/'bgpd.pid'), *common)

    def daemon(self, name, executable, directory, *args):
        log = directory/(Path(executable).name+'.log')
        with log.open('w') as stream:
            proc = subprocess.Popen(['ip', 'netns', 'exec', name, executable, *args], stdout=stream, stderr=stream)
        PROCESSES.append((proc, log))

        def ready():
            assert proc.poll() is None, log.read_text()[-4000:]
            assert (directory/(Path(executable).name+'.vty')).exists(), log.read_text()[-4000:]
        eventually(ready, 20)

    # ---- checks ------------------------------------------------------------------------
    def syntax(self):
        version = command('/usr/lib/frr/bgpd', '--version').stdout
        assert self.bundle['frrVersion'] in version, version
        REPORT['frrVersion'] = self.bundle['frrVersion']
        for g in self.plan['gateways']:
            path = ROOT/f'syntax-{g["routerId"]}.conf'
            path.write_text(g['frr'])
            result = command('/usr/lib/frr/bgpd', '-C', '-S', '-f', str(path), check=False)
            text = (result.stdout+result.stderr).lower()
            assert result.returncode == 0 and not any(x in text for x in ['unknown command', 'no such command', 'error', 'failure']), result.stdout+result.stderr

    def tunnels(self):
        # Underlay and tunnel data path, independent of BGP: every planned interface reaches its peer.
        for i in range(len(self.sites)):
            for w in self.gw(i)['wireguard']:
                peer = w['peerAddress'].split('/')[0]
                before = transfer(site(i), w['interfaceName'])
                assert ping(site(i), peer), ('native tunnel does not carry packets', i, w['peerRouterId'])
                assert transfer(site(i), w['interfaceName']) > before, ('ping bypassed the planned interface', i, w['interfaceName'])
            for j, peer in enumerate(self.sites):
                if j != i:
                    assert ping(site(i), peer['external']), ('external tunnel does not carry packets', i, j)

    def sessions(self):
        for i in range(len(self.sites)):
            data = vty(site(i), 'show bgp ipv4 unicast summary json')
            peers = data.get('ipv4Unicast', data).get('peers', {})
            expected = 2*(len(self.sites)-1)+(1 if i == self.cluster else 0)
            assert len(peers) == expected and all(p.get('state') == 'Established' for p in peers.values()), (i, peers)

    def path(self, i, j, native):
        s, peer = self.sites[i], self.sites[j]
        want = peer['native'] if native else peer['external']
        assert want in best_nexthops(site(i), peer['block']), (i, j, native)
        iface = self.native_iface(i, j) if native else 'cf0'
        assert fib_dev(site(i), peer['clientLan']) == iface, (i, j, fib_dev(site(i), peer['clientLan']))
        before = transfer(site(i), iface)
        assert ping(client(i), peer['clientLan']), ('packet failed', i, j)
        assert transfer(site(i), iface) > before, ('packet did not use the selected tunnel', i, j, iface)

    def all_paths(self, native=lambda i, j: True):
        for i in range(len(self.sites)):
            for j in range(len(self.sites)):
                if i != j:
                    self.path(i, j, native(i, j))

    def cluster_routes(self):
        c = self.cluster
        s = self.sites[c]
        o = 40+c
        local = site(c)
        assert s['clientLan'] in best_nexthops(local, s['vip']+'/32')
        assert s['clientLan'] in best_nexthops(local, f'10.{o}.128.0/24')
        for refused in (f'10.{o}.0.0/24', f'10.{o}.192.0/18'):
            assert not any(any(n.get('ip') == s['clientLan'] for n in p.get('nexthops', [])) for p in bgp_paths(local, refused)), ('gateway accepted', refused)
        for i in range(len(self.sites)):
            if i == c:
                continue
            assert s['native'] in best_nexthops(site(i), s['vip']+'/32'), ('VIP not via native', i)
            assert s['native'] in best_nexthops(site(i), f'10.{o}.128.0/24'), ('pod prefix not via native', i)
            for refused in (f'10.{o}.0.0/24', f'10.{o}.192.0/18'):
                assert not bgp_paths(site(i), refused), ('remote site learned', refused, i)
            assert ping(client(i), s['vip']), ('VIP unreachable', i)
            assert ping(client(i), f'10.{o}.128.1'), ('pod address unreachable', i)

    def set_native(self, pairs, up):
        for i, j in pairs:
            ns(site(i), 'ip', 'link', 'set', self.native_iface(i, j), 'up' if up else 'down')
        if up:
            for i, j in pairs:
                iface = self.native_iface(i, j)
                eventually(lambda i=i, iface=iface: self.zebra_up(i, iface), 20)
                peer = next(w for w in self.gw(i)['wireguard'] if w['interfaceName'] == iface)
                ns(site(i), 'ip', 'route', 'replace', peer['peerAddress'], 'dev', iface)

    def zebra_up(self, i, iface):
        state = vty(site(i), f'show interface {iface}', 'zebra')
        assert f'{iface} is up' in state and 'line protocol is up' in state, state

    def converge(self, scenario, native):
        started = time.monotonic()
        result = eventually(lambda: self.all_paths(native) or True)
        REPORT['measurements'].append({'scenario': scenario, 'convergenceMs': round((time.monotonic()-started)*1000, 3)})
        return result

    def link_failure(self):
        self.set_native([(0, 1), (1, 0)], False)
        self.converge('single native link 0-1 down', lambda i, j: {i, j} != {0, 1})

    def link_recovery(self):
        self.set_native([(0, 1), (1, 0)], True)
        self.converge('single native link 0-1 recovered', lambda i, j: True)

    def silent_failure(self):
        # Interfaces stay up and routes stay installed; only packets disappear. Emptying site1's
        # AllowedIPs for its peer site0 makes WireGuard drop decrypted traffic in both directions.
        # (Changing a listen port is not enough: WireGuard roams to the new source port.)
        # Only the BGP hold timer can notice (lab timers 1/3 s; no BFD in this scenario).
        iface = self.native_iface(1, 0)
        pub = ns(site(1), 'wg', 'show', iface, 'peers').stdout.split()[0]
        self.silent = (iface, pub)
        ns(site(1), 'wg', 'set', iface, 'peer', pub, 'allowed-ips', '')
        assert 'UP' in json.loads(ns(site(0), 'ip', '-j', 'link', 'show', self.native_iface(0, 1)).stdout)[0]['flags']
        self.converge('silent native loss on link 0-1 (interfaces up)', lambda i, j: {i, j} != {0, 1})

    def silent_recovery(self):
        iface, pub = self.silent
        ns(site(1), 'wg', 'set', iface, 'peer', pub, 'allowed-ips', '0.0.0.0/0,::/0')
        self.converge('silent native loss on link 0-1 repaired', lambda i, j: True)

    def all_pairs(self):
        n = len(self.sites)
        return [(i, j) for i in range(n) for j in range(n) if i != j]

    def full_failure(self):
        self.set_native(self.all_pairs(), False)
        self.converge('all native links down', lambda i, j: False)

    def full_recovery(self):
        self.set_native(self.all_pairs(), True)
        self.converge('all native links recovered', lambda i, j: True)

    def leakage(self):
        # Gateway 0 deliberately originates management space, its Service aggregate and the tunnel
        # pool. The planned export filter must refuse all three although they are in its RIB.
        name = site(0)
        refused = ['10.95.0.0/16', '10.40.192.0/18', '10.90.0.0/24']
        for prefix in refused:
            ns(name, 'ip', 'route', 'add', 'blackhole', prefix)
        args = ['vtysh', '--vty_socket', str(ROOT/name), '-d', 'bgpd', '-c', 'configure terminal', '-c', 'router bgp 65001', '-c', 'address-family ipv4 unicast']
        for prefix in refused:
            args += ['-c', f'network {prefix}']
        ns(name, *args)
        eventually(lambda: all(bgp_paths(name, p) for p in refused) or (_ for _ in ()).throw(AssertionError('origin not installed; leak test did not open the path')))
        time.sleep(3)
        for i in range(1, len(self.sites)):
            for prefix in refused:
                assert not bgp_paths(site(i), prefix), ('leaked', prefix, i)

    def static_shadow(self):
        # A metric-0 kernel route for a remote block (what wg-quick would install from AllowedIPs)
        # beats every BGP route. The plan lists this as a precondition; the lab shows why.
        peer = self.sites[1]
        ns(site(0), 'ip', 'route', 'add', peer['block'], 'dev', 'cf0', 'metric', '0')
        try:
            def shadowed():
                assert peer['native'] in best_nexthops(site(0), peer['block'])
                assert fib_dev(site(0), peer['clientLan']) == 'cf0'
                before = transfer(site(0), 'cf0')
                assert ping(client(0), peer['clientLan'])
                assert transfer(site(0), 'cf0') > before
            eventually(shadowed, 10)
        finally:
            ns(site(0), 'ip', 'route', 'del', peer['block'], 'dev', 'cf0', 'metric', '0')
        ns(site(0), 'vtysh', '--vty_socket', str(ROOT/site(0)), '-d', 'bgpd', '-c', 'clear bgp * soft in')
        eventually(lambda: self.all_paths() or True)


def main():
    assert sys.platform == 'linux' and os.geteuid() == 0
    assert Path('/.dockerenv').exists(), 'lab is container-only'
    # A fresh --network none namespace holds lo, plus the per-namespace fallback tunnel devices
    # that some kernels (Docker Desktop) create when tunnel modules are loaded. Those must be down
    # and unaddressed; anything else means the container is attached to a real network.
    fallback = {'tunl0', 'gre0', 'gretap0', 'erspan0', 'ip_vti0', 'ip6_vti0', 'sit0', 'ip6tnl0', 'ip6gre0'}
    links = json.loads(command('ip', '-j', 'addr', 'show').stdout)
    for l in links:
        if l['ifname'] == 'lo':
            continue
        assert l['ifname'] in fallback and 'UP' not in l.get('flags', []) and not l.get('addr_info'), 'lab requires a fresh --network none container: '+l['ifname']
    bundle = json.loads((RESULTS/'input.json').read_text())
    lab = Lab(bundle)
    REPORT['planHash'] = bundle['plan']['hash']
    REPORT['gatewayHashes'] = {g['routerId']: g['hash'] for g in bundle['plan']['gateways']}
    REPORT['runtimeTransforms'] = ['ephemeral keys replace placeholder public keys', 'Address/Table/MTU applied with ip(8) instead of wg-quick',
                                   'external backbone simulated by one WireGuard interface', 'lab-only BGP timers', 'cluster speaker simulated by FRR']
    record('FRR parser accepts every planned gateway configuration', lab.syntax)
    record('namespaces, per-peer native tunnels, simulated external backbone, FRR and cluster speaker', lab.setup)
    record('every planned native tunnel and the external backbone carry packets', lambda: eventually(lambda: lab.tunnels() or True, 30))
    record('every gateway establishes its native, external and cluster sessions', lambda: eventually(lab.sessions))
    record('all twelve site pairs use their own native tunnel (BGP, FIB, bytes, packets)', lambda: eventually(lambda: lab.all_paths() or True))
    record('cluster VIP and Pod prefix propagate; infrastructure and Service aggregate are refused', lambda: eventually(lambda: lab.cluster_routes() or True))
    record('one native link down moves only that site pair to the external backbone', lab.link_failure)
    record('that link recovering returns the pair to native', lab.link_recovery)
    record('silent packet loss on one native link (interfaces up) is detected by BGP and fails over', lab.silent_failure)
    record('repairing the silent loss returns the pair to native', lab.silent_recovery)
    record('all native links down moves every pair to the external backbone', lab.full_failure)
    record('native recovery returns every pair to native', lab.full_recovery)
    record('management, Service aggregate and tunnel pool cannot leak through export filters', lab.leakage)
    record('a metric-0 kernel route shadows the BGP selection', lab.static_shadow)
    REPORT['passed'] = True


try:
    main()
except Exception as error:
    REPORT['passed'] = False
    REPORT['failureType'] = type(error).__name__
    if isinstance(error, subprocess.CalledProcessError):
        REPORT['failure'] = {'command': [a for a in error.cmd if 'PrivateKey' not in a], 'stderr': error.stderr[-4000:]}
    else:
        REPORT['failure'] = str(error)[:4000]
finally:
    if not REPORT.get('passed'):
        REPORT['diagnostics'] = {}
        for name in [p.name for p in ROOT.iterdir() if p.is_dir()]:
            try:
                REPORT['diagnostics'][name] = {'bgp': vty(name, 'show bgp ipv4 unicast summary json'),
                                               'fib': json.loads(ns(name, 'ip', '-j', 'route', 'show').stdout)}
            except (subprocess.SubprocessError, ValueError):
                pass
        try:
            # Separate "tunnel carries packets" from "BGP will not try the session".
            bundle = json.loads((RESULTS/'input.json').read_text())
            peer = bundle['sites'][1]
            REPORT['diagnostics']['site0-probe'] = {
                'pingNativePeer': ping('site0', peer['native']), 'pingExternalPeer': ping('site0', peer['external']),
                'neighbor': vty('site0', f'show bgp neighbors {peer["native"]}')[-2500:],
                # Public fields only. Never `dump` or `private-key`: those print key material.
                'wg': {n: {f: ns(n, 'wg', 'show', 'all', f).stdout for f in ('listen-port', 'endpoints', 'latest-handshakes', 'transfer')}
                       for n in ('site0', 'site1')},
                'routes': {n: ns(n, 'ip', 'route', 'show').stdout for n in ('site0', 'site1')},
                'routeGet': {'site0': ns('site0', 'ip', 'route', 'get', peer['native'], check=False).stdout,
                             'site1': ns('site1', 'ip', 'route', 'get', bundle['sites'][0]['native'], check=False).stdout},
                'linkStats': {n: ns(n, 'ip', '-s', 'link', 'show', check=False).stdout for n in ('site0', 'site1')},
                'rpFilter': {n: ns(n, 'sh', '-c', 'grep . /proc/sys/net/ipv4/conf/*/rp_filter', check=False).stdout for n in ('site0', 'site1')},
                'pingVerbose': ns('site0', 'ping', '-n', '-c', '2', '-W', '2', peer['native'], check=False, timeout=8).stdout}
        except (subprocess.SubprocessError, ValueError, OSError, KeyError):
            pass
        REPORT['daemonLogs'] = {str(log.relative_to(ROOT)): log.read_text()[-3000:] for _, log in PROCESSES if log.exists()}
    for proc, _ in reversed(PROCESSES):
        proc.terminate()
    (RESULTS/'report.json').write_text(json.dumps(REPORT, indent=2)+'\n')
    print(json.dumps({k: v for k, v in REPORT.items() if k not in ('diagnostics', 'daemonLogs')}, indent=2))
sys.exit(0 if REPORT.get('passed') else 1)
