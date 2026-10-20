"""Disposable namespace lab. Only synthetic compiler output is consumed; no production transport.

Each test asserts BGP selection, kernel FIB, WG byte deltas and workload packets separately.
JSON records measured durations and loss, never a promised failover time.
"""
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(tempfile.mkdtemp(prefix='hp-network-lab-'))
ROOT.chmod(0o755)
RESULTS = Path('/results')
REPORT = {'schemaVersion': 1, 'scope': 'isolated-synthetic-lab',
          'cloudflareVerified': False, 'kubernetesVerified': False,
          'checks': [], 'measurements': []}
PROCESSES = []


def command(*argv, input=None, check=True, timeout=15):
    return subprocess.run(argv, input=input, text=True, capture_output=True,
                          timeout=timeout, check=check)


def ns(i, *argv, **kwargs):
    return command('ip', 'netns', 'exec', 'site'+str(i), *argv, **kwargs)


def vty(i, cmd):
    return json.loads(ns(i, 'vtysh', '--vty_socket', str(ROOT/str(i)),
                         '-d', 'bgpd', '-c', cmd).stdout)


def record(name, fn):
    started = time.monotonic()
    fn()
    REPORT['checks'].append({'name': name, 'passed': True,
                             'durationMs': round((time.monotonic()-started)*1000, 3)})


def eventually(fn, seconds=75):
    end = time.monotonic()+seconds
    last = None
    while time.monotonic() < end:
        try:
            fn()
            return
        except (AssertionError, subprocess.SubprocessError, ValueError, KeyError) as error:
            last = str(error)
            time.sleep(0.25)
    raise AssertionError('convergence timeout: '+str(last))


def routes(i, j):
    prefix = f'192.0.2.{64*j}/27'
    data = vty(i, 'show bgp ipv4 unicast '+prefix+' json')
    return data.get('paths', [])


def selected(i, j, primary=True):
    expected = f'198.51.100.{(0 if primary else 32)+j+1}'
    best = [p for p in routes(i, j) if p.get('bestpath', {}).get('overall')]
    assert len(best) == 1, ('missing selected BGP route', i, j, best)
    assert any(n.get('ip') == expected for n in best[0].get('nexthops', [])), best
    fib = json.loads(ns(i, 'ip', '-j', 'route', 'get', f'192.0.2.{64*j+2}').stdout)
    assert fib[0].get('dev') == ('wg0' if primary else 'cf0'), fib


def transfer(i, interface):
    return sum(int(row.split()[2]) for row in ns(i, 'wg', 'show', interface, 'transfer').stdout.splitlines() if row)


def ping(i, j, offset=2):
    return command('ip', 'netns', 'exec', 'client'+str(i), 'ping', '-n', '-q',
                   '-c', '1', '-W', '1', f'192.0.2.{64*j+offset}', check=False, timeout=3).returncode == 0


def all_paths(primary=True):
    for i in range(4):
        for j in range(4):
            if i == j:
                continue
            selected(i, j, primary)
            interface = 'wg0' if primary else 'cf0'
            before = transfer(i, interface)
            for offset in [2,34,50]:
                assert ping(i, j, offset), ('workload/synthetic pod/VIP packet failed', i, j, offset)
                fib=json.loads(ns(i,'ip','-j','route','get',f'192.0.2.{64*j+offset}').stdout)
                assert fib[0].get('dev') == interface, fib
            assert transfer(i, interface) > before, ('packet did not use selected tunnel', i, j)


def sessions():
    for i in range(4):
        data = vty(i, 'show bgp ipv4 unicast summary json')
        peers = data.get('ipv4Unicast', data).get('peers', {})
        assert len(peers) == 6 and all(p.get('state') == 'Established' for p in peers.values()), peers


def syntax(bundle):
    expected = bundle['input']['frr'][0]['frrVersion']
    version = command('/usr/lib/frr/bgpd', '--version').stdout
    assert expected in version, version
    REPORT['frrVersion'] = expected
    for i, artifact in enumerate(bundle['frr']):
        path = ROOT/f'bgp{i}.conf'
        path.write_text(artifact['template'])
        result = command('/usr/lib/frr/bgpd', '-C', '-S', '-f', str(path), check=False)
        assert result.returncode == 0 and not any(x in (result.stdout+result.stderr).lower() for x in ['unknown command', 'no such command', 'error', 'failure']), result.stdout+result.stderr


def setup(bundle):
    # A namespace is mandatory. Failure is fatal rather than a skipped/pass lab.
    command('ip', 'link', 'add', 'lab-underlay', 'type', 'bridge')
    command('ip', 'link', 'set', 'lab-underlay', 'up')
    keys = [command('wg', 'genkey').stdout.strip() for _ in range(4)]
    pubs = [command('wg', 'pubkey', input=k+'\n').stdout.strip() for k in keys]
    for i in range(4):
        command('ip', 'netns', 'add', 'site'+str(i))
        command('ip', 'netns', 'add', 'client'+str(i))
        command('ip', 'link', 'add', 'edge'+str(i), 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'site'+str(i))
        command('ip', 'link', 'set', 'edge'+str(i), 'master', 'lab-underlay')
        command('ip', 'link', 'set', 'edge'+str(i), 'up')
        ns(i, 'ip', 'link', 'set', 'lo', 'up')
        ns(i, 'ip', 'addr', 'add', f'203.0.113.{i+1}/24', 'dev', 'eth0')
        ns(i, 'ip', 'link', 'set', 'eth0', 'up')
        command('ip', 'link', 'add', 'lan0', 'netns', 'site'+str(i), 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'client'+str(i))
        ns(i, 'ip', 'addr', 'add', f'192.0.2.{64*i+1}/27', 'dev', 'lan0')
        ns(i, 'ip', 'link', 'set', 'lan0', 'up')
        command('ip', 'netns', 'exec', 'client'+str(i), 'ip', 'link', 'set', 'lo', 'up')
        for args in [('addr','add',f'192.0.2.{64*i+2}/27','dev','eth0'),('link','set','eth0','up'),('route','add','default','via',f'192.0.2.{64*i+1}')]:
            command('ip', 'netns', 'exec', 'client'+str(i), 'ip', *args)
        ns(i, 'sysctl', '-w', 'net.ipv4.ip_forward=1')
        for device in ['all', 'default', 'eth0', 'lan0']:
            ns(i, 'sysctl', '-w', 'net.ipv4.conf.'+device+'.rp_filter=0')
        ns(i, 'ip', 'link', 'add', 'mgmt0', 'type', 'dummy')
        ns(i, 'ip', 'addr', 'add', f'198.51.100.{129+i}/32', 'dev', 'mgmt0')
        ns(i, 'ip', 'link', 'set', 'mgmt0', 'up')
        for interface, offset, port in [('wg0', 0, 51820), ('cf0', 32, 51821)]:
            ns(i, 'ip', 'link', 'add', interface, 'type', 'wireguard')
            template = bundle['wireguard']['interfaces'][i]['template']
            # Only secret/public-key provisioning and secondary lab address/port substitution.
            # Route policy, prefix lists and FRR output are consumed from the actual compiler.
            for j, spec in enumerate(bundle['input']['wireguard']['gateways']):
                template = template.replace(spec['publicKey'], pubs[j])
            lines = [l for l in template.splitlines() if not l.startswith(('Address =', 'Table =', 'MTU =', '#'))]
            template = '\n'.join(lines)+'\n'
            template = template.replace('[Interface]', '[Interface]\nPrivateKey = '+keys[i])
            if offset:
                template = template.replace('51820', str(port))
                for j in range(4):
                    template = template.replace(f'198.51.100.{j+1}/32', f'198.51.100.{offset+j+1}/32')
            config = ROOT/f'wg-{i}-{interface}.conf'
            config.write_text(template)
            config.chmod(0o600)
            ns(i, 'wg', 'setconf', interface, str(config))
            config.unlink()
            ns(i, 'ip', 'addr', 'add', f'198.51.100.{offset+i+1}/32', 'dev', interface)
            ns(i, 'ip', 'link', 'set', interface, 'mtu', '1420', 'up')
            ns(i, 'sysctl', '-w', f'net.ipv4.conf.{interface}.rp_filter=0')
            for j in range(4):
                if i != j:
                    ns(i, 'ip', 'route', 'add', f'198.51.100.{offset+j+1}/32', 'dev', interface)
        for prefix in [f'192.0.2.{i*64+32}/28',f'192.0.2.{i*64+50}/32']:
            ns(i,'ip','route','add',prefix,'via',f'192.0.2.{i*64+2}','dev','lan0')
        for offset in [34,50]:
            command('ip','netns','exec','client'+str(i),'ip','addr','add',f'192.0.2.{i*64+offset}/32','dev','lo')
        directory = ROOT/str(i)
        directory.mkdir(mode=0o777)
        os.chmod(directory, 0o777)
        common = ['-i', str(directory/'zebra.pid'), '-z', str(directory/'zserv.api'), '--vty_socket', str(directory)]
        start_daemon(i,'/usr/lib/frr/zebra',directory,'-f','/dev/null',*common)
        eventually(lambda: assert_socket(directory/'zserv.api'), 10)
        common[1] = str(directory/'bgpd.pid')
        start_daemon(i,'/usr/lib/frr/bgpd',directory,'-S','-f',str(ROOT/f'bgp{i}.conf'),*common)
        # Short lab timers are applied only to the lab daemon, not emitted as production defaults.
        for peer in bundle['input']['frr'][i]['peers']:
            ns(i,'vtysh','--vty_socket',str(directory),'-d','bgpd','-c','configure terminal','-c',f'router bgp {65100+i}',
               '-c',f'neighbor {peer["address"]} timers 1 3','-c',f'neighbor {peer["address"]} timers connect 1')


def start_daemon(i, executable, directory, *args):
    log = directory/(Path(executable).name+'.log')
    with log.open('w') as stream:
        proc = subprocess.Popen(['ip','netns','exec','site'+str(i),executable,*args], stdout=stream, stderr=stream)
    PROCESSES.append((proc,log))
    def ready():
        assert proc.poll() is None, log.read_text()[-4000:]
        assert (directory/(Path(executable).name+'.vty')).exists(), log.read_text()[-4000:]
    eventually(ready,20)


def assert_socket(path):
    assert path.exists(), str(path)


def failover(primary, bundle):
    started = time.monotonic()
    for i in range(4):
        ns(i, 'ip', 'link', 'set', 'wg0', 'up' if primary else 'down')
        if primary:
            # Administrative down deletes these non-persistent kernel routes. Recovery is
            # interface-up PLUS restoration of the compiler's declared host-route artifacts.
            # Do not imply that plain link-up is sufficient, or reset BGP to hide the gap.
            for route in bundle['wireguard']['interfaces'][i]['peerHostRoutes']:
                ns(i,'ip','route','replace',route['destination'],'dev','wg0')
    if primary:
        REPORT['recoveryActions']=['bring native interface up','restore compiler-declared peer host routes deleted by administrative down']
    sent = 0
    lost = 0
    last = None
    first_packet = None
    end = time.monotonic()+75
    while time.monotonic() < end:
        sent += 1
        if not ping(0, 1):
            lost += 1
        elif first_packet is None:
            first_packet = time.monotonic()
        try:
            all_paths(primary)
            REPORT['measurements'].append({'scenario': 'recovery' if primary else 'primary-failure',
                'convergenceMs': round((time.monotonic()-started)*1000, 3), 'sampledPackets': sent,
                'sampledLostPackets': lost, 'firstSuccessfulSampleMs': None if first_packet is None else round((first_packet-started)*1000, 3)})
            return
        except (AssertionError, subprocess.SubprocessError, KeyError, ValueError) as error:
            last=str(error)
            time.sleep(0.25)
    raise AssertionError('failover/recovery forwarding did not converge: '+str(last))


def management():
    for i in range(4):
        local = json.loads(ns(i, 'ip', '-j', 'addr', 'show', 'dev', 'mgmt0').stdout)
        assert local[0]['addr_info'][0]['local'] == f'198.51.100.{129+i}'
        for j in range(4):
            if i != j:
                assert not routes_for_prefix(i, f'198.51.100.{129+j}/32')
        assert not json.loads(ns(i, 'ip', '-j', 'route', 'show', 'default').stdout)


def routes_for_prefix(i, prefix):
    return vty(i, 'show bgp ipv4 unicast '+prefix+' json').get('paths', [])


def static_shadow():
    ns(0, 'ip', 'route', 'add', '192.0.2.64/27', 'dev', 'cf0', 'metric', '0')
    try:
        eventually(lambda: assert_shadow(), 10)
    finally:
        ns(0, 'ip', 'route', 'del', '192.0.2.64/27', 'dev', 'cf0', 'metric', '0')
    # An equal-prefix kernel route can hide BGP despite its primary selection.
    # Re-trigger BGP installation after removal instead of assuming Linux resurrects it.
    ns(0, 'vtysh', '--vty_socket', str(ROOT/'0'), '-d', 'bgpd', '-c', 'clear bgp * soft in')
    eventually(lambda: all_paths(True))


def assert_shadow():
    best=[p for p in routes(0,1) if p.get('bestpath',{}).get('overall')]
    assert len(best)==1 and any(n.get('ip')=='198.51.100.2' for n in best[0].get('nexthops',[])), best
    fib = json.loads(ns(0, 'ip', '-j', 'route', 'get', '192.0.2.66').stdout)
    assert fib[0]['dev'] == 'cf0', fib
    before=transfer(0,'cf0')
    assert ping(0,1)
    assert transfer(0,'cf0')>before


def leakage():
    # Deliberately try to originate management and the complete service pool. Export policy
    # must refuse them even when a valid local origin route exists in the daemon's RIB.
    ns(0,'ip','route','add','blackhole','192.0.2.48/28')
    ns(0,'vtysh','--vty_socket',str(ROOT/'0'),'-d','bgpd','-c','configure terminal','-c','router bgp 65100','-c','address-family ipv4 unicast','-c','network 198.51.100.129/32','-c','network 192.0.2.48/28')
    eventually(lambda: assert_origins())
    time.sleep(2)
    for i in range(1,4):
        assert not routes_for_prefix(i,'198.51.100.129/32')
        assert not routes_for_prefix(i,'192.0.2.48/28')


def assert_origins():
    assert routes_for_prefix(0,'198.51.100.129/32'), 'management origin was never installed; leak test did not open the path'
    assert routes_for_prefix(0,'192.0.2.48/28'), 'service aggregate origin was never installed; leak test did not open the path'


def main():
    assert sys.platform == 'linux' and os.geteuid() == 0
    assert Path('/.dockerenv').exists(), 'lab is container-only'
    bundle = json.loads((RESULTS/'input.json').read_text())
    record('FRR parser accepts exact compiled templates', lambda: syntax(bundle))
    record('isolated namespaces and compiler-fed WireGuard setup', lambda: setup(bundle))
    record('all six neighbors per site established', lambda: eventually(sessions))
    record('all twelve ordered workload paths use native WireGuard with FIB and byte evidence', lambda: eventually(lambda: all_paths(True)))
    record('primary failure uses secondary tunnel, not Cloudflare emulation', lambda: failover(False,bundle))
    record('management route preserved during outage', management)
    record('native tunnel recovery returns all paths to primary', lambda: failover(True,bundle))
    record('static kernel route shadow is detected separately from BGP selection', static_shadow)
    record('management and complete service pool cannot leak through export filters', leakage)
    record('management not advertised and default route not replaced', management)
    REPORT['passed'] = True


try:
    main()
except Exception as error:
    REPORT['passed'] = False
    # Never capture WG configuration or command inputs: they can contain ephemeral keys.
    REPORT['failureType'] = type(error).__name__
    if isinstance(error, subprocess.CalledProcessError):
        REPORT['failure'] = {'command': list(error.cmd), 'stderr': error.stderr[-4000:]}
    else:
        REPORT['failure'] = str(error)[:4000]
finally:
    if not REPORT.get('passed'):
        REPORT['diagnostics']={}
        for i in range(4):
            try:
                REPORT['diagnostics'][str(i)]={'bgp':vty(i,'show bgp ipv4 unicast summary json'), 'fib':json.loads(ns(i,'ip','-j','route','show').stdout)}
            except (subprocess.SubprocessError,ValueError):
                pass
        REPORT['daemonLogs'] = {str(log.relative_to(ROOT)): log.read_text()[-4000:] for _,log in PROCESSES if log.exists()}
    for proc,_ in reversed(PROCESSES):
        proc.terminate()
    (RESULTS/'report.json').write_text(json.dumps(REPORT, indent=2)+'\n')
    print(json.dumps(REPORT, indent=2))
    # The container dies next; no namespace deletion runs against the host.
sys.exit(0 if REPORT.get('passed') else 1)
