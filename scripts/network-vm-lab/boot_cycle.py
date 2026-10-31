#!/usr/bin/env python3
"""Observe/reboot only the explicitly marked local disposable gateway; no profile apply.

Requires a prepared lab root, exact source checkout and a production-Agent transaction.
This primitive is not a claim that the full thirteen-scenario matrix passed.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import signal
import subprocess
import time
import uuid


# A graceful reboot waits for the Agent to stop: up to its TimeoutStopSec (300 s in
# packaging/systemd/heliopause-agent-network.conf), then SIGKILL, then the boot (51-132 s measured).
# The old 240 s bound ended every graceful case whose Agent thread was held at a boundary before
# the reboot happened (lab C, 2026-10-31). @see test_the_reboot_wait_outlasts_the_agent_stop_timeout
AGENT_STOP_TIMEOUT_SECONDS=300
REBOOT_WAIT_SECONDS=AGENT_STOP_TIMEOUT_SECONDS+240


def run(argv, data=None, timeout=30):
    return subprocess.run(argv,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=True).stdout


def monitor_argv(nonce, identity, routes):
    """Every route of the transaction: the monitor picks the probe pair the way the verifier does.
    Passing only the first route failed on the primary set, whose first route is the peer's tunnel
    address and has no pair (lab C, 2026-10-31)."""
    return ['/usr/bin/python3','/source/scripts/network-vm-lab/monitor.py','--nonce',nonce,'--id',identity,*[arg for route in routes for arg in ('--route',route)]]


class Lab:
    def __init__(self, root, ssh_ports=None):
        self.root=root.resolve();self.manifest=json.loads((self.root/'environment.json').read_text())
        self.nonce=self.manifest['labNonce']
        self.ssh_ports={'gateway':22220,'peer':22221} if ssh_ports is None else dict(ssh_ports)
        if set(self.ssh_ports)!={'gateway','peer'} or any(type(port)is not int or not 1<=port<=65535 for port in self.ssh_ports.values()) or len(set(self.ssh_ports.values()))!=2:
            raise ValueError('two distinct valid SSH ports required')
    def ssh(self, role, *args, data=None, timeout=30):
        return run(['ssh','-i',str(self.root/'lab-key'),'-o','BatchMode=yes','-o','UserKnownHostsFile='+str(self.root/'known_hosts'),'-o','ConnectTimeout=3','-p',str(self.ssh_ports[role]),'lab@127.0.0.1',shlex.join(args)],data,timeout)
    def guard(self, role):
        code="import json,os,stat;from pathlib import Path;p=Path('/etc/heliopause-disposable-lab');s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600;print(p.read_text())"
        marker=json.loads(self.ssh(role,'sudo','python3','-c',code))
        if marker!={'role':role,'nonce':self.nonce}:raise ValueError('guest lab identity mismatch')
    def boot(self, role):
        return self.ssh(role,'cat','/proc/sys/kernel/random/boot_id').decode().strip()
    def evidence(self):
        code='''import json,hashlib,os,pathlib,subprocess,time
r=lambda a:subprocess.run(a,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
p=pathlib.Path('/var/lib/heliopause/network-executor/transactions.json');d=json.loads(p.read_text())
def optional(name):
 p=pathlib.Path(name)
 try:
  raw=p.read_bytes()
  if len(raw)>1024*1024:return {'error':'evidence-size-bound'}
  return json.loads(raw)
 except FileNotFoundError:return None
 except (ValueError,OSError):return {'error':'evidence-unreadable'}
profiles=[]
for row in d['transactions'].values():
 u=row['authorization']['operation'].get('profileUuid')
 if not u:continue
 p=pathlib.Path('/etc/NetworkManager/system-connections/heliopause-'+u+'.nmconnection')
 try:
  s=p.lstat();profiles.append({'uuid':u,'mode':s.st_mode,'uid':s.st_uid,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
 except FileNotFoundError:profiles.append({'uuid':u,'missing':True})
def listing(name):
 # Names, types and link targets only; never contents. NM leaves `<uuid>.nmmeta -> /dev/null`
 # tombstones here, and a rolled-back case must not leave one for its own profile.
 out=[]
 try:entries=sorted(os.scandir(name),key=lambda e:e.name)
 except FileNotFoundError:return None
 for e in entries[:256]:
  kind='symlink' if e.is_symlink() else 'dir' if e.is_dir(follow_symlinks=False) else 'file'
  out.append({'name':e.name,'type':kind,'target':os.readlink(e.path) if kind=='symlink' else None})
 return out
nm_profiles=r(['nmcli','-t','-f','UUID','connection','show'])
if nm_profiles.returncode:raise RuntimeError('NM inventory unavailable')
boot_time=next(int(line.split()[1]) for line in pathlib.Path('/proc/stat').read_text().splitlines() if line.startswith('btime '))
unit=r(['systemctl','cat','heliopause-agent.service']).stdout
# How the previous boot's Agent stopped: a clean exit or systemd's SIGKILL at TimeoutStopSec.
stop_words=('Stopping','Stopped','Deactivated','timed out','Killing','SIGKILL','Failed with','] stopped')
previous=subprocess.run(['journalctl','-b','-1','--no-pager','-o','short-unix','-u','heliopause-agent.service'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
print(json.dumps({'at':time.time(),'bootId':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
'bootTime':boot_time,
'agentUnit':{'sha256':hashlib.sha256(unit).hexdigest(),'text':unit.decode(errors='replace')[:65536]},
'previousBootAgentStop':[line for line in previous.stdout.decode(errors='replace').splitlines() if any(w in line for w in stop_words)][-40:] if previous.returncode==0 else None,
'journal':d,'profiles':profiles,
'lifecycle':optional('/var/lib/heliopause-agent/lifecycle-status.json'),
'firewall':optional('/var/lib/heliopause-agent/state.json'),
'acknowledgements':optional('/var/lib/heliopause/network-executor/terminal-acks.json'),
'delivery':optional('/var/lib/heliopause/network-executor/terminal-delivery-status.json'),
'kernel':r(['uname','-r']).stdout.decode().strip(),
'packages':r(['rpm','-q','NetworkManager','NetworkManager-libnm','systemd','python3','iproute','wireguard-tools','nftables']).stdout.decode().splitlines(),
'nmProfiles':nm_profiles.stdout.decode().splitlines(),
'nmDirectories':{d:listing(d) for d in ['/etc/NetworkManager/system-connections','/run/NetworkManager/system-connections']},
'nmDevices':r(['nmcli','-t','-f','UUID,TYPE,DEVICE','connection','show','--active']).stdout.decode().splitlines(),
'service':r(['systemctl','show','heliopause-agent.service','-p','MainPID','-p','ActiveState','-p','SubState','-p','ExecStart','-p','UnitFileState','-p','After','-p','CapabilityBoundingSet','-p','ReadWritePaths']).stdout.decode(),
'links':json.loads(r(['ip','-j','-d','link','show']).stdout),
'addresses':json.loads(r(['ip','-j','address','show']).stdout),
'routes':json.loads(r(['ip','-j','-4','route','show','table','all']).stdout)}))
'''
        return json.loads(self.ssh('gateway','sudo','python3','-',data=code.encode(),timeout=40))
    def manager_evidence(self):
        code="import json;from pathlib import Path;p=Path('/var/lib/heliopause-vm-lab/registry.json');raw=p.read_bytes();assert len(raw)<=8*1024*1024;print(json.dumps(json.loads(raw)['execution']))"
        return json.loads(self.ssh('peer','sudo','python3','-c',code))

    def monitor_start(self, routes):
        identity=uuid.uuid4().hex
        unit='heliopause-vm-observer-'+identity
        self.ssh('peer','sudo','systemd-run','--unit='+unit,'--collect','--property=KillMode=mixed',*monitor_argv(self.nonce,identity,routes))
        end=time.monotonic()+30
        while time.monotonic()<end:
            try:
                ready=json.loads(self.ssh('peer','sudo','cat','/var/lib/heliopause-vm-lab/observations/'+identity+'.ready'))
                return identity,unit,ready
            except subprocess.CalledProcessError:time.sleep(.5)
        self.ssh('peer','sudo','systemctl','stop',unit)
        raise TimeoutError('independent monitor did not become ready')
    def peer_clock(self):
        return json.loads(self.ssh('peer','python3','-c',"import json,time;from pathlib import Path;print(json.dumps({'at':time.time(),'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}))"))
    def monitor_read(self, identity):
        raw=self.ssh('peer','sudo','head','-c','524288','/var/lib/heliopause-vm-lab/observations/'+identity+'.jsonl')
        if len(raw)>=524288:raise ValueError('packet timeline exceeds evidence bound')
        return [json.loads(line) for line in raw.splitlines()]
    def monitor_stop(self, identity, unit, recovery_at=None):
        if recovery_at is not None:
            end=time.monotonic()+30
            while time.monotonic()<end:
                records=self.monitor_read(identity)
                if sum(row['at']>=recovery_at for row in records)>=3:break
                time.sleep(.25)
        self.ssh('peer','sudo','systemctl','stop',unit)
        return {'samples':self.monitor_read(identity),'stopped':self.peer_clock()}

    def power_cut(self):
        pid=int((self.root/'gateway-qemu.pid').read_text())
        actual=Path('/proc')/str(pid)/'cmdline'
        argv=actual.read_bytes().split(b'\0')
        expected=json.loads((self.root/'gateway-qemu-command.json').read_text())
        # Exact process argv and dedicated disk, never a discovered/foreign hypervisor.
        if [v.decode() for v in argv if v]!=expected:raise ValueError('QEMU process ownership mismatch')
        if 'file='+str(self.root/'gateway.qcow2')+',if=virtio,format=qcow2' not in expected:raise ValueError('guest disk mismatch')
        os.kill(pid,signal.SIGKILL)
        end=time.monotonic()+10
        while actual.exists() and time.monotonic()<end:
            if (Path('/proc')/str(pid)/'stat').read_text().split()[2]=='Z':break
            time.sleep(.1)
        env=dict(os.environ);env['LD_LIBRARY_PATH']=str(Path(expected[0]).parents[1]/'lib/x86_64-linux-gnu')
        subprocess.run(expected,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True)


SIGNED_OBSERVATION_CHECK='''import json,os,sys,tempfile,time
sys.path.insert(0,'/opt/heliopause/agent')
import network_executor as n
from pathlib import Path
transaction=sys.argv[1];envelope=json.load(sys.stdin)
journal=json.loads(Path('/var/lib/heliopause/network-executor/transactions.json').read_text())
row=journal['transactions'][transaction]
with tempfile.TemporaryDirectory() as state:
 value=n.verify(envelope,'heliopause-network-boot-observation-v1','/etc/heliopause/trust/verifier',n.crypto_helpers(state))
if set(value)!={'authorizationHash','bootId','observedAt','checks'}:raise ValueError('signed observation fields')
if value['authorizationHash']!=n.digest(row['authorization']):raise ValueError('signed observation names another authorization')
if value['bootId']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip():raise ValueError('signed observation is from another boot')
if not 0<=time.time()*1000-value['observedAt']<=30000:raise ValueError('signed observation is stale')
print(json.dumps(value))
'''


def rolled_back_at(row):
    history=row.get('history') or []
    return history[-1].get('at') if row['state']=='rolled-back' and history and history[-1].get('state')=='rolled-back' else None


def recovery_complete(journal, transaction, boot, expected, boot_started=None, stopped_after=None):
    """`boot_started` is the gateway boot's start (`btime`, seconds). `rolled-back` must be the new
    boot's recovery, and `rolled-back-on-stop` the old boot's own shutdown after `stopped_after`
    (seconds, the last pre-reboot snapshot); state alone does not tell them apart (2026-10-31 review)."""
    target=journal['transactions'][transaction];restore=target.get('bootRestore',{})
    if expected=='restored':
        complete=target['state']=='confirmed' and restore.get('bootId')==boot and restore.get('state')=='restored'
    elif expected=='rolled-back':
        at=rolled_back_at(target)
        complete=at is not None and boot_started is not None and at>=boot_started*1000
    elif expected=='rolled-back-on-stop':
        at=rolled_back_at(target)
        complete=at is not None and None not in (boot_started,stopped_after) and stopped_after*1000<=at<boot_started*1000
    elif expected=='degraded-unchanged':
        complete=target['state']=='confirmed' and restore.get('bootId')==boot and restore.get('state')=='degraded' and restore.get('recovery') in {'not-started','rolled-back'}
    elif expected=='rollback-failed':complete=target['state']=='rollback-failed'
    elif expected=='inactive':complete=target['state']=='confirmed' and restore.get('bootId')!=boot
    else:return False
    return complete and not any((row['state'] not in {'confirmed','rolled-back','cancelled-before-accept'} or row.get('bootRestore',{}).get('state')=='attempting' or row.get('bootRestore',{}).get('recovery')=='rollback-failed') and not (identity==transaction and expected=='rollback-failed') for identity,row in journal['transactions'].items())


def stopped_cleanly(lines):
    """The previous boot's last Agent stop exited by itself. systemd logs `Deactivated successfully`
    only for that; a stop that ends in SIGKILL at TimeoutStopSec logs `Failed with result 'timeout'`."""
    stops=[i for i,line in enumerate(lines or []) if 'Stopping heliopause-agent' in line]
    return bool(stops) and any('Deactivated successfully' in line for line in lines[stops[-1]:])


def removed_profile(after, transaction):
    op=after['journal']['transactions'][transaction]['authorization']['operation'];dev=op['interfaceName']
    current=next(row for row in after['profiles'] if row['uuid']==op['profileUuid'])
    leftovers=[entry for entries in (after.get('nmDirectories') or {}).values() for entry in (entries or []) if op['profileUuid'] in entry['name']]
    return not leftovers and current.get('missing') is True and not any(row['ifname']==dev for row in after['links']) and not any(row.get('dev')==dev for row in after['routes']) and isinstance(after.get('nmProfiles'),list) and op['profileUuid'] not in after['nmProfiles'] and not any(line.startswith(op['profileUuid']+':') for line in after.get('nmDevices',[]))


def rollback_progress(before, after, transaction):
    status=after.get('lifecycle') or {}
    service=dict(line.split('=',1) for line in after['service'].splitlines() if '=' in line)
    row=after['journal']['transactions'][transaction];old=before['journal']['transactions'][transaction]
    return service.get('ActiveState')=='active' and service.get('SubState')=='running' and service.get('MainPID')==str(status.get('agentPid')) and 0<=after['at']-status.get('reportedAt',0)<=10 and bool(row.get('history')) and row['history'][-1].get('state')=='rollback-failed' and row['history'][-1]!=old['history'][-1]


def timeline_valid(records, peer_boot, request_at, recovered_at, stopped):
    if len(records)<3 or stopped['bootId']!=peer_boot:return False
    required={'at','peerBootId','management','forward','reverse'}
    if any(set(row)!=required or row['peerBootId']!=peer_boot or type(row['at']) not in {int,float} or not math.isfinite(row['at']) or any(type(row[key]) is not bool for key in ['management','forward','reverse']) for row in records):return False
    times=[row['at'] for row in records]
    return times[0]<=request_at and len([value for value in times if value>=recovered_at])>=3 and all(0<b-a<=10 for a,b in zip(times,times[1:])) and 0<=stopped['at']-times[-1]<=10 and stopped['at']-times[0]<900


def service_inactive(service):
    values=dict(line.split('=',1) for line in service.splitlines() if '=' in line)
    return values.get('MainPID')=='0' and values.get('ActiveState') in {'inactive','failed'} and values.get('SubState') in {'dead','failed'}


def inactive_preserved(before, after, transaction):
    op=before['journal']['transactions'][transaction]['authorization']['operation'];dev=op['interfaceName']
    original=next(row for row in before['profiles'] if row['uuid']==op['profileUuid'])
    current=next(row for row in after['profiles'] if row['uuid']==op['profileUuid'])
    return original==current and not any(row['ifname']==dev for row in after['links']) and not any(row.get('dev')==dev for row in after['routes'])


def fresh_packets(probe, boot, now):
    checks=probe['checks'];required={'interface','address','route','fib','handshake','protected','management','forward','reverse'}
    return set(checks)==required and all(v is True for v in checks.values()) and probe['gateway']['bootId']==boot and 0<=now-probe['observedAt']<=10000


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--mode',choices=['graceful','power-cut'],required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--require-confirmed-forwarding',action='store_true');parser.add_argument('--transaction',required=True);parser.add_argument('--expected',choices=['restored','rolled-back','rolled-back-on-stop','degraded-unchanged','rollback-failed','inactive'],required=True);args=parser.parse_args()
    source=Path(__file__).resolve().parents[2]
    if run(['git','-C',str(source),'status','--porcelain']).strip():raise ValueError('clean committed source required for final boot evidence')
    commit=run(['git','-C',str(source),'rev-parse','HEAD']).decode().strip()
    package=json.loads((source/'package.json').read_text())
    agent={Path(name).name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in package['files'] if name.startswith('agent/') and name.endswith('.py')}
    tracked=run(['git','-C',str(source),'ls-files']).decode().splitlines()
    # The peer's monitor imports /source/agent; the gateway runs fault_entry.py and faults.py from
    # /source. Neither was hashed before (2026-10-30 review, MINOR).
    peer={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in tracked if name.startswith(('src/','agent/','scripts/network-transaction-lab/','scripts/network-vm-lab/')) and name.endswith(('.ts','.py'))}
    gateway_lab={name:sha for name,sha in peer.items() if name.startswith('scripts/network-vm-lab/') and name.endswith('.py')}

    lab=Lab(args.root)
    for role in ['gateway','peer']:lab.guard(role)
    for role,base,files in [('gateway','/opt/heliopause/agent',agent),('gateway','/source',gateway_lab),('peer','/source',peer)]:
        code='import json,sys,hashlib;from pathlib import Path;v=json.load(sys.stdin);assert all(hashlib.sha256((Path(v["base"])/name).read_bytes()).hexdigest()==sha for name,sha in v["files"].items())'
        lab.ssh(role,'sudo','python3','-c',code,data=json.dumps({'base':base,'files':files}).encode())

    report={'sourceCommit':commit,'imageSha256':lab.manifest['imageSha256'],'mode':args.mode,'transaction':args.transaction,'expected':args.expected,'passed':False,'before':lab.evidence(),'peerBootBefore':lab.boot('peer'),'managerBefore':lab.manager_evidence()}
    target=report['before']['journal']['transactions'][args.transaction]
    report['agentUnitBefore']=report['before']['agentUnit']
    allowed={'confirmed'} if args.expected in {'restored','degraded-unchanged','inactive'} else {'prepared','applying','awaiting-verification','awaiting-confirm','rolling-back','rollback-failed'}
    if target['state'] not in allowed:raise ValueError('scenario pre-reboot transaction state mismatch')
    if args.output.exists():raise ValueError('existing evidence file refused')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    # Probe this transaction's own path (probe_pairs.py), not the primary pair.
    monitor_id,monitor_unit,ready=lab.monitor_start(target['authorization']['operation']['routes'])
    if ready['peerBootId']!=report['peerBootBefore']:raise ValueError('peer monitor boot mismatch')
    request_clock=lab.peer_clock()
    if request_clock['bootId']!=report['peerBootBefore']:raise ValueError('monitor peer changed boot')
    report['requestPeerAt']=request_clock['at']
    started=time.monotonic();report['requestAt']=time.time()
    try:
        if args.mode=='graceful':
            try:lab.ssh('gateway','sudo','systemctl','reboot')
            except subprocess.CalledProcessError as error:
                # sshd may exit before returning systemctl's successful response.
                # Only an independently observed changed boot ID proves reboot below.
                if error.returncode!=255:raise
        else:lab.power_cut()
        end=time.monotonic()+REBOOT_WAIT_SECONDS
        while time.monotonic()<end:
            try:
                boot=lab.boot('gateway')
                if boot!=report['before']['bootId']:break
            except (subprocess.SubprocessError,OSError):pass
            time.sleep(1)
        else:raise TimeoutError('changed actual guest boot ID not observed')
        report['sshRecoveredAt']=time.time();report['elapsedSeconds']=time.monotonic()-started
        # Wait for production worker, not merely sshd, to publish restored/degraded state.
        end=time.monotonic()+240
        while True:
            report['after']=lab.evidence()
            if report['after']['bootId']!=boot:raise ValueError('unexpected additional gateway reboot')
            complete=recovery_complete(report['after']['journal'],args.transaction,boot,args.expected,report['after']['bootTime'],report['before']['at'])
            if args.expected=='rolled-back-on-stop':complete=complete and stopped_cleanly(report['after']['previousBootAgentStop'])
            if args.expected=='inactive':complete=complete and service_inactive(report['after']['service'])
            if args.expected=='rollback-failed':
                complete=complete and rollback_progress(report['before'],report['after'],args.transaction)
            if complete:break
            if time.monotonic()>=end:raise TimeoutError('Agent boot recovery not terminal')
            time.sleep(1)
        if args.expected in {'rolled-back','rolled-back-on-stop'} and not removed_profile(report['after'],args.transaction):raise ValueError('rolled-back objects remain')
        if args.expected in {'degraded-unchanged','rollback-failed','inactive'} and not inactive_preserved(report['before'],report['after'],args.transaction):raise ValueError('negative-case profile/kernel preservation failed')
        report['recoveredPeerAt']=lab.peer_clock()['at']
        report['peerBootAfter']=lab.boot('peer')
        if report['peerBootBefore']!=report['peerBootAfter']:raise ValueError('independent peer rebooted')
        if args.require_confirmed_forwarding:
            report['connectivityAttempts']=[]
            for attempt in range(3):
                try:
                    lab.ssh('peer','sudo','/opt/node/bin/node','/source/scripts/network-vm-lab/verify.ts','observe',args.transaction,timeout=60)
                    probe=json.loads(lab.ssh('peer','sudo','cat','/var/lib/heliopause-vm-lab/current-probes.json'))
                    report['connectivityAttempts'].append(probe)
                    if probe.get('transactionId')==args.transaction and fresh_packets(probe,boot,time.time()*1000):
                        # The contract asks for a new independently *signed* observation, not the
                        # unsigned probe file. The gateway checks it with the Agent's own verifier
                        # trust: signature, this transaction's authorization hash, this boot, fresh.
                        envelope=json.loads(lab.ssh('peer','sudo','cat','/var/lib/heliopause-vm-lab/boot-observation.json'))
                        signed=json.loads(lab.ssh('gateway','sudo','python3','-c',SIGNED_OBSERVATION_CHECK,args.transaction,data=json.dumps(envelope).encode()))
                        if signed['checks']!=probe['checks']:raise ValueError('signed observation checks differ from the probe')
                        report['currentProbes']=probe
                        report['signedObservation']={'envelope':envelope,'payload':signed}
                        break
                except subprocess.CalledProcessError as error:
                    # Preserve a fixed diagnostic code; never export arbitrary stderr/key material.
                    text=(error.stderr or b'').decode(errors='replace')
                    known=['stale collector result','collector span exceeds proof freshness','TimeoutError','probe command failed','authorization does not name the case transaction','no lab probe pair','signed observation']
                    report['connectivityAttempts'].append({'error':next((label for label in known if label in text),'independent-command-failed'),'stderrSha256':hashlib.sha256(error.stderr or b'').hexdigest()})
            else:raise ValueError('fresh independent connectivity failed')
        report['passed']=True
    except Exception as error:
        report['error']=type(error).__name__+': '+str(error)[:400]
        raise
    finally:
        try:
            timeline=lab.monitor_stop(monitor_id,monitor_unit,report.get('recoveredPeerAt'))
            report['packetTimeline']=timeline['samples']
            report['monitorStopped']=timeline['stopped']
            report['managerAfter']=lab.manager_evidence()
            if not timeline_valid(report['packetTimeline'],report['peerBootBefore'],report['requestPeerAt'],report.get('recoveredPeerAt',float('inf')),timeline['stopped']):raise ValueError('independent timeline coverage unavailable')
            if args.expected in {'degraded-unchanged','rollback-failed','inactive'} and not all(row['management'] is True and row['forward'] is False and row['reverse'] is False for row in report['packetTimeline'][-3:]):raise ValueError('negative-case independent packet result mismatch')
        except Exception:
            report['passed']=False;report['monitorError']='independent-monitor-unavailable'
        body=(json.dumps(report,indent=2)+'\n').encode()
        fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
        # Written once, beside the report, so a later copy can be checked against the original.
        fd=os.open(str(args.output)+'.sha256',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream:stream.write(hashlib.sha256(body).hexdigest()+'  '+args.output.name+'\n')
    if not report['passed']:raise RuntimeError('boot evidence did not satisfy all requirements')


if __name__=='__main__':main()
