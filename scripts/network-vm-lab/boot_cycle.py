#!/usr/bin/env python3
"""Observe/reboot only the explicitly marked local disposable gateway; no profile apply.

Requires a prepared lab root, exact source checkout and a production-Agent transaction.
This primitive is not a claim that the full thirteen-scenario matrix passed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import time
import uuid


def run(argv, data=None, timeout=30):
    return subprocess.run(argv,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=True).stdout


class Lab:
    def __init__(self, root):
        self.root=root.resolve();self.manifest=json.loads((self.root/'environment.json').read_text())
        self.nonce=self.manifest['labNonce']
    def ssh(self, role, *args, data=None, timeout=30):
        return run(['ssh','-i',str(self.root/'lab-key'),'-o','BatchMode=yes','-o','UserKnownHostsFile='+str(self.root/'known_hosts'),'-o','ConnectTimeout=3','-p',str(22220 if role=='gateway' else 22221),'lab@127.0.0.1',shlex.join(args)],data,timeout)
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
print(json.dumps({'at':time.time(),'bootId':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
'journal':d,'profiles':profiles,
'lifecycle':optional('/var/lib/heliopause-agent/lifecycle-status.json'),
'firewall':optional('/var/lib/heliopause-agent/state.json'),
'acknowledgements':optional('/var/lib/heliopause/network-executor/terminal-acks.json'),
'delivery':optional('/var/lib/heliopause/network-executor/terminal-delivery-status.json'),
'kernel':r(['uname','-r']).stdout.decode().strip(),
'packages':r(['rpm','-q','NetworkManager','NetworkManager-libnm','systemd','python3','iproute','wireguard-tools','nftables']).stdout.decode().splitlines(),
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

    def monitor_start(self):
        identity=uuid.uuid4().hex
        unit='heliopause-vm-observer-'+identity
        self.ssh('peer','sudo','systemd-run','--unit='+unit,'--collect','/usr/bin/python3','/source/scripts/network-vm-lab/monitor.py','--nonce',self.nonce,'--id',identity)
        end=time.monotonic()+30
        while time.monotonic()<end:
            try:
                ready=json.loads(self.ssh('peer','sudo','cat','/var/lib/heliopause-vm-lab/observations/'+identity+'.ready'))
                return identity,unit,ready
            except subprocess.CalledProcessError:time.sleep(.5)
        self.ssh('peer','sudo','systemctl','stop',unit)
        raise TimeoutError('independent monitor did not become ready')
    def monitor_stop(self, identity, unit):
        self.ssh('peer','sudo','systemctl','stop',unit)
        raw=self.ssh('peer','sudo','head','-c','524288','/var/lib/heliopause-vm-lab/observations/'+identity+'.jsonl')
        if len(raw)>=524288:raise ValueError('packet timeline exceeds evidence bound')
        return [json.loads(line) for line in raw.splitlines()]

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


def recovery_complete(journal, transaction, boot, expected):
    target=journal['transactions'][transaction];restore=target.get('bootRestore',{})
    if expected=='restored':
        complete=target['state']=='confirmed' and restore.get('bootId')==boot and restore.get('state')=='restored'
    elif expected=='rolled-back':complete=target['state']=='rolled-back'
    elif expected=='degraded-unchanged':
        complete=target['state']=='confirmed' and restore.get('bootId')==boot and restore.get('state')=='degraded' and restore.get('recovery') in {'not-started','rolled-back'}
    elif expected=='rollback-failed':complete=target['state']=='rollback-failed'
    elif expected=='inactive':complete=target['state']=='confirmed' and restore.get('bootId')!=boot
    else:return False
    return complete and not any((row['state'] not in {'confirmed','rolled-back','cancelled-before-accept'} or row.get('bootRestore',{}).get('state')=='attempting' or row.get('bootRestore',{}).get('recovery')=='rollback-failed') and not (identity==transaction and expected=='rollback-failed') for identity,row in journal['transactions'].items())


def removed_profile(after, transaction):
    op=after['journal']['transactions'][transaction]['authorization']['operation'];dev=op['interfaceName']
    current=next(row for row in after['profiles'] if row['uuid']==op['profileUuid'])
    return current.get('missing') is True and not any(row['ifname']==dev for row in after['links']) and not any(row.get('dev')==dev for row in after['routes']) and not any(line.startswith(op['profileUuid']+':') for line in after.get('nmDevices',[]))


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
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--mode',choices=['graceful','power-cut'],required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--require-confirmed-forwarding',action='store_true');parser.add_argument('--transaction',required=True);parser.add_argument('--expected',choices=['restored','rolled-back','degraded-unchanged','rollback-failed','inactive'],required=True);args=parser.parse_args()
    source=Path(__file__).resolve().parents[2]
    if run(['git','-C',str(source),'status','--porcelain']).strip():raise ValueError('clean committed source required for final boot evidence')
    commit=run(['git','-C',str(source),'rev-parse','HEAD']).decode().strip()
    package=json.loads((source/'package.json').read_text())
    agent={Path(name).name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in package['files'] if name.startswith('agent/') and name.endswith('.py')}
    peer={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in run(['git','-C',str(source),'ls-files']).decode().splitlines() if name.startswith(('src/','scripts/network-transaction-lab/','scripts/network-vm-lab/')) and name.endswith(('.ts','.py'))}

    lab=Lab(args.root)
    for role in ['gateway','peer']:lab.guard(role)
    for role,base,files in [('gateway','/opt/heliopause/agent',agent),('peer','/source',peer)]:
        code='import json,sys,hashlib;from pathlib import Path;v=json.load(sys.stdin);assert all(hashlib.sha256((Path(v["base"])/name).read_bytes()).hexdigest()==sha for name,sha in v["files"].items())'
        lab.ssh(role,'sudo','python3','-c',code,data=json.dumps({'base':base,'files':files}).encode())

    report={'sourceCommit':commit,'imageSha256':lab.manifest['imageSha256'],'mode':args.mode,'transaction':args.transaction,'expected':args.expected,'passed':False,'before':lab.evidence(),'peerBootBefore':lab.boot('peer'),'managerBefore':lab.manager_evidence()}
    target=report['before']['journal']['transactions'][args.transaction]
    allowed={'confirmed'} if args.expected in {'restored','degraded-unchanged','inactive'} else {'prepared','applying','awaiting-verification','awaiting-confirm','rolling-back','rollback-failed'}
    if target['state'] not in allowed:raise ValueError('scenario pre-reboot transaction state mismatch')
    if args.output.exists():raise ValueError('existing evidence file refused')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    monitor_id,monitor_unit,ready=lab.monitor_start()
    if ready['peerBootId']!=report['peerBootBefore']:raise ValueError('peer monitor boot mismatch')
    started=time.monotonic();report['requestAt']=time.time()
    try:
        if args.mode=='graceful':
            try:lab.ssh('gateway','sudo','systemctl','reboot')
            except subprocess.CalledProcessError as error:
                # sshd may exit before returning systemctl's successful response.
                # Only an independently observed changed boot ID proves reboot below.
                if error.returncode!=255:raise
        else:lab.power_cut()
        end=time.monotonic()+240
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
            complete=recovery_complete(report['after']['journal'],args.transaction,boot,args.expected)
            if args.expected=='inactive':complete=complete and service_inactive(report['after']['service'])
            if args.expected=='rollback-failed':
                status=report['after'].get('lifecycle') or {}
                complete=complete and status.get('agentPid') and 0<=report['after']['at']-status.get('reportedAt',0)<=10
            if complete:break
            if time.monotonic()>=end:raise TimeoutError('Agent boot recovery not terminal')
            time.sleep(1)
        if args.expected=='rolled-back' and not removed_profile(report['after'],args.transaction):raise ValueError('rolled-back objects remain')
        if args.expected in {'degraded-unchanged','rollback-failed','inactive'} and not inactive_preserved(report['before'],report['after'],args.transaction):raise ValueError('negative-case profile/kernel preservation failed')
        report['peerBootAfter']=lab.boot('peer')
        if report['peerBootBefore']!=report['peerBootAfter']:raise ValueError('independent peer rebooted')
        if args.require_confirmed_forwarding:
            report['connectivityAttempts']=[]
            for attempt in range(3):
                try:
                    lab.ssh('peer','sudo','/opt/node/bin/node','/source/scripts/network-vm-lab/verify.ts','observe',timeout=60)
                    probe=json.loads(lab.ssh('peer','sudo','cat','/var/lib/heliopause-vm-lab/current-probes.json'))
                    report['connectivityAttempts'].append(probe)
                    if probe.get('transactionId')==args.transaction and fresh_packets(probe,boot,time.time()*1000):
                        report['currentProbes']=probe
                        break
                except subprocess.CalledProcessError as error:
                    # Preserve a fixed diagnostic code; never export arbitrary stderr/key material.
                    text=(error.stderr or b'').decode(errors='replace')
                    known=['stale collector result','collector span exceeds proof freshness','TimeoutError','probe command failed']
                    report['connectivityAttempts'].append({'error':next((label for label in known if label in text),'independent-command-failed'),'stderrSha256':hashlib.sha256(error.stderr or b'').hexdigest()})
            else:raise ValueError('fresh independent connectivity failed')
        report['passed']=True
    except Exception as error:
        report['error']=type(error).__name__+': '+str(error)[:400]
        raise
    finally:
        try:
            report['packetTimeline']=lab.monitor_stop(monitor_id,monitor_unit)
            report['managerAfter']=lab.manager_evidence()
            if not report['packetTimeline'] or any(row['peerBootId']!=report['peerBootBefore'] for row in report['packetTimeline']):raise ValueError('independent timeline unavailable')
            if args.expected in {'degraded-unchanged','rollback-failed','inactive'} and not all(row['management'] is True and row['forward'] is False and row['reverse'] is False for row in report['packetTimeline'][-3:]):raise ValueError('negative-case independent packet result mismatch')
        except Exception:
            report['passed']=False;report['monitorError']='independent-monitor-unavailable'
        fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    if not report['passed']:raise RuntimeError('boot evidence did not satisfy all requirements')


if __name__=='__main__':main()
