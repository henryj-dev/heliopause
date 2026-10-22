#!/usr/bin/env python3
"""Observe an already confirmed isolated VM for a full 24 hours. No gateway writes.

Fault/rotation exercises are separate source-bound runs. This baseline does not issue work,
recycle objects or consume ledger slots. A short sample is never a successful soak.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import time
import uuid
import sys
from concurrent.futures import ThreadPoolExecutor
from boot_cycle import Lab, run
from soak_inputs import source_modules
from soak_settlement import require_settled
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'agent'))
from network_executor import digest

HOURS = 24
INTERVAL = 60


def write(path, value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(value,stream,allow_nan=False);stream.write('\n');stream.flush();os.fsync(stream.fileno())


def assess(sample, initial, expected_modules, expected_tx):
    gateway,peer=sample['gateway'],sample['peer']
    if gateway['journalId']!=initial['gateway']['journalId'] or gateway['acceptedSequence']!=initial['gateway']['acceptedSequence'] or gateway['terminalSequence']!=initial['gateway']['terminalSequence']:
        raise ValueError('journal/replay state changed during zero-issuance baseline')
    if expected_tx not in gateway['transactions'] or gateway['transactions'][expected_tx]['state']!='confirmed' or gateway['transactions']!=initial['gateway']['transactions']:
        raise ValueError('confirmed target or transaction set changed')
    if gateway['trust']!=initial['gateway']['trust'] or gateway['journalContentHash']!=initial['gateway']['journalContentHash']:
        raise ValueError('trust or semantic journal drift')
    for name in ['journal-identity.json','terminal-results.json','terminal-acks.json']:
        if gateway['files'][name].get('missing') or gateway['files'][name]!=initial['gateway']['files'][name]:raise ValueError('identity/outbox/ack drift')
    if gateway.get('maintenanceRequired') or peer['ledger'].get('capacityHold'):raise ValueError('capacity maintenance excludes stability baseline')
    if peer['ledger']['fence'] is not None:raise ValueError('unsettled Manager fence')
    if gateway['bootId']!=initial['gateway']['bootId'] or peer['bootId']!=initial['peer']['bootId']:
        raise ValueError('unexpected reboot during baseline')
    for role in ['gateway','peer']:
        if sample[role]['deployedModules']!=expected_modules[role]:raise ValueError(role+' deployed module drift')
        if not sample[role].get('frozenInputs') or sample[role]['frozenInputs']!=initial[role].get('frozenInputs'):
            raise ValueError(role+' configuration or public trust drift')
    if gateway['targetBinding']!=peer['targetBinding'] or gateway['targetBinding']['journalId']!=gateway['journalId']:
        raise ValueError('Manager/Agent target or journal binding mismatch')
    require_settled(gateway,peer,expected_tx,digest)
    if peer['ledger']!=initial['peer']['ledger']:raise ValueError('Manager ledger drift or new fence')
    for role,key,rss_limit in [('gateway','agent',512),('gateway','courier',256),('gateway','networkManager',512),('peer','manager',768),('peer','relay',256)]:
        process=sample[role][key]
        if process['active']!='active' or not process['pid']:raise ValueError('service unavailable')
        if process['rssPages']*sample[role]['pageBytes']>rss_limit*1024*1024 or process['fdCount']>256 or process['children']>8:
            raise ValueError('process resource budget exceeded')
        if process['pid']!=initial[role][key]['pid'] or process['startTicks']!=initial[role][key]['startTicks']:
            raise ValueError('unexpected process restart during baseline')
        elapsed=sample[role]['at']-initial[role]['at']
        if elapsed>0 and (process['cpuTicks']-initial[role][key]['cpuTicks'])/sample[role]['clockTicksPerSecond']/elapsed>1.0:
            raise ValueError('process average CPU budget exceeded')
    status=gateway['lifecycle']
    if type(status.get('agentPid'))is not int or status['agentPid']!=gateway['agent']['pid']:
        raise ValueError('lifecycle process identity mismatch')
    if not 0<=gateway['at']-status.get('reportedAt',0)<=15:raise ValueError('stale lifecycle inventory')
    heartbeat=status.get('heartbeat',{});discovery=status.get('discovery',{})
    if not -1<=gateway['at']-heartbeat.get('lastSuccess',0)<=20 or heartbeat.get('lastFailure',0)>initial['gateway']['lifecycle'].get('heartbeat',{}).get('lastFailure',0):
        raise ValueError('heartbeat failure or stale success')
    if discovery.get('enabled') is not True or not -1<=gateway['at']-discovery.get('lastSuccess',0)<=360 or status.get('errors') or discovery.get('lastFailure',0)>initial['gateway']['lifecycle'].get('discovery',{}).get('lastFailure',0) or any(value is not False for value in status.get('recoveryDebt',{}).values()):
        raise ValueError('discovery failure or lifecycle errors')
    if gateway['files']['transactions.json']['bytes']>=7*1024*1024:raise ValueError('journal reserve exhausted')
    if not all(row['state'] in {'confirmed','rolled-back','cancelled-before-accept'} and
               row.get('bootRestore',{}).get('recovery')!='rollback-failed' and row.get('bootRestore',{}).get('state') not in {'attempting','degraded'} and
               (row['state']!='confirmed' or row.get('configurationMatches') is True and row.get('historicalAuthorityValid') is True) for row in gateway['transactions'].values()):
        raise ValueError('configuration mismatch or recovery debt')
    if not sample['packets'] or any(not all(row[k] is True for k in ['management','forward','reverse']) or row['peerBootId']!=peer['bootId'] for row in sample['packets']):
        raise ValueError('packet loss in baseline')
    times=([sample['previousPacketAt']] if sample.get('previousPacketAt') is not None else [])+[row['at'] for row in sample['packets']]
    if any(not 0<right-left<=12 for left,right in zip(times,times[1:])):raise ValueError('packet timeline gap/duplicate/order')
    if not -1<=sample['observedAt']-sample['packets'][-1]['at']<=20:raise ValueError('stale packet monitor')


def completed(start_mono, end_mono, samples):
    return end_mono-start_mono>=HOURS*3600 and samples>=HOURS*3600//INTERVAL


def succeeded(failure, normal_complete, started, ended, count, first_packet, last_packet):
    return failure is None and normal_complete is True and first_packet is not None and last_packet is not None and last_packet-first_packet>=86400 and completed(started,ended,count)


def next_delay(started, count, now):
    target=started+count*INTERVAL
    if now-target>INTERVAL:raise ValueError('snapshot schedule overrun')
    return max(0,target-now)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--transaction',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--gateway-ssh-port',type=int,default=22220);p.add_argument('--peer-ssh-port',type=int,default=22221);a=p.parse_args()
    if not re.fullmatch('[a-f0-9]{32}',a.transaction):raise ValueError('exact confirmed transaction required')
    source=Path(__file__).resolve().parents[2]
    if run(['git','-C',str(source),'status','--porcelain']).strip():raise ValueError('clean committed source required')
    head=run(['git','-C',str(source),'rev-parse','HEAD']).decode().strip()
    package=json.loads((source/'package.json').read_text());expected={Path(n).name:hashlib.sha256((source/n).read_bytes()).hexdigest() for n in package['files'] if n.startswith('agent/') and n.endswith('.py')}
    expected={'gateway':expected,'peer':source_modules(source)}
    # Private output parent is supplied explicitly. Originals are never modified/deleted.
    info=a.output.parent.lstat()
    if a.output.parent.is_symlink() or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('private output parent required')
    a.output.mkdir(mode=0o700)
    lab=Lab(a.root,ssh_ports={'gateway':a.gateway_ssh_port,'peer':a.peer_ssh_port})
    for role in ['gateway','peer']:lab.guard(role)
    for role in ['gateway','peer']:
        for name in ['lifecycle_snapshot.py','soak_inputs.py','soak_settlement.py','soak_peer.py','monitor.py','guest_fixture.py']:
            expected_sha=hashlib.sha256((source/'scripts/network-vm-lab'/name).read_bytes()).hexdigest()
            observed=lab.ssh(role,'sudo','sha256sum','/source/scripts/network-vm-lab/'+name).decode().split()[0]
            if observed!=expected_sha:raise ValueError('deployed observation tool mismatch')
    run_id=uuid.uuid4().hex;unit='heliopause-soak-'+run_id
    plan={'schema':'heliopause-24h-baseline-v1','runId':run_id,'sourceCommit':head,'imageSha256':lab.manifest['imageSha256'],
          'durationSeconds':86400,'sampleIntervalSeconds':INTERVAL,'packetIntervalSeconds':5,
          'confirmedTransaction':a.transaction,'newExecutions':0,'ledgerBudget':0,'faults':'none; separate exercises must not run concurrently',
          'stopCriteria':'any packet loss, drift/debt, service/PID/boot change, stale inventory, resource budget or collection failure',
          'resourcesMiB':{'agent':512,'courier':256,'NetworkManager':512,'manager':768,'relay':256},'maxFds':256,'maxChildren':8,'maxAverageCpuCoresPerProcess':1,'heartbeatMaxAgeSeconds':20,'discoveryMaxAgeSeconds':360,
          'scope':'24-hour isolated baseline; no longer-term reliability or fault-exercise success implied',
          'deployedModulesExpected':expected,'sshPorts':lab.ssh_ports,'frozenInputScope':'configuration and public trust/certificates; private keys not read; disk hashes do not attest loaded memory','startedAt':time.time()}
    write(a.output/'plan.json',plan)
    lab.ssh('peer','sudo','systemd-run','--unit='+unit,'--collect','--property=RuntimeMaxSec=90000','--property=MemoryMax=128M',
            '/usr/bin/python3','/source/scripts/network-vm-lab/soak_peer.py','--nonce',lab.nonce,'--id',run_id,'--seconds','90000')
    cursor=0;previous='0'*64;count=0;started=time.monotonic();initial=None;first_packet=None;last_packet=None
    fd=os.open(a.output/'samples.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    failure=None;normal_complete=False
    try:
        with os.fdopen(fd,'w') as stream,ThreadPoolExecutor(max_workers=2) as pool:
            while True:
                jobs={role:pool.submit(lab.ssh,role,'sudo','python3','/source/scripts/network-vm-lab/lifecycle_snapshot.py','--role',role,'--nonce',lab.nonce,timeout=75) for role in ['gateway','peer']}
                sample={role:json.loads(job.result()) for role,job in jobs.items()}
                # Read only new bounded packet rows; no arbitrary peer path is accepted.
                code="import sys;from pathlib import Path;p=Path('/var/lib/heliopause-vm-lab/observations/soak-'+sys.argv[1]+'.jsonl');s=p.stat();assert s.st_size<=8*1024*1024;f=p.open('rb');f.seek(int(sys.argv[2]));sys.stdout.buffer.write(f.read(262144))"
                raw=lab.ssh('peer','sudo','python3','-c',code,run_id,str(cursor))
                if raw and not raw.endswith(b'\n'):raise ValueError('partial packet row')
                cursor+=len(raw);sample['packets']=[json.loads(line) for line in raw.splitlines()]
                sample.update(previousPacketAt=last_packet,observedAt=time.time(),sourceCommit=head,sequence=count+1,previousHash=previous)
                if initial is None:initial=sample
                # Preserve the complete failing sample before rejecting it.
                encoded=json.dumps(sample,sort_keys=True,separators=(',',':'),allow_nan=False)
                stream.write(encoded+'\n');stream.flush();os.fsync(stream.fileno());previous=hashlib.sha256(encoded.encode()).hexdigest();count+=1
                assess(sample,initial,expected,a.transaction)
                if first_packet is None:first_packet=sample['packets'][0]['at']
                last_packet=sample['packets'][-1]['at']
                if completed(started,time.monotonic(),count) and last_packet-first_packet>=86400:
                    normal_complete=True
                    break
                time.sleep(next_delay(started,count,time.monotonic()))
    except (Exception, KeyboardInterrupt) as error:
        failure={'type':type(error).__name__,'reason':str(error)[:240]}
    finally:
        try:
            lab.ssh('peer','sudo','systemctl','stop',unit)
            tail=lab.ssh('peer','sudo','python3','-c',code,run_id,str(cursor))
            rows=[json.loads(line) for line in tail.splitlines()]
            times=([last_packet] if last_packet is not None else [])+[row['at'] for row in rows]
            if (tail and not tail.endswith(b'\n')) or any(not 0<right-left<=12 for left,right in zip(times,times[1:])) or any(row['peerBootId']!=initial['peer']['bootId'] or any(row[k] is not True for k in ['management','forward','reverse']) for row in rows):raise ValueError('final packet tail failed')
            write(a.output/'final-packet-tail.json',{'rows':rows,'startByte':cursor,'bytes':len(tail)})
        except Exception:failure=failure or {'type':'CleanupError','reason':'peer monitor stop unverified'}
        final={'sourceCommit':head,'runId':run_id,'startedAt':plan['startedAt'],'finishedAt':time.time(),
               'elapsedMonotonicSeconds':time.monotonic()-started,'samples':count,'lastSampleHash':previous,
               'firstPacketAt':first_packet,'lastPacketAt':last_packet,'packetBytes':cursor,'normalCompletion':normal_complete,'passed':succeeded(failure,normal_complete,started,time.monotonic(),count,first_packet,last_packet),'failure':failure,
               'imageSha256':plan['imageSha256'],'trialReady':False}
        write(a.output/'result.json',final)
    if not final['passed']:raise RuntimeError('24-hour baseline did not pass; evidence preserved')


if __name__=='__main__':main()
