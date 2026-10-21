#!/usr/bin/env python3
"""Read-only lifecycle inventory on an explicitly marked disposable guest.

No secret bytes, keyfile exports, environment or command lines are emitted. This does not
attest a loaded Python process; module commitments measure current installed disk bytes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
sys.path.insert(0,'/opt/heliopause/agent')
sys.path.insert(0,'/source/agent')
import network_executor as n
from guest_fixture import guard
from soak_inputs import source_modules, frozen_inputs


def command(args):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,check=True)
    if len(result.stdout)>65536:raise ValueError('inventory command output bound')
    return result.stdout.decode().strip()


def commitment(path,maximum=8*1024*1024):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size>maximum:raise ValueError('inventory file bound')
        with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(maximum+1)
        if len(raw)>maximum:raise ValueError('inventory file grew beyond bound')
        return {'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode)}
    finally:os.close(fd)


def process(unit):
    values=dict(line.split('=',1) for line in command(['systemctl','show',unit,'-p','MainPID','-p','ActiveState','-p','SubState']).splitlines())
    pid=int(values['MainPID']);result={'pid':pid,'active':values['ActiveState'],'sub':values['SubState']}
    if not pid:return result
    root=Path('/proc')/str(pid)
    fields=(root/'stat').read_text().rsplit(')',1)[1].split()
    # Kernel stat indexes after comm: state is field3.
    result.update(startTicks=int(fields[19]),cpuTicks=int(fields[11])+int(fields[12]),rssPages=int(fields[21]),
                  fdCount=len(list((root/'fd').iterdir())),children=len((root/'task'/str(pid)/'children').read_text().split()))
    return result


def snapshot(role):
    result={'at':time.time(),'bootId':n.current_boot_id(),'role':role,
            'systemdVersion':command(['rpm','-q','systemd']), 'clockTicksPerSecond':os.sysconf('SC_CLK_TCK'),
            'pageBytes':os.sysconf('SC_PAGE_SIZE')}
    base=Path('/var/lib/heliopause-vm-lab')
    if role=='peer':
        registry=n.read_json(str(base/'registry.json'));state=registry['execution'];cfg=n.read_json(str(base/'config.json'))
        result.update(manager=process('heliopause-vm-lab-manager.service'),relay=process('heliopause-vm-lab-relay.service'),
                      deployedModules=source_modules('/source'),frozenInputs=frozen_inputs(role,cfg),targetBinding={'journalId':cfg['journalId'],'identity':cfg['identity']},
                      ledger={'commitment':commitment(base/'registry.json'),'nextSequence':state['nextSequence'],
                              'records':len(state['records']),'fence':state['fence'],'capacityHold':state.get('capacityHold'),'executionSchemaVersion':state['schemaVersion'],
                              'results':{r['transactionId']:r.get('resultHash') for r in state['records']}})
        result['at']=time.time()
        return result
    cfg=n.read_json('/etc/heliopause/network-executor.json');directory=Path('/var/lib/heliopause/network-executor')
    journal=n.read_json(str(directory/'transactions.json'));provider=n.crypto_helpers(str(directory))
    # _load_artifact_key_dir reads only public keys and invokes bounded OpenSSL pkey -pubin.
    trust={role:[row[0] for row in provider._load_artifact_key_dir(cfg[role+'Keys'],'manager')] for role in ['manager','verifier']}
    modulebase=Path('/opt/heliopause/agent');package=n.read_json('/source/package.json')
    modules={Path(name).name:commitment(modulebase/Path(name).name)['sha256'] for name in package['files'] if name.startswith('agent/') and name.endswith('.py')}
    status=n.read_json('/var/lib/heliopause-agent/lifecycle-status.json')
    rows={}
    identity=n.read_json(str(directory/'journal-identity.json'));effective=n.capacity_rows(journal,identity)
    for tx,row in effective.items():
        rows[tx]={'state':row['state'],'bootRestore':{k:v for k,v in row.get('bootRestore',{}).items() if k in {'bootId','state','reason','recovery','currentConnectivity','diagnostic'}},
                  'diagnostic':row.get('diagnostic'),'authorizationHash':row.get('authorizationHash')}
        if row['state']=='confirmed' and row['authorization']['operation']['driver']==n.PERSISTENT_DRIVER:
            from network_nm_wireguard import NetworkManagerWireGuard
            n.validate_operation(row['authorization']['operation'])
            driver=NetworkManagerWireGuard(cfg['secrets']);driver.command_deadline=time.monotonic()+25
            checker=object.__new__(n.Executor);checker.config=cfg;checker.provider=provider
            checker.validate_restore_authority(row,journal['journalId'])
            rows[tx]['historicalAuthorityValid']=True
            rows[tx]['configurationMatches']=driver.prepare_restore(row,cfg['protectedAddresses'])=={'wasActive':True}
    files={}
    for name in ['transactions.json','journal-identity.json','terminal-results.json','terminal-acks.json','terminal-delivery-status.json']:
        try:files[name]=commitment(directory/name)
        except FileNotFoundError:files[name]={'missing':True}
    status=n.read_json('/var/lib/heliopause-agent/lifecycle-status.json')
    result.update(agent=process('heliopause-agent.service'),courier=process('heliopause-network-terminal.service'),
                  networkManager=process('NetworkManager.service'),targetBinding={'journalId':cfg['journalId'],'identity':cfg['identity']},journalId=journal['journalId'],
                  acceptedSequence=journal['acceptedSequence'],terminalSequence=journal['terminalSequence'],effectiveAcceptedSequence=len(effective),effectiveTerminalSequence=journal['terminalSequence']+int('capacityCancellation' in identity),maintenanceRequired='capacityCancellation' in identity,transactions=rows,
                  files=files,frozenInputs=frozen_inputs(role,cfg),journalContentHash=n.digest({k:v for k,v in journal.items() if k!='lastClock'}),trust=trust,deployedModules=modules,lifecycle=status)
    result['at']=time.time()
    return result


def main():
    p=argparse.ArgumentParser();p.add_argument('--role',choices=['gateway','peer'],required=True);p.add_argument('--nonce',required=True);a=p.parse_args()
    guard(a.role,a.nonce)
    print(json.dumps(snapshot(a.role),allow_nan=False))


if __name__=='__main__':main()
