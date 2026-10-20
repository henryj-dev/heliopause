"""Disposable-kernel acceptance suite. Refuses a container with pre-existing non-loopback links."""
import base64
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
sys.path.insert(0,'/source/agent')
import network_executor as n


def run(*args,ns=None,data=None,ok=True):
    command=(['ip','netns','exec',ns] if ns else [])+list(args)
    p=subprocess.run(command,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
    if ok and p.returncode:
        raise RuntimeError('lab command failed: '+str(args[:3])+' '+p.stderr.decode()[:400])
    return p.stdout.decode().strip() if ok else p.returncode==0


def ip(ns,*args): return json.loads(run('ip','-j',*args,ns=ns))
def authority(action,path,*extra,ok=True):
    return run('node','--experimental-strip-types','scripts/network-transaction-lab/authority.ts',action,path,*extra,ok=ok)


if os.geteuid()!=0 or sys.platform!='linux' or [x['ifname'] for x in ip(None,'link','show')]!=['lo']:
    raise RuntimeError('requires disposable network-none Linux container')

NAMES=['p6-gw','p6-peer','p6-client','p6-workload','p6-verifier']
results=[]
processes=[]
DEV=None


def wait_for(test,seconds=6):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        if test(): return
        time.sleep(0.1)
    raise AssertionError('condition timed out')


def veth(a,dev_a,addr_a,b,dev_b,addr_b):
    run('ip','link','add','tmpa','type','veth','peer','name','tmpb')
    for ns,old,dev,addr in [(a,'tmpa',dev_a,addr_a),(b,'tmpb',dev_b,addr_b)]:
        run('ip','link','set',old,'netns',ns)
        run('ip','link','set',old,'name',dev,ns=ns)
        run('ip','address','add',addr,'dev',dev,ns=ns)
        run('ip','link','set',dev,'up',ns=ns)


def setup(path,mutate=False):
    for ns in NAMES:
        run('ip','netns','add',ns)
        run('ip','link','set','lo','up',ns=ns)
    veth('p6-gw','underlay','203.0.113.1/30','p6-peer','underlay','203.0.113.2/30')
    veth('p6-gw','mgmt','192.0.2.2/30','p6-verifier','mgmt','192.0.2.1/30')
    veth('p6-gw','lan','198.51.100.1/30','p6-client','eth0','198.51.100.2/30')
    veth('p6-peer','lan','198.51.100.5/30','p6-workload','eth0','198.51.100.6/30')
    for ns in ['p6-gw','p6-peer']:
        run('sysctl','-w','net.ipv4.ip_forward=1',ns=ns)
    run('ip','route','add','198.51.100.6/32','via','198.51.100.1',ns='p6-client')
    run('ip','route','add','198.51.100.2/32','via','198.51.100.5',ns='p6-workload')
    os.mkdir(path+'/secrets',0o700);os.mkdir(path+'/state',0o700)
    public={}
    for name in ['gateway','peer']:
        secret=run('wg','genkey')
        fd=os.open(path+'/secrets/'+name+'.key',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f: f.write(secret+'\n')
        public[name]=run('wg','pubkey',data=(secret+'\n').encode())
    run('ip','link','add','fixedwg','type','wireguard',ns='p6-peer')
    run('wg','set','fixedwg','private-key',path+'/secrets/peer.key','listen-port','51820','peer',public['gateway'],'endpoint','203.0.113.1:51820','allowed-ips','192.0.2.129/32,198.51.100.2/32','persistent-keepalive','1',ns='p6-peer')
    run('ip','address','add','192.0.2.130/32','dev','fixedwg',ns='p6-peer')
    run('ip','link','set','fixedwg','mtu','1400','up',ns='p6-peer')
    for dst in ['192.0.2.129/32','198.51.100.2/32']:
        run('ip','route','add',dst,'dev','fixedwg',ns='p6-peer')
    authority('keys',path)
    # Wait for address setup before committing the complete protected IPv6 snapshot.
    for ns in NAMES:
        wait_for(lambda ns=ns:not any('tentative' in a.get('flags',[]) for x in ip(ns,'-6','address','show') for a in x.get('addr_info',[])))
    # Observe through the same driver reader in the actual gateway namespace.
    out=run('python3','-c',"import sys,json;sys.path.insert(0,'/source/agent');import network_executor as n;print(n.canonical(n.LinuxWireGuard('/unused').snapshot()))",ns='p6-gw')
    n.atomic(path+'/facts.json',{'snapshot':json.loads(out),'publicKey':public['gateway'],'peerPublicKey':public['peer'],'mutateRegistry':mutate})
    cfg={'enabled':True,'identity':{'source':'lab','host':'gateway','nodeId':'gateway'},'managerKeys':path+'/manager','verifierKeys':path+'/verifier','secrets':path+'/secrets','protectedAddresses':['192.0.2.1']}
    n.atomic(path+'/config.json',cfg)
    if mutate:
        assert not authority('issue',path,ok=False)
        assert not os.path.exists(path+'/authorization.json')
        return
    authority('issue',path)
    envelope=n.read_json(path+'/authorization.json')
    a=json.loads(base64.urlsafe_b64decode(envelope['payload']+'=='))
    global DEV
    DEV=a['operation']['interfaceName']
    n.atomic(path+'/decoded.json',a)
    shutil.copyfile(path+'/authorization.json',path+'/state/request.json')
    os.chmod(path+'/state/request.json',0o600)


def start(path,fault='',production=False):
    args=['python3','agent/heliopause-pull.py','--network-executor','--config',path+'/config.json','--state-dir',path+'/state'] if production else ['python3','scripts/network-transaction-lab/worker.py',path+'/config.json',path+'/state',fault]
    log=open(path+'/worker.log','ab',buffering=0)
    env={**os.environ,'HELIOPAUSE_STATE_FILE':path+'/firewall-state.json','HELIOPAUSE_WRITER_LOCK':path+'/writer.lock','HELIOPAUSE_NETWORK_EXECUTOR_CONFIG':path+'/config.json','HELIOPAUSE_NETWORK_EXECUTOR_STATE_DIR':path+'/state'}
    p=subprocess.Popen(['ip','netns','exec','p6-gw']+args,stdout=log,stderr=log,env=env)
    processes.append((p,log));return p


def stop(p):
    if p.poll() is None: p.kill();p.wait(timeout=5)


def row(path):
    try:
        rows=n.read_json(path+'/state/transactions.json')['transactions']
        return next(iter(rows.values()),{})
    except FileNotFoundError: return {}


def state(path): return row(path).get('state')
def exists(): return any(x['ifname']==DEV for x in ip('p6-gw','link','show'))
def await_state(path,wanted,seconds=7):
    try:
        wait_for(lambda:state(path) in wanted,seconds)
    except Exception:
        print('Agent diagnostic: '+open(path+'/worker.log').read()[-4000:],flush=True)
        print('Agent state: '+str(state(path)),flush=True)
        print('Kernel link: '+json.dumps(ip('p6-gw','-d','link','show')),flush=True)
        if os.path.exists(path+'/state/response.json'): print(n.read_json(path+'/state/response.json'),flush=True)
        raise


def verify_and_confirm(path):
    run('python3','scripts/network-transaction-lab/verifier.py',path,ns='p6-verifier')
    checks=n.read_json(path+'/verification.json')
    if not all(checks.values()): assert not authority('confirm',path,ok=False)
    authority('confirm' if all(checks.values()) else 'unsafe-confirm',path)
    shutil.copyfile(path+'/confirmation.json',path+'/state/confirm.json')
    return checks


def dropped(ns,chain,condition):
    run('nft','add','table','inet','fault',ns=ns)
    run('nft','-f','-',ns=ns,data=('add chain inet fault '+chain+' { type filter hook '+chain+' priority -10; policy accept; }\nadd rule inet fault '+chain+' '+condition+' drop\n').encode())


def scenario(kind):
    with tempfile.TemporaryDirectory(prefix='hp6-') as path:
        setup(path,kind=='registry-changed')
        if kind=='registry-changed': return
        if kind in {'signature','target','expiry','hash','approval'}:
            authority('tamper',path,kind);shutil.copyfile(path+'/request-tampered.json',path+'/state/request.json')
            p=start(path);wait_for(lambda:os.path.exists(path+'/state/response.json'))
            assert n.read_json(path+'/state/response.json')['state']=='rejected' and not exists()
            stop(p);return
        if kind=='local-changed':
            run('ip','address','add','192.0.2.10/32','dev','lo',ns='p6-gw')
            p=start(path);wait_for(lambda:os.path.exists(path+'/state/response.json'))
            assert n.read_json(path+'/state/response.json')['state']=='rejected' and not exists();stop(p);return
        if kind=='prepare-failed':
            # /proc refuses journal creation. No external write can follow this persistence error.
            code="import sys;sys.path.insert(0,'/source/agent');import network_executor as n;e=n.Executor(n.read_json(sys.argv[1]),sys.argv[2]);n.atomic=lambda *a:(_ for _ in ()).throw(OSError('disk full'));e.accept(n.read_json(sys.argv[2]+'/request.json'))"
            assert not run('python3','-c',code,path+'/config.json',path+'/state',ns='p6-gw',ok=False)
            assert not exists();return
        fault={'fail-created':'fail-created','fail-routes':'fail-routes','foreign-create':'foreign-create','crash-before-alias':'raw-create','crash-partial-routes':'first-route','crash-apply':'created','crash-rollback':'rolling-back','crash-after-remove':'removed'}.get(kind,'')
        p=start(path,fault,production=kind in {'normal','writer-conflict','graceful-stop'})
        if kind=='foreign-create':
            await_state(path,{'rollback-failed'});assert exists();stop(p);return
        if kind in {'fail-created','fail-routes'}:
            await_state(path,{'rolled-back'});assert not exists();stop(p);return
        if kind in {'crash-apply','crash-before-alias','crash-partial-routes'}:
            wait_for(lambda:os.path.exists(path+'/state/barrier.json'));assert exists()
            if kind=='crash-partial-routes': assert len([r for r in ip('p6-gw','-4','route','show') if r.get('dev')==DEV])==1
            stop(p)
            p=start(path);await_state(path,{'rolled-back'});assert not exists();stop(p);return
        await_state(path,{'awaiting-verification'})
        if kind=='graceful-stop':
            p.terminate();p.wait(timeout=5)
            assert state(path)=='rolled-back' and not exists();return
        if kind=='writer-conflict':
            second=start(path,production=True);second.wait(timeout=4)
            assert second.returncode!=0 and p.poll() is None and exists()
            stop(p);return
        if kind=='duplicate':
            index=ip('p6-gw','link','show','dev',DEV)[0]['ifindex']
            code="import sys;sys.path.insert(0,'/source/agent');import network_executor as n;e=n.Executor(n.read_json(sys.argv[1]),sys.argv[2]);assert e.accept(n.read_json(sys.argv[2]+'/request.json'))=='awaiting-verification'"
            run('python3','-c',code,path+'/config.json',path+'/state',ns='p6-gw')
            assert ip('p6-gw','link','show','dev',DEV)[0]['ifindex']==index
        if kind in {'normal','duplicate','secret-redaction'}:
            checks=verify_and_confirm(path);assert all(checks.values()),checks
            await_state(path,{'confirmed'});assert exists();stop(p)
            p=start(path);time.sleep(0.3);assert state(path)=='confirmed' and exists();stop(p)
            if kind=='secret-redaction':
                secret=open(path+'/secrets/gateway.key','rb').read().strip()
                for filename in ['worker.log','state/transactions.json','state/response.json','review.json']:
                    assert secret not in open(path+'/'+filename,'rb').read()
            return
        if kind in {'crash-wait','disabled-recovery'}:
            deadline=row(path)['authorization']['rollbackAt'];stop(p)
            cfg=n.read_json(path+'/config.json')
            if kind=='disabled-recovery': cfg['enabled']=False
            n.atomic(path+'/config.json',cfg)
            p=start(path);await_state(path,{'rolled-back'});assert row(path)['authorization']['rollbackAt']==deadline and not exists();stop(p);return
        if kind=='foreign-writer':
            run('ip','address','add','192.0.2.140/32','dev',DEV,ns='p6-gw')
            stop(p);p=start(path);await_state(path,{'rollback-failed'});assert exists();assert 'rollback' in row(path)['diagnostic'];stop(p);return
        if kind=='rollback-command-failed':
            stop(p)
            code="import sys;sys.path.insert(0,'/source/agent');import network_executor as n;e=n.Executor(n.read_json(sys.argv[1]),sys.argv[2]);original=e.driver.run;e.driver.run=lambda args,*a,**kw:original(['ip','link','del','dev','does-not-exist']) if args[:3]==['ip','link','del'] else original(args,*a,**kw);e.recover()"
            run('python3','-c',code,path+'/config.json',path+'/state',ns='p6-gw');assert state(path)=='rollback-failed' and exists()
            p=start(path);await_state(path,{'rolled-back'});assert not exists();stop(p);return
        if kind=='peer-route-loss':
            run('ip','link','set',DEV,'down',ns='p6-gw');run('ip','link','set',DEV,'up',ns='p6-gw')
            # Explicitly measure the post-up routes; if this kernel retained them, inject their loss.
            # The Agent must refuse confirm and undo the unconfirmed interface, not infer recovery
            # from link-up or install routes outside its authorized apply path.
            for dst in n.read_json(path+'/decoded.json')['operation']['routes']:
                run('ip','route','del',dst,'dev',DEV,ns='p6-gw',ok=False)
            assert not run('ping','-c','1','-W','1','198.51.100.6',ns='p6-client',ok=False)
            checks=verify_and_confirm(path)
            assert not checks['route'] and not checks['fib']
            await_state(path,{'rolled-back'},15);assert not exists();stop(p);return
        if kind in {'management-failed','asymmetric','blackhole','lost-confirm','forged-verifier'}:
            assert run('ping','-c','1','-W','2','192.0.2.130',ns='p6-gw',ok=False)
        if kind=='management-failed': dropped('p6-gw','input','iifname "mgmt"')
        if kind=='asymmetric': dropped('p6-peer','forward','ip saddr 198.51.100.6')
        if kind=='blackhole': dropped('p6-gw','forward','oifname \"'+DEV+'\"')
        if kind in {'management-failed','asymmetric','blackhole'}:
            checks=verify_and_confirm(path)
            assert not all(checks.values())
            assert checks['handshake']
            if kind=='management-failed': assert checks['forward'] and checks['reverse'] and not checks['management']
            wait_for(lambda:os.path.exists(path+'/state/response.json') and n.read_json(path+'/state/response.json')['state']=='rejected')
        if kind=='forged-verifier':
            run('python3','scripts/network-transaction-lab/verifier.py',path,ns='p6-verifier')
            r=n.read_json(path+'/receipt.json');r['signature']='A'*86;n.atomic(path+'/receipt.json',r)
            assert not authority('confirm',path,ok=False)
            authority('unsafe-confirm',path);shutil.copyfile(path+'/confirmation.json',path+'/state/confirm.json')
            wait_for(lambda:n.read_json(path+'/state/response.json')['state']=='rejected')
        if kind=='lost-confirm':
            run('python3','scripts/network-transaction-lab/verifier.py',path,ns='p6-verifier')
            assert all(n.read_json(path+'/verification.json').values())
            authority('confirm',path)
            assert os.path.exists(path+'/confirmation.json') and not os.path.exists(path+'/state/confirm.json')
        # absent verifier, lost confirm and all injected delivery failures must time out locally.
        if kind in {'crash-rollback','crash-after-remove'}:
            wait_for(lambda:os.path.exists(path+'/state/barrier.json'),15);stop(p)
            p=start(path);await_state(path,{'rolled-back'});assert not exists();stop(p);return
        await_state(path,{'rolled-back'},15);assert not exists();stop(p)


cases=['normal','signature','target','expiry','hash','approval','registry-changed','local-changed','duplicate','prepare-failed','fail-created','fail-routes','management-failed','asymmetric','blackhole','absent-verifier','lost-confirm','forged-verifier','crash-apply','crash-before-alias','crash-partial-routes','crash-wait','crash-rollback','crash-after-remove','foreign-writer','rollback-command-failed','peer-route-loss','secret-redaction','disabled-recovery','writer-conflict','graceful-stop','foreign-create']
for case in cases:
    started=time.monotonic()
    try:
        scenario(case)
        results.append({'name':case,'status':'passed','seconds':round(time.monotonic()-started,2)})
        print('PASS '+case,flush=True)
    except Exception as e:
        print('FAIL '+case+': '+str(e),flush=True)
        raise
    finally:
        for p,log in processes: stop(p);log.close()
        processes.clear()
        for ns in NAMES: run('ip','netns','del',ns,ok=False)
assert len(results)==32
print(json.dumps({'kind':'network-transaction-kernel-report','passed':len(results),'failed':0,'skipped':0,'hostRebootVerified':False,'backend':n.DRIVER,'scenarios':results}),flush=True)
