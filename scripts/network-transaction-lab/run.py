"""Disposable-kernel acceptance suite. Refuses a container with pre-existing non-loopback links."""
import base64
import json
import os
import platform
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


def setup(path,mutate=False,continuous=False):
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
    if continuous:
        run('ip','address','add','198.51.100.10/32','dev','lo',ns='p6-client')
        run('ip','address','add','198.51.100.14/32','dev','lo',ns='p6-workload')
        run('ip','route','add','198.51.100.10/32','via','198.51.100.2',ns='p6-gw')
        run('ip','route','add','198.51.100.14/32','via','198.51.100.6',ns='p6-peer')
        run('ip','route','add','198.51.100.14/32','via','198.51.100.1',ns='p6-client')
        run('ip','route','add','198.51.100.10/32','via','198.51.100.5',ns='p6-workload')
    os.mkdir(path+'/secrets',0o700);os.mkdir(path+'/state',0o700)
    journal_id=n.initialize_journal(path+'/state')
    public={}
    for name in (['gateway','peer','gateway2','peer2'] if continuous else ['gateway','peer']):
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
    if continuous:
        run('ip','link','add','fixedwg2','type','wireguard',ns='p6-peer')
        run('wg','set','fixedwg2','private-key',path+'/secrets/peer2.key','listen-port','51821','peer',public['gateway2'],'endpoint','203.0.113.1:51821','allowed-ips','192.0.2.145/32,198.51.100.10/32','persistent-keepalive','1',ns='p6-peer')
        run('ip','address','add','192.0.2.146/32','dev','fixedwg2',ns='p6-peer')
        run('ip','link','set','fixedwg2','mtu','1400','up',ns='p6-peer')
        for dst in ['192.0.2.145/32','198.51.100.10/32']:run('ip','route','add',dst,'dev','fixedwg2',ns='p6-peer')
        n.atomic(path+'/next-keys.json',{'publicKey':public['gateway2'],'peerPublicKey':public['peer2']})
    authority('keys',path)
    # Wait for address setup before committing the complete protected IPv6 snapshot.
    for ns in NAMES:
        def settled(ns=ns):
            addresses=ip(ns,'-6','address','show')
            routes=ip(ns,'-6','route','show','table','local')
            return all(not a.get('tentative',False) and 'tentative' not in a.get('flags',[]) and any(r.get('type')=='local' and r.get('dev')==x['ifname'] and r.get('dst','').removesuffix('/128')==a['local'] for r in routes) for x in addresses for a in x.get('addr_info',[]))
        wait_for(settled)
    # Observe through the same driver reader in the actual gateway namespace.
    out=run('python3','-c',"import sys,json;sys.path.insert(0,'/source/agent');import network_executor as n;print(n.canonical(n.LinuxWireGuard('/unused').snapshot()))",ns='p6-gw')
    n.atomic(path+'/facts.json',{'snapshot':json.loads(out),'journalId':journal_id,'publicKey':public['gateway'],'peerPublicKey':public['peer'],'mutateRegistry':mutate})
    cfg={'enabled':True,'journalId':journal_id,'identity':{'source':'lab','host':'gateway','nodeId':'gateway'},'managerKeys':path+'/manager','verifierKeys':path+'/verifier','secrets':path+'/secrets','protectedAddresses':['192.0.2.1']}
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


def start(path,fault='',production=False,normal_entry=False,network_enabled=True,extra_env=None):
    if production and not os.path.exists(path+'/relay-ready'):
        if not os.path.exists(path+'/pki'):setup_manager(path)
        log=open(path+'/relay.log','ab',buffering=0)
        relay=subprocess.Popen(['ip','netns','exec','p6-verifier','python3','scripts/network-transaction-lab/relay.py',path],stdout=log,stderr=log)
        processes.append((relay,log));wait_for(lambda:os.path.exists(path+'/relay-ready') or relay.poll() is not None)
        assert relay.poll() is None
    args=['python3','agent/heliopause-pull.py','--network-executor','--config',path+'/config.json','--state-dir',path+'/state'] if production else ['python3','scripts/network-transaction-lab/worker.py',path+'/config.json',path+'/state',fault]
    if normal_entry:args=['python3','agent/heliopause-pull.py']
    log=open(path+'/worker.log','ab',buffering=0)
    env={**os.environ,'HELIOPAUSE_STATE_FILE':path+'/firewall-state.json','HELIOPAUSE_WRITER_LOCK':path+'/writer.lock','HELIOPAUSE_NETWORK_EXECUTOR_CONFIG':path+'/config.json','HELIOPAUSE_NETWORK_EXECUTOR_STATE_DIR':path+'/state'}
    if production:
        env.update({'HELIOPAUSE_RELAY_URL':'https://192.0.2.1:8444','HELIOPAUSE_CA_FILE':path+'/pki/ca.pem','HELIOPAUSE_CERT_FILE':path+'/pki/gateway.pem','HELIOPAUSE_KEY_FILE':path+'/pki/gateway.key','HELIOPAUSE_TARGET':'lab','HELIOPAUSE_HOST_ID':'gateway','HELIOPAUSE_MANAGER_SIGNING_KEYS_DIR':path+'/manager','HELIOPAUSE_BREAK_GLASS_KEYS_DIR':path+'/verifier','HELIOPAUSE_INTERVAL_SEC':'1','HELIOPAUSE_NETWORK_DISCOVERY':'1','HELIOPAUSE_NETWORK_DISCOVERY_BUDGET':'5'})
    env['HELIOPAUSE_NETWORK_EXECUTOR']='1' if network_enabled else '0'
    if extra_env:env.update(extra_env)
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
        print('Transaction diagnostic: '+str(row(path).get('diagnostic')),flush=True)
        print('Protected before: '+json.dumps(row(path).get('before')),flush=True)
        print('Protected current: '+run('python3','-c',"import sys,json;sys.path.insert(0,'/source/agent');import network_executor as n;print(json.dumps(n.LinuxWireGuard('/unused').snapshot()))",ns='p6-gw'),flush=True)
        print('Kernel link: '+json.dumps(ip('p6-gw','-d','link','show')),flush=True)
        print('Kernel IPv6: '+json.dumps({'addresses':ip('p6-gw','-6','address','show','dev',DEV),'routes':ip('p6-gw','-6','route','show','table','all','dev',DEV)}),flush=True)
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


def setup_manager(path):
    os.mkdir(path+'/pki',0o700)
    pki=path+'/pki/'
    run('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',pki+'ca.key','-out',pki+'ca.pem','-days','1','-subj','/CN=lab-ca')
    for identity in ['manager','gateway','alice','bob']:
        run('openssl','req','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',pki+identity+'.key','-out',pki+identity+'.csr','-subj','/CN='+identity)
        os.chmod(pki+identity+'.key',0o600)
        with open(pki+'leaf.ext','w') as stream:
            stream.write('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,'+('serverAuth\nsubjectAltName=IP:192.0.2.1\n' if identity=='manager' else 'clientAuth\n'))
        run('openssl','x509','-req','-in',pki+identity+'.csr','-CA',pki+'ca.pem','-CAkey',pki+'ca.key','-CAcreateserial','-out',pki+identity+'.pem','-days','1','-extfile',pki+'leaf.ext')
    cfg=n.read_json(path+'/config.json')
    cfg['terminalDelivery']={'url':'https://192.0.2.1:8443/api/network/execution/terminal','caFile':pki+'ca.pem','certFile':pki+'gateway.pem','keyFile':pki+'gateway.key'}
    n.atomic(path+'/config.json',cfg)


def start_manager(path):
    ready=path+'/manager-ready.json'
    if os.path.exists(ready):os.unlink(ready)
    log=open(path+'/manager.log','ab',buffering=0)
    process=subprocess.Popen(['ip','netns','exec','p6-verifier','node','--experimental-strip-types','scripts/network-transaction-lab/manager.ts',path],stdout=log,stderr=log)
    processes.append((process,log))
    wait_for(lambda:os.path.exists(ready) or process.poll() is not None)
    assert process.poll() is None,open(path+'/manager.log').read()[-4000:]
    return process


def api(path,action,body=None,identity='alice',expected=200):
    filename=path+'/api-body.json'
    if body is not None:n.atomic(filename,body)
    args=[path,identity,action]+([filename] if body is not None else [])
    response=json.loads(run('python3','scripts/network-transaction-lab/api.py',*args,ns='p6-gw'))
    assert response['status']==expected,response
    return response['body']


def courier(path,success=True):
    command=['python3','agent/network_terminal_delivery.py','--config',path+'/config.json','--state-dir',path+'/state','--once']
    assert run(*command,ns='p6-gw',ok=False)==success


def manager_confirm(path):
    run('python3','scripts/network-transaction-lab/verifier.py',path,ns='p6-verifier')
    assert all(n.read_json(path+'/verification.json').values())
    a=n.read_json(path+'/decoded.json')
    body={'hash':a['approval']['planHash'],'verification':n.read_json(path+'/receipt.json')}
    confirmation=api(path,'confirm',body)['envelope']
    n.atomic(path+'/confirmation.json',confirmation)
    return body,confirmation


def consecutive(kind):
    global DEV
    with tempfile.TemporaryDirectory(prefix='hp-consecutive-') as path:
        setup(path,continuous=True);setup_manager(path)
        manager=start_manager(path);manager_restarts=0
        agent=start(path,production=True);original_pid=agent.pid
        await_state(path,{'awaiting-verification'})
        first=n.read_json(path+'/decoded.json');first_dev=DEV
        first_request=n.read_json(path+'/authorization.json')
        if kind=='consecutive-agent-restart':
            stop(agent);agent=start(path,production=True);await_state(path,{'rolled-back'})
        elif kind=='consecutive-rollback-failed':
            run('ip','address','add','192.0.2.131/32','dev',DEV,ns='p6-gw')
            await_state(path,{'rollback-failed'},16)
            bad={'schemaVersion':1,'domain':n.TERMINAL_DOMAIN,'transactionId':first['transactionId'],'fenceId':first['transactionId'],'target':first['target'],'journalId':first['journalId'],'authorizationHash':n.digest(first),'artifactHash':first['artifactHash'],'registryRevision':first['registryRevision'],'state':'rollback-failed','sequence':1,'proof':{'removalVerified':False}}
            bad['stateHash']=n.digest(bad)
            api(path,'terminal',bad,identity='gateway',expected=409)
            assert api(path,'status')['fence']['transactionId']==first['transactionId']
            # A new production issuance must fail while debt remains; no ledger/fence is deleted.
            n.atomic(path+'/facts-next.json',n.read_json(path+'/facts.json'))
            assert not authority('next',path,ok=False)
            run('ip','address','del','192.0.2.131/32','dev',DEV,ns='p6-gw')
            await_state(path,{'rolled-back'},5)
        else:
            confirm_body,confirmation=manager_confirm(path)
            if kind=='consecutive-manager-restart':
                stop(manager);manager=start_manager(path);manager_restarts+=1
                assert api(path,'confirm',confirm_body)['envelope']==confirmation
            if kind=='consecutive-rolled-back':
                # The Manager issued confirm, but delivery is lost. Agent must independently undo.
                await_state(path,{'rolled-back'},16)
            else:
                n.atomic(path+'/state/confirm.json',confirmation);await_state(path,{'confirmed'})
                assert exists()
        wait_for(lambda:os.path.exists(path+'/state/terminal-results.json') and len(n.read_json(path+'/state/terminal-results.json'))==1)
        terminal=n.read_json(path+'/state/terminal-results.json')[0]
        if kind in {'consecutive-delayed-duplicate','consecutive-manager-restart'}:
            wait_for(lambda:time.time()*1000>first['rollbackAt']+100,16)
        if kind=='consecutive-manager-restart':
            with open(path+'/drop-terminal-response','w') as stream:stream.write('drop')
            courier(path,success=False);wait_for(lambda:manager.poll() is not None)
            manager=start_manager(path);manager_restarts+=1
            assert api(path,'status')['fence'] is None
        courier(path)
        settled=api(path,'status')
        assert settled['fence'] is None and settled['records'][0]['state']=='settled'
        assert api(path,'terminal',terminal,identity='gateway')['duplicate'] is True
        # First rollback deadline really expires before the next execution, with the same live
        # production process for every case except the explicitly named Agent restart case.
        wait_for(lambda:time.time()*1000>first['rollbackAt']+100,16)
        assert agent.poll() is None
        if kind!='consecutive-agent-restart':assert agent.pid==original_pid
        late=n.canonical(first_request)+'\n '
        with open(path+'/state/request.json','w') as stream:stream.write(late)
        stamp=n.hashlib.sha256(late.encode()).hexdigest()
        wait_for(lambda:n.read_json(path+'/state/response.json').get('requestHash')==stamp)
        assert n.read_json(path+'/state/response.json')['state']=='rejected'
        assert len(n.read_json(path+'/state/transactions.json')['transactions'])==1
        if first['transactionId'] in n.read_json(path+'/state/transactions.json')['transactions']:
            assert n.read_json(path+'/state/transactions.json')['transactions'][first['transactionId']]['state']==terminal['state']
        snapshot=json.loads(run('python3','-c',"import sys,json;sys.path.insert(0,'/source/agent');import network_executor as n;print(json.dumps(n.LinuxWireGuard('/unused').snapshot()))",ns='p6-gw'))
        facts={**n.read_json(path+'/next-keys.json'),'snapshot':snapshot,'journalId':first['journalId']}
        n.atomic(path+'/facts-next.json',facts);authority('next',path)
        second=json.loads(base64.urlsafe_b64decode(n.read_json(path+'/authorization.json')['payload']+'=='))
        n.atomic(path+'/decoded.json',second);DEV=second['operation']['interfaceName']
        assert second['transactionId']!=first['transactionId'] and DEV!=first_dev
        assert second['operation']['address']=='192.0.2.145/32'
        assert second['operation']['routes']==['192.0.2.146/32','198.51.100.14/32']
        assert second['operation']['secretRef']=='gateway2' and second['operation']['listenPort']==51821
        n.atomic(path+'/state/request.json',n.read_json(path+'/authorization.json'))
        wait_for(lambda:n.read_json(path+'/state/transactions.json')['transactions'].get(second['transactionId'],{}).get('state')=='awaiting-verification')
        assert agent.poll() is None
        # Even while a new fence exists, an older authentic duplicate cannot release it.
        assert api(path,'terminal',terminal,identity='gateway')['duplicate'] is True
        assert api(path,'status')['fence']['transactionId']==second['transactionId']
        _,confirmation=manager_confirm(path)
        n.atomic(path+'/state/confirm.json',confirmation)
        wait_for(lambda:n.read_json(path+'/state/transactions.json')['transactions'][second['transactionId']]['state']=='confirmed')
        wait_for(lambda:len(n.read_json(path+'/state/terminal-results.json'))==2)
        courier(path)
        final=api(path,'status')
        assert final['fence'] is None and len(final['records'])==2 and all(r['state']=='settled' for r in final['records'])
        journal=n.read_json(path+'/state/transactions.json')
        assert len(journal['transactions'])==2 and journal['terminalSequence']==2
        assert agent.poll() is None
        assert any(x['ifname']==first_dev for x in ip('p6-gw','link','show'))==(terminal['state']=='confirmed')
        for filename in ['worker.log','manager.log','state/terminal-results.json','api-body.json','registry.json']:
            data=open(path+'/'+filename,'rb').read()
            for secret in ['gateway','peer','gateway2','peer2']:
                assert open(path+'/secrets/'+secret+'.key','rb').read().strip() not in data
            assert b'PRIVATE KEY-----' not in data
        assert journal['transactions'][second['transactionId']]['acceptedAt']>first['rollbackAt']
        beats=[json.loads(line) for line in open(path+'/relay-events.jsonl') if json.loads(line)['path']=='/heartbeat']
        gaps=[b['at']-a['at'] for a,b in zip(beats,beats[1:])]
        assert len(beats)>=5 and gaps and max(gaps)<3, (len(beats),gaps)
        assert any(json.loads(line)['path']=='/network/observations' for line in open(path+'/relay-events.jsonl'))
        evidence={'heartbeatCount':len(beats),'heartbeatMaxGapSeconds':max(gaps),'firstState':terminal['state'],'firstAgentPid':original_pid,'secondAgentPid':agent.pid,'managerRestarts':manager_restarts,'firstRollbackAt':first['rollbackAt'],'secondAcceptedAt':journal['transactions'][second['transactionId']]['acceptedAt'],'settledRecords':len(final['records']),'registryRevision':second['registryRevision']}
        stop(agent);stop(manager)
        return evidence


def relay_events(path):
    filename=path+'/relay-events.jsonl'
    if not os.path.exists(filename):return []
    raw=open(filename).read()
    return [json.loads(line) for line in raw.splitlines() if line] if raw.endswith('\n') else []


def integrated(kind):
    with tempfile.TemporaryDirectory(prefix='hp-integrated-') as path:
        setup(path);setup_manager(path)
        extra={};normal=True;enabled=True
        if kind in {'integrated-firewall-busy','integrated-firewall-watchdog'}:
            os.unlink(path+'/state/request.json')
            authority('firewall',path)
            if kind=='integrated-firewall-busy':open(path+'/hold-artifact','w').close()
            else:open(path+'/fail-pending','w').close()
        if kind=='integrated-disabled':enabled=False
        if kind=='integrated-command-timeout':
            os.mkdir(path+'/bin',0o700)
            with open(path+'/bin/wg','w') as stream:
                stream.write('#!/bin/sh\nif [ "$1" = "set" ]; then sleep 10; fi\nexec /usr/bin/wg "$@"\n')
            os.chmod(path+'/bin/wg',0o700)
            extra={'PATH':path+'/bin:'+os.environ['PATH']}
        if kind=='integrated-corrupt-network':
            run('nft','add','table','inet','heliopause',ns='p6-gw')
            n.atomic(path+'/firewall-state.json',{'state':'pending','generation':'recovery-fixture','pendingBackup':{'elements':None},'rollbackAt':time.time()-1})
            with open(path+'/state/transactions.json','w') as stream:stream.write('{')
        agent=start(path,production=True,normal_entry=normal,network_enabled=enabled,extra_env=extra)
        pid=agent.pid
        if kind=='integrated-disabled':
            wait_for(lambda:os.path.exists(path+'/state/response.json'))
            assert n.read_json(path+'/state/response.json')['state']=='rejected' and not exists()
        elif kind=='integrated-corrupt-network':
            wait_for(lambda:n.read_json(path+'/firewall-state.json')['state']=='rolled-back')
            assert not run('nft','list','table','inet','heliopause',ns='p6-gw',ok=False)
            assert open(path+'/state/transactions.json').read()=='{'
        elif kind=='integrated-firewall-busy':
            wait_for(lambda:os.path.exists(path+'/artifact-entered'))
            shutil.copyfile(path+'/authorization.json',path+'/state/request.json')
            wait_for(lambda:os.path.exists(path+'/state/response.json'))
            response=n.read_json(path+'/state/response.json')
            assert response['state']=='rejected' and 'busy' in response['diagnostic']
            assert not exists() and not n.read_json(path+'/state/transactions.json')['transactions']
            first=n.read_json(path+'/decoded.json')
            wait_for(lambda:time.time()*1000>first['expiresAt']+100)
            os.unlink(path+'/wanted.json');os.unlink(path+'/hold-artifact')
            # Explicit redelivery after the clash has ended rechecks expiry; no queue extends it.
            with open(path+'/state/request.json','w') as stream:stream.write(n.canonical(n.read_json(path+'/authorization.json'))+'\n ')
            wait_for(lambda:'busy' not in n.read_json(path+'/state/response.json').get('diagnostic',''))
            assert n.read_json(path+'/state/response.json')['state']=='rejected' and not exists()
        elif kind=='integrated-firewall-watchdog':
            wait_for(lambda:os.path.exists(path+'/firewall-state.json') and n.read_json(path+'/firewall-state.json')['state']=='pending',10)
            promised=n.read_json(path+'/firewall-state.json')['rollbackAt']
            shutil.copyfile(path+'/authorization.json',path+'/state/request.json')
            wait_for(lambda:os.path.exists(path+'/state/response.json'))
            assert n.read_json(path+'/state/response.json')['state']=='rejected' and not exists()
            assert run('nft','list','table','inet','heliopause',ns='p6-gw',ok=False)
            wait_for(lambda:n.read_json(path+'/firewall-state.json')['state']=='rolled-back',100)
            rolled_at=time.time()
            assert promised<=rolled_at<promised+3, (promised,rolled_at)
            assert not run('nft','list','table','inet','heliopause',ns='p6-gw',ok=False)
        elif kind=='integrated-command-timeout':
            await_state(path,{'rolled-back'},16)
            assert not exists() and any('timed out' in h.get('diagnostic','') for h in [row(path)])
        else:
            await_state(path,{'awaiting-verification'})
            if kind=='integrated-disabled-recovery':
                stop(agent);agent=start(path,production=True,normal_entry=True,network_enabled=False)
                await_state(path,{'rolled-back'});assert not exists() and agent.pid!=pid
            elif kind=='integrated-network-busy':
                n.atomic(path+'/wanted.json',{'generation':'deferred-firewall'})
                try:
                    wait_for(lambda:os.path.exists(path+'/firewall-state.json') and bool(n.read_json(path+'/firewall-state.json').get('lastRefusal')))
                except Exception:
                    print('Busy Agent log: '+open(path+'/worker.log').read()[-5000:],flush=True)
                    print('Busy lifecycle: '+open(path+'/lifecycle-status.json').read(),flush=True)
                    print('Busy Relay events: '+str(relay_events(path)),flush=True)
                    raise
                assert not os.path.exists(path+'/artifact-entered')
                n.atomic(path+'/malformed.json',[])
                before=len(relay_events(path));wait_for(lambda:len(relay_events(path))>=before+3)
                assert agent.poll() is None and state(path)=='awaiting-verification'
                os.unlink(path+'/malformed.json');os.unlink(path+'/wanted.json')
                await_state(path,{'rolled-back'},16);assert not exists()
            elif kind=='integrated-confirmed-missing':
                assert all(verify_and_confirm(path).values());await_state(path,{'confirmed'})
                run('ip','link','del',DEV,ns='p6-gw')
                tx=n.read_json(path+'/decoded.json')['transactionId']
                def absent():
                    report=n.read_json(path+'/lifecycle-status.json')
                    return report.get('network',{}).get('confirmedKernel',{}).get(tx,{}).get('state')=='absent-or-drifted'
                wait_for(absent,34)
                assert state(path)=='confirmed' and not exists()
            elif kind=='integrated-corrupt-firewall':
                stop(agent)
                with open(path+'/firewall-state.json','w') as stream:stream.write('{')
                agent=start(path,production=True,normal_entry=True)
                await_state(path,{'rolled-back'});assert not exists()
                assert open(path+'/firewall-state.json').read()=='{'
        wait_for(lambda:len([e for e in relay_events(path) if e['path']=='/heartbeat'])>=4,8)
        events=relay_events(path);beats=[e for e in events if e['path']=='/heartbeat']
        gaps=[b['at']-a['at'] for a,b in zip(beats,beats[1:])]
        allowed=6 if kind=='integrated-firewall-watchdog' else 5 if kind=='integrated-firewall-busy' else 3
        assert max(gaps)<allowed,(kind,gaps)
        assert agent.poll() is None
        report=n.read_json(path+'/lifecycle-status.json')
        assert report['mode']=='integrated'
        evidence={'firstAgentPid':pid,'finalAgentPid':agent.pid,'heartbeatCount':len(beats),'heartbeatMaxGapSeconds':max(gaps),'heartbeatGapLimitSeconds':allowed}
        if kind=='integrated-firewall-watchdog':evidence.update({'rollbackDeadline':promised,'rollbackObservedAt':rolled_at,'rollbackLatenessSeconds':rolled_at-promised})
        agent.terminate();agent.wait(timeout=8)
        return evidence


cases=['normal','signature','target','expiry','hash','approval','registry-changed','local-changed','duplicate','prepare-failed','fail-created','fail-routes','management-failed','asymmetric','blackhole','absent-verifier','lost-confirm','forged-verifier','crash-apply','crash-before-alias','crash-partial-routes','crash-wait','crash-rollback','crash-after-remove','foreign-writer','rollback-command-failed','peer-route-loss','secret-redaction','disabled-recovery','writer-conflict','graceful-stop','foreign-create','consecutive-confirmed','consecutive-rolled-back','consecutive-rollback-failed','consecutive-manager-restart','consecutive-agent-restart','consecutive-delayed-duplicate']
cases += ['integrated-disabled','integrated-disabled-recovery','integrated-network-busy','integrated-firewall-busy','integrated-command-timeout','integrated-firewall-watchdog','integrated-confirmed-missing','integrated-corrupt-network','integrated-corrupt-firewall']
# New continuity cases run first for useful fail-fast diagnostics; success still requires all38.
cases.sort(key=lambda name:0 if name.startswith('integrated-') else 1 if name.startswith('consecutive-') else 2)
for case in cases:
    started=time.monotonic()
    try:
        evidence=integrated(case) if case.startswith('integrated-') else consecutive(case) if case.startswith('consecutive-') else scenario(case)
        results.append({'name':case,'status':'passed','seconds':round(time.monotonic()-started,2),**({'evidence':evidence} if evidence else {})})
        print('PASS '+case,flush=True)
    except Exception as e:
        print('FAIL '+case+': '+str(e),flush=True)
        raise
    finally:
        for p,log in processes: stop(p);log.close()
        processes.clear()
        for ns in NAMES: run('ip','netns','del',ns,ok=False)
assert len(results)==47
print(json.dumps({'kind':'network-transaction-kernel-report','passed':len(results),'failed':0,'skipped':0,'hostRebootVerified':False,'backend':n.DRIVER,'sourceCommit':os.environ.get('HELIOPAUSE_LAB_SOURCE_COMMIT'),'kernel':platform.release(),'wireguardTools':run('wg','--version'),'iproute2':run('ip','-Version'),'scenarios':results}),flush=True)
