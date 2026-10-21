#!/usr/bin/env python3
"""Provision only the explicitly marked disposable Rocky VM fixture.

Gateway transaction resources are never applied here: those use the shipping Agent mailbox.
This fixture creates the fixed peer/workload topology and isolated test credentials only.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
sys.path.insert(0, '/source/agent')
import network_executor as n

BASE = Path('/var/lib/heliopause-vm-lab')
STATE = Path('/var/lib/heliopause/network-executor')
ETC = Path('/etc/heliopause')


def command(*args, data=None):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
    if result.returncode:
        raise RuntimeError('fixture operation failed: '+args[0])
    return result.stdout.decode().strip()


def protected(path, content):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content if isinstance(content, bytes) else content.encode())


def guard(role, nonce):
    marker = Path('/etc/heliopause-disposable-lab')
    info = marker.lstat()
    if os.geteuid() != 0 or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('explicit disposable guest marker required')
    if json.loads(marker.read_text()) != {'role':role, 'nonce':nonce} or not re.fullmatch(r'[a-f0-9]{32}', nonce):
        raise ValueError('disposable guest identity mismatch')
    release = Path('/etc/os-release').read_text()
    if 'ID="rocky"' not in release or 'VERSION_ID="10.2"' not in release or command('systemd-detect-virt') != 'qemu':
        raise ValueError('marked Rocky 10.2 QEMU guest required')


def wireguard_key(name):
    BASE.mkdir(mode=0o700, exist_ok=True)
    secrets = BASE/'secrets'; secrets.mkdir(mode=0o700, exist_ok=True)
    path = secrets/(name+'.key')
    if not path.exists(): protected(path, command('wg', 'genkey')+'\n')
    return command('wg', 'pubkey', data=path.read_bytes())


def gateway_initialize():
    ETC.mkdir(mode=0o700, exist_ok=True)
    secrets = ETC/'secrets';secrets.mkdir(mode=0o700, exist_ok=True)
    key = secrets/'gateway.key'
    if not key.exists():
        if (STATE/'journal-identity.json').exists():raise ValueError('known gateway secret missing')
        protected(key, command('wg', 'genkey')+'\n')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not (STATE/'transactions.json').exists():
        if (STATE/'journal-identity.json').exists(): raise ValueError('known journal missing')
        journal = n.initialize_journal(str(STATE))
    else:
        journal = n.read_json(str(STATE/'journal-identity.json'))['journalId']
    return {'journalId':journal, 'publicKey':command('wg', 'pubkey', data=key.read_bytes())}


def peer_initialize():
    public = wireguard_key('peer')
    if not (BASE/'manager.key').exists():
        command('/opt/node/bin/node', '/source/scripts/network-transaction-lab/authority.ts', 'keys', str(BASE))
    pki = BASE/'pki';pki.mkdir(mode=0o700, exist_ok=True)
    if not (pki/'ca.pem').exists():
        command('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',str(pki/'ca.key'),'-out',str(pki/'ca.pem'),'-days','1','-subj','/CN=lab-ca')
        os.chmod(pki/'ca.key',0o600)
    for identity in ['manager','gateway','alice','bob']:
        if (pki/(identity+'.pem')).exists():continue
        command('openssl','req','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',str(pki/(identity+'.key')),'-out',str(pki/(identity+'.csr')),'-subj','/CN='+identity)
        os.chmod(pki/(identity+'.key'),0o600)
        protected(pki/'leaf.ext','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,'+('serverAuth\nsubjectAltName=IP:192.0.2.1\n' if identity=='manager' else 'clientAuth\n'))
        command('openssl','x509','-req','-in',str(pki/(identity+'.csr')),'-CA',str(pki/'ca.pem'),'-CAkey',str(pki/'ca.key'),'-CAcreateserial','-out',str(pki/(identity+'.pem')),'-days','1','-extfile',str(pki/'leaf.ext'))
    return {'publicKey':public}


def peer_configure(gateway_public, journal):
    if not n.key(gateway_public) or not re.fullmatch(r'[a-f0-9]{32}',journal):raise ValueError('invalid lab binding')
    # Devices and profiles below were created by this fixture's cloud-init seed.
    command('nmcli','device','set','lan','managed','no')
    if Path('/var/run/netns/p6-client').exists(): raise ValueError('existing workload namespace refused')
    command('ip','netns','add','p6-client');command('ip','netns','add','p6-workload')
    command('ip','-4','address','flush','dev','lan');command('ip','link','set','lan','netns','p6-client')
    command('ip','netns','exec','p6-client','ip','link','set','lan','name','eth0')
    command('ip','link','add','workload','type','veth','peer','name','workload-peer')
    command('ip','link','set','workload-peer','netns','p6-workload')
    command('ip','netns','exec','p6-workload','ip','link','set','workload-peer','name','eth0')
    for namespace,address,via,destination in [('p6-client','198.51.100.2/30','198.51.100.1','198.51.100.6/32'),('p6-workload','198.51.100.6/30','198.51.100.5','198.51.100.2/32')]:
        prefix=['ip','netns','exec',namespace]
        command(*prefix,'ip','link','set','lo','up');command(*prefix,'ip','address','add',address,'dev','eth0');command(*prefix,'ip','link','set','eth0','up');command(*prefix,'ip','route','add',destination,'via',via)
    command('ip','address','add','198.51.100.5/30','dev','workload');command('ip','link','set','workload','up')
    command('sysctl','-w','net.ipv4.ip_forward=1')
    command('ip','link','add','fixedwg','type','wireguard')
    command('wg','set','fixedwg','private-key',str(BASE/'secrets/peer.key'),'listen-port','51820','peer',gateway_public,'endpoint','203.0.113.1:51820','allowed-ips','192.0.2.129/32,198.51.100.2/32','persistent-keepalive','1')
    command('ip','address','add','192.0.2.130/32','dev','fixedwg');command('ip','link','set','fixedwg','mtu','1400','up')
    for destination in ['192.0.2.129/32','198.51.100.2/32']:command('ip','route','add',destination,'dev','fixedwg')
    cfg={'enabled':True,'journalId':journal,'identity':{'source':'lab','host':'gateway','nodeId':'gateway'}}
    n.atomic(str(BASE/'config.json'),cfg)
    return {'peerConfigured':True}


def gateway_install():
    if (STATE/'transactions.json').exists() and n.read_json(str(STATE/'transactions.json'))['transactions']:
        raise ValueError('fixture installation refuses an already used journal')
    # Whitelist the credential bundle; never extract arbitrary archive paths as root.
    allowed={'pki/ca.pem','pki/gateway.pem','pki/gateway.key','manager/public.pem','verifier/public.pem'}
    with tarfile.open('/home/lab/gateway-credentials.tar') as archive:
        if {member.name for member in archive.getmembers()} != allowed:raise ValueError('unsupported credential bundle')
        for member in archive.getmembers():
            if not member.isfile() or member.size > 65536:raise ValueError('unsafe credential member')
            relative=member.name if member.name.startswith('pki/') else 'trust/'+member.name
            protected(ETC/relative,archive.extractfile(member).read())
    info=gateway_initialize()
    cfg={'enabled':True,'journalId':info['journalId'],'identity':{'source':'lab','host':'gateway','nodeId':'gateway'},'managerKeys':str(ETC/'trust/manager'),'verifierKeys':str(ETC/'trust/verifier'),'secrets':str(ETC/'secrets'),'protectedAddresses':['192.0.2.1'],
         'terminalDelivery':{'url':'https://192.0.2.1:8443/api/network/execution/terminal','caFile':str(ETC/'pki/ca.pem'),'certFile':str(ETC/'pki/gateway.pem'),'keyFile':str(ETC/'pki/gateway.key')}}
    n.atomic(str(ETC/'network-executor.json'),cfg)
    target=Path('/opt/heliopause/agent');target.mkdir(mode=0o755,parents=True,exist_ok=True)
    for name in json.loads(Path('/source/package.json').read_text())['files']:
        if name.startswith('agent/') and name.endswith('.py'):
            shutil.copyfile('/source/'+name,target/Path(name).name);os.chmod(target/Path(name).name,0o644)
    environment={'HELIOPAUSE_RELAY_URL':'https://192.0.2.1:8444','HELIOPAUSE_CA_FILE':str(ETC/'pki/ca.pem'),'HELIOPAUSE_CERT_FILE':str(ETC/'pki/gateway.pem'),'HELIOPAUSE_KEY_FILE':str(ETC/'pki/gateway.key'),'HELIOPAUSE_TARGET':'lab','HELIOPAUSE_HOST_ID':'gateway','HELIOPAUSE_MANAGER_SIGNING_KEYS_DIR':str(ETC/'trust/manager'),'HELIOPAUSE_BREAK_GLASS_KEYS_DIR':str(ETC/'trust/verifier'),'HELIOPAUSE_INTERVAL_SEC':'1','HELIOPAUSE_NETWORK_DISCOVERY':'1','HELIOPAUSE_NETWORK_DISCOVERY_BUDGET':'5'}
    protected(ETC/'agent.env',''.join(key+'='+value+'\n' for key,value in environment.items()))
    units=Path('/etc/systemd/system')
    for name in ['heliopause-agent.service','heliopause-network-terminal.service']:
        shutil.copyfile('/source/packaging/systemd/'+name,units/name)
    drop=units/'heliopause-agent.service.d';drop.mkdir(exist_ok=True)
    for name in ['heliopause-agent-network.conf','heliopause-agent-networkmanager.conf']:
        shutil.copyfile('/source/packaging/systemd/'+name,drop/name)
    command('systemctl','daemon-reload')
    command('systemctl','enable','heliopause-agent.service','heliopause-network-terminal.service')
    return info


def peer_services():
    for name, executable in [
        ('manager', '/opt/node/bin/node /source/scripts/network-transaction-lab/manager.ts'),
        ('relay', '/usr/bin/python3 /source/scripts/network-transaction-lab/relay.py'),
    ]:
        protected('/etc/systemd/system/heliopause-vm-lab-'+name+'.service',
                  '[Unit]\nDescription=Disposable Heliopause VM lab '+name+'\nAfter=NetworkManager.service\n'
                  '[Service]\nType=simple\nWorkingDirectory=/source\nExecStart='+executable+' '+str(BASE)+'\n'
                  'Restart=on-failure\nRestartSec=1s\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n')
    command('systemctl','daemon-reload')
    command('systemctl','enable','--now','heliopause-vm-lab-manager.service','heliopause-vm-lab-relay.service')
    return {'servicesStarted':True}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--role',choices=['gateway','peer'],required=True);parser.add_argument('--nonce',required=True);parser.add_argument('--action',choices=['initialize','configure','install','services'],required=True);parser.add_argument('--gateway-public-key');parser.add_argument('--journal-id');args=parser.parse_args()
    guard(args.role,args.nonce)
    if args.action=='initialize':result=gateway_initialize() if args.role=='gateway' else peer_initialize()
    elif args.role=='peer' and args.action=='configure':result=peer_configure(args.gateway_public_key,args.journal_id)
    elif args.role=='gateway' and args.action=='install':result=gateway_install()
    elif args.role=='peer' and args.action=='services':result=peer_services()
    else:raise ValueError('unsupported fixture action')
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
