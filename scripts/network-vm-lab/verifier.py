#!/usr/bin/env python3
"""Independent peer-side collector; reads gateway kernel over the isolated management link.

No Agent state bit establishes any check. A warm mTLS client waits for the verifier signature,
then asks the real Manager to confirm and delivers its envelope to the production mailbox.
"""
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import ssl
import subprocess
import sys
import time
import urllib.request

BASE=Path('/var/lib/heliopause-vm-lab')


def ssh(*args,data=None):
    command=['ssh','-i',str(BASE/'gateway-console.key'),'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(BASE/'known_hosts'),'-o','HostKeyAlias=heliopause-gateway','-o','ConnectTimeout=3','lab@192.0.2.2',shlex.join(args)]
    result=subprocess.run(command,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12)
    if result.returncode:raise RuntimeError('gateway management probe failed: '+result.stderr.decode()[-2048:])
    return result.stdout


def ping(namespace,source,destination):
    command=(['ip','netns','exec',namespace] if namespace else [])+['ping','-n','-I',source,'-c','2','-W','1',destination]
    start=time.time()
    result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
    return {'success':result.returncode==0,'startedAt':start,'completedAt':time.time(),'output':result.stdout.decode()[-2048:]}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('redirect refused')


def gateway_probe_code(marker,dev,routes):
    # Values are Python literals, never text replacements inside the program.
    prefix='EXPECTED_MARKER='+repr(marker)+'\nDEV='+repr(dev)+'\nROUTES='+repr(routes)+'\n'
    return prefix+'''import json,subprocess,time,pathlib
r=lambda a:subprocess.run(a,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3)
def ip(*a):
 p=r(['ip','-j']+list(a));return json.loads(p.stdout) if p.returncode==0 else []
marker=json.loads(pathlib.Path('/etc/heliopause-disposable-lab').read_text())
assert marker==EXPECTED_MARKER
p=r(['wg','show',DEV,'latest-handshakes'])
print(json.dumps({'bootId':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'now':time.time(),
'links':ip('-d','link','show','dev',DEV),'addresses':ip('address','show','dev',DEV),
'routes':ip('-4','route','show','table','main'),'fibs':[ip('-4','route','get',dst.split('/')[0]) for dst in ROUTES],
'managementFib':ip('-4','route','get','192.0.2.1'),'underlayFib':ip('-4','route','get','203.0.113.2'),
'managementAddresses':ip('address','show','dev','mgmt'),'handshakes':p.stdout.decode().strip() if p.returncode==0 else ''}))
'''


def evaluate(gateway,op,traffic):
    dev=op['interfaceName']
    links=gateway['links'];addresses=gateway['addresses'];handshakes=[line.split() for line in gateway['handshakes'].splitlines()]
    checks={key:value['success'] for key,value in traffic.items()}
    checks.update(interface=len(links)==1 and links[0].get('linkinfo',{}).get('info_kind')=='wireguard' and links[0]['mtu']==op['mtu'] and 'UP' in links[0].get('flags',[]),
                  address=bool(addresses) and any(value['local']+'/'+str(value['prefixlen'])==op['address'] for value in addresses[0].get('addr_info',[])),
                  route=all(any(row.get('dst') in {dst,dst.split('/')[0]} and row.get('dev')==dev and row.get('metric')==42760 and row.get('protocol')=='static' for row in gateway['routes']) for dst in op['routes']),
                  fib=all(bool(rows) and rows[0].get('dev')==dev for rows in gateway['fibs']),
                  handshake=len(handshakes)==len(op['peers']) and {row[0] for row in handshakes}=={peer['publicKey'] for peer in op['peers']} and all(len(row)==2 and int(row[1])>0 and abs(gateway['now']-int(row[1]))<120 for row in handshakes),
                  protected=bool(gateway['managementFib']) and gateway['managementFib'][0].get('dev')=='mgmt' and bool(gateway['underlayFib']) and gateway['underlayFib'][0].get('dev')=='underlay' and any(value.get('local')=='192.0.2.2' for row in gateway['managementAddresses'] for value in row.get('addr_info',[])))
    return checks


def main():
    mode=sys.argv[1]
    if mode not in {'confirm','observe'}:raise ValueError('unsupported verifier mode')
    marker=json.loads(Path('/etc/heliopause-disposable-lab').read_text())
    if os.geteuid()!=0 or marker['role']!='peer':raise ValueError('marked peer required')
    envelope=json.loads((BASE/'authorization.json').read_text())
    a=json.loads(base64.urlsafe_b64decode(envelope['payload']+'=='));op=a['operation'];dev=op['interfaceName']
    if not re.fullmatch(r'hp[a-f0-9]{12}',dev) or not 1<=len(op['routes'])<=16:raise ValueError('unsupported probe target')
    for route in op['routes']:
        if ipaddress.ip_network(route).version!=4 or ipaddress.ip_network(route).prefixlen!=32:raise ValueError('bounded host route required')
    # Prepare TLS before packet observation so interpreter/TLS setup is not misreported as fresh observation time.
    context=ssl.create_default_context(cafile=str(BASE/'pki/ca.pem'))
    context.load_cert_chain(str(BASE/'pki/alice.pem'),str(BASE/'pki/alice.key'))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context),NoRedirect())
    code=gateway_probe_code({'role':'gateway','nonce':marker['nonce']},dev,op['routes'])
    gateway=json.loads(ssh('sudo','python3','-',data=code.encode()))
    traffic={'forward':ping('p6-client','198.51.100.2','198.51.100.6'),
             'reverse':ping('p6-workload','198.51.100.6','198.51.100.2'),
             'management':ping(None,'192.0.2.1','192.0.2.2')}
    checks=evaluate(gateway,op,traffic)
    result={'kind':'probe','transactionId':a['transactionId'],'observedAt':int(time.time()*1000),'checks':checks,'gateway':gateway,'traffic':traffic}
    print(json.dumps(result),flush=True)
    if mode=='observe':return
    message=json.loads(sys.stdin.readline(180000))
    if set(message)!={'receipt','hash'}:raise ValueError('unsupported confirmation message')
    request=urllib.request.Request('https://192.0.2.1:8443/api/network/execution/confirm',data=json.dumps({'hash':message['hash'],'verification':message['receipt']}).encode(),headers={'Content-Type':'application/json'},method='POST')
    with opener.open(request,timeout=3) as response:reply=json.loads(response.read(180000))
    confirmation=reply['envelope']
    delivery="import sys,json;sys.path.insert(0,'/opt/heliopause/agent');import network_executor as n;n.atomic('/var/lib/heliopause/network-executor/confirm.json',json.load(sys.stdin))"
    ssh('sudo','python3','-c',delivery,data=json.dumps(confirmation).encode())
    print(json.dumps({'kind':'delivered','deliveredAt':time.time(),'confirmation':confirmation}),flush=True)


if __name__=='__main__':main()
