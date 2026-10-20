"""Separate verifier process/namespace: independent management + both actual workload directions.
Lab-only CAP_SYS_ADMIN permits read-only probes in target namespaces. No Agent status bit is used.
"""
import json
import os
import subprocess
import sys
sys.path.insert(0,'/source/agent')
import network_executor as n
path=sys.argv[1]


def run(ns,*args):
    command=['ip','netns','exec',ns]+list(args) if ns else list(args)
    result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=4)
    return result.returncode==0,result.stdout.decode()


def ip(*args):
    ok,out=run('p6-gw','ip','-j',*args)
    return json.loads(out) if ok else []


op=n.read_json(path+'/decoded.json')['operation']
DEV=op['interfaceName']
links=ip('-d','link','show','dev',DEV)
addresses=ip('address','show','dev',DEV)
check={}
check['interface']=len(links)==1 and links[0].get('linkinfo',{}).get('info_kind')=='wireguard' and links[0]['mtu']==op['mtu'] and 'UP' in links[0].get('flags',[])
check['address']=bool(addresses) and any(a['local']==op['address'].split('/')[0] and a['prefixlen']==32 for a in addresses[0].get('addr_info',[]))
check['route']=all(any(r.get('dst') in {dst,dst.split('/')[0]} and r.get('dev')==DEV for r in ip('route','show','table','main')) for dst in op['routes'])
check['fib']=all(any(r.get('dev')==DEV for r in ip('route','get',dst.split('/')[0])) for dst in op['routes'])
source,destination=('198.51.100.10','198.51.100.14') if op['address']=='192.0.2.145/32' else ('198.51.100.2','198.51.100.6')
check['forward']=run('p6-client','ping','-n','-I',source,'-c','2','-W','1',destination)[0]
check['reverse']=run('p6-workload','ping','-n','-I',destination,'-c','2','-W','1',source)[0]
# This process is already in verifier namespace; this ping crosses the management veth.
check['management']=run(None,'ping','-n','-c','2','-W','1','192.0.2.2')[0]
ok,handshakes=run('p6-gw','wg','show',DEV,'latest-handshakes')
check['handshake']=ok and bool(handshakes.strip()) and all(int(line.split()[1])>0 for line in handshakes.splitlines())
check['protected']=any(r.get('dst')=='192.0.2.0/30' and r.get('dev')=='mgmt' for r in ip('route','show')) and any(a['local']=='192.0.2.2' for x in ip('address','show','dev','mgmt') for a in x.get('addr_info',[]))
n.atomic(path+'/verification.json',check)
subprocess.run(['node','--experimental-strip-types','scripts/network-transaction-lab/authority.ts','verify',path],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
