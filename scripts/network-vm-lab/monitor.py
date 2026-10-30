#!/usr/bin/env python3
"""Independent bounded packet timeline on the surviving, explicitly marked peer."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import signal
import threading
import subprocess
import sys
import time
sys.path.insert(0,'/source/agent')
import network_executor as n
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from probe_pairs import pair_for


def ping(namespace, source, destination):
    prefix=['ip','netns','exec',namespace] if namespace else []
    try:return subprocess.run(prefix+['ping','-n','-c','1','-W','1','-I',source,destination],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2).returncode==0
    except subprocess.TimeoutExpired:return False


def parse(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--nonce',required=True);parser.add_argument('--id',required=True);parser.add_argument('--route',action='append',required=True)
    return parser.parse_args(argv)


def main():
    args=parse()
    if os.geteuid()!=0 or not re.fullmatch('[a-f0-9]{32}',args.id) or n.read_json('/etc/heliopause-disposable-lab')!={'role':'peer','nonce':args.nonce}:raise ValueError('marked disposable peer required')
    directory=Path('/var/lib/heliopause-vm-lab/observations');directory.mkdir(mode=0o700,exist_ok=True)
    fd=os.open(directory/(args.id+'.jsonl'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    (client_ns,client),(workload_ns,workload)=pair_for(args.route)
    boot=n.current_boot_id();deadline=time.monotonic()+900
    stop=threading.Event();signal.signal(signal.SIGTERM,lambda *_:stop.set())
    with os.fdopen(fd,'w') as stream,ThreadPoolExecutor(max_workers=3) as pool:
        first=True
        while time.monotonic()<deadline and not stop.is_set():
            jobs={name:pool.submit(ping,*values) for name,values in {'management':(None,'192.0.2.1','192.0.2.2'),'forward':(client_ns,client,workload),'reverse':(workload_ns,workload,client)}.items()}
            record={'at':time.time(),'peerBootId':boot,**{name:job.result() for name,job in jobs.items()}}
            stream.write(json.dumps(record)+'\n');stream.flush();os.fsync(stream.fileno())
            if first:n.atomic(str(directory/(args.id+'.ready')),{'peerBootId':boot});first=False
            stop.wait(.25)


if __name__=='__main__':main()
