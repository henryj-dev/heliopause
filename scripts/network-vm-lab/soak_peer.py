#!/usr/bin/env python3
"""Bounded long observation on the independent peer; never changes gateway resources."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import signal
import threading
import time
from monitor import ping
from guest_fixture import guard


def main():
    p=argparse.ArgumentParser();p.add_argument('--nonce',required=True);p.add_argument('--id',required=True);p.add_argument('--seconds',type=int,required=True);a=p.parse_args()
    guard('peer',a.nonce)
    if not re.fullmatch('[a-f0-9]{32}',a.id) or not 86400<=a.seconds<=90000:raise ValueError('bounded 24h observation required')
    directory=Path('/var/lib/heliopause-vm-lab/observations');directory.mkdir(mode=0o700,exist_ok=True)
    fd=os.open(directory/('soak-'+a.id+'.jsonl'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    stop=threading.Event();signal.signal(signal.SIGTERM,lambda *_:stop.set())
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();deadline=time.monotonic()+a.seconds
    with os.fdopen(fd,'w') as stream,ThreadPoolExecutor(max_workers=3) as pool:
        while time.monotonic()<deadline and not stop.is_set():
            jobs={k:pool.submit(ping,*values) for k,values in {'management':(None,'192.0.2.1','192.0.2.2'),'forward':('p6-client','198.51.100.2','198.51.100.6'),'reverse':('p6-workload','198.51.100.6','198.51.100.2')}.items()}
            row={'at':time.time(),'peerBootId':boot,**{k:job.result() for k,job in jobs.items()}}
            stream.write(json.dumps(row)+'\n');stream.flush();os.fsync(stream.fileno())
            if stream.tell()>8*1024*1024:raise ValueError('packet evidence capacity exhausted')
            stop.wait(5)


if __name__=='__main__':main()
