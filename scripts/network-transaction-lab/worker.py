"""Lab fault injector. All external writes/rollback still use the production Agent executor."""
import os
import sys
import time
sys.path.insert(0,'/source/agent')
import network_executor as n

config=n.read_json(sys.argv[1])
state=sys.argv[2]
fault=sys.argv[3] if len(sys.argv)>3 else ''


def event(point):
    if fault==point:
        # Parent sends SIGKILL after observing this persistent lab-only barrier.
        n.atomic(state+'/barrier.json',{'point':point})
        while True: time.sleep(1)
    if fault=='fail-'+point:
        raise RuntimeError('lab injected failure')


# Same process lock, recovery and loop as the production entry point, with an observer hook only.
executor=n.Executor(config,state,event=event)
if fault in {'first-route','raw-create','foreign-create'}:
    original=executor.driver.run
    def first_route(args,*a,**kw):
        if fault=='foreign-create' and args[:3]==['ip','link','add']:
            original(['ip','link','add','name',args[4],'type','wireguard'])
        result=original(args,*a,**kw)
        if (fault=='first-route' and args[:3]==['ip','route','add']) or (fault=='raw-create' and args[:3]==['ip','link','add']):
            n.atomic(state+'/barrier.json',{'point':'first-route'})
            while True: time.sleep(1)
        return result
    executor.driver.run=first_route
fd=os.open(state+'/worker.lock',os.O_RDWR|os.O_CREAT,0o600)
n.fcntl.flock(fd,n.fcntl.LOCK_EX|n.fcntl.LOCK_NB)
executor.recover()
if os.path.exists(state+'/request.json'):
    try:
        result=executor.accept(n.read_json(state+'/request.json'))
        n.atomic(state+'/response.json',{'state':result})
    except Exception as e:
        n.atomic(state+'/response.json',{'state':'rejected','error':n.safe_diagnostic(e)})
while True:
    if os.path.exists(state+'/confirm.json'):
        try:
            result=executor.confirm(n.read_json(state+'/confirm.json'))
            n.atomic(state+'/response.json',{'state':result})
        except Exception as e:
            n.atomic(state+'/response.json',{'state':'rejected','error':n.safe_diagnostic(e)})
        os.unlink(state+'/confirm.json')
    executor.tick()
    time.sleep(0.1)
