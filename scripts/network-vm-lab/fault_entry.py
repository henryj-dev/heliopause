#!/usr/bin/env python3
"""Freeze at a shipping Executor durable boundary inside a marked disposable gateway.

No alternate apply/rollback implementation. The production entry, mailbox, writer lock,
watchdog and service sandbox remain in use. Remove the test ExecStart override before boot.
"""
import importlib.util
import os
import sys
import signal
sys.path.insert(0,'/opt/heliopause/agent')
import network_executor as n

point,nonce=sys.argv[1:]
if point not in {'prepared','applying','created','configured','awaiting-verification','awaiting-confirm','rolling-back','rollback-failed','removed'}:
    raise ValueError('unsupported durable boundary')
marker=n.read_json('/etc/heliopause-disposable-lab')
if os.geteuid()!=0 or marker!={'role':'gateway','nonce':nonce}:
    raise ValueError('explicit disposable gateway required')
Base=n.Executor
class Observed(Base):
    def __init__(self,*args,**kwargs):
        production=kwargs.pop('event',lambda _:None)
        def event(at):
            production(at)
            if at==point:
                n.atomic('/var/lib/heliopause/network-executor/lab-barrier.json',{'point':at,'pid':os.getpid(),'bootId':n.current_boot_id(),'transactionId':getattr(self,'current_transaction',None)})
                os.kill(os.getpid(),signal.SIGSTOP)
        super().__init__(*args,event=event,**kwargs)
n.Executor=Observed
spec=importlib.util.spec_from_file_location('observed_agent','/opt/heliopause/agent/heliopause-pull.py')
agent=importlib.util.module_from_spec(spec);sys.modules[spec.name]=agent;spec.loader.exec_module(agent)
sys.argv=['agent']
sys.exit(agent.run_writer_mode())
