#!/usr/bin/env python3
"""Freeze at a shipping Executor durable boundary inside a marked disposable gateway.

No alternate apply/rollback implementation. The production entry, mailbox, writer lock,
watchdog and service sandbox remain in use. Remove the test ExecStart override before boot.
"""
import importlib.util
import os
import sys
import signal
import threading

POINTS = {'prepared','applying','created','configured','awaiting-verification','awaiting-confirm','rolling-back','rollback-failed','removed'}


def boundary_event(production, point, record, freeze, hold):
    """Wrap the Executor's event hook so the thread that reaches `point` never passes it.

    SIGSTOP alone was not a barrier: it is raised from the network-mailbox thread, the stop is
    asynchronous, and systemd's SIGCONT on stop resumes the process. The 2026-10-30 lab case
    03-awaiting-confirm-graceful-r2 committed its confirmation after the barrier that way. So the
    reaching thread also parks in `hold`, which never returns. Other threads still run once the
    process is continued; only this thread's progress past the boundary is held.
    """
    def event(at):
        production(at)
        if at == point:
            record(at)
            freeze()
            hold()
    return event


def park():
    threading.Event().wait()


def main():
    sys.path.insert(0,'/opt/heliopause/agent')
    import network_executor as n
    point,nonce=sys.argv[1:]
    if point not in POINTS:
        raise ValueError('unsupported durable boundary')
    marker=n.read_json('/etc/heliopause-disposable-lab')
    if os.geteuid()!=0 or marker!={'role':'gateway','nonce':nonce}:
        raise ValueError('explicit disposable gateway required')
    Base=n.Executor
    class Observed(Base):
        def __init__(self,*args,**kwargs):
            def record(at):
                n.atomic('/var/lib/heliopause/network-executor/lab-barrier.json',{'point':at,'pid':os.getpid(),'thread':threading.current_thread().name,'bootId':n.current_boot_id(),'transactionId':getattr(self,'current_transaction',None)})
            event=boundary_event(kwargs.pop('event',lambda _:None),point,record,lambda:os.kill(os.getpid(),signal.SIGSTOP),park)
            super().__init__(*args,event=event,**kwargs)
    n.Executor=Observed
    spec=importlib.util.spec_from_file_location('observed_agent','/opt/heliopause/agent/heliopause-pull.py')
    agent=importlib.util.module_from_spec(spec);sys.modules[spec.name]=agent;spec.loader.exec_module(agent)
    sys.argv=['agent']
    sys.exit(agent.run_writer_mode())


if __name__=='__main__':main()
