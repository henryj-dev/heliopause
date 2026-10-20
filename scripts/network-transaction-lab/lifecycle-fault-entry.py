"""Fault observer around the production entry function; no alternate scheduler or writer."""
import importlib.util
import os
import sys
import time
sys.path.insert(0,'/source/agent')
import network_executor as n
path,point=sys.argv[1:3]
Base=n.Executor
class Observed(Base):
    def __init__(self,config,directory,**kwargs):
        production_event=kwargs.pop('event',lambda _:None)
        def event(at):
            production_event(at)
            if at==point:
                n.atomic(path+'/state/barrier.json',{'point':at,'pid':os.getpid()})
                while True:time.sleep(.1)
        super().__init__(config,directory,event=event,**kwargs)
n.Executor=Observed
# Lifecycle imports Executor only after this hook. Recovery, admission and the heartbeat loop
# below are the actual shipping entry, with normal environment/credentials.
spec=importlib.util.spec_from_file_location('observed_agent','/source/agent/heliopause-pull.py')
agent=importlib.util.module_from_spec(spec);sys.modules[spec.name]=agent;spec.loader.exec_module(agent)
sys.argv=['agent','--network-executor','--config',path+'/config.json','--state-dir',path+'/state']
sys.exit(agent.run_writer_mode())
