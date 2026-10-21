#!/usr/bin/env python3
"""Pure synthetic acceptance checks; forbid host processes and sockets."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import socket
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parent))
import soak


def sample():
    process={'pid':1,'active':'active','startTicks':1,'cpuTicks':0,'rssPages':10,'fdCount':5,'children':0}
    gateway={'journalId':'a'*32,'acceptedSequence':1,'terminalSequence':1,'bootId':'gateway-boot','deployedModules':{'agent.py':'b'*64},
             'at':100,'pageBytes':4096,'clockTicksPerSecond':100,'lifecycle':{'reportedAt':100,'heartbeat':{'lastSuccess':99},'discovery':{'enabled':True,'lastSuccess':99},'errors':{},'recoveryDebt':{'network':False,'firewall':False,'workload':False}},
             'trust':{'manager':['key-a'],'verifier':['key-b']},'journalContentHash':'same','files':{name:{'bytes':1000,'sha256':'same'} for name in ['transactions.json','journal-identity.json','terminal-results.json','terminal-acks.json']},'transactions':{'tx':{'state':'confirmed','configurationMatches':True,'historicalAuthorityValid':True}}}
    peer={'bootId':'peer-boot','at':100,'pageBytes':4096,'clockTicksPerSecond':100,'ledger':{'fence':None}}
    for key in ['agent','courier','networkManager']:gateway[key]=copy.deepcopy(process)
    for key in ['manager','relay']:peer[key]=copy.deepcopy(process)
    return {'gateway':gateway,'peer':peer,'observedAt':100,'packets':[{'at':99,'peerBootId':'peer-boot','management':True,'forward':True,'reverse':True}]}


class SoakAcceptance(unittest.TestCase):
    def setUp(self):
        self.initial=sample();self.current=copy.deepcopy(self.initial)
        for module,name in [(subprocess,'Popen'),(socket,'socket')]:
            guard=patch.object(module,name,side_effect=AssertionError('escaped host boundary'));guard.start();self.addCleanup(guard.stop)
    def check(self):return soak.assess(self.current,self.initial,{'agent.py':'b'*64},'tx')
    def test_baseline_pass(self):self.check()
    def test_interrupted_long_run_cannot_emit_success(self):
        self.assertFalse(soak.succeeded(None,False,0,86405,1440,10,86404))
    def test_short_packet_span_cannot_pass(self):
        self.assertFalse(soak.succeeded(None,True,0,86405,1440,10,86404))
    def test_cleanup_failure_cannot_pass(self):
        self.assertFalse(soak.succeeded({'type':'CleanupError'},True,0,86405,1440,0,86404))
    def test_complete_run_can_pass(self):
        self.assertTrue(soak.succeeded(None,True,0,86405,1440,0,86404))
    def test_short_run_cannot_pass(self):self.assertFalse(soak.completed(0,86399,2000))
    def test_sparse_run_cannot_pass(self):self.assertFalse(soak.completed(0,90000,1439))
    def test_full_duration_and_samples(self):self.assertTrue(soak.completed(100,86500,1440))
    def test_replay_reset(self):
        self.current['gateway']['acceptedSequence']=0
        with self.assertRaisesRegex(ValueError,'replay'):self.check()
    def test_initial_fence_rejected(self):
        self.initial['peer']['ledger']['fence']='pending';self.current=copy.deepcopy(self.initial)
        with self.assertRaisesRegex(ValueError,'fence'):self.check()
    def test_confirmed_target_missing(self):
        self.current['gateway']['transactions']={}
        with self.assertRaisesRegex(ValueError,'confirmed target'):self.check()
    def test_trust_changed(self):
        self.current['gateway']['trust']={}
        with self.assertRaisesRegex(ValueError,'trust'):self.check()
    def test_degraded_refused(self):
        self.current['gateway']['transactions']['tx']['bootRestore']={'state':'attempting'};self.initial=copy.deepcopy(self.current)
        with self.assertRaisesRegex(ValueError,'configuration mismatch'):self.check()
    def test_discovery_recovered_failure_refused(self):
        self.current['gateway']['lifecycle']['discovery']['lastFailure']=100
        with self.assertRaisesRegex(ValueError,'discovery'):self.check()
    def test_batch_packet_gap(self):
        self.current['packets'].insert(0,{**self.current['packets'][0],'at':50})
        with self.assertRaisesRegex(ValueError,'timeline gap'):self.check()
    def test_cross_batch_gap(self):
        self.current['previousPacketAt']=50
        with self.assertRaisesRegex(ValueError,'timeline gap'):self.check()
    def test_duplicate_packet(self):
        self.current['previousPacketAt']=99
        with self.assertRaisesRegex(ValueError,'timeline gap'):self.check()
    def test_fixed_schedule_excludes_collection_time(self):
        self.assertEqual(soak.next_delay(100,1,120),40)
        self.assertEqual(soak.next_delay(100,2,180),40)
        with self.assertRaisesRegex(ValueError,'overrun'):soak.next_delay(100,1,221)
    def test_expected_modules(self):
        self.current['gateway']['deployedModules']={}
        with self.assertRaisesRegex(ValueError,'module drift'):self.check()
    def test_packet_loss(self):
        self.current['packets'][0]['reverse']=False
        with self.assertRaisesRegex(ValueError,'packet loss'):self.check()
    def test_stale_packet(self):
        self.current['packets'][0]['at']=0
        with self.assertRaisesRegex(ValueError,'stale packet'):self.check()
    def test_same_pid_different_process(self):
        self.current['gateway']['agent']['startTicks']=2
        with self.assertRaisesRegex(ValueError,'process restart'):self.check()
    def test_actual_reboot(self):
        self.current['gateway']['bootId']='new-boot'
        with self.assertRaisesRegex(ValueError,'reboot'):self.check()
    def test_resource_growth(self):
        self.current['gateway']['agent']['fdCount']=257
        with self.assertRaisesRegex(ValueError,'resource budget'):self.check()
    def test_cpu_limit(self):
        self.current['gateway']['at']=101;self.current['gateway']['agent']['cpuTicks']=200
        with self.assertRaisesRegex(ValueError,'CPU budget'):self.check()
    def test_manager_fence(self):
        self.current['peer']['ledger']['fence']='debt'
        with self.assertRaisesRegex(ValueError,'Manager fence'):self.check()
    def test_heartbeat_failure(self):
        self.current['gateway']['lifecycle']['heartbeat']['lastFailure']=100
        with self.assertRaisesRegex(ValueError,'heartbeat'):self.check()
    def test_discovery_stale(self):
        self.current['gateway']['lifecycle']['discovery']['lastSuccess']=-300
        with self.assertRaisesRegex(ValueError,'discovery'):self.check()
    def test_recovery_debt(self):
        self.current['gateway']['transactions']['tx']['bootRestore']={'recovery':'rollback-failed'};self.initial=copy.deepcopy(self.current)
        with self.assertRaisesRegex(ValueError,'recovery debt'):self.check()
    def test_profile_drift(self):
        self.current['gateway']['transactions']['tx']['configurationMatches']=False;self.initial=copy.deepcopy(self.current)
        with self.assertRaisesRegex(ValueError,'configuration mismatch'):self.check()
    def test_journal_capacity(self):
        self.current['gateway']['files']['transactions.json']['bytes']=7*1024*1024
        with self.assertRaisesRegex(ValueError,'reserve exhausted'):self.check()


if __name__=='__main__':unittest.main()
