#!/usr/bin/env python3
"""Pure synthetic acceptance checks; forbid host processes and sockets."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import socket
import sys
import unittest
import tempfile
import os
import json
from soak_inputs import source_modules, public_directory, file_commitment, frozen_inputs
from boot_cycle import Lab
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parent))
import soak


def sample():
    process={'pid':1,'active':'active','startTicks':1,'cpuTicks':0,'rssPages':10,'fdCount':5,'children':0}
    gateway={'journalId':'a'*32,'acceptedSequence':1,'terminalSequence':1,'bootId':'gateway-boot','deployedModules':{'agent.py':'b'*64},
             'at':100,'pageBytes':4096,'clockTicksPerSecond':100,'lifecycle':{'reportedAt':100,'agentPid':1,'heartbeat':{'lastSuccess':99},'discovery':{'enabled':True,'lastSuccess':99},'errors':{},'recoveryDebt':{'network':False,'firewall':False,'workload':False}},
             'frozenInputs':{'config':{'sha256':'config'}},'trust':{'manager':['key-a'],'verifier':['key-b']},'journalContentHash':'same','files':{name:{'bytes':1000,'sha256':'same'} for name in ['transactions.json','journal-identity.json','terminal-results.json','terminal-acks.json']},'transactions':{'tx':{'state':'confirmed','configurationMatches':True,'historicalAuthorityValid':True}}}
    peer={'bootId':'peer-boot','at':100,'pageBytes':4096,'clockTicksPerSecond':100,'ledger':{'fence':None},'deployedModules':{'src/manager-server.ts':'a'*64},'frozenInputs':{'config':{'sha256':'config'}}}
    for role in [gateway,peer]:role['targetBinding']={'journalId':'a'*32,'identity':{'source':'lab','host':'gateway','nodeId':'gateway'}}
    for key in ['agent','courier','networkManager']:gateway[key]=copy.deepcopy(process)
    for key in ['manager','relay']:peer[key]=copy.deepcopy(process)
    return {'gateway':gateway,'peer':peer,'observedAt':100,'packets':[{'at':99,'peerBootId':'peer-boot','management':True,'forward':True,'reverse':True}]}


class SoakAcceptance(unittest.TestCase):
    def setUp(self):
        self.initial=sample();self.current=copy.deepcopy(self.initial)
        for module,name in [(subprocess,'Popen'),(socket,'socket')]:
            guard=patch.object(module,name,side_effect=AssertionError('escaped host boundary'));guard.start();self.addCleanup(guard.stop)
    def check(self):return soak.assess(self.current,self.initial,{'gateway':{'agent.py':'b'*64},'peer':{'src/manager-server.ts':'a'*64}},'tx')
    def test_peer_module_drift_is_rejected(self):
        self.initial['peer']['deployedModules']={'src/manager-server.ts':'a'*64}
        self.current=copy.deepcopy(self.initial)
        self.current['peer']['deployedModules']['src/manager-server.ts']='b'*64
        with self.assertRaisesRegex(ValueError,'module'):self.check()
    def test_gateway_configuration_drift_is_rejected(self):
        self.initial['gateway']['frozenInputs']={'executor-config':{'sha256':'a'*64}}
        self.current=copy.deepcopy(self.initial)
        self.current['gateway']['frozenInputs']['executor-config']['sha256']='b'*64
        with self.assertRaisesRegex(ValueError,'configuration'):self.check()
    def test_peer_target_binding_drift_is_rejected(self):
        self.initial['peer']['frozenInputs']={'manager-config':{'sha256':'a'*64}}
        self.current=copy.deepcopy(self.initial)
        self.current['peer']['frozenInputs']['manager-config']['sha256']='b'*64
        with self.assertRaisesRegex(ValueError,'configuration'):self.check()
    def test_peer_unqualified_initial_source_is_rejected(self):
        self.current['peer']['deployedModules']['src/manager-server.ts']='b'*64
        self.initial=copy.deepcopy(self.current)
        with self.assertRaisesRegex(ValueError,'module'):self.check()
    def test_missing_initial_config_commitment_is_rejected(self):
        self.current['peer'].pop('frozenInputs');self.initial=copy.deepcopy(self.current)
        with self.assertRaisesRegex(ValueError,'configuration'):self.check()
    def test_initial_target_binding_mismatch_rejected(self):
        self.current['peer']['targetBinding']['identity']['host']='other'
        self.initial=copy.deepcopy(self.current)
        with self.assertRaisesRegex(ValueError,'binding mismatch'):self.check()
    def test_initial_agent_config_journal_mismatch_rejected(self):
        for role in ['gateway','peer']:self.current[role]['targetBinding']['journalId']='b'*32
        self.initial=copy.deepcopy(self.current)
        with self.assertRaisesRegex(ValueError,'binding mismatch'):self.check()
    def test_lifecycle_status_must_belong_to_current_agent(self):
        self.current['gateway']['lifecycle']['agentPid']=2
        with self.assertRaisesRegex(ValueError,'process identity'):self.check()
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


class FrozenInputBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for module,name in [(subprocess,'Popen'),(socket,'socket')]:
            guard=patch.object(module,name,side_effect=AssertionError('escaped host boundary'));guard.start();self.addCleanup(guard.stop)
    def test_source_manifest_measures_runtime_and_omits_tests(self):
        (self.root/'src').mkdir();(self.root/'src/manager.ts').write_text('runtime')
        (self.root/'src/manager.test.ts').write_text('test')
        for name in ['package.json','package-lock.json']:(self.root/name).write_text('{}')
        self.assertEqual(set(source_modules(self.root)),{'src/manager.ts','package.json','package-lock.json'})
    def test_source_directory_symlink_refused(self):
        (self.root/'src').symlink_to(self.root,target_is_directory=True)
        for name in ['package.json','package-lock.json']:(self.root/name).write_text('{}')
        with self.assertRaisesRegex(ValueError,'symlink'):source_modules(self.root)
    def test_hardlink_and_symlink_inputs_refused(self):
        path=self.root/'original';path.write_text('public');os.link(path,self.root/'linked')
        with self.assertRaisesRegex(ValueError,'unsafe'):file_commitment(path)
        (self.root/'sym').symlink_to(path)
        with self.assertRaisesRegex(ValueError,'unsafe'):file_commitment(self.root/'sym')
    def test_private_key_path_not_opened_as_public_trust(self):
        (self.root/'private.key').write_text('never inspect')
        with patch('soak_inputs.file_commitment',side_effect=AssertionError('private entry opened')):
            with self.assertRaisesRegex(ValueError,'public PEM'):public_directory(self.root)
    def test_private_pem_never_produces_commitment(self):
        (self.root/'public.pem').write_text('-----BEGIN '+ 'PRIVATE KEY-----\ninvalid\n')
        with self.assertRaisesRegex(ValueError,'public PEM'):public_directory(self.root)
    def test_peer_uses_real_shared_manager_relay_certificate_layout(self):
        base=self.root/'peer';base.mkdir();(base/'pki').mkdir()
        (base/'config.json').write_text('{}');(base/'lifecycle-revocations.json').write_text('{}')
        for name in ['ca.pem','gateway.pem','manager.pem']:
            (base/'pki'/name).write_text('-----BEGIN CERTIFICATE-----\npublic')
        for role in ['manager','verifier']:
            (base/role).mkdir();(base/role/'public.pem').write_text('-----BEGIN PUBLIC KEY-----\npublic')
        result=frozen_inputs('peer',{'lifecycleRevocations':True},base=base)
        self.assertEqual(set(result['files']),{str(base/'config.json'),str(base/'lifecycle-revocations.json')}|{str(base/'pki'/n)for n in ['ca.pem','gateway.pem','manager.pem']})
    def test_declared_private_inode_refused_before_open(self):
        path=self.root/'key';path.write_text('private');info=path.stat()
        with patch('soak_inputs.os.open',side_effect=AssertionError('private path opened')):
            with self.assertRaisesRegex(ValueError,'private key alias'):file_commitment(path,forbidden={(info.st_dev,info.st_ino)})
    def test_change_during_read_refused_without_hash(self):
        path=self.root/'config';path.write_text('before');original=os.fstat;calls=0
        def altered(fd):
            nonlocal calls
            calls+=1
            if calls==2:path.write_text('after!')
            return original(fd)
        with patch('soak_inputs.os.fstat',side_effect=altered):
            with self.assertRaisesRegex(ValueError,'changed during read'):file_commitment(path)
    def test_certificate_extension_never_controls_public_type_check(self):
        etc=self.root/'etc';etc.mkdir();(etc/'pki').mkdir()
        for name in ['network-executor.json','agent.env']:(etc/name).write_text('{}')
        for name in ['ca.pem','gateway.pem']:(etc/'pki'/name).write_text('-----BEGIN CERTIFICATE-----\npublic')
        certificate=self.root/'alternate-cert';certificate.write_text('-----BEGIN '+ 'PRIVATE KEY-----\nprivate')
        key=self.root/'key';key.write_text('declared private')
        cfg={'managerKeys':'unused','verifierKeys':'unused','terminalDelivery':{'caFile':str(etc/'pki/ca.pem'),'certFile':str(certificate),'keyFile':str(key)}}
        with patch('soak_inputs.public_directory',return_value={}):
            with self.assertRaisesRegex(ValueError,'public PEM'):frozen_inputs('gateway',cfg,etc=etc)
        cfg['terminalDelivery']['certFile']=str(key)
        with patch('soak_inputs.file_commitment',side_effect=AssertionError('key opened')):
            with self.assertRaisesRegex(ValueError,'private key alias'):frozen_inputs('gateway',cfg,etc=etc)
    def test_ssh_ports_are_explicit_and_preserve_default(self):
        (self.root/'environment.json').write_text(json.dumps({'labNonce':'test'}))
        self.assertEqual(Lab(self.root).ssh_ports,{'gateway':22220,'peer':22221})
        lab=Lab(self.root,ssh_ports={'gateway':22228,'peer':22229})
        with patch('boot_cycle.run',return_value=b'ok')as run:
            self.assertEqual(lab.ssh('gateway','true'),b'ok')
        self.assertEqual(run.call_args.args[0][run.call_args.args[0].index('-p')+1],'22228')
    def test_bad_ports_refused_before_transport(self):
        (self.root/'environment.json').write_text(json.dumps({'labNonce':'test'}))
        for ports in [{'gateway':True,'peer':22},{'gateway':22,'peer':22},{'gateway':0,'peer':23},{'gateway':22}]:
            with self.subTest(ports=ports),self.assertRaisesRegex(ValueError,'SSH ports'):Lab(self.root,ssh_ports=ports)


if __name__=='__main__':unittest.main()
