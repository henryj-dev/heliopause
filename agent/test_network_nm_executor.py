"""Production Executor state transitions with isolated signatures/driver and fatal host boundaries."""
import copy
import os
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import network_executor as n
from network_nm_profile import DRIVER, BOOT_POLICY, profile_uuid
from test_network_executor import Fake, authorization

BOOT_A = '11111111-1111-1111-1111-111111111111'
BOOT_B = '22222222-2222-2222-2222-222222222222'


class PersistentFake(Fake):
    def __init__(self, directory):
        super().__init__(); self.directory=directory; self.restores=0; self.undos=0; self.restore_failure=False
    def bind(self, row): self.row=row
    def prepare(self, row): return {'profileUuid':row['authorization']['operation']['profileUuid'], 'profileHash':'f'*64, 'stagingName':'fixture'}
    def create(self, op, owner):
        saved=n.read_json(self.directory+'/transactions.json')['transactions'][self.row['authorization']['transactionId']]
        if saved.get('persistence') != self.prepare(self.row) or 'authorization' not in saved.get('restorationAuthority',{}):
            raise AssertionError('first write escaped durable undo/authority')
        super().create(op,owner)
    def prepare_restore(self, row, protected): return {'wasActive':False, 'before':{'boot':'fresh'}, 'paths':{'mgmt':'fresh'}}
    def restore(self, row, protected):
        saved=n.read_json(self.directory+'/transactions.json')['transactions'][row['authorization']['transactionId']]
        if saved['bootRestore'].get('plan') != row['bootRestore']['plan']: raise AssertionError('restore escaped durable undo')
        self.restores+=1;self.exists=True
        if self.restore_failure: raise ValueError('injected restoration mismatch')
    def undo_restore(self, row): self.undos+=1;self.exists=False


class Persistence(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        for module,name in [(subprocess,'run'),(subprocess,'Popen'),(socket,'socket')]:
            guard=patch.object(module,name,side_effect=AssertionError('escaped persistence unit boundary'));guard.start();self.addCleanup(guard.stop)
        for target,kwargs in [('crypto_helpers',{'return_value':object()}),('independent_trust',{'return_value':None}),('verify',{'side_effect':lambda value,*args:value}),('current_boot_id',{'return_value':BOOT_A})]:
            guard=patch.object(n,target,**kwargs);guard.start();self.addCleanup(guard.stop)
        self.a=authorization();self.a['journalId']=n.initialize_journal(self.temp.name)
        self.a['operation'].update(driver=DRIVER,profileUuid=profile_uuid(self.a['transactionId']),bootPolicy=BOOT_POLICY)
        self.a['artifactHash']=n.digest(self.a['operation'])
        self.a['approval']['planHash']='sha256:'+n.digest({k:v for k,v in self.a.items() if k!='approval'})
        self.driver=PersistentFake(self.temp.name)
        self.cfg={'enabled':True,'journalId':self.a['journalId'],'identity':self.a['target'],'managerKeys':'unused','verifierKeys':'unused','secrets':'unused','protectedAddresses':['192.0.2.1']}
        self.e=n.Executor(self.cfg,self.temp.name,self.driver)
    def row(self): return self.e.load()['transactions'][self.a['transactionId']]
    def confirm(self):
        self.e.accept(self.a);now=int(time.time()*1000)
        v={'transactionId':self.a['transactionId'],'authorizationHash':n.digest(self.a),'artifactHash':self.a['artifactHash'],'observedAt':now,'expiresAt':now+2000,'nonce':'a'*32,'checks':{k:True for k in n.CHECKS}}
        c={'transactionId':self.a['transactionId'],'authorizationHash':n.digest(self.a),'artifactHash':self.a['artifactHash'],'expiresAt':now+3000,'verification':v}
        self.e.confirm(c)
    def test_first_persistent_write_has_durable_undo_and_authority(self):
        self.e.accept(self.a)
        self.assertEqual(self.row()['persistence'],self.driver.prepare(self.row()))
        self.assertEqual(self.row()['restorationAuthority']['authorization'],self.a)
    def test_confirm_preserves_signed_restoration_evidence(self):
        self.confirm();row=self.row()
        self.assertEqual(row['bootIdAtConfirm'],BOOT_A)
        self.e.validate_restore_authority(row,self.a['journalId'])
        self.assertNotIn('before',row)
        self.assertIn('confirmation',row['restorationAuthority'])
    def test_same_boot_restart_and_shutdown_undo_do_not_restore(self):
        self.confirm();self.e.restore_confirmed_boot();self.e.recover()
        self.assertEqual(self.driver.restores,0)
    def test_new_boot_restores_without_reaccepting_or_new_terminal_sequence(self):
        self.confirm();before=self.e.load();self.driver.exists=False
        with patch.object(n,'current_boot_id',return_value=BOOT_B):self.e.restore_confirmed_boot()
        after=self.e.load();self.assertEqual(self.driver.restores,1)
        self.assertEqual(after['acceptedSequence'],before['acceptedSequence'])
        self.assertEqual(after['terminalSequence'],before['terminalSequence'])
        self.assertEqual(self.row()['bootRestore']['currentConnectivity'],'unknown')
    def test_disabled_new_execution_still_restores_confirmed(self):
        self.confirm();self.e.config['enabled']=False
        with patch.object(n,'current_boot_id',return_value=BOOT_B):self.e.restore_confirmed_boot()
        self.assertEqual(self.driver.restores,1)
    def test_unconfirmed_is_undone_not_restored_on_new_boot(self):
        self.e.accept(self.a)
        with patch.object(n,'current_boot_id',return_value=BOOT_B):self.e.recover();self.e.restore_confirmed_boot()
        self.assertEqual(self.row()['state'],'rolled-back');self.assertEqual(self.driver.restores,0)
    def test_only_readonly_preparation_timeout_retries_before_one_activation(self):
        self.confirm();plan=self.driver.prepare_restore(self.row(),[])
        with patch.object(self.driver,'prepare_restore',side_effect=[RuntimeError('network command unavailable or timed out: python3 helper'),plan]) as prepare:
            with patch.object(n,'current_boot_id',return_value=BOOT_B):self.e.restore_confirmed_boot()
        self.assertEqual(prepare.call_count,2);self.assertEqual(self.driver.restores,1)
        self.assertEqual(self.row()['bootRestore']['preparationAttempts'],2)
    def test_foreign_preparation_failure_never_retries_or_activates(self):
        self.confirm()
        with patch.object(self.driver,'prepare_restore',side_effect=ValueError('foreign profile')) as prepare:
            with patch.object(n,'current_boot_id',return_value=BOOT_B):
                with self.assertRaises(ValueError):self.e.restore_confirmed_boot()
        self.assertEqual(prepare.call_count,1);self.assertEqual(self.driver.restores,0)

    def test_failed_restore_undoes_activation_and_preserves_confirmation(self):
        self.confirm();self.driver.restore_failure=True
        with patch.object(n,'current_boot_id',return_value=BOOT_B):
            with self.assertRaises(ValueError):self.e.restore_confirmed_boot()
        self.assertFalse(self.driver.exists);self.assertEqual(self.driver.undos,1)
        self.assertEqual(self.row()['state'],'confirmed')
        self.assertEqual(self.row()['bootRestore']['recovery'],'rolled-back')
    def test_same_boot_failure_does_not_repeat_successful_undo(self):
        self.confirm();self.driver.restore_failure=True
        with patch.object(n,'current_boot_id',return_value=BOOT_B):
            for _ in range(2):
                with self.assertRaises(ValueError):self.e.restore_confirmed_boot()
        self.assertEqual(self.driver.restores,1);self.assertEqual(self.driver.undos,1)
    def test_failed_activation_undo_retries_without_another_activation(self):
        self.confirm();self.driver.restore_failure=True
        with patch.object(self.driver, 'undo_restore', side_effect=[ValueError('injected undo failure'), None]) as undo:
            with patch.object(n,'current_boot_id',return_value=BOOT_B):
                for _ in range(2):
                    with self.assertRaises(ValueError):self.e.restore_confirmed_boot()
            self.assertEqual(undo.call_count,2)
        self.assertEqual(self.driver.restores,1)
        self.assertEqual(self.row()['bootRestore']['recovery'],'rolled-back')

    def test_startup_recover_leaves_confirmed_debt_to_bounded_worker(self):
        self.confirm();data=self.e.load();row=data['transactions'][self.a['transactionId']]
        row['bootRestore']={'bootId':BOOT_A,'state':'degraded','recovery':'rollback-failed'}
        self.e.save(data)
        with patch.object(self.driver,'undo_restore',side_effect=AssertionError('startup must not retry confirmed debts')):
            self.e.recover()
        self.assertEqual(self.row()['bootRestore']['recovery'],'rollback-failed')
        self.e.tick()
        self.assertEqual(self.driver.undos,1)
        self.assertEqual(self.row()['bootRestore']['recovery'],'rolled-back')

    def test_near_hard_byte_limit_still_undoes_and_exports_pending_work(self):
        self.e.accept(self.a);data=self.e.load()
        data['transactions'][self.a['transactionId']]['fixtureEvidence']='x'*(15*1024*1024//2)
        self.e.save(data)
        self.assertGreater(os.stat(self.e.path).st_size,7*1024*1024)
        self.e.config['enabled']=False;self.e.recover();self.e.publish_results()
        self.assertFalse(self.driver.exists)
        self.assertEqual(self.row()['state'],'rolled-back')
        self.assertEqual(n.read_json(self.temp.name+'/terminal-results.json')[0]['state'],'rolled-back')
        self.assertLess(os.stat(self.e.path).st_size,8*1024*1024)

    def test_boot_refuses_activation_before_undo_exceeds_reserved_capacity(self):
        self.confirm();self.driver.exists=False;data=self.e.load()
        data['transactions'][self.a['transactionId']]['fixtureEvidence']='x'*(15*1024*1024//2)
        self.e.save(data)
        with patch.object(self.driver,'prepare_restore',return_value={'wasActive':False,'before':'x'*(2*1024*1024)}):
            with patch.object(n,'current_boot_id',return_value=BOOT_B):
                with self.assertRaises(ValueError):self.e.restore_confirmed_boot()
        self.assertEqual(self.driver.restores,0)
        self.assertEqual(self.row()['bootRestore']['recovery'],'not-started')
        self.assertNotIn('plan',self.row()['bootRestore'])
        self.e.publish_results()
        self.assertEqual(n.read_json(self.temp.name+'/terminal-results.json')[0]['state'],'confirmed')
        self.assertLess(os.stat(self.e.path).st_size,8*1024*1024)

    def test_historical_verifier_proof_tamper_blocks_restoration(self):
        self.confirm();data=self.e.load();row=data['transactions'][self.a['transactionId']]
        row['restorationAuthority']['confirmation']['verification']['checks']['forward']=False
        self.e.save(data)
        with patch.object(n,'current_boot_id',return_value=BOOT_B):
            with self.assertRaises(ValueError):self.e.restore_confirmed_boot()
        self.assertEqual(self.driver.restores,0)
    def test_missing_historical_authority_blocks_restoration(self):
        self.confirm();data=self.e.load();data['transactions'][self.a['transactionId']].pop('restorationAuthority');self.e.save(data)
        with patch.object(n,'current_boot_id',return_value=BOOT_B):
            with self.assertRaises(ValueError):self.e.restore_confirmed_boot()
        self.assertEqual(self.driver.restores,0)


if __name__=='__main__':unittest.main()
