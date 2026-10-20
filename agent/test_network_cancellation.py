"""Cancellation uses production Executor/ledger, fake crypto and driver, real protected temp I/O.
The process race fixture permits only local fixture child processes; no kernel/socket path is used.
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import network_executor as n
import test_network_executor as fixtures


def cancellation(a):
    return {'schemaVersion':1,'transactionId':a['transactionId'],'fenceId':a['transactionId'],'target':a['target'],'journalId':a['journalId'],'authorizationHash':n.digest(a),'artifactHash':a['artifactHash'],'registryRevision':a['registryRevision'],'requestedAt':int(time.time()*1000),'requestedBy':'alice','authorization':copy.deepcopy(a)}


class Cancellation(unittest.TestCase):
    def setUp(self):
        fixtures.Transactions.setUp(self)
        guard=patch.object(n.subprocess,'Popen',side_effect=AssertionError('escaped cancellation unit boundary'));guard.start();self.addCleanup(guard.stop)
    row=fixtures.Transactions.row
    confirmation=fixtures.Transactions.confirmation
    def test_preaccept_tombstone_is_not_rollback_and_never_calls_driver(self):
        self.assertEqual(self.e.cancel(cancellation(self.a)),'cancelled-before-accept')
        self.assertEqual(self.driver.calls,[])
        self.assertNotIn('acceptedAt',self.row())
        self.assertEqual(self.e.terminal_results()[0]['proof']['acceptancePrevented'],True)
        with self.assertRaisesRegex(ValueError,'permanently cancelled'):self.e.accept(self.a)
    def test_duplicate_cancel_and_reconstructed_executor_keep_same_result(self):
        c=cancellation(self.a);self.e.cancel(c);r=self.e.terminal_results()
        e=n.Executor(self.cfg,self.temp.name,self.driver);e.recover();e.cancel(c)
        self.assertEqual(r,e.terminal_results());self.assertEqual(e.load()['acceptedSequence'],1)
        self.assertFalse(self.driver.exists)
    def test_expired_authority_and_uncertain_clock_can_be_cancelled_when_disabled(self):
        c=cancellation(self.a);self.cfg['enabled']=False
        with patch.object(n.time,'time',return_value=1):self.e.cancel(c)
        self.assertEqual(self.row()['state'],'cancelled-before-accept')
        self.assertFalse(self.driver.calls)
    def test_expired_authority_is_historical_not_a_new_apply(self):
        c=cancellation(self.a)
        with patch.object(n.time,'time',return_value=(self.a['rollbackAt']+99999)/1000):self.e.cancel(c)
        self.assertEqual(self.e.terminal_results()[0]['state'],'cancelled-before-accept')
    def test_bad_signature_identity_hash_journal_and_scope_do_not_persist(self):
        for field,value in [('target',{'source':'bad'}),('journalId','f'*32),('authorizationHash','0'*64),('artifactHash','0'*64),('registryRevision',2),('fenceId','f'*32),('schemaVersion',2)]:
            c=cancellation(self.a);c[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.e.cancel(c)
        with patch.object(n,'verify',side_effect=ValueError('bad signature')),self.assertRaises(ValueError):self.e.cancel(cancellation(self.a))
        self.assertEqual(self.e.load()['transactions'],{});self.assertFalse(self.driver.calls)
    def test_accepted_cancel_is_not_never_accepted_and_tick_uses_original_undo(self):
        self.e.accept(self.a);self.assertEqual(self.e.cancel(cancellation(self.a)),'cancellation-rejected')
        result=self.e.terminal_results()[0]
        self.assertEqual(result['state'],'cancellation-rejected');self.assertNotIn('acceptancePrevented',result['proof'])
        self.assertTrue(self.driver.exists)
        with self.assertRaisesRegex(ValueError,'cancellation requested'):self.e.confirm(self.confirmation())
        self.e.tick();self.assertFalse(self.driver.exists);self.assertEqual(self.row()['state'],'rolled-back')
    def test_prepared_and_applying_never_emit_preaccept_result(self):
        for state in ['prepared','applying']:
            with self.subTest(state=state):
                if not self.e.load()['transactions']:self.e.accept(self.a)
                data=self.e.load();row=data['transactions'][self.a['transactionId']]
                row.pop('cancelRequested',None);row.pop('cancellationResponse',None);self.e.save(data,row,state)
                self.assertEqual(self.e.cancel(cancellation(self.a)),'cancellation-rejected')
                self.assertEqual(self.e.terminal_results()[0]['proof']['acceptedState'],state)
    def test_confirmed_cancellation_does_not_delete_objects_or_rewrite_history(self):
        self.e.accept(self.a);self.e.confirm(self.confirmation());before=self.e.terminal_results()
        self.assertEqual(self.e.cancel(cancellation(self.a)),'confirmed');self.e.tick();self.e.recover()
        self.assertTrue(self.driver.exists);self.assertEqual(before,self.e.terminal_results())
    def test_rollback_failed_keeps_debt_then_retries_successfully(self):
        self.e.accept(self.a);self.driver.fail='remove';self.e.cancel(cancellation(self.a));self.e.tick()
        self.assertEqual(self.row()['state'],'rollback-failed');self.assertEqual(self.e.terminal_results()[0]['state'],'cancellation-rejected')
        self.driver.fail=None;self.e.tick();self.assertEqual(self.row()['state'],'rolled-back')
    def test_before_save_failure_emits_no_success_or_mutation(self):
        with patch.object(n,'atomic',side_effect=OSError('no storage')),self.assertRaises(OSError):self.e.cancel(cancellation(self.a))
        self.assertEqual(self.e.terminal_results(),[]);self.assertFalse(self.driver.calls)
    def test_damaged_or_missing_journal_never_exports_success(self):
        self.e.cancel(cancellation(self.a));original=self.e.load()
        for change in ['missing-cancellation','accepted-marker','wrong-proof','missing-file']:
            data=copy.deepcopy(original);row=data['transactions'][self.a['transactionId']]
            if change=='missing-cancellation':row.pop('cancellation')
            elif change=='accepted-marker':row['acceptedAt']=1
            elif change=='wrong-proof':row['terminalResult']['proof']['acceptancePrevented']=False
            if change=='missing-file':os.unlink(self.e.path)
            else:n.atomic(self.e.path,data)
            with self.subTest(change=change),self.assertRaises((ValueError,KeyError)):self.e.terminal_results()
    def test_orphan_rejection_response_is_not_exported(self):
        self.e.accept(self.a);self.e.cancel(cancellation(self.a));data=self.e.load();data['transactions'][self.a['transactionId']].pop('cancelRequested');n.atomic(self.e.path,data)
        with self.assertRaises(ValueError):self.e.terminal_results()
    def test_full_ledger_keeps_existing_cancel_undo_and_refuses_new_tombstone(self):
        self.e.accept(self.a)
        data=self.e.load();row=data['transactions'][self.a['transactionId']]
        # Existing capacity is exercised with validated terminal-shaped fixture rows, not1024 applies.
        for i in range(1023):
            a=copy.deepcopy(self.a);a['transactionId']=format(i+1,'032x');c=cancellation(a)
            r={'authorization':a,'cancellation':c,'state':'cancelled-before-accept','history':[]}
            data['transactions'][a['transactionId']]=r;data['acceptedSequence']+=1
            data['terminalSequence']+=1
            result={'schemaVersion':2,'domain':n.CANCELLATION_RESULT_DOMAIN,'transactionId':a['transactionId'],'fenceId':a['transactionId'],'target':a['target'],'journalId':a['journalId'],'authorizationHash':n.digest(a),'artifactHash':a['artifactHash'],'registryRevision':a['registryRevision'],'state':'cancelled-before-accept','sequence':data['terminalSequence'],'proof':{'cancellationHash':n.digest(c),'acceptancePrevented':True}}
            r['terminalResult']={**result,'stateHash':n.digest(result)}
        n.atomic(self.e.path,data)
        self.e.cancel(cancellation(self.a));self.e.tick();self.assertEqual(self.row()['state'],'rolled-back')
        a=copy.deepcopy(self.a);a['transactionId']='f'*32
        with self.assertRaisesRegex(ValueError,'capacity'):self.e.cancel(cancellation(a))
        self.assertEqual(len(self.e.terminal_results()),1024)


CHILD=r'''
import sys,os,time,json,socket,subprocess
sys.path.insert(0,sys.argv[1])
import network_executor as n
from test_network_executor import Fake
path,action=sys.argv[2:]
n.crypto_helpers=lambda _:object();n.verify=lambda value,*_:value;n.independent_trust=lambda *_:None
for name in ['run','Popen']:setattr(subprocess,name,lambda *a,**k:(_ for _ in ()).throw(AssertionError('escaped subprocess')))
socket.socket=lambda *a,**k:(_ for _ in ()).throw(AssertionError('escaped socket'))
a=n.read_json(path+'/a.json');cfg=n.read_json(path+'/cfg.json');c=n.read_json(path+'/c.json')
def event(point):
 if point==os.environ.get('BARRIER'):
  n.atomic(path+'/entered.json',{'point':point,'pid':os.getpid()})
  while not os.path.exists(path+'/release'):time.sleep(.005)
e=n.Executor(cfg,path,Fake(),event=event)
while not os.path.exists(path+'/go'):time.sleep(.005)
try: result=e.accept(a) if action=='accept' else e.cancel(c)
except (ValueError,BlockingIOError) as error:result=type(error).__name__;diagnostic=str(error)
n.atomic(path+'/'+action+'-result.json',{'state':result,'permanentlyCancelled':'permanently cancelled' in locals().get('diagnostic',''),'beforeExpiry':int(time.time()*1000)<a['expiresAt']})
'''

class Processes(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.path=self.temp.name
        a=fixtures.authorization();a['journalId']=n.initialize_journal(self.path);a['expiresAt']+=20000;a['rollbackAt']+=20000
        a['approval']['planHash']='sha256:'+n.digest({k:v for k,v in a.items() if k!='approval'})
        n.atomic(self.path+'/a.json',a);n.atomic(self.path+'/c.json',cancellation(a));n.atomic(self.path+'/cfg.json',{'enabled':True,'journalId':a['journalId'],'identity':a['target'],'managerKeys':'unused','verifierKeys':'unused','secrets':'unused','protectedAddresses':['192.0.2.1']})
    def start(self,action,barrier=''):
        p=subprocess.Popen([sys.executable,'-c',CHILD,os.path.dirname(__file__),self.path,action],env={**os.environ,'BARRIER':barrier},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.addCleanup(lambda:p.kill() if p.poll() is None else None);return p
    def wait(self,file):
        until=time.monotonic()+5
        while not os.path.exists(self.path+'/'+file):
            if time.monotonic()>until:self.fail('child did not reach '+file)
            time.sleep(.005)
    def test_actual_process_race_cancel_durable_first_blocks_accept(self):
        c=self.start('cancel','cancelled-before-accept');n.atomic(self.path+'/go',{});self.wait('entered.json')
        a=self.start('accept');a.communicate(timeout=5);self.assertEqual(n.read_json(self.path+'/accept-result.json')['state'],'BlockingIOError')
        n.atomic(self.path+'/release',{});c.communicate(timeout=5)
        a=self.start('accept');a.communicate(timeout=5);self.assertEqual(n.read_json(self.path+'/accept-result.json')['state'],'ValueError');self.assertTrue(n.read_json(self.path+'/accept-result.json')['permanentlyCancelled']);self.assertTrue(n.read_json(self.path+'/accept-result.json')['beforeExpiry'])
        self.assertEqual(n.read_json(self.path+'/transactions.json')['transactions'][fixtures.authorization()['transactionId']]['state'],'cancelled-before-accept')
    def test_actual_process_race_accept_durable_first_never_cancels_as_unexecuted(self):
        a=self.start('accept','prepared');n.atomic(self.path+'/go',{});self.wait('entered.json')
        c=self.start('cancel');c.communicate(timeout=5);self.assertEqual(n.read_json(self.path+'/cancel-result.json')['state'],'BlockingIOError')
        n.atomic(self.path+'/release',{});a.communicate(timeout=5)
        c=self.start('cancel');c.communicate(timeout=5);self.assertEqual(n.read_json(self.path+'/cancel-result.json')['state'],'cancellation-rejected')
    def test_sigkill_before_and_after_tombstone_commit(self):
        for point in ['before-cancel-save','cancelled-before-accept']:
            with self.subTest(point=point):
                for name in ['entered.json','release','cancel-result.json']:
                    try:os.unlink(self.path+'/'+name)
                    except FileNotFoundError:pass
                p=self.start('cancel',point);n.atomic(self.path+'/go',{});self.wait('entered.json');p.kill();p.communicate(timeout=5)
                data=n.read_json(self.path+'/transactions.json');self.assertEqual(bool(data['transactions']),point=='cancelled-before-accept')
                if point=='before-cancel-save':continue
                fresh=self.start('accept');fresh.communicate(timeout=5);self.assertEqual(n.read_json(self.path+'/accept-result.json')['state'],'ValueError');self.assertTrue(n.read_json(self.path+'/accept-result.json')['permanentlyCancelled']);self.assertTrue(n.read_json(self.path+'/accept-result.json')['beforeExpiry'])

if __name__=='__main__':unittest.main()
