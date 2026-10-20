"""Admission/recovery boundaries: fake writers and transport, real temporary journal/status files."""
import copy
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch
import network_executor as n
import network_lifecycle as lifecycle


class Executor:
    def __init__(self, directory):
        self.directory=directory
        self.data={'transactions':{}}
        self.config={'enabled':True}
        self.driver=types.SimpleNamespace(owned=Mock(return_value=True))
        self.accept=Mock(return_value='awaiting-verification')
        self.confirm=Mock(return_value='confirmed')
        self.tick=Mock()
        self.recover=Mock()
    def load(self):return copy.deepcopy(self.data)
    def publish_results(self):n.atomic(self.directory+'/terminal-results.json',[])


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=self.temp.name
        self.st={'state':'confirmed','generation':'firewall-1','workloadState':None}
        self.calls=[]
        self.agent=types.SimpleNamespace(STATE_FILE=self.path+'/firewall.json',_stop=threading.Event(),
            load_state=lambda:dict(self.st),_has_live_commitment=lambda st:st['state'] in lifecycle.DEBT,
            recover_commitment=Mock(),recover_workload_commitment=Mock(),reconcile_recovered_commitments=Mock(),rollback_generation=Mock())
        n.atomic(self.agent.STATE_FILE,self.st)
        self.executor=Executor(self.path)
        self.l=lifecycle.Lifecycle(self.agent,directory=self.path,enabled=True,executor=self.executor)
        self.l.recover();self.addCleanup(self.cleanup)
        for module,name in [(subprocess,'run'),(subprocess,'Popen'),(socket,'socket')]:
            guard=patch.object(module,name,side_effect=AssertionError('escaped lifecycle unit boundary'));guard.start();self.addCleanup(guard.stop)
    def cleanup(self):
        self.agent._stop.set()
        if self.l.thread:self.l.thread.join(timeout=2)
        if self.l.worker_fd is not None:os.close(self.l.worker_fd);self.l.worker_fd=None
    def request(self,filename='request.json'):n.atomic(self.path+'/'+filename,{'fixture':True})
    def test_firewall_admission_precedes_any_network_write(self):
        self.assertTrue(self.l.begin_firewall());self.request();self.l.step()
        self.executor.accept.assert_not_called()
        self.assertEqual(n.read_json(self.path+'/response.json')['state'],'rejected')
        self.assertEqual(self.l.report()['activeWriter']['kind'],'firewall')
        self.l.end_firewall();self.assertIsNone(self.l.report()['activeWriter'])
    def test_network_admission_blocks_new_firewall_and_has_no_queue(self):
        self.l.begin_network();self.assertFalse(self.l.begin_firewall())
        with self.assertRaises(ValueError):self.l.begin_network()
        self.l.refresh();self.assertTrue(self.l.begin_firewall())
    def test_firewall_pending_journal_blocks_network(self):
        self.st['state']='pending'
        with self.assertRaises(ValueError):self.l.begin_network()
        self.executor.accept.assert_not_called()
    def test_raw_corrupt_firewall_is_not_empty_admission(self):
        with open(self.agent.STATE_FILE,'w') as stream:stream.write('{')
        with self.assertRaises(ValueError):self.l.begin_network()
    def test_network_failure_does_not_suppress_firewall_recovery(self):
        self.executor.recover.side_effect=ValueError('fixture failure')
        self.l.recover()
        self.agent.recover_commitment.assert_called()
        self.agent.recover_workload_commitment.assert_called()
        self.assertIn('network-recovery',self.l.report()['errors'])
        self.assertFalse(self.l.begin_firewall())
    def test_one_firewall_helper_failure_does_not_skip_other_recovery(self):
        self.agent.recover_commitment.side_effect=ValueError('failure')
        self.l.recover_firewall()
        self.agent.recover_workload_commitment.assert_called()
        self.agent.reconcile_recovered_commitments.assert_called()
    def test_held_worker_flock_never_ticks_or_recovers_another_owner(self):
        other_executor=Executor(self.path)
        other_executor.publish_results=Mock()
        other=lifecycle.Lifecycle(self.agent,directory=self.path,executor=other_executor)
        other.recover();other.step();other.close()
        self.assertIsNone(other.worker_fd)
        other_executor.tick.assert_not_called();other_executor.recover.assert_not_called();other_executor.publish_results.assert_not_called()
    def test_unknown_state_and_corrupt_recovery_material_fail_closed(self):
        for bad in [{'state':'garbage'},{'state':'confirmed'},{'state':'pending','generation':'g','pendingRoutes':'invalid'}]:
            n.atomic(self.agent.STATE_FILE,bad)
            self.l.recover_firewall()
            self.assertFalse(self.l.begin_firewall())
            with self.assertRaises(ValueError):self.l.begin_network()
            self.assertEqual(self.l.report()['recoveryDebt']['firewall'],'unknown')
    def test_disabled_still_ticks_recovers_and_publishes(self):
        self.l.enabled=False;self.l.recover();self.l.step()
        self.executor.recover.assert_called();self.executor.tick.assert_called()
        self.assertTrue(os.path.exists(self.path+'/terminal-results.json'))
    def test_confirm_is_separate_from_heartbeat(self):
        self.l.heartbeat(True);self.executor.confirm.assert_not_called()
        self.request('confirm.json');self.l.step();self.executor.confirm.assert_called_once()
    def test_hung_network_action_does_not_block_production_firewall_rollback(self):
        entered=threading.Event();release=threading.Event();restores=[]
        def accept(_):entered.set();release.wait(2);return 'awaiting-verification'
        self.executor.accept.side_effect=accept;self.request();self.l.start()
        self.assertTrue(entered.wait(1))
        agent=n.crypto_helpers(self.path);agent.STATE_FILE=self.path+'/watchdog.json'
        state={**agent._EMPTY_STATE,'state':'pending','generation':'watchdog-fixture'}
        n.atomic(agent.STATE_FILE,state);agent._backup=None
        def restore(_):restores.append(time.monotonic());return True,'fixture kernel restore'
        armed=time.monotonic();timer=threading.Timer(.03,agent.rollback,args=('watchdog fixture','watchdog-fixture'))
        stamps=[]
        try:
            with patch.object(agent,'_restore',side_effect=restore),patch.object(agent,'_restore_routes',return_value=(True,'no fixture routes')):
                timer.start()
                for _ in range(5):
                    self.l.heartbeat(True);stamps.append(time.monotonic());time.sleep(.02)
                timer.join(timeout=1)
                self.assertEqual(n.read_json(agent.STATE_FILE)['state'],'rolled-back')
                self.assertEqual(len(restores),1);self.assertLess(restores[0]-armed,.2)
                self.assertLess(max(b-a for a,b in zip(stamps,stamps[1:])),.1)
                self.assertFalse(self.l.begin_firewall())
        finally:release.set();timer.join()
    def test_missing_outbox_does_not_suppress_tick_or_recovery(self):
        self.executor.publish_results=Mock(side_effect=OSError('disk'))
        self.l.step();self.executor.tick.assert_called()
        self.l.recover();self.executor.recover.assert_called()
        self.assertIn('terminal-outbox',self.l.report()['errors'])
    def test_capacity_and_confirmed_kernel_are_distinct(self):
        self.executor.data['transactions']={'tx':{'state':'confirmed','authorization':{'operation':{}},'owner':'fixture'}}
        self.executor.driver.owned.return_value=False;self.l.refresh()
        report=self.l.report()['network']
        self.assertEqual(report['ledger'],{'used':1,'limit':1024,'remaining':1023})
        self.assertEqual(report['confirmedKernel']['tx']['state'],'absent-or-drifted')
        self.assertEqual(report['transactions'][0]['state'],'confirmed')
    def test_rollback_failed_remains_active(self):
        self.executor.data['transactions']={'tx':{'state':'rollback-failed'}};self.l.refresh()
        self.assertFalse(self.l.begin_firewall())
        self.assertTrue(self.l.report()['recoveryDebt']['network'])
    def test_status_has_timestamps_and_no_configuration_secrets(self):
        self.l.heartbeat(True);self.l.discovery(False);self.l.write_status()
        report=n.read_json(self.path+'/lifecycle-status.json')
        self.assertGreater(report['heartbeat']['lastSuccess'],0);self.assertGreater(report['discovery']['lastFailure'],0)
        self.assertNotIn('secrets',n.canonical(report));self.assertNotIn(self.path,n.canonical(report))
    def test_integrated_entry_requires_independent_protected_management(self):
        for addresses in [[],['0.0.0.0'],['192.0.2.1']*17]:
            with self.assertRaises(ValueError):
                lifecycle.Lifecycle(self.agent,{'protectedAddresses':addresses},self.path,True)
    def test_command_budget_caps_timeout_and_fails_closed(self):
        driver=n.LinuxWireGuard('/unused');driver.deadline=time.monotonic()+.1
        self.assertGreater(driver.command_timeout(),0);self.assertLessEqual(driver.command_timeout(),.1)
        driver.deadline=None;driver.command_deadline=time.monotonic()-1
        with self.assertRaises(RuntimeError):driver.command_timeout()


if __name__=='__main__':unittest.main()
