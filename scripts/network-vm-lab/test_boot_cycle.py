"""Report acceptance must reject in-progress recovery and stale/empty packet evidence."""
import copy
import unittest
from boot_cycle import recovery_complete, fresh_packets

class ReportAcceptance(unittest.TestCase):
    def test_restored_requires_terminal_matching_boot_without_other_debt(self):
        row={'state':'confirmed','bootRestore':{'bootId':'new','state':'restored'}}
        journal={'transactions':{'tx':row}}
        self.assertTrue(recovery_complete(journal,'tx','new','restored'))
        for value in ['attempting','degraded']:
            row['bootRestore']['state']=value
            self.assertFalse(recovery_complete(journal,'tx','new','restored'))
        row['bootRestore']['state']='restored'
        self.assertFalse(recovery_complete(journal,'tx','old','restored'))
        journal['transactions']['other']={'state':'rollback-failed'}
        self.assertFalse(recovery_complete(journal,'tx','new','restored'))
    def test_expected_rollback_does_not_accept_confirmed_or_pending(self):
        for state in ['confirmed','applying','rolling-back','rollback-failed']:
            self.assertFalse(recovery_complete({'transactions':{'tx':{'state':state}}},'tx','new','rolled-back'))
        self.assertTrue(recovery_complete({'transactions':{'tx':{'state':'rolled-back'}}},'tx','new','rolled-back'))
    def test_packets_require_exact_checks_current_boot_and_fresh_time(self):
        probe={'checks':{key:True for key in ['interface','address','route','fib','handshake','protected','management','forward','reverse']},'gateway':{'bootId':'new'},'observedAt':1000}
        self.assertTrue(fresh_packets(probe,'new',2000))
        for now in [999,11001]:self.assertFalse(fresh_packets(probe,'new',now))
        self.assertFalse(fresh_packets(probe,'old',2000))
        for checks in [{},{**probe['checks'],'extra':True},{**probe['checks'],'forward':1},{**probe['checks'],'reverse':False}]:
            bad=copy.deepcopy(probe);bad['checks']=checks
            self.assertFalse(fresh_packets(bad,'new',2000))

if __name__=='__main__':unittest.main()
