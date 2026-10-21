"""Report acceptance must reject in-progress recovery and stale/empty packet evidence."""
import copy
import unittest
from boot_cycle import recovery_complete, fresh_packets, inactive_preserved, service_inactive

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
    def test_negative_boot_requires_known_safe_degraded_or_preserved_inactive(self):
        row={'state':'confirmed','bootRestore':{'bootId':'new','state':'degraded','recovery':'not-started'}}
        journal={'transactions':{'tx':row}}
        self.assertTrue(recovery_complete(journal,'tx','new','degraded-unchanged'))
        row['bootRestore']['recovery']='rollback-failed'
        self.assertFalse(recovery_complete(journal,'tx','new','degraded-unchanged'))
        row['bootRestore']={'bootId':'old','state':'restored'}
        self.assertTrue(recovery_complete(journal,'tx','new','inactive'))
        self.assertFalse(recovery_complete(journal,'tx','new','unsupported'))
    def test_inactive_agent_requires_no_process_and_no_activation_in_progress(self):
        self.assertTrue(service_inactive('MainPID=0\nActiveState=failed\nSubState=failed'))
        self.assertTrue(service_inactive('MainPID=0\nActiveState=inactive\nSubState=dead'))
        for service in ['MainPID=12\nActiveState=active\nSubState=running','MainPID=0\nActiveState=activating\nSubState=auto-restart','MainPID=0']:
            self.assertFalse(service_inactive(service))

    def test_negative_boot_preserves_exact_profile_and_no_kernel_objects(self):
        before={'journal':{'transactions':{'tx':{'authorization':{'operation':{'profileUuid':'id','interfaceName':'hp-owned'}}}}},'profiles':[{'uuid':'id','sha256':'foreign'}]}
        after={'profiles':copy.deepcopy(before['profiles']),'links':[],'routes':[]}
        self.assertTrue(inactive_preserved(before,after,'tx'))
        after['links']=[{'ifname':'hp-owned'}]
        self.assertFalse(inactive_preserved(before,after,'tx'))
        after['links']=[];after['profiles'][0]['sha256']='changed'
        self.assertFalse(inactive_preserved(before,after,'tx'))

    def test_packets_require_exact_checks_current_boot_and_fresh_time(self):
        probe={'checks':{key:True for key in ['interface','address','route','fib','handshake','protected','management','forward','reverse']},'gateway':{'bootId':'new'},'observedAt':1000}
        self.assertTrue(fresh_packets(probe,'new',2000))
        for now in [999,11001]:self.assertFalse(fresh_packets(probe,'new',now))
        self.assertFalse(fresh_packets(probe,'old',2000))
        for checks in [{},{**probe['checks'],'extra':True},{**probe['checks'],'forward':1},{**probe['checks'],'reverse':False}]:
            bad=copy.deepcopy(probe);bad['checks']=checks
            self.assertFalse(fresh_packets(bad,'new',2000))

if __name__=='__main__':unittest.main()
