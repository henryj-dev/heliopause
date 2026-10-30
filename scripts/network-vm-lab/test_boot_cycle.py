"""Report acceptance must reject in-progress recovery and stale/empty packet evidence."""
import copy
import unittest
from boot_cycle import REBOOT_WAIT_SECONDS, AGENT_STOP_TIMEOUT_SECONDS, monitor_argv, recovery_complete, fresh_packets, inactive_preserved, service_inactive, removed_profile, timeline_valid, rollback_progress
import json
import tempfile
from pathlib import Path
from probe_pairs import pair_for, load_pairs

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

    def test_rollback_report_refuses_a_leftover_nm_entry_for_the_profile(self):
        # NM leaves `<uuid>.nmmeta -> /dev/null` tombstones; a rolled-back case must not keep one.
        after={'journal':{'transactions':{'tx':{'authorization':{'operation':{'profileUuid':'id','interfaceName':'hp-owned'}}}}},'profiles':[{'uuid':'id','missing':True}],'links':[],'routes':[],'nmDevices':[],'nmProfiles':[],
               'nmDirectories':{'/etc/NetworkManager/system-connections':[{'name':'other.nmconnection','type':'file','target':None}],'/run/NetworkManager/system-connections':None}}
        self.assertTrue(removed_profile(after,'tx'))
        after['nmDirectories']['/etc/NetworkManager/system-connections'].append({'name':'id.nmmeta','type':'symlink','target':'/dev/null'})
        self.assertFalse(removed_profile(after,'tx'))

    def test_rollback_report_requires_file_cache_and_kernel_absence(self):
        after={'journal':{'transactions':{'tx':{'authorization':{'operation':{'profileUuid':'id','interfaceName':'hp-owned'}}}}},'profiles':[{'uuid':'id','missing':True}],'links':[],'routes':[],'nmDevices':[],'nmProfiles':[]}
        self.assertTrue(removed_profile(after,'tx'))
        after['nmDevices']=['id:wireguard:hp-owned']
        self.assertFalse(removed_profile(after,'tx'))
        after['nmDevices']=[];after['nmProfiles']=['id']
        self.assertFalse(removed_profile(after,'tx'))
        after['nmProfiles']=[];after['profiles']=[{'uuid':'id','sha256':'leftover'}]
        self.assertFalse(removed_profile(after,'tx'))

    def test_timeline_requires_continuous_fresh_samples_after_recovery(self):
        rows=[{'at':value,'peerBootId':'peer','management':True,'forward':True,'reverse':True} for value in range(6)]
        stopped={'at':6,'bootId':'peer'}
        self.assertTrue(timeline_valid(rows,'peer',.5,2,stopped))
        for records,end in [(rows[:1],stopped),(rows[:3],stopped),(rows,{'at':20,'bootId':'peer'}),(rows,{'at':6,'bootId':'new'}),(list(reversed(rows)),stopped)]:
            self.assertFalse(timeline_valid(records,'peer',.5,2,end))
        gap=copy.deepcopy(rows);gap[-1]['at']=20
        self.assertFalse(timeline_valid(gap,'peer',.5,2,{'at':21,'bootId':'peer'}))
        expired=[{**rows[0],'at':value} for value in range(902)]
        self.assertFalse(timeline_valid(expired,'peer',.5,899,{'at':902,'bootId':'peer'}))
    def test_rollback_failed_requires_current_service_and_new_history(self):
        before={'journal':{'transactions':{'tx':{'history':[{'state':'rollback-failed','at':1}]}}}}
        after={'journal':copy.deepcopy(before['journal']),'service':'MainPID=20\nActiveState=active\nSubState=running','lifecycle':{'agentPid':20,'reportedAt':100},'at':101}
        self.assertFalse(rollback_progress(before,after,'tx'))
        after['journal']['transactions']['tx']['history'].append({'state':'rollback-failed','at':99})
        self.assertTrue(rollback_progress(before,after,'tx'))
        after['lifecycle']['agentPid']=19
        self.assertFalse(rollback_progress(before,after,'tx'))

    def test_packets_require_exact_checks_current_boot_and_fresh_time(self):
        probe={'checks':{key:True for key in ['interface','address','route','fib','handshake','protected','management','forward','reverse']},'gateway':{'bootId':'new'},'observedAt':1000}
        self.assertTrue(fresh_packets(probe,'new',2000))
        for now in [999,11001]:self.assertFalse(fresh_packets(probe,'new',now))
        self.assertFalse(fresh_packets(probe,'old',2000))
        for checks in [{},{**probe['checks'],'extra':True},{**probe['checks'],'forward':1},{**probe['checks'],'reverse':False}]:
            bad=copy.deepcopy(probe);bad['checks']=checks
            self.assertFalse(fresh_packets(bad,'new',2000))



class RebootWait(unittest.TestCase):
    def test_the_reboot_wait_outlasts_the_agent_stop_timeout(self):
        # The gateway installs this drop-in (guest_fixture.py); its TimeoutStopSec overrides the unit's.
        conf=(Path(__file__).resolve().parents[2]/'packaging/systemd/heliopause-agent-network.conf').read_text()
        stop=[int(line.split('=',1)[1].rstrip('s')) for line in conf.splitlines() if line.startswith('TimeoutStopSec=')]
        self.assertEqual(stop,[AGENT_STOP_TIMEOUT_SECONDS])
        self.assertGreaterEqual(REBOOT_WAIT_SECONDS-AGENT_STOP_TIMEOUT_SECONDS,240)


class ProbePairs(unittest.TestCase):
    """Probes follow the transaction's route; a route with no pair fails closed (2026-10-30 review M2)."""

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'probe-pairs.json'

    def test_the_two_built_in_address_sets(self):
        self.assertEqual(pair_for(['198.51.100.6/32'],self.path),(('p6-client','198.51.100.2'),('p6-workload','198.51.100.6')))
        self.assertEqual(pair_for(['198.51.100.14/32'],self.path),(('p6-client','198.51.100.10'),('p6-workload','198.51.100.14')))

    def test_an_unknown_route_never_falls_back_to_the_primary(self):
        with self.assertRaisesRegex(ValueError,'no lab probe pair'):
            pair_for(['198.51.100.18/32'],self.path)

    def test_a_lab_file_adds_an_address_set(self):
        self.path.write_text(json.dumps({'198.51.100.18/32':{'client':['p6-client3','198.51.100.17'],'workload':['p6-workload3','198.51.100.18']}}))
        self.assertEqual(pair_for(['198.51.100.18/32'],self.path),(('p6-client3','198.51.100.17'),('p6-workload3','198.51.100.18')))

    def test_a_malformed_lab_file_is_refused(self):
        for bad in [{'198.51.100.0/24':{'client':['a','198.51.100.1'],'workload':['b','198.51.100.2']}},
                    {'198.51.100.18/32':{'client':['Bad Name','198.51.100.1'],'workload':['b','198.51.100.2']}},
                    {'198.51.100.18/32':{'client':['a','198.51.100.1']}}]:
            self.path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError,msg=json.dumps(bad)):load_pairs(self.path)

    def test_the_monitor_gets_every_route_and_finds_the_primary_pair(self):
        # The primary operation's first route is the peer tunnel address, which has no pair.
        import sys
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'agent'))
        import monitor
        args,pair=monitor.parse(monitor_argv('n'*32,'i'*32,['192.0.2.130/32','198.51.100.6/32'])[2:],self.path)
        self.assertEqual(args.route,['192.0.2.130/32','198.51.100.6/32'])
        self.assertEqual(pair,(('p6-client','198.51.100.2'),('p6-workload','198.51.100.6')))


if __name__=='__main__':unittest.main()
