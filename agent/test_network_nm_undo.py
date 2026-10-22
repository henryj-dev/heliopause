"""NM asynchronous activation cancellation boundaries; no live process/socket/file access."""
import socket
import subprocess
import unittest
from unittest.mock import Mock,patch
from network_nm_wireguard import NetworkManagerWireGuard
from test_network_nm_profile import operation,OWNER


class ActivationUndo(unittest.TestCase):
    def setUp(self):
        for module,name in [(subprocess,'run'),(subprocess,'Popen'),(socket,'socket')]:
            guard=patch.object(module,name,side_effect=AssertionError('escaped NM undo unit boundary'));guard.start();self.addCleanup(guard.stop)
        self.op=operation();self.row={'authorization':{'operation':self.op},'owner':OWNER,'bootRestore':{'plan':{'wasActive':False,'before':{'baseline':True},'paths':{'mgmt':{'dev':'mgmt'}},'nmOwner':'s ":1.10"'}}}
        self.driver=NetworkManagerWireGuard('/unused')
        self.driver.bind(self.row)
        self.driver.check_file=Mock(return_value=b'isolated')
        self.driver.cached=Mock(return_value=True)
        self.driver.ip=Mock(return_value=[])
        self.driver.snapshot=Mock(return_value={'baseline':True})
        self.driver.route_get=Mock(return_value={'dev':'mgmt'})
        self.driver.manager_instance=Mock(return_value='s ":1.10"')
        self.commands=[]
    def responses(self,active_before='',active_after=''):
        active=iter([active_before,active_after])
        def run(args,*unused,**kwargs):
            self.commands.append(args)
            return next(active) if args[-1]=='--active' else ''
        self.driver.run=run
    def test_cold_nm_command_cap_never_exceeds_shared_deadline(self):
        with patch('network_nm_wireguard.time.monotonic',return_value=100):
            self.assertEqual(self.driver.command_timeout(),10)
            self.driver.deadline=108;self.driver.command_deadline=103
            self.assertEqual(self.driver.command_timeout(),3)
            self.driver.command_deadline=99
            with self.assertRaisesRegex(RuntimeError,'budget elapsed'):self.driver.command_timeout()

    def test_foreign_fwmark_and_keepalive_block_owned_removal(self):
        public=self.op['peers'][0]['publicKey']
        for mark,keepalive in [('0x1',public+' 1'),('off',public+' 25'),('off','foreign 1')]:
            self.driver.run=Mock(side_effect=[mark,keepalive] if mark=='off' else [mark])
            with self.assertRaisesRegex(ValueError,'ownership conflict'):
                self.driver.kernel_options_owned(self.op)
        for keepalive in ['',public+' 1']:
            self.driver.run=Mock(side_effect=['off',keepalive])
            self.driver.kernel_options_owned(self.op)

    def test_activating_uuid_is_cancelled_even_without_kernel_link(self):
        self.responses(self.op['profileUuid']+':--','')
        self.driver.undo_restore(self.row)
        self.assertIn(['nmcli','--wait','10','connection','down','uuid',self.op['profileUuid']],self.commands)
    def test_absent_kernel_and_active_list_do_not_prove_pending_request_cancelled(self):
        self.responses()
        with self.assertRaisesRegex(ValueError,'outcome uncertain'):self.driver.undo_restore(self.row)
    def test_completed_activation_can_be_verified_absent_without_pending_request(self):
        self.row['bootRestore']['plan']['activationCompleted']=True
        self.responses();self.driver.undo_restore(self.row)
    def test_new_nm_instance_cannot_complete_old_queued_request(self):
        self.driver.manager_instance.return_value='s ":1.11"'
        self.responses();self.driver.undo_restore(self.row)
    def test_remaining_active_uuid_blocks_success(self):
        active=self.op['profileUuid']+':--';self.responses(active,active)
        with self.assertRaisesRegex(ValueError,'cancellation unverified'):self.driver.undo_restore(self.row)
    def test_foreign_cached_profile_is_preserved(self):
        self.driver.cached.side_effect=ValueError('foreign cache');self.responses()
        with self.assertRaisesRegex(ValueError,'foreign cache'):self.driver.undo_restore(self.row)
        self.assertEqual(self.commands,[])
    def test_foreign_kernel_shape_blocks_deactivation(self):
        self.driver.ip.return_value=[{'ifname':self.op['interfaceName']}]
        self.driver.owned=Mock(side_effect=ValueError('foreign kernel'))
        self.responses(self.op['profileUuid']+':'+self.op['interfaceName'],'')
        with self.assertRaisesRegex(ValueError,'foreign kernel'):self.driver.undo_restore(self.row)
        self.assertFalse(any('down' in command for command in self.commands))


if __name__=='__main__':unittest.main()
