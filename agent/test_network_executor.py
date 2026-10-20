"""Unit boundary: fake Linux driver + fake signature decoder; real protected journal I/O in tempdir.
No pull rollback helper, sockets, subprocess or production filesystem is reachable through Fake.
Cryptographic interoperability and kernel effects are exercised separately by the isolated lab.
"""
import copy
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import network_executor as n

PUB='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
PEER='AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI='


class Fake:
    def __init__(self):
        self.exists=False
        self.calls=[]
        self.fail=None
        self.changed=False
    def preflight(self,op,protected):
        self.calls.append('preflight')
        if self.exists: raise ValueError('exists')
        return {'before':True},{'management':True}
    def create(self,op,owner):
        self.calls.append('create'); self.exists=True
        if self.fail=='create': raise RuntimeError('injected')
    def configure(self,op):
        self.calls.append('configure')
    def fingerprint(self,op):
        return {'configured':not self.changed}
    def routes(self,op):
        self.calls.append('routes')
        if self.fail=='routes': raise RuntimeError('injected')
    def owned(self,op,owner): return self.exists
    def remove(self,op,owner):
        self.calls.append('remove')
        if self.fail=='remove': raise RuntimeError('injected')
        self.exists=False
    def verify_local(self,*args):
        self.calls.append('verify')
        if self.fail=='verify': raise ValueError('local mismatch')
        return {'verified':True}


def authorization():
    now=int(time.time()*1000)
    op={'driver':n.DRIVER,'interfaceId':'wg-new','interfaceName':'hpaaaaaaaaaaaa','address':'192.0.2.129/32','mtu':1400,'listenPort':51820,'secretRef':'test','publicKey':PUB,'peers':[{'publicKey':PEER,'endpoint':'203.0.113.2:51820','allowedIps':['192.0.2.130/32']}],'routes':['192.0.2.130/32']}
    a={'schemaVersion':2,'journalId':'e'*32,'transactionId':'a'*32,'target':{'source':'lab','host':'gateway','nodeId':'gateway'},'registryRevision':1,'resources':[{'id':'wg-new','generation':1}], 'desiredDigest':'a'*64,'reviewHash':'b'*64,'artifactHash':n.digest(op),'observation':{'digest':'c'*64,'collectedAt':now,'maxAgeMs':10000},'localPrecondition':n.digest({'before':True}),'operation':op,'issuedAt':now,'expiresAt':now+5000,'rollbackAt':now+10000}
    a['approval']={'mode':'two-person','proposedBy':'alice','approvedBy':'bob','approvedAt':now,'planHash':'sha256:'+n.digest(a)}
    return a


class Transactions(unittest.TestCase):
    def setUp(self):
        for module,name in [(n.subprocess,'run'),(n.socket,'socket')]:
            boundary=patch.object(module,name,side_effect=AssertionError('escaped transaction unit boundary'))
            boundary.start();self.addCleanup(boundary.stop)
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.patch=patch.object(n,'crypto_helpers',return_value=object());self.patch.start();self.addCleanup(self.patch.stop)
        self.trust=patch.object(n,'independent_trust');self.trust.start();self.addCleanup(self.trust.stop)
        self.decode=patch.object(n,'verify',side_effect=lambda value,*args:value);self.decode.start();self.addCleanup(self.decode.stop)
        journal_id=n.initialize_journal(self.temp.name)
        self.driver=Fake();self.a=authorization();self.a['journalId']=journal_id
        self.a['approval']['planHash']='sha256:'+n.digest({k:v for k,v in self.a.items() if k!='approval'})
        self.cfg={'enabled':True,'journalId':journal_id,'identity':self.a['target'],'managerKeys':'unused','verifierKeys':'unused','secrets':'unused','protectedAddresses':['192.0.2.1']}
        self.e=n.Executor(self.cfg,self.temp.name,self.driver)
    def reapprove(self):
        self.a['approval']['planHash']='sha256:'+n.digest({k:v for k,v in self.a.items() if k!='approval'})
    def row(self): return self.e.load()['transactions'][self.a['transactionId']]
    def confirmation(self):
        now=int(time.time()*1000)
        v={'transactionId':self.a['transactionId'],'authorizationHash':n.digest(self.a),'artifactHash':self.a['artifactHash'],'observedAt':now,'expiresAt':now+2000,'nonce':os.urandom(16).hex(),'checks':{k:True for k in n.CHECKS}}
        return {'transactionId':self.a['transactionId'],'authorizationHash':n.digest(self.a),'artifactHash':self.a['artifactHash'],'expiresAt':now+3000,'verification':v}
    def test_normal_apply_independent_confirm(self):
        self.assertEqual(self.e.accept(self.a),'awaiting-verification')
        self.assertEqual(self.e.confirm(self.confirmation()),'confirmed')
        self.e.recover();self.assertTrue(self.driver.exists)
    def test_confirmed_deadline_does_not_poison_next_real_preflight(self):
        self._two_confirmed_transactions()
    def test_terminal_rename_then_fsync_error_does_not_poison_next_real_preflight(self):
        self._two_confirmed_transactions(fsync_error=True)
    def _two_confirmed_transactions(self,fsync_error=False):
        # Real Linux preflight/run deadline predicate; only reads, secret lookup and command
        # boundary are replaced. Writes remain Fake and no host networking is invoked.
        from types import SimpleNamespace
        real=n.LinuxWireGuard(self.temp.name)
        snapshot={'links':[],'routes':[]}
        real.snapshot=lambda:copy.deepcopy(snapshot)
        real.route_get=lambda address:{'dev':'underlay'}
        secret=os.path.join(self.temp.name,'local-secret')
        with open(secret,'w') as stream:stream.write('test-only')
        real.secret=lambda op:os.open(secret,os.O_RDONLY)
        fake=self.driver
        for method in ['create','configure','routes','fingerprint','verify_local','owned','remove']:
            setattr(real,method,getattr(fake,method))
        self.e.driver=real
        self.a['localPrecondition']=n.digest(snapshot);self.reapprove()
        with patch.object(n.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'version')) as command:
            self.assertEqual(self.e.accept(self.a),'awaiting-verification')
            if fsync_error:
                original=n.atomic
                def installed_then_failed(path,value):
                    original(path,value)
                    if any(row.get('state')=='confirmed' for row in value.get('transactions',{}).values()):raise OSError('injected directory fsync failure')
                with patch.object(n,'atomic',side_effect=installed_then_failed):
                    with self.assertRaises(OSError):self.e.confirm(self.confirmation())
                self.assertEqual(self.row()['state'],'confirmed')
            else:self.assertEqual(self.e.confirm(self.confirmation()),'confirmed')
            later_wall=time.time()+20;later_mono=time.monotonic()+20
            with patch.object(n.time,'time',return_value=later_wall),patch.object(n.time,'monotonic',return_value=later_mono):
                self.a=authorization();self.a['journalId']=self.cfg['journalId'];self.a['transactionId']='b'*32
                self.a['operation']['interfaceName']='hpbbbbbbbbbbbb'
                self.a['artifactHash']=n.digest(self.a['operation'])
                self.a['localPrecondition']=n.digest(snapshot);self.reapprove()
                self.assertEqual(self.e.accept(self.a),'awaiting-verification')
                self.assertEqual(self.e.confirm(self.confirmation()),'confirmed')
            self.assertEqual(command.call_count,2)
        self.assertEqual(len(self.e.load()['transactions']),2)

    def test_terminal_receipt_is_read_from_durable_confirmation(self):
        self.e.accept(self.a);c=self.confirmation();self.e.confirm(c)
        result=self.e.terminal_results()[0]
        self.assertEqual(result['proof'],{'confirmationHash':n.digest(c),'verificationHash':n.digest(c['verification'])})
        self.assertEqual(result['authorizationHash'],n.digest(self.a))
        committed={k:v for k,v in result.items() if k!='stateHash'}
        self.assertEqual(result['stateHash'],n.digest(committed))
        self.assertEqual(self.e.confirm(c),'confirmed')
        self.assertEqual(self.e.terminal_results(),[result])
    def test_rollback_failure_cannot_emit_success_terminal_and_next_apply_is_refused(self):
        self.e.accept(self.a);self.driver.fail='remove';self.e.recover()
        self.assertEqual(self.row()['state'],'rollback-failed');self.assertEqual(self.e.terminal_results(),[])
        other=copy.deepcopy(self.a);other['transactionId']='b'*32;other['operation']['interfaceName']='hpbbbbbbbbbbbb';other['artifactHash']=n.digest(other['operation']);other['approval']['planHash']='sha256:'+n.digest({k:v for k,v in other.items() if k!='approval'})
        with self.assertRaises(ValueError):self.e.accept(other)
        self.driver.fail=None;self.e.recover()
        self.assertEqual(self.e.terminal_results()[0]['proof'],{'removalVerified':True})
    def test_disabled_recovery_still_publishes_authenticated_transport_outbox(self):
        self.e.accept(self.a);self.cfg['enabled']=False;self.e.recover();self.e.publish_results()
        result=n.read_json(self.temp.name+'/terminal-results.json')[0]
        self.assertEqual(result['state'],'rolled-back');self.assertEqual(result['journalId'],self.cfg['journalId'])
    def test_terminal_write_failure_never_publishes_uncommitted_success(self):
        self.e.accept(self.a);original=n.atomic
        def fail(path,value):
            if any(r.get('state')=='confirmed' for r in value.get('transactions',{}).values()):raise OSError('disk full')
            return original(path,value)
        with patch.object(n,'atomic',side_effect=fail):
            with self.assertRaises(OSError):self.e.confirm(self.confirmation())
        self.assertEqual(self.e.terminal_results(),[])
        self.e.recover();self.assertEqual(self.e.terminal_results()[0]['state'],'rolled-back')
    def test_missing_journal_never_reinitializes_replay_state(self):
        self.e.accept(self.a);os.unlink(self.e.path)
        with self.assertRaises((ValueError,FileNotFoundError)):self.e.accept(self.a)
        with self.assertRaises(ValueError):n.initialize_journal(self.temp.name)
    def test_removed_transaction_is_detected_without_replay_ledger_pruning(self):
        self.e.accept(self.a);data=self.e.load();data['transactions']={};n.atomic(self.e.path,data)
        with self.assertRaises(ValueError):self.e.load()
    def test_fresh_journal_identity_refuses_old_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            identity=n.initialize_journal(directory)
            cfg={**self.cfg,'journalId':identity};other=n.Executor(cfg,directory,Fake())
            self.assertNotEqual(identity,self.cfg['journalId'])
            with self.assertRaises(ValueError):other.accept(self.a)
            self.assertEqual(other.driver.calls,[])
    def test_terminal_export_requires_successful_durability_barrier(self):
        self.e.accept(self.a);self.e.confirm(self.confirmation())
        with patch.object(n.os,'fsync',side_effect=OSError('injected fsync failure')):
            with self.assertRaises(OSError):self.e.publish_results()
        self.assertFalse(os.path.exists(self.temp.name+'/terminal-results.json'))
        self.e.publish_results();self.assertEqual(len(n.read_json(self.temp.name+'/terminal-results.json')),1)

    def test_terminal_before_outbox_new_process_recovers_reporting(self):
        self.e.accept(self.a);self.e.confirm(self.confirmation())
        self.assertFalse(os.path.exists(self.temp.name+'/terminal-results.json'))
        # New process, disk only. Explicit subprocess boundary allows only this fixed read/export.
        import subprocess
        original=__import__('subprocess').Popen
        code="import sys;sys.path.insert(0,'agent');import network_executor as n;n.crypto_helpers=lambda directory:object();e=n.Executor(n.read_json(sys.argv[1]),sys.argv[2]);e.publish_results()"
        n.atomic(self.temp.name+'/config.json',self.cfg)
        process=original([sys.executable,'-c',code,self.temp.name+'/config.json',self.temp.name],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        out,error=process.communicate(timeout=5)
        self.assertEqual(process.returncode,0,error.decode())
        self.assertEqual(n.read_json(self.temp.name+'/terminal-results.json')[0]['state'],'confirmed')

    def test_overlapping_verifier_trust_is_rejected(self):
        class Provider:
            def _load_artifact_key_dir(self,*args):return [('same-key','manager','unused')]
        # Invoke the real trust predicate outside the signature/driver unit stubs.
        self.trust.stop()
        with self.assertRaises(ValueError): n.independent_trust(self.cfg,Provider())
        self.trust.start()
    def test_signature_rejection_has_no_driver_calls(self):
        with patch.object(n,'verify',side_effect=ValueError('bad signature')):
            with self.assertRaises(ValueError): self.e.accept(self.a)
        self.assertEqual(self.driver.calls,[])
    def test_wrong_target(self):
        self.a['target']['host']='other'
        self.cfg['identity']={'source':'lab','host':'gateway','nodeId':'gateway'}
        with self.assertRaises(ValueError): self.e.accept(self.a)
        self.assertFalse(self.driver.exists)
    def test_expired(self):
        self.a['expiresAt']=1
        with self.assertRaises(ValueError): self.e.accept(self.a)
    def test_artifact_mismatch(self):
        self.a['artifactHash']='d'*64;self.reapprove()
        with self.assertRaises(ValueError): self.e.accept(self.a)
    def test_signature_is_not_approval(self):
        self.a['approval']['approvedBy']='alice'
        with self.assertRaises(ValueError): self.e.accept(self.a)
    def test_changed_precondition(self):
        self.a['localPrecondition']='e'*64;self.reapprove()
        with self.assertRaises(ValueError): self.e.accept(self.a)
        self.assertNotIn('create',self.driver.calls)
    def test_expiry_during_preflight_changes_nothing(self):
        clock=[time.time()]
        def preflight(*args):
            clock[0]=(self.a['expiresAt']+1)/1000
            return {'before':True},{'management':True}
        with patch.object(n.time,'time',side_effect=lambda:clock[0]),patch.object(self.driver,'preflight',side_effect=preflight):
            with self.assertRaises(ValueError): self.e.accept(self.a)
        self.assertNotIn('create',self.driver.calls)
    def test_duplicate_does_not_apply_twice(self):
        self.e.accept(self.a);self.e.accept(copy.deepcopy(self.a))
        self.assertEqual(self.driver.calls.count('create'),1)
    def test_reuse_identity_different_bytes(self):
        self.e.accept(self.a);self.a['reviewHash']='f'*64;self.reapprove()
        with self.assertRaises(ValueError): self.e.accept(self.a)
    def test_failed_prepare_has_no_external_changes(self):
        with patch.object(n,'atomic',side_effect=OSError('disk full')):
            with self.assertRaises(OSError): self.e.accept(self.a)
        self.assertNotIn('create',self.driver.calls)
    def test_failure_after_create_rolls_back(self):
        self.driver.fail='create';self.assertEqual(self.e.accept(self.a),'rolled-back');self.assertFalse(self.driver.exists)
    def test_failure_after_route_write_rolls_back(self):
        self.driver.fail='routes';self.assertEqual(self.e.accept(self.a),'rolled-back');self.assertFalse(self.driver.exists)
    def test_forward_or_management_failure_never_confirms(self):
        self.e.accept(self.a)
        for field in ['forward','reverse','management','handshake','fib','protected']:
            c=self.confirmation();c['verification']['checks'][field]=False
            with self.assertRaises(ValueError): self.e.confirm(c)
        self.assertEqual(self.row()['state'],'awaiting-verification')
    def test_no_confirm_times_out(self):
        self.e.accept(self.a)
        with patch.object(n.time,'time',return_value=(self.a['rollbackAt']+1)/1000): self.e.tick()
        self.assertEqual(self.row()['state'],'rolled-back')
    def test_backwards_clock_rolls_back(self):
        self.e.accept(self.a)
        with patch.object(n.time,'time',return_value=(self.a['issuedAt']-1)/1000): self.e.tick()
        self.assertEqual(self.row()['state'],'rolled-back')
    def test_deadline_during_verification_never_confirms(self):
        self.e.accept(self.a);c=self.confirmation()
        clock=[time.time()]
        def delayed(*args): clock[0]=(self.a['rollbackAt']+1)/1000
        with patch.object(n.time,'time',side_effect=lambda:clock[0]),patch.object(self.driver,'verify_local',side_effect=delayed):
            with self.assertRaises(ValueError): self.e.confirm(c)
        self.assertEqual(self.row()['state'],'rolled-back')
    def test_monotonic_deadline_rejects_confirm(self):
        self.e.accept(self.a);c=self.confirmation()
        with patch.object(n.time,'monotonic',return_value=time.monotonic()+100):
            with self.assertRaises(ValueError): self.e.confirm(c)
        self.assertEqual(self.row()['state'],'rolled-back')
    def test_restart_recovery_even_when_disabled(self):
        self.e.accept(self.a);self.cfg['enabled']=False
        n.Executor(self.cfg,self.temp.name,self.driver).recover()
        self.assertEqual(self.row()['state'],'rolled-back')
        with self.assertRaises(ValueError): self.e.accept(authorization())
    def test_foreign_writer_preserved(self):
        self.e.accept(self.a);self.driver.changed=True;self.e.recover()
        self.assertEqual(self.row()['state'],'rollback-failed');self.assertTrue(self.driver.exists)
    def test_rollback_failure_and_bounded_history(self):
        self.e.accept(self.a);self.driver.fail='remove'
        for _ in range(30): self.e.recover()
        self.assertEqual(self.row()['state'],'rollback-failed');self.assertLessEqual(len(self.row()['history']),16)
        self.assertIn('rollback',self.row()['diagnostic'])
    def test_invalid_operations(self):
        for field,value in [('interfaceName','eth0'),('secretRef','../key'),('address','0.0.0.0/0'),('driver','shell')]:
            op=copy.deepcopy(self.a['operation']);op[field]=value
            with self.assertRaises(ValueError): n.validate_operation(op)
    def test_protected_journal_permissions(self):
        self.e.accept(self.a)
        self.assertEqual(os.stat(self.e.path).st_mode & 0o777,0o600)
        with open(self.e.path) as stream:
            self.assertNotIn('privateKey',stream.read())


class TerminalCourier(unittest.TestCase):
    def setUp(self):
        import network_terminal_delivery as delivery
        self.d=delivery;self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=self.temp.name
        self.cfg={'terminalDelivery':{'url':'https://manager.example.invalid/api/network/execution/terminal','caFile':self.path+'/ca','certFile':self.path+'/cert','keyFile':self.path+'/key'}}
        for name in ['ca','cert','key']:
            n.atomic(self.path+'/'+name,{'test':'fixture'})
        n.atomic(self.path+'/terminal-results.json',[{'transactionId':'a'*32,'state':'confirmed'}])
        self.ssl=patch.object(delivery.ssl,'create_default_context');self.ssl.start();self.addCleanup(self.ssl.stop)
        self.network=patch.object(delivery.urllib.request,'build_opener');self.opener=self.network.start().return_value;self.addCleanup(self.network.stop)
        self.opener.open.return_value.__enter__.return_value.read.return_value=b'{"settled":true}'
        for module,name in [(n.subprocess,'run'),(n.subprocess,'Popen'),(n.socket,'socket')]:
            guard=patch.object(module,name,side_effect=AssertionError('escaped courier unit boundary'));guard.start();self.addCleanup(guard.stop)
    def test_only_direct_https_mtls_delivery_and_ack_deduplication(self):
        self.assertEqual(self.d.deliver(self.cfg,self.path),1)
        self.assertEqual(self.d.deliver(self.cfg,self.path),0)
        self.opener.open.assert_called_once()
        request=self.opener.open.call_args[0][0]
        self.assertNotIn('Authorization',request.headers);self.assertNotIn('Cookie',request.headers)
    def test_transport_loss_does_not_ack_and_can_retry_identical_result(self):
        self.opener.open.side_effect=OSError('lost response')
        with self.assertRaises(OSError):self.d.deliver(self.cfg,self.path)
        self.assertFalse(os.path.exists(self.path+'/terminal-acks.json'))
        self.opener.open.side_effect=None
        self.assertEqual(self.d.deliver(self.cfg,self.path),1)
    def test_unsuccessful_manager_response_never_acknowledges(self):
        self.opener.open.return_value.__enter__.return_value.read.return_value=b'{"settled":false}'
        with self.assertRaises(ValueError):self.d.deliver(self.cfg,self.path)
        self.assertFalse(os.path.exists(self.path+'/terminal-acks.json'))
    def test_plaintext_credentials_and_redirects_are_refused(self):
        for url in ['http://manager.example.invalid/api/network/execution/terminal','https://user:password@manager.example.invalid/api/network/execution/terminal','https://manager.example.invalid/api/network/execution/terminal?key=secret']:
            self.cfg['terminalDelivery']['url']=url
            with self.assertRaises(ValueError):self.d.deliver(self.cfg,self.path)
        with self.assertRaises(ValueError):self.d.NoRedirect().redirect_request(None,None,None,None,None,None)
    def test_private_key_permissions_are_checked_before_transport(self):
        # Inject insecure metadata without making even a disposable key world-readable.
        metadata=list(os.stat(self.path+'/key'));metadata[0]=(metadata[0] & ~0o777) | 0o644
        with patch.object(n.os,'fstat',return_value=os.stat_result(metadata)):
            with self.assertRaises(ValueError):self.d.deliver(self.cfg,self.path)
        self.opener.open.assert_not_called()
    def test_oversized_untrusted_response_is_not_recorded(self):
        self.opener.open.return_value.__enter__.return_value.read.return_value=b'X'*4097
        with self.assertRaises(ValueError):self.d.deliver(self.cfg,self.path)
        self.assertFalse(os.path.exists(self.path+'/terminal-acks.json'))


class Ownership(unittest.TestCase):
    def setUp(self):
        self.op=authorization()['operation']
        self.owner='heliopause:'+('a'*32)+':owner'
        self.routes=[{'dst':'192.0.2.130','dev':'hpaaaaaaaaaaaa','protocol':'static','scope':'link','metric':42760}]
        self.link={'ifindex':3,'ifname':'hpaaaaaaaaaaaa','mtu':1400,'ifalias':self.owner,'group':n.owner_group(self.owner),'linkinfo':{'info_kind':'wireguard'}}
        self.driver=n.LinuxWireGuard('/unused')
        self.psk='(none)'
        self.public=PUB;self.port='51820';self.peers=PEER
        self.addresses=[{'family':'inet','local':'192.0.2.129','prefixlen':32}]
        self.v6=[];self.routes6=[]
        def ip(*args):
            if args[0]=='-6': return [{'addr_info':self.v6}] if 'address' in args else self.routes6
            if 'link' in args: return [self.link]
            if 'address' in args: return [{'addr_info':self.addresses}]
            return self.routes
        def run(args,*unused,**kwargs):
            command=args[-1]
            return {'public-key':self.public,'listen-port':self.port,'endpoints':PEER+'\t203.0.113.2:51820' if self.peers else '', 'peers':self.peers,'allowed-ips':PEER+'\t192.0.2.130/32' if self.peers else '', 'preshared-keys':PEER+'\t'+self.psk if self.peers else ''}[command]
        self.driver.ip=ip;self.driver.run=run
        self.guard=patch.object(n.subprocess,'run',side_effect=AssertionError('escaped unit driver boundary'));self.guard.start();self.addCleanup(self.guard.stop)
    def test_expected_owned_shape(self): self.assertTrue(self.driver.owned(self.op,self.owner))
    def test_untagged_empty_interrupted_create_owned_by_transaction_name(self):
        self.link.pop('ifalias');self.public='(none)';self.port='0';self.peers='';self.addresses=[];self.routes=[]
        self.assertTrue(self.driver.owned(self.op,self.owner))
    def test_signed_numeric_group_matches_exact_kernel_bits(self):
        self.link['group']=str(n.owner_group(self.owner)-(1<<32))
        self.assertTrue(self.driver.owned(self.op,self.owner))
        for invalid in ['foreign',str(n.owner_group(self.owner)+(1<<32)),True]:
            self.link['group']=invalid
            with self.assertRaises(ValueError): self.driver.owned(self.op,self.owner)
    def test_foreign_same_name_default_group_is_preserved(self):
        self.link['group']=0
        with self.assertRaises(ValueError): self.driver.owned(self.op,self.owner)
    def test_untagged_nonempty_interface_is_preserved(self):
        self.link.pop('ifalias')
        with self.assertRaises(ValueError): self.driver.owned(self.op,self.owner)
    def test_foreign_gateway_route_preserved(self):
        self.routes[0]['gateway']='192.0.2.131'
        with self.assertRaises(ValueError): self.driver.owned(self.op,self.owner)
    def test_foreign_preferred_source_preserved(self):
        self.routes[0]['prefsrc']='192.0.2.2'
        with self.assertRaises(ValueError): self.driver.owned(self.op,self.owner)
    def test_foreign_table_preserved(self):
        self.routes[0]['table']=100
        with self.assertRaises(ValueError): self.driver.owned(self.op,self.owner)
    def test_foreign_kernel_route_preserved(self):
        self.routes.append({'dst':'192.0.2.140','dev':'hpaaaaaaaaaaaa','protocol':'kernel'})
        with self.assertRaises(ValueError): self.driver.owned(self.op,self.owner)
    def test_foreign_psk_preserved(self):
        self.psk='opaque-foreign-secret'
        with self.assertRaises(ValueError): self.driver.owned(self.op,self.owner)
    def test_no_ipv6_interface_row_is_empty_not_missing_ipv4_link(self):
        original=self.driver.ip
        self.driver.ip=lambda *args: [] if args[0]=='-6' and 'address' in args else original(*args)
        self.assertTrue(self.driver.owned(self.op,self.owner))
    def test_kernel_multicast_only_is_owned_but_foreign_ipv6_route_is_preserved(self):
        self.routes6=[{'type':'multicast','dst':'ff00::/8','table':'local','protocol':'kernel','metric':256,'flags':[],'pref':'medium'}]
        self.assertTrue(self.driver.owned(self.op,self.owner))
        normalized=dict(self.routes6[0]);normalized.pop('flags');normalized['dev']=self.op['interfaceName']
        self.assertTrue(n.kernel_multicast_route(normalized,self.op['interfaceName']))
        self.routes6[0]['metric']=257
        with self.assertRaises(ValueError): self.driver.owned(self.op,self.owner)
    def test_foreign_ipv6_preserved(self):
        self.v6=[{'local':'2001:db8::1'}]
        with self.assertRaises(ValueError): self.driver.owned(self.op,self.owner)


class NetlinkCreate(unittest.TestCase):
    def test_exclusive_create_carries_atomic_identity_group_and_mtu(self):
        class Channel:
            request=None
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def bind(self,address):self.address=address
            def getsockname(self):return (1234,0)
            def settimeout(self,value):self.timeout=value
            def sendto(self,request,address):self.request=request
            def recvfrom(self,size):
                seq=n.struct.unpack_from('=I',self.request,8)[0]
                return n.struct.pack('=IHHIIi',20,2,0,seq,1234,0),(0,0)
        channel=Channel()
        with patch.object(n.socket,'AF_NETLINK',16,create=True),patch.object(n.socket,'socket',return_value=channel) as boundary:
            n.LinuxWireGuard('/unused').create_link('hpaaaaaaaaaaaa',0x87654321,1400)
        boundary.assert_called_once()
        length,kind,flags,_,pid=n.struct.unpack_from('=IHHII',channel.request)
        self.assertEqual(length,len(channel.request));self.assertEqual(kind,16);self.assertEqual(flags & 0x600,0x600);self.assertEqual(pid,1234)
        self.assertEqual(n.struct.unpack_from('=BBHiII',channel.request,16)[-1],0)
        offset=32;attrs={}
        while offset<len(channel.request):
            size,field=n.struct.unpack_from('=HH',channel.request,offset)
            attrs[field]=channel.request[offset+4:offset+size];offset+=(size+3)&~3
        self.assertEqual(attrs[3],b'hpaaaaaaaaaaaa\0')
        self.assertEqual(n.struct.unpack('=I',attrs[27])[0],0x87654321)
        self.assertEqual(n.struct.unpack('=I',attrs[4])[0],1400)
        self.assertIn(b'wireguard\0',attrs[18|0x8000])


class WriterMode(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=self.temp.name
        self.agent=n.crypto_helpers(self.path)
        self.agent.STATE_FILE=self.path+'/firewall.json'
        self.config=self.path+'/custom-config.json';n.atomic(self.config,{})
        self.state=self.path+'/custom-state'
        self.calls=[];self.terminal=True
        owner=self
        class Recovery:
            def __init__(self,cfg,directory): owner.calls.append(('locate',directory))
            def recover(self): owner.calls.append(('recover',))
            def publish_results(self): owner.calls.append(('publish',))
            def load(self): return {'transactions':{'tx':{'state':'rolled-back' if owner.terminal else 'rollback-failed'}}}
        self.patches=[patch.object(n,'Executor',Recovery),patch.object(n.subprocess,'run',side_effect=AssertionError('unexpected subprocess boundary')),patch.object(n.subprocess,'Popen',side_effect=AssertionError('unexpected child boundary')),patch.dict(os.environ,{'HELIOPAUSE_WRITER_LOCK':self.path+'/writer.lock','HELIOPAUSE_NETWORK_EXECUTOR_STATE_DIR':self.path+'/unused-default'}),patch.object(sys,'argv',['agent'])]
        for p in self.patches:p.start();self.addCleanup(p.stop)
        self.agent.main=lambda:0
    def network_args(self):
        sys.argv[:]=['agent','--network-executor','--config',self.config,'--state-dir',self.state]
    def test_custom_locator_recovered_by_other_mode(self):
        self.network_args()
        with patch.object(n,'main',return_value=0) as enter:
            self.assertEqual(self.agent.run_writer_mode(),0);enter.assert_called_once()
        self.assertEqual(n.read_json(self.path+'/network-writer-locator.json')['stateDir'],self.state)
        sys.argv[:]=['agent']
        self.assertEqual(self.agent.run_writer_mode(),0)
        self.assertIn(('locate',self.state),self.calls);self.assertIn(('recover',),self.calls);self.assertIn(('publish',),self.calls)
    def test_unsettled_network_blocks_other_writer(self):
        n.atomic(self.path+'/network-writer-locator.json',{'config':self.config,'stateDir':self.state})
        self.terminal=False
        with patch.object(self.agent,'main',return_value=0) as enter:
            with self.assertRaises(RuntimeError):self.agent.run_writer_mode()
            enter.assert_not_called()
        self.assertIn(('recover',),self.calls)
    def test_live_writer_lock_preserves_owner(self):
        self.network_args()
        def active(*args):
            self.assertEqual(self.agent.run_writer_mode(),2)
            self.calls.append(('owner-survived',));return 0
        with patch.object(n,'main',side_effect=active):self.assertEqual(self.agent.run_writer_mode(),0)
        self.assertIn(('owner-survived',),self.calls)
    def test_old_firewall_debt_settled_before_new_writer(self):
        n.atomic(self.agent.STATE_FILE,{})
        state={'state':'pending','generation':'test-generation','workloadState':None,'workloadGeneration':None}
        def undo(*args):self.calls.append(('undo',));state['state']='rolled-back'
        self.network_args()
        # Explicit legacy recovery entry points are the boundary; their nft/ip/kubectl children
        # cannot escape because both subprocess entry points are fatal guards above.
        with patch.object(self.agent,'load_state',side_effect=lambda:dict(state)),patch.object(self.agent,'recover_commitment') as host,patch.object(self.agent,'recover_workload_commitment') as workload,patch.object(self.agent,'reconcile_recovered_commitments') as reconcile,patch.object(self.agent,'rollback_generation',side_effect=undo),patch.object(n,'main',return_value=0) as enter:
            self.assertEqual(self.agent.run_writer_mode(),0)
            host.assert_called_once();workload.assert_called_once();reconcile.assert_called_once();enter.assert_called_once()
        self.assertIn(('undo',),self.calls)
    def test_graceful_stop_settles_firewall_watchdog_debt(self):
        state={'state':'confirmed','generation':'test-generation','workloadState':None,'workloadGeneration':None}
        def run():state['state']='pending';return 0
        def undo(*args):self.calls.append(('stop-undo',));state['state']='rolled-back'
        self.agent.main=run
        with patch.object(self.agent,'load_state',side_effect=lambda:dict(state)),patch.object(self.agent,'rollback_generation',side_effect=undo):self.assertEqual(self.agent.run_writer_mode(),0)
        self.assertIn(('stop-undo',),self.calls)


if __name__=='__main__': unittest.main()
