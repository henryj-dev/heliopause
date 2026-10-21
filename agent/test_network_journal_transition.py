"""Offline transition crash-window tests. Only tempfiles; all host processes/sockets fatal.

Cryptographic checks are independently exercised by Node/production signing tests and VM
round trips; these tests replace signature decoding and live kernel absence explicitly.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import network_executor as n
import network_journal_transition as t
REAL_CRYPTO_HELPERS=n.crypto_helpers
from test_network_executor import Fake,authorization


def synthetic_evidence(rows):
    evidence={'schemaVersion':1,'runs':[],'files':{}};attachments={}
    for tx,row in rows.items():
        files={}
        for role in t.ROLES:
            name=role+'-'+tx+'.json';raw=n.canonical({'synthetic':True,'kind':role,'transactionId':tx}).encode();attachments[name]=raw
            evidence['files'][name]={'kind':role,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)};files[role]=[name]
        evidence['runs'].append({'transactionId':tx,'authorizationHash':n.digest(row['authorization']),'sourceCommit':'1'*40,'imageSha256':'2'*64,'moduleManifestSha256':evidence['files'][files['modules'][0]]['sha256'],'files':files})
    return evidence,attachments


class Transition(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for module,name in [(subprocess,'Popen'),(socket,'socket')]:
            guard=patch.object(module,name,side_effect=AssertionError('escaped transition unit boundary'));guard.start();self.addCleanup(guard.stop)
        for target,options in [('crypto_helpers',{'return_value':object()}),('verify',{'side_effect':lambda value,*args:value.get('body',value)}),('independent_trust',{'return_value':None})]:
            guard=patch.object(n,target,**options);guard.start();self.addCleanup(guard.stop)
        self.state=self.root/'state';self.state.mkdir(mode=0o700);journal=n.initialize_journal(str(self.state));a=authorization();a['journalId']=journal;a['approval']['planHash']='sha256:'+n.digest({k:v for k,v in a.items() if k!='approval'})
        self.cfg={'enabled':True,'journalId':journal,'identity':a['target'],'managerKeys':'unused','verifierKeys':'unused','secrets':'unused','protectedAddresses':['192.0.2.1']}
        self.config=self.root/'config.json';n.atomic(str(self.config),self.cfg)
        self.executor=n.Executor(self.cfg,str(self.state),Fake());self.executor.accept(a);self.executor.recover();self.executor.publish_results()
        agent=self.executor.load();result=agent['transactions'][a['transactionId']]['terminalResult'];stamp=n.digest(result)
        n.atomic(str(self.state/'terminal-acks.json'),{stamp:True})
        manager={'schemaVersion':2,'execution':{'fence':None,'records':[{'transactionId':a['transactionId'],'authorization':{'payload':base64.urlsafe_b64encode(n.canonical(a).encode()).decode().rstrip('=')},'authorizationHash':n.digest(a),'target':a['target'],'journalId':journal,'state':'settled','result':result,'resultHash':stamp}]}}
        evidence,attachments=synthetic_evidence(agent['transactions'])
        raw_files={'evidence':n.canonical(evidence).encode(),'agent':(self.state/'transactions.json').read_bytes(),'manager':n.canonical(manager).encode(),'identity':(self.state/'journal-identity.json').read_bytes(),'outbox':(self.state/'terminal-results.json').read_bytes(),'acknowledgments':(self.state/'terminal-acks.json').read_bytes(),'trust':b'{"manager":{},"verifier":{}}','config':self.config.read_bytes()}
        self.archive=self.root/'archive';self.archive.mkdir(mode=0o700);ed=self.archive/'evidence';ed.mkdir(mode=0o700)
        for name,raw in attachments.items():p=ed/name;p.write_bytes(raw);p.chmod(0o600)
        manifest={'schemaVersion':1,'files':{}}
        for name,raw in raw_files.items():
            file=t.FILES[name];p=self.archive/file;p.write_bytes(raw);p.chmod(0o600);manifest['files'][file]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
        n.atomic(str(self.archive/'manifest.json'),manifest)
        archive=t.read_archive(self.archive);now=1000
        draft={'schemaVersion':1,'mode':'quiescent-without-confirmed-v1','transitionId':'d'*32,'target':a['target'],'oldJournalId':journal,'newJournalId':'e'*32,'archiveHash':n.digest(archive['rawFiles']),'managerHash':hashlib.sha256(raw_files['manager']).hexdigest(),'agentHash':hashlib.sha256(raw_files['agent']).hexdigest(),'configHash':hashlib.sha256(raw_files['config']).hexdigest(),'evidenceHash':hashlib.sha256(raw_files['evidence']).hexdigest(),'issuedAt':now,'expiresAt':now+3600000}
        self.payload={**draft,'approval':{'mode':'two-person','planHash':'sha256:'+n.digest(draft),'proposedBy':'alice','approvedBy':'bob','approvedAt':now}}
        self.envelope={'keyId':'test-manager','body':self.payload};self.receipt={'keyId':'test-manager','body':{'schemaVersion':1,'transitionHash':n.digest(self.payload),'oldJournalId':journal,'newJournalId':'e'*32,'target':a['target'],'archiveHash':draft['archiveHash'],'evidenceHash':draft['evidenceHash'],'committedAt':now}}
        self.writer=self.root/'writer.lock';self.writer.write_bytes(b'');self.writer.chmod(0o600)
        mount_guard=patch.object(t,'mount_info',return_value=[]);mount_guard.start();self.addCleanup(mount_guard.stop)
        self.absence=patch.object(t,'resource_absence',side_effect=AssertionError('live kernel absence must be explicitly injected'));self.absence.start();self.addCleanup(self.absence.stop)
    def apply(self,event=None,absence=lambda *args:None):
        return t.apply_agent(str(self.config),str(self.state),str(self.archive),self.envelope,self.receipt,str(self.writer),event=event,absence=absence)
    def reserve_capacity(self):
        from test_network_cancellation import cancellation
        data=self.executor.load();data['transactions'][next(iter(data['transactions']))]['diagnostic']='x'*(6*1024*1024);n.atomic(self.executor.path,data)
        a=copy.deepcopy(next(iter(data['transactions'].values()))['authorization']);a['transactionId']='f'*32
        self.executor.cancel(cancellation(a));self.executor.publish_results()
        rows=n.capacity_rows(self.executor.load(),n.read_json(str(self.state/'journal-identity.json')))
        results=self.executor.terminal_results();acks={n.digest(r):True for r in results};n.atomic(str(self.state/'terminal-acks.json'),acks)
        manager=n.read_json(str(self.archive/'manager.json'));record=copy.deepcopy(manager['execution']['records'][0]);result=results[-1]
        record.update(transactionId=a['transactionId'],authorization={'payload':base64.urlsafe_b64encode(n.canonical(a).encode()).decode().rstrip('=')},authorizationHash=n.digest(a),result=result,resultHash=n.digest(result));manager['execution']['records'].append(record)
        evidence,attachments=synthetic_evidence(rows)
        for name,raw in attachments.items():path=self.archive/'evidence'/name;path.write_bytes(raw);path.chmod(0o600)
        values={'manager':n.canonical(manager).encode(),'evidence':n.canonical(evidence).encode()}
        for name in ['agent','identity','outbox','acknowledgments']:values[name]=(self.state/t.FILES[name]).read_bytes()
        manifest=n.read_json(str(self.archive/'manifest.json'))
        for name,raw in values.items():
            path=self.archive/t.FILES[name];path.write_bytes(raw);path.chmod(0o600);manifest['files'][path.name]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
        n.atomic(str(self.archive/'manifest.json'),manifest);archive=t.read_archive(self.archive)
        draft={k:v for k,v in self.payload.items() if k!='approval'};draft.update(archiveHash=n.digest(archive['rawFiles']),managerHash=hashlib.sha256(values['manager']).hexdigest(),agentHash=hashlib.sha256(values['agent']).hexdigest(),evidenceHash=hashlib.sha256(values['evidence']).hexdigest())
        self.payload={**draft,'approval':{**self.payload['approval'],'planHash':'sha256:'+n.digest(draft)}};self.envelope={'keyId':'test-manager','body':self.payload}
        self.receipt={'keyId':'test-manager','body':{**self.receipt['body'],'transitionHash':n.digest(self.payload),'archiveHash':draft['archiveHash'],'evidenceHash':draft['evidenceHash']}}
        return values
    def test_capacity_archive_preserves_both_raw_replay_stores_and_checks_absence_for_reservation(self):
        values=self.reserve_capacity();seen=[]
        result=self.apply(absence=lambda cfg,old:seen.extend(old['transactions']))
        previous=Path(result['oldStatePreservedAt'])
        for name in ['agent','identity','outbox','acknowledgments']:self.assertEqual((previous/t.FILES[name]).read_bytes(),values[name])
        self.assertEqual(len(seen),2);self.assertEqual(n.read_json(str(self.state/'journal-identity.json')),{'journalId':'e'*32})
    def test_capacity_archive_resumes_after_primary_preserved_without_losing_reservation(self):
        values=self.reserve_capacity()
        def crash(point):
            if point=='old-preserved':raise RuntimeError('power cut')
        with self.assertRaises(RuntimeError):self.apply(event=crash)
        result=self.apply();previous=Path(result['oldStatePreservedAt'])
        self.assertEqual((previous/'journal-identity.json').read_bytes(),values['identity'])

    def test_real_signature_workspace_does_not_recreate_unpublished_successor(self):
        # Retain the production helper's mkdir/temp-file/fsync/cleanup behavior while
        # isolating its only subprocess (OpenSSL); no host network command can escape.
        def openssl_only(argv,*args,**kwargs):
            self.assertEqual(argv[1:3],['pkeyutl','-verify'])
            return subprocess.CompletedProcess(argv,0,b'Verified',b'')
        def verify(value,domain,keys,provider):
            self.assertTrue(provider._verify_ed25519('public-test',b'message',b'signature'))
            return value.get('body',value)
        with patch.object(n,'crypto_helpers',side_effect=REAL_CRYPTO_HELPERS),patch.object(n,'verify',side_effect=verify),patch.object(subprocess,'run',side_effect=openssl_only):
            def crash(point):
                if point=='old-preserved':raise RuntimeError('crash')
            with self.assertRaisesRegex(RuntimeError,'crash'):self.apply(event=crash)
            self.assertFalse(self.state.exists())
            result=self.apply()
            self.assertTrue(result['committed'])
            self.assertEqual(n.read_json(str(self.state/'journal-identity.json')),{'journalId':'e'*32})
        self.assertFalse(list(self.root.glob('.artifact-signature.*')))

    def test_complete_and_duplicate_never_reset_successor(self):
        result=self.apply();self.assertTrue(result['committed']);self.assertEqual(n.read_json(str(self.state/'journal-identity.json')),{'journalId':'e'*32})
        previous=Path(result['oldStatePreservedAt']);self.assertTrue((previous/'transactions.json').exists());self.assertTrue(n.journal_transition_pending(str(previous)))
        data=n.read_json(str(self.state/'transactions.json'));data['lastClock']=999;n.atomic(str(self.state/'transactions.json'),data)
        self.assertTrue(self.apply()['duplicate']);self.assertEqual(n.read_json(str(self.state/'transactions.json'))['lastClock'],999)
    def test_two_successive_epochs_preserve_both_originals(self):
        first=self.apply();old=self.cfg['journalId'];self.cfg=n.read_json(str(self.config))
        self.archive=self.root/'second-archive';self.archive.mkdir(mode=0o700);(self.archive/'evidence').mkdir(mode=0o700)
        manager={'schemaVersion':2,'execution':{'fence':None,'records':[]}}
        values={'evidence':n.canonical({'schemaVersion':1,'runs':[],'files':{}}).encode(),'manager':n.canonical(manager).encode(),'trust':b'{"manager":{},"verifier":{}}','config':self.config.read_bytes()}
        for name in ['agent','identity','outbox','acknowledgments']:values[name]=(self.state/t.FILES[name]).read_bytes()
        manifest={'schemaVersion':1,'files':{}}
        for name,raw in values.items():
            path=self.archive/t.FILES[name];path.write_bytes(raw);path.chmod(0o600)
            manifest['files'][path.name]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
        n.atomic(str(self.archive/'manifest.json'),manifest);archive=t.read_archive(self.archive)
        draft={k:v for k,v in self.payload.items() if k!='approval'}
        draft.update(transitionId='c'*32,oldJournalId='e'*32,newJournalId='f'*32,archiveHash=n.digest(archive['rawFiles']),managerHash=hashlib.sha256(values['manager']).hexdigest(),agentHash=hashlib.sha256(values['agent']).hexdigest(),configHash=hashlib.sha256(values['config']).hexdigest(),evidenceHash=hashlib.sha256(values['evidence']).hexdigest())
        self.payload={**draft,'approval':{**self.payload['approval'],'planHash':'sha256:'+n.digest(draft)}}
        self.envelope={'keyId':'test-manager','body':self.payload}
        self.receipt={'keyId':'test-manager','body':{**self.receipt['body'],'transitionHash':n.digest(self.payload),'oldJournalId':'e'*32,'newJournalId':'f'*32,'archiveHash':draft['archiveHash'],'evidenceHash':draft['evidenceHash']}}
        second=self.apply();self.assertTrue(second['committed'])
        self.assertEqual(n.read_json(str(self.state/'journal-identity.json')),{'journalId':'f'*32})
        self.assertEqual(n.read_json(str(Path(first['oldStatePreservedAt'])/'journal-identity.json')),{'journalId':old})
        prior=Path(second['oldStatePreservedAt']);self.assertTrue((prior/'previous-transition.json').exists())
        self.assertEqual(n.read_json(str(prior/'journal-identity.json')),{'journalId':'e'*32})
    def test_config_boolean_alias_not_accepted_as_same_bytes(self):
        cfg=copy.deepcopy(self.cfg);cfg['enabled']=1;n.atomic(str(self.config),cfg)
        with self.assertRaisesRegex(ValueError,'configuration bytes differ'):self.apply()
        self.assertFalse(Path(str(self.state)+'.transition.json').exists())
    def test_read_only_inspection_refuses_manager_fence(self):
        path=self.archive/'manager.json';manager=n.read_json(str(path));manager['execution']['fence']={'transactionId':'f'*32};n.atomic(str(path),manager)
        manifest=n.read_json(str(self.archive/'manifest.json'));raw=path.read_bytes();manifest['files'][path.name]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)};n.atomic(str(self.archive/'manifest.json'),manifest)
        with self.assertRaisesRegex(ValueError,'quiescent identities/fence'):t.inspect_agent(str(self.config),str(self.state),str(self.archive),str(self.writer),absence=lambda *args:None)
        self.assertFalse(Path(str(self.state)+'.transition.json').exists())
    def test_read_only_inspection_before_manager_commit_does_not_change_files(self):
        before={str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        result=t.inspect_agent(str(self.config),str(self.state),str(self.archive),str(self.writer),absence=lambda *args:None)
        self.assertTrue(result['readOnly']);self.assertTrue(result['readyForManagerReview'])
        self.assertEqual(before,{str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
    def test_mounted_state_refused_before_intent(self):
        with patch.object(t,'mount_info',return_value=[str(self.state)]):
            with self.assertRaisesRegex(ValueError,'mounted journal directory'):self.apply()
        self.assertFalse(Path(str(self.state)+'.transition.json').exists())
    def test_owned_partial_stage_completed_without_tempfile_overwrite(self):
        def crash(point):
            if point=='stage-owned':raise RuntimeError('crash')
        with self.assertRaises(RuntimeError):self.apply(event=crash)
        stage=self.state.with_name(self.state.name+'.prepared-'+self.payload['transitionId'])
        raw=n.canonical(t.empty_journal(self.payload['newJournalId'])).encode();partial=raw[:17]
        file=stage/'transactions.json';file.write_bytes(partial);file.chmod(0o600)
        original=n.atomic
        def no_stage_atomic(path,value):
            if str(path).startswith(str(stage)+os.sep):raise AssertionError('partial staging must use append without orphan tempfiles')
            return original(path,value)
        with patch.object(n,'atomic',side_effect=no_stage_atomic):self.assertTrue(self.apply()['committed'])
        progress=n.read_json(str(self.state)+'.transition.json')
        self.assertEqual(progress['partialStages']['transactions.json'],[hashlib.sha256(partial).hexdigest()])
        self.assertEqual((self.state/'transactions.json').read_bytes(),raw)
    def test_missing_external_evidence_preserves_journal(self):
        path=next((self.archive/'evidence').iterdir());path.unlink()
        with self.assertRaisesRegex(ValueError,'missing/extra execution evidence'):self.apply()
        self.assertEqual(self.executor.load()['acceptedSequence'],1)
        self.assertFalse(Path(str(self.state)+'.transition.json').exists())
    def test_tampered_external_evidence_preserves_journal(self):
        next((self.archive/'evidence').iterdir()).write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,'execution evidence hash mismatch'):self.apply()
        self.assertEqual(self.executor.load()['acceptedSequence'],1)
    def test_evidence_manifest_not_in_manager_receipt_refused(self):
        self.receipt['body']['evidenceHash']='0'*64
        with self.assertRaisesRegex(ValueError,'receipt binding mismatch'):self.apply()
        self.assertFalse(Path(str(self.state)+'.transition.json').exists())
    def test_config_changed_while_waiting_for_lock(self):
        import fcntl
        original=fcntl.flock
        def change(fd,operation):
            result=original(fd,operation)
            cfg=copy.deepcopy(self.cfg);cfg['enabled']=False;n.atomic(str(self.config),cfg)
            return result
        with patch.object(fcntl,'flock',side_effect=change):
            with self.assertRaisesRegex(ValueError,'configuration changed'):self.apply()
        self.assertFalse(Path(str(self.state)+'.transition.json').exists())
    def test_retired_sidecar_drift_on_resume(self):
        def crash(point):
            if point=='old-preserved':raise RuntimeError('crash')
        with self.assertRaises(RuntimeError):self.apply(event=crash)
        previous=self.state.with_name(self.state.name+'.retired-'+self.cfg['journalId'])
        n.atomic(str(previous/'terminal-acks.json'),{})
        with self.assertRaisesRegex(ValueError,'sidecar drift'):self.apply()
        self.assertFalse(self.state.exists())
    def test_foreign_stage_without_owner_preserved(self):
        stage=self.state.with_name(self.state.name+'.prepared-'+self.payload['transitionId'])
        stage.mkdir(mode=0o700);foreign=stage/'transactions.json';foreign.write_bytes(b'{');foreign.chmod(0o600)
        with self.assertRaises(FileNotFoundError):self.apply()
        self.assertEqual(foreign.read_bytes(),b'{')
    def test_missing_receipt_no_intent(self):
        self.receipt['body']['transitionHash']='f'*64
        with self.assertRaisesRegex(ValueError,'exact Manager'):self.apply()
        self.assertFalse(Path(str(self.state)+'.transition.json').exists())
    def test_archive_tamper_no_mutation(self):
        (self.archive/'transactions.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,'hash mismatch'):self.apply()
        self.assertEqual(self.executor.load()['acceptedSequence'],1)
    def test_configuration_drift(self):
        cfg=copy.deepcopy(self.cfg);cfg['enabled']=False;n.atomic(str(self.config),cfg)
        with self.assertRaisesRegex(ValueError,'configuration drift'):self.apply()
    def test_missing_ack_no_mutation(self):
        n.atomic(str(self.state/'terminal-acks.json'),{})
        with self.assertRaisesRegex(ValueError,'sidecar drift'):self.apply()
    def test_foreign_resource_refused(self):
        with self.assertRaisesRegex(ValueError,'foreign interface'):self.apply(absence=lambda *args:(_ for _ in ()).throw(ValueError('old/foreign interface remains')))
        self.assertFalse(Path(str(self.state)+'.transition.json').exists())
    def test_preexisting_destination_never_overwritten(self):
        previous=self.state.with_name(self.state.name+'.retired-'+self.cfg['journalId']);previous.mkdir(mode=0o700)
        with self.assertRaises(FileNotFoundError):self.apply()
        self.assertEqual(self.executor.load()['acceptedSequence'],1)
    def test_unsafe_archive_symlink(self):
        path=self.archive/'terminal-acks.json';data=path.read_bytes();path.unlink();target=self.root/'outside';target.write_bytes(data);target.chmod(0o600);path.symlink_to(target)
        with self.assertRaises(OSError):self.apply()
    def test_pending_blocks_admission_but_preserves_terminal_recovery(self):
        def crash(point):
            if point=='intent-saved':raise RuntimeError('crash')
        with self.assertRaisesRegex(RuntimeError,'crash'):self.apply(event=crash)
        with self.assertRaisesRegex(ValueError,'offline transition'):self.executor.accept(authorization())
        self.executor.recover();self.assertEqual(self.executor.load()['acceptedSequence'],1)
        self.assertTrue(self.apply()['committed'])


def boundary_test(point):
    def test(self):
        def crash(value):
            if value==point:raise RuntimeError('simulated crash '+point)
        with self.assertRaisesRegex(RuntimeError,'simulated crash'):self.apply(event=crash)
        self.assertTrue(self.apply()['committed'])
        self.assertEqual(n.read_json(str(self.state/'transactions.json'))['acceptedSequence'],0)
    return test
for boundary in ['intent-saved','old-retired','old-preserved','stage-created','stage-owned','successor-prepared','successor-published','config-bound','complete']:
    setattr(Transition,'test_resume_after_'+boundary.replace('-','_'),boundary_test(boundary))


if __name__=='__main__':unittest.main()
