#!/usr/bin/env python3
"""Synthetic evidence only; no sockets, guest commands, or host network commands."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('bundle',Path(__file__).with_name('bundle.py'))
b = importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
SOURCE = '1'*40
IMAGE = '2'*64


def fixture():
    docs = {};boots = [];previous = 'initial'
    for i,name in enumerate(sorted(b.BOOTS)):
        tx = 'a'*32;boot = 'boot-'+str(i)
        row = {'state':'confirmed','authorization':{'operation':{'driver':'networkmanager-wireguard-1.56-v1'}},
               'bootRestore':{'bootId':boot,'state':'restored'}}
        journal = {'journalId':'b'*32,'acceptedSequence':1,'terminalSequence':1,'transactions':{tx:row}}
        at = i*10+1
        timeline = [{'at':at+n,'peerBootId':'peer','management':True,'forward':True,'reverse':True} for n in range(5)]
        v = {'sourceCommit':SOURCE,'imageSha256':IMAGE,'mode':'graceful' if i<13 else 'power-cut',
             'transaction':tx,'expected':'restored','passed':True,'before':{'bootId':previous,'journal':copy.deepcopy(journal)},
             'after':{'bootId':boot,'journal':journal},'peerBootBefore':'peer','peerBootAfter':'peer',
             'managerBefore':{'nextSequence':2,'records':[{'transactionId':'a'*32,'authorizationHash':'c'*64}]},'managerAfter':{'nextSequence':2,'records':[{'transactionId':'a'*32,'authorizationHash':'c'*64}]},
             'requestAt':at,'requestPeerAt':at,'recoveredPeerAt':at+2,'packetTimeline':timeline,
             'monitorStopped':{'at':at+4,'bootId':'peer'},'currentProbes':{'transactionId':tx,'gateway':{'bootId':boot},
             'observedAt':(at+3)*1000,'checks':{k:True for k in ['interface','address','route','fib','handshake','protected','management','forward','reverse']}}}
        p='/synthetic/'+name;docs[p]=v
        boots.append({'file':p,'mode':v['mode'],'transaction':tx,'expected':'restored','beforeBootId':previous,
                      'afterBootId':boot,'peerBootId':'peer','samples':5})
        previous=boot
    for i in range(10):
        auth={'target':{'source':'lab','host':'gw','nodeId':'node'},'artifactHash':'d'*64};authhash=b.sha(b.canonical(auth));result={'state':'rolled-back','target':auth['target'],'authorizationHash':authhash,'artifactHash':auth['artifactHash'],'transactionId':'tx'};stamp=b.sha(b.canonical(result))
        docs[f'/synthetic/{i}-settled.json']={'sourceCommit':SOURCE,'passed':True,'acknowledgedResultHash':stamp,
            'evidence':{'journal':{'journalId':'b'*32,'transactions':{'tx':{'terminalResult':result,'authorization':auth}}},'acknowledgements':{stamp:True}},
            'manager':{'fence':None,'records':[{'state':'settled','journalId':'b'*32,'transactionId':'tx','result':result,'resultHash':stamp,'target':auth['target'],'authorizationHash':authhash,'artifactHash':auth['artifactHash']}]}}
    groups=[{'id':name,'passed':True,'evidence':[]} for name in sorted(b.GROUPS)]
    for i,(p,v) in enumerate(docs.items()):groups[i%13]['evidence'].append({'path':p,'sha256':b.sha(b.canonical(v))})
    report={'kind':'rocky10-persistent-actual-vm-acceptance','sourceCommit':SOURCE,'imageSha256':IMAGE,
            'backend':'networkmanager-wireguard-1.56-v1','passed':13,'failed':0,'skipped':0,'bootCases':25,
            'graceful':13,'powerCut':12,'groups':groups,'boots':boots,'additionalEvidence':[],'orchestration':[],
            'transientRecoveryEvents':[{'diagnostic':'retained synthetic fault'}],'orchestrationInterruptions':[{'reason':'retained synthetic interruption'}]}
    return report,docs


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.report,self.docs=fixture()
        self.block=patch('subprocess.Popen',side_effect=AssertionError('escaped process'))
        self.block.start();self.addCleanup(self.block.stop)
        self.socket=patch('socket.socket',side_effect=AssertionError('escaped socket'));self.socket.start();self.addCleanup(self.socket.stop)
    def check(self):return b.validate(self.report,self.docs,SOURCE,IMAGE)
    def archive(self,root):
        report,docs=fixture();lab=root/'lab';lab.mkdir(mode=0o700)
        for group in report['groups']:
            for entry in group['evidence']:
                old=entry['path'];entry['path']=str(lab/Path(old).name)
                (lab/Path(old).name).write_bytes(b.canonical(docs[old]))
        for boot in report['boots']:boot['file']=str(lab/Path(boot['file']).name)
        raw=b.canonical(report);path=lab/'report.json';path.write_bytes(raw)
        return path,lab,root/'bundle',b.sha(raw)
    def test_archive_roundtrip_and_mutations(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b,'source_commitments',return_value={'agent/fake.py':'a'*64}):
            root=Path(tmp);path,lab,dest,stamp=self.archive(root)
            b.preserve(path,lab,dest,stamp,SOURCE,IMAGE,root)
            self.assertEqual(len(b.check_bundle(dest,stamp,SOURCE,IMAGE,root)),35)
            manifest=b.parse((dest/'manifest.json').read_bytes());entry=manifest['files'][0]
            target=dest/entry['file'];original=target.read_bytes();target.write_bytes(original+b' ')
            with self.assertRaisesRegex(ValueError,'hash mismatch'):b.check_bundle(dest,stamp,SOURCE,IMAGE,root)
            target.write_bytes(original);target.unlink()
            with self.assertRaises(FileNotFoundError):b.check_bundle(dest,stamp,SOURCE,IMAGE,root)
    def test_archive_permissions_rechecked(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b,'source_commitments',return_value={}):
            root=Path(tmp);path,lab,dest,stamp=self.archive(root);b.preserve(path,lab,dest,stamp,SOURCE,IMAGE,root)
            (dest/'report.json').chmod(0o644)
            with self.assertRaisesRegex(ValueError,'0600'):b.check_bundle(dest,stamp,SOURCE,IMAGE,root)
            (dest/'report.json').chmod(0o600);dest.chmod(0o755)
            with self.assertRaisesRegex(ValueError,'0700'):b.check_bundle(dest,stamp,SOURCE,IMAGE,root)
    def test_archive_wrong_anchor_and_source(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b,'source_commitments',return_value={}):
            root=Path(tmp);path,lab,dest,stamp=self.archive(root)
            with self.assertRaisesRegex(ValueError,'digest mismatch'):b.preserve(path,lab,dest,'0'*64,SOURCE,IMAGE,root)
            self.assertFalse(dest.exists())
            b.preserve(path,lab,dest,stamp,SOURCE,IMAGE,root)
            with self.assertRaisesRegex(ValueError,'anchor mismatch'):b.check_bundle(dest,stamp,'0'*40,IMAGE,root)
    def test_archive_refuses_existing_destination(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b,'source_commitments',return_value={}):
            root=Path(tmp);path,lab,dest,stamp=self.archive(root);dest.mkdir()
            with self.assertRaises(FileExistsError):b.preserve(path,lab,dest,stamp,SOURCE,IMAGE,root)
    def test_archive_refuses_public_parent(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b,'source_commitments',return_value={}):
            root=Path(tmp);path,lab,dest,stamp=self.archive(root);root.chmod(0o755)
            with self.assertRaisesRegex(ValueError,'private archive parent'):b.preserve(path,lab,dest,stamp,SOURCE,IMAGE,root)
    def test_partial_copy_is_not_verified_archive(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b,'source_commitments',return_value={}):
            root=Path(tmp);path,lab,dest,stamp=self.archive(root)
            actual=b.write_file;calls=[]
            def fail(fd,name,raw):
                calls.append(name)
                if len(calls)==3:raise OSError('synthetic archive disk full')
                actual(fd,name,raw)
            with patch.object(b,'write_file',side_effect=fail):
                with self.assertRaisesRegex(OSError,'disk full'):b.preserve(path,lab,dest,stamp,SOURCE,IMAGE,root)
            self.assertTrue(path.exists());self.assertFalse((dest/'manifest.json').exists())
            with self.assertRaises(FileNotFoundError):b.check_bundle(dest,stamp,SOURCE,IMAGE,root)
    def test_duplicate_or_unmanifested_archive_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b,'source_commitments',return_value={}):
            root=Path(tmp);path,lab,dest,stamp=self.archive(root);b.preserve(path,lab,dest,stamp,SOURCE,IMAGE,root)
            manifest=b.parse((dest/'manifest.json').read_bytes());manifest['files'][1]=manifest['files'][0]
            (dest/'manifest.json').write_bytes(b.canonical(manifest))
            with self.assertRaisesRegex(ValueError,'duplicate'):b.check_bundle(dest,stamp,SOURCE,IMAGE,root)

    def test_synthetic_complete(self):self.assertEqual(len(self.check()),25)
    def test_parent_traversal_reference_rejected(self):
        self.report['groups'][0]['evidence'][0]['path']='/synthetic/../outside.json'
        with self.assertRaisesRegex(ValueError,'parent traversal'):b.references(self.report)
    def test_manager_record_substitution_rejected(self):
        next(iter(self.docs.values()))['managerAfter']['records'][0]['transactionId']='other'
        with self.assertRaisesRegex(ValueError,'issuance changed'):self.check()
    def test_settlement_target_substitution_rejected(self):
        self.docs['/synthetic/0-settled.json']['manager']['records'][0]['target']={'host':'other'}
        with self.assertRaisesRegex(ValueError,'terminal result'):self.check()
    def test_missing_group(self):
        self.report['groups'].pop()
        with self.assertRaisesRegex(ValueError,'group'):self.check()
    def test_duplicate_group(self):
        self.report['groups'][1]=self.report['groups'][0]
        with self.assertRaisesRegex(ValueError,'group'):self.check()
    def test_duplicate_case(self):
        g=self.report['groups'][0];g['evidence'].append(g['evidence'][0])
        with self.assertRaisesRegex(ValueError,'duplicate case'):self.check()
    def test_wrong_source(self):
        self.report['sourceCommit']='f'*40
        with self.assertRaisesRegex(ValueError,'source'):self.check()
    def test_missing_boot(self):
        self.docs[next(iter(self.docs))].pop('mode')
        with self.assertRaisesRegex(ValueError,'boot case'):self.check()
    def test_pid_restart_is_not_boot(self):
        v=next(iter(self.docs.values()));v['after']['bootId']=v['before']['bootId']
        with self.assertRaisesRegex(ValueError,'actual boot'):self.check()
    def test_peer_reboot(self):
        next(iter(self.docs.values()))['peerBootAfter']='new-peer'
        with self.assertRaisesRegex(ValueError,'peer'):self.check()
    def test_journal_reset(self):
        next(iter(self.docs.values()))['after']['journal']['acceptedSequence']=0
        with self.assertRaisesRegex(ValueError,'replay identity'):self.check()
    def test_no_fresh_packet(self):
        next(iter(self.docs.values()))['currentProbes']['checks']['forward']=False
        with self.assertRaisesRegex(ValueError,'packet'):self.check()
    def test_stale_packet(self):
        next(iter(self.docs.values()))['currentProbes']['observedAt']=0
        with self.assertRaisesRegex(ValueError,'outside boot'):self.check()
    def test_timeline_gap(self):
        next(iter(self.docs.values()))['packetTimeline'][2]['at']+=20
        with self.assertRaisesRegex(ValueError,'timeline'):self.check()
    def test_false_ack(self):
        v=self.docs['/synthetic/0-settled.json'];v['evidence']['acknowledgements']={}
        with self.assertRaisesRegex(ValueError,'acknowledgment'):self.check()
    def test_wrong_settlement(self):
        self.docs['/synthetic/0-settled.json']['manager']['records'][0]['result']={'state':'confirmed'}
        with self.assertRaisesRegex(ValueError,'terminal result'):self.check()
    def test_failure_history_required(self):
        self.report['transientRecoveryEvents']=[]
        with self.assertRaisesRegex(ValueError,'failure history'):self.check()
    def test_private_pem_refused(self):
        with self.assertRaisesRegex(ValueError,'private PEM'):b.secret_check(b'-----BEGIN '+b'PRIVATE KEY-----',False)
    def test_nested_envelope_secret_refused(self):
        import base64
        raw=b.canonical({'payload':base64.urlsafe_b64encode(b'{"privateKey":"secret"}').decode()})
        with self.assertRaisesRegex(ValueError,'secret field'):b.secret_check(raw,True)
    def test_full_profile_refused(self):
        with self.assertRaisesRegex(ValueError,'keyfile'):b.secret_check(b'[wireguard]\nprivate-key=hidden',False)
    def test_duplicate_json_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate'):b.parse(b'{"x":1,"x":2}')
    def test_nonfinite_json_rejected(self):
        with self.assertRaisesRegex(ValueError,'nonfinite'):b.parse(b'{"x":NaN}')
    def test_symlink_and_hardlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'file';p.write_bytes(b'test');q=Path(tmp)/'link';q.symlink_to(p)
            with self.assertRaises(OSError):b.safe_read(q)
            q.unlink();os.link(p,q)
            with self.assertRaisesRegex(ValueError,'single-link'):b.safe_read(p)
    def test_symlink_ancestor_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)/'d';d.mkdir();(d/'f').write_bytes(b'test');s=Path(tmp)/'s';s.symlink_to(d)
            with self.assertRaises(OSError):b.safe_read(s/'f')
    def test_oversize_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'file';p.write_bytes(b'1234')
            with self.assertRaisesRegex(ValueError,'bounded'):b.safe_read(p,3)
    def test_exclusive_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            fd=os.open(tmp,os.O_DIRECTORY)
            try:
                b.write_file(fd,'f',b'original')
                with self.assertRaises(FileExistsError):b.write_file(fd,'f',b'replaced')
                self.assertEqual((Path(tmp)/'f').read_bytes(),b'original')
            finally:os.close(fd)


if __name__=='__main__':unittest.main()
