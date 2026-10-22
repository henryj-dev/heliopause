#!/usr/bin/env python3
"""Generate ephemeral PKI only in tempfiles. Only bounded local OpenSSL is allowed."""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'agent'))
sys.path.insert(0,str(Path(__file__).parent))
import lifecycle_pki as pki
import lifecycle_snapshot as inventory


class LifecycleFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.binary=shutil.which('openssl');self.assertIsNotNone(self.binary)
        original=subprocess.run
        def guarded(argv,*args,**kwargs):
            if argv[0] not in {'openssl',self.binary}:raise AssertionError('escaped lifecycle fixture subprocess')
            kwargs['timeout']=min(kwargs.get('timeout',5),5)
            return original(argv,*args,**kwargs)
        guard=patch.object(subprocess,'run',side_effect=guarded);guard.start();self.addCleanup(guard.stop)
        guard=patch.object(socket,'socket',side_effect=AssertionError('escaped fixture socket'));guard.start();self.addCleanup(guard.stop)
        guard=patch.object(pki,'BASE',self.root/'new-pki');guard.start();self.addCleanup(guard.stop)
    def test_generated_leaf_constraints_and_wrong_ca(self):
        result=pki.prepare();self.assertTrue(result['newIsolatedCa']);self.assertEqual(len(result['labels']),9)
        base=pki.BASE/'pki'
        for label in ['gateway','gateway-next','gateway-retry']:
            self.assertIn('CN=gateway',result['labels'][label]['subject'].replace(' ',''))
            self.assertIn('TLS Web Client Authentication',result['labels'][label]['extendedKeyUsage'])
            self.assertNotEqual(result['labels'][label]['certificateSha256'],result['labels']['wrong-cn']['certificateSha256'])
        self.assertIn('CN=intruder',result['labels']['wrong-cn']['subject'].replace(' ',''))
        self.assertIn('TLS Web Server Authentication',result['labels']['wrong-eku']['extendedKeyUsage'])
        good=subprocess.run(['openssl','verify','-CAfile',str(base/'ca.pem'),str(base/'gateway.pem')],capture_output=True)
        wrong=subprocess.run(['openssl','verify','-CAfile',str(base/'ca.pem'),str(base/'wrong-ca.pem')],capture_output=True)
        self.assertEqual(good.returncode,0);self.assertNotEqual(wrong.returncode,0)
        self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertEqual((base/'gateway.key').stat().st_mode&0o777,0o600)
        with self.assertRaises(FileExistsError):pki.prepare()
    def test_inventory_file_commitment_and_bounds(self):
        file=self.root/'evidence';file.write_bytes(b'public measurement')
        self.assertEqual(inventory.commitment(file)['bytes'],18)
        with self.assertRaises(ValueError):inventory.commitment(file,1)
        link=self.root/'link';link.symlink_to(file)
        with self.assertRaises(OSError):inventory.commitment(link)


if __name__=='__main__':unittest.main()
