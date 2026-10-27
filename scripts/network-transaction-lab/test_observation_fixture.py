"""HOST temporary-file controls, not guest or production Relay qualification."""
import hashlib
import json
import os
import stat
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from observation_fixture import ObservationTransport, decode_body


class Store(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = ObservationTransport(self.temp.name)
        self.addCleanup(self.store.close)

    def test_exact_tokens_receipt_and_original_survive_reopen(self):
        raw = b' { "report": {"x":1e0,"stamp":"original"}, "host":"gateway" } \n'
        first = self.store.put(raw)
        result = self.store.get()
        self.assertIn(b'"x":1e0,"stamp":"original"', result)
        self.assertEqual(json.loads(result)['observations'][0]['receivedAt'], first['receivedAt'])
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual((self.store.root / ('body-' + digest + '.bin')).read_bytes(), raw)
        self.assertEqual(self.store.put(raw), first)
        self.store.close()
        self.store = ObservationTransport(self.temp.name)
        self.assertEqual(self.store.get(), result)
        self.store.close()

    def test_partial_write_is_retained_and_not_repaired(self):
        raw = b'{"host":"gateway","report":{}}'
        original = self.store.exclusive
        with patch.object(self.store, 'exclusive', wraps=self.store.exclusive) as write:
            write.side_effect = lambda name, data: (_ for _ in ()).throw(OSError('receipt full')) if name.startswith('receipt-') else original(name, data)
            with self.assertRaises(OSError):
                self.store.put(raw)
        digest = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError, 'partial observation'):
            self.store.put(raw)
        self.assertEqual((self.store.root / ('body-' + digest + '.bin')).read_bytes(), raw)
        self.assertEqual(self.store.get(), b'{"observations":[]}')

    def test_orphan_receipt_never_recreates_missing_original(self):
        raw = b'{"host":"gateway","report":{}}'
        digest = hashlib.sha256(raw).hexdigest()
        self.store.exclusive('receipt-' + digest + '.json', b'{}')
        before = {p.name: p.read_bytes() for p in self.store.root.iterdir()}
        with self.assertRaisesRegex(ValueError, 'partial observation'):
            self.store.put(raw)
        self.assertEqual({p.name: p.read_bytes() for p in self.store.root.iterdir()}, before)

    def test_failed_pointer_is_preserved_and_never_retried(self):
        raw = b'{"host":"gateway","report":{}}'
        with patch('observation_fixture.os.replace', side_effect=OSError('rename failed')):
            with self.assertRaises(OSError):
                self.store.put(raw)
        before = {p.name: p.read_bytes() for p in self.store.root.iterdir()}
        self.assertTrue(any(name.startswith('.current-') for name in before))
        with self.assertRaisesRegex(ValueError, 'partial observation pointer'):
            self.store.put(raw)
        self.assertEqual({p.name: p.read_bytes() for p in self.store.root.iterdir()}, before)

    def test_visible_receipt_requires_file_and_directory_barriers_before_reuse(self):
        raw = b'{"host":"gateway","report":{}}'
        real_sync = os.fsync
        def receipt_sync_failure(fd):
            info = os.fstat(fd)
            receipts = list(self.store.root.glob('receipt-*.json'))
            if stat.S_ISREG(info.st_mode) and any(p.stat().st_ino == info.st_ino for p in receipts):
                raise OSError('receipt fsync EIO')
            return real_sync(fd)
        with patch('observation_fixture.os.fsync', side_effect=receipt_sync_failure):
            with self.assertRaisesRegex(OSError, 'receipt fsync'):
                self.store.put(raw)
            before = {p.name: p.read_bytes() for p in self.store.root.iterdir()}
            with self.assertRaisesRegex(OSError, 'receipt fsync'):
                self.store.put(raw)
            self.assertEqual({p.name: p.read_bytes() for p in self.store.root.iterdir()}, before)
        def directory_failure(fd):
            if fd == self.store.fd:
                raise OSError('directory fsync EIO')
            return real_sync(fd)
        with patch('observation_fixture.os.fsync', side_effect=directory_failure):
            with self.assertRaisesRegex(OSError, 'directory fsync'):
                self.store.put(raw)
            self.assertEqual({p.name: p.read_bytes() for p in self.store.root.iterdir()}, before)
        original_receipt = json.loads(next(self.store.root.glob('receipt-*.json')).read_bytes())
        self.assertEqual(self.store.put(raw), original_receipt)
        self.assertEqual(json.loads(self.store.get())['observations'][0]['receivedAt'], original_receipt['receivedAt'])

    def test_bad_pointer_and_symlink_original_refuse(self):
        self.store.put(b'{"host":"gateway","report":{}}')
        p = self.store.root / 'current.json'
        p.write_bytes(b'{"bodySha256":"../elsewhere"}')
        with self.assertRaises(ValueError):
            self.store.get()
        target = self.store.root / 'outside'
        target.write_bytes(b'never read')
        target.chmod(0o600)
        link = self.store.root / ('body-' + '0' * 64 + '.bin')
        link.symlink_to(target)
        with self.assertRaises(OSError):
            self.store.record('0' * 64)

    def test_immutable_body_tamper_refused(self):
        self.store.put(b'{"host":"gateway","report":{}}')
        path = next(self.store.root.glob('body-*.bin'))
        path.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.store.get()

    def test_full_spool_refuses_without_pruning(self):
        with patch('observation_fixture.MAX_RECORDS', 1):
            self.store.put(b'{"host":"gateway","report":{}}')
            before = {p.name: p.read_bytes() for p in self.store.root.iterdir()}
            with self.assertRaisesRegex(ValueError, 'full'):
                self.store.put(b'{"host":"gateway","report":{"x":2}}')
            self.assertEqual({p.name: p.read_bytes() for p in self.store.root.iterdir()}, before)


class Envelope(unittest.TestCase):
    def test_bad_utf8_duplicate_unknown_or_host_refuse(self):
        for raw in [b'\xff', b'{"host":"gateway","host":"gateway","report":{}}',
                    b'{"host":"gateway","report":{"x":1,"x":2}}',
                    b'{"host":"other","report":{}}',
                    b'{"host":"gateway","report":{},"receivedAt":"forged"}',
                    b'{"host":"gateway","report":[]}', b'{"host":"gateway","report":{"x":NaN}}']:
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                decode_body(raw)


if __name__ == '__main__':
    unittest.main()
