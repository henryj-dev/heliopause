"""Filesystem-only persistence contract tests; escaped process/socket calls are fatal."""
import copy
import hashlib
import os
import socket
import stat
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from network_nm_profile import ProfileStore, render, profile_uuid, DRIVER, BOOT_POLICY
from network_executor import validate_operation

TX = 'a'*32
OWNER = 'heliopause:'+TX+':'+'b'*32
KEY = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
PEER = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI='


def operation():
    return {'driver': DRIVER, 'interfaceId': 'new', 'interfaceName': 'hp'+TX[:12],
            'profileUuid': profile_uuid(TX), 'bootPolicy': BOOT_POLICY,
            'address': '198.51.100.1/32', 'mtu': 1420, 'listenPort': 51820,
            'secretRef': 'local', 'publicKey': KEY,
            'peers': [{'publicKey': PEER, 'endpoint': '203.0.113.2:51820', 'allowedIps': ['198.51.100.2/32']}],
            'routes': ['198.51.100.2/32']}


@unittest.skipUnless(sys.platform == 'linux', 'Linux renameat2 profile publication')
class Profiles(unittest.TestCase):
    def setUp(self):
        # The checkout's protected ancestors are used rather than a world-writable /tmp.
        self.temp = tempfile.TemporaryDirectory(prefix='.nm-profile-test-', dir=os.getcwd())
        self.addCleanup(self.temp.cleanup)
        self.store = ProfileStore(self.temp.name)
        self.op = operation()
        self.identity = self.op['profileUuid']
        self.content = render(self.op, OWNER, KEY)
        for module, name in [(subprocess, 'run'), (subprocess, 'Popen'), (socket, 'socket')]:
            guard = patch.object(module, name, side_effect=AssertionError('escaped profile unit boundary'))
            guard.start(); self.addCleanup(guard.stop)

    def path(self):
        return os.path.join(self.temp.name, self.store.basename(self.identity))

    def test_profile_is_never_automatically_activated(self):
        text = self.content.decode()
        self.assertIn('autoconnect=false\n', text)
        self.assertIn('peer-routes=false\n', text)
        self.assertIn('method=disabled\n', text)
        self.assertIn('route1=198.51.100.2/32,,42760\n', text)
        self.assertIn('heliopause.owner='+OWNER+'\n', text)
        self.assertNotIn('PostUp', text)

    def test_exclusive_publish_and_secret_mode(self):
        self.store.create(self.identity, self.content, OWNER)
        self.assertEqual(self.store.read(self.identity), self.content)
        info = os.stat(self.path())
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_nlink, 1)
        with self.assertRaises(FileExistsError): self.store.create(self.identity, self.content, OWNER)
        self.assertEqual(self.store.read(self.identity), self.content)

    def test_undo_requires_hash_but_not_original_secret(self):
        self.store.create(self.identity, self.content, OWNER)
        self.store.remove(self.identity, hashlib.sha256(self.content).hexdigest())
        self.assertFalse(os.path.lexists(self.path()))
        self.store.remove(self.identity, hashlib.sha256(self.content).hexdigest())

    def test_foreign_content_is_preserved(self):
        self.store.create(self.identity, b'foreign-profile', OWNER)
        with self.assertRaises(ValueError): self.store.remove(self.identity, hashlib.sha256(self.content).hexdigest())
        self.assertEqual(self.store.read(self.identity), b'foreign-profile')

    def test_symlink_is_neither_followed_nor_removed(self):
        target = os.path.join(self.temp.name, 'foreign')
        with open(target, 'wb') as stream: stream.write(b'foreign')
        os.symlink(target, self.path())
        with self.assertRaises(OSError): self.store.read(self.identity)
        with self.assertRaises(OSError): self.store.remove(self.identity, '0'*64)
        self.assertTrue(os.path.islink(self.path()))

    def reported_mode(self, path, mode):
        # Inject unsafe metadata at fstat; never loosen permissions even on fake secrets.
        original=os.fstat;identity=os.stat(path)
        def observe(fd):
            info=original(fd)
            if (info.st_dev,info.st_ino)==(identity.st_dev,identity.st_ino):
                values=list(info);values[0]=(info.st_mode & ~0o777)|mode
                return os.stat_result(values)
            return info
        return patch('network_nm_profile.os.fstat',side_effect=observe)

    def test_group_readable_secret_is_rejected(self):
        self.store.create(self.identity, self.content, OWNER)
        with self.reported_mode(self.path(),0o640):
            with self.assertRaises(ValueError): self.store.read(self.identity)

    def test_symlink_directory_is_rejected(self):
        alias = self.temp.name+'-alias'; os.symlink(self.temp.name, alias)
        self.addCleanup(os.unlink, alias)
        with self.assertRaises(OSError): ProfileStore(alias).read(self.identity)

    def test_writable_directory_is_rejected(self):
        with self.reported_mode(self.temp.name,0o770):
            with self.assertRaises(ValueError): self.store.create(self.identity, self.content, OWNER)

    def test_unsafe_signed_fields_are_rejected(self):
        for field, value in [('bootPolicy', 'autoconnect'), ('profileUuid', '../foreign'), ('interfaceName', 'external'), ('secretRef', 'x\nPostUp=sh')]:
            with self.subTest(field=field):
                op = copy.deepcopy(self.op); op[field] = value
                with self.assertRaises(ValueError): validate_operation(op)
        op = copy.deepcopy(self.op); op['profilePath'] = '/tmp/profile'
        with self.assertRaises(ValueError): validate_operation(op)

    def test_owner_and_uuid_are_bound(self):
        with self.assertRaises(ValueError): render(self.op, 'heliopause:'+'c'*32+':'+'b'*32, KEY)
        with self.assertRaises(ValueError): render(self.op, OWNER+'\n', KEY)
        with self.assertRaises(ValueError): render(self.op, OWNER, KEY+'\n')

    def test_complete_staging_secret_is_owned_and_removed(self):
        name = self.store.staging_name(self.identity, OWNER)
        path = os.path.join(self.temp.name, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream: stream.write(self.content)
        self.store.remove_staging(self.identity, OWNER, hashlib.sha256(self.content).hexdigest())
        self.assertFalse(os.path.exists(path))

    def test_partial_staging_secret_retains_explicit_recovery_debt(self):
        name = self.store.staging_name(self.identity, OWNER)
        path = os.path.join(self.temp.name, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream: stream.write(self.content[:50])
        with self.assertRaises(ValueError):
            self.store.remove_staging(self.identity, OWNER, hashlib.sha256(self.content).hexdigest())
        self.assertTrue(os.path.exists(path))

    def test_absence_has_directory_durability_barrier(self):
        with patch.object(os, 'fsync', wraps=os.fsync) as barrier:
            self.store.remove(self.identity, '0'*64)
        self.assertEqual(barrier.call_count, 1)

    def test_fsync_failure_after_publish_preserves_recovery_evidence(self):
        real = os.fsync; calls = []
        def failing(fd):
            calls.append(fd)
            if len(calls) == 2: raise OSError('injected directory fsync failure')
            return real(fd)
        with patch.object(os, 'fsync', side_effect=failing):
            with self.assertRaises(OSError): self.store.create(self.identity, self.content, OWNER)
        self.assertEqual(self.store.read(self.identity), self.content)
        self.assertEqual(os.stat(self.path()).st_nlink, 1)
        self.store.remove(self.identity, hashlib.sha256(self.content).hexdigest())


@unittest.skipUnless(sys.platform == 'linux', 'protected profile directory ancestors')
class Tombstones(unittest.TestCase):
    """NM leaves `<uuid>.nmmeta -> /dev/null` when it cannot delete a keyfile (2026-10-31 lab, 05)."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.nm-tombstone-test-', dir=os.getcwd())
        self.addCleanup(self.temp.cleanup)
        self.store = ProfileStore(self.temp.name)
        self.identity = profile_uuid(TX)
        self.marker = os.path.join(self.temp.name, self.identity+'.nmmeta')
        for module, name in [(subprocess, 'run'), (subprocess, 'Popen'), (socket, 'socket')]:
            guard = patch.object(module, name, side_effect=AssertionError('escaped profile unit boundary'))
            guard.start(); self.addCleanup(guard.stop)

    def test_the_marker_nm_left_for_a_removed_profile_is_removed(self):
        os.symlink('/dev/null', self.marker)
        self.store.remove_tombstone(self.identity)
        self.assertFalse(os.path.lexists(self.marker))

    def test_no_marker_is_a_clean_removal(self):
        self.store.remove_tombstone(self.identity)
        self.assertFalse(os.path.lexists(self.marker))

    def test_the_marker_stays_while_the_keyfile_is_present(self):
        os.symlink('/dev/null', self.marker)
        keyfile = os.path.join(self.temp.name, self.store.basename(self.identity))
        with open(keyfile, 'wb') as stream: stream.write(b'profile')
        with self.assertRaisesRegex(ValueError, 'still present'): self.store.remove_tombstone(self.identity)
        self.assertTrue(os.path.islink(self.marker))

    def test_metadata_that_is_not_the_deletion_marker_is_preserved(self):
        target = os.path.join(self.temp.name, 'elsewhere.nmconnection')
        for make in [lambda: os.symlink(target, self.marker), lambda: open(self.marker, 'wb').close()]:
            with self.subTest(make=make):
                make()
                with self.assertRaisesRegex(ValueError, 'foreign NetworkManager metadata'):
                    self.store.remove_tombstone(self.identity)
                self.assertTrue(os.path.lexists(self.marker))
                os.unlink(self.marker)


if __name__ == '__main__': unittest.main()
