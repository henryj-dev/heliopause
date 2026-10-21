"""Bounded, read-only commitments for this disposable lab's baseline inputs.

Only bounded source, public trust/certificates and configuration inputs are hashed.
Declared private-key paths/inode aliases are refused before opening public inputs;
malformed public PEMs produce no commitment. This is not secret declassification or
process-memory attestation.
"""
import hashlib
import os
from pathlib import Path
import stat

SOURCE_TREES = ('src', 'agent', 'scripts/network-transaction-lab', 'scripts/network-vm-lab', 'packages/i18n')


def stat_identity(info):
    return tuple(getattr(info, name) for name in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink'))


def file_commitment(path, public_kind=None, forbidden=()):
    before = os.lstat(path)
    if (before.st_dev,before.st_ino) in forbidden:
        raise ValueError('declared private key alias is not a public input')
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 8 * 1024 * 1024:
        raise ValueError('unsafe baseline input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if stat_identity(info) != stat_identity(before):
            raise ValueError('baseline input changed before read')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(8 * 1024 * 1024 + 1)
        if len(raw) != info.st_size or stat_identity(info) != stat_identity(os.fstat(fd)) or stat_identity(info) != stat_identity(os.lstat(path)):
            raise ValueError('baseline input changed during read')
        if public_kind and not raw.startswith(b'-----BEGIN '+public_kind+b'-----'):
            raise ValueError('expected public PEM input')
        return {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'uid': info.st_uid, 'mode': stat.S_IMODE(info.st_mode)}
    finally:
        os.close(fd)


def source_modules(root):
    """Fixed repository runtime trees; omit test files, refuse symlink traversal."""
    root = Path(root)
    paths = [root / 'package.json', root / 'package-lock.json']
    for tree in SOURCE_TREES:
        base = root / tree
        for current, dirs, files in os.walk(base, followlinks=False):
            if Path(current).is_symlink() or any((Path(current) / name).is_symlink() for name in dirs):
                raise ValueError('source directory symlink')
            for name in files:
                if name.endswith(('.ts', '.py', '.json')) and '.test.' not in name and not name.startswith('test_'):
                    paths.append(Path(current) / name)
    if len(paths) > 1024:
        raise ValueError('baseline source file count exceeded')
    return {str(path.relative_to(root)): file_commitment(path)['sha256'] for path in sorted(paths)}


def public_directory(path, forbidden=()):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError('public trust directory required')
    entries = sorted(path.iterdir())
    if len(entries) > 64:
        raise ValueError('public trust count exceeded')
    if any(entry.suffix!='.pem' for entry in entries):
        raise ValueError('only public PEM trust entries supported')
    return {entry.name: file_commitment(entry,b'PUBLIC KEY',forbidden) for entry in entries}


def frozen_inputs(role, config, etc=Path('/etc/heliopause'), base=Path('/var/lib/heliopause-vm-lab')):
    """Fixed lab configuration/public inputs; explicit key files are stat-only."""
    if role == 'gateway':
        delivery = config['terminalDelivery']
        certificates = {etc / 'pki/ca.pem', etc / 'pki/gateway.pem', Path(delivery['caFile']), Path(delivery['certFile'])}
        files = {etc / 'network-executor.json', etc / 'agent.env'} | certificates
        key_paths = [Path(delivery['keyFile']), etc / 'pki/gateway.key']
        directories = {'manager': Path(config['managerKeys']), 'verifier': Path(config['verifierKeys']), 'breakGlass': etc / 'trust/break-glass'}
    elif role == 'peer':
        certificates = {base / 'pki' / name for name in ('ca.pem', 'gateway.pem', 'manager.pem', 'relay.pem')}
        files = {base / 'config.json'} | certificates
        if config.get('lifecycleRevocations') is True:
            files.add(base / 'lifecycle-revocations.json')
        key_paths = [base / 'manager.key', base / 'verifier.key'] + [base / 'pki' / name for name in ('ca.key','gateway.key','manager.key','relay.key')]
        directories = {name: base / name for name in ('manager', 'verifier')}
    else:
        raise ValueError('unknown disposable role')
    forbidden = set()
    for path in key_paths:
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('declared private key must be a regular file')
        forbidden.add((info.st_dev,info.st_ino))
    # Do not open a declared key accidentally configured as a public certificate.
    for path in files:
        info = path.lstat()
        if (info.st_dev,info.st_ino) in forbidden:
            raise ValueError('declared private key alias is not a public input')
    trust = {name: public_directory(path,forbidden) for name,path in directories.items()}
    return {'files': {str(path): file_commitment(path,b'CERTIFICATE' if path in certificates else None,forbidden) for path in sorted(files)}, 'publicTrust': trust}
