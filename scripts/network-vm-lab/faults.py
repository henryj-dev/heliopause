#!/usr/bin/env python3
"""Reversible prerequisite faults in an explicitly marked disposable gateway.

Never activates/removes a gateway transaction through a substitute driver. Restoring the
exact injected prerequisite is an operator repair; only the production Agent performs
subsequent activation/undo/terminal settlement. No arbitrary input paths or commands.
"""
import argparse
import hashlib
import os
from pathlib import Path
import stat
import re
import sys
sys.path.insert(0,'/opt/heliopause/agent')
import network_executor as n
from network_nm_profile import ProfileStore


def read(path):
    return n.read_file(str(path),maximum=32768,secret=True)


def write(path, data, replace=False):
    # All callers derive these paths from validated, signed transaction identities.
    temporary=path.with_name(path.name+'.fault-stage')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    if replace:os.replace(temporary,path)
    else:
        os.link(temporary,path,follow_symlinks=False);os.unlink(temporary)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--nonce',required=True);parser.add_argument('--id',required=True);parser.add_argument('--transaction',required=True);parser.add_argument('--action',choices=['profile-mtu','profile-missing','secret-missing','secret-permissions','repair'],required=True);args=parser.parse_args()
    if os.geteuid()!=0 or n.read_json('/etc/heliopause-disposable-lab')!={'role':'gateway','nonce':args.nonce}:raise ValueError('marked disposable gateway required')
    if not re.fullmatch('[a-f0-9]{32}',args.id):raise ValueError('unique fault identity required')
    cfg=n.read_json('/etc/heliopause/network-executor.json')
    rows=n.read_json('/var/lib/heliopause/network-executor/transactions.json')['transactions'];row=rows[args.transaction]
    op=row['authorization']['operation'];n.validate_operation(op)
    if op['driver']!='networkmanager-wireguard-1.56-v1' or op['profileUuid'].replace('-','')!=args.transaction:raise ValueError('persistent transaction required')
    directory=Path('/var/lib/heliopause-vm-lab/faults')/args.transaction/args.id
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    info=directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('protected fault directory required')
    metadata=directory/'pending.json'
    profile=Path('/etc/NetworkManager/system-connections')/ProfileStore.basename(op['profileUuid'])
    secret=Path(cfg['secrets'])/(op['secretRef']+'.key')
    sha=lambda value:hashlib.sha256(value).hexdigest()
    if args.action=='repair':
        fault=n.read_json(str(metadata));target=profile if fault['kind'].startswith('profile-') else secret
        backup=read(directory/'original')
        if sha(backup)!=fault['originalHash']:raise ValueError('fault backup integrity mismatch')
        missing=fault['kind'].endswith('-missing')
        if missing:
            try:target.lstat()
            except FileNotFoundError:pass
            else:raise ValueError('new foreign prerequisite must be preserved')
        elif fault['kind']=='secret-permissions':
            fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
            try:
                info=os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o640 or os.read(fd,129)!=backup:raise ValueError('secret changed after injected fault')
                os.fchmod(fd,0o600);os.fsync(fd)
            finally:os.close(fd)
        elif sha(read(target))!=fault['faultHash']:raise ValueError('foreign profile changed after injected fault')
        if fault['kind']!='secret-permissions':write(target,backup,replace=not missing)
        metadata.rename(directory/'completed.json')
        print(n.canonical({'repairedPrerequisite':fault['kind'],'activationOrUndoPerformed':False}));return
    if metadata.exists() or (directory/'original').exists():raise ValueError('fault identity already used; no backup replacement')
    target=profile if args.action.startswith('profile-') else secret
    original=read(target)
    if args.action.startswith('profile-') and sha(original)!=row['persistence']['profileHash']:raise ValueError('original approved profile required')
    write(directory/'original',original)
    changed=original.replace(b'mtu=1400\n',b'mtu=1380\n',1) if args.action=='profile-mtu' else None
    if changed==original:raise ValueError('expected lab MTU required')
    n.atomic(str(metadata),{'kind':args.action,'originalHash':sha(original),'faultHash':sha(changed) if changed else None})
    if args.action.endswith('-missing'):target.unlink()
    elif args.action=='profile-mtu':write(target,changed,replace=True)
    else:
        fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fchmod(fd,0o640);os.fsync(fd)
        finally:os.close(fd)
    print(n.canonical({'injected':args.action,'transactionId':args.transaction}))


if __name__=='__main__':main()
