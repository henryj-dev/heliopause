#!/usr/bin/env python3
"""Bounded, private, byte-preserving Phase10 evidence archive (never a ledger reset).

An external report digest anchors integrity, not the identity of a lab operator.
Public signing keys must be pinned independently; a key bundled with evidence is not trust.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'network-vm-lab'))
from boot_cycle import fresh_packets, timeline_valid, recovery_complete, removed_profile, inactive_preserved

SCHEMA = 'heliopause-private-vm-evidence-v1'
LIMIT = 16 * 1024 * 1024
TOTAL = 256 * 1024 * 1024
GROUPS = {'01-confirmed','02-prepared-applying','03-confirm-wait','04-rollback-interrupted',
          '05-rollback-failed','06-agent-start','07-nm-restart','08-profile-integrity',
          '09-foreign-profile','10-secret-integrity','11-firewall-coexistence',
          '12-disabled-recovery','13-terminal-delay-retry'}
BOOTS = {'acceptance-01-confirmed.json','01-confirmed-power-cut.json','06-agent-delayed.json',
         '06-agent-failed.json','07-nm-restart.json','08-profile-missing.json','08-profile-mtu.json',
         '09-foreign-profile.json','10-secret-missing.json','10-secret-permissions.json',
         '10-prerequisites-repaired.json','11-firewall-coexistence.json',
         '11-firewall-refused-network-recovers.json','11-firewall-prerequisite-repaired.json',
         '02-prepared.json','02-applying.json','02-created.json','02-configured.json',
         '03-confirm-wait.json','04-rolling-back.json','04-removed.json','05-rollback-failed.json',
         '05-rollback-failed-prerequisites-repaired.json','12-disabled-recovery.json','13-terminal-delay.json'}
HEX = re.compile(r'[a-f0-9]{64}')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(rows):
    result = {}
    for k, v in rows:
        require(k not in result, 'duplicate JSON member')
        result[k] = v
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def safe_read(path, maximum=LIMIT, private=False):
    # Walk every ancestor with nofollow dirfds; do not resolve away a symlink.
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        file = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(file)
            if private:
                require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, 'private owned 0600 archive file required')
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum,
                    'bounded single-link regular evidence file required')
            with os.fdopen(os.dup(file), 'rb') as stream:
                raw = stream.read(maximum + 1)
            require(len(raw) <= maximum, 'evidence size limit')
            require((info.st_size, info.st_mtime_ns) == (os.fstat(file).st_size, os.fstat(file).st_mtime_ns), 'evidence changed while reading')
            return raw
        finally:
            os.close(file)
    finally:
        os.close(fd)


def secret_check(raw, json_file):
    require(not re.search(rb'-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----', raw), 'private PEM refused')
    require(not re.search(rb'(?im)^\s*(?:private-key|preshared-key)\s*=\s*\S+', raw), 'full keyfile refused')
    if not json_file:
        return
    def walk(v, depth=0):
        require(depth <= 80, 'JSON depth limit')
        if isinstance(v, dict):
            for k, value in v.items():
                normalized = re.sub('[^a-z]', '', k.lower())
                require(normalized not in {'privatekey','presharedkey','password','clientsecret','keyfilecontents'}, 'secret field refused')
                walk(value, depth+1)
                if k == 'payload' and isinstance(value, str):
                    try:
                        decoded = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
                        nested = parse(decoded)
                    except (ValueError, UnicodeError):
                        continue
                    walk(nested, depth+1)
        elif isinstance(v, list):
            for item in v:
                walk(item, depth+1)
    walk(parse(raw))


def references(report):
    entries = [e for g in report['groups'] for e in g['evidence']]
    entries += report['additionalEvidence'] + report['orchestration']
    result = {}
    for e in entries:
        require(set(e) == {'path','sha256'} and HEX.fullmatch(e['sha256']) and Path(e['path']).is_absolute(), 'invalid reference')
        require('..' not in Path(e['path']).parts, 'parent traversal reference refused')
        require(Path(e['path']).suffix in {'.json','.py'}, 'unsupported evidence type')
        require(e['path'] not in result or result[e['path']] == e['sha256'], 'conflicting reference')
        result[e['path']] = e['sha256']
    require(1 <= len(result) <= 256, 'reference count limit')
    return result


def source_commitments(repo, commit):
    require(re.fullmatch('[a-f0-9]{40}', commit), 'exact source commit required')
    def git(*args):
        return subprocess.run(['git','-C',str(repo),*args], check=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=15).stdout
    package = parse(git('show',commit+':package.json'))
    return {name:sha(git('show',commit+':'+name)) for name in package['files']
            if name.startswith('agent/') and name.endswith('.py')}


def validate(report, documents, source, image):
    require(report['kind'] == 'rocky10-persistent-actual-vm-acceptance' and report['sourceCommit'] == source and
            report['imageSha256'] == image and report['backend'] == 'networkmanager-wireguard-1.56-v1', 'source/image/backend mismatch')
    require((report['passed'],report['failed'],report['skipped'],report['bootCases'],report['graceful'],report['powerCut']) == (13,0,0,25,13,12), 'acceptance counts mismatch')
    groups = report['groups']
    require(len(groups) == 13 and {g['id'] for g in groups} == GROUPS, 'missing or duplicate group')
    for g in groups:
        require(g['passed'] is True and g['evidence'], 'unsuccessful group')
        require(len({e['path'] for e in g['evidence']}) == len(g['evidence']), 'duplicate case reference')
        for e in g['evidence']:
            v = documents[e['path']]
            require(v['sourceCommit'] == source and v['passed'] is True, 'unsuccessful or wrong-source evidence')
    boots = {p:v for p,v in documents.items() if isinstance(v,dict) and v.get('mode') in {'graceful','power-cut'}}
    require(len(boots) == 25 and {Path(p).name for p in boots} == BOOTS, 'missing or duplicate boot case')
    require(sum(v['mode'] == 'graceful' for v in boots.values()) == 13, 'boot mode mismatch')
    summarized = {b['file']:b for b in report['boots']}
    require(len(report['boots']) == len(summarized) == 25 and summarized.keys() == boots.keys(), 'boot summary mismatch')
    for p, v in boots.items():
        before, after, tx = v['before'], v['after'], v['transaction']
        old, new = before['journal'], after['journal']
        require(v['sourceCommit'] == source and v['imageSha256'] == image and v['passed'] is True, 'wrong boot source or result')
        require(before['bootId'] != after['bootId'] and v['peerBootBefore'] == v['peerBootAfter'], 'actual boot or independent peer evidence absent')
        require(old['journalId'] == new['journalId'] and old['acceptedSequence'] == new['acceptedSequence'], 'replay identity changed')
        require(old['transactions'][tx]['authorization']['operation']['driver'] == report['backend'], 'wrong operation driver')
        require(v['managerBefore']['nextSequence'] == v['managerAfter']['nextSequence'] and
                [(r['transactionId'],r['authorizationHash']) for r in v['managerBefore']['records']] ==
                [(r['transactionId'],r['authorizationHash']) for r in v['managerAfter']['records']], 'Manager issuance changed during boot')
        require(new['terminalSequence'] == old['terminalSequence'] + (1 if v['expected'] == 'rolled-back' else 0), 'terminal sequence mismatch')
        require(recovery_complete(new,tx,after['bootId'],v['expected']), 'recovery state mismatch')
        require(timeline_valid(v['packetTimeline'],v['peerBootBefore'],v['requestPeerAt'],v['recoveredPeerAt'],v['monitorStopped']), 'packet timeline incomplete')
        summary = summarized[p]
        require(all(summary[k] == value for k,value in {'beforeBootId':before['bootId'],'afterBootId':after['bootId'],
                'peerBootId':v['peerBootBefore'],'transaction':tx,'mode':v['mode'],'expected':v['expected'],'samples':len(v['packetTimeline'])}.items()), 'boot summary differs from evidence')
        if v['expected'] == 'restored':
            probe = v.get('currentProbes',{})
            require(probe.get('transactionId') == tx and fresh_packets(probe,after['bootId'],probe['observedAt']), 'fresh packet checks absent')
            require(v['requestPeerAt']*1000 <= probe['observedAt'] <= v['monitorStopped']['at']*1000, 'packet observation outside boot interval')
        else:
            require(all(row['management'] is True and row['forward'] is False and row['reverse'] is False for row in v['packetTimeline'][-3:]), 'negative packet checks failed')
        if v['expected'] == 'rolled-back':
            require(removed_profile(after,tx), 'rollback objects remain')
        if v['expected'] in {'degraded-unchanged','rollback-failed','inactive'}:
            require(inactive_preserved(before,after,tx), 'negative case changed owned objects')
    settlements = [v for p,v in documents.items() if p.endswith('-settled.json')]
    require(len(settlements) == 10, 'missing final settlements')
    for v in settlements:
        stamp = v['acknowledgedResultHash']
        journal = v['evidence']['journal']
        require(v['evidence']['acknowledgements'].get(stamp) is True and v['manager']['fence'] is None, 'settlement acknowledgment/fence mismatch')
        records = [r for r in v['manager']['records'] if r.get('resultHash') == stamp]
        require(len(records) == 1 and records[0]['state'] == 'settled', 'exact Manager settlement missing')
        record = records[0];row = journal['transactions'][record['transactionId']]
        require(row['terminalResult'] == record['result'] and sha(canonical(record['result'])) == stamp and
                record['journalId'] == journal['journalId'] and
                record['target'] == row['authorization']['target'] == record['result']['target'] and
                record['authorizationHash'] == sha(canonical(row['authorization'])) == record['result']['authorizationHash'] and
                record['artifactHash'] == row['authorization']['artifactHash'] == record['result']['artifactHash'] and
                record['result']['transactionId'] == record['transactionId'], 'terminal result/identity mismatch')
    ordered = sorted(boots.values(),key=lambda v:v['requestAt'])
    for previous,current in zip(ordered,ordered[1:]):
        if previous['after']['journal']['journalId'] == current['before']['journal']['journalId']:
            require(previous['after']['bootId'] == current['before']['bootId'], 'broken boot chain')
    require(report['transientRecoveryEvents'] and report['orchestrationInterruptions'], 'known failure history missing')
    return boots


def verify_signatures(documents, manager_key, manager_id, verifier_key, verifier_id):
    # Reuse production Ed25519 domains, framing, key ID computation and canonical checks.
    import tempfile
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'agent'))
    from network_executor import crypto_helpers, verify, Executor, EXECUTION, CONFIRM, VERIFY
    require(manager_id != verifier_id, 'Manager/verifier trust must be distinct')
    verified = set()
    with tempfile.TemporaryDirectory() as temp:
        provider = crypto_helpers(temp)
        for role,path,key_id in [('manager',manager_key,manager_id),('verifier',verifier_key,verifier_id)]:
            raw = safe_read(path,65536)
            require(raw.startswith(b'-----BEGIN PUBLIC KEY-----') and b'PRIVATE' not in raw, 'public key required')
            directory = Path(temp)/role
            directory.mkdir(mode=0o700)
            (directory/'key.pem').write_bytes(raw)
            (directory/'key.pem').chmod(0o600)
            keys = provider._load_artifact_key_dir(str(directory),'manager')
            require(len(keys) == 1 and keys[0][0] == key_id, 'external signing key pin mismatch')
        authorities = set()
        for v in documents.values():
            if not isinstance(v,dict):continue
            if isinstance(v.get('authorization'),dict) and 'payload' in v['authorization']:
                a = verify(v['authorization'],EXECUTION,str(Path(temp)/'manager'),provider)
                require(a == v['decoded'] and sha(canonical(a['operation'])) == a['artifactHash'], 'authorization/artifact mismatch')
                authorities.add(a['transactionId'])
            for field in ('before','after'):
                for tx,row in v.get(field,{}).get('journal',{}).get('transactions',{}).items():
                    authority = row.get('restorationAuthority',{})
                    if not authority.get('confirmation'):continue
                    stamp = sha(canonical(authority))
                    if stamp in verified:continue
                    a = verify(authority['authorization'],EXECUTION,str(Path(temp)/'manager'),provider)
                    c = verify(authority['confirmation'],CONFIRM,str(Path(temp)/'manager'),provider)
                    proof = verify(c['verification'],VERIFY,str(Path(temp)/'verifier'),provider)
                    require(a == row['authorization'] and a['transactionId'] == tx and
                            c['transactionId'] == tx and proof['transactionId'] == tx and
                            c['authorizationHash'] == sha(canonical(a)) == proof['authorizationHash'] and
                            c['artifactHash'] == a['artifactHash'] == proof['artifactHash'], 'signed authority binding mismatch')
                    checker = object.__new__(Executor)
                    checker.config = {'managerKeys':str(Path(temp)/'manager'),'verifierKeys':str(Path(temp)/'verifier'),'identity':a['target']}
                    checker.provider = provider
                    checker.validate_restore_authority(row,v[field]['journal']['journalId'])
                    verified.add(stamp)
    require(verified and len(authorities) == 10, 'missing signed restoration or transaction evidence')
    return {'restoration':len(verified),'transactions':len(authorities)}


def write_file(fd, name, raw):
    f = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
    with os.fdopen(f,'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def preserve(report_path, root, output, expected_sha, source, image, repo):
    raw = safe_read(report_path)
    require(sha(raw) == expected_sha, 'external report digest mismatch')
    secret_check(raw,True)
    report = parse(raw)
    refs = references(report)
    root = Path(os.path.abspath(root))
    files = {}; documents = {}; total = len(raw)
    for p,digest in refs.items():
        require(Path(p).is_relative_to(root), 'reference escapes reviewed lab root')
        data = safe_read(p)
        require(sha(data) == digest, 'reference hash mismatch')
        secret_check(data,Path(p).suffix == '.json')
        total += len(data)
        require(total <= TOTAL, 'total archive size limit')
        files[p] = data
        if Path(p).suffix == '.json':documents[p] = parse(data)
    validate(report,documents,source,image)
    modules = source_commitments(repo,source)
    output = Path(os.path.abspath(output))
    # Parent must already exist, be private, and have no symlink ancestors.
    parent = output.parent
    parentfd = os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in parent.parts[1:]:
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parentfd)
            os.close(parentfd);parentfd=child
        info = os.fstat(parentfd)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private archive parent required')
        os.mkdir(output.name,0o700,dir_fd=parentfd)
        fd = os.open(output.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parentfd)
        try:
            write_file(fd,'report.json',raw)
            entries = []
            for index,(p,data) in enumerate(sorted(files.items())):
                name = f'{index:03d}'+Path(p).suffix
                write_file(fd,name,data)
                entries.append({'originalPath':p,'file':name,'originalSha256':sha(data),'archiveSha256':sha(data),'bytes':len(data),'transformation':'none'})
            manifest = {'schema':SCHEMA,'runIdentity':expected_sha,'reportSha256':expected_sha,'sourceCommit':source,
                        'imageSha256':image,'files':entries,'sourceModules':modules,
                        'deploymentCommitmentScope':'historical runner checked deployed bytes before each boot; report did not retain per-file deployed hashes',
                        'confidentiality':'restricted reviewed evidence; no public redistribution implied; secret scanner is defense in depth, not declassification',
                        'provenance':'external report hash and separately trusted public keys required; archive does not authenticate the operator'}
            write_file(fd,'manifest.json',canonical(manifest)+b'\n')
            os.fsync(fd)
        finally:os.close(fd)
        os.fsync(parentfd)
    finally:os.close(parentfd)
    return manifest


def check_bundle(directory, expected_sha, source, image, repo):
    info = Path(directory).lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private owned 0700 archive directory required')
    raw = safe_read(Path(directory)/'manifest.json',private=True)
    manifest = parse(raw)
    require(manifest['schema'] == SCHEMA and manifest['runIdentity'] == expected_sha and
            manifest['reportSha256'] == expected_sha and manifest['sourceCommit'] == source and manifest['imageSha256'] == image, 'manifest anchor mismatch')
    require(manifest['sourceModules'] == source_commitments(repo,source), 'source module commitment mismatch')
    report_raw = safe_read(Path(directory)/'report.json',private=True)
    require(sha(report_raw) == expected_sha, 'report tampered')
    report = parse(report_raw);refs = references(report);documents = {};seen = set();total = len(report_raw)
    require(len(manifest['files']) == len(refs), 'missing/extra archived references')
    names = set()
    for e in manifest['files']:
        require(e['originalPath'] in refs and e['originalPath'] not in seen and
                re.fullmatch(r'[0-9]{3}\.(json|py)',e['file']) and e['file'] not in names, 'duplicate/path-unsafe archive entry')
        seen.add(e['originalPath']);names.add(e['file'])
        data = safe_read(Path(directory)/e['file'],private=True);total += len(data)
        require(total <= TOTAL and e['bytes'] == len(data) and e['transformation'] == 'none' and
                sha(data) == e['archiveSha256'] == e['originalSha256'] == refs[e['originalPath']], 'archive file hash mismatch')
        secret_check(data,e['file'].endswith('.json'))
        if e['file'].endswith('.json'):documents[e['originalPath']] = parse(data)
    require({p.name for p in Path(directory).iterdir()} == names | {'manifest.json','report.json'}, 'unmanifested archive object')
    validate(report,documents,source,image)
    return documents


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation',choices=['preserve','verify']);p.add_argument('--bundle',type=Path,required=True)
    p.add_argument('--expected-report-sha256',required=True);p.add_argument('--source',required=True);p.add_argument('--image-sha256',required=True)
    p.add_argument('--source-repo',type=Path,required=True);p.add_argument('--report',type=Path);p.add_argument('--lab-root',type=Path)
    p.add_argument('--manager-key',type=Path,required=True);p.add_argument('--manager-key-id',required=True)
    p.add_argument('--verifier-key',type=Path,required=True);p.add_argument('--verifier-key-id',required=True)
    a = p.parse_args()
    require(HEX.fullmatch(a.expected_report_sha256) and HEX.fullmatch(a.image_sha256), 'exact digest required')
    require(all(not key.absolute().is_relative_to(a.bundle.absolute()) for key in [a.manager_key,a.verifier_key]), 'trust keys must be supplied outside bundle')
    if a.operation == 'preserve':
        require(a.report and a.lab_root, 'report and reviewed lab root required')
        preserve(a.report,a.lab_root,a.bundle,a.expected_report_sha256,a.source,a.image_sha256,a.source_repo)
    documents = check_bundle(a.bundle,a.expected_report_sha256,a.source,a.image_sha256,a.source_repo)
    count = verify_signatures(documents,a.manager_key,a.manager_key_id,a.verifier_key,a.verifier_key_id)
    print(json.dumps({'verified':True,'sourceCommit':a.source,'bootCases':25,'groups':13,'signedAuthorities':count,
                      'operatorProvenance':'not independently authenticated by this archive'}))


if __name__ == '__main__':
    try:main()
    except (ValueError,KeyError,TypeError,OSError,subprocess.SubprocessError) as error:
        print('evidence verification failed: '+type(error).__name__+': '+str(error)[:200],file=sys.stderr)
        sys.exit(2)
