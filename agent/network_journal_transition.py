"""Offline scope-A journal replacement. Manager commits first; original state is never pruned.

No confirmed transfer or network writer is implemented here. The maintenance process holds
both existing host/executor locks and only reads kernel/profile ownership before transition.
"""
import argparse
import base64
import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import tempfile
import network_executor as n

DOMAIN='heliopause-network-quiescent-transition-v1'
RECEIPT='heliopause-network-transition-manager-commit-v1'
FILES={'manager':'manager.json','agent':'transactions.json','identity':'journal-identity.json',
       'outbox':'terminal-results.json','acknowledgments':'terminal-acks.json','trust':'audit-public-keys.json','config':'network-executor-config.json','evidence':'execution-evidence.json'}


def need(condition,reason):
    if not condition:raise ValueError(reason)


def secure_directory(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in Path(os.path.abspath(path)).parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        info=os.fstat(fd)
        need(info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700,'owned0700 directory required')
        return fd
    except BaseException:
        os.close(fd);raise


def read_at(fd,name,maximum):
    file=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
    with os.fdopen(file,'rb') as stream:
        info=os.fstat(file)
        need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and info.st_size<=maximum,'bounded owned0600 file required')
        raw=stream.read(maximum+1);need(len(raw)<=maximum,'archive file size limit');after=os.fstat(file)
        need((info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_mode,info.st_uid,info.st_nlink)==(after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_mode,after.st_uid,after.st_nlink) and len(raw)==after.st_size,'archive file changed during read')
        os.fsync(file);return raw


def read_archive(path):
    fd=secure_directory(path)
    try:
        manifest=n.decode_json(read_at(fd,'manifest.json',16384));n.exact(manifest,'schemaVersion files')
        need(manifest['schemaVersion']==1 and set(manifest['files'])==set(FILES.values()) and set(os.listdir(fd))==set(FILES.values())|{'manifest.json','evidence'},'incomplete archive')
        parsed={};raw_files={}
        for name,file in FILES.items():
            raw=read_at(fd,file,(4 if name=='manager' else 8)*1024*1024)
            need(manifest['files'][file]=={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)},'archive file hash mismatch')
            parsed[name]=n.decode_json(raw);reject_credentials(parsed[name]);raw_files[name]=base64.urlsafe_b64encode(raw).decode().rstrip('=')
        validate_evidence(parsed['evidence'],n.capacity_rows(parsed['agent'],parsed['identity']))
        evidence_fd=secure_directory(Path(path)/'evidence')
        try:
            need(set(os.listdir(evidence_fd))==set(parsed['evidence']['files']),'missing/extra execution evidence files')
            for name,entry in parsed['evidence']['files'].items():
                raw=read_at(evidence_fd,name,4*1024*1024)
                need(len(raw)==entry['bytes'] and hashlib.sha256(raw).hexdigest()==entry['sha256'],'execution evidence hash mismatch')
                reject_credentials(n.decode_json(raw))
            os.fsync(evidence_fd)
        finally:os.close(evidence_fd)
        os.fsync(fd)
        return {'schemaVersion':1,'rawFiles':raw_files,**parsed}
    finally:os.close(fd)


ROLES=['report','inventory','packets','modules','history']

def reject_credentials(value,depth=0):
    import re
    need(depth<=128,'archive JSON depth bound')
    if isinstance(value,str):need(not re.search(r'-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----',value),'private key archive refused')
    if isinstance(value,list):
        for child in value:reject_credentials(child,depth+1)
    if isinstance(value,dict):
        for key,child in value.items():
            need(re.sub('[_-]','',key.lower()) not in {'privatekey','password','token','clientsecret','presharedkey','cookie'},'credential field archive refused')
            reject_credentials(child,depth+1)


def validate_evidence(value,transactions):
    import re
    def hex_value(v,size):return isinstance(v,str) and re.fullmatch('[a-f0-9]{'+str(size)+'}',v)
    n.exact(value,'schemaVersion runs files')
    need(n.integer(value['schemaVersion'],1,1) and isinstance(value['runs'],list) and len(value['runs'])<=1024 and isinstance(value['files'],dict) and len(value['files'])<=4096,'invalid execution evidence manifest')
    total=0
    for name,entry in value['files'].items():
        n.exact(entry,'kind sha256 bytes')
        need(re.fullmatch(r'[a-z][a-z0-9-]{0,63}\.json',name) and entry['kind'] in ROLES and hex_value(entry['sha256'],64) and n.integer(entry['bytes'],1,4*1024*1024),'invalid execution evidence file')
        total+=entry['bytes']
    need(total<=128*1024*1024,'execution evidence total byte capacity')
    ids=set();used=set()
    for run in value['runs']:
        n.exact(run,'transactionId authorizationHash sourceCommit imageSha256 moduleManifestSha256 files')
        need(hex_value(run['transactionId'],32) and run['transactionId'] not in ids and hex_value(run['authorizationHash'],64) and hex_value(run['sourceCommit'],40) and hex_value(run['imageSha256'],64) and hex_value(run['moduleManifestSha256'],64),'duplicate/invalid execution evidence run')
        ids.add(run['transactionId']);n.exact(run['files'],' '.join(ROLES))
        for role in ROLES:
            names=run['files'][role]
            need(isinstance(names,list) and 1<=len(names)<=64 and all(isinstance(name,str) for name in names) and len(set(names))==len(names),'missing/duplicate execution evidence role')
            for name in names:
                need(name in value['files'] and value['files'][name]['kind']==role,'unbound execution evidence attachment');used.add(name)
        need(value['files'][run['files']['modules'][0]]['sha256']==run['moduleManifestSha256'],'module evidence commitment mismatch')
        row=transactions.get(run['transactionId'])
        need(row and n.digest(row['authorization'])==run['authorizationHash'],'execution evidence authorization mismatch')
    need(ids==set(transactions) and used==set(value['files']),'missing/unreferenced execution evidence')


def validate_authority(config,archive,envelope,receipt,provider):
    t=n.verify(envelope,DOMAIN,config['managerKeys'],provider);r=n.verify(receipt,RECEIPT,config['managerKeys'],provider)
    n.exact(t,'schemaVersion mode transitionId target oldJournalId newJournalId archiveHash managerHash agentHash configHash evidenceHash issuedAt expiresAt approval')
    n.exact(r,'schemaVersion transitionHash oldJournalId newJournalId target archiveHash evidenceHash committedAt')
    for field in ['transitionId','oldJournalId','newJournalId']:
        need(isinstance(t[field],str) and __import__('re').fullmatch('[a-f0-9]{32}',t[field]),'invalid transition identity')
    need(t['schemaVersion']==r['schemaVersion']==1 and t['mode']=='quiescent-without-confirmed-v1' and t['oldJournalId']!=t['newJournalId'],'unsupported identity transition')
    need(t['target']==config['identity'] and t['archiveHash']==n.digest(archive['rawFiles']),'transition target/archive mismatch')
    for field in ['oldJournalId','newJournalId','target','archiveHash','evidenceHash']:need(r[field]==t[field],'Manager receipt binding mismatch')
    need(r['transitionHash']==n.digest(t) and receipt['keyId']==envelope['keyId'],'exact Manager commit receipt required')
    need(n.integer(t['issuedAt'],1,2**53-1) and n.integer(t['expiresAt'],t['issuedAt']+1,t['issuedAt']+3600000) and n.integer(r['committedAt'],t['issuedAt'],t['expiresAt']-1),'invalid Manager transition commit time')
    # Receipt proves the first commit was timely. Completing that same partial transition after
    # expiry is recovery, not a new authorization or permission to reset a nonempty successor.
    approval=t['approval'];n.exact(approval,'mode planHash proposedBy approvedBy approvedAt')
    need(approval['mode']=='two-person' and n.name(approval['proposedBy']) and n.name(approval['approvedBy']) and approval['proposedBy']!=approval['approvedBy'] and approval['planHash']=='sha256:'+n.digest({k:v for k,v in t.items() if k!='approval'}) and n.integer(approval['approvedAt'],t['issuedAt'],t['expiresAt']-1),'two-person transition approval mismatch')
    need(t['agentHash']==hashlib.sha256(base64.urlsafe_b64decode(archive['rawFiles']['agent']+'==')).hexdigest() and t['managerHash']==hashlib.sha256(base64.urlsafe_b64decode(archive['rawFiles']['manager']+'==')).hexdigest(),'archive commitment mismatch')
    need(t['configHash']==hashlib.sha256(base64.urlsafe_b64decode(archive['rawFiles']['config']+'==')).hexdigest(),'configuration archive commitment mismatch')
    need(archive['config']['journalId']==t['oldJournalId'] and config in [archive['config'],{**archive['config'],'journalId':t['newJournalId']}],'configuration drift refused')
    need(t['evidenceHash']==hashlib.sha256(base64.urlsafe_b64decode(archive['rawFiles']['evidence']+'==')).hexdigest(),'execution evidence manifest commitment mismatch')
    validate_quiescent_core(archive,t['target'],t['oldJournalId'])
    return t


def integer_contract_encoding(value):
    """Committed execution/cancellation/result objects define only integer numbers.

    Decimal/exponent tokens parse as float even when mathematically integral. Do not
    normalize them: that would change the original bytes and Python's committed digest.
    History/monotonic measurements are deliberately outside these exact substructures.
    """
    need(type(value) is not float,'unsupported committed integer JSON token encoding')
    if isinstance(value,dict):
        for child in value.values():integer_contract_encoding(child)
    elif isinstance(value,list):
        for child in value:integer_contract_encoding(child)


def validate_quiescent_core(archive,target,old_id):
    old=archive['agent'];manager=archive['manager']['execution']
    need(n.valid_replay_counters(old),'invalid Agent replay counters or clock')
    rows=n.capacity_rows(old,archive['identity'])
    for row in rows.values():
        for field in ['authorization','cancellation','terminalResult','cancellationResponse']:
            if field in row:integer_contract_encoding(row[field])
    for result in archive['outbox']:integer_contract_encoding(result)
    for record in manager['records']:
        if 'sequence' in record:integer_contract_encoding(record['sequence'])
        for field in ['result','cancellationResponse']:
            if field in record:integer_contract_encoding(record[field])
    need(old['schemaVersion']==2 and old['journalId']==old_id and manager['fence'] is None,'quiescent identities/fence required')
    need(len(old['transactions'])==old['acceptedSequence']==old['terminalSequence'] and len(rows)==len(manager['records'])==len(archive['outbox'])==len(archive['acknowledgments']),'complete terminal archive required')
    need(len({r['transactionId'] for r in manager['records']})==len(manager['records']) and {r['transactionId'] for r in manager['records']}==set(rows),'Manager/Agent record identities differ')
    outbox={row['transactionId']:row for row in archive['outbox']};need(len(outbox)==len(archive['outbox']),'duplicate outbox identity')
    for record in manager['records']:
        row=rows[record['transactionId']];result=record['result']
        need(row['state'] in {'rolled-back','cancelled-before-accept'} and record['state']=='settled' and row.get('bootRestore') is None and 'before' not in row and 'paths' not in row,'confirmed resources or recovery debt forbid scope A')
        need(record['journalId']==old['journalId'] and record['target']==target and row['authorization']['target']==target and row['authorization']['journalId']==old['journalId'],'archive target mismatch')
        need(row['authorization']==n.decode_json(base64.urlsafe_b64decode(record['authorization']['payload']+'==')) and n.digest(row['authorization'])==record['authorizationHash'],'archive authorization mismatch')
        need(row['terminalResult']==outbox[record['transactionId']]==result and record['resultHash']==n.digest(result) and archive['acknowledgments'].get(record['resultHash']) is True,'exact settlement/outbox/ack required')


def resource_absence(config,old):
    deadline=time.monotonic()+60
    driver=n.LinuxWireGuard(config['secrets']);driver.command_deadline=deadline
    snapshot=driver.snapshot();persistent=None
    for row in old['transactions'].values():
        op=row['authorization']['operation'];n.validate_operation(op)
        need(not any(link['name']==op['interfaceName'] for link in snapshot['links']),'old/foreign interface remains')
        need(not any(route.get('dev')==op['interfaceName'] or route.get('dst') in set(op['routes'])|{r.split('/')[0] for r in op['routes']} for route in snapshot['routes']),'old/foreign route remains')
        if op['driver']==n.PERSISTENT_DRIVER:
            if persistent is None:
                from network_nm_wireguard import NetworkManagerWireGuard
                nm=NetworkManagerWireGuard(config['secrets']);nm.command_deadline=deadline;nm.available()
                persistent=(nm,nm.profiles())
            nm,profiles=persistent
            need(op['profileUuid'] not in profiles,'old/foreign NM profile remains')
            try:nm.store.read(op['profileUuid'])
            except FileNotFoundError:pass
            else:raise ValueError('old/foreign keyfile remains')


def rename_new(parent,source,dest):
    function=ctypes.CDLL(None,use_errno=True).renameat2
    function.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];function.restype=ctypes.c_int
    if function(parent,source.encode(),parent,dest.encode(),1):raise OSError(ctypes.get_errno(),'exclusive journal directory rename refused')
    os.fsync(parent)


def empty_journal(identity):
    return {'schemaVersion':2,'journalId':identity,'terminalSequence':0,'acceptedSequence':0,'transactions':{},'lastClock':0}


def mount_info():
    with open('/proc/self/mountinfo',encoding='utf-8') as stream:
        raw=stream.read(1024*1024+1)
    need(len(raw)<=1024*1024,'mount inventory bound')
    return [line.split()[4].replace('\\040',' ').replace('\\011','\t').replace('\\012','\n').replace('\\134','\\') for line in raw.splitlines()]


def inspect_layout(directory,parent):
    info=directory.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700,'owned0700 journal required')
    need(info.st_dev==os.fstat(parent).st_dev and str(directory) not in mount_info(),'mounted journal directory cannot be replaced; explicit storage migration required')


def inspect_agent(config_path,directory,archive_path,writer_lock,absence=resource_absence):
    config=n.read_json(config_path);n.validate_execution_config(config);archive=read_archive(archive_path)
    need(n.read_file(config_path)==base64.urlsafe_b64decode(archive['rawFiles']['config']+'=='),'configuration drift refused')
    validate_quiescent_core(archive,config['identity'],config['journalId'])
    directory=Path(os.path.abspath(directory));parent=secure_directory(directory.parent);host=None;executor=None
    try:
        host=os.open(writer_lock,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        info=os.fstat(host);need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600,'owned host writer lock required')
        fcntl.flock(host,fcntl.LOCK_EX|fcntl.LOCK_NB)
        executor=os.open(directory/'executor.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        info=os.fstat(executor);need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600,'owned executor lock required')
        fcntl.flock(executor,fcntl.LOCK_EX|fcntl.LOCK_NB);inspect_layout(directory,parent);n.assert_active_journal(str(directory))
        config_raw=n.read_file(config_path)
        need(config_raw==base64.urlsafe_b64decode(archive['rawFiles']['config']+'=='),'configuration changed during inspection')
        config=n.decode_json(config_raw);n.validate_execution_config(config)
        need(read_archive(archive_path)['rawFiles']==archive['rawFiles'],'archive changed during inspection')
        for name in ['agent','identity','outbox','acknowledgments']:
            need(n.read_file(str(directory/FILES[name]))==base64.urlsafe_b64decode(archive['rawFiles'][name]+'=='),'Agent changed since archive')
        need(n.Executor(config,str(directory)).load()==archive['agent'],'Agent/archive mismatch')
        for row in n.capacity_rows(archive['agent'],archive['identity']).values():need(row['state'] in {'rolled-back','cancelled-before-accept'} and row.get('bootRestore') is None and 'before' not in row and 'paths' not in row,'confirmed resources or recovery debt forbid scope A')
        absence(config,{**archive['agent'],'transactions':n.capacity_rows(archive['agent'],archive['identity'])})
        return {'readOnly':True,'oldJournalId':config['journalId'],'archiveHash':n.digest(archive['rawFiles']),'evidenceHash':hashlib.sha256(base64.urlsafe_b64decode(archive['rawFiles']['evidence']+'==')).hexdigest(),'readyForManagerReview':True}
    finally:
        if executor is not None:os.close(executor)
        if host is not None:os.close(host)
        os.close(parent)


def apply_agent(config_path,directory,archive_path,envelope,receipt,writer_lock,event=None,absence=resource_absence):
    event=event or (lambda _:None)
    config_raw=n.read_file(config_path);config=n.decode_json(config_raw);n.validate_execution_config(config)
    archive=read_archive(archive_path)
    # The shared verifier creates temporary signature/message files. Never point it at the
    # replaceable journal: verification on resume would recreate an unpublished successor.
    workspace=Path(writer_lock).parent;workspace_fd=secure_directory(workspace);os.close(workspace_fd)
    provider=n.crypto_helpers(str(workspace))
    t=validate_authority(config,archive,envelope,receipt,provider)
    need(config_raw in [base64.urlsafe_b64decode(archive['rawFiles']['config']+'=='),n.canonical({**archive['config'],'journalId':t['newJournalId']}).encode()],'configuration bytes differ from approved transition')
    directory=Path(os.path.abspath(directory));parent=secure_directory(directory.parent)
    host=os.open(writer_lock,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    executor_fd=None
    try:
        info=os.fstat(host);need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600,'owned host writer lock required')
        fcntl.flock(host,fcntl.LOCK_EX|fcntl.LOCK_NB)
        marker=Path(str(directory)+'.transition.json');previous=directory.with_name(directory.name+'.retired-'+t['oldJournalId']);stage=directory.with_name(directory.name+'.prepared-'+t['transitionId'])
        if directory.exists():
            sourcefd=secure_directory(directory);os.close(sourcefd)
        lock_directory=directory if directory.exists() else previous
        executor_fd=os.open(lock_directory/'executor.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        info=os.fstat(executor_fd);need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600,'owned executor lock required')
        fcntl.flock(executor_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(n.read_file(config_path)==config_raw,'configuration changed while acquiring locks')
        archive=read_archive(archive_path)
        validate_authority(config,archive,envelope,receipt,provider)
        def check_original(location):
            for name in ['agent','identity','outbox','acknowledgments']:
                need(n.read_file(str(location/FILES[name]))==base64.urlsafe_b64decode(archive['rawFiles'][name]+'=='),'preserved original sidecar drift')
        if previous.exists():check_original(previous)
        else:inspect_layout(directory,parent);check_original(directory)
        progress=n.read_json(str(marker)) if marker.exists() else None
        if progress and progress['transitionHash']!=n.digest(t):
            need(progress['phase']=='complete','different pending transition refused')
            need(config['journalId']==t['oldJournalId'] and n.read_json(str(directory/'transition-owner.json'))=={'transitionHash':progress['transitionHash']},'prior completed transition ownership mismatch')
            prior=directory/'previous-transition.json'
            if prior.exists():need(n.read_json(str(prior))==progress,'prior completed evidence drift')
            else:n.atomic(str(prior),progress)
            progress=None
        if progress:
            need(progress['authorization']==envelope and progress['receipt']==receipt,'different pending transition refused')
            if progress['phase']=='complete':
                need(config['journalId']==t['newJournalId'] and n.read_json(str(directory/'journal-identity.json'))=={'journalId':t['newJournalId']},'completed transition drift')
                n.durable_admission_epoch(str(directory))
                return {'committed':True,'duplicate':True,'journalId':t['newJournalId']}
            absence(config,{**archive['agent'],'transactions':n.capacity_rows(archive['agent'],archive['identity'])})
        else:
            need(config['journalId']==t['oldJournalId'] and hashlib.sha256(n.read_file(str(directory/'transactions.json'))).hexdigest()==t['agentHash'],'Agent changed since approved archive')
            current=n.Executor(config,str(directory))
            need(current.load()==archive['agent'],'current Agent/archive mismatch')
            absence(config,{**archive['agent'],'transactions':n.capacity_rows(archive['agent'],archive['identity'])})
            progress={'transitionHash':n.digest(t),'authorization':envelope,'receipt':receipt,'phase':'prepared'};n.atomic(str(marker),progress)
            event('intent-saved')
        def phase(value):
            progress['phase']=value;n.atomic(str(marker),progress);event(value)
        if not previous.exists():
            need(directory.exists() and hashlib.sha256(n.read_file(str(directory/'transactions.json'))).hexdigest()==t['agentHash'],'original Agent state changed')
            retired=directory/'retired-journal.json'
            if retired.exists():need(n.read_json(str(retired))=={'transitionHash':n.digest(t)},'foreign retirement marker')
            else:n.atomic(str(retired),{'transitionHash':n.digest(t)})
            phase('old-retired');rename_new(parent,directory.name,previous.name);phase('old-preserved')
        else:
            oldfd=secure_directory(previous);os.close(oldfd)
            need(hashlib.sha256(n.read_file(str(previous/'transactions.json'))).hexdigest()==t['agentHash'] and n.read_json(str(previous/'retired-journal.json'))=={'transitionHash':n.digest(t)},'preserved original drift')
        if not directory.exists():
            if not stage.exists():
                creating=Path(tempfile.mkdtemp(prefix=stage.name+'.creating-',dir=directory.parent));os.fsync(parent)
                event('stage-created')
                n.atomic(str(creating/'transition-owner.json'),{'transitionHash':n.digest(t)})
                rename_new(parent,creating.name,stage.name)
                event('stage-owned')
            stagefd=secure_directory(stage)
            try:
                expected={'journal-identity.json':{'journalId':t['newJournalId']},'transactions.json':empty_journal(t['newJournalId']),'terminal-results.json':[],'terminal-acks.json':{}}
                need(n.decode_json(read_at(stagefd,'transition-owner.json',4096))=={'transitionHash':n.digest(t)},'foreign staging ownership')
                need(set(os.listdir(stagefd))<=set(expected)|{'transition-owner.json'},'foreign staging files')
                for name,value in expected.items():
                    raw=n.canonical(value).encode();path=stage/name
                    if path.exists():
                        partial=read_at(stagefd,name,8*1024*1024)
                        if partial==raw:continue
                        need(raw.startswith(partial),'foreign/nonempty successor staging refused')
                        history=progress.setdefault('partialStages',{}).setdefault(name,[]);stamp=hashlib.sha256(partial).hexdigest()
                        if not history or history[-1]!=stamp:
                            need(len(history)<256,'partial stage diagnostic capacity');history.append(stamp);n.atomic(str(marker),progress)
                        fd=os.open(name,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=stagefd)
                        with os.fdopen(fd,'r+b') as stream:
                            info=os.fstat(stream.fileno())
                            need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and stream.read(len(raw)+1)==partial,'partial stage changed')
                            stream.write(raw[len(partial):]);stream.flush();os.fsync(stream.fileno())
                    else:
                        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=stagefd)
                        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                os.fsync(stagefd)
            finally:os.close(stagefd)
            phase('successor-prepared');rename_new(parent,stage.name,directory.name);phase('successor-published')
        else:
            need(n.read_json(str(directory/'transactions.json'))==empty_journal(t['newJournalId']) and n.read_json(str(directory/'journal-identity.json'))=={'journalId':t['newJournalId']},'nonempty/foreign successor refused')
        newfd=secure_directory(directory)
        try:
            expected={'journal-identity.json':{'journalId':t['newJournalId']},'transactions.json':empty_journal(t['newJournalId']),'terminal-results.json':[],'terminal-acks.json':{}}
            need(set(os.listdir(newfd))<=set(expected)|{'executor.lock','transition-owner.json'},'foreign successor files refused')
            need(n.decode_json(read_at(newfd,'transition-owner.json',4096))=={'transitionHash':n.digest(t)},'foreign successor ownership')
            for name,value in expected.items():need(n.decode_json(read_at(newfd,name,8*1024*1024))==value,'successor not pristine')
        finally:os.close(newfd)
        need(n.read_file(config_path)==config_raw,'configuration changed during maintenance')
        config={**config,'journalId':t['newJournalId']};n.atomic(config_path,config);phase('config-bound');phase('complete')
        return {'committed':True,'duplicate':False,'journalId':t['newJournalId'],'oldStatePreservedAt':str(previous),'managerBindingRestartRequired':True}
    finally:
        if executor_fd is not None:os.close(executor_fd)
        os.close(host);os.close(parent)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',required=True);p.add_argument('--authorization');p.add_argument('--manager-receipt');p.add_argument('--apply',action='store_true');a=p.parse_args()
    config_path='/etc/heliopause/network-executor.json';directory='/var/lib/heliopause/network-executor';writer='/var/lib/heliopause-agent/writer.lock'
    need(n.read_json('/var/lib/heliopause-agent/network-writer-locator.json')=={'config':config_path,'stateDir':directory},'default integrated writer layout required')
    if not a.apply:
        need(not a.authorization and not a.manager_receipt,'authorization and receipt are apply-only; inspect archive before Manager commit')
        print(n.canonical(inspect_agent(config_path,directory,a.archive,writer)));return
    need(a.authorization and a.manager_receipt,'signed authorization and Manager commit receipt required for apply')
    envelope=n.read_json(a.authorization);receipt=n.read_json(a.manager_receipt)
    need(os.geteuid()==0,'root offline maintenance required')
    for unit in ['heliopause-agent.service','heliopause-network-terminal.service']:
        result=subprocess.run(['systemctl','show',unit,'-p','MainPID','--value'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,check=True)
        need(result.stdout.strip()==b'0','stop Agent and courier before maintenance')
    print(n.canonical(apply_agent(config_path,directory,a.archive,envelope,receipt,writer)))


if __name__=='__main__':main()
