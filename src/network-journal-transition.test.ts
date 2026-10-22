import { settleNetworkExecution } from './network-execution-settlement.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, unlinkSync, symlinkSync, chmodSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { createJournalArchive, loadJournalArchive, parseJournalArchiveFile } from './network-journal-archive.ts';
import { NetworkRegistryStore } from './network-registry.ts';
import { emptyApprovals, propose, approve } from './approval.ts';
import { signNetworkMessage } from './network-execution.ts';
import { artifactSigningKeyId } from './artifact-signature.ts';
import { networkDigest } from './network-canonical.ts';
import { validateJournalEvidence } from './network-journal-evidence.ts';
import { networkLabInput } from '../examples/network-lab.ts';
import { planJournalTransition, authorizeJournalTransition, validateQuiescentArchive, journalTransitionHash, commitManagerJournalTransition, verifyJournalMessage, JOURNAL_TRANSITION_DOMAIN, JOURNAL_TRANSITION_RECEIPT_DOMAIN, type JournalArchive } from './network-journal-transition.ts';

function fixture(count=1) {
  const dir=mkdtempSync(join(tmpdir(),'hp-journal-transition-')),store=new NetworkRegistryStore(join(dir,'registry.json'));
  store.mutate(0,'alice',{action:'replace',resources:networkLabInput().registry.resources});store.initializeExecutions();
  const keys=generateKeyPairSync('ed25519'),target={source:'lab',host:'gateway',nodeId:'gateway'},journal='a'.repeat(32),now=Date.now();
  const rows:Record<string,any>={},outbox:any[]=[],acks:Record<string,true>={};
  if(count)store.executionTransaction((state,doc)=>{
    const tx='b'.repeat(32),a={schemaVersion:2,transactionId:tx,journalId:journal,target,registryRevision:doc.revision,artifactHash:'c'.repeat(64),approval:{planHash:'sha256:'+'d'.repeat(64)}};
    const base={schemaVersion:1 as const,domain:'heliopause-network-terminal-mtls-v1' as const,transactionId:tx,fenceId:tx,target,journalId:journal,authorizationHash:networkDigest(a),artifactHash:a.artifactHash,registryRevision:doc.revision,state:'rolled-back' as const,sequence:1,proof:{removalVerified:true as const}};
    const result={...base,stateHash:networkDigest(base)},resultHash=networkDigest(result);outbox.push(result);acks[resultHash]=true;
    rows[tx]={authorization:a,state:'rolled-back',terminalResult:result,history:[{state:'rolled-back',at:now}]};
    state.records.push({sequence:1,transactionId:tx,fenceId:tx,planHash:a.approval.planHash,authorization:signNetworkMessage('heliopause-network-execution-v2',a,keys.privateKey),authorizationHash:networkDigest(a),target,journalId:journal,registryRevision:doc.revision,artifactHash:a.artifactHash,issuedAt:now,issuedBy:'alice',state:'settled',result,resultHash,settledAt:now,settledBy:'gateway',audit:[{action:'settled',actor:'gateway',at:now}]});
    state.nextSequence=2;
  });
  const attachments:Record<string,Buffer>={},evidence:any={schemaVersion:1,runs:[],files:{}};
  for(const [transactionId,row] of Object.entries(rows)){
    const files:Record<string,string[]>={};
    for(const kind of ['report','inventory','packets','modules','history']){
      const name=kind+'-'+transactionId+'.json',raw=Buffer.from(JSON.stringify({synthetic:true,kind,transactionId}));attachments[name]=raw;
      evidence.files[name]={kind,bytes:raw.length,sha256:createHash('sha256').update(raw).digest('hex')};files[kind]=[name];
    }
    evidence.runs.push({transactionId,authorizationHash:networkDigest(row.authorization),sourceCommit:'1'.repeat(40),imageSha256:'2'.repeat(64),moduleManifestSha256:evidence.files[files.modules![0]!].sha256,files});
  }
  const archive:JournalArchive={schemaVersion:1,rawFiles:{} as any,evidence,manager:store.read(),agent:{schemaVersion:2,journalId:journal,acceptedSequence:count,terminalSequence:count,lastClock:now,transactions:rows},identity:{journalId:journal},config:{enabled:true,journalId:journal,identity:target,managerKeys:'/etc/heliopause/trust/manager',verifierKeys:'/etc/heliopause/trust/verifier',secrets:'/etc/heliopause/secrets',protectedAddresses:['192.0.2.1']},outbox,acknowledgments:acks,trust:{manager:{[artifactSigningKeyId(keys.publicKey)]:keys.publicKey.export({type:'spki',format:'pem'}).toString()},verifier:{}}};
  const sync=()=>{for(const name of ['manager','agent','identity','outbox','acknowledgments','trust','config','evidence'] as const)archive.rawFiles[name]=Buffer.from(JSON.stringify(archive[name])).toString('base64url');archive.rawFiles.manager=readFileSync(store.path).toString('base64url');};sync();
  const archiveDirectory=join(dir,'archive');createJournalArchive(archiveDirectory,Object.fromEntries(Object.entries(archive.rawFiles).map(([name,encoded])=>[name,Buffer.from(encoded,'base64url')])) as any,attachments);
  const approvals=emptyApprovals();
  const draft=()=>planJournalTransition(archive,target,'e'.repeat(32),'f'.repeat(32),now);
  const issue=()=>{const d=draft(),hash=journalTransitionHash(d);propose(approvals,{hash,generation:d.transitionId,summary:{hosts:[]},by:'alice',now:new Date(now)});approve(approvals,{hash,by:'bob',now:new Date(now)});return authorizeJournalTransition(archive,d,approvals,'alice',keys.privateKey,new Date(now));};
  const cleanup=()=>rmSync(dir,{recursive:true,force:true});
  return {dir,store,archive,sync,keys,target,journal,now,draft,issue,approvals,archiveDirectory,cleanup};
}

test('scope A commits a new epoch and retains retirement receipt; retry never prunes later records',()=>{
  const f=fixture();try {
    const envelope=f.issue(),before=f.store.read(),receipt=commitManagerJournalTransition(f.store,f.archive,envelope,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now);
    const after=f.store.read();assert.deepEqual(after.resources,before.resources);assert.deepEqual(after.ownershipClaims,before.ownershipClaims);assert.equal(after.execution!.records.length,0);assert.equal(after.execution!.journalEpoch!.journalId,'e'.repeat(32));assert.equal(after.execution!.journalEpoch!.transitions[0]!.oldJournalId,f.journal);
    const p=verifyJournalMessage(receipt,JOURNAL_TRANSITION_RECEIPT_DOMAIN,[f.keys.publicKey]);assert.equal(p.archiveHash,f.draft().archiveHash);
    assert.deepEqual(commitManagerJournalTransition(f.store,f.archive,envelope,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now+7200000),receipt);
    assert.equal(f.archive.manager.execution!.records.length,1);
  }finally{f.cleanup();}
});
test('empty quiescent journal is explicitly supported',()=>{const f=fixture(0);try{validateQuiescentArchive(f.archive,f.target);}finally{f.cleanup();}});
const validationContract=JSON.parse(readFileSync(new URL('../scripts/network-transaction-lab/fixtures/journal-validation-v1.json',import.meta.url),'utf8'));
for(const entry of validationContract.evidenceCases)test('shared evidence contract: '+entry.name,()=>{
 const f=fixture();try{
  (f.archive.evidence.runs[0] as any)[entry.field]=entry.value;
  // Validate without row lookup too: attachment loading uses this public boundary.
  if(entry.accepted)validateJournalEvidence(f.archive.evidence);
  else assert.throws(()=>validateJournalEvidence(f.archive.evidence));
 }finally{f.cleanup();}
});
for(const entry of validationContract.emptyJournalCounterCases)test('shared replay counter contract: '+entry.name,()=>{
 const f=fixture(0);try{
  (f.archive.agent as any)[entry.field]=entry.value;f.sync();
  if(entry.accepted)validateQuiescentArchive(f.archive,f.target);
  else assert.throws(()=>validateQuiescentArchive(f.archive,f.target));
 }finally{f.cleanup();}
});
test('a previously signed malformed counter cannot clear the Manager before Agent refusal',()=>{
 const f=fixture(0);try{
  const draft=f.draft(),before=readFileSync(f.store.path);
  (f.archive.agent as any).terminalSequence=false;f.sync();
  draft.archiveHash=networkDigest(f.archive.rawFiles);
  draft.agentHash=createHash('sha256').update(Buffer.from(f.archive.rawFiles.agent,'base64url')).digest('hex');
  const malformedDirectory=join(f.dir,'malformed-counter');
  createJournalArchive(malformedDirectory,Object.fromEntries(Object.entries(f.archive.rawFiles).map(([name,encoded])=>[name,Buffer.from(encoded,'base64url')])) as any);
  const authorization=signNetworkMessage(JOURNAL_TRANSITION_DOMAIN,{...draft,approval:{mode:'two-person',planHash:journalTransitionHash(draft),proposedBy:'alice',approvedBy:'bob',approvedAt:f.now}},f.keys.privateKey);
  assert.throws(()=>commitManagerJournalTransition(f.store,f.archive,authorization,[f.keys.publicKey],f.keys.privateKey,malformedDirectory,f.now),/replay counters/);
  assert.deepEqual(readFileSync(f.store.path),before);
 }finally{f.cleanup();}
});
for(const entry of validationContract.rawCounterTokenCases)test('shared raw counter encoding: '+entry.name,()=>{
 const f=fixture(entry.records);try{
  const raw=JSON.stringify(f.archive.agent).replace(new RegExp('"'+entry.field+'":-?[0-9]+'), '"'+entry.field+'":'+entry.token);
  f.archive.rawFiles.agent=Buffer.from(raw).toString('base64url');f.archive.agent=JSON.parse(raw);
  const before=readFileSync(f.store.path),input=Buffer.from(f.archive.rawFiles.agent,'base64url');
  if(entry.accepted)validateQuiescentArchive(f.archive,f.target);
  else assert.throws(()=>validateQuiescentArchive(f.archive,f.target));
  assert.deepEqual(readFileSync(f.store.path),before);
  assert.deepEqual(Buffer.from(f.archive.rawFiles.agent,'base64url'),input);
  if(!entry.accepted&&/[.eE]/.test(entry.token)){
   const destination=join(f.dir,'unsupported-number');
   assert.throws(()=>createJournalArchive(destination,Object.fromEntries(Object.entries(f.archive.rawFiles).map(([name,encoded])=>[name,Buffer.from(encoded,'base64url')])) as any),/integer JSON token/);
   assert.throws(()=>readFileSync(join(destination,'transactions.json')),/ENOENT/);
  }
 }finally{f.cleanup();}
});
test('signed exponent counter cannot commit a retained pre-upgrade archive or mutate Registry bytes',()=>{
 const f=fixture(1);try{
  const draft=f.draft(),before=readFileSync(f.store.path);
  const raw=Buffer.from(f.archive.rawFiles.agent,'base64url').toString().replace(/"lastClock":\d+/,'"lastClock":1e0');
  f.archive.rawFiles.agent=Buffer.from(raw).toString('base64url');f.archive.agent=JSON.parse(raw);
  draft.archiveHash=networkDigest(f.archive.rawFiles);draft.agentHash=createHash('sha256').update(raw).digest('hex');
  // Simulate an exact retained archive produced by the older validator, not a new archive.
  const path=join(f.archiveDirectory,'transactions.json'),manifestPath=join(f.archiveDirectory,'manifest.json');
  writeFileSync(path,raw);const manifest=JSON.parse(readFileSync(manifestPath,'utf8'));
  manifest.files['transactions.json']={sha256:draft.agentHash,bytes:Buffer.byteLength(raw)};writeFileSync(manifestPath,JSON.stringify(manifest));
  const authorization=signNetworkMessage(JOURNAL_TRANSITION_DOMAIN,{...draft,approval:{mode:'two-person',planHash:journalTransitionHash(draft),proposedBy:'alice',approvedBy:'bob',approvedAt:f.now}},f.keys.privateKey);
  for(let i=0;i<2;i++)assert.throws(()=>commitManagerJournalTransition(f.store,f.archive,authorization,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now),/integer JSON token/);
  assert.deepEqual(readFileSync(f.store.path),before);assert.equal(readFileSync(path,'utf8'),raw);
 }finally{f.cleanup();}
});
for(const [name,change,pattern] of [
  ['confirmed resource',(f:any)=>{f.archive.agent.transactions['b'.repeat(32)].state='confirmed';},/confirmed/],
  ['rollback debt',(f:any)=>{f.archive.agent.transactions['b'.repeat(32)].state='rollback-failed';},/confirmed or nonterminal/],
  ['null undo marker',(f:any)=>{f.archive.agent.transactions['b'.repeat(32)].before=null;},/debt/],
  ['null path marker',(f:any)=>{f.archive.agent.transactions['b'.repeat(32)].paths=null;},/debt/],
  ['missing acknowledgment',(f:any)=>{f.archive.acknowledgments={};},/acknowledgments/],
  ['missing outbox',(f:any)=>{f.archive.outbox=[];},/record sets/],
  ['journal reuse',(f:any)=>{},/fresh transition/],
  ['unresolved restore debt',(f:any)=>{f.archive.agent.transactions['b'.repeat(32)].bootRestore={recovery:'rollback-failed'};},/debt/],
  ['Agent identity mismatch',(f:any)=>{f.archive.identity.journalId='0'.repeat(32);},/identity/],
  ['terminal proof tamper',(f:any)=>{f.archive.agent.transactions['b'.repeat(32)].terminalResult.proof={removalVerified:false};},/settlement|commitment/],
] as const) test('refuses '+name,()=>{
  const f=fixture();try{change(f);f.sync();if(name==='journal reuse')assert.throws(()=>planJournalTransition(f.archive,f.target,f.journal,'f'.repeat(32),f.now),pattern);else assert.throws(f.draft,pattern);}finally{f.cleanup();}
});
test('raw archived bytes cannot disagree with parsed content',()=>{const f=fixture();try{f.archive.agent.lastClock++;assert.throws(f.draft,/raw\/parsed/);}finally{f.cleanup();}});
test('no two-person approval means no transition authority',()=>{const f=fixture();try{assert.throws(()=>authorizeJournalTransition(f.archive,f.draft(),f.approvals,'alice',f.keys.privateKey,new Date(f.now)));}finally{f.cleanup();}});
test('wrong key and wrong domain cannot commit',()=>{const f=fixture();try{const envelope=f.issue(),wrong=generateKeyPairSync('ed25519');assert.throws(()=>commitManagerJournalTransition(f.store,f.archive,envelope,[wrong.publicKey],f.keys.privateKey,f.archiveDirectory,f.now),/signature/);assert.throws(()=>verifyJournalMessage(envelope,JOURNAL_TRANSITION_RECEIPT_DOMAIN,[f.keys.publicKey]),/signature/);assert.equal(f.store.executionStatus().records.length,1);}finally{f.cleanup();}});
test('expired Manager first commit does not reclaim records',()=>{const f=fixture();try{const envelope=f.issue();assert.throws(()=>commitManagerJournalTransition(f.store,f.archive,envelope,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now+3600000),/expired/);assert.equal(f.store.executionStatus().records.length,1);}finally{f.cleanup();}});
test('changed Manager rejects stale approved archive',()=>{const f=fixture();try{const envelope=f.issue();f.store.executionTransaction(state=>{state.records[0]!.audit.push({action:'observed',actor:'operator',at:f.now});});assert.throws(()=>commitManagerJournalTransition(f.store,f.archive,envelope,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now),/changed/);assert.equal(f.store.executionStatus().records.length,1);}finally{f.cleanup();}});
test('same record count with foreign journal cannot be archived',()=>{const f=fixture();try{f.archive.agent.journalId='0'.repeat(32);f.archive.identity.journalId=f.archive.agent.journalId;f.archive.config.journalId=f.archive.agent.journalId;f.sync();assert.throws(f.draft,/single-target/);}finally{f.cleanup();}});

test('old authority and delayed old result cannot touch a successor fence',()=>{
 const f=fixture();try{
  const envelope=f.issue();commitManagerJournalTransition(f.store,f.archive,envelope,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now);
  const old=f.archive.manager.execution!.records[0]!,oldEnvelope=old.authorization;
  assert.throws(()=>f.store.fenceExecution(f.store.read().revision,old.transactionId,()=>oldEnvelope,'alice'),/retired or foreign/);
  assert.equal(f.store.executionStatus().fence,null);
  const payload=JSON.parse(Buffer.from(oldEnvelope.payload,'base64url').toString());payload.journalId='e'.repeat(32);payload.transactionId='1'.repeat(32);
  const fresh=signNetworkMessage('heliopause-network-execution-v2',payload,f.keys.privateKey);
  f.store.fenceExecution(f.store.read().revision,payload.transactionId,()=>fresh,'alice');
  const before=readFileSync(f.store.path);
  assert.throws(()=>settleNetworkExecution(f.store,old.result!,{...f.target,journalId:f.journal},'gateway'));
  assert.deepEqual(readFileSync(f.store.path),before);
  commitManagerJournalTransition(f.store,f.archive,envelope,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now);
  assert.equal(f.store.executionStatus().records.length,1);assert.equal(f.store.executionStatus().fence!.transactionId,payload.transactionId);
 }finally{f.cleanup();}
});

for(const length of [0,63,65])test('malformed transition signature length '+length+' cannot commit',()=>{
 const f=fixture();try{const envelope={...f.issue(),signature:Buffer.alloc(length).toString('base64url')},before=readFileSync(f.store.path);assert.throws(()=>commitManagerJournalTransition(f.store,f.archive,envelope,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now),/signature/);assert.deepEqual(readFileSync(f.store.path),before);}finally{f.cleanup();}
});

for(const [name,change,pattern] of [
 ['missing run',(e:any)=>{e.runs=[];},/missing execution evidence run|unreferenced execution evidence files/],
 ['duplicate run',(e:any)=>{e.runs.push(structuredClone(e.runs[0]));},/duplicate or invalid/],
 ['wrong source',(e:any)=>{e.runs[0].sourceCommit='rolling-latest';},/duplicate or invalid/],
 ['wrong authority',(e:any)=>{e.runs[0].authorizationHash='0'.repeat(64);},/authorization mismatch/],
 ['wrong module commitment',(e:any)=>{e.runs[0].moduleManifestSha256='0'.repeat(64);},/module evidence commitment/],
 ['missing packet role',(e:any)=>{e.runs[0].files.packets=[];},/missing or duplicate/],
 ['path escape',(e:any)=>{e.files['../outside.json']={kind:'history',sha256:'0'.repeat(64),bytes:2};},/invalid execution evidence file/],
] as const)test('archive evidence refuses '+name,()=>{const f=fixture();try{change(f.archive.evidence);f.sync();assert.throws(f.draft,pattern);}finally{f.cleanup();}});
for(const fault of ['missing','tampered','symlink','permissions'] as const)test('Manager preserves old records when evidence attachment is '+fault,()=>{
 const f=fixture();try{const envelope=f.issue(),name=f.archive.evidence.runs[0]!.files.report[0]!,path=join(f.archiveDirectory,'evidence',name),before=readFileSync(f.store.path);
 if(fault==='missing')unlinkSync(path);if(fault==='tampered')writeFileSync(path,'{}');if(fault==='symlink'){unlinkSync(path);symlinkSync(f.store.path,path);}if(fault==='permissions')chmodSync(path,0o644);
 assert.throws(()=>commitManagerJournalTransition(f.store,f.archive,envelope,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now));assert.deepEqual(readFileSync(f.store.path),before);
 }finally{f.cleanup();}
});

test('Manager restart preserves the exact full transition authority and receipt after a lost response',()=>{
 const f=fixture();try{const envelope=f.issue(),receipt=commitManagerJournalTransition(f.store,f.archive,envelope,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now);
 const restarted=new NetworkRegistryStore(f.store.path),saved=restarted.executionStatus().journalEpoch!.transitions[0]!;
 assert.deepEqual(saved.authorization,envelope);assert.deepEqual(saved.receipt,receipt);
 assert.deepEqual(commitManagerJournalTransition(restarted,f.archive,saved.authorization,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now+3600001),receipt);
 }finally{f.cleanup();}
});

function capacityArchive() {
  const f=fixture(),tx='b'.repeat(32),row=f.archive.agent.transactions[tx],a=row.authorization;
  const cancellation={schemaVersion:1,transactionId:tx,fenceId:tx,target:a.target,journalId:a.journalId,authorizationHash:networkDigest(a),artifactHash:a.artifactHash,registryRevision:a.registryRevision,requestedAt:f.now,requestedBy:'alice',authorization:f.archive.manager.execution!.records[0]!.authorization};
  const signedCancel=signNetworkMessage('heliopause-network-cancel-v1',cancellation,f.keys.privateKey);
  const body={...row.terminalResult,schemaVersion:3,domain:'heliopause-network-capacity-stop-mtls-v1',state:'cancelled-before-accept',proof:{cancellationHash:networkDigest(cancellation),acceptancePrevented:true,maintenanceRequired:true}};delete body.stateHash;
  const result={...body,stateHash:networkDigest(body)},resultHash=networkDigest(result);
  f.store.executionTransaction(state=>{const record=state.records[0]!;record.cancellation=signedCancel;record.cancelStatus='settled';record.result=result;record.resultHash=resultHash;state.schemaVersion=2;state.capacityHold={target:f.target,journalId:f.journal,transactionId:tx,authorizationHash:networkDigest(a),resultHash};});
  f.archive.manager=f.store.read();f.archive.agent.transactions={};f.archive.agent.acceptedSequence=f.archive.agent.terminalSequence=0;
  f.archive.identity.capacityCancellation={authorization:a,cancellation,state:'cancelled-before-accept',history:[{state:'cancelled-before-accept',at:f.now}],authorizationHash:networkDigest(a),terminalResult:result};
  f.archive.outbox=[result];f.archive.acknowledgments={[resultHash]:true};f.sync();
  const attachments=Object.fromEntries(Object.keys(f.archive.evidence.files).map(name=>[name,readFileSync(join(f.archiveDirectory,'evidence',name))]));
  rmSync(f.archiveDirectory,{recursive:true});createJournalArchive(f.archiveDirectory,Object.fromEntries(Object.entries(f.archive.rawFiles).map(([k,v])=>[k,Buffer.from(v,'base64url')])) as any,attachments);
  return f;
}
for(const entry of validationContract.rawCommittedNumberCases)test('shared committed integer encoding: '+entry.name,()=>{
 const f=entry.reserved?capacityArchive():fixture();try{
  const value=structuredClone((f.archive as any)[entry.store]),path=entry.path.map((part:string)=>part==='$tx'?'b'.repeat(32):part==='$firstFile'?Object.keys(f.archive.evidence.files)[0]:part);
  let parent=value;for(const part of path.slice(0,-1))parent=parent[part];
  const field=path.at(-1),number=parent[field],token=String(number)+(entry.encoding==='decimal'?'.0':entry.encoding==='exponent'?'e0':'');
  assert.equal(typeof number,'number');parent[field]='__raw_integer_contract_token__';
  const raw=JSON.stringify(value).replace('"__raw_integer_contract_token__"',token),before=readFileSync(f.store.path);
  (f.archive.rawFiles as any)[entry.store]=Buffer.from(raw).toString('base64url');(f.archive as any)[entry.store]=JSON.parse(raw);
  if(entry.accepted)validateQuiescentArchive(f.archive,f.target);
  else assert.throws(()=>validateQuiescentArchive(f.archive,f.target),/integer JSON token/);
  assert.deepEqual(readFileSync(f.store.path),before);
  assert.equal(Buffer.from((f.archive.rawFiles as any)[entry.store],'base64url').toString(),raw);
 }finally{f.cleanup();}
});
test('verified full archive retires capacity reservation and hold together without pruning original identity',()=>{
  const f=capacityArchive();try {
    validateQuiescentArchive(f.archive,f.target);const oldIdentity=structuredClone(f.archive.identity),authority=f.issue();
    commitManagerJournalTransition(f.store,f.archive,authority,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now);
    const state=f.store.executionStatus();assert.equal(state.schemaVersion,1);assert.equal(state.capacityHold,undefined);assert.equal(state.records.length,0);
    assert.deepEqual(f.archive.identity,oldIdentity);assert.equal(f.archive.agent.terminalSequence,0);assert.equal(f.archive.outbox.length,1);
    assert.equal(state.journalEpoch!.transitions[0]!.oldJournalId,f.journal);
  }finally{f.cleanup();}
});
for(const damage of ['missing-identity','bad-sequence','wrong-cancel','missing-ack','missing-evidence'] as const)test('capacity archive refuses '+damage,()=>{
  const f=capacityArchive();try {
    if(damage==='missing-identity')delete f.archive.identity.capacityCancellation;
    else if(damage==='bad-sequence')f.archive.identity.capacityCancellation.terminalResult.sequence=1+f.archive.agent.terminalSequence+1;
    else if(damage==='wrong-cancel')f.archive.identity.capacityCancellation.cancellation.authorizationHash='0'.repeat(64);
    else if(damage==='missing-ack')f.archive.acknowledgments={};
    else f.archive.evidence.runs=[];
    f.sync();assert.throws(()=>validateQuiescentArchive(f.archive,f.target));
  }finally{f.cleanup();}
});

test('malformed UTF-8 archive cannot clear Manager state even with a signed transition',()=>{
 const f=fixture();try{
  const draft=f.draft(),before=readFileSync(f.store.path),row=Object.values(f.archive.agent.transactions)[0] as any;
  row.diagnostic='utf8-marker';f.sync();
  const original=Buffer.from(f.archive.rawFiles.agent,'base64url'),index=original.indexOf(Buffer.from('utf8-marker'));assert.ok(index>=0);
  const raw=Buffer.concat([original.subarray(0,index),Buffer.from([0xff]),original.subarray(index+'utf8-marker'.length)]);
  f.archive.rawFiles.agent=raw.toString('base64url');row.diagnostic='\ufffd';
  const path=join(f.archiveDirectory,'transactions.json'),manifestPath=join(f.archiveDirectory,'manifest.json'),manifest=JSON.parse(readFileSync(manifestPath,'utf8'));
  writeFileSync(path,raw);manifest.files['transactions.json']={sha256:createHash('sha256').update(raw).digest('hex'),bytes:raw.length};writeFileSync(manifestPath,JSON.stringify(manifest));
  draft.archiveHash=networkDigest(f.archive.rawFiles);draft.agentHash=manifest.files['transactions.json'].sha256;
  const envelope=signNetworkMessage(JOURNAL_TRANSITION_DOMAIN,{...draft,approval:{mode:'two-person',planHash:journalTransitionHash(draft),proposedBy:'alice',approvedBy:'bob',approvedAt:f.now}},f.keys.privateKey);
  for(let i=0;i<2;i++){
   assert.throws(()=>commitManagerJournalTransition(f.store,f.archive,envelope,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now),/UTF-8/);
   assert.deepEqual(readFileSync(f.store.path),before);assert.deepEqual(readFileSync(path),raw);
  }
 }finally{f.cleanup();}
});

for(const stage of ['create','load'] as const)test('archive '+stage+' refuses malformed UTF-8 evidence despite matching commitments',()=>{
 const f=fixture();try{
  const name=Object.keys(f.archive.evidence.files).find(name=>name.startsWith('history-'))!,raw=Buffer.concat([Buffer.from('{"diagnostic":"'),Buffer.from([0xff]),Buffer.from('"}')]);
  const entry=f.archive.evidence.files[name]!;entry.sha256=createHash('sha256').update(raw).digest('hex');entry.bytes=raw.length;f.sync();
  const before=readFileSync(f.store.path);
  if(stage==='create'){
   const attachments=Object.fromEntries(Object.keys(f.archive.evidence.files).map(file=>[file,file===name?raw:readFileSync(join(f.archiveDirectory,'evidence',file))]));
   const destination=join(f.dir,'malformed-evidence');
   assert.throws(()=>createJournalArchive(destination,Object.fromEntries(Object.entries(f.archive.rawFiles).map(([key,value])=>[key,Buffer.from(value,'base64url')])) as any,attachments),/UTF-8/);
   assert.equal(existsSync(destination),false);
  }else{
   writeFileSync(join(f.archiveDirectory,'evidence',name),raw);
   const evidence=Buffer.from(f.archive.rawFiles.evidence,'base64url'),manifestPath=join(f.archiveDirectory,'manifest.json'),manifest=JSON.parse(readFileSync(manifestPath,'utf8'));
   writeFileSync(join(f.archiveDirectory,'execution-evidence.json'),evidence);manifest.files['execution-evidence.json']={sha256:createHash('sha256').update(evidence).digest('hex'),bytes:evidence.length};writeFileSync(manifestPath,JSON.stringify(manifest));
   assert.throws(()=>loadJournalArchive(f.archiveDirectory),/UTF-8/);assert.deepEqual(readFileSync(join(f.archiveDirectory,'evidence',name)),raw);
  }
  assert.deepEqual(readFileSync(f.store.path),before);
 }finally{f.cleanup();}
});


for (const [name,history] of [
 ['missing history',undefined],['empty history',[]],['extra entry',[{state:'cancelled-before-accept',at:1},{state:'cancelled-before-accept',at:2}]],
 ['wrong state',[{state:'confirmed',at:1}]],['extra field',[{state:'cancelled-before-accept',at:1,padding:'synthetic'}]],
 ['boolean timestamp',[{state:'cancelled-before-accept',at:false}]],['fraction timestamp',[{state:'cancelled-before-accept',at:1.5}]],
 ['negative timestamp',[{state:'cancelled-before-accept',at:-1}]],['unsafe timestamp',[{state:'cancelled-before-accept',at:Number.MAX_SAFE_INTEGER+1}]],
] as const)test('capacity history refuses '+name+' without changing Manager state',()=>{
 const f=capacityArchive();try{
  const before=readFileSync(f.store.path);f.archive.identity.capacityCancellation.history=history;f.sync();
  assert.throws(()=>validateQuiescentArchive(f.archive,f.target),/capacity|integer JSON token/);assert.deepEqual(readFileSync(f.store.path),before);
 }finally{f.cleanup();}
});
for(const at of [0,Number.MAX_SAFE_INTEGER])test('capacity history accepts producer integer bound '+at,()=>{
 const f=capacityArchive();try{f.archive.identity.capacityCancellation.history[0].at=at;f.sync();validateQuiescentArchive(f.archive,f.target);}finally{f.cleanup();}
});
for(const token of ['1.0','1e0'])test('signed raw capacity history '+token+' cannot commit or alter original archive',()=>{
 const f=capacityArchive();try{
  const draft=f.draft(),before=readFileSync(f.store.path);f.archive.identity.capacityCancellation.history[0].at=1;f.sync();
  const raw=Buffer.from(f.archive.rawFiles.identity,'base64url').toString().replace('"at":1','"at":'+token);
  assert.notEqual(raw,Buffer.from(f.archive.rawFiles.identity,'base64url').toString());f.archive.rawFiles.identity=Buffer.from(raw).toString('base64url');f.archive.identity=JSON.parse(raw);
  assert.throws(()=>parseJournalArchiveFile('identity',Buffer.from(raw)),/integer JSON token/);
  const path=join(f.archiveDirectory,'journal-identity.json'),manifestPath=join(f.archiveDirectory,'manifest.json'),manifest=JSON.parse(readFileSync(manifestPath,'utf8'));
  writeFileSync(path,raw);manifest.files['journal-identity.json']={sha256:createHash('sha256').update(raw).digest('hex'),bytes:Buffer.byteLength(raw)};writeFileSync(manifestPath,JSON.stringify(manifest));
  const manifestBefore=readFileSync(manifestPath);draft.archiveHash=networkDigest(f.archive.rawFiles);
  const authority=signNetworkMessage(JOURNAL_TRANSITION_DOMAIN,{...draft,approval:{mode:'two-person',planHash:journalTransitionHash(draft),proposedBy:'alice',approvedBy:'bob',approvedAt:f.now}},f.keys.privateKey);
  for(let i=0;i<2;i++)assert.throws(()=>commitManagerJournalTransition(f.store,f.archive,authority,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now),/integer JSON token/);
  assert.deepEqual(readFileSync(f.store.path),before);assert.equal(readFileSync(path,'utf8'),raw);assert.deepEqual(readFileSync(manifestPath),manifestBefore);
 }finally{f.cleanup();}
});
test('signed unused config surrogate cannot retire Manager state',()=>{
 const f=fixture();try{
  const draft=f.draft(),before=readFileSync(f.store.path);f.archive.config.terminalDelivery={url:'https://192.0.2.1:8443/api/network/execution/terminal',caFile:'/etc/heliopause/ca.pem',certFile:'/etc/heliopause/\ud800.pem',keyFile:'/etc/heliopause/leaf.key'};f.sync();
  const raw=Buffer.from(f.archive.rawFiles.config,'base64url'),path=join(f.archiveDirectory,'network-executor-config.json'),manifestPath=join(f.archiveDirectory,'manifest.json'),manifest=JSON.parse(readFileSync(manifestPath,'utf8'));
  writeFileSync(path,raw);manifest.files['network-executor-config.json']={sha256:createHash('sha256').update(raw).digest('hex'),bytes:raw.length};writeFileSync(manifestPath,JSON.stringify(manifest));
  draft.archiveHash=networkDigest(f.archive.rawFiles);draft.configHash=manifest.files['network-executor-config.json'].sha256;
  const authority=signNetworkMessage(JOURNAL_TRANSITION_DOMAIN,{...draft,approval:{mode:'two-person',planHash:journalTransitionHash(draft),proposedBy:'alice',approvedBy:'bob',approvedAt:f.now}},f.keys.privateKey);
  for(let i=0;i<2;i++)assert.throws(()=>commitManagerJournalTransition(f.store,f.archive,authority,[f.keys.publicKey],f.keys.privateKey,f.archiveDirectory,f.now),/surrogate/);
  assert.deepEqual(readFileSync(f.store.path),before);assert.deepEqual(readFileSync(path),raw);
 }finally{f.cleanup();}
});
