import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateKeyPairSync } from 'node:crypto';
import { createJournalArchive } from './network-journal-archive.ts';
import { NetworkRegistryStore } from './network-registry.ts';
import { emptyApprovals, propose, approve } from './approval.ts';
import { signNetworkMessage } from './network-execution.ts';
import { networkDigest } from './network-canonical.ts';
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
  const archive:JournalArchive={schemaVersion:1,rawFiles:{} as any,manager:store.read(),agent:{schemaVersion:2,journalId:journal,acceptedSequence:count,terminalSequence:count,lastClock:now,transactions:rows},identity:{journalId:journal},outbox,acknowledgments:acks};
  const sync=()=>{for(const name of ['manager','agent','identity','outbox','acknowledgments'] as const)archive.rawFiles[name]=Buffer.from(JSON.stringify(archive[name])).toString('base64url');archive.rawFiles.manager=readFileSync(store.path).toString('base64url');};sync();
  const archiveDirectory=join(dir,'archive');createJournalArchive(archiveDirectory,Object.fromEntries(Object.entries(archive.rawFiles).map(([name,encoded])=>[name,Buffer.from(encoded,'base64url')])) as any);
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
for(const [name,change,pattern] of [
  ['confirmed resource',(f:any)=>{f.archive.agent.transactions['b'.repeat(32)].state='confirmed';},/confirmed/],
  ['rollback debt',(f:any)=>{f.archive.agent.transactions['b'.repeat(32)].state='rollback-failed';},/confirmed or nonterminal/],
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
test('same record count with foreign journal cannot be archived',()=>{const f=fixture();try{f.archive.agent.journalId='0'.repeat(32);f.archive.identity.journalId=f.archive.agent.journalId;f.sync();assert.throws(f.draft,/single-target/);}finally{f.cleanup();}});
