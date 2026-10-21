import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { writeFileSync, unlinkSync } from 'node:fs';
import { issueDurableNetworkConfirm, settleNetworkExecution } from './network-execution-settlement.ts';
import { NETWORK_TERMINAL_DOMAIN, type NetworkTerminalResult } from './network-execution-state.ts';
import { signNetworkMessage, NETWORK_VERIFY_DOMAIN } from './network-execution.ts';
import { generateKeyPairSync, verify } from 'node:crypto';
import { NetworkRegistryStore } from './network-registry.ts';
import { buildNetworkChangeSet } from './network-change-set.ts';
import { emptyApprovals, propose, approve } from './approval.ts';
import { authorizeNetworkExecution, confirmNetworkExecution, networkExecutionHash, NETWORK_EXECUTION_DOMAIN, type NetworkExecutionDraft } from './network-execution.ts';
import { networkDigest } from './network-canonical.ts';
import { networkLabInput } from '../examples/network-lab.ts';

function fixture() {
  const dir=mkdtempSync(join(tmpdir(),'hp-execution-')),store=new NetworkRegistryStore(join(dir,'registry.json'));
  const input=networkLabInput();
  for (const r of input.registry.resources) if (r.management.mode==='managed') { r.management.driver='wg-quick'; if(r.kind==='interface'&&r.id==='wg0')r.name='hpaaaaaaaaaaaa'; if(r.kind==='route'&&r.interfaceId==='wg0'){r.protocol='static';r.metric=42760;} }
  const registry=store.mutate(0,'alice',{action:'replace',resources:input.registry.resources});
  store.initializeExecutions();
  const now=Date.now();
  const observation=structuredClone(input.observations[0]!);observation.receivedAt=new Date(now).toISOString();observation.report.completedAt=observation.receivedAt;
  const review=buildNetworkChangeSet({...input,wireguard:undefined,frr:undefined,registry,now});
  const operation={driver:'linux-wireguard-v1' as const,interfaceId:'wg0',interfaceName:'hpaaaaaaaaaaaa',address:'198.51.100.1/32',mtu:1420,listenPort:51820,secretRef:'local',publicKey:Buffer.alloc(32,1).toString('base64'),peers:[{publicKey:Buffer.alloc(32,2).toString('base64'),endpoint:'203.0.113.2:51820',allowedIps:['198.51.100.2/32']}],routes:['198.51.100.2/32']};
  const draft:NetworkExecutionDraft={schemaVersion:2,journalId:'e'.repeat(32),transactionId:'a'.repeat(32),target:{source:'lab-relay',host:'lab-host-0',nodeId:'n0'},registryRevision:1,resources:registry.resources.map(r=>({id:r.id,generation:r.generation})),desiredDigest:review.desiredDigest,reviewHash:review.contentHash,artifactHash:networkDigest(operation),observation:{digest:networkDigest(observation),collectedAt:now,maxAgeMs:10000},localPrecondition:'b'.repeat(64),operation,issuedAt:now,expiresAt:now+10000,rollbackAt:now+20000};
  const approvals=emptyApprovals(),key=generateKeyPairSync('ed25519');
  const proposeDraft=()=>propose(approvals,{hash:networkExecutionHash(draft),generation:draft.transactionId,summary:{hosts:[]},by:'alice',now:new Date(now)});
  const approveDraft=()=>approve(approvals,{hash:networkExecutionHash(draft),by:'bob',now:new Date(now)});
  const issue=()=>authorizeNetworkExecution(store,approvals,draft,'alice',key.privateKey,{observation,review},new Date(now));
  return {dir,store,registry,draft,approvals,key,proposeDraft,approveDraft,issue,observation,review};
}

function issued() {
  const f=fixture();f.proposeDraft();f.approveDraft();const envelope=f.issue();
  const a=JSON.parse(Buffer.from(envelope.payload,'base64url').toString());
  const agent={...a.target,journalId:a.journalId};
  const result=(state:'confirmed'|'rolled-back'='rolled-back'):NetworkTerminalResult=>{
    const record=f.store.executionStatus().records[0]!;
    const c=record.confirmation&&JSON.parse(Buffer.from(record.confirmation.payload,'base64url').toString());
    const v=c&&JSON.parse(Buffer.from(c.verification.payload,'base64url').toString());
    const body:Omit<NetworkTerminalResult,'stateHash'>={schemaVersion:1,domain:NETWORK_TERMINAL_DOMAIN,transactionId:a.transactionId,fenceId:a.transactionId,target:a.target,journalId:a.journalId,authorizationHash:networkDigest(a),artifactHash:a.artifactHash,registryRevision:a.registryRevision,state,sequence:1,proof:state==='confirmed'?{confirmationHash:networkDigest(c),verificationHash:networkDigest(v)}:{removalVerified:true as const}};
    return {...body,stateHash:networkDigest(body)};
  };
  const confirm=()=>{
    const verifier=generateKeyPairSync('ed25519'),now=Date.now();
    const receipt=signNetworkMessage(NETWORK_VERIFY_DOMAIN,{transactionId:a.transactionId,authorizationHash:networkDigest(a),artifactHash:a.artifactHash,observedAt:now,expiresAt:now+5000,nonce:'f'.repeat(32),checks:Object.fromEntries(['interface','address','route','handshake','fib','forward','reverse','management','protected'].map(k=>[k,true]))},verifier.privateKey);
    const envelope=issueDurableNetworkConfirm(f.store,networkExecutionHash(f.draft),receipt,[verifier.publicKey],f.key.privateKey,'alice',now);
    return {receipt,verifier,envelope};
  };
  return {...f,a,agent,result,confirm,cleanup:()=>rmSync(f.dir,{recursive:true,force:true})};
}
const registryUrl=new URL('./network-registry.ts',import.meta.url).href;
const settlementUrl=new URL('./network-execution-settlement.ts',import.meta.url).href;
function child(code:string) {
  return spawnSync(process.execPath,['--experimental-strip-types','--input-type=module','-e',code],{encoding:'utf8',timeout:15000});
}
for(const state of ['confirmed','rolled-back'] as const)test(`authenticated ${state} settles exact fence atomically and duplicate result is idempotent`,()=>{
  const f=issued();try {
    if(state==='confirmed')f.confirm();
    const r=f.result(state);
    assert.deepEqual(settleNetworkExecution(f.store,r,f.agent,'agent'),{settled:true,duplicate:false});
    assert.equal(new NetworkRegistryStore(f.store.path).executionStatus().fence,null);
    assert.deepEqual(settleNetworkExecution(f.store,r,f.agent,'agent'),{settled:true,duplicate:true});
    assert.doesNotThrow(()=>f.store.mutate(1,'next',{action:'update',id:'s0',resource:{...f.registry.resources.find(r=>r.id==='s0'),owner:'next'}}));
  } finally {f.cleanup();}
});
for(const field of ['transactionId','target','journalId','authorizationHash','artifactHash','registryRevision','fenceId','stateHash','proof','state'] as const)test(`terminal alteration ${field} cannot release fence`,()=>{
  const f=issued();try {
    const r:any=f.result();
    if(field==='target')r.target={...r.target,host:'other'};
    else if(field==='registryRevision')r.registryRevision++;
    else if(field==='proof')r.proof={removalVerified:false};
    else if(field==='state')r.state='rollback-failed';
    else r[field]='f'.repeat(64);
    if(field!=='stateHash'){const {stateHash,...body}=r;r.stateHash=networkDigest(body);}
    assert.throws(()=>settleNetworkExecution(f.store,r,f.agent,'agent'));
    assert.ok(f.store.executionStatus().fence);
  }finally{f.cleanup();}
});
test('conflicting terminal result is audited without overwriting settled history',()=>{
  const f=issued();try {
    f.confirm();const r=f.result('confirmed');settleNetworkExecution(f.store,r,f.agent,'agent');
    assert.throws(()=>settleNetworkExecution(f.store,f.result(),f.agent,'agent'),/conflicting/);
    const record=f.store.executionStatus().records[0]!;assert.deepEqual(record.result,r);assert.equal(record.audit.at(-1)!.action,'settlement-refused');
  }finally{f.cleanup();}
});
test('historical terminal settlement remains valid after authorization expiry and clock uncertainty',()=>{
  const f=issued();try {assert.equal(settleNetworkExecution(f.store,f.result(),f.agent,'agent',f.a.rollbackAt+1000000).settled,true);}finally{f.cleanup();}
});
test('old transaction result never unlocks a newly issued fence',()=>{
  const f=issued();try {
    const old=f.result();settleNetworkExecution(f.store,old,f.agent,'agent');
    const next=structuredClone(f.a);next.transactionId='b'.repeat(32);next.approval.planHash='sha256:'+networkDigest({...next,approval:undefined});
    // Production fence installation, separate unique identity; settled old delivery is historical.
    f.store.fenceExecution(1,next.transactionId,()=>signNetworkMessage(NETWORK_EXECUTION_DOMAIN,next,f.key.privateKey),'alice');
    assert.equal(settleNetworkExecution(f.store,old,f.agent,'agent').duplicate,true);
    assert.equal(f.store.executionStatus().fence!.transactionId,next.transactionId);
  }finally{f.cleanup();}
});
test('durable confirm survives Manager restart and lost responses without extending deadlines',()=>{
  const f=issued();try {
    const c=f.confirm();
    const repeated=issueDurableNetworkConfirm(new NetworkRegistryStore(f.store.path),networkExecutionHash(f.draft),c.receipt,[c.verifier.publicKey],f.key.privateKey,'alice',f.a.rollbackAt+1000);
    assert.deepEqual(repeated,c.envelope);
    assert.throws(()=>issueDurableNetworkConfirm(f.store,networkExecutionHash(f.draft),{...c.receipt,signature:'A'.repeat(86)},[c.verifier.publicKey],f.key.privateKey,'alice'),/conflicting/);
    assert.ok(f.store.executionStatus().fence);assert.equal(f.store.executionStatus().records[0]!.state,'confirm-issued');
  }finally{f.cleanup();}
});
for(const kind of ['missing-record','missing-execution','missing-file','corrupt'] as const)test(`damaged ${kind} fails closed`,()=>{
  const f=issued();try {
    const result=f.result();
    const doc=JSON.parse(readFileSync(f.store.path,'utf8'));
    if(kind==='missing-record')doc.execution.records=[];
    if(kind==='missing-execution')delete doc.execution;
    if(kind==='missing-file')unlinkSync(f.store.path);else writeFileSync(f.store.path,kind==='corrupt'?'{broken':JSON.stringify(doc));
    assert.throws(()=>settleNetworkExecution(f.store,result,f.agent,'agent'));
    assert.throws(()=>new NetworkRegistryStore(f.store.path).executionStatus());
  }finally{f.cleanup();}
});
for(const point of ['before-commit','after-commit'] as const)test(`SIGKILL ${point} leaves an atomic state and releases kernel Registry lock`,()=>{
  const f=issued();try {
    const path=JSON.stringify(f.store.path),r=f.result();
    const operation=point==='before-commit'?`s.executionTransaction(state=>{state.fence=null;process.kill(process.pid,'SIGKILL')})`:`settleNetworkExecution(s,${JSON.stringify(r)},${JSON.stringify(f.agent)},'agent');process.kill(process.pid,'SIGKILL')`;
    const killed=child(`import {NetworkRegistryStore} from ${JSON.stringify(registryUrl)};import {settleNetworkExecution} from ${JSON.stringify(settlementUrl)};const s=new NetworkRegistryStore(${path});${operation}`);
    assert.equal(killed.signal,'SIGKILL',killed.stderr);
    const status=new NetworkRegistryStore(f.store.path).executionStatus();
    assert.equal(status.fence!==null,point==='before-commit');
    assert.equal(settleNetworkExecution(f.store,r,f.agent,'agent').settled,true);
    assert.equal(f.store.executionStatus().fence,null);
  }finally{f.cleanup();}
});
test('Registry mutation and authenticated settlement serialize across real processes',async()=>{
  const f=issued();try {
    const prefix=`import {NetworkRegistryStore} from ${JSON.stringify(registryUrl)};import {settleNetworkExecution} from ${JSON.stringify(settlementUrl)};const s=new NetworkRegistryStore(${JSON.stringify(f.store.path)});`;
    const mutation={action:'update',id:'s0',resource:{...f.registry.resources.find(r=>r.id==='s0'),owner:'next'}};
    const codes=[`settleNetworkExecution(s,${JSON.stringify(f.result())},${JSON.stringify(f.agent)},'agent')`,`try{s.mutate(1,'next',${JSON.stringify(mutation)})}catch(e){if(!/fence/.test(e.message))throw e}`];
    const children=codes.map(code=>spawn(process.execPath,['--experimental-strip-types','--input-type=module','-e',prefix+code],{stdio:'pipe'}));
    const results=await Promise.all(children.map(c=>once(c,'exit')));assert.deepEqual(results.map(x=>x[0]),[0,0]);
    assert.equal(f.store.executionStatus().fence,null);assert.ok([1,2].includes(f.store.read().revision));
  }finally{f.cleanup();}
});

test('post-rename directory fsync failure cannot expose a cached authority until a durable read barrier succeeds',async()=>{
  const {createRequire,syncBuiltinESMExports}=await import('node:module');
  const fs=createRequire(import.meta.url)('node:fs');
  const f=fixture(),original=fs.fsyncSync;
  try {
    f.proposeDraft();f.approveDraft();
    fs.fsyncSync=(fd:number)=>{if(fs.fstatSync(fd).isDirectory())throw new Error('injected directory fsync failure');return original(fd);};syncBuiltinESMExports();
    assert.throws(f.issue,/directory fsync/);
    assert.ok(f.store.read().execution!.fence); // installed but uncertainty isn't permission to return it
    assert.throws(()=>f.store.executionStatus(),/directory fsync/);
  } finally {fs.fsyncSync=original;syncBuiltinESMExports();}
  try {
    const recovered=new NetworkRegistryStore(f.store.path).executionStatus();
    assert.equal(recovered.records.length,1);assert.equal(recovered.fence!.transactionId,f.draft.transactionId);
  }finally{rmSync(f.dir,{recursive:true,force:true});}
});

test('full Manager ledger still cancels and settles its active fence and refuses new issuance',()=>{
  const f=issued();try {
    const terminal=f.result();
    f.store.executionTransaction(state=>{
      const active=state.records[0]!;
      const archived=Array.from({length:255},(_,i)=>{
        const transactionId=(i+1).toString(16).padStart(32,'0');
        const a={...f.a,transactionId};
        const authorization=signNetworkMessage(NETWORK_EXECUTION_DOMAIN,a,f.key.privateKey);
        const result={...terminal,transactionId,fenceId:transactionId,authorizationHash:networkDigest(a)};
        const {stateHash,...body}=result;result.stateHash=networkDigest(body);
        return {...structuredClone(active),sequence:i+1,transactionId,fenceId:transactionId,authorization,authorizationHash:networkDigest(a),state:'settled' as const,result,resultHash:networkDigest(result),settledAt:Date.now(),settledBy:'fixture'};
      });
      state.records=[...archived,{...active,sequence:256}];state.nextSequence=257;
    });
    assert.equal(f.store.executionStatus().records.length,256);
    assert.equal(settleNetworkExecution(f.store,cancelled(f),f.agent,'agent').settled,true);
    assert.equal(f.store.executionStatus().fence,null);
    let signed=false;
    assert.throws(()=>f.store.fenceExecution(1,'f'.repeat(32),()=>{signed=true;throw new Error('must not sign');},'alice'),/capacity/);
    assert.equal(signed,false);assert.equal(f.store.executionStatus().records.length,256);
  } finally {f.cleanup();}
});

// Pre-accept cancellation shares the production Registry transaction and direct-mTLS verifier.
import { issueDurableNetworkCancellation, cancellationHash } from './network-execution-cancellation.ts';
import { NETWORK_CANCELLATION_RESULT_DOMAIN } from './network-execution-state.ts';
function cancelled(f:ReturnType<typeof issued>,state:'cancelled-before-accept'|'cancellation-rejected'='cancelled-before-accept'):NetworkTerminalResult {
  const envelope=issueDurableNetworkCancellation(f.store,f.a.transactionId,networkDigest(f.a),f.key.privateKey,'alice');
  const body:NetworkTerminalResult={...f.result(),schemaVersion:2,domain:NETWORK_CANCELLATION_RESULT_DOMAIN,state,proof:state==='cancelled-before-accept'?{cancellationHash:cancellationHash(envelope),acceptancePrevented:true as const}:{cancellationHash:cancellationHash(envelope),acceptedState:'awaiting-verification'}};
  const {stateHash,...committed}=body;return {...committed,stateHash:networkDigest(committed)};
}
test('preaccept cancellation is durable, distinct and idempotently settles after original expiry',()=>{
  const f=issued();try {
    const r=cancelled(f),envelope=f.store.executionStatus().records[0]!.cancellation!;
    const recovered=new NetworkRegistryStore(f.store.path);
    assert.deepEqual(issueDurableNetworkCancellation(recovered,f.a.transactionId,networkDigest(f.a),f.key.privateKey,'bob',f.a.rollbackAt+9999),envelope);
    assert.equal(recovered.executionStatus().records[0]!.cancelStatus,'requested');assert.ok(recovered.executionStatus().fence);
    assert.equal(settleNetworkExecution(recovered,r,f.agent,'gateway',f.a.rollbackAt+9999).settled,true);
    assert.equal(settleNetworkExecution(recovered,r,f.agent,'gateway').duplicate,true);
    assert.equal(recovered.executionStatus().records[0]!.cancelStatus,'settled');assert.equal(recovered.executionStatus().fence,null);
    assert.equal(recovered.mutate(1,'alice',{action:'update',id:'s0',resource:{...f.registry.resources.find(r=>r.id==='s0'),owner:'next'}}).revision,2);
  }finally{f.cleanup();}
});
for(const field of ['transactionId','authorizationHash','artifactHash','journalId','target','fenceId','registryRevision','schemaVersion','domain','proof'] as const)test(`cancelled result tampered ${field} preserves fence`,()=>{
  const f=issued();try {
    const r:any=cancelled(f);r[field]=field==='target'?{...r.target,host:'wrong'}:field==='proof'?{cancellationHash:'0'.repeat(64),acceptancePrevented:true}:typeof r[field]==='number'?r[field]+1:'wrong';
    const {stateHash,...body}=r;r.stateHash=networkDigest(body);
    assert.throws(()=>settleNetworkExecution(f.store,r,f.agent,'gateway'));
    assert.ok(f.store.executionStatus().fence);
  }finally{f.cleanup();}
});
test('accepted cancellation receipt is diagnostic, blocks confirm and never releases fence',()=>{
  const f=issued();try {
    const c=f.confirm();const r=cancelled(f,'cancellation-rejected');
    assert.deepEqual(settleNetworkExecution(f.store,r,f.agent,'gateway'),{settled:false,recorded:true,duplicate:false});
    const count=f.store.executionStatus().records[0]!.audit.length;
    assert.equal(settleNetworkExecution(f.store,r,f.agent,'gateway').duplicate,true);
    assert.equal(f.store.executionStatus().records[0]!.audit.length,count);
    assert.ok(f.store.executionStatus().fence);assert.equal(f.store.executionStatus().records[0]!.cancelStatus,'accepted-recovery-required');
    assert.throws(()=>issueDurableNetworkConfirm(f.store,networkExecutionHash(f.draft),c.receipt,[c.verifier.publicKey],f.key.privateKey,'alice'),/cancellation/);
    assert.throws(()=>settleNetworkExecution(f.store,cancelled(f),f.agent,'gateway'),/never-accepted/);
    assert.equal(settleNetworkExecution(f.store,f.result(),f.agent,'gateway').settled,true);
  }finally{f.cleanup();}
});
test('never-accepted terminal and accepted diagnostic conflict in either arrival order',()=>{
  const f=issued();try {
    const r=cancelled(f);settleNetworkExecution(f.store,r,f.agent,'gateway');
    assert.throws(()=>settleNetworkExecution(f.store,cancelled(f,'cancellation-rejected'),f.agent,'gateway'),/conflicts/);
    assert.equal(f.store.executionStatus().records[0]!.result!.state,'cancelled-before-accept');
  }finally{f.cleanup();}
});
test('old cancellation cannot clear a later execution fence',()=>{
  const f=issued();try {
    const r=cancelled(f);settleNetworkExecution(f.store,r,f.agent,'gateway');
    const a={...f.a,transactionId:'b'.repeat(32)};
    f.store.fenceExecution(1,a.transactionId,()=>signNetworkMessage(NETWORK_EXECUTION_DOMAIN,a,f.key.privateKey),'alice');
    assert.equal(settleNetworkExecution(f.store,r,f.agent,'gateway').duplicate,true);
    assert.equal(f.store.executionStatus().fence!.transactionId,a.transactionId);
    assert.throws(()=>issueDurableNetworkCancellation(f.store,a.transactionId,'0'.repeat(64),f.key.privateKey,'alice'));
  }finally{f.cleanup();}
});
for(const point of ['before-commit','after-commit'] as const)test(`cancel settlement SIGKILL ${point} recovers atomically in a new Manager process`,()=>{
  const f=issued();try {
    const r=cancelled(f);
    const p=child(`import fs from 'node:fs';import {syncBuiltinESMExports} from 'node:module';import {NetworkRegistryStore} from ${JSON.stringify(registryUrl)};import {settleNetworkExecution} from ${JSON.stringify(settlementUrl)};
      const path=${JSON.stringify(f.store.path)},rename=fs.renameSync;
      fs.renameSync=(from,to)=>{if(String(to)===path){if(${JSON.stringify(point)}==='before-commit')process.kill(process.pid,'SIGKILL');rename(from,to);process.kill(process.pid,'SIGKILL');}else rename(from,to)};
      syncBuiltinESMExports();settleNetworkExecution(new NetworkRegistryStore(path),${JSON.stringify(r)},${JSON.stringify(f.agent)},'gateway');`);
    assert.equal(p.signal,'SIGKILL',p.stderr);
    assert.equal(Boolean(new NetworkRegistryStore(f.store.path).executionStatus().fence),point==='before-commit');
    assert.equal(settleNetworkExecution(f.store,r,f.agent,'gateway').settled,true);
  }finally{f.cleanup();}
});
test('cancel issuance rejects oversized legacy payload and invalid principal before caching',()=>{
  const f=issued();try {
    assert.throws(()=>issueDurableNetworkCancellation(f.store,f.a.transactionId,networkDigest(f.a),f.key.privateKey,'bad actor'));
    assert.equal(f.store.executionStatus().records[0]!.cancellation,undefined);
    const doc=JSON.parse(readFileSync(f.store.path,'utf8')),record=doc.execution.records[0];
    const a={...f.a,legacyPadding:'x'.repeat(110000)};record.authorization=signNetworkMessage(NETWORK_EXECUTION_DOMAIN,a,f.key.privateKey);record.authorizationHash=networkDigest(a);doc.execution.fence.authorizationHash=record.authorizationHash;writeFileSync(f.store.path,JSON.stringify(doc));
    assert.throws(()=>issueDurableNetworkCancellation(f.store,f.a.transactionId,record.authorizationHash,f.key.privateKey,'alice'),/payload limit/);
    assert.equal(f.store.executionStatus().records[0]!.cancellation,undefined);assert.ok(f.store.executionStatus().fence);
  }finally{f.cleanup();}
});
for(const damage of ['status','orphan-response-hash','response-hash'] as const)test(`damaged cancellation ${damage} cannot settle`,()=>{
  const f=issued();try {
    const r=cancelled(f,'cancellation-rejected');settleNetworkExecution(f.store,r,f.agent,'gateway');
    const doc=JSON.parse(readFileSync(f.store.path,'utf8')),record=doc.execution.records[0];
    if(damage==='status')delete record.cancellationResponse;
    else if(damage==='orphan-response-hash')delete record.cancellationResponse;
    else record.cancellationResponseHash='0'.repeat(64);
    writeFileSync(f.store.path,JSON.stringify(doc));assert.throws(()=>f.store.executionStatus());assert.throws(()=>settleNetworkExecution(f.store,r,f.agent,'gateway'));
  }finally{f.cleanup();}
});

test('new issuance reserves recovery bytes and rejects an oversized authority without installing a fence',()=>{
  const f=issued();try {
    settleNetworkExecution(f.store,f.result(),f.agent,'gateway');
    const next={...f.a,transactionId:'b'.repeat(32)};
    assert.throws(()=>f.store.fenceExecution(1,next.transactionId,()=>signNetworkMessage(NETWORK_EXECUTION_DOMAIN,{...next,padding:'x'.repeat(70000)},f.key.privateKey),'alice'),/payload capacity/);
    assert.equal(f.store.executionStatus().fence,null);
    const doc=JSON.parse(readFileSync(f.store.path,'utf8'));doc.execution.records[0].audit[0].reason='x'.repeat(3*1024*1024);writeFileSync(f.store.path,JSON.stringify(doc));
    const before=readFileSync(f.store.path,'utf8');
    assert.throws(()=>f.store.fenceExecution(1,next.transactionId,()=>signNetworkMessage(NETWORK_EXECUTION_DOMAIN,next,f.key.privateKey),'alice'),/recovery reserve/);
    assert.equal(readFileSync(f.store.path,'utf8'),before);assert.equal(f.store.executionStatus().fence,null);
  }finally{f.cleanup();}
});

function capacityResult(f:ReturnType<typeof issued>):NetworkTerminalResult {
  const ordinary=cancelled(f),{stateHash,...body}=ordinary;
  const result={...body,schemaVersion:3 as const,domain:'heliopause-network-capacity-stop-mtls-v1' as const,proof:{...body.proof,maintenanceRequired:true as const}};
  return {...result,stateHash:networkDigest(result)};
}
test('capacity cancellation atomically settles and persists a downgrade-resistant issuance hold',()=>{
  const f=issued();try {
    const result=capacityResult(f);settleNetworkExecution(f.store,result,f.agent,'gateway');
    const state=new NetworkRegistryStore(f.store.path).executionStatus();
    assert.equal(state.schemaVersion,2);assert.equal(state.fence,null);assert.equal(state.capacityHold!.resultHash,networkDigest(result));
    assert.throws(()=>f.store.fenceExecution(1,'b'.repeat(32),()=>{throw new Error('issuance escaped hold');},'alice'),/capacity maintenance/);
    assert.deepEqual(settleNetworkExecution(f.store,result,f.agent,'gateway'),{settled:true,duplicate:true});
    assert.deepEqual(f.store.executionStatus().capacityHold,state.capacityHold);
  }finally{f.cleanup();}
});
for(const field of ['maintenanceRequired','cancellationHash','schemaVersion','domain'] as const)test('capacity result refuses altered '+field+' without releasing fence',()=>{
  const f=issued();try {
    const r:any=capacityResult(f);
    if(field==='maintenanceRequired')r.proof.maintenanceRequired=false;
    else if(field==='cancellationHash')r.proof.cancellationHash='0'.repeat(64);
    else if(field==='schemaVersion')r.schemaVersion=2;
    else r.domain='heliopause-network-cancellation-mtls-v1';
    const {stateHash,...body}=r;r.stateHash=networkDigest(body);
    assert.throws(()=>settleNetworkExecution(f.store,r,f.agent,'gateway'));
    assert.ok(f.store.executionStatus().fence);assert.equal(f.store.executionStatus().capacityHold,undefined);
  }finally{f.cleanup();}
});
for(const damage of ['remove-hold','downgrade','wrong-result','wrong-journal'] as const)test('capacity ledger refuses damaged '+damage,()=>{
  const f=issued();try {
    settleNetworkExecution(f.store,capacityResult(f),f.agent,'gateway');
    const doc=JSON.parse(readFileSync(f.store.path,'utf8'));
    if(damage==='remove-hold')delete doc.execution.capacityHold;
    else if(damage==='downgrade'){doc.execution.schemaVersion=1;delete doc.execution.capacityHold;}
    else if(damage==='wrong-result')doc.execution.capacityHold.resultHash='0'.repeat(64);
    else doc.execution.capacityHold.journalId='0'.repeat(32);
    writeFileSync(f.store.path,JSON.stringify(doc));assert.throws(()=>new NetworkRegistryStore(f.store.path).executionStatus());
  }finally{f.cleanup();}
});
for(const point of ['before-commit','after-commit'] as const)test('capacity settlement crash '+point+' preserves fence or exact hold',()=>{
  const f=issued();try {
    const r=capacityResult(f);
    const p=child(`import fs from 'node:fs';import {syncBuiltinESMExports} from 'node:module';import {NetworkRegistryStore} from ${JSON.stringify(registryUrl)};import {settleNetworkExecution} from ${JSON.stringify(settlementUrl)};
      const path=${JSON.stringify(f.store.path)},rename=fs.renameSync;
      fs.renameSync=(from,to)=>{if(String(to)===path){if(${JSON.stringify(point)}==='before-commit')process.kill(process.pid,'SIGKILL');rename(from,to);process.kill(process.pid,'SIGKILL');}else rename(from,to)};
      syncBuiltinESMExports();settleNetworkExecution(new NetworkRegistryStore(path),${JSON.stringify(r)},${JSON.stringify(f.agent)},'gateway');`);
    assert.equal(p.signal,'SIGKILL',p.stderr);const state=f.store.executionStatus();
    assert.equal(Boolean(state.fence),point==='before-commit');assert.equal(Boolean(state.capacityHold),point==='after-commit');
    settleNetworkExecution(f.store,r,f.agent,'gateway');assert.ok(f.store.executionStatus().capacityHold);
  }finally{f.cleanup();}
});

test('capacity stop cannot retire an epoch containing a confirmed resource',()=>{
 const f=issued();try {
  f.confirm();settleNetworkExecution(f.store,f.result('confirmed'),f.agent,'gateway');
  const a={...f.a,transactionId:'b'.repeat(32)},authorization=signNetworkMessage(NETWORK_EXECUTION_DOMAIN,a,f.key.privateKey);
  f.store.fenceExecution(1,a.transactionId,()=>authorization,'alice');
  const c=issueDurableNetworkCancellation(f.store,a.transactionId,networkDigest(a),f.key.privateKey,'alice');
  const body={...f.result(),transactionId:a.transactionId,fenceId:a.transactionId,authorizationHash:networkDigest(a),schemaVersion:3 as const,domain:'heliopause-network-capacity-stop-mtls-v1' as const,state:'cancelled-before-accept' as const,sequence:2,proof:{cancellationHash:cancellationHash(c),acceptancePrevented:true as const,maintenanceRequired:true as const}};
  const {stateHash,...committed}=body,result={...committed,stateHash:networkDigest(committed)};
  assert.throws(()=>settleNetworkExecution(f.store,result,f.agent,'gateway'),/resource-free/);
  assert.equal(f.store.executionStatus().fence!.transactionId,a.transactionId);assert.equal(f.store.executionStatus().capacityHold,undefined);
 }finally{f.cleanup();}
});
