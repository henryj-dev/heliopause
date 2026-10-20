import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, verify } from 'node:crypto';
import { NetworkRegistryStore } from './network-registry.ts';
import { buildNetworkChangeSet } from './network-change-set.ts';
import { emptyApprovals, propose, approve } from './approval.ts';
import { authorizeNetworkExecution, networkExecutionHash, NETWORK_EXECUTION_DOMAIN, type NetworkExecutionDraft } from './network-execution.ts';
import { networkDigest } from './network-canonical.ts';
import { networkLabInput } from '../examples/network-lab.ts';

function fixture() {
  const dir=mkdtempSync(join(tmpdir(),'hp-execution-')),store=new NetworkRegistryStore(join(dir,'registry.json'));
  const input=networkLabInput();
  for (const r of input.registry.resources) if (r.management.mode==='managed') { r.management.driver='wg-quick'; if(r.kind==='interface'&&r.id==='wg0')r.name='hpaaaaaaaaaaaa'; if(r.kind==='route'&&r.interfaceId==='wg0'){r.protocol='static';r.metric=42760;} }
  const registry=store.mutate(0,'alice',{action:'replace',resources:input.registry.resources});
  const now=Date.now();
  const observation=structuredClone(input.observations[0]!);observation.receivedAt=new Date(now).toISOString();observation.report.completedAt=observation.receivedAt;
  const review=buildNetworkChangeSet({...input,wireguard:undefined,frr:undefined,registry,now});
  const operation={driver:'linux-wireguard-v1' as const,interfaceId:'wg0',interfaceName:'hpaaaaaaaaaaaa',address:'198.51.100.1/32',mtu:1420,listenPort:51820,secretRef:'local',publicKey:Buffer.alloc(32,1).toString('base64'),peers:[{publicKey:Buffer.alloc(32,2).toString('base64'),endpoint:'203.0.113.2:51820',allowedIps:['198.51.100.2/32']}],routes:['198.51.100.2/32']};
  const draft:NetworkExecutionDraft={schemaVersion:1,transactionId:'a'.repeat(32),target:{source:'lab-relay',host:'lab-host-0',nodeId:'n0'},registryRevision:1,resources:registry.resources.map(r=>({id:r.id,generation:r.generation})),desiredDigest:review.desiredDigest,reviewHash:review.contentHash,artifactHash:networkDigest(operation),observation:{digest:networkDigest(observation),collectedAt:now,maxAgeMs:10000},localPrecondition:'b'.repeat(64),operation,issuedAt:now,expiresAt:now+10000,rollbackAt:now+20000};
  const approvals=emptyApprovals(),key=generateKeyPairSync('ed25519');
  const proposeDraft=()=>propose(approvals,{hash:networkExecutionHash(draft),generation:draft.transactionId,summary:{hosts:[]},by:'alice',now:new Date(now)});
  const approveDraft=()=>approve(approvals,{hash:networkExecutionHash(draft),by:'bob',now:new Date(now)});
  const issue=()=>authorizeNetworkExecution(store,approvals,draft,'alice',key.privateKey,{observation,review},new Date(now));
  return {dir,store,registry,draft,approvals,key,proposeDraft,approveDraft,issue,observation,review};
}

test('network issuer requires existing two-person approval independently of signing key',()=>{
  const f=fixture();try { f.proposeDraft();assert.throws(f.issue,/not been approved/);assert.equal(existsSync(f.store.path+'.execution-fence'),false); } finally {rmSync(f.dir,{recursive:true,force:true});}
});
test('signed execution binds artifact and retains a durable mutation fence across store restarts',()=>{
  const f=fixture();try {
    f.proposeDraft();f.approveDraft();const envelope=f.issue();
    const frame=(s:string)=>{const b=Buffer.from(s),l=Buffer.alloc(4);l.writeUInt32BE(b.length);return Buffer.concat([l,b]);};
    const payload=Buffer.from(envelope.payload,'base64url');
    assert.equal(verify(null,Buffer.concat([frame(NETWORK_EXECUTION_DOMAIN),frame(envelope.keyId),frame(payload.toString())]),f.key.publicKey,Buffer.from(envelope.signature,'base64url')),true);
    assert.equal(JSON.parse(payload.toString()).approval.approvedBy,'bob');
    assert.throws(()=>new NetworkRegistryStore(f.store.path).mutate(1,'external',{action:'replace',resources:f.registry.resources}),/fence/);
    assert.equal(JSON.parse(readFileSync(f.store.path+'.execution-fence','utf8')).transactionId,f.draft.transactionId);
    assert.throws(f.issue,/already been published/);
  } finally {rmSync(f.dir,{recursive:true,force:true});}
});
for(const change of ['revision','generation','artifact','observation','review','ownership'] as const) test(`execution refuses changed ${change} before issuance`,()=>{
  const f=fixture();try {
    if(change==='revision') f.store.mutate(1,'external',{action:'update',id:'wg0',resource:{...f.registry.resources.find(r=>r.id==='wg0'),mtu:1400}});
    if(change==='generation') f.draft.resources[0]!.generation++;
    if(change==='artifact') f.draft.artifactHash='c'.repeat(64);
    if(change==='observation') f.draft.observation.digest='d'.repeat(64);
    if(change==='review') f.draft.reviewHash='e'.repeat(64);
    if(change==='ownership') {f.draft.operation.interfaceName='external';f.draft.artifactHash=networkDigest(f.draft.operation);}
    f.proposeDraft();f.approveDraft();assert.throws(f.issue);assert.equal(existsSync(f.store.path+'.execution-fence'),false);
  } finally {rmSync(f.dir,{recursive:true,force:true});}
});

for (const [field,value] of [['protocol','boot'],['metric',123],['nextHop','198.51.100.3']] as const) test(`issuer refuses route desired-state mismatch: ${field}`,()=>{
  const f=fixture();try {
    const route=f.registry.resources.find(r=>r.kind==='route'&&r.interfaceId==='wg0')!;
    (route as any)[field]=value;
    // Create a fresh Registry/review commitment so this exercises semantic validation, not CAS.
    const next=f.store.mutate(1,'alice',{action:'update',id:route.id,resource:route});
    f.draft.registryRevision=next.revision;f.draft.resources=next.resources.map(r=>({id:r.id,generation:r.generation}));
    const input=networkLabInput();
    const review=buildNetworkChangeSet({...input,registry:next,expectedRegistryRevision:next.revision,wireguard:undefined,frr:undefined});
    f.draft.desiredDigest=review.desiredDigest;f.draft.reviewHash=review.contentHash;
    f.proposeDraft();f.approveDraft();
    assert.throws(()=>authorizeNetworkExecution(f.store,f.approvals,f.draft,'alice',f.key.privateKey,{observation:f.observation,review},new Date(f.draft.issuedAt)),/host route ownership/);
  } finally {rmSync(f.dir,{recursive:true,force:true});}
});
