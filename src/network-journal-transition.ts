/** Explicit scope A only: replace a quiescent single-target replay epoch after verified archival.
 * No confirmed ownership transfer, partial pruning, unlock, or implicit certificate rebinding.
 */
import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';
import { artifactSigningKeyId } from './artifact-signature.ts';
import { loadJournalArchive } from './network-journal-archive.ts';
import { readBoundedStoreFile } from './json-store.ts';
import { canonicalNetworkJson, networkDigest } from './network-canonical.ts';
import { claimForPublish, settle, type ApprovalState } from './approval.ts';
import { signNetworkMessage, type NetworkSignedEnvelope } from './network-execution.ts';
import { NetworkRegistryStore, type NetworkRegistryDocument } from './network-registry.ts';
import { validateExecutionState, type NetworkTarget } from './network-execution-state.ts';

export const JOURNAL_TRANSITION_DOMAIN='heliopause-network-quiescent-transition-v1';
export const JOURNAL_TRANSITION_RECEIPT_DOMAIN='heliopause-network-transition-manager-commit-v1';
export const JOURNAL_TRANSITION_LIMIT=256;
export interface JournalArchive {
  schemaVersion:1;
  rawFiles:Record<'manager'|'agent'|'identity'|'outbox'|'acknowledgments',string>;
  manager:NetworkRegistryDocument;
  agent:{schemaVersion:2;journalId:string;acceptedSequence:number;terminalSequence:number;lastClock:number;transactions:Record<string,any>};
  identity:{journalId:string};outbox:any[];acknowledgments:Record<string,true>;
}
export interface JournalTransitionDraft {
  schemaVersion:1;mode:'quiescent-without-confirmed-v1';transitionId:string;target:NetworkTarget;
  oldJournalId:string;newJournalId:string;archiveHash:string;managerHash:string;agentHash:string;
  issuedAt:number;expiresAt:number;
}
export interface JournalTransition extends JournalTransitionDraft {
  approval:{mode:'two-person';planHash:string;proposedBy:string;approvedBy:string;approvedAt:number};
}
export interface JournalEpoch {
  journalId:string;target:NetworkTarget;
  transitions:Array<{oldJournalId:string;newJournalId:string;transitionHash:string;archiveHash:string;receipt:NetworkSignedEnvelope}>;
}
const exact=(v:any,fields:string)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(' ')===fields.split(' ').sort().join(' ');
const id=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{32}$/.test(v);
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const principal=(v:unknown)=>typeof v==='string'&&/^[A-Za-z0-9_.-]{1,64}$/.test(v);
const equal=(a:unknown,b:unknown)=>networkDigest(a)===networkDigest(b);
function need(condition:unknown,reason:string):asserts condition {if(!condition)throw new Error(reason);}

/** This checks stored proof correspondence, not live kernel absence or archive custody. Those
 * independent Agent maintenance checks are mandatory before its own commit.
 */
export function validateQuiescentArchive(archive:JournalArchive,target:NetworkTarget):void {
  need(exact(archive,'schemaVersion rawFiles manager agent identity outbox acknowledgments')&&archive.schemaVersion===1,'unsupported archive');
  need(exact(archive.rawFiles,'manager agent identity outbox acknowledgments'),'exact raw archive files required');
  for(const name of ['manager','agent','identity','outbox','acknowledgments'] as const) {
    const encoded=archive.rawFiles[name];need(typeof encoded==='string'&&encoded.length<=12*1024*1024,'raw archive file bound');
    const raw=Buffer.from(encoded,'base64url');need(raw.toString('base64url')===encoded&&equal(JSON.parse(raw.toString()),archive[name]),'raw/parsed archive mismatch');
  }
  need(exact(target,'source host nodeId')&&Object.values(target).every(principal),'exact target required');
  const a=archive.agent,m=archive.manager.execution;
  need(exact(a,'schemaVersion journalId acceptedSequence terminalSequence lastClock transactions')&&a.schemaVersion===2&&id(a.journalId)&&equal(archive.identity,{journalId:a.journalId}),'invalid Agent archive identity');
  need(m&&archive.manager.schemaVersion===2,'Manager execution archive required');validateExecutionState(m);
  need(m.fence===null&&m.records.every(r=>r.state==='settled'&&r.journalId===a.journalId&&equal(r.target,target)),'single-target settled Manager required');
  need(a.transactions&&typeof a.transactions==='object'&&!Array.isArray(a.transactions)&&Object.keys(a.transactions).length<=1024&&a.acceptedSequence===Object.keys(a.transactions).length,'invalid Agent replay archive');
  need(Array.isArray(archive.outbox)&&archive.outbox.length===m.records.length&&Object.keys(a.transactions).length===m.records.length,'archive record sets differ');
  need(archive.acknowledgments&&typeof archive.acknowledgments==='object'&&!Array.isArray(archive.acknowledgments)&&Object.keys(archive.acknowledgments).length===archive.outbox.length&&Object.entries(archive.acknowledgments).every(([k,v])=>hash(k)&&v===true),'exact terminal acknowledgments required');
  const outbox=new Map(archive.outbox.map(r=>[r.transactionId,r]));need(outbox.size===archive.outbox.length,'duplicate outbox identity');
  const sequences=new Set<number>();
  for(const record of m.records) {
    const row=a.transactions[record.transactionId],result=record.result;
    need(row&&['rolled-back','cancelled-before-accept'].includes(row.state)&&result&&result.state===row.state,'confirmed or nonterminal resources forbid scope A');
    need(!row.bootRestore&&!row.before&&!row.paths,'recovery/diagnostic debt requires reconciliation');
    need(equal(row.authorization,JSON.parse(Buffer.from(record.authorization.payload,'base64url').toString()))&&record.authorizationHash===networkDigest(row.authorization),'authorization archive mismatch');
    need(equal(row.cancellationResponse??null,record.cancellationResponse??null),'accepted cancellation response archive mismatch');
    need(row.authorization.journalId===a.journalId&&equal(row.authorization.target,target),'Agent target archive mismatch');
    need(equal(row.terminalResult,result)&&equal(outbox.get(record.transactionId),result)&&record.resultHash===networkDigest(result)&&archive.acknowledgments[record.resultHash!]===true,'exact archived settlement/ack required');
    need(result.journalId===a.journalId&&equal(result.target,target)&&result.authorizationHash===record.authorizationHash&&result.artifactHash===record.artifactHash,'terminal binding mismatch');
    const {stateHash,...committed}=result;need(stateHash===networkDigest(committed),'terminal state commitment mismatch');
    need(Number.isSafeInteger(result.sequence)&&result.sequence>=1&&!sequences.has(result.sequence),'terminal sequence mismatch');sequences.add(result.sequence);
    if(result.state==='rolled-back')need(exact(result.proof,'removalVerified')&&'removalVerified' in result.proof&&result.proof.removalVerified===true,'removal proof required');
    else need(exact(result.proof,'cancellationHash acceptancePrevented')&&'acceptancePrevented' in result.proof&&result.proof.acceptancePrevented===true,'never-accepted proof required');
  }
  need(a.terminalSequence===m.records.length&&[...sequences].every(seq=>seq<=a.terminalSequence),'terminal ledger continuity required');
  need(!m.journalEpoch||(m.journalEpoch.journalId===a.journalId&&equal(m.journalEpoch.target,target)&&m.journalEpoch.transitions.length<JOURNAL_TRANSITION_LIMIT),'epoch transition capacity or identity refusal');
}

export function planJournalTransition(archive:JournalArchive,target:NetworkTarget,newJournalId:string,transitionId:string,now=Date.now()):JournalTransitionDraft {
  validateQuiescentArchive(archive,target);
  need(id(newJournalId)&&newJournalId!==archive.agent.journalId&&id(transitionId),'fresh transition/journal identity required');
  need(!archive.manager.execution!.journalEpoch?.transitions.some(t=>t.oldJournalId===newJournalId||t.newJournalId===newJournalId),'journal identity reuse refused');
  need(Number.isSafeInteger(now)&&now>0,'valid transition clock required');
  return {schemaVersion:1,mode:'quiescent-without-confirmed-v1',transitionId,target,oldJournalId:archive.agent.journalId,newJournalId,
    archiveHash:networkDigest(archive.rawFiles),managerHash:createHash('sha256').update(Buffer.from(archive.rawFiles.manager,'base64url')).digest('hex'),agentHash:createHash('sha256').update(Buffer.from(archive.rawFiles.agent,'base64url')).digest('hex'),issuedAt:now,expiresAt:now+3600000};
}
export const journalTransitionHash=(draft:JournalTransitionDraft)=>'sha256:'+networkDigest(draft);
export function authorizeJournalTransition(archive:JournalArchive,draft:JournalTransitionDraft,approvals:ApprovalState,by:string,key:KeyObject,now=new Date()):NetworkSignedEnvelope {
  const expected=planJournalTransition(archive,draft.target,draft.newJournalId,draft.transitionId,draft.issuedAt);
  need(equal(draft,expected)&&draft.issuedAt<=+now&&+now<draft.expiresAt,'stale or changed transition plan');
  const hash=journalTransitionHash(draft),plan=claimForPublish(approvals,{hash,by,now});
  need(plan.approval&&!plan.approval.solo&&plan.proposedBy!==plan.approval.by,'two-person transition approval required');
  const result=signNetworkMessage(JOURNAL_TRANSITION_DOMAIN,{...draft,approval:{mode:'two-person',planHash:hash,proposedBy:plan.proposedBy,approvedBy:plan.approval.by,approvedAt:Date.parse(plan.approval.at)}},key);
  settle(approvals,hash);return result;
}
export function verifyJournalMessage(envelope:NetworkSignedEnvelope,domain:string,keys:readonly KeyObject[]):any {
  need(exact(envelope,'version algorithm keyId payload signature')&&envelope.version==='heliopause-ed25519-v1'&&envelope.algorithm==='Ed25519'&&typeof envelope.payload==='string'&&envelope.payload.length<=180000,'invalid transition envelope');
  const material=new Map(keys.map(key=>[artifactSigningKeyId(key),key]));need(material.size===keys.length,'duplicate transition trust key');
  const key=material.get(envelope.keyId),payload=Buffer.from(envelope.payload,'base64url'),signature=Buffer.from(envelope.signature,'base64url');
  const frame=(data:Buffer)=>{const size=Buffer.alloc(4);size.writeUInt32BE(data.length);return Buffer.concat([size,data]);};
  need(key&&signature.length===64&&verify(null,Buffer.concat([frame(Buffer.from(domain)),frame(Buffer.from(envelope.keyId)),frame(payload)]),key,signature),'untrusted transition signature');
  const parsed=JSON.parse(payload.toString());need(canonicalNetworkJson(parsed)===payload.toString(),'noncanonical transition message');return parsed;
}

/** The exact archive is approved before any capacity is reclaimed. Existing Registry kernel
 * writer arbitration surrounds the recheck and one atomic Registry replace. Other stores are
 * not claimed atomic: Agent consumes this durable receipt in its separate maintenance phase.
 */
export function commitManagerJournalTransition(store:NetworkRegistryStore,archive:JournalArchive,envelope:NetworkSignedEnvelope,trustedKeys:readonly KeyObject[],key:KeyObject,archiveDirectory:string,now=Date.now()):NetworkSignedEnvelope {
  const durableArchive=loadJournalArchive(archiveDirectory);
  need(equal(durableArchive,archive),'durable archive differs from approved input');
  need(artifactSigningKeyId(createPublicKey(key))===envelope.keyId,'transition receipt must use approved Manager signing key');
  const t=verifyJournalMessage(envelope,JOURNAL_TRANSITION_DOMAIN,trustedKeys) as JournalTransition;
  need(exact(t,'schemaVersion mode transitionId target oldJournalId newJournalId archiveHash managerHash agentHash issuedAt expiresAt approval'),'invalid transition contract');
  const {approval,...draft}=t;
  const expected=planJournalTransition(archive,t.target,t.newJournalId,t.transitionId,t.issuedAt);
  need(equal(draft,expected)&&exact(approval,'mode planHash proposedBy approvedBy approvedAt')&&approval.mode==='two-person'&&approval.planHash===journalTransitionHash(draft)&&principal(approval.proposedBy)&&principal(approval.approvedBy)&&approval.proposedBy!==approval.approvedBy&&Number.isSafeInteger(approval.approvedAt)&&approval.approvedAt>=t.issuedAt&&approval.approvedAt<t.expiresAt,'transition approval mismatch');
  return store.executionTransaction((state,doc)=>{
    const previous=state.journalEpoch?.transitions.find(r=>r.transitionHash===networkDigest(t));
    if(previous) return previous.receipt; // Re-fsync by executionTransaction before returning.
    need(t.issuedAt<=now&&now<t.expiresAt,'transition expired before Manager commit');
    need(createHash('sha256').update(readBoundedStoreFile(store.path,4*1024*1024)).digest('hex')===t.managerHash,'Manager changed since archived plan');
    validateQuiescentArchive({...archive,manager:doc},t.target);
    const receipt=signNetworkMessage(JOURNAL_TRANSITION_RECEIPT_DOMAIN,{schemaVersion:1,transitionHash:networkDigest(t),oldJournalId:t.oldJournalId,newJournalId:t.newJournalId,target:t.target,archiveHash:t.archiveHash,committedAt:now},key);
    state.journalEpoch={journalId:t.newJournalId,target:t.target,transitions:[...(state.journalEpoch?.transitions??[]),{oldJournalId:t.oldJournalId,newJournalId:t.newJournalId,transitionHash:networkDigest(t),archiveHash:t.archiveHash,receipt}]};
    state.records=[];state.nextSequence=1;state.fence=null;
    return receipt;
  });
}
