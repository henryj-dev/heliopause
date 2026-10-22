import type { JournalEpoch } from './network-journal-transition.ts';
import { networkDigest } from './network-canonical.ts';
import type { NetworkSignedEnvelope } from './network-execution.ts';
export const NETWORK_EXECUTION_CAPACITY=256;
export const NETWORK_TERMINAL_DOMAIN='heliopause-network-terminal-mtls-v1';
export const NETWORK_CANCELLATION_RESULT_DOMAIN='heliopause-network-cancellation-mtls-v1';
export const NETWORK_CAPACITY_RESULT_DOMAIN='heliopause-network-capacity-stop-mtls-v1';
export interface NetworkTarget { source:string;host:string;nodeId:string }
export interface NetworkTerminalResult {
  schemaVersion:1|2|3;domain:typeof NETWORK_TERMINAL_DOMAIN|typeof NETWORK_CANCELLATION_RESULT_DOMAIN|typeof NETWORK_CAPACITY_RESULT_DOMAIN;transactionId:string;fenceId:string;
  target:NetworkTarget;journalId:string;authorizationHash:string;artifactHash:string;registryRevision:number;
  state:'confirmed'|'rolled-back'|'cancelled-before-accept'|'cancellation-rejected';sequence:number;stateHash:string;
  proof:{confirmationHash:string;verificationHash:string}|{removalVerified:true}|{cancellationHash:string;acceptancePrevented:true}|{cancellationHash:string;acceptedState:string}|{cancellationHash:string;acceptancePrevented:true;maintenanceRequired:true};
}
export interface NetworkExecutionRecord {
  sequence:number;transactionId:string;fenceId:string;planHash:string;authorization:NetworkSignedEnvelope;
  authorizationHash:string;target:NetworkTarget;journalId:string;registryRevision:number;artifactHash:string;
  issuedAt:number;issuedBy:string;state:'issued'|'confirm-issued'|'settled';
  confirmation?:NetworkSignedEnvelope;verificationHash?:string;
  cancellation?:NetworkSignedEnvelope;cancelStatus?:'requested'|'accepted-recovery-required'|'settled';
  cancellationResponse?:NetworkTerminalResult;cancellationResponseHash?:string;
  result?:NetworkTerminalResult;resultHash?:string;settledAt?:number;settledBy?:string;
  audit:Array<{action:string;actor:string;at:number;reason?:string}>;
}
export interface NetworkExecutionState {
  schemaVersion:1|2;nextSequence:number;
  capacityHold?:{target:NetworkTarget;journalId:string;transactionId:string;authorizationHash:string;resultHash:string};
  fence:null|{transactionId:string;fenceId:string;authorizationHash:string;registryRevision:number};
  records:NetworkExecutionRecord[];
  /** Scope-A retirement tombstones, never pruned. After transition this Registry is single-target. */
  journalEpoch?:JournalEpoch;
}
const hex=(v:unknown)=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
export function validateExecutionState(state:NetworkExecutionState):void {
  if(!state||![1,2].includes(state.schemaVersion)||!Array.isArray(state.records)||state.records.length>NETWORK_EXECUTION_CAPACITY||state.nextSequence!==state.records.length+1) throw new Error('invalid execution ledger');
  if(state.journalEpoch) {
    const e=state.journalEpoch,retired=new Set<string>();let prior:string|undefined;
    if(!/^[a-f0-9]{32}$/.test(e.journalId)||!e.target||Object.keys(e.target).sort().join(' ')!=='host nodeId source'||Object.values(e.target).some(v=>typeof v!=='string'||!/^[A-Za-z0-9_.-]{1,64}$/.test(v))||!Array.isArray(e.transitions)||!e.transitions.length||e.transitions.length>256) throw new Error('invalid journal epoch');
    for(const t of e.transitions) {
      if(!/^[a-f0-9]{32}$/.test(t.oldJournalId)||!/^[a-f0-9]{32}$/.test(t.newJournalId)||t.oldJournalId===t.newJournalId||retired.has(t.oldJournalId)||retired.has(t.newJournalId)||prior!==undefined&&t.oldJournalId!==prior||!hex(t.transitionHash)||!hex(t.archiveHash)||!hex(t.evidenceHash)||!t.authorization||!t.receipt) throw new Error('invalid journal retirement chain');
      const authority=JSON.parse(Buffer.from(t.authorization.payload,'base64url').toString());
      if(networkDigest(authority)!==t.transitionHash||authority.oldJournalId!==t.oldJournalId||authority.newJournalId!==t.newJournalId||authority.archiveHash!==t.archiveHash||authority.evidenceHash!==t.evidenceHash||networkDigest(authority.target)!==networkDigest(e.target)||t.authorization.keyId!==t.receipt.keyId)throw new Error('invalid durable transition authority');
      const p=JSON.parse(Buffer.from(t.receipt.payload,'base64url').toString());
      if(p.schemaVersion!==1||p.transitionHash!==t.transitionHash||p.archiveHash!==t.archiveHash||p.evidenceHash!==t.evidenceHash||p.oldJournalId!==t.oldJournalId||p.newJournalId!==t.newJournalId||networkDigest(p.target)!==networkDigest(e.target)||!Number.isSafeInteger(p.committedAt)) throw new Error('invalid journal retirement receipt');
      retired.add(t.oldJournalId);prior=t.newJournalId;
    }
    if(prior!==e.journalId||retired.has(e.journalId)||state.records.some(r=>r.journalId!==e.journalId||networkDigest(r.target)!==networkDigest(e.target))) throw new Error('retired or foreign journal record');
  }
  const ids=new Set<string>();
  for(const [index,r] of state.records.entries()) {
    const a=JSON.parse(Buffer.from(r.authorization.payload,'base64url').toString());
    if(r.sequence!==index+1||ids.has(r.transactionId)||!['issued','confirm-issued','settled'].includes(r.state)||r.transactionId!==a.transactionId||r.fenceId!==a.transactionId||r.journalId!==a.journalId||r.planHash!==a.approval.planHash||networkDigest(a)!==r.authorizationHash||networkDigest(a.target)!==networkDigest(r.target)||r.registryRevision!==a.registryRevision||r.artifactHash!==a.artifactHash||!hex(r.authorizationHash)||!hex(r.artifactHash)||!Array.isArray(r.audit)||!r.audit.length||r.audit.length>32) throw new Error('invalid issued record');
    if(r.state==='confirm-issued'&&!r.confirmation) throw new Error('missing confirmation');
    if(r.cancellation) {
      const c=JSON.parse(Buffer.from(r.cancellation.payload,'base64url').toString());
      if(c.schemaVersion!==1||c.transactionId!==r.transactionId||c.fenceId!==r.fenceId||c.authorizationHash!==r.authorizationHash||c.journalId!==r.journalId||c.registryRevision!==r.registryRevision||c.artifactHash!==r.artifactHash||networkDigest(c.target)!==networkDigest(r.target)||networkDigest(c.authorization)!==networkDigest(r.authorization)||!['requested','accepted-recovery-required','settled'].includes(r.cancelStatus!)) throw new Error('invalid cancellation record');
      if(r.cancellationResponse&&(networkDigest(r.cancellationResponse)!==r.cancellationResponseHash||r.cancellationResponse.state!=='cancellation-rejected')) throw new Error('invalid cancellation response');
      if(Boolean(r.cancellationResponse)!==Boolean(r.cancellationResponseHash)||r.cancelStatus==='accepted-recovery-required'&&!r.cancellationResponse||r.cancelStatus==='settled'&&r.state!=='settled'||r.state==='settled'&&r.cancelStatus!=='settled') throw new Error('inconsistent cancellation state');
    } else if(r.cancelStatus||r.cancellationResponse||r.cancellationResponseHash) throw new Error('orphan cancellation state');
    if(r.state==='settled'&&(!r.result||networkDigest(r.result)!==r.resultHash||!Number.isSafeInteger(r.settledAt)||!r.settledBy)) throw new Error('invalid settlement');
    ids.add(r.transactionId);
  }
  // A schema bump is intentional: older Managers must reject this durable issuance hold.
  if(state.schemaVersion===1&&state.capacityHold||state.schemaVersion===2&&!state.capacityHold)throw new Error('capacity schema/hold mismatch');
  const stops=state.records.filter(r=>r.result?.schemaVersion===3||r.result?.domain===NETWORK_CAPACITY_RESULT_DOMAIN);
  if(stops.length&&(stops.length!==1||!state.capacityHold||state.schemaVersion!==2||stops[0]!==state.records.at(-1)||stops[0]!.transactionId!==state.capacityHold.transactionId))throw new Error('capacity result requires final durable hold');
  if(state.capacityHold) {
    const h=state.capacityHold,r=state.records.find(r=>r.transactionId===h.transactionId);
    if(state.records.some(prior=>prior!==r&&(prior.state!=='settled'||!prior.result||!['rolled-back','cancelled-before-accept'].includes(prior.result.state))))throw new Error('capacity hold requires resource-free settled history');
    if(r?.result){const {stateHash,...committed}=r.result;if(stateHash!==networkDigest(committed))throw new Error('capacity result persistence mismatch');}
    if(Object.keys(h).sort().join(' ')!=='authorizationHash journalId resultHash target transactionId'||!r||r.state!=='settled'||!r.result||r.result.schemaVersion!==3||r.result.domain!==NETWORK_CAPACITY_RESULT_DOMAIN||r.result.state!=='cancelled-before-accept'||!r.cancellation||networkDigest(r.result.proof)!==networkDigest({cancellationHash:networkDigest(JSON.parse(Buffer.from(r.cancellation.payload,'base64url').toString())),acceptancePrevented:true,maintenanceRequired:true})||r.authorizationHash!==h.authorizationHash||r.resultHash!==h.resultHash||r.journalId!==h.journalId||networkDigest(r.target)!==networkDigest(h.target)||state.fence!==null)throw new Error('invalid capacity maintenance hold');
  }
  const pending=state.records.filter(r=>r.state!=='settled');
  if(state.fence===null?pending.length!==0:pending.length!==1||pending[0]!.transactionId!==state.fence.transactionId||pending[0]!.fenceId!==state.fence.fenceId||pending[0]!.authorizationHash!==state.fence.authorizationHash||pending[0]!.registryRevision!==state.fence.registryRevision) throw new Error('execution fence/record mismatch');
}
