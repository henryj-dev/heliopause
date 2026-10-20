import { networkDigest } from './network-canonical.ts';
import type { NetworkSignedEnvelope } from './network-execution.ts';
export const NETWORK_EXECUTION_CAPACITY=256;
export const NETWORK_TERMINAL_DOMAIN='heliopause-network-terminal-mtls-v1';
export const NETWORK_CANCELLATION_RESULT_DOMAIN='heliopause-network-cancellation-mtls-v1';
export interface NetworkTarget { source:string;host:string;nodeId:string }
export interface NetworkTerminalResult {
  schemaVersion:1|2;domain:typeof NETWORK_TERMINAL_DOMAIN|typeof NETWORK_CANCELLATION_RESULT_DOMAIN;transactionId:string;fenceId:string;
  target:NetworkTarget;journalId:string;authorizationHash:string;artifactHash:string;registryRevision:number;
  state:'confirmed'|'rolled-back'|'cancelled-before-accept'|'cancellation-rejected';sequence:number;stateHash:string;
  proof:{confirmationHash:string;verificationHash:string}|{removalVerified:true}|{cancellationHash:string;acceptancePrevented:true}|{cancellationHash:string;acceptedState:string};
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
  schemaVersion:1;nextSequence:number;
  fence:null|{transactionId:string;fenceId:string;authorizationHash:string;registryRevision:number};
  records:NetworkExecutionRecord[];
}
const hex=(v:unknown)=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
export function validateExecutionState(state:NetworkExecutionState):void {
  if(!state||state.schemaVersion!==1||!Array.isArray(state.records)||state.records.length>NETWORK_EXECUTION_CAPACITY||state.nextSequence!==state.records.length+1) throw new Error('invalid execution ledger');
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
  const pending=state.records.filter(r=>r.state!=='settled');
  if(state.fence===null?pending.length!==0:pending.length!==1||pending[0]!.transactionId!==state.fence.transactionId||pending[0]!.fenceId!==state.fence.fenceId||pending[0]!.authorizationHash!==state.fence.authorizationHash||pending[0]!.registryRevision!==state.fence.registryRevision) throw new Error('execution fence/record mismatch');
}
