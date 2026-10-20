import { networkDigest } from './network-canonical.ts';
import type { NetworkSignedEnvelope } from './network-execution.ts';
export const NETWORK_TERMINAL_DOMAIN='heliopause-network-terminal-mtls-v1';
export interface NetworkTarget { source:string;host:string;nodeId:string }
export interface NetworkTerminalResult {
  schemaVersion:1;domain:typeof NETWORK_TERMINAL_DOMAIN;transactionId:string;fenceId:string;
  target:NetworkTarget;journalId:string;authorizationHash:string;artifactHash:string;registryRevision:number;
  state:'confirmed'|'rolled-back';sequence:number;stateHash:string;
  proof:{confirmationHash:string;verificationHash:string}|{removalVerified:true};
}
export interface NetworkExecutionRecord {
  sequence:number;transactionId:string;fenceId:string;planHash:string;authorization:NetworkSignedEnvelope;
  authorizationHash:string;target:NetworkTarget;journalId:string;registryRevision:number;artifactHash:string;
  issuedAt:number;issuedBy:string;state:'issued'|'confirm-issued'|'settled';
  confirmation?:NetworkSignedEnvelope;verificationHash?:string;
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
  if(!state||state.schemaVersion!==1||!Array.isArray(state.records)||state.records.length>256||state.nextSequence!==state.records.length+1) throw new Error('invalid execution ledger');
  const ids=new Set<string>();
  for(const [index,r] of state.records.entries()) {
    const a=JSON.parse(Buffer.from(r.authorization.payload,'base64url').toString());
    if(r.sequence!==index+1||ids.has(r.transactionId)||!['issued','confirm-issued','settled'].includes(r.state)||r.transactionId!==a.transactionId||r.fenceId!==a.transactionId||r.journalId!==a.journalId||r.planHash!==a.approval.planHash||networkDigest(a)!==r.authorizationHash||networkDigest(a.target)!==networkDigest(r.target)||r.registryRevision!==a.registryRevision||r.artifactHash!==a.artifactHash||!hex(r.authorizationHash)||!hex(r.artifactHash)||!Array.isArray(r.audit)||!r.audit.length||r.audit.length>32) throw new Error('invalid issued record');
    if(r.state==='confirm-issued'&&!r.confirmation) throw new Error('missing confirmation');
    if(r.state==='settled'&&(!r.result||networkDigest(r.result)!==r.resultHash||!Number.isSafeInteger(r.settledAt)||!r.settledBy)) throw new Error('invalid settlement');
    ids.add(r.transactionId);
  }
  const pending=state.records.filter(r=>r.state!=='settled');
  if(state.fence===null?pending.length!==0:pending.length!==1||pending[0]!.transactionId!==state.fence.transactionId||pending[0]!.fenceId!==state.fence.fenceId||pending[0]!.authorizationHash!==state.fence.authorizationHash||pending[0]!.registryRevision!==state.fence.registryRevision) throw new Error('execution fence/record mismatch');
}
