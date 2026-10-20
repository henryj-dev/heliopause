import { networkDigest } from './network-canonical.ts';
import { confirmNetworkExecution, type NetworkSignedEnvelope } from './network-execution.ts';
import { NetworkRegistryStore, NetworkRegistryError } from './network-registry.ts';
import { NETWORK_TERMINAL_DOMAIN, type NetworkTerminalResult, type NetworkTarget } from './network-execution-state.ts';
import type { KeyObject } from 'node:crypto';
const decode=(e:NetworkSignedEnvelope)=>JSON.parse(Buffer.from(e.payload,'base64url').toString());
const exact=(o:any,fields:string)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join(' ')===fields.split(' ').sort().join(' ');

/** Cached signed confirm survives response loss/restart; its original validity window is retained. */
export function issueDurableNetworkConfirm(store:NetworkRegistryStore,hash:string,verification:NetworkSignedEnvelope,keys:readonly KeyObject[],key:KeyObject,actor:string,now=Date.now()):NetworkSignedEnvelope {
  return store.executionTransaction(state=>{
    const record=state.records.find(r=>r.planHash===hash);
    if(!record) throw new NetworkRegistryError('issued execution not found',404);
    if(record.confirmation) {
      if(record.verificationHash!==networkDigest(verification)) throw new NetworkRegistryError('conflicting confirm evidence',409);
      return record.confirmation;
    }
    if(record.state==='settled'||state.fence?.transactionId!==record.transactionId) throw new NetworkRegistryError('execution already settled',409);
    const envelope=confirmNetworkExecution(record.authorization,verification,keys,key,now);
    record.confirmation=envelope;record.verificationHash=networkDigest(verification);record.state='confirm-issued';
    record.audit.push({action:'confirm-issued',actor,at:now});record.audit=record.audit.slice(-32);
    return envelope;
  });
}

/** Called only after direct, pinned Agent mTLS authentication, never from a Relay assertion. */
export function settleNetworkExecution(store:NetworkRegistryStore,result:NetworkTerminalResult,agent:NetworkTarget&{journalId:string},actor:string,now=Date.now()):{settled:true;duplicate:boolean} {
  const outcome=store.executionTransaction((state,doc)=>{
    const record=state.records.find(r=>r.transactionId===result?.transactionId);
    const refuse=(reason:string)=>{
      if(record) {record.audit.push({action:'settlement-refused',actor,at:now,reason});record.audit=record.audit.slice(-32);}
      return {reason};
    };
    if(!exact(result,'schemaVersion domain transactionId fenceId target journalId authorizationHash artifactHash registryRevision state sequence stateHash proof')||result.schemaVersion!==1||result.domain!==NETWORK_TERMINAL_DOMAIN||!record) return refuse('invalid or unknown terminal contract');
    if(networkDigest(result.target)!==networkDigest(record.target)||networkDigest(result.target)!==networkDigest({source:agent.source,host:agent.host,nodeId:agent.nodeId})||result.journalId!==agent.journalId||result.journalId!==record.journalId||result.fenceId!==record.fenceId||result.authorizationHash!==record.authorizationHash||result.artifactHash!==record.artifactHash||result.registryRevision!==record.registryRevision) return refuse('terminal identity or commitment mismatch');
    const {stateHash,...committed}=result;
    if(!Number.isSafeInteger(result.sequence)||result.sequence<1||result.sequence>1024||stateHash!==networkDigest(committed)) return refuse('terminal persistence commitment mismatch');
    if(record.result) return record.resultHash===networkDigest(result)?{settled:true as const,duplicate:true}:refuse('conflicting terminal result');
    if(state.fence?.transactionId!==record.transactionId||state.fence.authorizationHash!==record.authorizationHash||state.fence.fenceId!==record.fenceId||state.fence.registryRevision!==record.registryRevision||doc.revision!==record.registryRevision) return refuse('current fence mismatch');
    if(result.state==='confirmed') {
      if(!record.confirmation||!exact(result.proof,'confirmationHash verificationHash')||('confirmationHash' in result.proof&&result.proof.confirmationHash!==networkDigest(decode(record.confirmation)))||('verificationHash' in result.proof&&result.proof.verificationHash!==networkDigest(decode(decode(record.confirmation).verification)))) return refuse('confirmed result lacks issued independent confirm');
    } else if(result.state!=='rolled-back'||!exact(result.proof,'removalVerified')||!('removalVerified' in result.proof)||result.proof.removalVerified!==true) return refuse('verified successful terminal state required');
    record.result=result;record.resultHash=networkDigest(result);record.state='settled';record.settledAt=now;record.settledBy=actor;
    record.audit.push({action:'settled',actor,at:now});record.audit=record.audit.slice(-32);
    state.fence=null;
    return {settled:true as const,duplicate:false};
  });
  if('reason' in outcome) throw new NetworkRegistryError(outcome.reason!,409);
  return outcome;
}
