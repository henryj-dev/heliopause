import { networkDigest } from './network-canonical.ts';
import { confirmNetworkExecution, type NetworkSignedEnvelope } from './network-execution.ts';
import { NetworkRegistryStore, NetworkRegistryError } from './network-registry.ts';
import { NETWORK_TERMINAL_DOMAIN, NETWORK_CANCELLATION_RESULT_DOMAIN, NETWORK_CAPACITY_RESULT_DOMAIN, type NetworkTerminalResult, type NetworkTarget } from './network-execution-state.ts';
import { cancellationHash } from './network-execution-cancellation.ts';
import type { KeyObject } from 'node:crypto';
const decode=(e:NetworkSignedEnvelope)=>JSON.parse(Buffer.from(e.payload,'base64url').toString());
const exact=(o:any,fields:string)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join(' ')===fields.split(' ').sort().join(' ');

/** Cached signed confirm survives response loss/restart; its original validity window is retained. */
export function issueDurableNetworkConfirm(store:NetworkRegistryStore,hash:string,verification:NetworkSignedEnvelope,keys:readonly KeyObject[],key:KeyObject,actor:string,now=Date.now()):NetworkSignedEnvelope {
  return store.executionTransaction(state=>{
    const record=state.records.find(r=>r.planHash===hash);
    if(!record) throw new NetworkRegistryError('issued execution not found',404);
    if(record.cancellation) throw new NetworkRegistryError('cancellation requested; confirmation refused',409);
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
export function settleNetworkExecution(store:NetworkRegistryStore,result:NetworkTerminalResult,agent:NetworkTarget&{journalId:string},actor:string,now=Date.now()):{settled:true;duplicate:boolean}|{settled:false;recorded:true;duplicate:boolean} {
  const outcome=store.executionTransaction((state,doc)=>{
    const record=state.records.find(r=>r.transactionId===result?.transactionId);
    const refuse=(reason:string)=>{
      if(record) {record.audit.push({action:'settlement-refused',actor,at:now,reason});record.audit=record.audit.slice(-32);}
      return {reason};
    };
    if(!exact(result,'schemaVersion domain transactionId fenceId target journalId authorizationHash artifactHash registryRevision state sequence stateHash proof')||!record||!result.proof||typeof result.proof!=='object'||Array.isArray(result.proof)) return refuse('invalid or unknown terminal contract');
    const capacity=result.schemaVersion===3&&result.domain===NETWORK_CAPACITY_RESULT_DOMAIN;
    const cancellation=capacity||result.schemaVersion===2&&result.domain===NETWORK_CANCELLATION_RESULT_DOMAIN;
    if(!cancellation&&(result.schemaVersion!==1||result.domain!==NETWORK_TERMINAL_DOMAIN)) return refuse('unsupported terminal schema/domain');
    if(networkDigest(result.target)!==networkDigest(record.target)||networkDigest(result.target)!==networkDigest({source:agent.source,host:agent.host,nodeId:agent.nodeId})||result.journalId!==agent.journalId||result.journalId!==record.journalId||result.fenceId!==record.fenceId||result.authorizationHash!==record.authorizationHash||result.artifactHash!==record.artifactHash||result.registryRevision!==record.registryRevision) return refuse('terminal identity or commitment mismatch');
    const {stateHash,...committed}=result;
    if(!Number.isSafeInteger(result.sequence)||result.sequence<1||result.sequence>1024||stateHash!==networkDigest(committed)) return refuse('terminal persistence commitment mismatch');
    if(cancellation) {
      if(!record.cancellation||!('cancellationHash' in result.proof)||result.proof.cancellationHash!==cancellationHash(record.cancellation)) return refuse('cancellation commitment mismatch');
      if(capacity&&(result.state!=='cancelled-before-accept'||!exact(result.proof,'cancellationHash acceptancePrevented maintenanceRequired')||!('maintenanceRequired' in result.proof)||result.proof.maintenanceRequired!==true))return refuse('capacity stop proof required');
      if(result.state==='cancellation-rejected') {
        if(record.result?.state==='cancelled-before-accept') return refuse('accepted response conflicts with never-accepted result');
        if(!exact(result.proof,'cancellationHash acceptedState')||!('acceptedState' in result.proof)||!['prepared','applying','awaiting-verification','awaiting-confirm','rolling-back','rollback-failed'].includes(result.proof.acceptedState)) return refuse('accepted cancellation response required');
        if(record.cancellationResponse) return record.cancellationResponseHash===networkDigest(result)?{settled:false as const,recorded:true as const,duplicate:true}:refuse('conflicting cancellation response');
        record.cancellationResponse=result;record.cancellationResponseHash=networkDigest(result);
        if(record.state!=='settled') record.cancelStatus='accepted-recovery-required';
        record.audit.push({action:'cancel-requires-recovery',actor,at:now});record.audit=record.audit.slice(-32);
        return {settled:false as const,recorded:true as const,duplicate:false};
      }
      if(result.state!=='cancelled-before-accept'||!exact(result.proof,capacity?'cancellationHash acceptancePrevented maintenanceRequired':'cancellationHash acceptancePrevented')||!('acceptancePrevented' in result.proof)||result.proof.acceptancePrevented!==true||record.cancellationResponse) return refuse('durable never-accepted cancellation proof required');
    } else if(result.state!=='confirmed'&&result.state!=='rolled-back') return refuse('legacy terminal state required');
    if(capacity&&state.records.some(r=>r!==record&&(r.state!=='settled'||!r.result||!['rolled-back','cancelled-before-accept'].includes(r.result.state))))return refuse('capacity reservation requires resource-free settled history');
    if(record.result) return record.resultHash===networkDigest(result)?{settled:true as const,duplicate:true}:refuse('conflicting terminal result');
    if(state.fence?.transactionId!==record.transactionId||state.fence.authorizationHash!==record.authorizationHash||state.fence.fenceId!==record.fenceId||state.fence.registryRevision!==record.registryRevision||doc.revision!==record.registryRevision) return refuse('current fence mismatch');
    if(result.state==='confirmed') {
      if(!record.confirmation||!exact(result.proof,'confirmationHash verificationHash')||('confirmationHash' in result.proof&&result.proof.confirmationHash!==networkDigest(decode(record.confirmation)))||('verificationHash' in result.proof&&result.proof.verificationHash!==networkDigest(decode(decode(record.confirmation).verification)))) return refuse('confirmed result lacks issued independent confirm');
    } else if(!cancellation&&(result.state!=='rolled-back'||!exact(result.proof,'removalVerified')||!('removalVerified' in result.proof)||result.proof.removalVerified!==true)) return refuse('verified successful terminal state required');
    record.result=result;record.resultHash=networkDigest(result);record.state='settled';record.settledAt=now;record.settledBy=actor;
    record.audit.push({action:'settled',actor,at:now});record.audit=record.audit.slice(-32);
    if(record.cancellation) record.cancelStatus='settled';
    if(capacity){state.schemaVersion=2;state.capacityHold={target:record.target,journalId:record.journalId,transactionId:record.transactionId,authorizationHash:record.authorizationHash,resultHash:record.resultHash};}
    state.fence=null;
    return {settled:true as const,duplicate:false};
  });
  if('reason' in outcome) throw new NetworkRegistryError(outcome.reason!,409);
  return outcome;
}
