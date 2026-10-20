import type { KeyObject } from 'node:crypto';
import { networkDigest } from './network-canonical.ts';
import { signNetworkMessage, type NetworkSignedEnvelope } from './network-execution.ts';
import { NetworkRegistryStore, NetworkRegistryError } from './network-registry.ts';

export const NETWORK_CANCEL_DOMAIN='heliopause-network-cancel-v1';

/** A writer may reduce one exact issued authority. Never cancels resources or unlocks a fence. */
export function issueDurableNetworkCancellation(store:NetworkRegistryStore,transactionId:string,authorizationHash:string,key:KeyObject,actor:string,now=Date.now()):NetworkSignedEnvelope {
  return store.executionTransaction(state=>{
    const record=state.records.find(r=>r.transactionId===transactionId&&r.authorizationHash===authorizationHash);
    if(!record) throw new NetworkRegistryError('exact issued execution not found',404);
    if(record.cancellation) return record.cancellation;
    if(record.state==='settled'||state.fence?.transactionId!==transactionId||state.fence.authorizationHash!==authorizationHash) throw new NetworkRegistryError('execution already settled or fence mismatch',409);
    if(!/^[A-Za-z0-9_.-]{1,64}$/.test(actor)||!Number.isSafeInteger(now)||now<1) throw new NetworkRegistryError('invalid cancellation principal or time',400);
    const envelope=signNetworkMessage(NETWORK_CANCEL_DOMAIN,{
      schemaVersion:1,transactionId,fenceId:record.fenceId,target:record.target,journalId:record.journalId,
      authorizationHash,artifactHash:record.artifactHash,registryRevision:record.registryRevision,
      requestedAt:now,requestedBy:actor,authorization:record.authorization,
    },key);
    if(Buffer.from(envelope.payload,'base64url').length>128*1024) throw new NetworkRegistryError('legacy authority exceeds cancellation payload limit; retain fence',413);
    record.cancellation=envelope;
    record.cancelStatus='requested';
    record.audit.push({action:'cancel-requested',actor,at:now,reason:'exact authority restriction; Agent acknowledgment required'});record.audit=record.audit.slice(-32);
    // Same Registry replace as the issued record/fence; nothing is returned before persistence.
    return record.cancellation;
  });
}

export const cancellationHash=(envelope:NetworkSignedEnvelope)=>networkDigest(JSON.parse(Buffer.from(envelope.payload,'base64url').toString()));
