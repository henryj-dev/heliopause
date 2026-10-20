import type { NetworkObservationRecord } from './network-observation.ts';
import type { NetworkChangeSet } from './network-change-set.ts';
/** Single-host writer authorization. NetworkChangeSet remains review-only. */
import { sign, verify, createPublicKey, type KeyObject } from 'node:crypto';
import { artifactSigningKeyId } from './artifact-signature.ts';
import { canonicalNetworkJson, networkDigest } from './network-canonical.ts';
import { claimForPublish, settle, type ApprovalState } from './approval.ts';
import { NetworkRegistryStore } from './network-registry.ts';
import { prefixContains } from './network-prefix-policy.ts';

export const NETWORK_EXECUTION_DOMAIN = 'heliopause-network-execution-v1';
export const NETWORK_CONFIRM_DOMAIN = 'heliopause-network-confirm-v1';
export const NETWORK_VERIFY_DOMAIN = 'heliopause-network-verification-v1';
export interface NetworkWireGuardOperation {
  driver: 'linux-wireguard-v1'; interfaceId: string; interfaceName: string;
  address: string; mtu: number; listenPort: number; secretRef: string; publicKey: string;
  peers: Array<{ publicKey: string; endpoint: string; allowedIps: string[] }>;
  routes: string[];
}
export interface NetworkExecutionDraft {
  schemaVersion: 1; transactionId: string;
  target: { source: string; host: string; nodeId: string };
  registryRevision: number; resources: Array<{ id: string; generation: number }>;
  desiredDigest: string; reviewHash: string; artifactHash: string;
  observation: { digest: string; collectedAt: number; maxAgeMs: number };
  localPrecondition: string;
  operation: NetworkWireGuardOperation;
  issuedAt: number; expiresAt: number; rollbackAt: number;
}
export interface NetworkSignedEnvelope { version: 'heliopause-ed25519-v1'; algorithm: 'Ed25519'; keyId: string; payload: string; signature: string }
const frame = (value: string) => { const data=Buffer.from(value);const size=Buffer.alloc(4);size.writeUInt32BE(data.length);return Buffer.concat([size,data]); };
/** Domain separation reuses host-artifact framing and SPKI key identities, not its firewall payload. */
export function signNetworkMessage(domain: string, payload: unknown, key: KeyObject): NetworkSignedEnvelope {
  const keyId=artifactSigningKeyId(createPublicKey(key)), bytes=canonicalNetworkJson(payload);
  return {version:'heliopause-ed25519-v1',algorithm:'Ed25519',keyId,payload:Buffer.from(bytes).toString('base64url'),signature:sign(null,Buffer.concat([frame(domain),frame(keyId),frame(bytes)]),key).toString('base64url')};
}
export const networkExecutionHash = (draft: NetworkExecutionDraft) => 'sha256:'+networkDigest(draft);
/** Caller supplies authenticated principals to the existing propose/approve APIs first. */
export function authorizeNetworkExecution(store: NetworkRegistryStore, approvals: ApprovalState, draft: NetworkExecutionDraft, by: string, key: KeyObject, evidence: { observation: NetworkObservationRecord; review: NetworkChangeSet }, now=new Date()): NetworkSignedEnvelope {
  const hash=networkExecutionHash(draft);
  if (evidence.observation.host!==draft.target.host || evidence.observation.source!==draft.target.source || networkDigest(evidence.observation)!==draft.observation.digest || Date.parse(evidence.observation.report.completedAt)!==draft.observation.collectedAt || evidence.review.contentHash!==draft.reviewHash || evidence.review.registryRevision!==draft.registryRevision || evidence.review.desiredDigest!==draft.desiredDigest || evidence.review.executable!==false) throw new Error('review/observation commitment mismatch');
  const plan=claimForPublish(approvals,{hash,by,now});
  // This first writer supports two-person policy only; solo/OTP and break-glass stay firewall-only.
  if(!plan.approval || plan.approval.solo || plan.proposedBy===plan.approval.by) throw new Error('network execution requires two-person approval');
  const at=now.getTime();
  if(draft.schemaVersion!==1 || !/^[a-f0-9]{32}$/.test(draft.transactionId) || draft.issuedAt>at || at-draft.issuedAt>30000 || draft.expiresAt<=at || draft.expiresAt-draft.issuedAt>60000 || draft.rollbackAt<=draft.expiresAt || draft.rollbackAt-draft.issuedAt>180000) throw new Error('invalid execution validity window');
  if(draft.operation.interfaceName!=='hp'+draft.transactionId.slice(0,12)) throw new Error('interface name must bind transaction identity');
  if(draft.artifactHash!==networkDigest(draft.operation)) throw new Error('artifact hash mismatch');
  if(draft.observation.maxAgeMs<1 || draft.observation.maxAgeMs>600000 || draft.observation.collectedAt>at || at-draft.observation.collectedAt>draft.observation.maxAgeMs) throw new Error('stale observation');
  return store.fenceExecution(draft.registryRevision,draft.transactionId,registry=>{
    if(networkDigest([...registry.resources].sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0).map(r=>({resourceId:r.id,generation:r.generation,digest:networkDigest(r)})))!==draft.desiredDigest) throw new Error('desired digest mismatch');
    if(!draft.resources.length || new Set(draft.resources.map(r=>r.id)).size!==draft.resources.length || draft.resources.some(expected=>registry.resources.find(r=>r.id===expected.id)?.generation!==expected.generation)) throw new Error('resource generation mismatch');
    const op=draft.operation, iface=registry.resources.find(r=>r.id===op.interfaceId);
    const node=registry.resources.find(r=>r.id===draft.target.nodeId);
    if(node?.kind!=='node'||iface?.kind!=='interface'||iface.nodeId!==node.id||iface.name!==op.interfaceName||iface.mtu!==op.mtu||iface.management.mode!=='managed'||iface.management.provider!=='wireguard'||iface.management.driver!=='wg-quick'||!draft.resources.some(r=>r.id===iface.id)) throw new Error('interface ownership mismatch');
    const net=registry.resources.find(r=>r.id===iface.networkId);
    if(net?.kind!=='network'||net.purpose!=='backbone'||!registry.resources.some(r=>r.kind==='subnet'&&r.networkId===net.id&&prefixContains(r.cidr,op.address))) throw new Error('address outside backbone');
    for(const dst of op.routes) if(!registry.resources.some(r=>r.kind==='route'&&r.interfaceId===iface.id&&r.destination===dst&&r.table===254&&r.management.mode==='managed'&&r.management.provider==='wireguard'&&r.management.driver==='wg-quick'&&r.nextHop===null&&r.protocol==='static'&&r.metric===42760&&r.preferredSource===undefined&&(r.routeType===undefined||r.routeType==='unicast')&&draft.resources.some(e=>e.id===r.id))) throw new Error('host route ownership mismatch');
    const envelope=signNetworkMessage(NETWORK_EXECUTION_DOMAIN,{...draft,approval:{mode:'two-person',planHash:hash,proposedBy:plan.proposedBy,approvedBy:plan.approval!.by,approvedAt:Date.parse(plan.approval!.at)}},key);
    settle(approvals,hash);
    return envelope;
  });
}

/** Explicit confirm issuance after the original approval was consumed, using an independent ring. */
export function confirmNetworkExecution(authorization: NetworkSignedEnvelope, receipt: NetworkSignedEnvelope, verifierKeys: readonly KeyObject[], managerKey: KeyObject, now=Date.now()): NetworkSignedEnvelope {
  const a=JSON.parse(Buffer.from(authorization.payload,'base64url').toString());
  if(receipt.version!=='heliopause-ed25519-v1'||receipt.algorithm!=='Ed25519'||receipt.payload.length>180000||receipt.signature.length!==86) throw new Error('invalid verifier envelope');
  const publicKey=verifierKeys.find(k=>artifactSigningKeyId(k)===receipt.keyId);
  const bytes=Buffer.from(receipt.payload,'base64url');
  if(!publicKey||!verify(null,Buffer.concat([frame(NETWORK_VERIFY_DOMAIN),frame(receipt.keyId),frame(bytes.toString())]),publicKey,Buffer.from(receipt.signature,'base64url'))) throw new Error('untrusted verifier signature');
  const v=JSON.parse(bytes.toString());
  const checks=['interface','address','route','handshake','fib','forward','reverse','management','protected'];
  if(canonicalNetworkJson(v)!==bytes.toString()||v.transactionId!==a.transactionId||v.authorizationHash!==networkDigest(a)||v.artifactHash!==a.artifactHash||!Number.isSafeInteger(v.observedAt)||v.observedAt<a.issuedAt||v.observedAt>now||now-v.observedAt>10000||!Number.isSafeInteger(v.expiresAt)||v.expiresAt<=now||v.expiresAt>a.rollbackAt||now>=a.rollbackAt||!v.checks||Object.keys(v.checks).length!==checks.length||checks.some(c=>v.checks[c]!==true)||!/^[a-f0-9]{32}$/.test(v.nonce)) throw new Error('independent verification failed or expired');
  return signNetworkMessage(NETWORK_CONFIRM_DOMAIN,{transactionId:a.transactionId,authorizationHash:networkDigest(a),artifactHash:a.artifactHash,expiresAt:Math.min(v.expiresAt,a.rollbackAt),verification:receipt},managerKey);
}
