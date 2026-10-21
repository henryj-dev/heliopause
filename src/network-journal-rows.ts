import { networkDigest } from './network-canonical.ts';
import { NETWORK_CAPACITY_RESULT_DOMAIN } from './network-execution-state.ts';
/** Exact replay union. The raw primary journal remains immutable during emergency reservation. */
export function journalRows(agent:any,identity:any):Record<string,any> {
  const fail=()=>{throw new Error('invalid capacity replay identity');};
  if(!identity||!agent||identity.journalId!==agent.journalId||!['journalId','capacityCancellation journalId'].includes(Object.keys(identity).sort().join(' ')))fail();
  if(!agent.transactions||typeof agent.transactions!=='object'||Array.isArray(agent.transactions))fail();
  const rows={...agent.transactions};
  if(!Object.hasOwn(identity,'capacityCancellation'))return rows;
  if(Buffer.byteLength(JSON.stringify(identity))>512*1024)fail();
  const row=identity.capacityCancellation,a=row?.authorization,r=row?.terminalResult,c=row?.cancellation;
  if(!row||Object.keys(row).sort().join(' ')!=='authorization authorizationHash cancellation history state terminalResult'||!a||!r||!c||!/^[a-f0-9]{32}$/.test(a.transactionId)||a.journalId!==agent.journalId||Object.hasOwn(rows,a.transactionId)||Object.keys(rows).length>=1024||Object.values(rows).some((v:any)=>!['rolled-back','cancelled-before-accept'].includes(v.state)||['bootRestore','before','paths'].some(k=>Object.hasOwn(v,k))))fail();
  if(Object.keys(r).sort().join(' ')!=='artifactHash authorizationHash domain fenceId journalId proof registryRevision schemaVersion sequence state stateHash target transactionId')fail();
  if(row.state!=='cancelled-before-accept'||row.authorizationHash!==networkDigest(a)||r.schemaVersion!==3||r.domain!==NETWORK_CAPACITY_RESULT_DOMAIN||r.state!==row.state||r.authorizationHash!==networkDigest(a)||r.sequence!==agent.terminalSequence+1||!Number.isSafeInteger(r.sequence)||r.sequence>1024||r.sequence<1||r.fenceId!==a.transactionId)fail();
  for(const k of ['transactionId','target','journalId','artifactHash','registryRevision'])if(networkDigest(r[k])!==networkDigest(a[k])||networkDigest(c[k])!==networkDigest(a[k]))fail();
  if(c.authorizationHash!==networkDigest(a)||c.fenceId!==a.transactionId||c.schemaVersion!==1||networkDigest(r.proof)!==networkDigest({cancellationHash:networkDigest(c),acceptancePrevented:true,maintenanceRequired:true}))fail();
  const {stateHash,...committed}=r;if(stateHash!==networkDigest(committed))fail();
  rows[a.transactionId]=row;return rows;
}
