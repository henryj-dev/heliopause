import { compareNetworkText } from "./network-canonical.ts";
/** Declarative export permissions. Evidence references are not authenticated approvals or execution authority. */
import { isIP } from 'node:net';
import { cidrRange } from './nft.ts';
import type { NetworkInventoryResource } from './network-inventory.ts';
import { canonicalNetworkJson } from './network-canonical.ts';
export interface PrefixPermission {
  id: string; resourceId: string; siteId: string; prefix: string;
  role: 'infrastructure' | 'pod' | 'service-vip' | 'backbone';
  owner: { nodeId: string; provider: string; driver: string };
  evidence?: { source: string; host: string; collectionId: string; digest: string; observedAt: string };
  service?: { cluster: string; namespace: string; name: string; uid: string; ready: boolean; exposureRef: string; advertisement: 'originate' | 'relay' };
}
export interface NetworkPrefixPolicy { schemaVersion: 1; evaluatedAt: number; permissions: PrefixPermission[] }
export const prefixContains = (outer: string, inner: string) => {
  const a = cidrRange(outer), b = cidrRange(inner);
  return !!a && !!b && a.family === b.family && a.first <= b.first && a.last >= b.last;
};
export const prefixOverlaps = (left: string, right: string) => {
  const a = cidrRange(left), b = cidrRange(right);
  return !!a && !!b && a.family === b.family && a.first <= b.last && b.first <= a.last;
};
export const hostPrefix = (address: string) => address + (isIP(address) === 6 ? '/128' : '/32');
const text = (v: unknown): v is string => typeof v === 'string' && /^[a-zA-Z0-9_.:/-]{1,256}$/.test(v);
const obj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const exact = (v: Record<string, unknown>, keys: string[]) => Object.keys(v).every(k => keys.includes(k));
export function normalizePrefixPolicy(policy: NetworkPrefixPolicy): NetworkPrefixPolicy {
  return { ...policy, permissions: [...policy.permissions].sort((a,b) => compareNetworkText(canonicalNetworkJson(a), canonicalNetworkJson(b))) };
}
export function validatePrefixPolicy(resources: NetworkInventoryResource[], policy: NetworkPrefixPolicy): string[] {
  const errors = new Set<string>(); const bad = (s: string) => errors.add(s);
  if (!obj(policy) || !exact(policy, ['schemaVersion','evaluatedAt','permissions']) || policy.schemaVersion !== 1 || !Number.isFinite(policy.evaluatedAt) || !Array.isArray(policy.permissions) || policy.permissions.length > 512) return ['invalid prefix policy'];
  const rs = new Map(resources.map(r => [r.id,r])); const seen = new Set<string>();
  const protectedRanges = resources.flatMap(r => {
    if (r.kind === 'address-pool') return [{prefix:r.cidr,role:r.purpose}];
    if (r.kind === 'subnet') { const n=rs.get(r.networkId); if(n?.kind==='network' && n.purpose==='management') return [{prefix:r.cidr,role:'management' as const}]; }
    return [];
  });
  for (const p of policy.permissions) {
    if (!obj(p) || !exact(p,['id','resourceId','siteId','prefix','role','owner','evidence','service']) || ![p.id,p.resourceId,p.siteId].every(text) || typeof p.prefix !== 'string' || !['infrastructure','pod','service-vip','backbone'].includes(p.role) || !obj(p.owner) || !exact(p.owner,['nodeId','provider','driver']) || !Object.values(p.owner).every(text) || !text(p.owner.nodeId) || !text(p.owner.provider) || !text(p.owner.driver)) { bad('invalid prefix permission'); continue; }
    if(seen.has(p.id)) bad('duplicate prefix permission id'); seen.add(p.id);
    const r=rs.get(p.resourceId); const pool=r?.kind==='address-pool'?r:undefined;
    const sub=r?.kind==='subnet'?r:pool?rs.get(pool.subnetId):undefined;
    const net=sub?.kind==='subnet'?rs.get(sub.networkId):undefined; const node=rs.get(p.owner.nodeId);
    const range=cidrRange(p.prefix), addr=cidrRange(p.prefix.split('/')[0]!);
    if(!p.prefix.includes('/') || !range || !addr || range.first!==addr.first || range.bits===0) { bad('unaligned or default policy prefix'); continue; }
    if(!r || !('cidr' in r) || !prefixContains(r.cidr,p.prefix) || net?.kind!=='network' || node?.kind!=='node' || node.siteId!==p.siteId || (net.scope==='site-local' ? net.siteId!==p.siteId : !('siteIds' in net) || !net.siteIds.includes(p.siteId))) bad('prefix permission resource/site/owner mismatch');
    const overlaps=protectedRanges.filter(x=>prefixOverlaps(x.prefix,p.prefix));
    if(overlaps.some(x=>x.role==='management')) bad('management prefix export forbidden');
    if(p.role==='infrastructure' && (net?.kind!=='network' || net.purpose!=='infrastructure' || overlaps.some(x=>x.role==='kubernetes-pod'||x.role==='kubernetes-service'))) bad('infrastructure aggregate covers protected pool');
    if(p.role==='pod' && (!pool || pool.purpose!=='kubernetes-pod' || overlaps.some(x=>x.role==='kubernetes-service'))) bad('pod permission must reference an exact contained pod pool');
    if(p.role==='service-vip' && (!pool || pool.purpose!=='kubernetes-service' || range.bits!==(range.family==='ip'?32:128))) bad('service permission must be a host VIP inside service pool');
    if(p.role==='backbone' && (net?.kind!=='network'||net.purpose!=='backbone'||range.bits!==(range.family==='ip'?32:128))) bad('backbone export limited to explicit host prefixes');
    if(p.role==='pod'||p.role==='service-vip'||p.role==='backbone') {
      const e=p.evidence;
      if(!obj(e)||!exact(e,['source','host','collectionId','digest','observedAt'])||![e.source,e.host,e.collectionId].every(text)||typeof e.digest!=='string'||!/^[a-f0-9]{64}$/.test(e.digest)||typeof e.observedAt!=='string'||!Number.isFinite(Date.parse(e.observedAt))||Date.parse(e.observedAt)>policy.evaluatedAt||policy.evaluatedAt-Date.parse(e.observedAt)>600000) bad('fresh prefix reachability evidence reference required');
    }
    if(p.role==='service-vip') {
      const s=p.service;
      if(!obj(s)||!exact(s,['cluster','namespace','name','uid','ready','exposureRef','advertisement'])||![s.cluster,s.namespace,s.name,s.uid,s.exposureRef].every(text)||s.ready!==true||!['originate','relay'].includes(String(s.advertisement))) bad('ready service identity and explicit exposure reference required');
      // Relaying CNI-originated routes requires a separate redistribution/export design.
      if(s?.advertisement==='relay') bad('CNI-origin relay is unsupported; do not originate it in FRR');
    } else if(p.service!==undefined) bad('service metadata requires service-vip role');
  }
  for(let i=0;i<policy.permissions.length;i++) for(const b of policy.permissions.slice(i+1)) {
    const a=policy.permissions[i]!;
    if(obj(a)&&obj(b)&&typeof a.prefix==='string'&&typeof b.prefix==='string'&&prefixOverlaps(a.prefix,b.prefix)) bad('overlapping advertisement ownership claims');
  }
  return [...errors].sort();
}
export function permittedPrefix(policy: NetworkPrefixPolicy, siteId: string, prefix: string, writer?: {nodeId:string;provider:string;driver:string}): boolean {
  return policy.permissions.some(p=>p.siteId===siteId&&prefixContains(p.prefix,prefix)&&prefixContains(prefix,p.prefix)&&(!writer||(p.owner.nodeId===writer.nodeId&&p.owner.provider===writer.provider&&p.owner.driver===writer.driver)));
}
