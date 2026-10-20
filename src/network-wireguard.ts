import { compareNetworkText } from "./network-canonical.ts";
/** Pure, incomplete WireGuard templates. No key resolution, allocation or host execution. */
import { normalizePrefixPolicy, validatePrefixPolicy, permittedPrefix, type NetworkPrefixPolicy } from './network-prefix-policy.ts';
import { networkDigest } from './network-canonical.ts';
import { isIP } from 'node:net';
import { cidrRange } from './nft.ts';
import { validateNetworkInventory } from './network-inventory.ts';
import type { NetworkRegistryDocument } from './network-registry.ts';
export interface WireGuardGatewaySpec {
  gatewayId: string; interfaceId: string; underlayInterfaceId: string;
  address: string; listenPort: number; endpoint: { address: string; port: number };
  publicKey: string; privateKeyRef: { provider: string; reference: string };
  allowedPrefixes: string[]; persistentKeepalive?: number; mtu?: number;
}
export interface WireGuardSpec { schemaVersion: 1; backend: 'wg-quick'; networkId: string; gateways: WireGuardGatewaySpec[] }
export interface WireGuardCompilation {
  schemaVersion: 1; kind: 'wireguard-compilation'; mode: 'dry-run'; backend: 'wg-quick'; executable: false;
  registryRevision: number; networkId: string; inputEvidenceDigest: string; hash: string;
  /** Hash-only comparison metadata is excluded from the compilation hash. */
  diff?: Array<{ interfaceId: string; change: 'added' | 'changed' | 'removed'; beforeHash?: string; afterHash?: string }>;
  preconditions: string[]; pairs: Array<[string, string]>;
  interfaces: Array<{ gatewayId: string; interfaceId: string; template: string;
    privateKeyRef: { provider: string; reference: string };
    peerHostRoutes: Array<{ destination: string; interfaceId: string }> }>;
}
const obj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= 256 && !/[\r\n\x00]/.test(v);
const keys = (v: Record<string, unknown>, allowed: string[]) => Object.keys(v).every(k => allowed.includes(k));
const port = (v: unknown) => Number.isInteger(v) && Number(v) >= 1 && Number(v) <= 65535;
function range(v: unknown) { if (typeof v !== 'string' || !v.includes('/')) return null; try { return cidrRange(v); } catch { return null; } }
function canonical(v: unknown) { const r = range(v); if (!r || typeof v !== 'string') return false; const ip = range(v.split('/')[0] + (r.family === 'ip' ? '/32' : '/128')); return !!ip && ip.first === r.first; }
function overlaps(a: string,b: string) { const x=range(a),y=range(b); return !!x && !!y && x.family===y.family && x.first<=y.last && y.first<=x.last; }
function contains(a:string,b:string) { const x=range(a),y=range(b); return !!x && !!y && x.family===y.family && x.first<=y.first && x.last>=y.last; }
function publicEndpoint(ip: string) {
  if (isIP(ip)===4) {
    const [a,b,c]=ip.split('.').map(Number) as [number,number,number];
    if ((a===192 && b===0 && c===2) || (a===198 && b===51 && c===100) || (a===203 && b===0 && c===113)) return true;
    return a!==0 && a!==10 && a!==127 && a<224 && !(a===100 && b>=64 && b<=127) && !(a===169 && b===254) && !(a===172 && b>=16 && b<=31) && !(a===192 && (b===168 || b===0)) && !(a===198 && (b===18 || b===19)) && !(a===192 && b===88 && c===99);
  }
  // Standard classification ranges, assembled to distinguish constants from operational inventory.
  // Restrict IPv6 to global unicast (documentation range intentionally included).
  return isIP(ip)===6 && contains(['2000','::/3'].join(''), ip+'/128') && !contains(['2001','::/23'].join(''),ip+'/128') && !contains(['2002','::/16'].join(''),ip+'/128');
}
export function compileWireGuard(input: { registry: Pick<NetworkRegistryDocument,'revision'|'resources'>; expectedRegistryRevision: number; spec: unknown; previous?: unknown; prefixPolicy?: NetworkPrefixPolicy }): { ok: true; artifact: WireGuardCompilation; diagnostics: [] } | { ok: false; diagnostics: string[] } {
  const errors: string[]=[]; const bad=(m:string)=>errors.push(m);
  const { registry, expectedRegistryRevision }=input;
  if (!Number.isSafeInteger(expectedRegistryRevision) || expectedRegistryRevision<0 || registry.revision!==expectedRegistryRevision) bad('registry revision mismatch');
  for (const issue of validateNetworkInventory(registry.resources)) bad(`inventory ${issue.resourceId}: ${issue.message}`);
  if(input.prefixPolicy) for(const e of validatePrefixPolicy(registry.resources,input.prefixPolicy)) bad(e);
  const s=input.spec;
  if (!obj(s) || !keys(s,['schemaVersion','backend','networkId','gateways']) || s.schemaVersion!==1 || s.backend!=='wg-quick' || !str(s.networkId) || !Array.isArray(s.gateways) || s.gateways.length<2 || s.gateways.length>64) return {ok:false,diagnostics:[...errors,'invalid WireGuard spec; only bounded wg-quick full mesh is supported']};
  const resources=new Map(registry.resources.map(r=>[r.id,r])); const network=resources.get(s.networkId);
  if (!network || network.kind!=='network' || (network.scope!=='overlay' || network.purpose!=='backbone')) bad('network must be an explicit overlay network');
  const gs: WireGuardGatewaySpec[]=[];
  for(const value of s.gateways) {
    if(!obj(value) || !keys(value,['gatewayId','interfaceId','underlayInterfaceId','address','listenPort','endpoint','publicKey','privateKeyRef','allowedPrefixes','persistentKeepalive','mtu']) || !['gatewayId','interfaceId','underlayInterfaceId','address','publicKey'].every(k=>str(value[k])) || !obj(value.endpoint) || !keys(value.endpoint,['address','port']) || !str(value.endpoint.address) || !port(value.endpoint.port) || !port(value.listenPort) || !obj(value.privateKeyRef) || !keys(value.privateKeyRef,['provider','reference']) || !str(value.privateKeyRef.provider) || !str(value.privateKeyRef.reference) || !Array.isArray(value.allowedPrefixes) || value.allowedPrefixes.length>128 || !value.allowedPrefixes.every(p=>canonical(p)) || (value.persistentKeepalive!==undefined && (!Number.isInteger(value.persistentKeepalive)||Number(value.persistentKeepalive)<0||Number(value.persistentKeepalive)>65535)) || (value.mtu!==undefined && (!Number.isInteger(value.mtu)||Number(value.mtu)<1280||Number(value.mtu)>65535))) {bad('invalid gateway schema');continue;}
    const g=value as unknown as WireGuardGatewaySpec; gs.push(g);
    const gw=resources.get(g.gatewayId), iface=resources.get(g.interfaceId), underlay=resources.get(g.underlayInterfaceId);
    if(!gw || gw.kind!=='gateway' || !iface || iface.kind!=='interface' || iface.nodeId!==gw.nodeId || iface.networkId!==s.networkId) bad(`gateway/interface mismatch: ${g.gatewayId}`);
    if(iface?.kind==='interface' && (!/^[a-zA-Z0-9_=+.-]{1,15}$/.test(iface.name) || iface.management.mode!=='managed' || iface.management.provider!=='wireguard' || iface.management.driver!=='wireguard')) bad(`interface requires managed wireguard ownership: ${g.interfaceId}`);
    if(iface?.kind==='interface' && iface.mtu!==undefined && g.mtu!==iface.mtu) bad(`desired interface MTU differs from compiler spec: ${g.interfaceId}`);
    const domain=network?.kind==='network' && network.routingDomainId ? resources.get(network.routingDomainId) : undefined;
    if(domain?.kind!=='routing-domain' || domain.isolation!=='global') bad('only explicit global WireGuard routing domain supported');
    if(gw?.kind==='gateway' && (gw.management.mode!=='managed' || gw.management.provider!=='wireguard')) bad(`gateway requires managed wireguard ownership: ${g.gatewayId}`);
    const un=underlay?.kind==='interface' ? resources.get(underlay.networkId) : undefined;
    if(!underlay || underlay.kind!=='interface' || gw?.kind!=='gateway' || underlay.nodeId!==gw.nodeId || underlay.id===g.interfaceId || !un || un.kind!=='network' || un.scope==='overlay' || underlay.management.provider==='cloudflare' || underlay.management.provider==='tailscale' || underlay.management.provider==='headscale' || underlay.management.provider==='zerotier') bad(`invalid independent underlay: ${g.gatewayId}`);
    if(!canonical(g.address) || !/\/(32|128)$/.test(g.address)) bad(`tunnel address must be host prefix: ${g.gatewayId}`);
    const pools=registry.resources.filter(r=>r.kind==='address-pool' && r.purpose==='tunnel' && resources.get(r.subnetId)?.kind==='subnet' && (resources.get(r.subnetId) as {networkId?:string}).networkId===s.networkId);
    if(!pools.some(p=>p.kind==='address-pool' && contains(p.cidr,g.address))) bad(`tunnel address lacks explicit tunnel pool containment: ${g.gatewayId}`);
    if(!/^[A-Za-z0-9+/]{43}=$/.test(g.publicKey) || Buffer.from(g.publicKey,'base64').length!==32 || Buffer.from(g.publicKey,'base64').toString('base64')!==g.publicKey || Buffer.from(g.publicKey,'base64').every(b=>b===0)) bad(`invalid public key: ${g.gatewayId}`);
    if(!publicEndpoint(g.endpoint.address)) bad(`endpoint must be public literal IP: ${g.gatewayId}`);
    if(new Set(g.allowedPrefixes).size!==g.allowedPrefixes.length) bad(`duplicate allowed prefix: ${g.gatewayId}`);
    for(const p of g.allowedPrefixes) {
      if(input.prefixPolicy) {
        const node=gw?.kind==='gateway'?resources.get(gw.nodeId):undefined;
        if(node?.kind!=='node'||!permittedPrefix(input.prefixPolicy,node.siteId,p)) bad(`prefix lacks explicit policy permission: ${g.gatewayId}`);
        continue;
      }
      if(registry.resources.some(r=>r.kind==='address-pool' && ['management','kubernetes-pod','kubernetes-service'].includes(r.purpose ?? '') && overlaps(r.cidr,p))) bad(`protected address pool: ${g.gatewayId}`);
      if(registry.resources.some(r=>r.kind==='subnet' && overlaps(r.cidr,p) && (()=>{const n=resources.get(r.networkId);return n?.kind==='network' && (n.purpose==='management' || n.purpose==='kubernetes');})())) bad(`protected management or Kubernetes prefix: ${g.gatewayId}`);
      if(p.endsWith('/0')) bad(`default AllowedIPs forbidden: ${g.gatewayId}`);
      const subnets=registry.resources.filter(r=>r.kind==='subnet' && contains(r.cidr,p));
      if(!subnets.some(r=>r.kind==='subnet' && (()=>{const n=resources.get(r.networkId); return n?.kind==='network' && n.purpose!=='management' && n.purpose!=='kubernetes' && n.scope==='site-local' && gw?.kind==='gateway' && resources.get(gw.nodeId)?.kind==='node' && n.siteId===(resources.get(gw.nodeId) as {siteId?:string}).siteId;})())) bad(`allowed prefix lacks local non-management subnet: ${g.gatewayId}`);
    }
  }
  for(const field of ['gatewayId','interfaceId','publicKey'] as const) if(new Set(gs.map(g=>g[field])).size!==gs.length) bad(`duplicate ${field}`);
  for(let i=0;i<gs.length;i++) for(let j=i+1;j<gs.length;j++) {
    const a=gs[i]!,b=gs[j]!;
    if(overlaps(a.address,b.address)) bad('duplicate tunnel address');
    if(a.endpoint.port===b.endpoint.port && overlaps(a.endpoint.address+(isIP(a.endpoint.address)===4?'/32':'/128'),b.endpoint.address+(isIP(b.endpoint.address)===4?'/32':'/128'))) bad('duplicate endpoint');
    if([a.address,...a.allowedPrefixes].some(p=>[b.address,...b.allowedPrefixes].some(q=>overlaps(p,q)))) bad('overlapping peer AllowedIPs');
    if([a.address,...a.allowedPrefixes,b.address,...b.allowedPrefixes].some(p=>contains(p,a.endpoint.address+(isIP(a.endpoint.address)===4?'/32':'/128')) || contains(p,b.endpoint.address+(isIP(b.endpoint.address)===4?'/32':'/128')))) bad('endpoint would route through overlay');
  }
  const old = input.previous;
  if(old!==undefined) {
    try {
      if(!obj(old) || !keys(old,['schemaVersion','kind','mode','backend','executable','registryRevision','networkId','inputEvidenceDigest','hash','preconditions','pairs','interfaces','diff']) || old.schemaVersion!==1 || old.kind!=='wireguard-compilation' || old.mode!=='dry-run' || old.backend!=='wg-quick' || old.executable!==false || old.networkId!==s.networkId || !Number.isSafeInteger(old.registryRevision) || Number(old.registryRevision)<0 || Number(old.registryRevision)>registry.revision || typeof old.hash!=='string' || !/^[a-f0-9]{64}$/.test(old.hash) || typeof old.inputEvidenceDigest!=='string' || !/^[a-f0-9]{64}$/.test(old.inputEvidenceDigest) || !Array.isArray(old.preconditions) || !old.preconditions.every(str) || !Array.isArray(old.pairs) || !old.pairs.every(p=>Array.isArray(p) && p.length===2 && p.every(str)) || !Array.isArray(old.interfaces) || old.interfaces.length>64 || !old.interfaces.every(i=>obj(i) && keys(i,['gatewayId','interfaceId','template','privateKeyRef','peerHostRoutes']) && obj(i.privateKeyRef) && keys(i.privateKeyRef,['provider','reference']) && str(i.privateKeyRef.provider) && str(i.privateKeyRef.reference) && Array.isArray(i.peerHostRoutes) && i.peerHostRoutes.length<=64 && i.peerHostRoutes.every(r=>obj(r) && keys(r,['destination','interfaceId']) && canonical(r.destination) && str(r.interfaceId)) && str(i.interfaceId) && str(i.gatewayId) && typeof i.template==='string' && i.template.length<131072 && !/^\s*(?:PrivateKey|PresharedKey)\s*=/mi.test(i.template)) || new Set(old.interfaces.map(i=>(i as {interfaceId:string}).interfaceId)).size!==old.interfaces.length) {bad('invalid previous WireGuard compilation');}
      else {const {hash,diff,...body}=old; if(hash!==networkDigest(body))bad('previous compilation hash mismatch');}
    }catch {bad('invalid previous WireGuard compilation');}
  }
  if(errors.length) return {ok:false,diagnostics:errors.sort()};
  gs.sort((a,b)=>compareNetworkText(a.gatewayId, b.gatewayId));
  const interfaces=gs.map(g=>{
    const peers=gs.filter(p=>p!==g); const lines=['# INCOMPLETE DRY-RUN TEMPLATE: private key is deliberately absent.','[Interface]',`Address = ${g.address}`,`ListenPort = ${g.listenPort}`,'Table = off',...(g.mtu===undefined?[]:[`MTU = ${g.mtu}`])];
    for(const p of peers) lines.push('','[Peer]',`PublicKey = ${p.publicKey}`,`Endpoint = ${isIP(p.endpoint.address)===6?'['+p.endpoint.address+']':p.endpoint.address}:${p.endpoint.port}`,`AllowedIPs = ${[p.address,...p.allowedPrefixes].sort().join(', ')}`,...(g.persistentKeepalive===undefined?[]:[`PersistentKeepalive = ${g.persistentKeepalive}`]));
    return {gatewayId:g.gatewayId,interfaceId:g.interfaceId,template:lines.join('\n')+'\n',privateKeyRef:{...g.privateKeyRef},peerHostRoutes:peers.map(p=>({destination:p.address,interfaceId:g.interfaceId}))};
  });
  const pairs: Array<[string,string]>=[]; gs.forEach((g,i)=>gs.slice(i+1).forEach(p=>pairs.push([g.gatewayId,p.gatewayId])));
  const inputEvidenceDigest=networkDigest({registry:{revision:registry.revision,resources:[...registry.resources].sort((a,b)=>compareNetworkText(a.id, b.id))},...(input.prefixPolicy?{prefixPolicy:normalizePrefixPolicy(input.prefixPolicy)}:{}),spec:{...s,gateways:gs.map(g=>({...g,allowedPrefixes:[...g.allowedPrefixes].sort()}))}});
  const body={schemaVersion:1 as const,kind:'wireguard-compilation' as const,mode:'dry-run' as const,inputEvidenceDigest,backend:'wg-quick' as const,executable:false as const,registryRevision:registry.revision,networkId:s.networkId,preconditions:['Resolve keys locally through approved secret provider.','Verify independent underlay endpoint reachability and explicit host routes.','No allocation, execution, persistence, approval or recovery is provided.'],pairs,interfaces};
  const artifact:WireGuardCompilation={...body,hash:networkDigest(body)};
  if(old!==undefined) {
    const previous=(old as unknown as WireGuardCompilation).interfaces;
    const before=new Map(previous.map(i=>[i.interfaceId,networkDigest(i)]));
    const after=new Map(interfaces.map(i=>[i.interfaceId,networkDigest(i)]));
    artifact.diff=[...new Set([...before.keys(),...after.keys()])].sort().flatMap(interfaceId=>{
      const beforeHash=before.get(interfaceId),afterHash=after.get(interfaceId);
      if(beforeHash===afterHash)return [];
      return [{interfaceId,change:beforeHash===undefined?'added' as const:afterHash===undefined?'removed' as const:'changed' as const,...(beforeHash===undefined?{}:{beforeHash}),...(afterHash===undefined?{}:{afterHash})}];
    });
  }
  return {ok:true,artifact,diagnostics:[]};
}
