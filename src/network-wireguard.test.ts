import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compileWireGuard, type WireGuardSpec } from './network-wireguard.ts';
import type { NetworkInventoryResource } from './network-inventory.ts';
function fixture() {
 const base={owner:'team',generation:1,management:{mode:'managed',provider:'wireguard',driver:'wireguard'} as const};
 const resources:NetworkInventoryResource[]=[{...base,kind:'routing-domain',id:'rd',name:'overlay',isolation:'global'},{...base,kind:'network',id:'overlay',scope:'overlay',siteIds:['s0','s1','s2','s3'],routingDomainId:'rd',purpose:'backbone'},{...base,kind:'subnet',id:'tunsub',networkId:'overlay',cidr:'10.20.0.0/24'},{...base,kind:'address-pool',id:'tunpool',subnetId:'tunsub',cidr:'10.20.0.0/24',allocationAuthority:'operator',purpose:'tunnel'}];
 const gateways:WireGuardSpec['gateways']=[];
 for(let i=0;i<4;i++) {
  resources.push({...base,kind:'site',id:`s${i}`},{...base,kind:'node',id:`n${i}`,siteId:`s${i}`},{...base,kind:'gateway',id:`g${i}`,nodeId:`n${i}`},{...base,kind:'network',id:`u${i}`,scope:'site-local',siteId:`s${i}`,routingDomainId:'rd',purpose:'infrastructure'},{...base,kind:'interface',id:`eth${i}`,nodeId:`n${i}`,networkId:`u${i}`,name:'eth0'},{...base,kind:'interface',id:`wg${i}`,nodeId:`n${i}`,networkId:'overlay',name:'wg0'},{...base,kind:'subnet',id:`lan${i}`,networkId:`u${i}`,cidr:`10.${30+i}.0.0/24`});
  gateways.push({gatewayId:`g${i}`,interfaceId:`wg${i}`,underlayInterfaceId:`eth${i}`,address:`10.20.0.${i+1}/32`,listenPort:51820,endpoint:{address:`203.0.113.${i+1}`,port:51820},publicKey:Buffer.alloc(32,i+1).toString('base64'),privateKeyRef:{provider:'local',reference:`wg-key-${i}`},allowedPrefixes:[`10.${30+i}.0.0/24`]});
 }
 return {registry:{revision:4,resources},expectedRegistryRevision:4,spec:{schemaVersion:1,backend:'wg-quick',networkId:'overlay',gateways} as WireGuardSpec};
}
test('four sites compile six pairs, explicit host routes and incomplete keyless templates',()=>{
 const result=compileWireGuard(fixture()); assert.equal(result.ok,true,JSON.stringify(result)); if(!result.ok)return;
 assert.equal(result.artifact.pairs.length,6); assert.equal(result.artifact.interfaces.length,4);
 const first=result.artifact.interfaces[0]!; assert.equal(first.peerHostRoutes.length,3); assert.equal(first.peerHostRoutes[0]!.destination,'10.20.0.2/32');
 assert.match(first.template,/Table = off/); assert.doesNotMatch(first.template,/PrivateKey\s*=|wg-key-/); assert.match(first.template,/AllowedIPs = 10.20.0.2\/32, 10.31.0.0\/24/);
 assert.equal(result.artifact.executable,false);
});
test('input ordering does not change compiler digest',()=>{const f=fixture(),a=compileWireGuard(f);f.spec.gateways.reverse();f.registry.resources.reverse();assert.deepEqual(compileWireGuard(f),a);});
for(const [name,mutate] of [
 ['stale revision',(f:ReturnType<typeof fixture>)=>{f.expectedRegistryRevision=3;}],
 ['duplicate tunnel IP',(f:ReturnType<typeof fixture>)=>{f.spec.gateways[1]!.address=f.spec.gateways[0]!.address;}],
 ['duplicate public key',(f:ReturnType<typeof fixture>)=>{f.spec.gateways[1]!.publicKey=f.spec.gateways[0]!.publicKey;}],
 ['private endpoint',(f:ReturnType<typeof fixture>)=>{f.spec.gateways[0]!.endpoint.address='192.168.1.1';}],
 ['default route',(f:ReturnType<typeof fixture>)=>{f.spec.gateways[0]!.allowedPrefixes=['0.0.0.0/0'];}],
 ['foreign site prefix',(f:ReturnType<typeof fixture>)=>{f.spec.gateways[0]!.allowedPrefixes=['10.31.0.0/24'];}],
 ['unallocated tunnel',(f:ReturnType<typeof fixture>)=>{f.spec.gateways[0]!.address='10.21.0.1/32';}],
 ['overlay underlay',(f:ReturnType<typeof fixture>)=>{f.spec.gateways[0]!.underlayInterfaceId='wg0';}],
 ['wrong node',(f:ReturnType<typeof fixture>)=>{f.spec.gateways[0]!.interfaceId='wg1';}],
 ['external ownership',(f:ReturnType<typeof fixture>)=>{f.registry.resources.find(r=>r.id==='wg0')!.management={mode:'external',provider:'tailscale'};}],
 ['raw secret',(f:ReturnType<typeof fixture>)=>{Object.assign(f.spec.gateways[0]!,{privateKey:'secret'});}],
 ['unknown backend',(f:ReturnType<typeof fixture>)=>{Object.assign(f.spec,{backend:'wg-setconf'});}],
] as const) test(`reject ${name}`,()=>{const f=fixture();mutate(f);assert.equal(compileWireGuard(f).ok,false);});

for(const address of ['127.0.0.1','169.254.10.1','224.0.0.1','100.64.0.1','::1','fe80::1','ff02::1','fc00::1']) test(`reject unsafe endpoint ${address}`,()=>{const f=fixture();f.spec.gateways[0]!.endpoint.address=address;assert.equal(compileWireGuard(f).ok,false);});
test('IPv6 templates bracket public endpoints and retain /128 host routes',()=>{const f=fixture();for(const x of f.registry.resources)if(x.kind==='subnet' && x.id==='tunsub' || x.kind==='address-pool' && x.id==='tunpool')x.cidr='2001:db8:1::/64';for(let i=0;i<4;i++){f.spec.gateways[i]!.endpoint.address=`2001:db8::${i+1}`;f.spec.gateways[i]!.address=`2001:db8:1::${i+1}/128`;}const r=compileWireGuard(f);assert.equal(r.ok,true);if(r.ok){assert.match(r.artifact.interfaces[0]!.template,/Endpoint = \[2001:db8::2\]:51820/);assert.equal(r.artifact.interfaces[0]!.peerHostRoutes[0]!.destination,'2001:db8:1::2/128');}});
test('documentation endpoint 192.0.2.1 is allowed explicitly',()=>{const f=fixture();f.spec.gateways[0]!.endpoint.address='192.0.2.1';assert.equal(compileWireGuard(f).ok,true);});
test('management subnet cannot be exported even when covered by a local subnet',()=>{const f=fixture();const n=f.registry.resources.find(r=>r.id==='u0')!;if(n.kind==='network' && 'purpose' in n)n.purpose='management';assert.equal(compileWireGuard(f).ok,false);});
test('dry-run hash binds inventory generations and underlay evidence',()=>{
 const f=fixture();const a=compileWireGuard(f);assert.equal(a.ok,true);if(!a.ok)return;assert.equal(a.artifact.mode,'dry-run');
 f.registry.resources.find(r=>r.id==='eth0')!.generation=2;const b=compileWireGuard(f);assert.equal(b.ok,true);if(!b.ok)return;
 assert.notEqual(a.artifact.hash,b.artifact.hash);assert.notEqual(a.artifact.inputEvidenceDigest,b.artifact.inputEvidenceDigest);
});
test('optional previous produces stable hash-only diffs without altering content hash',()=>{
 const f=fixture();const a=compileWireGuard(f);assert.equal(a.ok,true);if(!a.ok)return;
 const same=compileWireGuard({...f,previous:a.artifact});assert.equal(same.ok,true);if(!same.ok)return;assert.deepEqual(same.artifact.diff,[]);assert.equal(same.artifact.hash,a.artifact.hash);
 f.spec.gateways[0]!.listenPort=51821;const b=compileWireGuard({...f,previous:a.artifact});assert.equal(b.ok,true);if(!b.ok)return;
 assert.deepEqual(b.artifact.diff?.map(d=>[d.interfaceId,d.change]),[['wg0','changed']]);assert.match(b.artifact.diff![0]!.beforeHash!,/^[a-f0-9]{64}$/);assert.doesNotMatch(JSON.stringify(b.artifact.diff),/PrivateKey|template|wg-key/);
 const plain=compileWireGuard(f);assert.equal(plain.ok,true);if(plain.ok)assert.equal(b.artifact.hash,plain.artifact.hash);
});
test('previous malformed, tampered, foreign and raw secret artifacts fail closed',()=>{
 const f=fixture(),a=compileWireGuard(f);assert.equal(a.ok,true);if(!a.ok)return;
 for(const previous of [{}, {...a.artifact,hash:'0'.repeat(64)},{...a.artifact,networkId:'other'},{...a.artifact,interfaces:a.artifact.interfaces.map((i,n)=>n===0?{...i,template:'PrivateKey = SECRET\n'}:i)}])assert.equal(compileWireGuard({...f,previous}).ok,false);
});
for(const purpose of ['management','kubernetes-pod','kubernetes-service'] as const)test(`protect ${purpose} pool nested under infrastructure subnet`,()=>{
 const f=fixture();f.registry.resources.push({owner:'team',generation:1,management:{mode:'external',provider:'inventory'},kind:'address-pool',id:'protected',subnetId:'lan0',cidr:'10.30.0.0/25',allocationAuthority:purpose==='management'?'operator':'kubernetes',purpose});
 const r=compileWireGuard(f);assert.equal(r.ok,false);if(!r.ok)assert.ok(r.diagnostics.some(d=>d.includes('protected address pool')));
});
test('previous comparison reports removed and added interfaces by hash only',()=>{
 const f=fixture(),full=compileWireGuard(f);assert.equal(full.ok,true);if(!full.ok)return;
 f.spec.gateways.pop();const reduced=compileWireGuard({...f,previous:full.artifact});assert.equal(reduced.ok,true);if(!reduced.ok)return;
 const removed=reduced.artifact.diff?.find(d=>d.interfaceId==='wg3');assert.equal(removed?.change,'removed');assert.equal(removed?.afterHash,undefined);assert.match(removed!.beforeHash!,/^[a-f0-9]{64}$/);
 const restored=compileWireGuard({...fixture(),previous:reduced.artifact});assert.equal(restored.ok,true);if(!restored.ok)return;
 const added=restored.artifact.diff?.find(d=>d.interfaceId==='wg3');assert.equal(added?.change,'added');assert.equal(added?.beforeHash,undefined);assert.match(added!.afterHash!,/^[a-f0-9]{64}$/);
});

test('equivalent IPv6 endpoint spellings cannot bypass duplicate socket check',()=>{
 const f=fixture();f.spec.gateways[0]!.endpoint.address='2001:db8::1';f.spec.gateways[1]!.endpoint.address='2001:0db8:0:0:0:0:0:1';
 const r=compileWireGuard(f);assert.equal(r.ok,false);if(!r.ok)assert.ok(r.diagnostics.includes('duplicate endpoint'));
});
