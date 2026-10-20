import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {networkLabInput,labPrefixEvidence} from '../examples/network-lab.ts';
import {validateNetworkInventory} from './network-inventory.ts';
import {NetworkRegistryStore} from './network-registry.ts';
import {matchNetworkInventory} from './network-matching.ts';
import {validatePrefixPolicy} from './network-prefix-policy.ts';
import {compileWireGuard} from './network-wireguard.ts';
import {compileFrr} from './network-frr.ts';
import {buildNetworkChangeSet} from './network-change-set.ts';
const codes=(input:ReturnType<typeof networkLabInput>)=>buildNetworkChangeSet(input).blockers.map(b=>b.code);
test('MTU already modeled: IPv6 minimum, omission, bounds and unknown schema fields fail closed',()=>{
  const f=networkLabInput();assert.deepEqual(validateNetworkInventory(f.registry.resources),[]);
  const iface=f.registry.resources.find(r=>r.id==='wg0')!;
  Object.assign(iface,{mtu:67});assert.ok(validateNetworkInventory(f.registry.resources).some(e=>e.message.includes('mtu')));
  Object.assign(iface,{mtu:1000});f.registry.resources.push({id:'v6',kind:'subnet',networkId:'primary',cidr:'2001:db8::/64',owner:'lab',generation:1,management:{mode:'external',provider:'lab'}});
  assert.ok(validateNetworkInventory(f.registry.resources).some(e=>e.message.includes('IPv6')));
  if(iface.kind==='interface')delete iface.mtu;
  assert.deepEqual(validateNetworkInventory(f.registry.resources),[]);
  Object.assign(iface,{mttu:1420});assert.ok(validateNetworkInventory(f.registry.resources).some(e=>e.message.includes('unknown resource')));
});
test('registry MTU mutation advances generation and preserves legacy resources',()=>{
  const f=networkLabInput(),dir=mkdtempSync(join(tmpdir(),'hp5-reg-'));
  try{const store=new NetworkRegistryStore(join(dir,'registry.json'));const first=store.mutate(0,'lab',{action:'replace',resources:f.registry.resources});const iface=first.resources.find(r=>r.id==='wg0')!;
    const next=store.mutate(first.revision,'lab',{action:'update',id:iface.id,resource:{...iface,mtu:1380}});
    assert.equal(next.resources.find(r=>r.id==='wg0')!.generation,2);assert.equal(next.revision,2);
  }finally{rmSync(dir,{recursive:true,force:true});}
});
test('route next hop, metric, preferred source and protocol are compared without inventing defaults',()=>{
  const f=networkLabInput(),r=f.registry.resources.find(r=>r.id==='route-p-0-1')!;
  const row=f.observations[0]!.report.observations.routes4!.data![0]!;
  const status=()=>matchNetworkInventory(f).matches.find(m=>m.resourceId===r.id)!;
  assert.equal(status().status,'matched');
  row.gateway='198.51.100.9';assert.equal(status().status,'different');
  Object.assign(r,{nextHop:'198.51.100.9',metric:20,preferredSource:'198.51.100.1'});assert.equal(status().status,'unknown');
  row.metric=30;row.prefsrc='198.51.100.1';assert.equal(status().status,'different');row.metric=20;assert.equal(status().status,'matched');
  row.protocol='bgp';assert.equal(status().status,'unknown');assert.equal(status().classification,'external-observation');
  Object.assign(r,{nextHop:'2001:db8::1'});assert.ok(validateNetworkInventory(f.registry.resources).some(e=>e.message.includes('address family')));
});
test('unmodeled gateway cannot claim equality, and ECMP input cannot become a static match',()=>{
  const f=networkLabInput(),route=f.registry.resources.find(r=>r.id==='route-p-0-1')!;
  if(route.kind==='route')delete route.nextHop;
  const row=f.observations[0]!.report.observations.routes4!.data![0]!;row.gateway='198.51.100.9';
  assert.equal(matchNetworkInventory(f).matches.find(m=>m.resourceId===route.id)!.status,'unknown');
  row.multipath=[{gateway:'198.51.100.2'}];assert.equal(matchNetworkInventory(f).matches.find(m=>m.resourceId===route.id)!.status,'unknown');
});
test('unclaimed and explicitly scoped residual observations stay informational, dynamic routes stay external',()=>{
  const f=networkLabInput();f.observations[0]!.report.observations.links!.data!.push({ifindex:9,ifname:'extra0'});
  const get=()=>matchNetworkInventory(f).matches.filter(m=>m.status==='unexpected');
  assert.ok(get().some(m=>m.classification==='unclaimed-observation'));
  f.managedScopes=[{nodeId:'n0',interfaceNames:['extra0']}];assert.ok(get().some(m=>m.classification==='unexpected-managed'));
  f.observations[0]!.report.observations.routes4!.data!.push({dst:'192.0.2.64/27',dev:'extra0',protocol:'bgp'});
  assert.ok(get().some(m=>m.classification==='external-observation'));
  assert.equal(buildNetworkChangeSet(f).operations.some(o=>o.resourceIds.some(id=>id.startsWith('observation:'))),false);
});
test('unified four-site change set composes five bound artifacts and ordered verification dependencies',()=>{
  const f=networkLabInput(),plan=buildNetworkChangeSet(f);
  assert.equal(plan.artifacts.length,5,JSON.stringify(plan.blockers));assert.equal(plan.executable,false);
  assert.equal(plan.artifacts[0]!.registryRevision,1);assert.equal(plan.observationEvidence.length,4);
  assert.ok(plan.artifacts.every(a=>a.desiredDigest===plan.desiredDigest));
  assert.ok(plan.order.indexOf('wireguard:wg0')<plan.order.indexOf('tunnel:wg0:wg1'));
  assert.ok(plan.order.indexOf('tunnel:wg0:wg1')<plan.order.indexOf('frr:n0'));
  assert.ok(plan.order.indexOf('frr:n0')<plan.order.indexOf('forwarding:n0'));
  assert.ok(plan.operations.filter(o=>o.kind==='wireguard').every(o=>o.target?.host.startsWith('lab-host-')));
  assert.ok(plan.operations.filter(o=>o.resourceIds.some(id=>id.startsWith('cf'))).every(o=>o.kind==='verify'||o.kind==='frr'));
  assert.doesNotMatch(JSON.stringify(plan),/PrivateKey\s*=/);
  for(const code of ['underlay-reachability-unverified','external-overlay-unverified','bgp-next-hop-unverified'])assert.ok(plan.blockers.some(b=>b.code===code));
});
test('change set content is independent of input array/object order and presentation metadata',()=>{
  const f=networkLabInput(),a=buildNetworkChangeSet(f);f.id='other';f.generatedAt='presentation only';f.registry.resources.reverse();f.frr.reverse();f.wireguard.gateways.reverse();f.observations=[...f.observations].reverse();f.bindings=[...f.bindings].reverse();f.prefixPolicy!.permissions.reverse();
  for(const s of f.frr){s.peers.reverse();s.exportSubnetIds.reverse();}
  const shuffled=JSON.parse(JSON.stringify(f),(_k,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.entries(v).reverse()):v);
  assert.equal(buildNetworkChangeSet(shuffled).contentHash,a.contentHash);
});
for(const [label,mutate,code] of [
  ['revision',(f:ReturnType<typeof networkLabInput>)=>{f.expectedRegistryRevision=0;},'revision-mismatch'],
  ['generation',(f:ReturnType<typeof networkLabInput>)=>{f.expectedGenerations={wg0:2};},'generation-mismatch'],
  ['wrong BGP peer',(f:ReturnType<typeof networkLabInput>)=>{f.frr[0]!.peers[0]!.address='198.51.100.9';const r=f.registry.resources.find(r=>r.id==='route-p-0-1')!;Object.assign(r,{destination:'198.51.100.9/32'});},'wg-frr-peer-mismatch'],
  ['different AllowedIPs',(f:ReturnType<typeof networkLabInput>)=>{f.wireguard.gateways[1]!.allowedPrefixes=[];},'wg-frr-prefix-mismatch'],
  ['missing secret',(f:ReturnType<typeof networkLabInput>)=>{Object.assign(f.wireguard.gateways[0]!,{privateKeyRef:undefined});},'wireguard-compile'],
  ['artifact commitment',(f:ReturnType<typeof networkLabInput>)=>{f.artifactAssertions=[{targetId:'wireguard',registryRevision:99,desiredDigest:'0'.repeat(64),hash:'0'.repeat(64)}];},'artifact-commitment-mismatch'],
  ['cycle',(f:ReturnType<typeof networkLabInput>)=>{f.operationDependencies=[{resourceId:'wireguard:wg0',dependsOn:'frr:n0'}];},'operation-cycle'],
  ['dependency',(f:ReturnType<typeof networkLabInput>)=>{f.operationDependencies=[{resourceId:'frr:n0',dependsOn:'missing'}];},'missing-operation-dependency'],
  ['external ownership',(f:ReturnType<typeof networkLabInput>)=>{f.registry.resources.find(r=>r.id==='wg0')!.management={mode:'external',provider:'cloudflare'};},'wireguard-compile'],
  ['unavailable collector',(f:ReturnType<typeof networkLabInput>)=>{const r=f.observations[0]!.report;r.observations.addresses={status:'timeout',startedAt:r.startedAt,completedAt:r.completedAt};r.capabilities.addresses={available:false,status:'timeout'};},'collector-unavailable'],
  ['stale',(f:ReturnType<typeof networkLabInput>)=>{f.now+=600001;},'observation-unavailable'],
  ['future',(f:ReturnType<typeof networkLabInput>)=>{f.now-=60001;},'observation-unavailable'],
  ['duplicate',(f:ReturnType<typeof networkLabInput>)=>{f.observations=[...f.observations,f.observations[0]!];},'observation-unavailable'],
  ['cache/relay absent',(f:ReturnType<typeof networkLabInput>)=>{f.observations=[];},'observation-unavailable'],
] as const)test(`unified blocker: ${label}`,()=>{const f=networkLabInput();mutate(f);assert.ok(codes(f).includes(code),JSON.stringify(codes(f)));});
test('explicit pod and service host permissions are shared by WG and FRR; aggregate bypass remains denied',()=>{
  const f=networkLabInput(),policy=f.prefixPolicy!;
  policy.permissions.push({id:'pod',resourceId:'pods0',siteId:'s0',prefix:'192.0.2.32/28',role:'pod',owner:{nodeId:'n0',provider:'native',driver:'frr'},evidence:labPrefixEvidence(f)});
  policy.permissions.push({id:'vip',resourceId:'services0',siteId:'s0',prefix:'192.0.2.50/32',role:'service-vip',owner:{nodeId:'n0',provider:'native',driver:'frr'},evidence:labPrefixEvidence(f),service:{cluster:'lab',namespace:'default',name:'echo',uid:'uid-1',ready:true,exposureRef:'review-1',advertisement:'originate'}});
  assert.deepEqual(validatePrefixPolicy(f.registry.resources,policy),[]);
  f.wireguard.gateways[0]!.allowedPrefixes.push('192.0.2.32/28','192.0.2.50/32');
  f.frr[0]!.exportSubnetIds.push('pods0','services0');
  const w=compileWireGuard({registry:f.registry,expectedRegistryRevision:1,spec:f.wireguard,prefixPolicy:policy});assert.equal(w.ok,true,JSON.stringify(w));
  const r=compileFrr({registry:f.registry,expectedRegistryRevision:1,spec:f.frr[0],prefixPolicy:policy});assert.equal(r.ok,true,JSON.stringify(r));if(r.ok)assert.match(r.artifact.template,/network 192\.0\.2\.50\/32/);
  assert.ok(codes(f).includes('prefix-forwarding-unverified'));
  policy.permissions[0]!.prefix='192.0.2.0/26';policy.permissions[0]!.resourceId='site0';
  assert.ok(validatePrefixPolicy(f.registry.resources,policy).some(e=>e.includes('protected pool')));
});
test('stale pod evidence, service aggregate, not-ready service and conflicting origin owners fail closed',()=>{
  const f=networkLabInput(),policy=f.prefixPolicy!;
  policy.permissions.push({id:'vip',resourceId:'services0',siteId:'s0',prefix:'192.0.2.48/28',role:'service-vip',owner:{nodeId:'n0',provider:'native',driver:'frr'},evidence:{...labPrefixEvidence(f),observedAt:'2025-01-01T00:00:00Z'},service:{cluster:'lab',namespace:'default',name:'echo',uid:'uid-1',ready:false,exposureRef:'review',advertisement:'relay'}});
  const errors=validatePrefixPolicy(f.registry.resources,policy);assert.ok(errors.some(e=>e.includes('host VIP')));assert.ok(errors.some(e=>e.includes('fresh prefix')));assert.ok(errors.some(e=>e.includes('ready service')));assert.ok(errors.some(e=>e.includes('CNI-origin')));
  policy.permissions.push({...policy.permissions[0]!,id:'duplicate-writer',owner:{nodeId:'n0',provider:'cilium',driver:'bgp'}});assert.ok(validatePrefixPolicy(f.registry.resources,policy).some(e=>e.includes('ownership')));
});
test('static route hiding the selected BGP prefix is a writer conflict',()=>{
  const f=networkLabInput();f.registry.resources.push({id:'shadow',owner:'lab',generation:1,kind:'route',interfaceId:'cf0',routingDomainId:'rd',destination:'192.0.2.64/27',table:254,management:{mode:'managed',provider:'native',driver:'static'}});
  assert.ok(codes(f).includes('route-writer-conflict'));
});
test('hash changes bind generations, exact observation evidence and advertisement policy',()=>{
  const a=buildNetworkChangeSet(networkLabInput()).contentHash;
  for(const mutate of [(f:ReturnType<typeof networkLabInput>)=>{f.registry.resources[0]!.generation++;},(f:ReturnType<typeof networkLabInput>)=>{f.observations[0]!.report.collectionId='11111111-1111-4111-8111-111111111111';},(f:ReturnType<typeof networkLabInput>)=>{f.prefixPolicy!.permissions.pop();}]){const f=networkLabInput();mutate(f);assert.notEqual(buildNetworkChangeSet(f).contentHash,a);}
});
test('FRR cannot mix logical domains in one global writer',()=>{
  const f=networkLabInput();f.registry.resources.push({id:'rd-other',kind:'routing-domain',name:'other',isolation:'global',owner:'lab',generation:1,management:{mode:'external',provider:'lab'}});
  const net=f.registry.resources.find(r=>r.id==='secondary')!;Object.assign(net,{routingDomainId:'rd-other'});
  for(const r of f.registry.resources)if(r.kind==='route'&&r.interfaceId.startsWith('cf'))r.routingDomainId='rd-other';
  assert.ok(codes(f).includes('frr-compile'));
});
test('even a currently matched host route cannot acquire a second writer',()=>{
  const f=networkLabInput();f.registry.resources.find(r=>r.id==='route-p-0-1')!.management={mode:'managed',provider:'native',driver:'static'};
  assert.ok(codes(f).includes('route-writer-conflict'));
});
test('a forged prefix observation reference is blocked by the unified source/digest binding',()=>{
  const f=networkLabInput();f.prefixPolicy!.permissions.push({id:'pod',resourceId:'pods0',siteId:'s0',prefix:'192.0.2.32/28',role:'pod',owner:{nodeId:'n0',provider:'native',driver:'frr'},evidence:{...labPrefixEvidence(f),digest:'0'.repeat(64)}});
  assert.ok(codes(f).includes('prefix-evidence-mismatch'));
});
