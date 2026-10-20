/** Composition boundary only. No transport, secrets, runtime writer or approval authority. */
import { buildNetworkPlan, type NetworkPlanInput, type NetworkPlanBlocker, type NetworkDependency } from './network-planner.ts';
import { compileWireGuard, type WireGuardCompilation, type WireGuardSpec } from './network-wireguard.ts';
import { compileFrr, type FrrCompilation, type FrrSpec } from './network-frr.ts';
import { networkDigest, canonicalNetworkJson } from './network-canonical.ts';
import { hostPrefix, prefixContains, validatePrefixPolicy, type NetworkPrefixPolicy } from './network-prefix-policy.ts';
import { observationFreshness } from './network-observation.ts';
import type { NetworkInventoryResource } from './network-inventory.ts';
export interface NetworkChangeSetInput extends NetworkPlanInput {
  generatedAt?: string;
  wireguard?: unknown;
  frr?: readonly unknown[];
  prefixPolicy?: NetworkPrefixPolicy;
  expectedGenerations?: Readonly<Record<string, number>>;
  /** Compare externally retained review commitments; artifacts themselves are always rebuilt. */
  artifactAssertions?: readonly { targetId: string; registryRevision: number; desiredDigest: string; hash: string }[];
  operationDependencies?: readonly NetworkDependency[];
}
export interface NetworkChangeOperation {
  id: string; kind: 'interface'|'route'|'wireguard'|'frr'|'verify';
  resourceIds: string[]; target: { nodeId: string; source: string; host: string } | null;
  routingDomainId: string | null; provider: string; driver: string;
  artifactHash: string | null; preconditions: string[]; verification: string[]; recovery: string[];
}
export interface NetworkChangeSet {
  schemaVersion: 1; kind: 'network-change-set'; id: string; generatedAt?: string;
  mode: 'dry-run'; executable: false; registryRevision: number; desiredDigest: string;
  resources: Array<{ resourceId:string;generation:number;digest:string }>;
  observationEvidence: ReturnType<typeof buildNetworkPlan>['evidence'];
  capabilityEvidence: ReturnType<typeof buildNetworkPlan>['capabilities'];
  matchingDigest: string;
  artifacts: Array<{ targetId:string; nodeIds:string[]; registryRevision:number; desiredDigest:string;hash:string;compilation:WireGuardCompilation|FrrCompilation }>;
  operations: NetworkChangeOperation[]; dependencies: NetworkDependency[]; order: string[];
  blockers: NetworkPlanBlocker[]; warnings: string[]; contentHash: string;
}
export function buildNetworkChangeSet(input: NetworkChangeSetInput): NetworkChangeSet {
  const plan=buildNetworkPlan(input);
  if(input.frr!==undefined&&!Array.isArray(input.frr)) throw new Error('FRR specs must be an array');
  const rs=new Map(input.registry.resources.map(r=>[r.id,r]));
  const blockers=[...plan.blockers];
  const block=(resourceId:string,code:string,reason:string)=>blockers.push({resourceId,code,reason});
  const operations: NetworkChangeOperation[]=[];
  const artifacts: NetworkChangeSet['artifacts']=[];
  const dependencies: NetworkDependency[]=[];
  const edge=(resourceId:string,dependsOn:string)=>dependencies.push({resourceId,dependsOn});
  const domain=(resource:NetworkInventoryResource|undefined):string|null=>{
    if(resource?.kind==='interface') {const n=rs.get(resource.networkId);return n?.kind==='network'?n.routingDomainId??null:null;}
    return null;
  };
  const target=(nodeId:string)=>{
    const bs=input.bindings.filter(b=>b.nodeId===nodeId);
    if(bs.length!==1) {block(nodeId,'identity-binding-ambiguous','exactly one trusted source/host binding is required');return null;}
    const b=bs[0]!;
    if(input.bindings.filter(x=>x.source===b.source&&x.host===b.host).length!==1) {block(nodeId,'identity-binding-ambiguous','source/host identity aliases multiple nodes');return null;}
    const reports=input.observations.filter(r=>r.source===b.source&&r.host===b.host);
    const ev=plan.evidence.filter(e=>e.source===b.source&&e.host===b.host);
    if(reports.length!==1||ev.length!==1||observationFreshness(reports[0]!,input.now,input.maxAgeMs)!=='fresh') block(nodeId,'observation-unavailable','fresh unambiguous validated observation evidence is required');
    else {
      for(const collector of ['links','addresses','routes4'] as const) if(reports[0]!.report.observations[collector]?.status!=='success') block(nodeId,'collector-unavailable',`required collector ${collector} is not available`);
    }
    return {nodeId,source:b.source,host:b.host};
  };
  const op=(id:string,kind:NetworkChangeOperation['kind'],nodeId:string,resourceIds:string[],routingDomainId:string|null,provider:string,driver:string,artifactHash:string|null)=>{
    const item={id,kind,resourceIds:[...resourceIds].sort(),target:target(nodeId),routingDomainId,provider,driver,artifactHash,
      preconditions:['Authenticated target and fresh collector evidence required.','Independent management and gateway reachability unverified.'],
      verification:['Verify kernel FIB, source binding and bidirectional packet forwarding.'],
      recovery:['Durable per-driver undo, independent rollback and approval are not implemented.']};
    operations.push(item);return item;
  };
  for(const [id,generation] of Object.entries(input.expectedGenerations??{})) {
    if(!Number.isSafeInteger(generation)||rs.get(id)?.generation!==generation) block(id,'generation-mismatch','resource generation differs from review commitment');
  }
  if(input.prefixPolicy) {
    for(const reason of validatePrefixPolicy(input.registry.resources,input.prefixPolicy)) block('','invalid-prefix-policy',reason);
    if(input.prefixPolicy.evaluatedAt!==input.now) block('','prefix-policy-clock-mismatch','policy and plan must use the same explicit evaluation clock');
    for(const p of validatePrefixPolicy(input.registry.resources,input.prefixPolicy).length ? [] : input.prefixPolicy.permissions) if(p.evidence) {
      const e=p.evidence;
      const binding=input.bindings.filter(b=>b.nodeId===p.owner.nodeId&&b.host===e.host&&b.source===e.source);
      const report=input.observations.filter(r=>r.host===e.host&&r.source===e.source&&r.report.collectionId===e.collectionId);
      const commitment=plan.evidence.find(x=>x.digest===e.digest&&x.host===e.host&&x.source===e.source&&x.collectionId===e.collectionId);
      if(binding.length!==1||report.length!==1||!commitment||observationFreshness(report[0]!,input.now)!=='fresh') block(p.id,'prefix-evidence-mismatch','reachability reference must bind fresh source-scoped observation evidence for the advertising node');
      // A route/collector snapshot does not prove pod, VIP or endpoint packet forwarding.
      block(p.id,'prefix-forwarding-unverified','independent packet forwarding, endpoint readiness and exposure authorization must be verified');
    }
  }
  for(const proposal of plan.proposals) {
    const r=rs.get(proposal.resourceId);const iface=r?.kind==='interface'?r:r?.kind==='route'?rs.get(r.interfaceId):undefined;
    if(iface?.kind!=='interface'||!r||r.management.mode!=='managed') continue;
    op(`resource:${r.id}`,proposal.kind,iface.nodeId,[r.id],domain(iface),r.management.provider,r.management.driver,null);
  }
  let wg:WireGuardSpec|undefined;let wgArtifact:WireGuardCompilation|undefined;
  if(input.wireguard!==undefined) {
    const result=compileWireGuard({registry:input.registry,expectedRegistryRevision:input.expectedRegistryRevision,spec:input.wireguard,prefixPolicy:input.prefixPolicy});
    if(!result.ok) for(const reason of result.diagnostics) block('wireguard','wireguard-compile',reason);
    else {
      wg=input.wireguard as WireGuardSpec;wgArtifact=result.artifact;
      const nodeIds=result.artifact.interfaces.flatMap(i=>{const g=rs.get(i.gatewayId);return g?.kind==='gateway'?[g.nodeId]:[];}).sort();
      artifacts.push({targetId:'wireguard',nodeIds,registryRevision:input.registry.revision,desiredDigest:plan.desiredDigest,hash:result.artifact.hash,compilation:result.artifact});
      for(const g of wg.gateways) {
        const gateway=rs.get(g.gatewayId); if(gateway?.kind!=='gateway') continue;
        const underlay=op(`underlay:${g.interfaceId}`,'verify',gateway.nodeId,[g.underlayInterfaceId],domain(rs.get(g.underlayInterfaceId)),'external','verify',null);
        underlay.verification=['Verify every public endpoint uses the independent underlay; reject overlay recursion.'];
        block(g.interfaceId,'underlay-reachability-unverified','declared underlay is not proof of endpoint path or reachability');
        op(`wireguard:${g.interfaceId}`,'wireguard',gateway.nodeId,[g.gatewayId,g.interfaceId],domain(rs.get(g.interfaceId)),'wireguard','wg-quick',result.artifact.hash);
        edge(`wireguard:${g.interfaceId}`,underlay.id);
        for(const remote of wg.gateways.filter(p=>p.gatewayId!==g.gatewayId)) {
          const id=`tunnel:${g.interfaceId}:${remote.interfaceId}`;
          op(id,'verify',gateway.nodeId,[g.interfaceId,remote.interfaceId],domain(rs.get(g.interfaceId)),'wireguard','verify',null);
          edge(id,`wireguard:${g.interfaceId}`);edge(id,`wireguard:${remote.interfaceId}`);
          block(id,'tunnel-reachability-unverified','handshake, peer host route and return-path forwarding must be verified');
        }
      }
    }
  }
  const asnNodes=new Map<number,string>();const nodeAsns=new Map<string,number>();const frrNodes=new Set<string>();
  for(const raw of input.frr??[]) {
    const result=compileFrr({registry:input.registry,expectedRegistryRevision:input.expectedRegistryRevision,spec:raw,prefixPolicy:input.prefixPolicy});
    if(!result.ok){for(const reason of result.diagnostics)block('frr','frr-compile',reason);continue;}
    const spec=raw as FrrSpec;
    if(frrNodes.has(spec.nodeId)) block(spec.nodeId,'writer-conflict','multiple FRR configurations target the same node');
    frrNodes.add(spec.nodeId);
    for(const [nodeId,asn] of [[spec.nodeId,spec.localAsn],...spec.peers.map(p=>[p.nodeId,p.remoteAsn])] as Array<[string,number]>) {
      if((asnNodes.has(asn)&&asnNodes.get(asn)!==nodeId)||(nodeAsns.has(nodeId)&&nodeAsns.get(nodeId)!==asn)) block(nodeId,'asn-conflict','ASN and node ownership must be consistent across all compiler inputs');
      asnNodes.set(asn,nodeId);nodeAsns.set(nodeId,asn);
    }
    const id=`frr:${spec.nodeId}`;
    artifacts.push({targetId:id,nodeIds:[spec.nodeId],registryRevision:input.registry.revision,desiredDigest:plan.desiredDigest,hash:result.artifact.hash,compilation:result.artifact});
    op(id,'frr',spec.nodeId,[spec.nodeId,...spec.peers.map(p=>p.interfaceId)],domain(rs.get(spec.peers[0]!.interfaceId)),'native','frr',result.artifact.hash);
    for(const peer of spec.peers) {
      if(input.prefixPolicy?.permissions.some(p=>p.siteId===peer.siteId&&peer.importSubnetIds.includes(p.resourceId)&&p.owner.nodeId!==peer.nodeId)) block(peer.nodeId,'prefix-origin-mismatch','advertisement owner does not match the BGP origin node');
      if(peer.backbone==='primary') {
        const local=wg?.gateways.find(g=>g.interfaceId===peer.interfaceId);
        const remote=wg?.gateways.find(g=>{const r=rs.get(g.gatewayId);return r?.kind==='gateway'&&r.nodeId===peer.nodeId;});
        if(!local||!remote||!prefixContains(local.address,hostPrefix(peer.updateSource))||!prefixContains(remote.address,hostPrefix(peer.address))) block(peer.interfaceId,'wg-frr-peer-mismatch','BGP peer and update source must match the local and remote WireGuard host addresses');
        else {
          edge(id,`tunnel:${local.interfaceId}:${remote.interfaceId}`);
          const permitted=input.prefixPolicy?.permissions.filter(p=>p.siteId===peer.siteId&&peer.importSubnetIds.includes(p.resourceId)).map(p=>p.prefix)??peer.importSubnetIds.flatMap(id=>{const r=rs.get(id);return r?.kind==='subnet'?[r.cidr]:[];});
          for(const p of permitted) if(!remote.allowedPrefixes.some(a=>prefixContains(a,p))) block(peer.interfaceId,'wg-frr-prefix-mismatch','BGP imported prefix is not deliverable through the remote peer AllowedIPs');
        }
      } else {
        const check=`external:${spec.nodeId}:${peer.interfaceId}`;
        if(!operations.some(o=>o.id===check)) op(check,'verify',spec.nodeId,[peer.interfaceId],domain(rs.get(peer.interfaceId)),'cloudflare','verify',null);
        edge(id,check);
        block(peer.interfaceId,'external-overlay-unverified','existing Cloudflare source address and TCP/179 transport must be verified; no interface changes authorized');
      }
      block(peer.interfaceId,'bgp-next-hop-unverified','BGP next hop, source binding and kernel FIB need independent verification');
      for(const subnetId of peer.importSubnetIds) {
        const prefixes=input.prefixPolicy?.permissions.filter(p=>p.resourceId===subnetId).map(p=>p.prefix)??[rs.get(subnetId)].flatMap(r=>r?.kind==='subnet'?[r.cidr]:[]);
        for(const route of input.registry.resources) {
          const iface=route.kind==='route'?rs.get(route.interfaceId):undefined;
          if(route.kind==='route'&&route.management.mode!=='external'&&iface?.kind==='interface'&&iface.nodeId===spec.nodeId&&route.table===254&&prefixes.some(p=>prefixContains(p,route.destination)||prefixContains(route.destination,p))) block(route.id,'route-writer-conflict','static route overlaps a BGP-imported prefix in the same target table');
        }
      }
    }
    const verify=op(`forwarding:${spec.nodeId}`,'verify',spec.nodeId,[spec.nodeId],null,'native','verify',null);
    verify.verification=['Verify selected BGP route AND kernel FIB and every ordered site-pair packet path; test failure and recovery.'];edge(verify.id,id);
  }
  // WG interface and peer-host routes have one writer. Coalesce a matching desired proposal.
  if(wg&&wgArtifact) for(const g of wg.gateways) {
    for(let i=operations.length-1;i>=0;i--) {
      const operation=operations[i]!;
      if(operation.id===`resource:${g.interfaceId}`) operations.splice(i,1);
      else if(operation.kind==='route') {
        const r=rs.get(operation.resourceIds[0]!);
        if(r?.kind==='route'&&r.interfaceId===g.interfaceId&&wgArtifact.interfaces.find(x=>x.interfaceId===g.interfaceId)?.peerHostRoutes.some(p=>p.destination===r.destination)) {
          if(r.management.mode==='managed'&&r.management.provider==='wireguard'&&r.management.driver==='wireguard') operations.splice(i,1);
          else block(r.id,'route-writer-conflict','WireGuard host route has a different desired writer');
        }
      }
    }
  }
  if(wg&&wgArtifact) for(const g of wg.gateways) for(const route of input.registry.resources) {
    const peerRoutes=wgArtifact.interfaces.find(i=>i.interfaceId===g.interfaceId)?.peerHostRoutes??[];
    const iface=rs.get(g.interfaceId);
    const routeIface=route.kind==='route'?rs.get(route.interfaceId):undefined;
    if(route.kind==='route'&&iface?.kind==='interface'&&routeIface?.kind==='interface'&&routeIface.nodeId===iface.nodeId&&route.table===254&&peerRoutes.some(p=>prefixContains(p.destination,route.destination)&&prefixContains(route.destination,p.destination))&&!(route.interfaceId===g.interfaceId&&route.management.mode==='managed'&&route.management.provider==='wireguard'&&route.management.driver==='wireguard')) block(route.id,'route-writer-conflict','WireGuard peer host route is claimed by another writer or interface');
  }
  for(const assertion of input.artifactAssertions??[]) {
    const a=artifacts.find(a=>a.targetId===assertion.targetId);
    if(!a||a.hash!==assertion.hash||a.registryRevision!==assertion.registryRevision||a.desiredDigest!==assertion.desiredDigest) block(assertion.targetId,'artifact-commitment-mismatch','artifact hash, revision or desired state differs from the retained review commitment');
  }
  for(const d of input.operationDependencies??[]) edge(d.resourceId,d.dependsOn);
  const ids=new Set(operations.map(o=>o.id));
  if(ids.size!==operations.length) block('','duplicate-operation','duplicate operation identity');
  const uniqueEdges=[...new Map(dependencies.map(d=>[canonicalNetworkJson(d),d])).values()].sort((a,b)=>canonicalNetworkJson(a).localeCompare(canonicalNetworkJson(b)));
  for(const d of uniqueEdges) if(!ids.has(d.resourceId)||!ids.has(d.dependsOn)) block(d.resourceId,'missing-operation-dependency','operation dependency is absent');
  const pending=new Set(ids),order:string[]=[];
  while(pending.size){const ready=[...pending].filter(id=>uniqueEdges.filter(d=>d.resourceId===id).every(d=>ids.has(d.dependsOn)&&!pending.has(d.dependsOn))).sort();if(!ready.length){block('','operation-cycle','operation graph has a cycle or unresolved dependency');break;}for(const id of ready){order.push(id);pending.delete(id);}}
  const warnings=['Dry-run artifacts are not signed execution bundles.','Secondary lab tunnels do not reproduce Cloudflare Mesh or WARP behavior.','Observation evidence and declarative exposure references do not confer execution authority.'];
  const body={schemaVersion:1 as const,kind:'network-change-set' as const,mode:'dry-run' as const,executable:false as const,registryRevision:plan.registryRevision,desiredDigest:plan.desiredDigest,resources:plan.desired,observationEvidence:plan.evidence,capabilityEvidence:plan.capabilities,matchingDigest:plan.matchingDigest,artifacts:artifacts.sort((a,b)=>a.targetId.localeCompare(b.targetId)),operations:operations.sort((a,b)=>a.id.localeCompare(b.id)),dependencies:uniqueEdges,order,blockers:[...new Map(blockers.map(b=>[canonicalNetworkJson(b),b])).values()].sort((a,b)=>canonicalNetworkJson(a).localeCompare(canonicalNetworkJson(b))),warnings};
  return {...body,id:input.id,...(input.generatedAt===undefined?{}:{generatedAt:input.generatedAt}),contentHash:networkDigest(body)};
}
