import { test } from "node:test";
import assert from "node:assert/strict";
import { buildNetworkPlan, type NetworkPlanInput } from "./network-planner.ts";
import type { NetworkInventoryResource } from "./network-inventory.ts";
const now = Date.parse("2026-10-19T12:00:00Z");
const at = new Date(now).toISOString();
function fixture(): NetworkPlanInput {
  const base = { owner: "operator", generation: 1, management: { mode: "managed" as const, provider: "heliopause", driver: "nmstate" } };
  const resources: NetworkInventoryResource[] = [{ ...base,id:"site",kind:"site" },{ ...base,id:"node",kind:"node",siteId:"site" },{ ...base,id:"net",kind:"network",siteId:"site" },{ ...base,id:"if",kind:"interface",nodeId:"node",networkId:"net",name:"eth0",mtu:1400 }];
  return { id:"plan-1",expectedRegistryRevision:3,registry:{revision:3,resources},now,bindings:[{source:"relay",host:"host",siteId:"site",nodeId:"node"}],observations:[{source:"relay",host:"host",receivedAt:at,relayReceivedAt:at,report:{schemaVersion:1,collectionId:"12345678-1234-1234-1234-123456789abc",startedAt:at,completedAt:at,observations:{links:{status:"success",startedAt:at,completedAt:at,data:[{ifindex:1,ifname:"eth0",mtu:1500}]}},capabilities:{links:{available:true,status:"success"}}}}] };
}
test("planner proposes modeled difference and can never execute or imply verified reachability", () => {
  const plan = buildNetworkPlan(fixture());
  assert.deepEqual(plan.proposals.map(p => [p.resourceId,p.action]),[["if","update"]]);
  assert.equal(plan.executable,false); assert.equal(plan.mode,"dry-run"); assert.equal(plan.kind,"network-plan");
  assert.equal(plan.preconditions.executionImplemented,false);
  for (const code of ["writer-capability-unavailable","management-reachability-unknown","gateway-reachability-unknown"]) assert.ok(plan.blockers.some(b=>b.code===code));
  assert.ok(plan.order.indexOf("site") < plan.order.indexOf("node"));
  assert.ok(plan.order.indexOf("node") < plan.order.indexOf("if"));
});
test("content hash is independent of id, resource and object insertion order", () => {
  const input=fixture(); const original=buildNetworkPlan(input);
  const reordered=structuredClone(input);reordered.id="other";reordered.registry.resources.reverse();
  reordered.registry.resources=reordered.registry.resources.map(r=>Object.fromEntries(Object.entries(r).reverse())) as NetworkInventoryResource[];
  assert.equal(buildNetworkPlan(reordered).contentHash,original.contentHash);
});
test("revision, generation, and exact evidence change content hash", () => {
  const original=fixture(); const hash=buildNetworkPlan(original).contentHash;
  for (const mutate of [(x:NetworkPlanInput)=>x.registry.revision++, (x:NetworkPlanInput)=>x.registry.resources[0]!.generation++, (x:NetworkPlanInput)=>x.observations[0]!.report.collectionId="22345678-1234-1234-1234-123456789abc"]) { const input=structuredClone(original);mutate(input);assert.notEqual(buildNetworkPlan(input).contentHash,hash); }
  const changed=fixture();changed.registry.revision++;assert.ok(buildNetworkPlan(changed).blockers.some(b=>b.code==="revision-mismatch"));
});
test("explicit cycles and missing dependencies block ordering", () => {
  const input=fixture();input.additionalDependencies=[{resourceId:"site",dependsOn:"if"},{resourceId:"node",dependsOn:"absent"}];
  const plan=buildNetworkPlan(input);assert.ok(plan.blockers.some(b=>b.code==="missing-dependency"));assert.ok(plan.blockers.some(b=>b.code==="dependency-cycle-or-unresolved"));
});
test("external and adopted metadata cannot grant proposal authority", () => {
  for (const mode of ["external","adopted"] as const) { const input=fixture();const r=input.registry.resources.find(r=>r.id==="if")!;r.management=mode==="external"?{mode,provider:"operator"}:{mode,provider:"heliopause",driver:"nmstate",adoption:{approvedBy:"operator",source:"text"}};assert.equal(buildNetworkPlan(input).proposals.length,0); }
});
test("stale, failed, unsupported and absent identity evidence never create proposals", () => {
  for (const variation of ["stale","failed","unsupported","identity"] as const) {
    const input=fixture();
    if(variation==="stale") input.now+=1_000_000;
    if(variation==="identity") input.bindings=[];
    if(variation==="failed"||variation==="unsupported") { const report=input.observations[0]!.report;const status=variation==="failed"?"error":"unsupported";report.observations.links={status,startedAt:at,completedAt:at};report.capabilities.links={available:false,status}; }
    const plan=buildNetworkPlan(input);assert.equal(plan.proposals.length,0);assert.ok(plan.blockers.some(b=>b.resourceId==="if"&&b.code.startsWith("observation-")));
  }
});
test("invalid reference returns a blocked plan instead of a partial proposal",()=>{
 const input=fixture();const r=input.registry.resources.find(r=>r.kind==="interface")!;if(r.kind==="interface")r.nodeId="missing";
 const plan=buildNetworkPlan(input);assert.equal(plan.proposals.length,0);assert.ok(plan.blockers.some(b=>b.code==="invalid-inventory"));
});
