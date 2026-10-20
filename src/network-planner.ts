import { compareNetworkText } from "./network-canonical.ts";
/** Offline proposal only. This format is never an agent command or signed policy bundle. */
import { validateNetworkObservation } from "./network-observation.ts";
import { networkDigest } from "./network-canonical.ts";
import { validateNetworkInventory } from "./network-inventory.ts";
import { matchNetworkInventory, type NetworkMatchingInput, type NetworkMatchingResult } from "./network-matching.ts";

export interface NetworkDependency { resourceId: string; dependsOn: string }
export interface NetworkPlanInput extends NetworkMatchingInput {
  id: string;
  expectedRegistryRevision: number;
  additionalDependencies?: readonly NetworkDependency[];
}
export interface NetworkPlanBlocker { resourceId: string; code: string; reason: string }
export interface NetworkPlan {
  schemaVersion: 1;
  kind: "network-plan";
  id: string;
  contentHash: string;
  mode: "dry-run";
  executable: false;
  evaluatedAt: number;
  registryRevision: number;
  expectedRegistryRevision: number;
  desired: Array<{ resourceId: string; generation: number; digest: string }>;
  desiredDigest: string;
  bindings: NetworkMatchingInput["bindings"];
  evidence: NetworkMatchingResult["evidence"];
  matchingDigest: string;
  capabilities: Array<{ source: string; host: string; collector: string; available: boolean }>;
  dependencies: NetworkDependency[];
  order: string[];
  proposals: Array<{ resourceId: string; kind: "interface" | "route"; action: "create" | "update"; generation: number; desiredDigest: string }>;
  blockers: NetworkPlanBlocker[];
  preconditions: { executionImplemented: false; managementReachability: "unknown"; gatewayReachability: "unknown"; approvals: "absent"; rollback: "unavailable" };
}

export function buildNetworkPlan(input: NetworkPlanInput): NetworkPlan {
  if (!input || typeof input !== "object" || !input.registry || !Array.isArray(input.registry.resources) || !Array.isArray(input.observations) || !Array.isArray(input.bindings) || (input.additionalDependencies !== undefined && !Array.isArray(input.additionalDependencies))) throw new Error("invalid network plan input");
  if (typeof input.id !== "string" || !input.id.trim() || input.id.length > 256) throw new Error("plan id is required");
  if (!Number.isSafeInteger(input.expectedRegistryRevision) || input.expectedRegistryRevision < 0) throw new Error("expected registry revision is required");
  if (!Number.isFinite(input.now)) throw new Error("explicit evaluation clock is required");
  const resources = [...input.registry.resources].sort((a, b) => compareNetworkText(a.id, b.id));
  const blockers: NetworkPlanBlocker[] = [];
  const block = (resourceId: string, code: string, reason: string) => blockers.push({ resourceId, code, reason });
  const issues = validateNetworkInventory(resources);
  // Malformed references are rejected by the matcher. Return a blocked plan for an invalid desired graph.
  for (const issue of issues) block(issue.resourceId, "invalid-inventory", issue.message);
  if (input.registry.revision !== input.expectedRegistryRevision) block("", "revision-mismatch", "registry revision differs from the caller's expected revision");
  let matching: NetworkMatchingResult = { matches: [], evidence: [], digest: networkDigest([]) };
  try { matching = matchNetworkInventory(input); }
  catch (error) { block("", "invalid-evidence", error instanceof Error ? error.message : "matching evidence is invalid"); }
  const ids = new Set(resources.map(r => r.id));
  const edges = new Map<string, NetworkDependency>();
  const edge = (resourceId: string, dependsOn: string) => {
    if (!ids.has(resourceId) || !ids.has(dependsOn)) block(resourceId, "missing-dependency", `dependency references unknown resource ${dependsOn}`);
    edges.set(JSON.stringify([resourceId, dependsOn]), { resourceId, dependsOn });
  };
  for (const resource of resources) {
    const record = resource as unknown as Record<string, unknown>;
    for (const field of ["siteId", "nodeId", "networkId", "subnetId", "parentSubnetId", "interfaceId", "routingDomainId"]) if (typeof record[field] === "string") edge(resource.id, record[field]);
    for (const field of ["siteIds", "domainIds"]) if (Array.isArray(record[field])) for (const id of record[field]) if (typeof id === "string") edge(resource.id, id);
  }
  for (const dependency of input.additionalDependencies ?? []) {
    if (!dependency || typeof dependency.resourceId !== "string" || typeof dependency.dependsOn !== "string") { block("", "invalid-dependency", "dependency requires resourceId and dependsOn"); continue; }
    edge(dependency.resourceId, dependency.dependsOn);
  }
  const dependencies = [...edges.values()].sort((a,b) => compareNetworkText(a.resourceId, b.resourceId) || compareNetworkText(a.dependsOn, b.dependsOn));
  const pending = new Set(ids); const order: string[] = [];
  while (pending.size) {
    const ready = [...pending].filter(id => dependencies.filter(e => e.resourceId === id).every(e => ids.has(e.dependsOn) && !pending.has(e.dependsOn))).sort();
    if (!ready.length) { for (const id of [...pending].sort()) block(id, "dependency-cycle-or-unresolved", "resource dependency graph cannot be ordered"); break; }
    for (const id of ready) { pending.delete(id); order.push(id); }
  }
  const proposals: NetworkPlan["proposals"] = [];
  const byId = new Map(resources.map(r => [r.id, r]));
  for (const match of matching.matches) {
    const resource = byId.get(match.resourceId);
    if (!resource || (resource.kind !== "interface" && resource.kind !== "route")) continue;
    if (["unknown", "stale", "unsupported"].includes(match.status)) block(resource.id, `observation-${match.status}`, match.reason);
    if (resource.management.mode === "external") continue;
    if (resource.management.mode === "adopted") { block(resource.id, "adoption-authority-absent", "inventory adoption metadata does not grant configuration authority"); continue; }
    if (match.status === "missing" || match.status === "different") proposals.push({ resourceId: resource.id, kind: resource.kind, action: match.status === "missing" ? "create" : "update", generation: resource.generation, desiredDigest: networkDigest(resource) });
  }
  // Collector availability describes observation support only, never a writer capability.
  const evidenceKeys = new Set(matching.evidence.map(e => JSON.stringify([e.source,e.host,e.collectionId])));
  const capabilities: NetworkPlan["capabilities"] = [];
  for (const observation of input.observations) {
    try {
      const report = validateNetworkObservation(observation.report);
      if (!evidenceKeys.has(JSON.stringify([observation.source ?? "", observation.host, report.collectionId]))) continue;
      for (const [collector, value] of Object.entries(report.capabilities)) capabilities.push({ source: observation.source ?? "", host: observation.host, collector, available: value.available });
    } catch { /* Invalid records provide no capability evidence. */ }
  }
  capabilities.sort((a,b) => compareNetworkText(JSON.stringify(a), JSON.stringify(b)));
  for (const proposal of proposals) block(proposal.resourceId, "writer-capability-unavailable", "observation collectors do not establish an available configuration writer");
  block("", "management-reachability-unknown", "independent management connectivity has not been verified");
  block("", "gateway-reachability-unknown", "gateway connectivity has not been independently verified");
  const desired = resources.map(resource => ({ resourceId: resource.id, generation: resource.generation, digest: networkDigest(resource) }));
  const bindings = [...input.bindings].sort((a,b) => compareNetworkText(networkDigest(a), networkDigest(b)));
  blockers.sort((a,b) => compareNetworkText(a.resourceId, b.resourceId) || compareNetworkText(a.code, b.code) || compareNetworkText(a.reason, b.reason));
  const content = { schemaVersion: 1 as const, kind: "network-plan" as const, mode: "dry-run" as const, executable: false as const, evaluatedAt: input.now, registryRevision: input.registry.revision, expectedRegistryRevision: input.expectedRegistryRevision, desired, desiredDigest: networkDigest(desired), bindings, evidence: matching.evidence, matchingDigest: matching.digest, capabilities, dependencies, order, proposals, blockers, preconditions: { executionImplemented: false as const, managementReachability: "unknown" as const, gatewayReachability: "unknown" as const, approvals: "absent" as const, rollback: "unavailable" as const } };
  return { ...content, id: input.id, contentHash: networkDigest(content) };
}
