/** Pure inventory comparison. Bindings must be supplied by a trusted caller, never inferred from telemetry. */
import { canonicalNetworkJson as canonical, networkDigest as hash } from "./network-canonical.ts";
import { cidrRange } from "./nft.ts";
import { validateNetworkInventory, type NetworkInventoryResource, type NetworkManagement } from "./network-inventory.ts";
import { observationFreshness, observationHost, validateNetworkObservation, type NetworkObservationRecord } from "./network-observation.ts";
import type { NetworkRegistryDocument } from "./network-registry.ts";

export interface NetworkIdentityBinding { source: string; host: string; siteId: string; nodeId: string }
export type NetworkMatchStatus = "matched" | "missing" | "unexpected" | "different" | "unknown" | "stale" | "unsupported";
export interface NetworkMatch { resourceId: string; status: NetworkMatchStatus; reason: string; management?: NetworkManagement }
export interface NetworkMatchEvidence { source: string; host: string; collectionId: string; digest: string }
export interface NetworkMatchingResult { matches: NetworkMatch[]; evidence: NetworkMatchEvidence[]; digest: string }
export interface NetworkMatchingInput {
  registry: Pick<NetworkRegistryDocument, "revision" | "resources">;
  observations: readonly NetworkObservationRecord[];
  bindings: readonly NetworkIdentityBinding[];
  now: number;
  maxAgeMs?: number;
}
const identity = (source: string | undefined, host: string) => JSON.stringify([source, host]);
function receipt(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|\+00:00)$/.test(value)) return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString().slice(0, 19) === value.slice(0, 19);
}
function prefix(value: unknown, ipv6 = false): string | undefined {
  if (typeof value !== "string") return undefined;
  const range = cidrRange(value === "default" ? ipv6 ? "::/0" : "0.0.0.0/0" : value);
  return range ? `${range.family}:${range.first}:${range.bits}` : undefined;
}
function table(value: unknown): number | undefined {
  if (value === undefined || value === "main") return 254;
  if (value === "local") return 255;
  if (value === "default") return 253;
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value === "string" && /^\d+$/.test(value)) return Number(value);
  return undefined;
}

export function matchNetworkInventory(input: NetworkMatchingInput): NetworkMatchingResult {
  const { registry, observations, bindings, now } = input;
  const maxAgeMs = input.maxAgeMs ?? 10 * 60_000;
  if (!Number.isFinite(now) || !Number.isFinite(maxAgeMs) || maxAgeMs < 0 || maxAgeMs > 10 * 60_000) throw new Error("invalid matching clock or freshness limit");
  if (!Number.isSafeInteger(registry.revision) || registry.revision < 0 || validateNetworkInventory(registry.resources).length) throw new Error("invalid matching registry");
  const byId = new Map(registry.resources.map(r => [r.id, r]));
  const byNode = new Map<string, NetworkIdentityBinding[]>();
  const byIdentity = new Map<string, NetworkIdentityBinding[]>();
  for (const b of bindings) {
    observationHost(b.source); observationHost(b.host);
    const site = byId.get(b.siteId); const node = byId.get(b.nodeId);
    if (site?.kind !== "site" || node?.kind !== "node" || node.siteId !== site.id) throw new Error("identity binding must reference its node and site");
    byNode.set(b.nodeId, [...(byNode.get(b.nodeId) ?? []), b]);
    const key = identity(b.source, b.host);
    byIdentity.set(key, [...(byIdentity.get(key) ?? []), b]);
  }
  const records = new Map<string, NetworkObservationRecord[]>();
  const evidence: NetworkMatchEvidence[] = [];
  const invalid = new Set<string>();
  for (const record of observations) {
    observationHost(record.host);
    if (record.source !== undefined) observationHost(record.source);
    const key = identity(record.source, record.host);
    records.set(key, [...(records.get(key) ?? []), record]);
    try {
      if (!receipt(record.receivedAt) || (record.source !== undefined && !receipt(record.relayReceivedAt)) || (record.relayReceivedAt !== undefined && !receipt(record.relayReceivedAt))) throw new Error("invalid receipt evidence");
      validateNetworkObservation(record.report);
      evidence.push({ source: record.source ?? "", host: record.host, collectionId: record.report.collectionId, digest: hash(record) });
    } catch { invalid.add(key); }
  }
  const matches: NetworkMatch[] = [];
  const add = (r: NetworkInventoryResource, status: NetworkMatchStatus, reason: string) => matches.push({ resourceId: r.id, management: structuredClone(r.management), status, reason });
  const used = new Set<string>();
  const eligible = new Map<string, NetworkObservationRecord>();
  for (const r of [...registry.resources].sort((a, b) => a.id.localeCompare(b.id))) {
    if (r.kind !== "interface" && r.kind !== "route") { add(r, "unsupported", "resource has no supported declarative observation comparison"); continue; }
    const iface = r.kind === "interface" ? r : byId.get(r.interfaceId);
    if (iface?.kind !== "interface") throw new Error("invalid interface reference");
    const bs = byNode.get(iface.nodeId) ?? [];
    if (bs.length !== 1 || byIdentity.get(identity(bs[0]?.source, bs[0]?.host ?? ""))?.length !== 1) { add(r, "unknown", "trusted identity binding is absent or ambiguous"); continue; }
    const b = bs[0]!; const key = identity(b.source, b.host); const rs = records.get(key) ?? [];
    if (rs.length !== 1 || invalid.has(key)) { add(r, "unknown", "observation is absent, invalid, or ambiguous"); continue; }
    const record = rs[0]!;
    if (observationFreshness(record, now, maxAgeMs) !== "fresh") { add(r, "stale", "observation evidence is stale"); continue; }
    eligible.set(key, record);
    const network = byId.get(iface.networkId);
    const domain = network?.kind === "network" && network.routingDomainId ? byId.get(network.routingDomainId) : undefined;
    if (domain?.kind === "routing-domain") {
      if (domain.isolation === "external") { add(r, "unsupported", "external routing-domain isolation cannot be verified"); continue; }
      const links = record.report.observations.links;
      const interfaceRows = links?.status === "success" && now - Date.parse(links.completedAt) <= maxAgeMs ? links.data?.filter(link => link.ifname === iface.name) ?? [] : [];
      if (interfaceRows.length !== 1) { add(r, "unknown", "routing-domain interface evidence is absent or ambiguous"); continue; }
      const master = interfaceRows[0]!.master;
      if (domain.isolation === "vrf") {
        if (!domain.vrf || master === undefined) { add(r, "unknown", "VRF master evidence is absent"); continue; }
        const masters = typeof master === "number" ? links!.data!.filter(link => link.ifindex === master) : [];
        const masterName = typeof master === "string" ? master : masters.length === 1 ? masters[0]!.ifname : undefined;
        if (typeof masterName !== "string") { add(r, "unknown", "VRF master identity is ambiguous"); continue; }
        if (masterName !== domain.vrf.name) { add(r, r.kind === "route" ? "unknown" : "different", "interface routing-domain master differs"); continue; }
      } else if (master !== undefined) { add(r, "unknown", "global routing-domain master cannot be verified"); continue; }
    }
    const collectorName = r.kind === "interface" ? "links" : cidrRange(r.destination)?.family === "ip6" ? "routes6" : "routes4";
    const collector = record.report.observations[collectorName];
    if (!collector || collector.status !== "success") {
      add(r, collector?.status === "unsupported" || collector?.status === "not-installed" ? "unsupported" : "unknown", "required collector did not succeed"); continue;
    }
    if (now - Date.parse(collector.completedAt) > maxAgeMs) { add(r, "stale", "collector evidence is stale"); continue; }
    const rows = collector.data ?? [];
    const candidates = rows.map((row, index) => ({ row, index })).filter(({ row }) => r.kind === "interface" ? row.ifname === iface.name : prefix(row.dst, collectorName === "routes6") === prefix(r.destination) && table(row.table) === r.table);
    if (!candidates.length) { add(r, "missing", "successful collector did not observe the desired identity"); continue; }
    for (const { index } of candidates) used.add(JSON.stringify([key, collectorName, index]));
    if (candidates.length !== 1) { add(r, "unknown", "multiple observations match the desired identity"); continue; }
    const row = candidates[0]!.row;
    if (r.kind === "route") {
      if (typeof row.dev !== "string") add(r, "unknown", "route interface is not available");
      else add(r, row.dev === iface.name ? "matched" : "different", row.dev === iface.name ? "supported route fields match" : "route interface differs");
    } else {
      const mtu = (r as typeof r & { mtu?: number }).mtu;
      if (mtu !== undefined && row.mtu === undefined) add(r, "unknown", "interface MTU is not available");
      else add(r, mtu !== undefined && row.mtu !== mtu ? "different" : "matched", mtu !== undefined && row.mtu !== mtu ? "interface MTU differs" : "supported interface fields match");
    }
  }
  for (const [key, record] of eligible) for (const name of ["links", "routes4", "routes6"]) {
    const collector = record.report.observations[name];
    if (collector?.status !== "success" || now - Date.parse(collector.completedAt) > maxAgeMs) continue;
    for (const [index, row] of (collector.data ?? []).entries()) {
      if (used.has(JSON.stringify([key, name, index]))) continue;
      // Unclaimed telemetry is reported as external and can never confer repair authority.
      matches.push({ resourceId: `observation:${hash([key, name, row])}`, status: "unexpected", reason: "observed resource has no desired inventory match", management: { mode: "external", provider: record.source! } });
    }
  }
  matches.sort((a, b) => a.resourceId.localeCompare(b.resourceId) || a.status.localeCompare(b.status) || a.reason.localeCompare(b.reason));
  evidence.sort((a, b) => canonical(a).localeCompare(canonical(b)));
  return { matches, evidence, digest: hash({ revision: registry.revision, resources: [...registry.resources].sort((a, b) => a.id.localeCompare(b.id)), bindings: [...bindings].sort((a, b) => canonical(a).localeCompare(canonical(b))), matches, evidence }) };
}
