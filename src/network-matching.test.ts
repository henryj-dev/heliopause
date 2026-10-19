import { test } from "node:test";
import assert from "node:assert/strict";
import { matchNetworkInventory, type NetworkMatchingInput } from "./network-matching.ts";
import type { NetworkInventoryResource } from "./network-inventory.ts";
import type { NetworkObservationRecord, CollectorStatus } from "./network-observation.ts";

const at = "2026-01-01T00:00:00Z";
const now = Date.parse(at);
const management = { mode: "managed", provider: "heliopause", driver: "nmstate" } as const;
function resource(id: string, kind: string, extra: object = {}): NetworkInventoryResource {
  return { id, kind, generation: 1, owner: "team", management, ...extra } as NetworkInventoryResource;
}
function setup(): NetworkMatchingInput {
  const record: NetworkObservationRecord = { source: "relay-a", host: "host-a", receivedAt: at, relayReceivedAt: at, report: {
    schemaVersion: 1, collectionId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", startedAt: at, completedAt: at,
    observations: {
      links: { status: "success", startedAt: at, completedAt: at, data: [{ ifindex: 2, ifname: "eth0", mtu: 1500 }] },
      routes4: { status: "success", startedAt: at, completedAt: at, data: [{ dst: "default", dev: "eth0", table: "main" }] },
    }, capabilities: { links: { available: true, status: "success" }, routes4: { available: true, status: "success" } },
  } };
  return { now, registry: { revision: 1, resources: [resource("site", "site"), resource("node", "node", { siteId: "site" }), resource("net", "network", { siteId: "site" }), resource("iface", "interface", { nodeId: "node", networkId: "net", name: "eth0", mtu: 1500 }), resource("route", "route", { interfaceId: "iface", destination: "0.0.0.0/0", table: 254 })] }, observations: [record], bindings: [{ source: "relay-a", host: "host-a", siteId: "site", nodeId: "node" }] };
}
const status = (input: NetworkMatchingInput, id = "iface") => matchNetworkInventory(input).matches.find(m => m.resourceId === id)!.status;
function collectorStatus(input: NetworkMatchingInput, value: CollectorStatus) {
  const report = input.observations[0]!.report;
  report.observations.links = { status: value, startedAt: at, completedAt: at, ...(value === "success" ? { data: [] } : {}) };
  report.capabilities.links = { status: value, available: value === "success" };
}

test("trusted binding matches supported interface and semantic default route fields", () => {
  const input = setup(); const result = matchNetworkInventory(input);
  assert.equal(status(input), "matched"); assert.equal(status(input, "route"), "matched");
  assert.equal(result.matches.find(m => m.resourceId === "net")!.status, "unsupported");
  assert.equal(result.evidence[0]!.collectionId, input.observations[0]!.report.collectionId);
  assert.match(result.digest, /^[a-f0-9]{64}$/);
});
test("same hostname and interface name cannot replace an explicit source/host binding", () => {
  const input = setup(); input.bindings = [];
  assert.equal(status(input), "unknown");
  input.bindings = [{ source: "different-relay", host: "host-a", siteId: "site", nodeId: "node" }];
  assert.equal(status(input), "unknown");
  input.bindings = [{ source: "relay-a", host: "host-a", siteId: "site", nodeId: "host-a" }];
  assert.throws(() => matchNetworkInventory(input), /binding/);
});
test("duplicate bindings and duplicate records fail closed including identical duplicates", () => {
  const input = setup(); input.bindings = [...input.bindings, ...input.bindings];
  assert.equal(status(input), "unknown");
  const duplicate = setup(); duplicate.observations = [...duplicate.observations, ...duplicate.observations];
  assert.equal(status(duplicate), "unknown");
  const aliases = setup(); aliases.bindings = [...aliases.bindings, { ...aliases.bindings[0]!, host: "alias" }];
  assert.equal(status(aliases), "unknown");
});
test("binding site and node membership and inventory routing-domain references are validated", () => {
  const input = setup(); input.registry.resources.push(resource("other-site", "site"));
  input.bindings = [{ ...input.bindings[0]!, siteId: "other-site" }];
  assert.throws(() => matchNetworkInventory(input), /binding/);
  const bad = setup(); Object.assign(bad.registry.resources.find(r => r.id === "route")!, { routingDomainId: "missing" });
  assert.throws(() => matchNetworkInventory(bad), /registry/);
});
test("missing requires successful complete collector, errors remain unknown and unsupported distinct", () => {
  const input = setup(); collectorStatus(input, "success"); assert.equal(status(input), "missing");
  for (const failure of ["timeout", "error", "unavailable", "output-limit"] as const) {
    collectorStatus(input, failure); assert.equal(status(input), "unknown");
  }
  for (const failure of ["unsupported", "not-installed"] as const) {
    collectorStatus(input, failure); assert.equal(status(input), "unsupported");
  }
  delete input.observations[0]!.report.observations.links;
  delete input.observations[0]!.report.capabilities.links;
  assert.equal(status(input), "unknown");
});
test("stale, future-poisoned and invalid evidence cannot produce missing or matched", () => {
  const input = setup(); input.now += 600_001; assert.equal(status(input), "stale");
  const future = setup(); future.now -= 30_001; assert.equal(status(future), "stale");
  const invalid = setup(); invalid.observations[0]!.report.observations.links!.data![0]!.privateKey = "secret";
  assert.equal(status(invalid), "unknown"); assert.equal(matchNetworkInventory(invalid).evidence.length, 0);
});
test("declarative MTU drift is different and absent MTU is unknown; operational state ignored", () => {
  const input = setup(); const row = input.observations[0]!.report.observations.links!.data![0]!;
  row.mtu = 1400; assert.equal(status(input), "different");
  delete row.mtu; assert.equal(status(input), "unknown");
  row.mtu = 1500; row.operstate = "DOWN"; assert.equal(status(input), "matched");
});
test("route table identity and interface drift are separate; duplicate candidates are unknown", () => {
  const input = setup(); const rows = input.observations[0]!.report.observations.routes4!.data!;
  rows[0]!.dev = "eth1"; assert.equal(status(input, "route"), "different");
  rows[0]!.table = 100; assert.equal(status(input, "route"), "missing");
  rows[0]!.table = 254; rows.push({ ...rows[0] }); assert.equal(status(input, "route"), "unknown");
});
test("IPv6 route normalization uses routes6 rather than an unrelated IPv4 collector", () => {
  const input = setup(); Object.assign(input.registry.resources.find(r => r.id === "route")!, { destination: "2001:db8::/64", table: 100 });
  input.observations[0]!.report.observations.routes6 = { status: "success", startedAt: at, completedAt: at, data: [{ dst: "2001:0db8:0:0::/64", table: 100, dev: "eth0" }] };
  input.observations[0]!.report.capabilities.routes6 = { status: "success", available: true };
  assert.equal(status(input, "route"), "matched");
});
test("external drift remains external and unexpected telemetry never becomes managed", () => {
  const input = setup(); input.registry.resources.find(r => r.id === "iface")!.management = { mode: "external", provider: "other" };
  input.observations[0]!.report.observations.links!.data![0]!.mtu = 1400;
  input.observations[0]!.report.observations.links!.data!.push({ ifindex: 3, ifname: "eth9", mtu: 1500 });
  const result = matchNetworkInventory(input);
  assert.equal(result.matches.find(m => m.resourceId === "iface")!.management!.mode, "external");
  assert.equal(result.matches.find(m => m.status === "unexpected")!.management!.mode, "external");
});
test("resource, binding, and observation ordering does not change digest and input is untouched", () => {
  const input = setup(); const before = structuredClone(input); const result = matchNetworkInventory(input);
  assert.deepEqual(input, before);
  input.registry.resources.reverse(); input.bindings = [...input.bindings].reverse(); input.observations = [...input.observations].reverse();
  assert.deepEqual(matchNetworkInventory(input), result);
  const changed = setup(); changed.observations[0]!.report.collectionId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
  assert.notEqual(matchNetworkInventory(changed).digest, result.digest);
});
test("invalid deterministic clock and invalid registry are rejected", () => {
  const input = setup(); input.now = NaN; assert.throws(() => matchNetworkInventory(input), /clock/);
  input.now = now; input.maxAgeMs = -1; assert.throws(() => matchNetworkInventory(input), /clock/);
  input.maxAgeMs = 600_001; assert.throws(() => matchNetworkInventory(input), /freshness/);
});
test("VRF identity uses explicit inventory domain and observed master, never interface name alone", () => {
  const input = setup();
  input.registry.resources.push(resource("domain", "routing-domain", { name: "tenant", isolation: "vrf", vrf: { name: "vrf-tenant", table: 100 } }));
  Object.assign(input.registry.resources.find(r => r.id === "net")!, { scope: "site-local", routingDomainId: "domain", purpose: "application" });
  Object.assign(input.registry.resources.find(r => r.id === "route")!, { table: 100, routingDomainId: "domain" });
  input.observations[0]!.report.observations.routes4!.data![0]!.table = 100;
  assert.equal(status(input), "unknown"); assert.equal(status(input, "route"), "unknown");
  const links = input.observations[0]!.report.observations.links!.data!;
  links[0]!.master = "vrf-other"; assert.equal(status(input), "different");
  links[0]!.master = "vrf-tenant"; assert.equal(status(input), "matched"); assert.equal(status(input, "route"), "matched");
  links[0]!.master = 9; assert.equal(status(input), "unknown");
  links.push({ ifindex: 9, ifname: "vrf-tenant", mtu: 1500 }); assert.equal(status(input), "matched");
  links.push({ ifindex: 9, ifname: "vrf-duplicate", mtu: 1500 }); assert.equal(status(input), "unknown");
});
test("external domain isolation is unsupported and unverified global masters remain unknown", () => {
  const input = setup();
  const domain = resource("domain", "routing-domain", { name: "domain", isolation: "external" });
  input.registry.resources.push(domain);
  Object.assign(input.registry.resources.find(r => r.id === "net")!, { scope: "site-local", routingDomainId: "domain", purpose: "application" });
  Object.assign(input.registry.resources.find(r => r.id === "route")!, { routingDomainId: "domain" });
  assert.equal(status(input), "unsupported");
  Object.assign(domain, { isolation: "global" });
  assert.equal(status(input), "matched");
  input.observations[0]!.report.observations.links!.data![0]!.master = "bridge0";
  assert.equal(status(input), "unknown");
});

test("missing or malformed receipt timestamps cannot produce fresh matching evidence", () => {
  for (const field of ["receivedAt", "relayReceivedAt"] as const) {
    for (const invalid of [undefined, "", "2026-01-01", "invalid", "2026-01-01T00:00:00+09:00", "2026-02-30T00:00:00Z", "2026-01-01T24:00:00Z"]) {
      const input = setup();
      Object.assign(input.observations[0]!, { [field]: invalid });
      assert.equal(status(input), "unknown", `${field}=${invalid}`);
      assert.equal(matchNetworkInventory(input).evidence.length, 0);
      input.observations[0]!.report.observations.links!.data = [];
      assert.equal(status(input), "unknown");
    }
  }
});
test("absent resources cannot bypass external or unverified VRF domain prerequisites", () => {
  const input = setup();
  const domain = resource("domain", "routing-domain", { name: "tenant", isolation: "external" });
  input.registry.resources.push(domain);
  Object.assign(input.registry.resources.find(r => r.id === "net")!, { scope: "site-local", routingDomainId: "domain", purpose: "application" });
  Object.assign(input.registry.resources.find(r => r.id === "route")!, { table: 100, routingDomainId: "domain" });
  input.observations[0]!.report.observations.routes4!.data = [];
  assert.equal(status(input, "route"), "unsupported");
  input.observations[0]!.report.observations.links!.data = [];
  assert.equal(status(input), "unsupported");
  Object.assign(domain, { isolation: "vrf", vrf: { name: "tenant-vrf", table: 100 } });
  assert.equal(status(input), "unknown"); assert.equal(status(input, "route"), "unknown");
  input.observations[0]!.report.observations.links!.data = [{ ifindex: 2, ifname: "eth0", mtu: 1500 }];
  assert.equal(status(input, "route"), "unknown");
  input.observations[0]!.report.observations.links!.data![0]!.master = "wrong-vrf";
  assert.equal(status(input, "route"), "unknown");
  input.observations[0]!.report.observations.links!.data![0]!.master = "tenant-vrf";
  assert.equal(status(input, "route"), "missing");
});
