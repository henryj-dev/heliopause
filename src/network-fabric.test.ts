import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { diffBgpFabricPlans, planBgpFabric, FABRIC_FALLBACK_METRIC, type BgpFabricPlan } from "./network-fabric.ts";
import { validateNetworkInventory, type NetworkInventoryResource } from "./network-inventory.ts";

// Synthetic addressing only; nothing here describes a real site.
const base = { owner: "ops", generation: 1 } as const;
const ext = (provider: string) => ({ mode: "external", provider } as const);
const managed = (provider: string, driver: string) => ({ mode: "managed", provider, driver } as const);
const key = (i: number) => Buffer.alloc(32, i + 1).toString("base64");
const doc = (i: number) => `203.0.113.${10 + i}`;

function site(i: number, opts: { cluster?: boolean } = {}): NetworkInventoryResource[] {
  const o = 40 + i;
  const rs: NetworkInventoryResource[] = [
    { ...base, management: ext("operator"), id: `s${i}`, kind: "site" },
    { ...base, management: ext("operator"), id: `n${i}`, kind: "node", siteId: `s${i}` },
    { ...base, management: ext("operator"), id: `g${i}`, kind: "gateway", nodeId: `n${i}` },
    { ...base, management: ext("operator"), id: `vpc${i}`, kind: "network", scope: "site-local", siteId: `s${i}`, routingDomainId: "rd", purpose: "infrastructure" },
    { ...base, management: ext("operator"), id: `blk${i}`, kind: "subnet", networkId: `vpc${i}`, cidr: `10.${o}.0.0/16` },
    { ...base, management: ext("operator"), id: `infra${i}`, kind: "subnet", networkId: `vpc${i}`, cidr: `10.${o}.0.0/17`, parentSubnetId: `blk${i}` },
    { ...base, management: ext("operator"), id: `lan${i}`, kind: "subnet", networkId: `vpc${i}`, cidr: `10.${o}.0.0/24`, parentSubnetId: `infra${i}` },
    { ...base, management: ext("operator"), id: `k8s${i}`, kind: "subnet", networkId: `vpc${i}`, cidr: `10.${o}.128.0/17`, parentSubnetId: `blk${i}` },
    { ...base, management: ext("operator"), id: `pod${i}`, kind: "address-pool", subnetId: `k8s${i}`, cidr: `10.${o}.128.0/18`, allocationAuthority: "kubernetes", purpose: "kubernetes-pod" },
    { ...base, management: ext("operator"), id: `svc${i}`, kind: "address-pool", subnetId: `k8s${i}`, cidr: `10.${o}.192.0/18`, allocationAuthority: "kubernetes", purpose: "kubernetes-service" },
    { ...base, management: ext("operator"), id: `lb${i}`, kind: "address-pool", subnetId: `infra${i}`, cidr: `10.${o}.127.0/24`, allocationAuthority: "cilium", purpose: "kubernetes-loadbalancer" },
    { ...base, management: managed("frr", "frr"), id: `r${i}`, kind: "bgp-router", nodeId: `n${i}`, role: "gateway", asn: 65001 + i, routerId: `10.${o}.0.1`,
      originSubnetIds: [`blk${i}`], advertiseSubnetIds: [`blk${i}`], fabricIndex: i + 1, ...(opts.cluster ? { address: `10.${o}.0.1` } : {}) },
    { ...base, management: managed("heliopause", "ipam"), id: `ip${i}`, kind: "address-allocation", poolId: "tunpool", address: `10.90.0.${i + 1}`, state: "allocated", consumerId: `att${i}` },
    { ...base, management: managed("wireguard", "wireguard"), id: `att${i}`, kind: "fabric-attachment", fabricId: "fab", routerId: `r${i}`, networkId: "native",
      tunnelAllocationId: `ip${i}`, endpoint: doc(i), publicKey: key(i), privateKeyRef: { provider: "file", reference: `wg-${i}` } },
    { ...base, management: ext("cloudflare"), id: `cfif${i}`, kind: "interface", nodeId: `n${i}`, networkId: "cf", name: "cfwg0" },
    { ...base, management: ext("cloudflare"), id: `cfip${i}`, kind: "address-allocation", poolId: "cfpool", address: `10.91.0.${i + 1}`, state: "allocated" },
    { ...base, management: ext("cloudflare"), id: `cfatt${i}`, kind: "fabric-attachment", fabricId: "fab", routerId: `r${i}`, networkId: "cf", tunnelAllocationId: `cfip${i}`, interfaceId: `cfif${i}` },
  ];
  if (opts.cluster) rs.push({ ...base, management: ext("cilium"), id: `c${i}`, kind: "bgp-router", nodeId: `n${i}`, role: "cluster", asn: 65100, routerId: `10.${o}.0.13`, address: `10.${o}.0.13` });
  return rs;
}
function inventory(count = 4, opts: { secondaryMode?: "bgp" | "static-fallback"; clusterAt?: number } = {}): NetworkInventoryResource[] {
  const sites = Array.from({ length: count }, (_, i) => i);
  return [
    { ...base, management: ext("operator"), id: "rd", kind: "routing-domain", name: "global", isolation: "global" },
    { ...base, management: managed("wireguard", "wireguard"), id: "native", kind: "network", scope: "overlay", siteIds: sites.map(i => `s${i}`), routingDomainId: "rd", purpose: "backbone" },
    { ...base, management: managed("wireguard", "wireguard"), id: "tunsub", kind: "subnet", networkId: "native", cidr: "10.90.0.0/24" },
    { ...base, management: managed("wireguard", "wireguard"), id: "tunpool", kind: "address-pool", subnetId: "tunsub", cidr: "10.90.0.0/24", allocationAuthority: "heliopause", purpose: "tunnel" },
    { ...base, management: ext("cloudflare"), id: "cf", kind: "network", scope: "overlay", siteIds: sites.map(i => `s${i}`), routingDomainId: "rd", purpose: "backbone" },
    { ...base, management: ext("cloudflare"), id: "cfsub", kind: "subnet", networkId: "cf", cidr: "10.91.0.0/24" },
    { ...base, management: ext("cloudflare"), id: "cfpool", kind: "address-pool", subnetId: "cfsub", cidr: "10.91.0.0/24", allocationAuthority: "cloudflare", purpose: "tunnel" },
    { ...base, management: ext("operator"), id: "mgmtrd", kind: "routing-domain", name: "management", isolation: "external" },
    { ...base, management: ext("cloudflare"), id: "mgmt", kind: "network", scope: "transit", siteIds: ["s0"], routingDomainId: "mgmtrd", purpose: "management" },
    { ...base, management: ext("cloudflare"), id: "mgmtsub", kind: "subnet", networkId: "mgmt", cidr: "10.95.0.0/16" },
    { ...base, management: managed("frr", "frr"), id: "fab", kind: "bgp-fabric", topology: "full-mesh", transports: [
      { networkId: "native", preference: "primary", mode: "bgp", listenPortBase: 51800, persistentKeepalive: 25, mtu: 1420 },
      { networkId: "cf", preference: "secondary", mode: opts.secondaryMode ?? "bgp" },
    ] },
    ...sites.flatMap(i => site(i, { cluster: opts.clusterAt === i })),
  ];
}
const plan = (resources: NetworkInventoryResource[], revision = 1): BgpFabricPlan => {
  const result = planBgpFabric({ registry: { revision, resources }, expectedRegistryRevision: revision, fabricId: "fab" });
  assert.equal(result.ok, true, result.ok ? "" : result.diagnostics.join("\n"));
  return (result as { plan: BgpFabricPlan }).plan;
};
const gw = (p: BgpFabricPlan, id: string) => p.gateways.find(g => g.routerId === id)!;
const issues = (resources: NetworkInventoryResource[]) => validateNetworkInventory(resources).map(i => `${i.resourceId}: ${i.message}`);

test("the fixture inventory is valid", () => {
  assert.deepEqual(issues(inventory()), []);
  assert.deepEqual(issues(inventory(4, { clusterAt: 1 })), []);
});

test("four sites give six sessions per BGP transport and one tunnel per peer", () => {
  const p = plan(inventory());
  assert.equal(p.mode, "dry-run");
  assert.equal(p.executable, false);
  assert.equal(p.sessions.filter(s => s.transportNetworkId === "native").length, 6);
  assert.equal(p.sessions.filter(s => s.transportNetworkId === "cf").length, 6);
  for (const g of p.gateways) {
    assert.equal(g.wireguard.length, 3, `${g.routerId} has one native tunnel per peer`);
    for (const w of g.wireguard) {
      assert.deepEqual(w.allowedIps, ["0.0.0.0/0", "::/0"]);
      assert.match(w.template, /^Table = off$/m);
      assert.doesNotMatch(w.template, /PrivateKey/);
      assert.match(w.interfaceName, /^hpf[0-9a-f]{12}$/);
    }
    assert.equal(new Set(g.wireguard.map(w => w.interfaceName)).size, 3);
  }
});

test("each tunnel's endpoint port is the port its peer listens on for that tunnel", () => {
  const p = plan(inventory());
  for (const g of p.gateways) for (const w of g.wireguard) {
    const back = gw(p, w.peerRouterId).wireguard.find(x => x.peerRouterId === g.routerId)!;
    assert.equal(w.peerEndpoint.split(":")[1], String(back.listenPort), `${g.routerId}→${w.peerRouterId}`);
    assert.equal(w.peerAddress, back.localAddress);
  }
  assert.deepEqual(gw(p, "r0").listenPorts, [51802, 51803, 51804]);
});

test("adding a site changes every existing gateway once and adds one", () => {
  const before = plan(inventory(4));
  const after = plan(inventory(5), 2);
  const diff = diffBgpFabricPlans(before, after);
  assert.deepEqual(diff.map(d => [d.routerId, d.change]), [["r0", "changed"], ["r1", "changed"], ["r2", "changed"], ["r3", "changed"], ["r4", "added"]]);
  for (const d of diff.filter(d => d.change === "changed")) assert.ok(d.parts.includes("wireguard") && d.parts.includes("frr"), d.routerId);
  // Existing tunnels keep their names and ports, so the change is one new peer, not a renumbering.
  for (const g of before.gateways) for (const w of g.wireguard) {
    const same = gw(after, g.routerId).wireguard.find(x => x.peerRouterId === w.peerRouterId)!;
    assert.deepEqual([same.interfaceName, same.listenPort, same.peerEndpoint], [w.interfaceName, w.listenPort, w.peerEndpoint]);
  }
});

test("a new subnet inside a site block changes only that site's gateway", () => {
  const resources = inventory();
  const before = plan(resources);
  const grown = resources.map(r => r.id === "r2" && r.kind === "bgp-router" ? { ...r, advertiseSubnetIds: ["blk2", "lan2"] } : r);
  const diff = diffBgpFabricPlans(before, plan(grown, 2));
  assert.deepEqual(diff.filter(d => d.change !== "unchanged").map(d => [d.routerId, d.parts]), [["r2", ["frr"]]]);
  assert.match(gw(plan(grown, 2), "r2").frr, /^ {2}network 10\.42\.0\.0\/24$/m);
});

test("peer filters accept the site block but no tunnel, management or Service aggregate", () => {
  const frr = gw(plan(inventory()), "r0").frr;
  const peer = frr.split("\n").filter(l => l.startsWith("ip prefix-list PL-SITE-") && l.includes("10.41."));
  assert.deepEqual(peer.map(l => l.replace(/^ip prefix-list \S+ seq \d+ /, "")), [
    "permit 10.41.127.0/24 ge 32",
    "deny 10.41.127.0/24 le 32",
    "permit 10.41.192.0/18 ge 32",
    "deny 10.41.192.0/18 le 32",
    "permit 10.41.0.0/16 le 32",
  ]);
  assert.doesNotMatch(frr, /10\.95\./, "management space never appears");
  assert.match(frr, /bgp as-path access-list AP-\S+ seq 5 permit \^65002\$/);
  assert.match(frr, /set local-preference 200/);
  assert.match(frr, /set local-preference 100/);
  assert.match(frr, /^ bgp ebgp-requires-policy$/m);
  // Tunnel peers are /32 host routes; single-hop eBGP needs the connected check disabled.
  const frrLines = frr.split("\n");
  for (const peer of ["10.90.0.2", "10.90.0.3", "10.90.0.4", "10.91.0.2"]) assert.ok(frrLines.includes(` neighbor ${peer} disable-connected-check`), peer);
  assert.doesNotMatch(frr, /redistribute/);
});

test("a cluster speaker peers only with its own gateway and may announce Pods and host routes", () => {
  const p = plan(inventory(4, { clusterAt: 1 }));
  const frr = gw(p, "r1").frr;
  assert.match(frr, /^ neighbor 10\.41\.0\.13 remote-as 65100$/m);
  assert.match(frr, /^ {2}neighbor 10\.41\.0\.13 route-map RM-IN-CLUSTER-V4 in$/m);
  assert.match(frr, /^ {2}neighbor 10\.41\.0\.13 route-map RM-DENY-ALL out$/m);
  const cluster = frr.split("\n").filter(l => l.startsWith("ip prefix-list PL-CLUSTER-")).map(l => l.replace(/^ip prefix-list \S+ seq \d+ /, ""));
  assert.deepEqual(cluster, ["permit 10.41.127.0/24 ge 32", "permit 10.41.128.0/18 le 32", "permit 10.41.192.0/18 ge 32"]);
  for (const id of ["r0", "r2", "r3"]) {
    assert.doesNotMatch(gw(p, id).frr, /10\.41\.0\.13/, `${id} never peers with another site's cluster`);
    assert.match(gw(p, id).frr, /permit \^65002\(_\(65100\)\)\?\$/, `${id} accepts r1's cluster-originated paths`);
  }
  assert.match(frr, /permit \^65100\$/, "r1 re-exports routes its cluster originated");
});

test("a static-fallback secondary installs no sessions and only high-metric routes", () => {
  const p = plan(inventory(4, { secondaryMode: "static-fallback" }));
  assert.equal(p.sessions.filter(s => s.transportNetworkId === "cf").length, 0);
  assert.deepEqual(gw(p, "r0").fallbackRoutes, ["10.41.0.0/16", "10.42.0.0/16", "10.43.0.0/16"].map(destination => ({ destination, interfaceId: "cfif0", metric: FABRIC_FALLBACK_METRIC })));
  assert.doesNotMatch(gw(p, "r0").frr, /10\.91\./);
  assert.ok(p.preconditions.some(c => c.includes("metric-0")));
});

test("plans are deterministic and independent of resource order", () => {
  const resources = inventory(4, { clusterAt: 2 });
  assert.equal(plan(resources).hash, plan([...resources].reverse()).hash);
});

test("planning refuses a stale revision and an invalid inventory", () => {
  const resources = inventory();
  assert.equal(planBgpFabric({ registry: { revision: 2, resources }, expectedRegistryRevision: 1, fabricId: "fab" }).ok, false);
  const broken = resources.filter(r => r.id !== "ip1");
  const result = planBgpFabric({ registry: { revision: 1, resources: broken }, expectedRegistryRevision: 1, fabricId: "fab" });
  assert.equal(result.ok, false);
});

const replace = (id: string, patch: Record<string, unknown>) => inventory(4, { clusterAt: 1 }).map(r => r.id === id ? { ...r, ...patch } as NetworkInventoryResource : r);
const rejects = (resources: NetworkInventoryResource[], pattern: RegExp) => assert.ok(issues(resources).some(m => pattern.test(m)), issues(resources).join("\n") || "no issues");

test("inventory rejects unsafe routing declarations", () => {
  rejects(replace("r0", { asn: 13335 }), /private ASN/);
  rejects(replace("r1", { asn: 65001 }), /gateway ASN is already used by another site/);
  rejects(replace("c1", { asn: 65002 }), /cluster ASN must differ/);
  rejects(replace("c1", { management: managed("cilium", "cilium") }), /owned by the cluster/);
  rejects(replace("r1", { address: undefined }), /needs a session address/);
  rejects(replace("r0", { originSubnetIds: ["blk1"] }), /router's own site/);
  rejects(replace("r0", { advertiseSubnetIds: ["blk0", "lan1"] }), /router's own site|inside an origin subnet/);
  rejects(replace("r0", { fabricIndex: 2 }), /fabricIndex is already used/);
  rejects(replace("r0", { routerId: "10.41.0.1" }), /routerId is already used/);
  rejects(replace("fab", { transports: [{ networkId: "native", preference: "primary", mode: "bgp", listenPortBase: 51800 }, { networkId: "cf", preference: "primary", mode: "bgp" }] }), /exactly one primary/);
  rejects(replace("fab", { transports: [{ networkId: "native", preference: "primary", mode: "static-fallback", listenPortBase: 51800 }] }), /only for a secondary/);
  rejects(replace("att0", { publicKey: "not-a-key" }), /WireGuard public key/);
  rejects(replace("att0", { privateKeyRef: undefined }), /privateKeyRef/);
  rejects(replace("cfatt0", { publicKey: key(9) }), /belongs to its provider/);
  rejects(replace("cfif0", { management: managed("wireguard", "wireguard") }), /stay externally managed/);
});

test("inventory keeps allocation authority with the allocator", () => {
  rejects(replace("ip0", { address: "10.90.0.2" }), /already allocated by/);
  rejects(replace("ip0", { address: "10.92.0.1" }), /inside its pool/);
  rejects(replace("ip0", { address: "10.90.0.0/32" }), /single IPv4 or IPv6 address/);
  rejects(replace("cfip0", { management: managed("heliopause", "ipam") }), /allocationAuthority is heliopause/);
  rejects([...inventory(), { ...base, management: ext("cilium"), id: "vip", kind: "address-allocation", poolId: "svc0", address: "10.40.192.10", state: "allocated" }], /Kubernetes allocates/);
  // An externally chosen VIP in a load-balancer pool is recordable.
  assert.deepEqual(issues([...inventory(), { ...base, management: ext("cilium"), id: "vip", kind: "address-allocation", poolId: "lb0", address: "10.40.127.1", state: "allocated" }]), []);
  // A load-balancer pool inside the Service range collides with ClusterIP allocation.
  rejects(replace("lb0", { subnetId: "k8s0", cidr: "10.40.200.0/24" }), /overlaps/);
});

test("two gateways in one site get no session between them and a warning", () => {
  const resources = inventory();
  resources.push(
    { ...base, management: ext("operator"), id: "n0b", kind: "node", siteId: "s0" },
    { ...base, management: ext("operator"), id: "g0b", kind: "gateway", nodeId: "n0b" },
    { ...base, management: managed("frr", "frr"), id: "r0b", kind: "bgp-router", nodeId: "n0b", role: "gateway", asn: 65001, routerId: "10.40.0.2", originSubnetIds: ["blk0"], fabricIndex: 9 },
    { ...base, management: managed("heliopause", "ipam"), id: "ip0b", kind: "address-allocation", poolId: "tunpool", address: "10.90.0.20", state: "allocated" },
    { ...base, management: managed("wireguard", "wireguard"), id: "att0b", kind: "fabric-attachment", fabricId: "fab", routerId: "r0b", networkId: "native", tunnelAllocationId: "ip0b", endpoint: doc(9), publicKey: key(9), privateKeyRef: { provider: "file", reference: "wg-0b" } },
  );
  const p = plan(resources);
  assert.ok(!p.sessions.some(s => s.routers.includes("r0") && s.routers.includes("r0b")));
  assert.equal(p.sessions.filter(s => s.transportNetworkId === "native").length, 6 + 3);
  assert.ok(!gw(p, "r0").wireguard.some(w => w.peerRouterId === "r0b"));
  assert.ok(p.warnings.some(w => w.includes("site s0") && w.includes("iBGP")));
});

test("management and tunnel pools inside a site block are never accepted from that site", () => {
  const resources = inventory();
  resources.push(
    { ...base, management: ext("operator"), id: "bmc1", kind: "address-pool", subnetId: "infra1", cidr: "10.41.100.0/24", allocationAuthority: "operator", purpose: "management" },
    { ...base, management: ext("operator"), id: "tun1", kind: "address-pool", subnetId: "infra1", cidr: "10.41.101.0/24", allocationAuthority: "operator", purpose: "tunnel" },
  );
  const lines = gw(plan(resources), "r0").frr.split("\n").filter(l => l.startsWith("ip prefix-list PL-SITE-") && l.includes("10.41.10"));
  assert.deepEqual(lines.map(l => l.replace(/^ip prefix-list \S+ seq \d+ /, "")), ["deny 10.41.100.0/24 le 32", "deny 10.41.101.0/24 le 32"]);
});

test("the offline CLI plans a fabric, reports per-gateway changes and has no apply path", () => {
  const dir = mkdtempSync(join(tmpdir(), "hp-fabric-cli-"));
  try {
    const path = join(dir, "input.json");
    const run = (extra: string[] = []) => spawnSync(process.execPath, ["bin/heliopause-network-compile.ts", "fabric", path, ...extra], { encoding: "utf8", timeout: 10000 });
    writeFileSync(path, JSON.stringify({ registry: { revision: 1, resources: inventory(4) }, expectedRegistryRevision: 1, fabricId: "fab" }));
    const first = run();
    assert.equal(first.status, 0, first.stderr);
    const out = JSON.parse(first.stdout);
    assert.equal(out.plan.executable, false);
    assert.deepEqual(out.changes.map((c: { change: string }) => c.change), ["added", "added", "added", "added"]);
    writeFileSync(path, JSON.stringify({ registry: { revision: 2, resources: inventory(5) }, expectedRegistryRevision: 2, fabricId: "fab", previous: out.plan }));
    const grown = JSON.parse(run().stdout);
    assert.deepEqual(grown.changes.map((c: { change: string }) => c.change), ["changed", "changed", "changed", "changed", "added"]);
    assert.equal(run(["--apply"]).status, 1);
    writeFileSync(path, JSON.stringify({ registry: { revision: 1, resources: inventory(4) }, expectedRegistryRevision: 1, fabricId: "fab", apply: true }));
    const bad = run();
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /unknown compiler input field/);
    writeFileSync(path, JSON.stringify({ registry: { revision: 1, resources: inventory(4) }, expectedRegistryRevision: 0, fabricId: "fab" }));
    assert.equal(run().status, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
