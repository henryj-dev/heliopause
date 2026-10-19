import { test } from "node:test";
import assert from "node:assert/strict";
import { validateNetworkInventory, type NetworkInventoryResource } from "./network-inventory.ts";

function fixture(): NetworkInventoryResource[] {
  const base = { owner: "team", management: { mode: "external", provider: "inventory" } as const, generation: 2, observedGeneration: 1 };
  return [
    { ...base, kind: "site", id: "site" },
    { ...base, kind: "node", id: "node", siteId: "site" },
    { ...base, kind: "gateway", id: "gateway", nodeId: "node" },
    { ...base, kind: "network", id: "network", siteId: "site" },
    { ...base, kind: "subnet", id: "subnet", networkId: "network", cidr: "192.0.2.0/24" },
    { ...base, kind: "address-pool", id: "pool", subnetId: "subnet", cidr: "192.0.2.0/25", allocationAuthority: "external-dhcp" },
    { ...base, kind: "interface", id: "interface", nodeId: "node", networkId: "network", name: "example0" },
    { ...base, kind: "route", id: "route", interfaceId: "interface", destination: "0.0.0.0/0", table: 254 },
  ];
}
function messages(input: unknown) { return validateNetworkInventory(input).map(x => x.message).join("\n"); }

test("complete external inventory accepts independent administrative and allocation owners", () => {
  assert.deepEqual(validateNetworkInventory(fixture()), []);
});
test("managed and explicitly adopted records require driver ownership and adoption evidence", () => {
  const data = fixture();
  data[0]!.management = { mode: "managed", provider: "linux", driver: "nmstate" };
  data[1]!.management = { mode: "adopted", provider: "linux", driver: "nmstate", adoption: { approvedBy: "operator", source: "snapshot" } };
  assert.deepEqual(validateNetworkInventory(data), []);
  assert.match(messages([{ ...data[1], management: { mode: "adopted", provider: "linux", driver: "nmstate" } }]), /adoption requires/);
  assert.match(messages([{ ...data[0], management: { mode: "managed", provider: "linux", driver: ["a", "b"] } }]), /one driver/);
  assert.match(messages([{ ...data[0], management: { mode: "external", provider: "linux", driver: "nmstate" } }]), /external resources cannot/);
});
test("untrusted documents reject malformed identities, generations and reference kinds", () => {
  assert.match(messages(null), /must be an array/);
  assert.match(messages([null]), /must be an object/);
  assert.match(messages([{ id: "", kind: "future", generation: 0 }]), /id must be nonempty/);
  assert.match(messages([{ ...fixture()[0], observedGeneration: 3 }]), /observedGeneration/);
  const data = fixture();
  data.push({ ...data[0]! });
  data[1] = { ...data[1]!, siteId: "network" } as NetworkInventoryResource;
  assert.match(messages(data), /duplicate id/);
  assert.match(messages(data), /siteId must reference a site/);
});
test("subnets overlap only within one network address domain", () => {
  const data = fixture();
  const subnet = data[4]!;
  data.push({ ...subnet, id: "overlap", cidr: "192.0.2.128/25" } as NetworkInventoryResource);
  assert.match(messages(data), /CIDR overlaps subnet/);
  data.pop();
  data.push({ ...data[3]!, id: "isolated" });
  data.push({ ...subnet, id: "reuse", networkId: "isolated" } as NetworkInventoryResource);
  assert.deepEqual(validateNetworkInventory(data), []);
});
test("IPv6 containment and overlapping pool checks use full 128-bit ranges", () => {
  const data = fixture();
  data[4] = { ...data[4]!, cidr: "2001:db8::/48" } as NetworkInventoryResource;
  data[5] = { ...data[5]!, cidr: "2001:db8:0:1::/64" } as NetworkInventoryResource;
  assert.deepEqual(validateNetworkInventory(data), []);
  data.push({ ...data[5]!, id: "pool2", cidr: "2001:db8:0:1::/80" } as NetworkInventoryResource);
  assert.match(messages(data), /CIDR overlaps pool/);
  data.pop();
  data[5] = { ...data[5]!, cidr: "2001:db8:1::/64" } as NetworkInventoryResource;
  assert.match(messages(data), /pool must be contained/);
  data[5] = { ...data[5]!, cidr: "192.0.2.0/25" } as NetworkInventoryResource;
  assert.match(messages(data), /pool must be contained/);
});
test("CIDR parsing rejects ambiguous prefixes and unaligned bases", () => {
  for (const cidr of ["192.0.2.1/24", "192.0.2.0/", "192.0.2.0/2e1", "192.0.2.0", "2001:db8::1/64", "2001:db8::/129"]) {
    const data = fixture();
    data[4] = { ...data[4]!, cidr } as NetworkInventoryResource;
    assert.match(messages(data), /valid, aligned/, cidr);
  }
});
test("physical interface and route ownership cannot be duplicated under different ids", () => {
  const data = fixture();
  data.push({ ...data[6]!, id: "duplicate-interface" });
  data.push({ ...data[7]!, id: "duplicate-route", interfaceId: "duplicate-interface" } as NetworkInventoryResource);
  assert.match(messages(data), /interface already has/);
  assert.match(messages(data), /route destination and table already have/);
  data.pop(); data.pop();
  data.push({ ...data[7]!, id: "other-table", table: 100 } as NetworkInventoryResource);
  assert.deepEqual(validateNetworkInventory(data), []);
});
test("cross-site interfaces and missing allocation authority are rejected", () => {
  const data = fixture();
  data.push({ ...data[0]!, id: "other-site" });
  data[3] = { ...data[3]!, siteId: "other-site" } as NetworkInventoryResource;
  data[5] = { ...data[5]!, allocationAuthority: "" } as NetworkInventoryResource;
  assert.match(messages(data), /same site/);
  assert.match(messages(data), /allocationAuthority/);
});

test("JSON arrays and objects cannot masquerade as resource or management enums", () => {
  for (const kind of [["node"], { toString: "node" }, null, 1]) {
    assert.match(messages([{ ...fixture()[0], kind }]), /unknown resource kind/);
  }
  for (const mode of [["external"], ["managed"], ["adopted"], {}, null, 1]) {
    assert.match(messages([{ ...fixture()[0], management: { mode, provider: "p", driver: "d" } }]), /management requires/);
  }
});

test("malformed JSON identifiers return issues without invoking object string conversion", () => {
  const bad = { toString: null };
  assert.match(messages([{ ...fixture()[0], id: bad }]), /id must be nonempty/);
  for (const [index, field] of [[5, "subnetId"], [7, "interfaceId"]] as const) {
    const data: unknown[] = fixture();
    data[index] = { ...(data[index] as object), [field]: bad };
    assert.match(messages(data), new RegExp(`${field} must reference`));
  }
});

function v2Fixture(): NetworkInventoryResource[] {
  const data = fixture();
  const base = data[0]!;
  data.push({ ...base, id: "domain", kind: "routing-domain", name: "Shared", isolation: "global" });
  data[3] = { ...base, id: "network", kind: "network", siteId: "site", scope: "site-local", routingDomainId: "domain", purpose: "infrastructure" };
  data[5] = { ...data[5]!, purpose: "infrastructure" } as NetworkInventoryResource;
  data[7] = { ...data[7]!, routingDomainId: "domain" } as NetworkInventoryResource;
  return data;
}

test("v2 scenario 1: separate networks in the same routing domain cannot claim overlapping CIDRs", () => {
  const data = v2Fixture();
  assert.deepEqual(validateNetworkInventory(data), []);
  data.push({ ...data[3]!, id: "second-network" });
  data.push({ ...data[4]!, id: "second-subnet", networkId: "second-network" } as NetworkInventoryResource);
  assert.match(messages(data), /CIDR overlaps subnet/);
});
test("v2 scenario 2: isolated routing domains can reuse IPv4 and IPv6 prefixes", () => {
  const data = v2Fixture();
  data.push({ ...data[8]!, id: "isolated" });
  data.push({ ...data[3]!, id: "second-network", routingDomainId: "isolated" } as NetworkInventoryResource);
  data.push({ ...data[4]!, id: "second-subnet", networkId: "second-network" } as NetworkInventoryResource);
  assert.deepEqual(validateNetworkInventory(data), []);
  for (const id of ["subnet", "second-subnet"]) {
    const i = data.findIndex(r => r.id === id);
    data[i] = { ...data[i]!, cidr: "2001:db8::/48" } as NetworkInventoryResource;
  }
  data.splice(5, 1); // Remove the IPv4 pool; it cannot be a child of an IPv6 subnet.
  assert.deepEqual(validateNetworkInventory(data), []);
});
test("v2 scenario 3: explicit subnet hierarchy permits containment but rejects siblings and cycles", () => {
  const data = v2Fixture();
  data.push({ ...data[4]!, id: "child-a", cidr: "192.0.2.0/25", parentSubnetId: "subnet" } as NetworkInventoryResource);
  data.push({ ...data[4]!, id: "child-b", cidr: "192.0.2.128/26", parentSubnetId: "subnet" } as NetworkInventoryResource);
  data.push({ ...data[4]!, id: "child-c", cidr: "192.0.2.192/26", parentSubnetId: "subnet" } as NetworkInventoryResource);
  assert.deepEqual(validateNetworkInventory(data), []);
  data.push({ ...data[4]!, id: "sibling-conflict", cidr: "192.0.2.192/27", parentSubnetId: "subnet" } as NetworkInventoryResource);
  assert.match(messages(data), /CIDR overlaps child-c/);
  data.pop();
  data[4] = { ...data[4]!, parentSubnetId: "child-a" } as NetworkInventoryResource;
  assert.match(messages(data), /acyclic/);
  assert.match(messages(data), /strict subdivision/);
});
test("v2 scenario 4: transit and overlay memberships accept gateways at three sites", () => {
  const data = v2Fixture();
  data[3] = { ...data[0]!, kind: "network", id: "network", scope: "transit", siteIds: ["site", "site-b", "site-c"], routingDomainId: "domain", purpose: "backbone" };
  for (const suffix of ["b", "c"]) {
    data.push({ ...data[0]!, id: `site-${suffix}` });
    data.push({ ...data[1]!, id: `node-${suffix}`, siteId: `site-${suffix}` } as NetworkInventoryResource);
    data.push({ ...data[2]!, id: `gateway-${suffix}`, nodeId: `node-${suffix}` } as NetworkInventoryResource);
    data.push({ ...data[6]!, id: `interface-${suffix}`, nodeId: `node-${suffix}` } as NetworkInventoryResource);
  }
  assert.deepEqual(validateNetworkInventory(data), []);
  data[3] = { ...data[3]!, scope: "overlay" } as NetworkInventoryResource;
  assert.deepEqual(validateNetworkInventory(data), []);
});
test("v2 scenario 5: one interface cannot be claimed by competing drivers", () => {
  const data = v2Fixture();
  data[6]!.management = { mode: "managed", provider: "linux", driver: "nmstate" };
  data.push({ ...data[6]!, id: "frr-interface", kind: "interface", nodeId: "node", networkId: "network", name: "example0", management: { mode: "managed", provider: "linux", driver: "frr" } });
  assert.match(messages(data), /interface already has an inventory owner/);
});
test("v2 scenario 6: static writer conflicts are distinct from normal learned BGP candidates", () => {
  const data = v2Fixture();
  data[7]!.management = { mode: "managed", provider: "linux", driver: "static" };
  data.push({ ...data[7]!, id: "frr-writer", kind: "route", interfaceId: "interface", destination: "0.0.0.0/0", table: 254, routingDomainId: "domain", management: { mode: "managed", provider: "linux", driver: "frr" } });
  assert.match(messages(data), /already have an inventory owner/);
  data.pop();
  for (const peer of ["peer-a", "peer-b"]) data.push({ ...data[0]!, id: peer, kind: "learned-route", management: { mode: "external", provider: "frr" }, interfaceId: "interface", routingDomainId: "domain", table: 254, destination: "0.0.0.0/0", protocol: "bgp", source: peer, stage: "learned" });
  assert.deepEqual(validateNetworkInventory(data), []);
  data[data.length - 1]!.management = { mode: "managed", provider: "linux", driver: "frr" };
  assert.match(messages(data), /external observations/);
});
test("v2 scenario 7: Kubernetes pools reserve distinct ranges without transferring allocation authority", () => {
  const data = v2Fixture();
  data[5] = { ...data[5]!, purpose: "kubernetes-pod", allocationAuthority: "kubernetes" } as NetworkInventoryResource;
  data.push({ ...data[5]!, id: "service-pool", cidr: "192.0.2.128/25", purpose: "kubernetes-service" } as NetworkInventoryResource);
  assert.deepEqual(validateNetworkInventory(data), []);
  data[5] = { ...data[5]!, allocationAuthority: "heliopause" } as NetworkInventoryResource;
  assert.match(messages(data), /retain kubernetes allocation authority/);
  data[5] = { ...data[5]!, allocationAuthority: "kubernetes" } as NetworkInventoryResource;
  data.push({ ...data[4]!, id: "child", cidr: "192.0.2.0/25", parentSubnetId: "subnet" } as NetworkInventoryResource);
  data.push({ ...data[5]!, id: "child-pool", subnetId: "child" } as NetworkInventoryResource);
  assert.match(messages(data), /CIDR overlaps pool/);
});
test("v2 scenario 8: invalid site, gateway, domain and hierarchy references fail", () => {
  const data = v2Fixture();
  data[3] = { ...data[0]!, kind: "network", id: "network", scope: "transit", siteIds: ["missing"], routingDomainId: "missing", purpose: "backbone" };
  data[2] = { ...data[2]!, nodeId: "site" } as NetworkInventoryResource;
  assert.match(messages(data), /unique existing siteIds/);
  assert.match(messages(data), /routingDomainId must reference/);
  assert.match(messages(data), /nodeId must reference a node/);
  assert.match(messages(data), /explicit network membership/);
});
test("v2 scenario 9: management networks require isolation and explicit connectivity consent", () => {
  const data = v2Fixture();
  data.push({ ...data[8]!, id: "management-domain" });
  data.push({ ...data[3]!, id: "management-network", purpose: "management", routingDomainId: "management-domain" } as NetworkInventoryResource);
  assert.deepEqual(validateNetworkInventory(data), []);
  data.push({ ...data[0]!, id: "connection", kind: "domain-connection", domainIds: ["domain", "management-domain"] });
  assert.match(messages(data), /explicit allowManagement/);
  data[data.length - 1] = { ...data[data.length - 1]!, allowManagement: true } as NetworkInventoryResource;
  assert.deepEqual(validateNetworkInventory(data), []);
  const i = data.findIndex(r => r.id === "management-network");
  data[i] = { ...data[i]!, routingDomainId: "domain" } as NetworkInventoryResource;
  assert.match(messages(data), /separate routing domain/);
});
test("v2 scenario 10: legacy fixtures work while partial v2 downgrade is rejected", () => {
  assert.deepEqual(validateNetworkInventory(fixture()), []);
  const data = v2Fixture();
  data.push({ ...fixture()[3]!, id: "legacy-mixed" });
  assert.match(messages(data), /migrate all legacy networks together/);
  const missingDomain = v2Fixture().filter(r => r.kind !== "routing-domain");
  assert.match(messages(missingDomain), /routingDomainId must reference/);
});
test("connected domains detect transitive IPv4 and IPv6 conflicts", () => {
  for (const cidr of ["192.0.2.0/24", "2001:db8::/48"]) {
    const data: NetworkInventoryResource[] = v2Fixture().filter(r => r.kind !== "address-pool");
    const subnet = data.find(r => r.kind === "subnet")!;
    const index = data.indexOf(subnet);
    data[index] = { ...subnet, cidr } as NetworkInventoryResource;
    for (const suffix of ["b", "c"]) data.push({ ...data.find(r => r.kind === "routing-domain")!, id: `domain-${suffix}` });
    data.push({ ...data.find(r => r.kind === "network")!, id: "network-c", routingDomainId: "domain-c" } as NetworkInventoryResource);
    data.push({ ...data[index]!, id: "subnet-c", networkId: "network-c" } as NetworkInventoryResource);
    assert.deepEqual(validateNetworkInventory(data), []);
    data.push({ ...data[0]!, id: "ab", kind: "domain-connection", domainIds: ["domain", "domain-b"] });
    data.push({ ...data[0]!, id: "bc", kind: "domain-connection", domainIds: ["domain-b", "domain-c"] });
    assert.match(messages(data), /connected routing domain/);
  }
});
test("VRF bindings constrain routes while logical domains need no kernel binding", () => {
  const data = v2Fixture();
  data[8] = { ...data[8]!, isolation: "vrf", vrf: { name: "example-vrf", table: 100 } } as NetworkInventoryResource;
  assert.match(messages(data), /route table must match/);
  data[7] = { ...data[7]!, table: 100 } as NetworkInventoryResource;
  assert.deepEqual(validateNetworkInventory(data), []);
});
test("malformed JSON generation cannot throw during observed generation validation", () => {
  assert.match(messages([{ ...fixture()[0], generation: { toString: null }, observedGeneration: 1 }]), /generation must be/);
});

test("explicit route domain cannot be silently ignored in a legacy inventory", () => {
  const data = fixture();
  data[7] = { ...data[7]!, routingDomainId: "missing" } as NetworkInventoryResource;
  assert.match(messages(data), /routingDomainId must reference/);
  assert.match(messages(data), /migrate all legacy networks together/);
});
