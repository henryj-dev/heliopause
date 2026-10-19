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
