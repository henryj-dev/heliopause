import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { NetworkRegistryStore, NetworkRegistryError, MAX_NETWORK_REGISTRY_RESOURCES } from "./network-registry.ts";

const site = (id = "site") => ({ id, kind: "site", owner: "team", management: { mode: "external", provider: "inventory" }, generation: 1 });
const base = (id: string, kind: string, fields = {}) => ({ ...site(id), kind, ...fields });
function setup(t: { after(fn: () => void): void }) {
  const dir = mkdtempSync(join(tmpdir(), "hp-network-registry-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return new NetworkRegistryStore(join(dir, "registry.json"));
}
const code = (expected: number) => (e: unknown) => e instanceof NetworkRegistryError && e.statusCode === expected;

test("desired inventory persists through store restart with private file permissions and authenticated audit", t => {
  const store = setup(t);
  assert.equal(store.read().revision, 0);
  const first = store.mutate(0, "operator", { action: "create", resource: site() });
  const restarted = new NetworkRegistryStore(store.path).read();
  assert.deepEqual(restarted, first);
  assert.equal(statSync(store.path).mode & 0o777, 0o600);
  assert.equal(first.updatedBy, "operator");
  assert.equal(first.history[0]?.actor, "operator");
  assert.match(first.history[0]?.changes[0]?.after ?? "", /^[a-f0-9]{64}$/);
});
test("resource generation and global revision are separate and no-op requests do not increment either", t => {
  const store = setup(t);
  store.mutate(0, "a", { action: "create", resource: site() });
  store.mutate(1, "b", { action: "create", resource: site("other") });
  assert.equal(store.read().resources.find(r => r.id === "site")?.generation, 1);
  const changed = store.mutate(2, "a", { action: "update", id: "site", resource: { ...site(), owner: "new-team" } });
  assert.equal(changed.revision, 3);
  const r = changed.resources.find(r => r.id === "site")!;
  assert.equal(r.generation, 2);
  assert.equal(store.mutate(3, "a", { action: "update", id: "site", resource: r }).revision, 3);
  assert.throws(() => store.mutate(3, "a", { action: "update", id: "site", resource: { ...r, generation: 90 } }), code(409));
});
test("CAS refusal leaves exact persisted document and audit unchanged", t => {
  const store = setup(t);
  store.mutate(0, "a", { action: "create", resource: site() });
  const before = readFileSync(store.path, "utf8");
  assert.throws(() => store.mutate(0, "b", { action: "create", resource: site("other") }), code(409));
  assert.equal(readFileSync(store.path, "utf8"), before);
});
test("whole inventory validation prevents invalid CIDRs and dangling references without partial writes", t => {
  const store = setup(t);
  const resources = [site(), base("network", "network", { siteId: "site" }), base("subnet", "subnet", { networkId: "network", cidr: "192.0.2.0/24" })];
  store.mutate(0, "a", { action: "replace", resources });
  assert.throws(() => store.mutate(1, "a", { action: "update", id: "subnet", resource: { ...resources[2], cidr: "192.0.2.1/24" } }), code(409));
  assert.throws(() => store.mutate(1, "a", { action: "create", resource: base("node", "node", { siteId: "missing" }) }), code(409));
  assert.equal(store.read().revision, 1);
});
test("routing domain collisions are rejected while explicit parent-child hierarchy persists", t => {
  const store = setup(t);
  const resources = [site(), base("domain", "routing-domain", { name: "example", isolation: "global" }),
    base("network", "network", { scope: "site-local", siteId: "site", routingDomainId: "domain", purpose: "infrastructure" }),
    base("parent", "subnet", { networkId: "network", cidr: "192.0.2.0/24" }),
    base("child", "subnet", { networkId: "network", cidr: "192.0.2.0/25", parentSubnetId: "parent" })];
  store.mutate(0, "a", { action: "replace", resources });
  assert.equal(store.read().resources.length, 5);
  assert.throws(() => store.mutate(1, "a", { action: "create", resource: base("conflict", "subnet", { networkId: "network", cidr: "192.0.2.0/24" }) }), code(409));
});
test("referenced deletion is refused; declaration deletion never executes infrastructure actions", t => {
  const store = setup(t);
  store.mutate(0, "a", { action: "replace", resources: [site(), base("node", "node", { siteId: "site" })] });
  assert.throws(() => store.mutate(1, "a", { action: "delete", id: "site" }), (e: unknown) => e instanceof NetworkRegistryError && e.statusCode === 409 && !!e.issues?.some(i => i.resourceId === "node"));
  store.mutate(1, "a", { action: "delete", id: "node" });
  assert.deepEqual(store.read().retiredIds, ["node"]);
  assert.throws(() => store.mutate(2, "a", { action: "create", resource: base("node", "node", { siteId: "site" }) }), code(409));
});
test("strings cannot authorize adoption, driver transfer or resource kind change", t => {
  const store = setup(t);
  store.mutate(0, "a", { action: "create", resource: site() });
  for (const management of [{ mode: "managed", provider: "linux", driver: "nmstate" }, { mode: "adopted", provider: "linux", driver: "nmstate", adoption: { approvedBy: "admin", source: "snapshot" } }]) {
    assert.throws(() => store.mutate(1, "a", { action: "update", id: "site", resource: { ...site(), management } }), code(403));
    if (management.mode === "adopted") assert.throws(() => store.mutate(1, "a", { action: "create", resource: { ...site("new"), management } }), code(403));
  }
  assert.throws(() => store.mutate(1, "a", { action: "update", id: "site", resource: { ...site(), kind: "node", siteId: "site" } }), code(409));
});
test("dynamic learned routes and observed generations cannot be persisted as desired state", t => {
  const store = setup(t);
  assert.throws(() => store.mutate(0, "a", { action: "create", resource: { ...site(), kind: "learned-route" } }), /learned routes belong/);
  assert.throws(() => store.mutate(0, "a", { action: "create", resource: { ...site(), observedGeneration: 1 } }), /observedGeneration/);
});
test("resource and byte ceilings reject expensive validation inputs", t => {
  const store = setup(t);
  assert.throws(() => store.mutate(0, "a", { action: "replace", resources: Array.from({ length: MAX_NETWORK_REGISTRY_RESOURCES + 1 }, (_, i) => site(`site-${i}`)) }), code(413));
  assert.throws(() => store.mutate(0, "a", { action: "create", resource: { ...site(), owner: "x".repeat(600000) } }), code(413));
});
test("corrupt or unknown store schema fails closed and is not overwritten", t => {
  const store = setup(t);
  writeFileSync(store.path, '{"schemaVersion":99}');
  assert.throws(() => store.read(), code(500));
  assert.throws(() => store.mutate(0, "a", { action: "create", resource: site() }), code(500));
  assert.equal(readFileSync(store.path, "utf8"), '{"schemaVersion":99}');
});
test("two actual processes using one revision cannot silently overwrite each other", async t => {
  const store = setup(t);
  const script = `import { NetworkRegistryStore } from ${JSON.stringify(new URL("./network-registry.ts", import.meta.url).href)}; const store=new NetworkRegistryStore(process.argv[1]); try { store.mutate(0,process.argv[2],{action:'create',resource:{id:process.argv[2],kind:'site',owner:'team',management:{mode:'external',provider:'inventory'},generation:1}}); process.stdout.write('saved'); } catch(e) { process.stdout.write(String(e.statusCode)); }`;
  const writer = (id: string) => new Promise<string>((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "--eval", script, store.path, id], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.on("data", chunk => out += chunk);
    child.stderr.on("data", chunk => err += chunk);
    child.on("error", reject);
    child.on("close", status => status === 0 ? resolve(out) : reject(new Error(err)));
  });
  assert.deepEqual((await Promise.all([writer("a"), writer("b")])).sort(), ["409", "saved"]);
  assert.equal(store.read().revision, 1);
  assert.equal(store.read().resources.length, 1);
});

test("interface and route ownership cannot transfer by changing ids or deleting then recreating claims", t => {
  const store = setup(t);
  const resources = [site(), base("node", "node", { siteId: "site" }), base("network", "network", { siteId: "site" }),
    base("iface", "interface", { nodeId: "node", networkId: "network", name: "example0" }),
    base("route", "route", { interfaceId: "iface", destination: "192.0.2.0/24", table: 254 })];
  store.mutate(0, "a", { action: "replace", resources });
  const managed = { mode: "managed", provider: "linux", driver: "nmstate" };
  assert.throws(() => store.mutate(1, "a", { action: "replace", resources: resources.map(r => r.id === "iface" ? { ...r, id: "replacement", management: managed } : r.id === "route" ? { ...r, interfaceId: "replacement" } : r) }), code(403));
  assert.throws(() => store.mutate(1, "a", { action: "replace", resources: resources.map(r => r.id === "route" ? { ...r, id: "other-route", management: managed } : r) }), code(403));
  store.mutate(1, "a", { action: "replace", resources: resources.slice(0, 3) });
  assert.throws(() => store.mutate(2, "a", { action: "create", resource: { ...resources[3], id: "replacement", management: managed } }), code(403));
  const restored = new NetworkRegistryStore(store.path);
  assert.equal(restored.read().ownershipClaims.length, 2);
  assert.throws(() => restored.mutate(2, "a", { action: "create", resource: { ...resources[3], id: "replacement", management: managed } }), code(403));
});

test("stored ownership claims must be unique and consistent with all active claims", t => {
  const store = setup(t);
  store.mutate(0, "a", { action: "replace", resources: [site(), base("node", "node", { siteId: "site" }), base("network", "network", { siteId: "site" }), base("iface", "interface", { nodeId: "node", networkId: "network", name: "example0" })] });
  const original = store.read();
  for (const ownershipClaims of [[], [...original.ownershipClaims, ...original.ownershipClaims], original.ownershipClaims.map(c => ({ ...c, management: { mode: "managed", provider: "linux", driver: "nmstate" } }))]) {
    writeFileSync(store.path, JSON.stringify({ ...original, ownershipClaims }));
    assert.throws(() => store.read(), code(500));
    assert.throws(() => store.mutate(1, "a", { action: "delete", id: "iface" }), code(500));
  }
});
