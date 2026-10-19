import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:https";
import { startRelay } from "./relay.ts";
import { SCHEMA_VERSION } from "./protocol.ts";
import { startManager } from "./manager-server.ts";
import { NetworkObservationStore } from "./network-observation.ts";
import { createHash } from "node:crypto";

const dir = mkdtempSync(join(tmpdir(), "hp-network-api-"));
const read = (f: string) => readFileSync(join(dir, f));
const site = { id: "site", kind: "site", owner: "team", management: { mode: "external", provider: "inventory" }, generation: 1 };
let port = 0;
let server: Awaited<ReturnType<typeof startManager>>["server"];
before(async () => {
  const ssl = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=network-test-ca");
  for (const name of ["server", "reader", "writer", "host"]) {
    ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", `/CN=${name}`);
    writeFileSync(join(dir, "leaf.ext"), `extendedKeyUsage=${name === "server" ? "serverAuth" : "clientAuth"}\n${name === "server" ? "subjectAltName=IP:127.0.0.1\n" : ""}`);
    ssl("x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", `${name}.pem`, "-days", "1", "-extfile", "leaf.ext");
  }
  writeFileSync(join(dir, "operator-writer.pem"), read("writer.pem"));
  writeFileSync(join(dir, "operator-writer.key"), read("writer.key"));
  const started = await startManager({ port: 0, hostname: "127.0.0.1", relays: [{ name: "example", url: "https://127.0.0.1:1", pkiDir: dir }],
    tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
    operatorCNs: ["reader", "writer"], writerCNs: ["writer"], log: () => {},
    networkRegistryFile: join(dir, "registry.json"), networkObservationsDir: join(dir, "observations") });
  server = started.server;
  port = (server.address() as { port: number }).port;
});
after(async () => { if (server) await new Promise<void>(resolve => server.close(() => resolve())); rmSync(dir, { recursive: true, force: true }); });
function call(path: string, method = "GET", who = "reader", body?: unknown, headers: Record<string, string> = {}) {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise<{ status: number; body: any }>((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, path, method, agent: false, signal: AbortSignal.timeout(5000), ca: read("ca.pem"),
      ...(who === "none" ? {} : { cert: read(`${who}.pem`), key: read(`${who}.key`) }), headers: { "content-type": "application/json", ...(payload === undefined ? {} : { "content-length": String(Buffer.byteLength(payload)) }), ...headers } }, res => {
      let text = ""; res.on("data", chunk => text += chunk); res.on("end", () => resolve({ status: res.statusCode!, body: JSON.parse(text) }));
    });
    req.on("error", reject); req.end(payload);
  });
}

test("registry API authenticates readers and denies read-only writers and cross-site certificate requests", async () => {
  assert.equal((await call("/api/network/inventory", "GET", "none")).status, 401);
  assert.equal((await call("/api/network/inventory")).status, 200);
  assert.equal((await call("/api/network/inventory", "POST", "reader", { expectedRevision: 0, resource: site })).status, 403);
  for (const method of ["POST", "PUT", "DELETE"]) {
    assert.equal((await call(method === "DELETE" ? "/api/network/inventory/site" : "/api/network/inventory", method, "writer", { expectedRevision: 0, resource: site }, { origin: "https://untrusted.example.invalid" })).status, 403);
  }
});
test("registry CRUD and revision history use trusted actor and CAS", async () => {
  const created = await call("/api/network/inventory", "POST", "writer", { expectedRevision: 0, resource: site, updatedBy: "forged-admin", actor: "forged-admin" });
  assert.equal(created.status, 201);
  assert.equal(created.body.updatedBy, "writer");
  assert.equal((await call("/api/network/inventory/site")).body.resource.id, "site");
  assert.equal((await call("/api/network/inventory", "POST", "writer", { expectedRevision: 0, resource: { ...site, id: "stale" } })).status, 409);
  const updated = await call("/api/network/inventory/site", "PUT", "writer", { expectedRevision: 1, resource: { ...site, owner: "other-team" } });
  assert.equal(updated.status, 200);
  assert.equal(updated.body.resources[0].generation, 2);
  const history = await call("/api/network/revisions");
  assert.deepEqual(history.body.history.map((r: any) => r.actor), ["writer", "writer"]);
  const deleted = await call("/api/network/inventory/site", "DELETE", "writer", { expectedRevision: 2 });
  assert.equal(deleted.status, 200);
  assert.equal(deleted.body.resources.length, 0);
});
test("registry API atomically imports legacy inventory and rejects reference deletion/adoption/body abuse", async () => {
  const resource = { ...site, id: "legacy" };
  const imported = await call("/api/network/inventory", "PUT", "writer", { expectedRevision: 3, resources: [resource, { ...site, id: "node", kind: "node", siteId: "legacy" }] });
  assert.equal(imported.status, 200);
  assert.equal((await call("/api/network/inventory/legacy", "DELETE", "writer", { expectedRevision: 4 })).status, 409);
  const adopted = { ...resource, management: { mode: "adopted", provider: "linux", driver: "nmstate", adoption: { approvedBy: "writer", source: "snapshot" } } };
  assert.equal((await call("/api/network/inventory/legacy", "PUT", "writer", { expectedRevision: 4, resource: adopted })).status, 403);
  assert.equal((await call("/api/network/inventory", "POST", "writer", undefined, { "content-length": "600000" })).status, 413);
  assert.equal((await call("/api/network/inventory")).body.revision, 4);
});
test("observation API preserves scoped stale cache and reports relay outage rather than fresh network health", async () => {
  assert.equal((await call("/api/network/observations", "GET", "none")).status, 401);
  const cache = new NetworkObservationStore(join(dir, "observations", createHash("sha256").update("example").digest("hex")));
  const stamp = new Date(Date.now() - 3600000).toISOString();
  cache.put("node.example.invalid", { schemaVersion: 1, collectionId: "00000000-0000-4000-8000-000000000001", startedAt: stamp, completedAt: stamp,
    observations: { links: { status: "success", startedAt: stamp, completedAt: stamp, data: [] } }, capabilities: { links: { available: true, status: "success" } } }, { source: "example", relayReceivedAt: stamp });
  const list = await call("/api/network/observations");
  assert.equal(list.status, 200);
  assert.equal(list.body.relays[0].status, "unavailable");
  assert.equal(list.body.observations[0].freshness, "stale");
  assert.equal(list.body.observations[0].collectors.links.status, "success");
  assert.equal(list.body.observations[0].collectors.links.freshness, "stale");
  assert.equal(list.body.observations[0].collectors["wg-peers"].status, "never-observed");
  assert.equal((await call("/api/network/observations/example/node.example.invalid")).body.observation.host, "node.example.invalid");
  assert.equal((await call("/api/network/observations/wrong/node.example.invalid")).status, 404);
  assert.equal((await call("/api/network/observations", "POST", "writer", {})).status, 405);
});

test("real authenticated Agent upload reaches Manager cache and survives Manager restart with Relay down", async () => {
  const relay = await startRelay({ port: 0, hostname: "127.0.0.1", artifactDir: join(dir, "relay-artifacts"),
    tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") }, operatorCNs: ["writer"], log: () => {} });
  const stamp = new Date().toISOString();
  relay.state.manifest = { generation: "example-generation", issuedAt: stamp, schemaVersion: SCHEMA_VERSION,
    hosts: { host: { stage: "canary", rulesetHash: "sha256:example", confirmTimeoutSec: 90, mustContain: [] } } };
  const policyBefore = JSON.stringify({ manifest: relay.state.manifest, statuses: relay.state.statuses, lastSeen: relay.state.lastSeen });
  const report = { schemaVersion: 1, collectionId: "00000000-0000-4000-8000-000000000002", startedAt: stamp, completedAt: stamp,
    observations: { links: { status: "success", startedAt: stamp, completedAt: stamp, data: [{ ifindex: 2, ifname: "example0", mtu: 1420 }] } }, capabilities: { links: { available: true, status: "success" } } };
  const relayPort = (relay.server.address() as { port: number }).port;
  const upload = () => new Promise<number>((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port: relayPort, path: "/network/observations", method: "POST", agent: false, signal: AbortSignal.timeout(5000),
      ca: read("ca.pem"), cert: read("host.pem"), key: read("host.key") }, res => { res.resume(); res.on("end", () => resolve(res.statusCode!)); });
    req.on("error", reject); req.end(JSON.stringify({ host: "host", report }));
  });
  const options = { port: 0, hostname: "127.0.0.1", relays: [{ name: "live", url: `https://127.0.0.1:${relayPort}`, pkiDir: dir, operatorName: "writer" }],
    tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
    operatorCNs: ["reader", "writer"], writerCNs: ["writer"], log: () => {}, networkObservationsDir: join(dir, "live-cache") };
  let manager: Awaited<ReturnType<typeof startManager>> | undefined;
  let relayClosed = false;
  const originalPort = port;
  try {
    assert.equal(await upload(), 200);
    assert.equal(JSON.stringify({ manifest: relay.state.manifest, statuses: relay.state.statuses, lastSeen: relay.state.lastSeen }), policyBefore, "observation upload cannot confirm or mutate policy heartbeat state");
    manager = await startManager(options); port = (manager.server.address() as { port: number }).port;
    const live = await call("/api/network/observations/live/host");
    assert.equal(live.status, 200);
    assert.equal(live.body.relayStatus, "available");
    assert.equal(live.body.observation.report.collectionId, report.collectionId);
    assert.equal(live.body.observation.report.observations.links.data[0].mtu, 1420);
    assert.equal(live.body.observation.source, "live");
    const firstReceived = live.body.observation.receivedAt;
    await new Promise<void>(resolve => manager!.server.close(() => resolve())); manager = undefined;
    await new Promise<void>(resolve => relay.server.close(() => resolve())); relayClosed = true;
    manager = await startManager(options); port = (manager.server.address() as { port: number }).port;
    const cached = await call("/api/network/observations/live/host");
    assert.equal(cached.status, 200);
    assert.equal(cached.body.relayStatus, "unavailable");
    assert.equal(cached.body.observation.receivedAt, firstReceived);
    assert.equal(cached.body.observation.report.collectionId, report.collectionId);
  } finally {
    port = originalPort;
    if (manager) await new Promise<void>(resolve => manager!.server.close(() => resolve()));
    if (!relayClosed) await new Promise<void>(resolve => relay.server.close(() => resolve()));
  }
});
