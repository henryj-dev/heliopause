import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile, execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { Agent, request } from "node:https";
import { createSecureContext } from "node:tls";
import { NetworkObservationStore, NetworkObservationStoreBusyError, observationFreshness, validateNetworkObservation, MAX_NETWORK_OBSERVATION_BYTES } from "./network-observation.ts";
import { startRelay } from "./relay.ts";
import { fetchNetworkObservations } from "./manager.ts";
import { SCHEMA_VERSION } from "./protocol.ts";

const at = "2026-01-01T00:00:00Z";
function report() { return { schemaVersion: 1, collectionId: "12345678-1234-1234-1234-123456789abc", startedAt: at, completedAt: at, observations: { links: { status: "success", startedAt: at, completedAt: at, data: [{ ifindex: 1, ifname: "example0", mtu: 1500 }] } }, capabilities: { links: { available: true, status: "success" } } }; }
test("strict runtime rejects secret fields, mismatched capabilities, old nested timestamps, size and schemas", () => {
  assert.equal(validateNetworkObservation(report()).schemaVersion, 1);
  const secret = report(); Object.assign(secret.observations.links.data[0]!, { privateKey: "hidden" });
  assert.throws(() => validateNetworkObservation(secret));
  const bad = report(); bad.capabilities.links.available = false; assert.throws(() => validateNetworkObservation(bad));
  const old = report(); old.observations.links.startedAt = "2025-01-01T00:00:00Z"; assert.throws(() => validateNetworkObservation(old));
  assert.throws(() => validateNetworkObservation({ ...report(), schemaVersion: 99 }));
  assert.throws(() => validateNetworkObservation({ ...report(), extra: "x".repeat(MAX_NETWORK_OBSERVATION_BYTES) }));
  const failed = report(); failed.observations.links.status = "timeout"; assert.throws(() => validateNetworkObservation(failed));
});
test("typed ingress rejects route/rule family mismatch and missing rule identity", () => {
  const check = (name: string, data: unknown) => {
    const original = report();
    return validateNetworkObservation({ ...original, observations: { [name]: { ...original.observations.links, data: [data] } }, capabilities: { [name]: original.capabilities.links } });
  };
  assert.throws(() => check("addresses", { ifindex: 2, ifname: "example0" }));
  assert.throws(() => check("routes4", { dst: "2001:db8::/64" }));
  assert.throws(() => check("routes4", { dst: "default", gateway: "2001:db8::1" }));
  assert.throws(() => check("routes6", { dst: "default", gateway: "192.0.2.1" }));
  assert.throws(() => check("rules4", { priority: 0 }));
  assert.throws(() => check("rules4", { priority: 0, src: "2001:db8::/64" }));
  assert.throws(() => check("frr-routes4", { addressFamily: "ipv6", prefix: "2001:db8::/64", valid: true, bestPath: true, nextHops: [] }));
  assert.throws(() => check("frr-routes6", { addressFamily: "ipv6", prefix: "192.0.2.0/24", valid: true, bestPath: true, nextHops: [] }));
  assert.equal(check("routes4", { dst: "default", gateway: "192.0.2.1" }).schemaVersion, 1);
  assert.equal(check("rules4", { priority: 0, src: "all" }).schemaVersion, 1);
  assert.equal(check("frr-routes6", { addressFamily: "ipv6", prefix: "2001:db8::/64", valid: true, bestPath: true, nextHops: [] }).schemaVersion, 1);
});
test("observations persist separately scoped hosts and duplicate/replayed reports cannot renew freshness", () => {
  const dir = mkdtempSync(join(tmpdir(), "hp-observation-store-"));
  try {
    const store = new NetworkObservationStore(dir); const first = store.put("host", report(), { source: "relay-a", relayReceivedAt: at });
    assert.deepEqual(new NetworkObservationStore(dir).get("host", "relay-a"), first);
    assert.equal(store.put("host", report(), { source: "relay-a" }).receivedAt, first.receivedAt);
    const replay = report(); replay.collectionId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    assert.equal(store.put("host", replay, { source: "relay-a" }).report.collectionId, first.report.collectionId);
    store.put("host", report(), { source: "relay-b" }); assert.equal(store.list().length, 2);
    assert.equal(observationFreshness(first, Date.parse(at) + 20 * 60_000), "stale");
    assert.equal(observationFreshness(null), "never-observed");
    assert.throws(() => store.put("../escape", report()));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("real mTLS observation upload binds manifest CN, isolates policy confirmation and persists after relay restart", async t => {
  const dir = mkdtempSync(join(tmpdir(), "hp-observation-tls-")); const pki = join(dir, "pki");
  const cli = (...args: string[]) => execFileSync("node", ["bin/heliopause-pki.ts", ...args], { stdio: "pipe" });
  cli("init", pki); cli("issue", pki, "relay", "--role=relay", "--san=127.0.0.1");
  for (const [name, role] of [["host", "agent"], ["outsider", "agent"], ["reader", "operator"]]) cli("issue", pki, name!, `--role=${role}`);
  // Fixture credentials initialize TLS state, never an HTTP payload.
  const clientAgents = new Map(["agent-host", "agent-outsider", "operator-reader"].map(name => [name,
    new Agent({ secureContext: createSecureContext({ ca: readFileSync(join(pki, "ca.pem")), cert: readFileSync(join(pki, `${name}.pem`)), key: readFileSync(join(pki, `${name}.key`)) }), keepAlive: false, maxCachedSessions: 0 })]));
  const options = { artifactDir: join(dir, "artifacts"), hostname: "127.0.0.1", port: 0, tls: { certFile: join(pki, "relay-relay.pem"), keyFile: join(pki, "relay-relay.key"), caFile: join(pki, "ca.pem") }, operatorCNs: ["reader"], log: () => {} };
  let relay = await startRelay(options);
  const manifest = { generation: "g1", issuedAt: at, schemaVersion: SCHEMA_VERSION, hosts: { host: { stage: "canary" as const, rulesetHash: "sha256:1", confirmTimeoutSec: 90, mustContain: [] } } };
  relay.state.manifest = manifest;
  const call = (who: string, path: string, body?: unknown) => new Promise<{ status: number; body: any }>((resolve, reject) => {
    const port = (relay.server.address() as { port: number }).port;
    const req = request({ host: "127.0.0.1", port, path, method: body ? "POST" : "GET", agent: clientAgents.get(who) }, res => { let raw = ""; res.on("data", d => raw += d); res.on("end", () => resolve({ status: res.statusCode!, body: JSON.parse(raw) })); });
    req.on("error", reject); req.end(body ? JSON.stringify(body) : undefined);
  });
  try {
    assert.equal((await call("agent-host", "/network/observations", { host: "other", report: report() })).status, 403);
    assert.equal((await call("agent-outsider", "/network/observations", { host: "outsider", report: report() })).status, 403);
    assert.equal((await call("operator-reader", "/network/observations", { host: "reader", report: report() })).status, 403);
    assert.equal((await call("agent-host", "/network/observations", { host: "host", report: { ...report(), schemaVersion: 99 } })).status, 400);
    mkdirSync(join(options.artifactDir, "network-observations"), { recursive: true });
    const contentionLock = join(options.artifactDir, "network-observations", "store.lock");
    writeFileSync(contentionLock, "another writer");
    assert.equal((await call("agent-host", "/network/observations", { host: "host", report: report() })).status, 503);
    assert.deepEqual(relay.state.statuses, {}); assert.deepEqual(relay.state.lastSeen, {});
    unlinkSync(contentionLock);
    const uploaded = await call("agent-host", "/network/observations", { host: "host", report: report() }); assert.equal(uploaded.status, 200);
    // Invoke only the worker's transport with a synthetic report: no ip/wg/vtysh command runs.
    await new Promise<void>((resolve, reject) => {
      const pin = createHash("sha256").update(new X509Certificate(readFileSync(options.tls.certFile)).raw).digest("base64");
      execFile("python3", ["-c", "import sys,json;sys.path.insert(0,'agent');import network_discovery_worker as w;w.upload(json.loads(sys.argv[1]))", JSON.stringify(report())], {
        timeout: 10_000, env: { ...process.env, HELIOPAUSE_RELAY_URL: `https://127.0.0.1:${(relay.server.address() as {port:number}).port}`, HELIOPAUSE_HOST_ID: "host", HELIOPAUSE_CA_FILE: join(pki, "ca.pem"), HELIOPAUSE_CERT_FILE: join(pki, "agent-host.pem"), HELIOPAUSE_KEY_FILE: join(pki, "agent-host.key"), HELIOPAUSE_PINS: pin },
      }, error => error ? reject(error) : resolve());
    });
    assert.deepEqual(relay.state.statuses, {}); assert.deepEqual(relay.state.lastSeen, {});
    assert.equal((await call("agent-host", "/network/observations")).status, 403);
    const records = await fetchNetworkObservations({ name: "relay-a", url: `https://127.0.0.1:${(relay.server.address() as {port:number}).port}`, pkiDir: pki, operatorName: "reader" });
    assert.equal(records.length, 1); assert.equal(records[0]!.host, "host");
    await new Promise<void>(resolve => relay.server.close(() => resolve())); relay = await startRelay(options); relay.state.manifest = manifest;
    const after = await call("operator-reader", "/network/observations"); assert.equal(after.body.observations[0].receivedAt, uploaded.body.receivedAt);
    await t.test("obstructed optional observation storage preserves startup and heartbeat", async () => {
      await new Promise<void>(resolve => relay.server.close(() => resolve()));
      const spool = join(options.artifactDir, "network-observations");
      rmSync(spool, { recursive: true, force: true });
      writeFileSync(spool, "pre-existing unrelated file");
      relay = await startRelay(options); relay.state.manifest = manifest;
      assert.equal((await call("agent-host", "/healthz")).status, 200);
      const heartbeat = { host: "host", agentVersion: "0.1.0-pull", schemaVersion: SCHEMA_VERSION,
        applied: { generation: null, state: "none", artifactHash: null, observedHash: null } };
      assert.equal((await call("agent-host", "/heartbeat", heartbeat)).status, 200);
      assert.ok(Object.hasOwn(relay.state.statuses, "host"));
      const before = JSON.stringify({ statuses: relay.state.statuses, lastSeen: relay.state.lastSeen });
      assert.equal((await call("agent-host", "/network/observations", { host: "host", report: report() })).status, 503);
      assert.equal((await call("operator-reader", "/network/observations")).status, 503);
      assert.equal(JSON.stringify({ statuses: relay.state.statuses, lastSeen: relay.state.lastSeen }), before);
      assert.equal((await call("agent-host", "/heartbeat", heartbeat)).status, 200);
      assert.equal(readFileSync(spool, "utf8"), "pre-existing unrelated file");
    });
  } finally { for (const agent of clientAgents.values()) agent.destroy(); await new Promise<void>(resolve => relay.server.close(() => resolve())); rmSync(dir, { recursive: true, force: true }); }
});

test("contended telemetry writes fail immediately without sleeping the heartbeat event loop", () => {
  const dir = mkdtempSync(join(tmpdir(), "hp-observation-contention-"));
  try {
    const store = new NetworkObservationStore(dir);
    writeFileSync(join(dir, "store.lock"), "another writer");
    const wait = mock.method(Atomics, "wait", () => "timed-out" as const);
    try {
      assert.throws(() => store.put("host", report()), NetworkObservationStoreBusyError);
      assert.equal(wait.mock.callCount(), 0, "observation lock contention cannot synchronously wait beside policy heartbeats");
      assert.equal(readFileSync(join(dir, "store.lock"), "utf8"), "another writer");
    } finally { wait.mock.restore(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("clock and replay admission preserves evidence across updates and recovery", async t => {
  const dir = mkdtempSync(join(tmpdir(), "hp-observation-clock-"));
  let now = Date.parse(at);
  let store = new NetworkObservationStore(dir, { now: () => now });
  const make = (id: number, offset = 0) => {
    const value = report(); value.collectionId = id.toString(16).padStart(32, "0");
    const time = new Date(now + offset).toISOString();
    value.startedAt = value.completedAt = time;
    value.observations.links.startedAt = value.observations.links.completedAt = time;
    return value;
  };
  try {
    let current = store.put("host", make(1));
    await t.test("normal update advances current", () => { now += 1000; current = store.put("host", make(2)); assert.equal(current.report.collectionId, make(2).collectionId); });
    await t.test("same ID cannot renew receipt", () => { now += 1000; assert.deepEqual(store.put("host", make(2)), current); });
    await t.test("previous ID cannot return with changed timestamp", () => { assert.deepEqual(store.put("host", make(1)), current); });
    await t.test("excessive future timestamp cannot poison current", () => { assert.throws(() => store.put("host", make(3, 30_001)), /future skew/); assert.deepEqual(store.get("host"), current); });
    await t.test("allowed skew remains usable", () => { current = store.put("host", make(3, 30_000)); assert.equal(observationFreshness(current, now), "fresh"); });
    await t.test("agent clock recovery requires explicit audited CAS", () => {
      now -= 60_000;
      assert.equal(store.put("host", make(4)).report.collectionId, current.report.collectionId);
      assert.throws(() => store.recover("host", make(4), { expectedCollectionId: "wrong", actor: "operator", reason: "clock corrected" }));
      current = store.recover("host", make(4), { expectedCollectionId: current.report.collectionId, actor: "operator", reason: "clock corrected" });
      assert.equal(current.recovery?.actor, "operator"); assert.equal(current.report.collectionId, make(4).collectionId);
      assert.deepEqual(store.put("host", make(3)), current);
    });
    await t.test("relay receipt has independent clock tolerance", () => {
      now += 1000;
      assert.throws(() => store.put("host", make(5), { relayReceivedAt: new Date(now + 30_001).toISOString() }), /future skew/);
      current = store.put("host", make(5), { relayReceivedAt: new Date(now + 20_000).toISOString() });
      assert.equal(observationFreshness(current, now), "fresh");
    });
    await t.test("old collection stays stale despite new manager receipt", () => {
      now += 20 * 60_000;
      current = store.put("host", make(6, -15 * 60_000));
      assert.equal(observationFreshness(current, now), "stale");
    });
    await t.test("collector error then success advances without treating error as data", () => {
      const failed: any = make(7); failed.observations.links.status = "error"; delete failed.observations.links.data;
      failed.capabilities.links = { available: false, status: "error" };
      assert.equal(store.put("host", failed).report.observations.links!.status, "error");
      now += 1000; current = store.put("host", make(8)); assert.equal(current.report.observations.links!.status, "success");
    });
    await t.test("restart preserves replay history and receipt", () => {
      store = new NetworkObservationStore(dir, { now: () => now });
      assert.deepEqual(store.get("host"), current);
      assert.deepEqual(store.put("host", make(1)), current);
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("legacy future-poisoned disk state is recovered with archived evidence, not deleted", () => {
  const dir = mkdtempSync(join(tmpdir(), "hp-observation-legacy-"));
  const now = Date.parse(at);
  const path = join(dir, createHash("sha256").update(JSON.stringify(["", "host"])).digest("hex") + ".json");
  const poisoned = report(); poisoned.startedAt = poisoned.completedAt = "2099-01-01T00:00:00Z";
  poisoned.observations.links.startedAt = poisoned.observations.links.completedAt = poisoned.completedAt;
  const previous = { host: "host", receivedAt: poisoned.completedAt, report: poisoned };
  writeFileSync(path, JSON.stringify(previous));
  try {
    const store = new NetworkObservationStore(dir, { now: () => now });
    const replacement = report(); replacement.collectionId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    assert.deepEqual(store.put("host", replacement), previous);
    const recovered = store.recover("host", replacement, { expectedCollectionId: poisoned.collectionId, actor: "operator", reason: "verified clock repair" });
    const digest = createHash("sha256").update(JSON.stringify(previous)).digest("hex");
    assert.deepEqual(JSON.parse(readFileSync(join(dir, `recovery-${createHash("sha256").update(JSON.stringify(["", "host"])).digest("hex")}-${digest}.json`), "utf8")), previous);
    assert.equal(store.list().length, 1); assert.equal(observationFreshness(recovered, now), "fresh");
    assert.throws(() => store.recover("host", { ...replacement, collectionId: "cccccccc-cccc-cccc-cccc-cccccccccccc" }, { expectedCollectionId: replacement.collectionId, actor: "operator", reason: "unnecessary" }), /future-poisoned/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});


test("freshness fails closed for missing receipts and invalid clock policies", () => {
  const valid = { host: "host", receivedAt: at, report: report() };
  for (const receivedAt of [undefined, null, ""]) assert.equal(observationFreshness({ ...valid, receivedAt } as any, Date.parse(at)), "stale");
  assert.equal(observationFreshness({ ...valid, source: "relay-a" }, Date.parse(at)), "stale");
  for (const age of [-1, Infinity, NaN, 600001]) assert.equal(observationFreshness(valid, Date.parse(at), age), "stale");
  assert.equal(observationFreshness(valid, NaN), "stale");
});

test("metadata cannot override identity or report and duplicate recovery cannot bypass CAS", () => {
  const dir = mkdtempSync(join(tmpdir(), "hp-observation-projection-"));
  let now = Date.parse(at);
  try {
    const store = new NetworkObservationStore(dir, { now: () => now });
    const first = store.put("host", report(), { host: "other", report: { invalid: true }, receivedAt: "2099-01-01T00:00:00Z" } as any);
    assert.equal(first.host, "host"); assert.equal(first.receivedAt, new Date(now).toISOString()); assert.equal(first.report.schemaVersion, 1);
    now -= 60000;
    const corrected = report();
    corrected.startedAt = corrected.completedAt = new Date(now).toISOString();
    corrected.observations.links.startedAt = corrected.observations.links.completedAt = corrected.completedAt;
    assert.throws(() => store.recover("host", corrected, { expectedCollectionId: "wrong", actor: "operator", reason: "repair" }), /matching/);
    assert.throws(() => store.recover("host", corrected, { expectedCollectionId: first.report.collectionId, actor: "operator", reason: "repair" }), /new collection ID/);
    assert.throws(() => store.recover("host", corrected, { expectedCollectionId: first.report.collectionId, actor: "operator", reason: null } as any), /invalid recovery/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});


test("calendar-invalid timestamps are rejected without normalization", () => {
  const invalid = report(); invalid.startedAt = "2026-02-30T00:00:00Z"; invalid.completedAt = invalid.startedAt;
  invalid.observations.links.startedAt = invalid.observations.links.completedAt = invalid.startedAt;
  assert.throws(() => validateNetworkObservation(invalid), /envelope/);
  assert.equal(observationFreshness({ host: "host", receivedAt: invalid.startedAt, report: report() }, Date.parse("2026-03-02T00:00:00Z")), "stale");
});
