import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile, execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { request } from "node:https";
import { NetworkObservationStore, observationFreshness, validateNetworkObservation, MAX_NETWORK_OBSERVATION_BYTES } from "./network-observation.ts";
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
test("real mTLS observation upload binds manifest CN, isolates policy confirmation and persists after relay restart", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hp-observation-tls-")); const pki = join(dir, "pki");
  const cli = (...args: string[]) => execFileSync("node", ["bin/heliopause-pki.ts", ...args], { stdio: "pipe" });
  cli("init", pki); cli("issue", pki, "relay", "--role=relay", "--san=127.0.0.1");
  for (const [name, role] of [["host", "agent"], ["outsider", "agent"], ["reader", "operator"]]) cli("issue", pki, name!, `--role=${role}`);
  const options = { artifactDir: join(dir, "artifacts"), hostname: "127.0.0.1", port: 0, tls: { certFile: join(pki, "relay-relay.pem"), keyFile: join(pki, "relay-relay.key"), caFile: join(pki, "ca.pem") }, operatorCNs: ["reader"], log: () => {} };
  let relay = await startRelay(options);
  const manifest = { generation: "g1", issuedAt: at, schemaVersion: SCHEMA_VERSION, hosts: { host: { stage: "canary" as const, rulesetHash: "sha256:1", confirmTimeoutSec: 90, mustContain: [] } } };
  relay.state.manifest = manifest;
  const call = (who: string, path: string, body?: unknown) => new Promise<{ status: number; body: any }>((resolve, reject) => {
    const port = (relay.server.address() as { port: number }).port;
    const req = request({ host: "127.0.0.1", port, path, method: body ? "POST" : "GET", ca: readFileSync(join(pki, "ca.pem")), cert: readFileSync(join(pki, `${who}.pem`)), key: readFileSync(join(pki, `${who}.key`)), agent: false }, res => { let raw = ""; res.on("data", d => raw += d); res.on("end", () => resolve({ status: res.statusCode!, body: JSON.parse(raw) })); });
    req.on("error", reject); req.end(body ? JSON.stringify(body) : undefined);
  });
  try {
    assert.equal((await call("agent-host", "/network/observations", { host: "other", report: report() })).status, 403);
    assert.equal((await call("agent-outsider", "/network/observations", { host: "outsider", report: report() })).status, 403);
    assert.equal((await call("operator-reader", "/network/observations", { host: "reader", report: report() })).status, 403);
    assert.equal((await call("agent-host", "/network/observations", { host: "host", report: { ...report(), schemaVersion: 99 } })).status, 400);
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
  } finally { await new Promise<void>(resolve => relay.server.close(() => resolve())); rmSync(dir, { recursive: true, force: true }); }
});
