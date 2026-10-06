// `/api/certificates` end to end: a real relay, a real manager, real TLS on both hops.
//
// The certificates are observed on the wire — the agent's by the relay, the relay's by the manager —
// so the only test that says they are read is one where there is a wire. The pure assembly is
// `cert-inventory.test.ts`; this file is about whether the readings reach it.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { initializeEnrollmentDocument } from "./enrollment-store.ts";
import { startManager } from "./manager-server.ts";
import { startRelay } from "./relay.ts";
import { SCHEMA_VERSION, type Heartbeat, type Manifest } from "./protocol.ts";

const dir = mkdtempSync(join(tmpdir(), "hp-cert-endpoint-"));
const pki = join(dir, "pki");
const operatorsDir = join(dir, "known-operators");
const store = join(dir, "enrollment.json");
const closers: Array<() => void> = [];
let relayPort = 0;
let relayServer: Awaited<ReturnType<typeof startRelay>>["server"];
let managerPort = 0;

const issue = (...a: string[]) => execFileSync("node", ["bin/heliopause-pki.ts", "issue", pki, ...a], { stdio: "pipe" });
const fingerprint = (file: string) =>
  new X509Certificate(readFileSync(file)).fingerprint256.replaceAll(":", "").toLowerCase();

type Answer = { status: number; body: any; headers: Record<string, string | string[] | undefined> };

/** One HTTPS request. `as` picks the client certificate; `token` sends a bearer instead of one. */
function call(port: number, path: string, opts: { as?: string; token?: string; method?: "GET" | "POST"; body?: unknown } = {}) {
  return new Promise<Answer>((resolve, reject) => {
    const payload = opts.body === undefined ? "" : JSON.stringify(opts.body);
    const req = request({
      host: "127.0.0.1", port, path, method: opts.method ?? "GET", ca: readFileSync(join(pki, "ca.pem")),
      ...(opts.as ? { cert: readFileSync(join(pki, `${opts.as}.pem`)), key: readFileSync(join(pki, `${opts.as}.key`)) } : {}),
      headers: {
        ...(payload ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } : {}),
        ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      },
      signal: AbortSignal.timeout(10_000),
    }, (res) => {
      let text = "";
      res.on("data", (p) => (text += p));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: text ? JSON.parse(text) : null, headers: res.headers }));
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const manifest: Manifest = {
  generation: "g1",
  issuedAt: "2026-10-06T00:00:00Z",
  schemaVersion: SCHEMA_VERSION,
  hosts: {
    "web-01.dev": { stage: "canary", rulesetHash: "sha256:1", confirmTimeoutSec: 60, mustContain: [] },
    // Listed and never heard from: the expected set must count it even though nothing reports it.
    "k3s-01.dev": { stage: "general", rulesetHash: "sha256:2", confirmTimeoutSec: 60, mustContain: [] },
  },
};

const heartbeat = (host: string): Heartbeat => ({
  host, agentVersion: "0.1.0-pull", schemaVersion: SCHEMA_VERSION,
  applied: { generation: null, state: "none", artifactHash: null, observedHash: null },
});

before(async () => {
  execFileSync("node", ["bin/heliopause-pki.ts", "init", pki], { stdio: "pipe" });
  issue("gw-01.dev", "--role=relay", "--san=127.0.0.1");
  issue("manager", "--role=relay", "--san=127.0.0.1");
  issue("hp-manager", "--role=operator");
  issue("ops", "--role=operator");
  // Five days: inside the critical window, so the fleet view has something to say about it.
  issue("web-01.dev", "--role=agent", "--days=5");

  mkdirSync(operatorsDir);
  copyFileSync(join(pki, "operator-ops.pem"), join(operatorsDir, "ops.pem"));
  writeFileSync(join(operatorsDir, "broken.pem"), "not a certificate\n");

  const artifactDir = join(dir, "artifacts");
  mkdirSync(artifactDir);
  const relay = await startRelay({
    artifactDir, port: 0, hostname: "127.0.0.1",
    tls: { certFile: join(pki, "relay-gw-01.dev.pem"), keyFile: join(pki, "relay-gw-01.dev.key"), caFile: join(pki, "ca.pem") },
    operatorCNs: ["hp-manager"],
    log: () => {},
  });
  relay.state.manifest = manifest;
  relayServer = relay.server;
  relayPort = (relay.server.address() as { port: number }).port;
  closers.push(() => relay.server.close());

  initializeEnrollmentDocument(store);
  const manager = await startManager({
    port: 0, hostname: "127.0.0.1",
    relays: [
      { name: "dev", url: `https://127.0.0.1:${relayPort}/`, pkiDir: pki, operatorName: "hp-manager" },
      // Configured and not there. The report must not get shorter because of it.
      { name: "prod", url: "https://127.0.0.1:1/", pkiDir: pki, operatorName: "hp-manager" },
    ],
    tls: { certFile: join(pki, "relay-manager.pem"), keyFile: join(pki, "relay-manager.key"), caFile: join(pki, "ca.pem") },
    operatorCNs: ["ops"],
    writerCNs: ["ops"],
    enrollment: { storeFile: store },
    knownOperatorsDir: operatorsDir,
    otp: {
      issuerUrl: "https://idp.example.invalid",
      serviceToken: "svc",
      users: new Map([["ops", "keystone-user-1"]]),
      fetchImpl: (async (_u: string | URL, init?: RequestInit) =>
        new Response(JSON.stringify({ ok: JSON.parse(String(init?.body ?? "{}")).code === "123456" }), {
          status: JSON.parse(String(init?.body ?? "{}")).code === "123456" ? 200 : 401,
        })) as unknown as typeof fetch,
    },
    timeoutMs: 2_000,
    log: () => {},
  });
  managerPort = (manager.server.address() as { port: number }).port;
  closers.push(() => manager.server.close());

  const beat = await call(relayPort, "/heartbeat", { as: "agent-web-01.dev", method: "POST", body: heartbeat("web-01.dev") });
  assert.equal(beat.status, 200, JSON.stringify(beat.body));
});

after(() => {
  for (const c of closers) c();
  rmSync(dir, { recursive: true, force: true });
});

describe("GET /api/certificates", () => {
  it("reports the agent's certificate as the relay saw it on the heartbeat", async () => {
    const r = await call(managerPort, "/api/certificates", { as: "operator-ops" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const agent = r.body.certificates.find((c: any) => c.kind === "agent");
    assert.ok(agent, "no agent row");
    assert.equal(agent.host, "web-01.dev");
    assert.equal(agent.vpc, "dev");
    assert.equal(agent.sha256, fingerprint(join(pki, "agent-web-01.dev.pem")));
    assert.equal(agent.state, "critical");
    assert.equal(agent.observedBy, "relay:dev");
    assert.equal(agent.source, "wire");
  });

  it("reports the relay's server certificate as the manager saw it on the wire", async () => {
    const r = await call(managerPort, "/api/certificates", { as: "operator-ops" });
    const relay = r.body.certificates.find((c: any) => c.kind === "relay-server" && c.vpc === "dev");
    assert.equal(relay?.sha256, fingerprint(join(pki, "relay-gw-01.dev.pem")));
    assert.equal(relay.cn, "gw-01.dev");
  });

  it("still reads the relay's certificate after the connection has closed", async () => {
    // The production shape: the relay closes an idle socket after 5 s and the console polls every
    // 10 s, so every poll but the first opens a new connection. A client that resumes the TLS session
    // there is handed an empty peer certificate. Shortened here so the socket closes between polls.
    relayServer.keepAliveTimeout = 50;
    const relayRow = async () => (await call(managerPort, "/api/certificates", { as: "operator-ops" }))
      .body.certificates.find((c: any) => c.kind === "relay-server" && c.vpc === "dev");
    assert.ok(await relayRow(), "first poll");
    await new Promise((r) => setTimeout(r, 300));
    assert.ok(await relayRow(), "second poll, on a new connection, lost the relay certificate");
  });

  it("reports its own certificates, the CA and the known operators from their files", async () => {
    const { body } = await call(managerPort, "/api/certificates", { as: "operator-ops" });
    const one = (kind: string, source: string, vpc: string | null = null) =>
      body.certificates.filter((c: any) => c.kind === kind && c.source === source && c.vpc === vpc);
    assert.equal(one("manager-server", "loaded")[0]?.sha256, fingerprint(join(pki, "relay-manager.pem")));
    assert.equal(one("manager-server", "file")[0]?.sha256, fingerprint(join(pki, "relay-manager.pem")));
    assert.equal(one("manager-client", "file", "dev")[0]?.sha256, fingerprint(join(pki, "operator-hp-manager.pem")));
    assert.equal(one("ca", "file", "dev")[0]?.sha256, fingerprint(join(pki, "ca.pem")));
    assert.equal(one("operator", "file")[0]?.cn, "ops");
    assert.equal(body.operatorsConfigured, true);
  });

  it("names what it could not see instead of reporting less", async () => {
    const { body } = await call(managerPort, "/api/certificates", { as: "operator-ops" });
    assert.equal(body.complete, false);
    const gaps = body.missing.map((m: any) => `${m.kind} ${m.vpc ?? "-"} ${m.host ?? "-"}`).sort();
    assert.deepEqual(gaps, [
      "agent dev k3s-01.dev",
      "agent prod -",
      "operator - -",
      "relay-server prod -",
    ]);
    assert.deepEqual(body.expected.byKind, {
      agent: 2, "relay-server": 2, "manager-client": 2, "manager-server": 2, ca: 2, operator: 2,
    });
  });

  it("answers an app token holding only certificates:read, and nothing else for it", async () => {
    const issued = await call(managerPort, "/enrollment/app-tokens", {
      as: "operator-ops", method: "POST",
      body: { otp: "123456", label: "cert-drift", scopes: ["certificates:read"], hostnamePattern: "*.dev" },
    });
    assert.equal(issued.status, 201, JSON.stringify(issued.body));
    const token = issued.body.token as string;

    const ok = await call(managerPort, "/api/certificates", { token });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.ok(ok.headers["x-heliopause-app-token-expires-at"]);
    // Fleet-wide: the `*.dev` pattern does not hide the prod relay's gap or the CA rows.
    assert.ok(ok.body.missing.some((m: any) => m.vpc === "prod"));
    assert.ok(ok.body.certificates.some((c: any) => c.kind === "ca"));
    assert.equal((await call(managerPort, "/certificates", { token })).status, 200);

    for (const [path, method] of [
      ["/site", "GET"], ["/api/site", "GET"], ["/enrollment/requests", "GET"], ["/enrollment/tokens", "POST"],
      ["/enrollment/app-tokens", "GET"], ["/plans", "GET"],
    ] as Array<[string, "GET" | "POST"]>) {
      const refused = await call(managerPort, path, { token, method, ...(method === "POST" ? { body: {} } : {}) });
      assert.equal(refused.status, 403, `${method} ${path} answered ${refused.status} to a certificates:read token`);
    }
  });

  it("does not answer an app token without certificates:read", async () => {
    const issued = await call(managerPort, "/enrollment/app-tokens", {
      as: "operator-ops", method: "POST",
      body: { otp: "123456", label: "queue-reader", scopes: ["enrollment:requests-read"], hostnamePattern: "*.dev" },
    });
    assert.equal(issued.status, 201, JSON.stringify(issued.body));
    assert.equal((await call(managerPort, "/api/certificates", { token: issued.body.token })).status, 403);
  });

  it("refuses a caller with neither a certificate nor a token", async () => {
    const r = await call(managerPort, "/api/certificates");
    assert.ok(r.status === 401 || r.status === 403, `answered ${r.status}`);
  });
});

describe("the fleet view", () => {
  it("lists a certificate inside the critical window under problems", async () => {
    const { status, body } = await call(managerPort, "/site", { as: "operator-ops" });
    assert.equal(status, 200);
    const line = body.problems.find((p: string) => p.includes("web-01.dev") && p.includes("certificate"));
    assert.match(line ?? "", /agent certificate dev web-01\.dev \(wire\): critical — [45] day\(s\) left/);
  });
});

describe("a renewed server certificate the manager has not restarted for", () => {
  it("shows as two different fingerprints — serving and on disk", async () => {
    const before = fingerprint(join(pki, "relay-manager.pem"));
    issue("manager", "--role=relay", "--san=127.0.0.1");
    const { body } = await call(managerPort, "/api/certificates", { as: "operator-ops" });
    const rows = body.certificates.filter((c: any) => c.kind === "manager-server");
    assert.equal(rows.find((c: any) => c.source === "loaded").sha256, before);
    assert.notEqual(rows.find((c: any) => c.source === "file").sha256, before);
  });
});
