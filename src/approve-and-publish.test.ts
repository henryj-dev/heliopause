// `POST /approve-and-publish`: one person, one one-time code, approve and publish in one request.
//
// ## Why this exists
//
// A solo operator approved with one code and then had to wait for the next TOTP window to publish:
// the IdP refuses a code at or below the last step it accepted (`otp.ts`), so the second request
// could not reuse the first code. The two-person rule was already off for them by role
// (`soloApprovalRoles`); the wait bought nothing but a 30-second pause between two clicks.
//
// ## What this pins
//
// The route is the existing approval and the existing publish, joined behind one code. So the cases
// below are mostly refusals — who may not use it, and that each refusal spends no code and leaves the
// plan as it was — plus the one property the join adds: a publish that fails after the approval
// leaves the plan approved, so the ordinary publish button still works.
//
// A real relay and a real OIDC session, because the thing under test is identity (which role the
// session carries, which name it collapses onto) and the seam to the relay.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:https";
import { execFileSync } from "node:child_process";
import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { startManager } from "./manager-server.ts";
import { startRelay } from "./relay.ts";
import { initializeRevocationSnapshot } from "./revocation-snapshot.ts";
import { startRevocationWriter } from "./revocation-writer.ts";
import { CSRF_HEADER } from "./session.ts";
import type { PlanBundle } from "./bundle.ts";
import { AUTHORIZED_ARTIFACT_BUNDLE_FILE } from "./artifact-signature.ts";
import { SCHEMA_VERSION, type Manifest } from "./protocol.ts";

const dir = mkdtempSync(join(tmpdir(), "hp-solo-pub-"));
const read = (f: string) => readFileSync(join(dir, f));
const sha = (s: string) => "sha256:" + createHash("sha256").update(s).digest("hex");
const closers: Array<() => void> = [];
let port = 0;
const logs: string[] = [];

// ── the IdP's one-time-code check, with KeyStone's replay rule ────────────────────────────────────
//
// KeyStone refuses a code at or below the last TOTP step it accepted. A set of used codes is the
// same property for a test that never advances a clock: a code works once.
const otpAsked: string[] = [];
const otpUsed = new Set<string>();
/** Runs while the IdP is "checking" this code — the window between the route's pre-check and approval. */
const duringOtp = new Map<string, () => Promise<void>>();
const otpFetch = (async (_u: string | URL, init?: RequestInit) => {
  const { code } = JSON.parse(String(init?.body ?? "{}")) as { code: string };
  otpAsked.push(code);
  await duringOtp.get(code)?.();
  if (code === "000000" || otpUsed.has(code)) return new Response(JSON.stringify({ ok: false }), { status: 401 });
  otpUsed.add(code);
  return new Response(JSON.stringify({ ok: true }), { status: 200 });
}) as unknown as typeof fetch;

/** A fresh six-digit code per call, so no test spends one another test needs. */
let nextCode = 100000;
const code = () => String(nextCode++);

// ── OIDC ──────────────────────────────────────────────────────────────────────────────────────────
const ROLE_CHANGE_EVENT = "https://idp.example.invalid/event/role-change";
const idpKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
let mintNonce = "";
let mintGroups: string[] = [];
const oidcFetch = (async (u: string | URL) => {
  const url = String(u);
  if (url.endsWith("/.well-known/openid-configuration")) {
    return new Response(JSON.stringify({
      issuer: "https://idp.example.invalid",
      authorization_endpoint: "https://idp.example.invalid/oidc/authorize",
      token_endpoint: "https://idp.example.invalid/oidc/token",
      jwks_uri: "https://idp.example.invalid/oidc/jwks",
      code_challenge_methods_supported: ["S256"],
    }), { status: 200 });
  }
  if (url.endsWith("/oidc/jwks")) {
    return new Response(JSON.stringify({
      keys: [{ ...idpKey.publicKey.export({ format: "jwk" }), kid: "k1", use: "sig", alg: "ES256" }],
    }), { status: 200 });
  }
  const now = Math.floor(Date.now() / 1000);
  const header = b64({ alg: "ES256", kid: "k1", typ: "JWT" });
  const payload = b64({
    iss: "https://idp.example.invalid", aud: "heliopause-manager", sub: "idp-sub-1",
    nonce: mintNonce, exp: now + 300, iat: now,
    email: "jang@example.invalid", email_verified: true, preferred_username: "henry", groups: mintGroups,
  });
  const sig = createSign("sha256").update(`${header}.${payload}`)
    .sign({ key: idpKey.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return new Response(JSON.stringify({ id_token: `${header}.${payload}.${sig}` }), { status: 200 });
}) as unknown as typeof fetch;

const ADMIN = ["heliopause-operators", "heliopause-writers", "heliopause-admins"];
const WRITER = ["heliopause-operators", "heliopause-writers"];

// ── PKI ───────────────────────────────────────────────────────────────────────────────────────────
function pki() {
  const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=test-ca");
  const leaf = (name: string, cn: string, eku: string, san?: string) => {
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", `/CN=${cn}`);
    writeFileSync(join(dir, `${name}.ext`), `extendedKeyUsage=critical,${eku}\n` + (san ? `subjectAltName=${san}\n` : ""));
    run("x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", `${name}.pem`, "-days", "1", "-extfile", `${name}.ext`);
  };
  leaf("mgr-server", "manager", "serverAuth", "IP:127.0.0.1");
  leaf("relay-server", "relay", "serverAuth", "IP:127.0.0.1");
  leaf("operator-alice", "ops-alice", "clientAuth");
  leaf("operator-jae", "ops-jae", "clientAuth");
  mkdirSync(join(dir, "relay-pki"), { recursive: true });
  writeFileSync(join(dir, "relay-pki", "ca.pem"), read("ca.pem"));
  leaf("operator-hp-manager", "hp-manager", "clientAuth");
  for (const ext of ["pem", "key"]) {
    writeFileSync(join(dir, "relay-pki", `operator-hp-manager.${ext}`), read(`operator-hp-manager.${ext}`));
  }
}

// ── HTTP ──────────────────────────────────────────────────────────────────────────────────────────
type Reply = { status: number; body: string; json: Record<string, unknown>; headers: Record<string, string | string[] | undefined> };

function call(
  path: string,
  method = "GET",
  headers: Record<string, string> = {},
  body?: unknown,
  cert?: "alice" | "jae",
): Promise<Reply> {
  const payload = body === undefined ? null : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const r = request({
      host: "127.0.0.1", port, path, method, ca: [read("ca.pem")],
      ...(cert ? { cert: read(`operator-${cert}.pem`), key: read(`operator-${cert}.key`) } : {}),
      headers: { ...(payload !== null ? { "content-type": "application/json" } : {}), ...headers },
    }, (res) => {
      let b = ""; res.on("data", (d) => (b += d));
      res.on("end", () => {
        let json: Record<string, unknown> = {};
        try { json = JSON.parse(b); } catch { /* not every body is JSON */ }
        resolve({ status: res.statusCode ?? 0, body: b, json, headers: res.headers });
      });
    });
    r.on("error", reject);
    if (payload !== null) r.write(payload);
    r.end();
  });
}

function cookiesFrom(res: Reply): string {
  return ([] as string[]).concat((res.headers["set-cookie"] as string[]) ?? [])
    .map((c) => c.split(";")[0]!).filter((c) => !c.endsWith("=")).join("; ");
}

/** A signed-in browser: the session cookie and the headers a write from the console carries. */
async function session(groups: string[]): Promise<Record<string, string>> {
  mintGroups = groups;
  const login = await call("/auth/login");
  const q = new URL(String(login.headers.location)).searchParams;
  mintNonce = q.get("nonce")!;
  const cb = await call(`/auth/callback?code=any&state=${encodeURIComponent(q.get("state")!)}`, "GET", { cookie: cookiesFrom(login) });
  assert.equal(cb.status, 302, `callback: ${cb.status} ${cb.body}`);
  const cookie = ([] as string[]).concat((cb.headers["set-cookie"] as string[]) ?? [])
    .map((c) => c.split(";")[0]!).find((c) => c.startsWith("__Host-heliopause-session="))!;
  const csrf = (await call("/plans", "GET", { cookie })).json.csrf as string;
  return { cookie, origin: `https://127.0.0.1:${port}`, [CSRF_HEADER]: csrf };
}

// ── plans ─────────────────────────────────────────────────────────────────────────────────────────
let generations = 0;
/** A bundle with a generation no other test uses, so the relay never sees one twice. */
function bundle(target: string): PlanBundle {
  const host = `gw-01.${target}`;
  const rules = JSON.stringify({
    nftables: [
      { add: { table: { family: "inet", name: "heliopause" } } },
      { add: { chain: { family: "inet", table: "heliopause", name: "input", type: "filter", hook: "input", prio: 0, policy: "drop" } } },
      { add: { rule: { family: "inet", table: "heliopause", chain: "input", expr: [{ accept: null }], comment: "BASE-SSH" } } },
    ],
  });
  const manifest: Manifest = {
    generation: `gen-solo-${++generations}`,
    issuedAt: "2026-10-10T00:00:00.000Z",
    schemaVersion: SCHEMA_VERSION,
    hosts: { [host]: { stage: "canary", rulesetHash: sha(rules), confirmTimeoutSec: 120, mustContain: ["BASE-SSH"], expectFilters: [] } },
  };
  return { manifest, rulesets: { [host]: rules }, workload: {} };
}

/** The manager's clock. Moved forward only by the test that needs a plan to expire. */
let clockOffsetMs = 0;

async function proposeAs(
  headers: Record<string, string>, target = "dev", cert?: "alice" | "jae", b = bundle(target),
): Promise<string> {
  const r = await call("/plan", "POST", headers, { target, bundle: b }, cert);
  assert.equal(r.status, 200, `propose: ${r.body}`);
  return r.json.hash as string;
}

async function planRow(headers: Record<string, string>, hash: string) {
  const plans = (await call("/plans", "GET", { cookie: headers.cookie! })).json.plans as Array<{
    hash: string; approval: { by: string; solo?: boolean } | null; publishedAt: string | null;
  }>;
  return plans.find((p) => p.hash === hash);
}

before(async () => {
  pki();
  const artifactDir = join(dir, "artifacts");
  mkdirSync(artifactDir, { recursive: true });
  const revocationFile = join(dir, "relay-revocations.json");
  const revocationWriterSocket = join(dir, "rw.sock");
  await initializeRevocationSnapshot(revocationFile);
  const writer = await startRevocationWriter({ snapshotFile: revocationFile, socketPath: revocationWriterSocket, log: () => {} });
  closers.push(() => writer.server.close());
  const relay = await startRelay({
    artifactDir, port: 0, hostname: "127.0.0.1",
    tls: { certFile: join(dir, "relay-server.pem"), keyFile: join(dir, "relay-server.key"), caFile: join(dir, "ca.pem") },
    operatorCNs: ["hp-manager"], publisherCNs: ["hp-manager"],
    revocationFile, revocationWriterSocket, log: () => {},
  });
  closers.push(() => relay.server.close());
  const relayPort = (relay.server.address() as { port: number }).port;

  const manager = await startManager({
    port: 0, hostname: "127.0.0.1",
    relays: [
      { name: "dev", url: `https://127.0.0.1:${relayPort}/`, pkiDir: join(dir, "relay-pki") },
      // Nothing listens on port 1. The publish that follows a successful approval fails here, which
      // is the case where the two halves of this route come apart.
      { name: "down", url: "https://127.0.0.1:1/", pkiDir: join(dir, "relay-pki") },
    ],
    tls: { certFile: join(dir, "mgr-server.pem"), keyFile: join(dir, "mgr-server.key"), caFile: join(dir, "ca.pem") },
    operatorCNs: ["ops-alice", "ops-jae"], writerCNs: ["ops-alice", "ops-jae"],
    oidc: {
      issuer: "https://idp.example.invalid", clientId: "heliopause-manager",
      redirectUri: "https://heliopause.example.invalid/auth/callback",
      roleChangeEvent: ROLE_CHANGE_EVENT,
      operatorGroups: ["heliopause-operators"], writerGroups: ["heliopause-writers"],
      soloApprovalRoles: ["heliopause-admins"],
      aliases: new Map([["jang@example.invalid", "ops-alice"]]),
      fetchImpl: oidcFetch,
    },
    otp: {
      issuerUrl: "https://otp.example.invalid", serviceToken: "svc",
      users: new Map([["ops-alice", "keystone-alice"], ["ops-jae", "keystone-jae"]]),
      fetchImpl: otpFetch,
    },
    artifactSigning: { privateKey: generateKeyPairSync("ed25519").privateKey },
    now: () => new Date(Date.now() + clockOffsetMs),
    timeoutMs: 1_000,
    publishTimeoutMs: 3_000,
    log: (m) => logs.push(m),
  });
  port = (manager.server.address() as { port: number }).port;
  closers.push(() => manager.server.close());
});

after(() => {
  for (const c of closers) c();
  rmSync(dir, { recursive: true, force: true });
});

describe("approve and publish with one code", () => {
  it("approves and publishes a solo operator's own plan on one code — the known positive", async () => {
    const admin = await session(ADMIN);
    const hash = await proposeAs(admin);
    const asked = otpAsked.length;
    const logged = logs.length;

    // Under /api/, which is where the console sends it.
    const r = await call("/api/approve-and-publish", "POST", admin, { hash, otp: code() });

    assert.equal(r.status, 200, r.body);
    assert.equal(r.json.published, true);
    assert.equal(r.json.approved, true);
    assert.equal(r.json.combined, true);
    assert.deepEqual([r.json.proposedBy, r.json.approvedBy, r.json.publishedBy], ["ops-alice", "ops-alice", "ops-alice"]);
    // One code for both halves. Two would be the old behaviour with a new URL.
    assert.equal(otpAsked.length - asked, 1, "the route asked the IdP more or less than once");
    // The serving generation is the relay's own report: the push landed.
    assert.match(String(r.json.serving), /^gen-solo-/);

    const row = await planRow(admin, hash);
    // Published plans leave the pending list, so the record of the approval is the log below.
    assert.equal(row, undefined, "a published plan is still listed as pending");

    // Both events, each marked as one half of a combined action.
    const fresh = logs.slice(logged);
    const approved = fresh.filter((l) => l.includes(`plan ${hash.slice(0, 20)} approved by ops-alice`));
    const published = fresh.filter((l) => /published gen-solo-\d+ to dev/.test(l));
    assert.equal(approved.length, 1, `no single approval line:\n${fresh.join("\n")}`);
    assert.equal(published.length, 1, `no single publish line:\n${fresh.join("\n")}`);
    assert.match(approved[0]!, /SOLO APPROVAL/);
    assert.match(approved[0]!, /combined approve\+publish, one one-time code/);
    assert.match(published[0]!, /combined approve\+publish, one one-time code/);
  });

  it("signs the published artifact as a solo authorization", async () => {
    // The combined route must not launder a solo approval into a two-person one on the wire: the
    // agent's record of who authorised what reads `authorizationMode`.
    const admin = await session(ADMIN);
    const hash = await proposeAs(admin);
    const r = await call("/approve-and-publish", "POST", admin, { hash, otp: code() });
    assert.equal(r.status, 200, r.body);
    const signed = JSON.parse(readFileSync(join(dir, "artifacts", AUTHORIZED_ARTIFACT_BUNDLE_FILE), "utf8")) as {
      artifacts: Record<string, { payload: string }>;
    };
    const payload = JSON.parse(Buffer.from(signed.artifacts["gw-01.dev"]!.payload, "base64url").toString("utf8"));
    assert.equal(payload.authorizationMode, "solo-otp");
  });
});

describe("approve and publish refuses before spending a code", () => {
  // Every refusal here is decided by facts the server already holds. Asking the IdP first would burn
  // the operator's code — and its rate-limit budget — on a request that was going to fail anyway.

  it("refuses a writer without the solo role, even for their own plan", async () => {
    const writer = await session(WRITER);
    const hash = await proposeAs(writer);
    const asked = otpAsked.length;
    const r = await call("/approve-and-publish", "POST", writer, { hash, otp: code() });
    assert.equal(r.status, 403, r.body);
    assert.match(r.body, /solo approval/);
    assert.equal(otpAsked.length, asked, "a code was spent on a refusal the server could decide alone");
    assert.equal((await planRow(writer, hash))?.approval, null, "the plan was approved anyway");
  });

  it("refuses a certificate caller, who can never approve their own plan", async () => {
    // A certificate carries no role claim, so `maySoloApprove` is false for every CLI caller.
    const hash = await proposeAs({}, "dev", "alice");
    const asked = otpAsked.length;
    const r = await call("/approve-and-publish", "POST", {}, { hash, otp: code() }, "alice");
    assert.equal(r.status, 403, r.body);
    assert.equal(otpAsked.length, asked);
    const admin = await session(ADMIN);
    assert.equal((await planRow(admin, hash))?.approval, null);
  });

  it("refuses someone else's plan — that is the two-person path, unchanged", async () => {
    const hash = await proposeAs({}, "dev", "jae");
    const admin = await session(ADMIN);
    const asked = otpAsked.length;
    const r = await call("/approve-and-publish", "POST", admin, { hash, otp: code() });
    assert.equal(r.status, 403, r.body);
    assert.match(r.body, /proposed by ops-jae/);
    assert.equal(otpAsked.length, asked);
    assert.equal((await planRow(admin, hash))?.approval, null, "another operator's plan was approved");
  });

  it("refuses a hash this manager does not hold", async () => {
    const admin = await session(ADMIN);
    const asked = otpAsked.length;
    const r = await call("/approve-and-publish", "POST", admin, { hash: "sha256:" + "e".repeat(64), otp: code() });
    assert.equal(r.status, 404, r.body);
    assert.equal(otpAsked.length, asked);
  });

  it("refuses a plan that is already approved — the ordinary publish button is the way on", async () => {
    const admin = await session(ADMIN);
    const hash = await proposeAs(admin);
    assert.equal((await call("/approve", "POST", admin, { hash, otp: code() })).status, 200);
    const asked = otpAsked.length;
    const r = await call("/approve-and-publish", "POST", admin, { hash, otp: code() });
    assert.equal(r.status, 409, r.body);
    assert.match(r.body, /already approved/);
    assert.equal(otpAsked.length, asked);
  });
});

describe("approve and publish decides again after the code", () => {
  it("refuses when the plan became someone else's while the IdP was checking the code", async () => {
    // The pre-check runs before an `await` on the IdP. In that window the plan can expire and another
    // operator can propose the same bundle — same target, same bytes, so the same hash, now with them
    // as the proposer. `approve` accepts that as an ordinary two-person approval; the combined route
    // must not, or one code publishes another operator's plan.
    const admin = await session(ADMIN);
    const b = bundle("dev");
    const hash = await proposeAs(admin, "dev", undefined, b);
    const c = code();
    duringOtp.set(c, async () => {
      clockOffsetMs += 11 * 60 * 1000;
      assert.equal(await proposeAs({}, "dev", "jae", b), hash, "the re-proposal did not reproduce the hash");
    });

    const r = await call("/approve-and-publish", "POST", admin, { hash, otp: c });

    assert.equal(r.status, 403, r.body);
    assert.match(r.body, /proposed by ops-jae/);
    const row = await planRow(admin, hash);
    assert.equal(row?.approval, null, "one code approved another operator's plan");
    assert.equal(row?.publishedAt, null);
  });
});

describe("approve and publish with a bad code", () => {
  it("does neither on a wrong code", async () => {
    const admin = await session(ADMIN);
    const hash = await proposeAs(admin);
    const r = await call("/approve-and-publish", "POST", admin, { hash, otp: "000000" });
    assert.equal(r.status, 401, r.body);
    const row = await planRow(admin, hash);
    assert.equal(row?.approval, null, "a wrong code approved the plan");
    assert.equal(row?.publishedAt, null);
  });

  it("does neither on a code that was already used", async () => {
    const admin = await session(ADMIN);
    const spent = code();
    const first = await proposeAs(admin);
    assert.equal((await call("/approve", "POST", admin, { hash: first, otp: spent })).status, 200);
    const hash = await proposeAs(admin);
    const r = await call("/approve-and-publish", "POST", admin, { hash, otp: spent });
    assert.equal(r.status, 401, r.body);
    assert.equal((await planRow(admin, hash))?.approval, null, "a replayed code approved the plan");
  });

  it("does neither with no code at all", async () => {
    const admin = await session(ADMIN);
    const hash = await proposeAs(admin);
    const r = await call("/approve-and-publish", "POST", admin, { hash });
    assert.equal(r.status, 401, r.body);
    assert.equal((await planRow(admin, hash))?.approval, null);
  });
});

describe("approve and publish when the publish half fails", () => {
  it("leaves the plan approved, and the ordinary publish still reaches it", async () => {
    const admin = await session(ADMIN);
    const hash = await proposeAs(admin, "down");
    const logged = logs.length;
    const r = await call("/approve-and-publish", "POST", admin, { hash, otp: code() });

    assert.equal(r.status, 502, r.body);
    assert.equal(r.json.approved, true, "the answer must say the approval stood");
    assert.equal(r.json.published, false);
    const row = await planRow(admin, hash);
    assert.equal(row?.approval?.by, "ops-alice", "the approval was rolled back with the publish");
    assert.equal(row?.approval?.solo, true);
    assert.equal(row?.publishedAt, null, "a failed push left the plan claimed");
    assert.equal(
      logs.slice(logged).filter((l) => l.includes(`plan ${hash.slice(0, 20)} approved by ops-alice`)).length, 1,
      "the approval that stood was not logged",
    );

    // The way on is the existing button with a fresh code. It fails again here only because the
    // relay is still down — 502, not 403 "not approved", is what says the plan is where it should be.
    const again = await call("/publish", "POST", admin, { hash, otp: code() });
    assert.equal(again.status, 502, again.body);
  });
});
