import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import {
  createAppToken, initializeEnrollmentDocument, loadEnrollmentDocument, withEnrollmentTransaction,
} from "./enrollment-store.ts";
import { startManager } from "./manager-server.ts";

const root = mkdtempSync(join(tmpdir(), "heliopause-enrollment-server-"));
const pki = join(root, "pki"); const store = join(root, "enrollment.json");
let port = 0; let close = () => {};

const managerOptions = (storeFile: string): Parameters<typeof startManager>[0] => ({
  port: 0,
  hostname: "127.0.0.1",
  relays: [{ name: "dev", url: "https://127.0.0.1:1", pkiDir: pki }],
  tls: { certFile: join(pki, "relay-manager.pem"), keyFile: join(pki, "relay-manager.key"), caFile: join(pki, "ca.pem") },
  operatorCNs: ["ops"],
  writerCNs: ["ops"],
  enrollment: { storeFile, trustedCaFiles: new Map([["dev", join(pki, "ca.pem")]]) },
  revocationFile: storeFile,
});

function call(path: string, method: "GET" | "POST", body?: unknown, mode: "operator" | "agent" = "operator", token?: string, target = port) {
  return new Promise<{ status: number; body: any }>((resolve, reject) => {
    const payload = body === undefined ? "" : JSON.stringify(body);
    const req = request({ host: "127.0.0.1", port: target, path, method, ca: readFileSync(join(pki, "ca.pem")),
      ...(mode === "operator" ? { cert: readFileSync(join(pki, "operator-ops.pem")), key: readFileSync(join(pki, "operator-ops.key")) } : {}),
      headers: { ...(payload ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) },
    }, (res) => { let text = ""; res.on("data", (part) => text += part); res.on("end", () => resolve({ status: res.statusCode ?? 0, body: JSON.parse(text) })); });
    req.setTimeout(5_000, () => req.destroy(new Error(`request timed out: ${method} ${path}`)));
    req.on("error", reject); if (payload) req.write(payload); req.end();
  });
}

before(async () => {
  execFileSync("node", ["bin/heliopause-pki.ts", "init", pki]);
  execFileSync("node", ["bin/heliopause-pki.ts", "issue", pki, "manager", "--role=relay", "--san=127.0.0.1"]);
  execFileSync("node", ["bin/heliopause-pki.ts", "issue", pki, "ops", "--role=operator"]);
  initializeEnrollmentDocument(store);
  const started = await startManager(managerOptions(store));
  port = (started.server.address() as { port: number }).port; close = () => started.server.close();
});
after(() => { close(); rmSync(root, { recursive: true, force: true }); });

describe("manager standalone enrollment API", () => {
  it("refuses a non-boolean revokeExisting without revoking the existing token", async () => {
    const created = await call("/enrollment/tokens", "POST", { hostname: "node-keep.dev" });
    assert.equal(created.status, 201);
    const rowId = created.body.id as string;
    const malformed = await call("/enrollment/tokens", "POST", { hostname: "node-keep.dev", revokeExisting: "false" });
    assert.equal(malformed.status, 400);
    const row = loadEnrollmentDocument(store).tokens.find((token) => token.id === rowId);
    assert.equal(row?.revokedAt, null);
  });

  it("refuses missing or malformed configured enrollment state at startup", async () => {
    const missing = join(root, "missing-enrollment.json");
    await assert.rejects(startManager(managerOptions(missing)), /enrollment store is unavailable/);
    assert.equal(existsSync(missing), false, "manager startup must not initialize durable state");

    const malformed = join(root, "malformed-enrollment.json");
    writeFileSync(malformed, JSON.stringify({ schemaVersion: 1, tokens: [], requests: [], audit: [], unknown: true }));
    await assert.rejects(startManager(managerOptions(malformed)), /unsupported fields/);
  });

  it("completes token, CSR, offline signing, upload and token-scoped fetch", { timeout: 15_000 }, async () => {
    const tokenAnswer = await call("/enrollment/tokens", "POST", { hostname: "node-03.dev", ttlSec: 600 });
    assert.equal(tokenAnswer.status, 201); const token = tokenAnswer.body.token as string;
    assert.equal(
      Date.parse(tokenAnswer.body.row.expiresAt) - Date.parse(tokenAnswer.body.row.createdAt),
      600_000,
      "the manager dropped the requested token TTL or omitted expiresAt",
    );
    const key = join(root, "host.key"); const csr = join(root, "host.csr");
    execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", key]);
    execFileSync("openssl", ["req", "-new", "-key", key, "-subj", "/CN=node-03.dev", "-out", csr]);
    const submitted = await call("/infra/node-csrs", "POST", { csrPem: readFileSync(csr, "utf8") }, "agent", token);
    assert.equal(submitted.status, 201); const row = submitted.body.request;
    const cert = join(root, "host.pem"); execFileSync("node", ["bin/heliopause-pki.ts", "sign-csr", pki, csr, cert,
      "--name=node-03.dev", `--expect-sha256=${row.csrSha256}`]);
    const uploaded = await call(`/enrollment/requests/${row.id}/certificate`, "POST", { certificatePem: readFileSync(cert, "utf8"), caName: "dev" });
    assert.equal(uploaded.status, 200);
    const fetched = await call(`/infra/node-csrs/${row.id}/certificate`, "GET", undefined, "agent", token);
    assert.equal(fetched.status, 200); assert.match(fetched.body.certificate.certificatePem, /BEGIN CERTIFICATE/);
    const auditAfterFirstFetch = loadEnrollmentDocument(store).audit.length;
    const fetchedAgain = await call(`/infra/node-csrs/${row.id}/certificate`, "GET", undefined, "agent", token);
    assert.equal(fetchedAgain.status, 200);
    assert.equal(loadEnrollmentDocument(store).audit.length, auditAfterFirstFetch, "polling appended unbounded fetch audit rows");
    const listed = await call("/enrollment/requests", "GET"); assert.equal(listed.body.requests[0].status, "signed");
    const revoked = await call("/enrollment/revocations", "POST", { certificatePem: readFileSync(join(pki, "operator-ops.pem"), "utf8"), reason: "operator credential retired" });
    assert.equal(revoked.status, 201);
    assert.equal((await call("/enrollment/requests", "GET")).status, 401);

    unlinkSync(store);
    assert.equal((await call("/enrollment/requests", "GET")).status, 401, "runtime deletion did not fail closed");
    assert.equal(
      (await call(`/infra/node-csrs/${row.id}/certificate`, "GET", undefined, "agent", token)).status,
      503,
      "a bearer-only runtime request did not observe deletion of the durable store",
    );
    assert.equal(existsSync(store), false, "a runtime request recreated deleted revocation state");
    await assert.rejects(startManager(managerOptions(store)), /enrollment store is unavailable/);
    assert.equal(existsSync(store), false, "restart recreated deleted revocation state");
  });
});

// ── The third principal, over HTTP ────────────────────────────────────────────
//
// A manager of its own, with a one-time code configured, because the two halves of this feature only
// make sense against each other: issuing an app token keeps every operator check there is, and using
// one has none of them. A deployment without OTP would exercise the second half and quietly skip the
// first — which is the half that decides the grant.
describe("app tokens over the manager API", () => {
  const appStore = join(root, "app-enrollment.json");
  let appPort = 0;
  let closeApp = () => {};
  let idpAnswer: { status: number; body: unknown } = { status: 200, body: { ok: true } };

  const app = (path: string, method: "GET" | "POST", body?: unknown, token?: string) =>
    call(path, method, body, "agent", token, appPort);
  const operator = (path: string, method: "GET" | "POST", body?: unknown) =>
    call(path, method, body, "operator", undefined, appPort);
  const issueAppToken = (body: Record<string, unknown>) =>
    operator("/enrollment/app-tokens", "POST", { otp: "123456", ...body });

  before(async () => {
    initializeEnrollmentDocument(appStore);
    const started = await startManager({
      ...managerOptions(appStore),
      otp: {
        issuerUrl: "https://idp.example.invalid",
        serviceToken: "svc",
        users: new Map([["ops", "keystone-user-1"]]),
        fetchImpl: (async (_u: string | URL, init?: RequestInit) => {
          const asked = JSON.parse(String(init?.body ?? "{}")) as { code?: string };
          const answer = asked.code === "123456" ? idpAnswer : { status: 401, body: { ok: false } };
          return new Response(JSON.stringify(answer.body), { status: answer.status });
        }) as unknown as typeof fetch,
      },
    });
    appPort = (started.server.address() as { port: number }).port;
    closeApp = () => started.server.close();
  });
  after(() => { closeApp(); });

  it("creates, lists and revokes an app token, and needs a one-time code to do the first and last", async () => {
    const noCode = await operator("/enrollment/app-tokens", "POST", {
      label: "no-code", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev",
    });
    assert.equal(noCode.status, 401, "an app token was minted without a one-time code");
    assert.equal(loadEnrollmentDocument(appStore).appTokens.some((row) => row.label === "no-code"), false);

    const created = await issueAppToken({
      label: "operator-cycle", scopes: ["enrollment:token-create", "enrollment:requests-read"], hostnamePattern: "*.dev",
    });
    assert.equal(created.status, 201);
    assert.match(created.body.token, /^hpapp_[0-9a-f]{64}$/);
    assert.equal(created.body.row.tokenHash, undefined, "the answer carried the stored hash");
    assert.equal(created.body.row.createdBy, "ops");
    assert.deepEqual(created.body.row.scopes, ["enrollment:token-create", "enrollment:requests-read"]);

    const listed = await operator("/enrollment/app-tokens", "GET");
    assert.equal(listed.status, 200);
    const row = listed.body.tokens.find((t: { id: string }) => t.id === created.body.id);
    assert.ok(row, "a created app token was missing from the list");
    assert.equal(row.tokenHash, undefined, "the list carried the stored hash");
    assert.equal(JSON.stringify(listed.body).includes(created.body.token), false);

    // Revocation is what makes a leaked token recoverable, so it carries the second factor too.
    assert.equal((await operator(`/enrollment/app-tokens/${created.body.id}/revoke`, "POST", {})).status, 401);
    const revoked = await operator(`/enrollment/app-tokens/${created.body.id}/revoke`, "POST", { otp: "123456" });
    assert.equal(revoked.status, 200);
    assert.ok(revoked.body.row.revokedAt);
    assert.equal(revoked.body.row.tokenHash, undefined);
    // And it takes effect on the next request rather than on a restart.
    assert.equal((await app("/enrollment/requests", "GET", undefined, created.body.token)).status, 401);
  });

  it("refuses a malformed scope list, pattern or label before anything is stored", async () => {
    const before = loadEnrollmentDocument(appStore).appTokens.length;
    const bad: Array<Record<string, unknown>> = [
      { label: "x", scopes: "enrollment:token-create", hostnamePattern: "*.dev" },
      { label: "x", scopes: [], hostnamePattern: "*.dev" },
      { label: "x", scopes: ["enrollment:sign"], hostnamePattern: "*.dev" },
      { label: "x", scopes: [7], hostnamePattern: "*.dev" },
      { label: 7, scopes: ["enrollment:token-create"], hostnamePattern: "*.dev" },
      { label: "x", scopes: ["enrollment:token-create"], hostnamePattern: "a.*.dev" },
      { label: "x", scopes: ["enrollment:token-create"], hostnamePattern: 7 },
      { label: "x", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev", ttlSec: "3600" },
    ];
    for (const body of bad) {
      const answer = await issueAppToken(body);
      assert.equal(answer.status, 400, `the manager accepted ${JSON.stringify(body)}`);
    }
    assert.equal(loadEnrollmentDocument(appStore).appTokens.length, before, "a refused request stored a token");
  });

  it("issues a node token for a hostname inside the pattern, marked as the app's work", async () => {
    const created = await issueAppToken({
      label: "dispatcher", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev",
    });
    const token = created.body.token as string;

    const issued = await app("/enrollment/tokens", "POST", { hostname: "k3s-07.dev", ttlSec: 86_400 }, token);
    assert.equal(issued.status, 201);
    assert.match(issued.body.token, /^stnode_[0-9a-f]{64}$/);
    assert.equal(issued.body.row.hostname, "k3s-07.dev");
    // The whole point of the audit line: a node token minted by a program is distinguishable from
    // one an operator minted, without reading a timestamp against a chat log.
    assert.equal(issued.body.row.createdBy, "app:dispatcher");
    assert.equal(issued.body.row.tokenHash, undefined);
    assert.equal(
      Date.parse(issued.body.row.expiresAt) - Date.parse(issued.body.row.createdAt), 86_400_000,
      "the app path dropped the requested node token TTL",
    );

    // Neither plaintext and neither hash may reach the audit trail.
    const document = loadEnrollmentDocument(appStore);
    const trail = JSON.stringify(document.audit);
    assert.equal(trail.includes(token), false, "the audit trail carries the app token plaintext");
    assert.equal(trail.includes(issued.body.token), false, "the audit trail carries the node token plaintext");
    for (const row of document.appTokens) assert.equal(trail.includes(row.tokenHash), false);
    for (const row of document.tokens) assert.equal(trail.includes(row.tokenHash), false);
    // Using a token is recorded, because "is anything still holding this?" is the question an
    // operator asks before revoking one.
    assert.ok(document.appTokens.find((row) => row.id === created.body.id)?.lastUsedAt);
  });

  it("refuses a hostname outside the pattern, and names both halves", async () => {
    const created = await issueAppToken({
      label: "dev-only", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev",
    });
    const token = created.body.token as string;
    const before = loadEnrollmentDocument(appStore).tokens.length;

    // `gw-01.prod` is the case from the exchange: the manager trusts one CA, so a token for a zone
    // it cannot sign for produces a CSR that stays pending forever.
    const refused = await app("/enrollment/tokens", "POST", { hostname: "gw-01.prod" }, token);
    assert.equal(refused.status, 403);
    assert.match(refused.body.error, /dev-only/);
    assert.match(refused.body.error, /\*\.dev/);
    assert.match(refused.body.error, /gw-01\.prod/);

    // One label, not a suffix: `*.dev` must not cover `k3s-01.attacker.dev`.
    assert.equal((await app("/enrollment/tokens", "POST", { hostname: "k3s-01.attacker.dev" }, token)).status, 403);
    assert.equal((await app("/enrollment/tokens", "POST", { hostname: "dev" }, token)).status, 403);
    // A hostname that is not a hostname is the caller's typo, not a scope decision.
    assert.equal((await app("/enrollment/tokens", "POST", { hostname: "not a hostname" }, token)).status, 400);
    assert.equal((await app("/enrollment/tokens", "POST", { hostname: 7 }, token)).status, 400);
    assert.equal(loadEnrollmentDocument(appStore).tokens.length, before, "a refused request minted a node token");
  });

  it("keeps each scope to its own route, and answers 403 rather than 401 for a valid token", async () => {
    const reader = await issueAppToken({
      label: "reader", scopes: ["enrollment:requests-read"], hostnamePattern: "*.dev",
    });
    const minter = await issueAppToken({
      label: "minter", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev",
    });

    const listed = await app("/enrollment/requests", "GET", undefined, reader.body.token);
    assert.equal(listed.status, 200);
    assert.ok(Array.isArray(listed.body.requests));
    assert.equal((await app("/enrollment/requests?status=signed", "GET", undefined, reader.body.token)).status, 200);
    assert.equal((await app("/enrollment/requests?status=nonsense", "GET", undefined, reader.body.token)).status, 400);

    // A valid token outside its grant is 403 and names itself: the operator reading the log has to
    // decide between widening a scope and fixing a caller, and 401 sends them after a credential
    // problem that is not there.
    const wrongScope = await app("/enrollment/tokens", "POST", { hostname: "k3s-01.dev" }, reader.body.token);
    assert.equal(wrongScope.status, 403);
    assert.match(wrongScope.body.error, /reader is not authorised/);
    assert.equal((await app("/enrollment/requests", "GET", undefined, minter.body.token)).status, 403);

    // Everything else the manager serves, including the route that mints app tokens.
    for (const [path, method] of [
      ["/enrollment/app-tokens", "POST"], ["/enrollment/app-tokens", "GET"], ["/enrollment/tokens", "GET"],
      ["/enrollment/audit", "GET"], ["/enrollment/revocations", "POST"], ["/site", "GET"], ["/approve", "POST"],
    ] as Array<[string, "GET" | "POST"]>) {
      const answer = await app(path, method, method === "POST" ? {} : undefined, minter.body.token);
      assert.equal(answer.status, 403, `${method} ${path} answered ${answer.status} to an app token`);
      assert.match(answer.body.error, /is not authorised for/);
    }
  });

  it("says only 'unauthorized' for a token it does not honour, whichever reason applies", async () => {
    const unknown = `hpapp_${"a".repeat(64)}`;
    const refused = await app("/enrollment/requests", "GET", undefined, unknown);
    assert.equal(refused.status, 401);
    assert.equal(refused.body.error, "unauthorized app token");

    // Expired, written straight into the store because the route floor is an hour.
    const expired = withEnrollmentTransaction(appStore, (document) => createAppToken(document, {
      label: "stale", scopes: ["enrollment:requests-read"], hostnamePattern: "*.dev",
      ttlSec: 3_600, now: new Date(Date.now() - 2 * 3_600_000),
    }).token);
    const stale = await app("/enrollment/requests", "GET", undefined, expired);
    assert.equal(stale.status, 401);
    assert.equal(stale.body.error, "unauthorized app token", "an expired token was told apart from an unknown one");

    // A node token is not an app token: the shapes are disjoint and neither gate admits the other.
    const node = await call("/enrollment/tokens", "POST", { hostname: "shape.dev", otp: "123456" }, "operator", undefined, appPort);
    assert.equal(node.status, 201);
    const asApp = await app("/enrollment/requests", "GET", undefined, node.body.token);
    assert.equal(asApp.status, 401, "a node token reached the app-token routes");
  });

  it("refuses an app-token request that carries a one-time code", async () => {
    const created = await issueAppToken({
      label: "confused", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev",
    });
    const before = loadEnrollmentDocument(appStore).tokens.length;
    // Ignoring the field would let "the dispatcher sends an OTP" live in a configuration until the
    // day somebody relies on a second factor that was never read.
    const answer = await app("/enrollment/tokens", "POST", { hostname: "k3s-09.dev", otp: "123456" }, created.body.token);
    assert.equal(answer.status, 400);
    assert.match(answer.body.error, /one-time code/);
    assert.equal(loadEnrollmentDocument(appStore).tokens.length, before);
  });

  it("refuses a cross-site request carrying an app token", async () => {
    const created = await issueAppToken({
      label: "browsered", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev",
    });
    const payload = JSON.stringify({ hostname: "k3s-11.dev" });
    const answer = await new Promise<{ status: number; body: any }>((resolve, reject) => {
      const req = request({
        host: "127.0.0.1", port: appPort, path: "/enrollment/tokens", method: "POST",
        ca: readFileSync(join(pki, "ca.pem")),
        headers: {
          "content-type": "application/json", "content-length": Buffer.byteLength(payload),
          authorization: `Bearer ${created.body.token}`, origin: "https://evil.example",
          "sec-fetch-site": "cross-site",
        },
      }, (res) => { let text = ""; res.on("data", (p) => text += p); res.on("end", () => resolve({ status: res.statusCode ?? 0, body: JSON.parse(text) })); });
      req.on("error", reject); req.write(payload); req.end();
    });
    assert.equal(answer.status, 403);
    assert.match(answer.body.error, /cross-site/);
  });
});
