import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { createServer as createHttpsServer, request } from "node:https";
import { createServer as createTcpServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import {
  beginHostDeregistration, confirmHostInfrastructureDestroyed, createAppToken, createNodeToken,
  initializeEnrollmentDocument, loadEnrollmentDocument, recordHostDeregistrationReplication,
  storeNodeCertificate, submitNodeCsr, withEnrollmentTransaction,
  type NodeCsrRecord,
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

function call(path: string, method: "GET" | "POST" | "PUT", body?: unknown, mode: "operator" | "agent" = "operator", token?: string, target = port) {
  return new Promise<{ status: number; body: any; headers: Record<string, string | string[] | undefined> }>((resolve, reject) => {
    const payload = body === undefined ? "" : JSON.stringify(body);
    const req = request({ host: "127.0.0.1", port: target, path, method, ca: readFileSync(join(pki, "ca.pem")),
      ...(mode === "operator" ? { cert: readFileSync(join(pki, "operator-ops.pem")), key: readFileSync(join(pki, "operator-ops.key")) } : {}),
      headers: { ...(payload ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) },
    }, (res) => { let text = ""; res.on("data", (part) => text += part); res.on("end", () => resolve({ status: res.statusCode ?? 0, body: JSON.parse(text), headers: res.headers })); });
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
    assert.equal((await call("/enrollment/tokens", "POST", { hostname: "unbound.dev" })).status, 400);
    const created = await call("/enrollment/tokens", "POST", { hostname: "node-keep.dev", hostLifecycleId: "life-node-keep" });
    assert.equal(created.status, 201);
    const rowId = created.body.id as string;
    const malformed = await call("/enrollment/tokens", "POST", {
      hostname: "node-keep.dev", hostLifecycleId: "life-node-keep", revokeExisting: "false",
    });
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

  it("rejects startup when the listen address is already occupied", async () => {
    const blocker = createTcpServer();
    await new Promise<void>((resolve, reject) => {
      blocker.once("error", reject);
      blocker.listen(0, "127.0.0.1", resolve);
    });
    const occupiedPort = (blocker.address() as { port: number }).port;
    let timeout: NodeJS.Timeout | undefined;
    try {
      await assert.rejects(Promise.race([
        startManager({ ...managerOptions(store), port: occupiedPort }),
        new Promise<never>((_resolve, reject) => {
          timeout = setTimeout(() => reject(new Error("startManager did not reject a listen error")), 1_000);
        }),
      ]), (error: unknown) => (error as NodeJS.ErrnoException).code === "EADDRINUSE");
    } finally {
      if (timeout) clearTimeout(timeout);
      blocker.close();
    }
  });

  it("completes token, CSR, offline signing, upload and token-scoped fetch", { timeout: 15_000 }, async () => {
    const tokenAnswer = await call("/enrollment/tokens", "POST", {
      hostname: "node-03.dev", hostLifecycleId: "life-node-03", ttlSec: 600,
    });
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
// A manager with a one-time code configured, because the two halves of this feature only make sense
// against each other: issuing an app token keeps every operator check there is, and using one has
// none of them. A deployment without OTP would exercise the second half and quietly skip the first —
// which is the half that decides the grant.
//
// ⚠️ **One manager per group of tests, and that is not tidiness.** App-token requests are counted by
// the same per-source bound as the certificate-less enrollment routes: 30 per minute per address,
// held in a `Map` that lives inside one `startManager` call. Every test here arrives from 127.0.0.1,
// so a single instance gives the whole file one shared budget of 30 — and the tests that exceeded it
// failed as `429`, from a limit they were not testing. A second instance is a second budget. The
// bound itself is pinned by its own group at the bottom, because a polling caller has to know it.
const startAppTokenManager = async (
  storeFile: string, overrides: Partial<Parameters<typeof startManager>[0]> = {},
) => {
  const started = await startManager({
    ...managerOptions(storeFile),
    ...overrides,
    otp: {
      issuerUrl: "https://idp.example.invalid",
      serviceToken: "svc",
      users: new Map([["ops", "keystone-user-1"]]),
      fetchImpl: (async (_u: string | URL, init?: RequestInit) => {
        const asked = JSON.parse(String(init?.body ?? "{}")) as { code?: string };
        return asked.code === "123456"
          ? new Response(JSON.stringify({ ok: true }), { status: 200 })
          : new Response(JSON.stringify({ ok: false }), { status: 401 });
      }) as unknown as typeof fetch,
    },
  });
  return {
    port: (started.server.address() as { port: number }).port,
    close: () => started.server.close(),
  };
};

const appTokenCalls = (livePort: () => number) => {
  let lifecycleSequence = 0;
  const app = (path: string, method: "GET" | "POST" | "PUT", body?: unknown, token?: string) => {
    const actualBody = path === "/enrollment/tokens" && method === "POST" && body && typeof body === "object" && !Array.isArray(body)
      && !("hostLifecycleId" in body)
      ? { ...(body as Record<string, unknown>), hostLifecycleId: `test-lifecycle-${++lifecycleSequence}` }
      : body;
    return call(path, method, actualBody, "agent", token, livePort());
  };
  const operator = (path: string, method: "GET" | "POST" | "PUT", body?: unknown) =>
    call(path, method, body, "operator", undefined, livePort());
  return {
    app, operator,
    issueAppToken: (body: Record<string, unknown>) =>
      operator("/enrollment/app-tokens", "POST", { otp: "123456", ...body }),
  };
};

const appStore = join(root, "app-enrollment.json");

describe("app tokens over the manager API", () => {
  let appPort = 0;
  let closeApp = () => {};
  const { app, operator, issueAppToken } = appTokenCalls(() => appPort);

  before(async () => {
    initializeEnrollmentDocument(appStore);
    const started = await startAppTokenManager(appStore);
    appPort = started.port;
    closeApp = started.close;
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
    // one an operator minted, without reading a timestamp against a chat log — and the id is there
    // because a label is not an identifier.
    assert.equal(issued.body.row.createdBy, `app:dispatcher#${created.body.id}`);
    assert.equal(issued.body.row.tokenHash, undefined);
    assert.equal(
      issued.headers["x-heliopause-app-token-expires-at"], created.body.row.expiresAt,
      "an accepted answer did not carry the app token's expiry",
    );
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
    // Minting is recorded, because "is anything still issuing with this?" is the question an
    // operator asks before revoking one. Reads are not — see the next test.
    assert.ok(document.appTokens.find((row) => row.id === created.body.id)?.lastUsedAt);
    const event = document.audit.filter((row) => row.action === "node-token.create").at(-1)!;
    assert.equal(event.actor, `app:dispatcher#${created.body.id}`);
    assert.equal(event.detail.appTokenId, created.body.id);
  });

  it("distinguishes two live tokens that share a label, which is why the id travels", async () => {
    // Rotation issues the replacement before revoking the old one, so a label is deliberately not
    // unique. `app:dispatcher` alone could not say which credential minted what.
    const first = await issueAppToken({ label: "rotating", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev" });
    const second = await issueAppToken({ label: "rotating", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev" });
    assert.notEqual(first.body.id, second.body.id);

    const byFirst = await app("/enrollment/tokens", "POST", { hostname: "rot-a.dev" }, first.body.token);
    const bySecond = await app("/enrollment/tokens", "POST", { hostname: "rot-b.dev" }, second.body.token);
    assert.equal(byFirst.body.row.createdBy, `app:rotating#${first.body.id}`);
    assert.equal(bySecond.body.row.createdBy, `app:rotating#${second.body.id}`);
    assert.notEqual(byFirst.body.row.createdBy, bySecond.body.row.createdBy);

    const audit = loadEnrollmentDocument(appStore).audit;
    assert.equal(audit.find((row) => row.target === byFirst.body.id)!.detail.appTokenId, first.body.id);
    assert.equal(audit.find((row) => row.target === bySecond.body.id)!.detail.appTokenId, second.body.id);
  });

  it("keeps the id in createdBy even at the longest label the manager will accept", async () => {
    // 🔴 `createdBy` is truncated to 120 characters on the way into the store, and a 120-character
    // label made `app:<label>#<id>` 141 long — the slice ate the id, which is the whole reason the
    // id is there. Invisible for every label short enough to test casually.
    const label = "l".repeat(120);
    const created = await issueAppToken({
      label, scopes: ["enrollment:token-create"], hostnamePattern: "*.dev",
    });
    assert.equal(created.status, 201);
    assert.equal(created.body.row.label, label);

    const issued = await app("/enrollment/tokens", "POST", { hostname: "long-label.dev" }, created.body.token);
    assert.equal(issued.status, 201);
    assert.equal(
      issued.body.row.createdBy.endsWith(`#${created.body.id}`), true,
      `createdBy lost the app token id: ${issued.body.row.createdBy}`,
    );
    assert.ok(issued.body.row.createdBy.length <= 120);
    assert.ok(issued.body.row.createdBy.startsWith("app:llll"), "the label half disappeared instead of the id");
    // The structured copy is never truncated, whatever the label does.
    const event = loadEnrollmentDocument(appStore).audit.filter((row) => row.target === issued.body.id).at(-1)!;
    assert.equal(event.detail.appTokenId, created.body.id);
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
    const node = await call("/enrollment/tokens", "POST", {
      hostname: "shape.dev", hostLifecycleId: "life-shape", otp: "123456",
    }, "operator", undefined, appPort);
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

// A second manager over the same store, for the reason recorded above `startAppTokenManager`: the
// per-source request bound lives in one `startManager` call, and these reads would otherwise spend a
// budget the tests above are already using.
describe("app tokens reading the CSR queue", () => {
  let readPort = 0;
  let closeRead = () => {};
  const { app, operator, issueAppToken } = appTokenCalls(() => readPort);

  /**
   * A CSR row written straight into the store.
   *
   * The filter under test reads `hostname` and `status` and nothing else, and producing real rows
   * would mean a key, an OpenSSL run and a node token each — which tests the enrollment path again
   * rather than the filter.
   */
  let seeded = 0;
  const seedCsr = (hostname: string, status: NodeCsrRecord["status"]) =>
    withEnrollmentTransaction(appStore, (document) => {
      seeded += 1;
      document.requests.push({
        id: `seed-${seeded}`, hostname, nodeTokenId: "seed", hostLifecycleId: null, status,
        csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
        csrSha256: "0".repeat(64), publicKeySha256: "1".repeat(64), keyAlgorithm: "ECDSA-P256",
        createdAt: new Date().toISOString(), sourceIp: null, decidedAt: null, decidedBy: null,
        decisionReason: null, signedAt: null, caName: null, certificatePem: null, caPem: null,
        certificateSha256: null, certificateNotBefore: null, certificateNotAfter: null, retrievedAt: null,
      });
    });

  before(async () => {
    const started = await startAppTokenManager(appStore);
    readPort = started.port;
    closeRead = started.close;
  });
  after(() => { closeRead(); });

  it("reads the queue without taking the enrollment lock, so lastUsedAt means minting only", async () => {
    // 🔴 This route used to wrap itself in a write transaction purely to stamp `lastUsedAt` — an
    // exclusive lock, a full re-serialisation and an fsync for a request that changes nothing, which
    // would serialise a poller against every token issue in the deployment.
    const created = await issueAppToken({
      label: "poller", scopes: ["enrollment:requests-read"], hostnamePattern: "*.dev",
    });
    const before = loadEnrollmentDocument(appStore);
    const beforeRow = before.appTokens.find((row) => row.id === created.body.id)!;
    assert.equal(beforeRow.lastUsedAt, null);
    const beforeBytes = readFileSync(appStore, "utf8");

    const answer = await app("/enrollment/requests", "GET", undefined, created.body.token);
    assert.equal(answer.status, 200);
    assert.equal(answer.headers["x-heliopause-app-token-expires-at"], created.body.row.expiresAt);

    assert.equal(readFileSync(appStore, "utf8"), beforeBytes, "a read of the CSR queue rewrote the store");
    assert.equal(
      loadEnrollmentDocument(appStore).appTokens.find((row) => row.id === created.body.id)!.lastUsedAt, null,
      "lastUsedAt must record minting only — the README documents it that way",
    );
    assert.equal(existsSync(`${appStore}.lock`), false);
  });

  it("carries the expiry only on answers it accepted", async () => {
    const created = await issueAppToken({
      label: "expiring", scopes: ["enrollment:requests-read"], hostnamePattern: "*.dev",
    });
    // A 401 must not become a way to ask whether a guessed token exists and when it dies.
    const unknown = await app("/enrollment/requests", "GET", undefined, `hpapp_${"b".repeat(64)}`);
    assert.equal(unknown.status, 401);
    assert.equal(unknown.headers["x-heliopause-app-token-expires-at"], undefined);
    // Nor may a refusal for a token that *is* real leak it.
    const outOfScope = await app("/enrollment/tokens", "POST", { hostname: "k3s-01.dev" }, created.body.token);
    assert.equal(outOfScope.status, 403);
    assert.equal(outOfScope.headers["x-heliopause-app-token-expires-at"], undefined);
    // And the operator routes, which are a different principal, never carry it at all.
    assert.equal((await operator("/enrollment/app-tokens", "GET")).headers["x-heliopause-app-token-expires-at"], undefined);
  });

  it("filters the CSR queue by hostname, for both principals, composed with status", async () => {
    seedCsr("filter-a.dev", "pending");
    seedCsr("filter-a.dev", "signed");
    seedCsr("filter-b.dev", "pending");
    const created = await issueAppToken({
      label: "queue-reader", scopes: ["enrollment:requests-read"], hostnamePattern: "*.dev",
    });
    const asApp = (query: string) => app(`/enrollment/requests${query}`, "GET", undefined, created.body.token);
    const asOperator = (query: string) => operator(`/enrollment/requests${query}`, "GET");

    for (const read of [asApp, asOperator]) {
      const all = await read("");
      assert.equal(all.status, 200);
      const byHost = await read("?hostname=filter-a.dev");
      assert.equal(byHost.status, 200);
      assert.equal(byHost.body.requests.length, 2);
      assert.ok(byHost.body.requests.every((row: { hostname: string }) => row.hostname === "filter-a.dev"));
      assert.ok(all.body.requests.length > byHost.body.requests.length, "the filter matched everything");

      // Normalised the same way a hostname is normalised anywhere else in this store.
      assert.equal((await read("?hostname=FILTER-A.DEV")).body.requests.length, 2);
      // Composed, not exclusive.
      const both = await read("?hostname=filter-a.dev&status=pending");
      assert.equal(both.body.requests.length, 1);
      assert.equal(both.body.requests[0].status, "pending");
      assert.equal((await read("?hostname=filter-b.dev&status=signed")).body.requests.length, 0);

      // A malformed name is refused rather than matching nothing: an empty list reads as "there are
      // no CSRs", and that is the sentence somebody acts on.
      const malformed = await read("?hostname=not%20a%20hostname");
      assert.equal(malformed.status, 400);
      assert.match(malformed.body.error, /invalid hostname/);
      assert.equal((await read("?status=nonsense")).status, 400);

      // An empty value is "no filter", not "filter by nothing". This route has behaved that way for
      // `?status=` since it was written, `heliopause-enrollment` builds its query from flags that may
      // be absent, and a 400 for a parameter somebody left blank is a regression dressed as
      // strictness. Both parameters, both principals.
      const blank = await read("?status=&hostname=");
      assert.equal(blank.status, 200);
      assert.equal(blank.body.requests.length, all.body.requests.length, "an empty value filtered something out");
      assert.equal((await read("?hostname=&status=pending")).status, 200);
    }
  });

  it("shows an app token only the zone its pattern covers, and does not confirm the rest", async () => {
    // 🔴 This route returned the whole fleet's queue. A `*.dev` token could read every hostname and
    // every public-key digest in prod and util — zones it cannot mint for and has no business
    // enumerating. The pattern bounded what the token may create; it now bounds what it may see.
    seedCsr("gw-01.prod", "pending");
    seedCsr("gw-01.util", "signed");
    const dev = await issueAppToken({
      label: "dev-reader", scopes: ["enrollment:requests-read"], hostnamePattern: "*.dev",
    });
    const exact = await issueAppToken({
      label: "one-host", scopes: ["enrollment:requests-read"], hostnamePattern: "filter-b.dev",
    });

    const seenByDev = await app("/enrollment/requests", "GET", undefined, dev.body.token);
    assert.equal(seenByDev.status, 200);
    assert.ok(seenByDev.body.requests.length > 0);
    assert.ok(
      seenByDev.body.requests.every((row: { hostname: string }) => row.hostname.endsWith(".dev")),
      "an app token read a zone outside its pattern",
    );

    // An exact-hostname pattern is a window one host wide.
    const seenByExact = await app("/enrollment/requests", "GET", undefined, exact.body.token);
    assert.ok(seenByExact.body.requests.length > 0);
    assert.ok(seenByExact.body.requests.every((row: { hostname: string }) => row.hostname === "filter-b.dev"));

    // Asking for a host outside the pattern is an empty list, not a refusal. A 403 there would
    // answer "is this host inside your pattern?" for any name the caller cares to try, turning a
    // read into an oracle for a boundary the caller is not supposed to map.
    const outside = await app("/enrollment/requests?hostname=gw-01.prod", "GET", undefined, dev.body.token);
    assert.equal(outside.status, 200);
    assert.deepEqual(outside.body.requests, []);
    const alsoOutside = await app("/enrollment/requests?hostname=filter-a.dev", "GET", undefined, exact.body.token);
    assert.equal(alsoOutside.status, 200);
    assert.deepEqual(alsoOutside.body.requests, []);
    // A hostname that is not a hostname is still a 400: that is a typo, not a boundary.
    assert.equal((await app("/enrollment/requests?hostname=not%20a%20host", "GET", undefined, dev.body.token)).status, 400);

    // The operator sees everything, unchanged — the narrowing is a property of the credential.
    const asOperator = await operator("/enrollment/requests", "GET");
    assert.ok(asOperator.body.requests.some((row: { hostname: string }) => row.hostname === "gw-01.prod"));
    assert.ok(asOperator.body.requests.some((row: { hostname: string }) => row.hostname === "gw-01.util"));
  });

  it("answers an app token at the bootstrap routes with the node-token refusal, by ordering", async () => {
    // `/infra/node-csrs` is dispatched above the app-token split and gates on `looksLikeNodeToken`,
    // which an app token fails. Pinned because the answer is correct but not obvious: those two
    // routes are the agent's own credential path, and an app token has no CSR of its own.
    const created = await issueAppToken({
      label: "not-an-agent", scopes: ["enrollment:token-create", "enrollment:requests-read"], hostnamePattern: "*.dev",
    });
    const submitted = await app("/infra/node-csrs", "POST", { csrPem: "x" }, created.body.token);
    assert.equal(submitted.status, 401);
    assert.equal(submitted.body.error, "unauthorized node token");
    const fetched = await app("/infra/node-csrs/any-id/certificate", "GET", undefined, created.body.token);
    assert.equal(fetched.status, 401);
    assert.equal(fetched.body.error, "unauthorized node token");
  });
});

describe("lifecycle-bound host deregistration", () => {
  const deregStore = join(root, "dereg-enrollment.json");
  let deregPort = 0;
  let relayPort = 0;
  let relayAccepts = false;
  let closeDereg = () => {};
  let closeRelay = () => {};
  const { app, operator } = appTokenCalls(() => deregPort);

  before(async () => {
    initializeEnrollmentDocument(deregStore);
    const relay = createHttpsServer({
      cert: readFileSync(join(pki, "relay-manager.pem")), key: readFileSync(join(pki, "relay-manager.key")),
    }, (req, res) => {
      let encoded = "";
      req.on("data", (chunk) => encoded += chunk);
      req.on("end", () => {
        if (!relayAccepts) { res.writeHead(503); return res.end(JSON.stringify({ error: "held for test" })); }
        const snapshot = JSON.parse(encoded) as { revocations: unknown[] };
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ count: snapshot.revocations.length }));
      });
    });
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    relayPort = (relay.address() as { port: number }).port;
    closeRelay = () => relay.close();
    const started = await startAppTokenManager(deregStore, {
      relays: [{ name: "dev", url: `https://127.0.0.1:${relayPort}`, pkiDir: pki }],
    });
    deregPort = started.port;
    closeDereg = started.close;
  });
  after(() => { closeDereg(); closeRelay(); });

  it("requires an operator writer and OTP to bind exact legacy inventory", async () => {
    const seeded = withEnrollmentTransaction(deregStore, (document) => {
      const token = createNodeToken(document, { hostname: "legacy-bind-api.dev" }).row;
      const request: NodeCsrRecord = {
        id: "legacy-bind-api-csr", hostname: "legacy-bind-api.dev", nodeTokenId: token.id,
        hostLifecycleId: null, status: "pending", csrPem: "fixture", csrSha256: "1".repeat(64),
        publicKeySha256: "2".repeat(64), keyAlgorithm: "ECDSA-P256", createdAt: new Date().toISOString(),
        sourceIp: null, decidedAt: null, decidedBy: null, decisionReason: null, signedAt: null, caName: null,
        certificatePem: null, caPem: null, certificateSha256: null, certificateNotBefore: null,
        certificateNotAfter: null, retrievedAt: null,
      };
      document.requests.push(request);
      return { tokenId: token.id, requestId: request.id };
    });
    const path = "/enrollment/host-lifecycle-bindings/legacy-bind-api.dev/create-api-uuid-1";
    const inventoryEvidence = {
      stardustCreateOperationId: "create-api-uuid-1", provider: "vultr", providerInstanceId: "vm-api-1",
      nodeTokenIds: [seeded.tokenId], csrRequestIds: [seeded.requestId], certificateFingerprints: [],
    };
    assert.equal((await operator(path, "PUT", { inventoryEvidence })).status, 401);
    assert.equal(loadEnrollmentDocument(deregStore).tokens.find((row) => row.id === seeded.tokenId)?.hostLifecycleId, null);
    const malformed = await operator(path, "PUT", { otp: "123456", inventoryEvidence: { ...inventoryEvidence, hostname: "guess.dev" } });
    assert.equal(malformed.status, 400);
    const bound = await operator(path, "PUT", { otp: "123456", inventoryEvidence });
    assert.equal(bound.status, 200); assert.equal(bound.body.binding.tokensBound, 1);
    assert.equal(bound.body.binding.requestsBound, 1); assert.match(bound.body.binding.evidenceSha256, /^[0-9a-f]{64}$/);
    assert.equal(JSON.stringify(bound.body).includes("tokenHash"), false);
    assert.equal((await operator(path, "PUT", { otp: "123456", inventoryEvidence })).status, 409);
  });

  it("repairs certificate inventory with writer+OTP, rollback, PEM-free output, and response-loss replay",
    { timeout: 30_000 }, async () => {
      const host = "repair-api.dev"; const lifecycle = "create-repair-api-1";
      const materialRoot = mkdtempSync(join(tmpdir(), "heliopause-repair-api-"));
      try {
        const keyPath = join(materialRoot, "host.key"); const csrPath = join(materialRoot, "host.csr");
        const certPath = join(materialRoot, "host.pem");
        execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt",
          "ec_paramgen_curve:prime256v1", "-out", keyPath]);
        execFileSync("openssl", ["req", "-new", "-key", keyPath, "-subj", `/CN=${host}`, "-out", csrPath]);
        const seeded = withEnrollmentTransaction(deregStore, (document) => {
          const issued = createNodeToken(document, { hostname: host, hostLifecycleId: lifecycle });
          const request = submitNodeCsr(document, { token: issued.token, csrPem: readFileSync(csrPath, "utf8") }).row;
          return { requestId: request.id, csrSha256: request.csrSha256 };
        });
        execFileSync("node", ["bin/heliopause-pki.ts", "sign-csr", pki, csrPath, certPath,
          `--name=${host}`, `--expect-sha256=${seeded.csrSha256}`], { cwd: process.cwd() });
        const certificatePem = readFileSync(certPath, "utf8");
        withEnrollmentTransaction(deregStore, (document) => {
          storeNodeCertificate(document, { requestId: seeded.requestId, certificatePem,
            caPem: readFileSync(join(pki, "ca.pem"), "utf8"), caName: "dev", actor: "ops" });
          document.requests.find((request) => request.id === seeded.requestId)!.certificatePem = null;
          beginHostDeregistration(document, {
            hostname: host, hostLifecycleId: lifecycle, externalOperationId: "destroy-repair-api-1",
            reason: "instance-destroy", requestedBy: "stardust:ops", actor: "app:destroyer",
            relayNames: ["dev"], scope: { appTokenId: "app-repair", label: "destroyer", hostnamePattern: "*.dev" },
            trustedCaPems: [readFileSync(join(pki, "ca.pem"), "utf8")],
          });
        });
        const path = `/enrollment/host-deregistrations/${host}/destroy-repair-api-1/repairs/certificate-inventory`;
        const repair = { hostLifecycleId: lifecycle,
          certificates: [{ requestId: seeded.requestId, certificatePem }] };
        assert.equal((await operator(path, "PUT", repair)).status, 401, "repair accepted no OTP");
        const readOnlyManager = await startAppTokenManager(deregStore, {
          writerCNs: [], relays: [{ name: "dev", url: `https://127.0.0.1:${relayPort}`, pkiDir: pki }],
        });
        try {
          assert.equal((await call(path, "PUT", { ...repair, otp: "123456" }, "operator", undefined,
            readOnlyManager.port)).status, 403, "non-writer repaired certificate inventory");
        } finally { readOnlyManager.close(); }
        const wrong = await operator(path, "PUT", { ...repair, otp: "123456",
          certificates: [{ requestId: seeded.requestId, certificatePem: readFileSync(join(pki, "relay-manager.pem"), "utf8") }] });
        assert.equal(wrong.status, 409);
        assert.equal(loadEnrollmentDocument(deregStore).requests.find((request) => request.id === seeded.requestId)?.certificatePem,
          null, "failed endpoint repair was not rolled back");
        const repaired = await operator(path, "PUT", { ...repair, otp: "123456" });
        assert.equal(repaired.status, 200);
        assert.equal(JSON.stringify(repaired.body).includes("BEGIN CERTIFICATE"), false, "repair response leaked PEM");
        const auditCount = loadEnrollmentDocument(deregStore).audit.length;
        const replay = await operator(path, "PUT", { ...repair, otp: "123456" });
        assert.equal(replay.status, 200); assert.equal(replay.body.operation.id, repaired.body.operation.id);
        const afterReplay = loadEnrollmentDocument(deregStore);
        assert.equal(afterReplay.audit.length, auditCount, "repair replay duplicated durable audit rows");
        assert.equal(JSON.stringify(afterReplay.audit).includes("BEGIN CERTIFICATE"), false, "repair audit leaked PEM");
      } finally { rmSync(materialRoot, { recursive: true, force: true }); }
    });

  it("repairs revocation capacity with writer+OTP, rollback, PEM-free output, and response-loss replay",
    { timeout: 30_000 }, async () => {
      const materialRoot = mkdtempSync(join(tmpdir(), "heliopause-capacity-api-"));
      const capacityStore = join(materialRoot, "enrollment.json");
      let closeCapacity = () => {};
      try {
        initializeEnrollmentDocument(capacityStore);
        const capacityManager = await startAppTokenManager(capacityStore, {
          relays: [{ name: "dev", url: `https://127.0.0.1:${relayPort}`, pkiDir: pki }],
        });
        closeCapacity = capacityManager.close;
        const capacityOperator = (path: string, body: unknown) =>
          call(path, "PUT", body, "operator", undefined, capacityManager.port);
        const makeCsr = (host: string, prefix: string) => {
          const key = join(materialRoot, `${prefix}.key`); const csr = join(materialRoot, `${prefix}.csr`);
          execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt",
            "ec_paramgen_curve:prime256v1", "-out", key]);
          execFileSync("openssl", ["req", "-new", "-key", key, "-subj", `/CN=${host}`, "-out", csr]);
          return csr;
        };
        const targetHost = "capacity-api.dev"; const targetLifecycle = "create-capacity-api-1";
        const targetCsr = makeCsr(targetHost, "target");
        const oldCsr = makeCsr("expired-capacity-api.dev", "old");
        const seeded = withEnrollmentTransaction(capacityStore, (document) => {
          const targetToken = createNodeToken(document, { hostname: targetHost, hostLifecycleId: targetLifecycle });
          const targetRequest = submitNodeCsr(document, { token: targetToken.token, csrPem: readFileSync(targetCsr, "utf8") }).row;
          const oldToken = createNodeToken(document, { hostname: "expired-capacity-api.dev", hostLifecycleId: "create-expired-api-1" });
          const oldRequest = submitNodeCsr(document, { token: oldToken.token, csrPem: readFileSync(oldCsr, "utf8") }).row;
          return { targetId: targetRequest.id, targetSha: targetRequest.csrSha256, oldId: oldRequest.id };
        });
        const targetCertPath = join(materialRoot, "target.pem");
        execFileSync("node", ["bin/heliopause-pki.ts", "sign-csr", pki, targetCsr, targetCertPath,
          `--name=${targetHost}`, `--expect-sha256=${seeded.targetSha}`], { cwd: process.cwd() });
        const indexPath = join(materialRoot, "index.txt"); const serialPath = join(materialRoot, "serial");
        const newCerts = join(materialRoot, "newcerts"); const caConfig = join(materialRoot, "ca.cnf");
        writeFileSync(indexPath, ""); writeFileSync(serialPath, "1000\n");
        execFileSync("mkdir", [newCerts]);
        writeFileSync(caConfig, [
          "[ca]", "default_ca=local", "[local]", `database=${indexPath}`, `new_certs_dir=${newCerts}`,
          `serial=${serialPath}`, "default_md=sha256", "policy=policy", "[policy]", "commonName=supplied",
          "[client]", "basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature",
          "extendedKeyUsage=critical,clientAuth",
        ].join("\n"));
        const opensslTime = (date: Date) => `${String(date.getUTCFullYear()).slice(-2)}${String(date.getUTCMonth() + 1).padStart(2, "0")}`
          + `${String(date.getUTCDate()).padStart(2, "0")}${String(date.getUTCHours()).padStart(2, "0")}`
          + `${String(date.getUTCMinutes()).padStart(2, "0")}${String(date.getUTCSeconds()).padStart(2, "0")}Z`;
        const oldFrom = new Date(Date.now() - 2 * 86_400_000); const oldTo = new Date(Date.now() - 86_400_000);
        const oldCertPath = join(materialRoot, "old.pem");
        execFileSync("openssl", ["ca", "-batch", "-notext", "-config", caConfig,
          "-cert", join(pki, "ca.pem"), "-keyfile", join(pki, "ca.key"), "-in", oldCsr,
          "-out", oldCertPath, "-startdate", opensslTime(oldFrom), "-enddate", opensslTime(oldTo),
          "-extensions", "client"]);
        const targetPem = readFileSync(targetCertPath, "utf8"); const oldPem = readFileSync(oldCertPath, "utf8");
        const oldCertificate = new X509Certificate(oldPem);
        const oldFingerprint = oldCertificate.fingerprint256.replaceAll(":", "").toLowerCase();
        withEnrollmentTransaction(capacityStore, (document) => {
          storeNodeCertificate(document, { requestId: seeded.targetId, certificatePem: targetPem,
            caPem: readFileSync(join(pki, "ca.pem"), "utf8"), caName: "dev", actor: "ops" });
          storeNodeCertificate(document, { requestId: seeded.oldId, certificatePem: oldPem,
            caPem: readFileSync(join(pki, "ca.pem"), "utf8"), caName: "dev", actor: "ops",
            now: new Date(Date.parse(oldCertificate.validFrom) + 60_000) });
          document.revocations = Array.from({ length: 1_588 }, (_, index) => ({
            fingerprint256: index === 0 ? oldFingerprint : index.toString(16).padStart(64, "0"),
            subject: null, reason: "x", actor: "x", revokedAt: oldFrom.toISOString(),
          }));
          beginHostDeregistration(document, {
            hostname: targetHost, hostLifecycleId: targetLifecycle, externalOperationId: "destroy-capacity-api-1",
            reason: "instance-destroy", requestedBy: "stardust:ops", actor: "app:destroyer",
            relayNames: ["dev"], scope: { appTokenId: "app-capacity", label: "destroyer", hostnamePattern: "*.dev" },
            trustedCaPems: [readFileSync(join(pki, "ca.pem"), "utf8")],
          });
        });
        const path = `/enrollment/host-deregistrations/${targetHost}/destroy-capacity-api-1/repairs/revocation-capacity`;
        const retained = loadEnrollmentDocument(capacityStore).revocations.filter((row) => row.fingerprint256 !== oldFingerprint)
          .map((row) => row.fingerprint256).sort();
        const digest = createHash("sha256").update(JSON.stringify(retained)).digest("hex");
        const compactedAt = new Date(Date.now() - 1_000).toISOString();
        const repair = { hostLifecycleId: targetLifecycle,
          relayConfirmations: [{ name: "dev", compactedAt, retainedFingerprintSha256: digest }] };
        assert.equal((await capacityOperator(path, repair)).status, 401, "capacity repair accepted no OTP");
        const readOnlyManager = await startAppTokenManager(capacityStore, {
          writerCNs: [], relays: [{ name: "dev", url: `https://127.0.0.1:${relayPort}`, pkiDir: pki }],
        });
        try {
          assert.equal((await call(path, "PUT", { ...repair, otp: "123456" }, "operator", undefined,
            readOnlyManager.port)).status, 403, "non-writer repaired revocation capacity");
        } finally { readOnlyManager.close(); }
        const beforeWrong = loadEnrollmentDocument(capacityStore).revocations.length;
        assert.equal((await capacityOperator(path, { ...repair, otp: "123456",
          relayConfirmations: [{ name: "dev", compactedAt, retainedFingerprintSha256: "0".repeat(64) }] })).status, 409);
        assert.equal(loadEnrollmentDocument(capacityStore).revocations.length, beforeWrong, "wrong digest was not rolled back");
        const repaired = await capacityOperator(path, { ...repair, otp: "123456" });
        assert.equal(repaired.status, 200, JSON.stringify(repaired.body));
        assert.equal(JSON.stringify(repaired.body).includes("BEGIN CERTIFICATE"), false);
        assert.equal(JSON.stringify(repaired.body).includes("tokenHash"), false);
        const auditCount = loadEnrollmentDocument(capacityStore).audit.length;
        const replay = await capacityOperator(path, { ...repair, otp: "123456" });
        assert.equal(replay.status, 200); assert.equal(replay.body.operation.id, repaired.body.operation.id);
        assert.equal(loadEnrollmentDocument(capacityStore).audit.length, auditCount);
      } finally { closeCapacity(); rmSync(materialRoot, { recursive: true, force: true }); }
    });

  it("closes only the exact lifecycle, converges through relay readiness, and queues reviewed policy removal", { timeout: 30_000 }, async () => {
    const issuedApp = withEnrollmentTransaction(deregStore, (document) => createAppToken(document, {
      label: "destroyer", scopes: ["enrollment:token-create", "enrollment:host-deregister"],
      hostnamePattern: "*.dev", createdBy: "ops",
    }));
    const appToken = issuedApp.token;
    const lifecycle = "create-operation-100";
    const node = await app("/enrollment/tokens", "POST", {
      hostname: "retire-me.dev", hostLifecycleId: lifecycle,
    }, appToken);
    assert.equal(node.status, 201);
    const sibling = await app("/enrollment/tokens", "POST", {
      hostname: "retire-me.dev", hostLifecycleId: "sibling-lifecycle", revokeExisting: false,
    }, appToken);
    assert.equal(sibling.status, 201);
    const signedKeyPath = join(root, "retire-exact.key"); const signedCsrPath = join(root, "retire-exact.csr");
    const signedCertPath = join(root, "retire-exact.pem");
    execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt",
      "ec_paramgen_curve:prime256v1", "-out", signedKeyPath]);
    execFileSync("openssl", ["req", "-new", "-key", signedKeyPath, "-subj",
      "/CN=retire-me.dev", "-out", signedCsrPath]);
    const submitted = withEnrollmentTransaction(deregStore, (document) => submitNodeCsr(document, {
      token: node.body.token as string, csrPem: readFileSync(signedCsrPath, "utf8"),
    }).row);
    execFileSync("node", ["bin/heliopause-pki.ts", "sign-csr", pki, signedCsrPath, signedCertPath,
      "--name=retire-me.dev", `--expect-sha256=${submitted.csrSha256}`], { cwd: process.cwd() });
    const certificatePem = readFileSync(signedCertPath, "utf8");
    const certificate = new X509Certificate(certificatePem);
    withEnrollmentTransaction(deregStore, (document) => {
      storeNodeCertificate(document, { requestId: submitted.id, certificatePem,
        caPem: readFileSync(join(pki, "ca.pem"), "utf8"), caName: "dev", actor: "ops" });
      document.requests.push({
        id: "pending-exact", hostname: "retire-me.dev", nodeTokenId: node.body.id,
        hostLifecycleId: lifecycle, status: "pending", csrPem: "pending", csrSha256: "1".repeat(64),
        publicKeySha256: "2".repeat(64), keyAlgorithm: "ECDSA-P256", createdAt: new Date().toISOString(),
        sourceIp: null, decidedAt: null, decidedBy: null, decisionReason: null, signedAt: null, caName: null,
        certificatePem: null, caPem: null, certificateSha256: null, certificateNotBefore: null,
        certificateNotAfter: null, retrievedAt: null,
      });
    });

    const path = "/enrollment/host-deregistrations/retire-me.dev/destroy-operation-200";
    const body = { hostLifecycleId: lifecycle, reason: "instance-destroy", requestedBy: "stardust:henry" };
    const destroyedAt = new Date(Date.now() - 120_000).toISOString();
    const first = await app(path, "PUT", body, appToken);
    assert.equal(first.status, 202);
    assert.equal(first.body.operation.credentials.state, "replicating");
    assert.equal(first.body.operation.credentials.tokens.revoked, 1);
    assert.equal(first.body.operation.credentials.requests.closed, 1);
    assert.equal(first.body.operation.credentials.certificates.revoked, 1);
    let storedAfterFirst = loadEnrollmentDocument(deregStore);
    assert.equal(storedAfterFirst.tokens.find((row) => row.id === sibling.body.id)?.revokedAt, null,
      "deregistration crossed into a same-host sibling lifecycle");
    const tombstonesAfterFirst = storedAfterFirst.hostLifecycleTombstones.length;
    const requestedAuditsAfterFirst = storedAfterFirst.audit.filter((row) => row.action === "host-deregistration.accept").length;
    assert.equal((await app(`${path}/infrastructure-destroyed`, "PUT", {
      hostLifecycleId: lifecycle, provider: "vultr", providerInstanceId: "vultr-9",
      destroyedAt,
    }, appToken)).status, 409, "a 2xx deregistration response became permission to destroy before relay install");

    relayAccepts = true;
    const replay = await app(path, "PUT", body, appToken);
    assert.equal(replay.status, 202);
    assert.equal(replay.body.operation.credentials.state, "ready_for_infrastructure_destroy");
    assert.equal(replay.body.operation.id, first.body.operation.id);
    storedAfterFirst = loadEnrollmentDocument(deregStore);
    assert.equal(storedAfterFirst.hostLifecycleTombstones.length, tombstonesAfterFirst);
    assert.equal(storedAfterFirst.audit.filter((row) => row.action === "host-deregistration.accept").length, requestedAuditsAfterFirst);
    assert.equal((await app(path, "PUT", { ...body, requestedBy: "somebody-else" }, appToken)).status, 409);
    assert.equal((await app(path, "PUT", { ...body, hostLifecycleId: "another-lifecycle" }, appToken)).status, 409);
    assert.equal((await app("/enrollment/host-deregistrations/retire-me.dev/unknown-op", "PUT", {
      ...body, hostLifecycleId: "unknown-lifecycle",
    }, appToken)).status, 404);

    const rotated = withEnrollmentTransaction(deregStore, (document) => createAppToken(document, {
      label: "destroyer-rotated", scopes: ["enrollment:host-deregister"], hostnamePattern: "*.dev", createdBy: "ops",
    }));
    assert.equal((await app(path, "GET", undefined, rotated.token)).status, 200);
    const outside = withEnrollmentTransaction(deregStore, (document) => createAppToken(document, {
      label: "prod-destroyer", scopes: ["enrollment:host-deregister"], hostnamePattern: "*.prod", createdBy: "ops",
    }));
    assert.equal((await app(path, "GET", undefined, outside.token)).status, 404);
    assert.equal((await app(path, "PUT", body, outside.token)).status, 404);
    assert.equal((await app(`${path}/infrastructure-destroyed`, "PUT", {
      hostLifecycleId: lifecycle, provider: "vultr", providerInstanceId: "vultr-9",
      destroyedAt,
    }, outside.token)).status, 404);

    const overlapping = withEnrollmentTransaction(deregStore, (document) => createAppToken(document, {
      label: "exact-destroyer", scopes: ["enrollment:host-deregister"],
      hostnamePattern: "retire-me.dev", createdBy: "ops",
    }));
    assert.equal((await app(path, "PUT", body, overlapping.token)).status, 404,
      "an overlapping but differently scoped token observed another authority's replay");

    const confirmation = {
      hostLifecycleId: lifecycle, provider: "vultr", providerInstanceId: "vultr-9", destroyedAt,
    };
    assert.equal((await app(`${path}/infrastructure-destroyed`, "PUT", {
      ...confirmation, destroyedAt: "08/30/2026",
    }, rotated.token)).status, 400);
    assert.equal((await app(`${path}/infrastructure-destroyed`, "PUT", {
      ...confirmation, destroyedAt: new Date(Date.now() + 60_000).toISOString(),
    }, rotated.token)).status, 400);
    const confirmed = await app(`${path}/infrastructure-destroyed`, "PUT", confirmation, rotated.token);
    assert.equal(confirmed.status, 202);
    assert.equal(confirmed.body.operation.policy.state, "queued");
    const confirmedAgain = await app(`${path}/infrastructure-destroyed`, "PUT", confirmation, rotated.token);
    assert.equal(confirmedAgain.status, 202);
    assert.equal((await app(`${path}/infrastructure-destroyed`, "PUT", {
      ...confirmation, providerInstanceId: "vultr-10",
    }, rotated.token)).status, 409);

    assert.equal((await app("/enrollment/tokens", "POST", {
      hostname: "retire-me.dev", hostLifecycleId: "create-operation-101",
    }, appToken)).status, 409, "hostname reuse crossed an unfinished policy removal");
    assert.equal((await operator(`${path}/policy-completed`, "PUT", {
      otp: "123456", hostLifecycleId: lifecycle, pullRequestUrl: "https://github.com/example/policy/pull/1",
      commitSha: "a".repeat(40), publishedGeneration: "generation-9",
      relayConfirmations: [{ name: "dev", absentAt: new Date(Date.now() + 60_000).toISOString() }],
    })).status, 400);
    const completed = await operator(`${path}/policy-completed`, "PUT", {
      otp: "123456", hostLifecycleId: lifecycle, pullRequestUrl: "https://github.com/example/policy/pull/1",
      commitSha: "a".repeat(40), publishedGeneration: "generation-9",
      relayConfirmations: [{ name: "dev", absentAt: new Date(Date.now() - 60_000).toISOString() }],
    });
    assert.equal(completed.status, 200);
    assert.equal(completed.body.operation.status, "completed");
    assert.equal((await app("/enrollment/tokens", "POST", {
      hostname: "retire-me.dev", hostLifecycleId: "create-operation-101",
    }, appToken)).status, 409, "policy attestation implicitly reopened a retired hostname");

    const stored = loadEnrollmentDocument(deregStore);
    assert.equal(stored.requests.find((row) => row.id === "pending-exact")?.status, "host-deregistered");
    assert.ok(stored.revocations.some((row) => row.fingerprint256 === certificate.fingerprint256.replaceAll(":", "").toLowerCase()));
    const serialized = JSON.stringify(stored.hostDeregistrations);
    assert.equal(serialized.includes(certificatePem), false);
    assert.equal(serialized.includes(appToken), false);
    assert.equal(serialized.includes(stored.tokens[0]!.tokenHash), false);
  });
});

describe("host deregistration policy break-glass recovery", () => {
  it("accepts the existing OTP-and-evidence endpoint from every destroyed worker-pending state", async () => {
    const recoveryStore = join(root, "policy-recovery-enrollment.json");
    initializeEnrollmentDocument(recoveryStore);
    const states = ["queued", "pr_open", "merged", "awaiting_publish", "published"] as const;
    withEnrollmentTransaction(recoveryStore, (document) => {
      const now = new Date("2026-08-31T00:10:00.000Z");
      for (const state of states) {
        const suffix = state.replaceAll("_", "-");
        const hostname = `manual-${suffix}.dev`;
        const hostLifecycleId = `create-${suffix}`;
        const externalOperationId = `destroy-${suffix}`;
        createNodeToken(document, { hostname, hostLifecycleId, now });
        beginHostDeregistration(document, {
          hostname, externalOperationId, hostLifecycleId,
          reason: "instance-destroy", requestedBy: "stardust", actor: "app:destroyer", relayNames: ["dev"],
          scope: { appTokenId: "app-1", label: "destroyer", hostnamePattern: "*.dev" }, now,
        });
        recordHostDeregistrationReplication(document, [
          { name: "dev", ok: true, count: 0, snapshotFingerprints: [] },
        ], ["dev"], now);
        const row = confirmHostInfrastructureDestroyed(document, {
          hostname, externalOperationId, hostLifecycleId,
          provider: "vultr", providerInstanceId: `vultr-${suffix}`,
          destroyedAt: "2026-08-31T00:09:00.000Z", actor: "app:destroyer", now,
        });
        row.policy.state = state;
        if (state !== "queued") {
          row.policy.pullRequestUrl = "https://github.test/o/r/pull/1";
          row.policy.commitSha = "b".repeat(40);
          row.policy.automation = {
            branch: `policy/host-deregister/${suffix}`, pullRequestNumber: 1,
            patchCommitSha: "b".repeat(40), mergeCommitSha: null,
            affectedRelays: ["dev"], reviewedBy: [], planGeneration: null, planProposedAt: null,
            plans: [], lastAttemptAt: null, lastError: null,
          };
        }
        if (["merged", "awaiting_publish", "published"].includes(state)) {
          row.policy.commitSha = "c".repeat(40);
          row.policy.automation!.mergeCommitSha = "c".repeat(40);
          row.policy.automation!.reviewedBy = ["human-reviewer"];
        }
        if (["awaiting_publish", "published"].includes(state)) {
          row.policy.publishedGeneration = "generation-1";
          row.policy.automation!.planGeneration = "generation-1";
          row.policy.automation!.planProposedAt = "2026-08-31T00:09:30.000Z";
          row.policy.automation!.plans = [{
            relay: "dev", hash: `sha256:${"d".repeat(64)}`, generation: "generation-1",
            proposedAt: "2026-08-31T00:09:30.000Z",
            publishedAt: state === "published" ? "2026-08-31T00:09:45.000Z" : null,
          }];
        }
      }
    });
    const started = await startAppTokenManager(recoveryStore);
    const recoveryPort = started.port;
    try {
      const withoutOtp = await call(
        "/enrollment/host-deregistrations/manual-queued.dev/destroy-queued/policy-completed",
        "PUT",
        {
          hostLifecycleId: "create-queued", pullRequestUrl: "https://github.test/o/r/pull/1",
          commitSha: "a".repeat(40), publishedGeneration: "generation-queued",
          relayConfirmations: [{ name: "dev", absentAt: "2026-08-31T00:09:30.000Z" }],
        },
        "operator",
        undefined,
        recoveryPort,
      );
      assert.equal(withoutOtp.status, 401, "manual recovery bypassed the existing OTP gate");
      assert.equal(loadEnrollmentDocument(recoveryStore).hostDeregistrations
        .find((row) => row.externalOperationId === "destroy-queued")?.policy.state, "queued");
      for (const state of states) {
        const suffix = state.replaceAll("_", "-");
        const answer = await call(
          `/enrollment/host-deregistrations/manual-${suffix}.dev/destroy-${suffix}/policy-completed`,
          "PUT",
          {
            otp: "123456", hostLifecycleId: `create-${suffix}`,
            pullRequestUrl: `https://github.test/o/r/pull/${states.indexOf(state) + 1}`,
            commitSha: "a".repeat(40), publishedGeneration: `generation-${suffix}`,
            relayConfirmations: [{ name: "dev", absentAt: "2026-08-31T00:09:30.000Z" }],
          },
          "operator",
          undefined,
          recoveryPort,
        );
        assert.equal(answer.status, 200, `${state}: ${JSON.stringify(answer.body)}`);
        assert.equal(answer.body.operation.policy.state, "completed");
        assert.equal(answer.body.operation.policy.completedBy, "ops");
      }
    } finally {
      started.close();
    }
  });
});

// The budget a polling caller actually has, pinned. Its own manager because pinning it means
// spending it, and its own group because every other test here would then fail on a limit it is not
// testing — which is exactly how this was found.
describe("the per-source bound on app-token requests", () => {
  let boundPort = 0;
  let closeBound = () => {};
  const { app, issueAppToken } = appTokenCalls(() => boundPort);

  before(async () => {
    const started = await startAppTokenManager(appStore);
    boundPort = started.port;
    closeBound = started.close;
  });
  after(() => { closeBound(); });

  it("counts app-token requests against the same bound as the certificate-less routes", async () => {
    const created = await issueAppToken({
      label: "chatty", scopes: ["enrollment:requests-read"], hostnamePattern: "*.dev",
    });
    // Not a rate limit on a credential: it is a bound on what one *address* can make this process
    // read synchronously, which is why it applies before the store is opened and why a refused
    // request still counts. 30 per minute — the number a dispatcher's polling interval has to fit
    // inside, and the reason a bounded wait for a CSR to appear is a wait, not a spin.
    let refusedAt = 0;
    for (let n = 1; n <= 31 && refusedAt === 0; n += 1) {
      const answer = await app("/enrollment/requests", "GET", undefined, created.body.token);
      if (answer.status === 429) refusedAt = n;
      else assert.equal(answer.status, 200, `request ${n} answered ${answer.status}`);
    }
    assert.equal(refusedAt, 31, "the app-token path is not counted by the enrollment bound");
    // An unknown token is refused before the store is read but after the counter — the bound exists
    // for callers who are guessing, so it must not be something guessing can step around.
    assert.equal((await app("/enrollment/requests", "GET", undefined, `hpapp_${"c".repeat(64)}`)).status, 429);
  });
});
