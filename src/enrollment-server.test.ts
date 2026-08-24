import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { initializeEnrollmentDocument, loadEnrollmentDocument } from "./enrollment-store.ts";
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

function call(path: string, method: "GET" | "POST", body?: unknown, mode: "operator" | "agent" = "operator", token?: string) {
  return new Promise<{ status: number; body: any }>((resolve, reject) => {
    const payload = body === undefined ? "" : JSON.stringify(body);
    const req = request({ host: "127.0.0.1", port, path, method, ca: readFileSync(join(pki, "ca.pem")),
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
