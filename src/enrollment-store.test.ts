import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  APP_TOKEN_PREFIX, MAX_CREATED_BY_CHARS, appTokenAllowsHostname, appTokenCreatedBy,
  beginHostDeregistration, bindLegacyHostLifecycle, completeHostDeregistrationPolicy,
  confirmHostInfrastructureDestroyed, createAppToken, createNodeToken, emptyEnrollmentDocument,
  fetchNodeCertificate, initializeEnrollmentDocument,
  loadEnrollmentDocument, looksLikeAppToken, looksLikeNodeToken, lookupAppToken, lookupNodeToken, NODE_TOKEN_PREFIX,
  recordHostDeregistrationReplication, rejectNodeCsr, reopenRetiredHostname,
  repairHostDeregistrationCertificateInventory, repairHostDeregistrationRevocationCapacity,
  revokeAppToken, saveEnrollmentDocument, storeNodeCertificate, submitNodeCsr, validateNodeCsrAsync,
  withEnrollmentTransaction, type NodeCsrRecord,
} from "./enrollment-store.ts";

function csr(root: string, name: string, suffix: string) {
  const key = join(root, `${suffix}.key`); const path = join(root, `${suffix}.csr`);
  execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", key]);
  execFileSync("openssl", ["req", "-new", "-key", key, "-subj", `/CN=${name}`, "-out", path]);
  return { key, path, pem: readFileSync(path, "utf8") };
}

function signClientCertificate(csrPath: string, outputPath: string, caPem: string, caKey: string, extPath: string): void {
  writeFileSync(extPath, [
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature",
    "extendedKeyUsage=critical,clientAuth",
  ].join("\n"));
  execFileSync("openssl", ["x509", "-req", "-in", csrPath, "-CA", caPem, "-CAkey", caKey,
    "-CAcreateserial", "-days", "1", "-sha256", "-extfile", extPath, "-out", outputPath]);
}

function storedRequest(input: Partial<NodeCsrRecord> & Pick<NodeCsrRecord, "id" | "hostname" | "nodeTokenId">): NodeCsrRecord {
  const defaults: NodeCsrRecord = {
    id: input.id, hostname: input.hostname, nodeTokenId: input.nodeTokenId, hostLifecycleId: null,
    status: "pending", csrPem: "fixture", csrSha256: "1".repeat(64), publicKeySha256: "2".repeat(64),
    keyAlgorithm: "ECDSA-P256", createdAt: "2026-08-01T00:00:00.000Z", sourceIp: null,
    decidedAt: null, decidedBy: null, decisionReason: null, signedAt: null, caName: null,
    certificatePem: null, caPem: null, certificateSha256: null, certificateNotBefore: null,
    certificateNotAfter: null, retrievedAt: null,
  };
  return { ...defaults, ...input };
}

// ── Reopening a retired hostname ─────────────────────────────────────────────
//
// The 409 that guards a retired name has always said "an operator must explicitly reopen it before
// reuse", and for as long as it has said that, nothing implemented it. It was found on 2026-09-02:
// stardust submitted a re-create of `web-01.dev-icn-vtr` and the create saga stopped at token issue
// with exactly that message. The gate was right and the door behind it did not exist.
describe("reopenRetiredHostname", () => {
  /** A hostname carried all the way to `completed`, the only state a reopen is allowed from. */
  const retired = (over: { hostname?: string; stopAt?: "credentials" | "destroyed" } = {}) => {
    const host = over.hostname ?? "web-01.dev";
    const document = emptyEnrollmentDocument();
    const now = new Date("2026-09-01T00:10:00.000Z");
    createNodeToken(document, { hostname: host, hostLifecycleId: "create-1", now });
    beginHostDeregistration(document, {
      hostname: host, externalOperationId: "destroy-1", hostLifecycleId: "create-1",
      reason: "instance-destroy", requestedBy: "stardust", actor: "app:destroyer", relayNames: ["dev"],
      scope: { appTokenId: "app-1", label: "destroyer", hostnamePattern: "*.dev" }, trustedCaPems: [], now,
    });
    if (over.stopAt === "credentials") return { document, host, now };
    recordHostDeregistrationReplication(document, [
      { name: "dev", ok: true, count: 0, snapshotFingerprints: [] },
    ], ["dev"], now);
    confirmHostInfrastructureDestroyed(document, {
      hostname: host, externalOperationId: "destroy-1", hostLifecycleId: "create-1",
      provider: "vultr", providerInstanceId: "vultr-1", destroyedAt: "2026-09-01T00:09:00.000Z",
      actor: "app:destroyer", now,
    });
    if (over.stopAt === "destroyed") return { document, host, now };
    completeHostDeregistrationPolicy(document, {
      hostname: host, externalOperationId: "destroy-1", hostLifecycleId: "create-1",
      pullRequestUrl: "https://github.test/o/r/pull/16", commitSha: "f".repeat(40),
      publishedGeneration: "f2628da", relayConfirmations: [{ name: "dev", absentAt: "2026-09-01T00:09:30.000Z" }],
      relayNames: ["dev"], actor: "ops", now,
    });
    return { document, host, now };
  };

  const reopen = (document: ReturnType<typeof emptyEnrollmentDocument>, host: string, over: Record<string, unknown> = {}) =>
    reopenRetiredHostname(document, {
      hostname: host, externalOperationId: "destroy-1", reason: "stardust is re-creating the instance",
      actor: "ops", now: new Date("2026-09-02T01:00:00.000Z"), ...over,
    });

  it("frees the hostname for a new lifecycle and keeps the old one dead", () => {
    // The whole safety of granting this. Reuse of the *name* is what an operator decides; reuse of
    // the retired *lifecycle* is never on the table, and the two are separate checks so the second
    // cannot be lifted by accident along with the first.
    const { document, host } = retired();
    assert.throws(() => createNodeToken(document, { hostname: host, hostLifecycleId: "create-2" }), /must explicitly reopen/);

    const result = reopen(document, host);
    assert.equal(result.changed, true);
    assert.equal(result.row.reopened?.by, "ops");
    assert.equal(result.row.reopened?.reason, "stardust is re-creating the instance");

    // The name is now available — to a *new* lifecycle.
    const token = createNodeToken(document, { hostname: host, hostLifecycleId: "create-2" });
    assert.equal(token.row.hostname, host);
    // And permanently unavailable to the retired one.
    assert.throws(() => createNodeToken(document, { hostname: host, hostLifecycleId: "create-1" }), /deregistered/);
  });

  it("keeps the deregistration as evidence rather than deleting it", () => {
    // A retirement is what proves the teardown happened — lifecycle, provider instance, relay
    // confirmations, reviewed commit. Reusing the name makes none of that untrue, and deleting the
    // row to unblock a re-create would leave "was it ever actually destroyed?" with no answer.
    const { document, host } = retired();
    reopen(document, host);
    assert.equal(document.hostDeregistrations.length, 1);
    const row = document.hostDeregistrations[0]!;
    assert.equal(row.status, "completed");
    assert.equal(row.policy.commitSha, "f".repeat(40));
    assert.equal(row.infrastructure.providerInstanceId, "vultr-1");
    assert.equal(document.hostLifecycleTombstones.length, 1);
    assert.ok(document.audit.some((event) =>
      event.action === "host-deregistration.hostname-reopened" && event.actor === "ops"));
  });

  it("refuses to reopen a teardown that has not finished", () => {
    // A new host taking a name whose VM may still exist, or whose policy pull request is still open,
    // races the unfinished half over the same certificates and the same policy entry.
    for (const stopAt of ["credentials", "destroyed"] as const) {
      const { document, host } = retired({ stopAt });
      assert.throws(() => reopen(document, host), /not completed/, `reopen was allowed from ${stopAt}`);
      assert.throws(() => createNodeToken(document, { hostname: host, hostLifecycleId: "create-2" }), /reopen|deregistered/);
    }
  });

  it("requires the exact operation, and a reason", () => {
    const { document, host } = retired();
    // Not "reopen whatever retired this name": an operator with the wrong retirement in mind is
    // refused rather than quietly opening a different one.
    assert.throws(() => reopen(document, host, { externalOperationId: "destroy-2" }), /not found/);
    assert.throws(() => reopen(document, "other-host.dev"), /not found/);
    // The reason is the only place the argument for reusing the name survives.
    assert.throws(() => reopen(document, host, { reason: "  " }), /reason must be/);
    assert.throws(() => reopen(document, host, { actor: "" }), /actor must be/);
  });

  it("is idempotent, and keeps the first operator's record", () => {
    const { document, host } = retired();
    const first = reopen(document, host);
    const second = reopen(document, host, { actor: "someone-else", reason: "different reason" });
    assert.equal(second.changed, false);
    assert.equal(second.row.reopened?.by, "ops");
    assert.equal(second.row.reopened?.at, first.row.reopened?.at);
    assert.equal(document.audit.filter((e) => e.action === "host-deregistration.hostname-reopened").length, 1);
  });

  it("survives a save/load round trip, and a store written before the field existed", () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-reopen-"));
    try {
      const { document, host } = retired();
      reopen(document, host);
      const file = join(root, "store.json");
      saveEnrollmentDocument(file, document);
      const reloaded = loadEnrollmentDocument(file);
      assert.equal(reloaded!.hostDeregistrations[0]!.reopened?.by, "ops");
      // A store written before this field existed has no `reopened` key. It must load as "not
      // reopened" rather than being refused for an unsupported shape.
      const older = JSON.parse(readFileSync(file, "utf8")) as { hostDeregistrations: Array<Record<string, unknown>> };
      delete older.hostDeregistrations[0]!.reopened;
      writeFileSync(file, JSON.stringify(older));
      const legacy = loadEnrollmentDocument(file);
      assert.equal(legacy!.hostDeregistrations[0]!.reopened, null);
      assert.throws(() => createNodeToken(legacy!, { hostname: host, hostLifecycleId: "create-2" }), /must explicitly reopen/);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});

describe("standalone enrollment store", () => {
  it("allows exact break-glass policy evidence from every destroyed worker-pending state", () => {
    for (const state of ["queued", "pr_open", "merged", "awaiting_publish", "published"] as const) {
      const document = emptyEnrollmentDocument();
      const now = new Date("2026-08-31T00:10:00.000Z");
      createNodeToken(document, { hostname: "manual-recovery.dev", hostLifecycleId: "create-1", now });
      beginHostDeregistration(document, {
        hostname: "manual-recovery.dev", externalOperationId: "destroy-1", hostLifecycleId: "create-1",
        reason: "instance-destroy", requestedBy: "stardust", actor: "app:destroyer", relayNames: ["dev"],
        scope: { appTokenId: "app-1", label: "destroyer", hostnamePattern: "*.dev" }, trustedCaPems: [], now,
      });
      recordHostDeregistrationReplication(document, [
        { name: "dev", ok: true, count: 0, snapshotFingerprints: [] },
      ], ["dev"], now);
      const row = confirmHostInfrastructureDestroyed(document, {
        hostname: "manual-recovery.dev", externalOperationId: "destroy-1", hostLifecycleId: "create-1",
        provider: "vultr", providerInstanceId: "vultr-1", destroyedAt: "2026-08-31T00:09:00.000Z",
        actor: "app:destroyer", now,
      });
      row.policy.state = state;

      const completed = completeHostDeregistrationPolicy(document, {
        hostname: "manual-recovery.dev", externalOperationId: "destroy-1", hostLifecycleId: "create-1",
        pullRequestUrl: "https://github.test/o/r/pull/1", commitSha: "a".repeat(40),
        publishedGeneration: "generation-1",
        relayConfirmations: [{ name: "dev", absentAt: "2026-08-31T00:09:30.000Z" }],
        relayNames: ["dev"], actor: "ops", now,
      });
      assert.equal(completed.policy.state, "completed", `manual recovery was blocked from ${state}`);
      assert.equal(completed.status, "completed");
      assert.equal(completed.policy.completedBy, "ops");
    }
  });

  it("fails closed on a persisted publish state whose durable automation evidence is incomplete", () => {
    const document = emptyEnrollmentDocument();
    const now = new Date("2026-08-31T00:10:00.000Z");
    createNodeToken(document, { hostname: "corrupt-policy.dev", hostLifecycleId: "create-1", now });
    beginHostDeregistration(document, {
      hostname: "corrupt-policy.dev", externalOperationId: "destroy-1", hostLifecycleId: "create-1",
      reason: "instance-destroy", requestedBy: "stardust", actor: "app:destroyer", relayNames: ["dev"],
      scope: { appTokenId: "app-1", label: "destroyer", hostnamePattern: "*.dev" }, trustedCaPems: [], now,
    });
    recordHostDeregistrationReplication(document, [
      { name: "dev", ok: true, count: 0, snapshotFingerprints: [] },
    ], ["dev"], now);
    const row = confirmHostInfrastructureDestroyed(document, {
      hostname: "corrupt-policy.dev", externalOperationId: "destroy-1", hostLifecycleId: "create-1",
      provider: "vultr", providerInstanceId: "vultr-1", destroyedAt: "2026-08-31T00:09:00.000Z",
      actor: "app:destroyer", now,
    });
    row.policy.state = "awaiting_publish";
    row.policy.pullRequestUrl = "https://github.test/o/r/pull/1";
    row.policy.commitSha = "c".repeat(40);
    row.policy.publishedGeneration = "generation-1";
    row.policy.automation = {
      branch: "policy/host-deregister/destroy-1", pullRequestNumber: 1,
      patchCommitSha: "b".repeat(40), mergeCommitSha: "c".repeat(40),
      affectedRelays: ["dev"], reviewedBy: ["human-reviewer"],
      planGeneration: "generation-1", planProposedAt: "2026-08-31T00:09:30.000Z",
      plans: [], lastAttemptAt: null, lastError: null,
    };
    const corruptRoot = mkdtempSync(join(tmpdir(), "heliopause-corrupt-policy-"));
    const path = join(corruptRoot, "store.json");
    try {
      writeFileSync(path, JSON.stringify(document), { mode: 0o600 });
      assert.throws(() => loadEnrollmentDocument(path), /lacks exact durable plans/);
    } finally {
      rmSync(corruptRoot, { recursive: true, force: true });
    }
  });

  it("rejects a non-boolean revokeExisting before changing existing tokens", () => {
    const document = emptyEnrollmentDocument();
    const issued = createNodeToken(document, { hostname: "node-keep.dev" });
    assert.throws(
      () => createNodeToken(document, { hostname: "node-keep.dev", revokeExisting: "false" as unknown as boolean }),
      /revokeExisting must be a boolean/,
    );
    assert.equal(document.tokens.find((token) => token.id === issued.row.id)?.revokedAt, null);
  });

  it("requires explicit one-time initialization before any transaction", () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-enroll-init-"));
    const path = join(root, "store.json");
    try {
      assert.throws(
        () => withEnrollmentTransaction(path, () => undefined, { waitMs: 0 }),
        (error: unknown) => (error as { statusCode?: number }).statusCode === 503,
      );
      assert.throws(
        () => loadEnrollmentDocument(path),
        (error: unknown) => (error as { statusCode?: number }).statusCode === 503,
      );
      assert.equal(existsSync(path), false);
      initializeEnrollmentDocument(path);
      assert.equal(statSync(path).mode & 0o777, 0o600);
      const original = readFileSync(path, "utf8");
      assert.throws(() => initializeEnrollmentDocument(path), /refusing to overwrite/);
      assert.equal(readFileSync(path, "utf8"), original);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("stores only a token hash and preserves a different CSR as conflict", () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-enroll-store-"));
    const document = emptyEnrollmentDocument();
    const issued = createNodeToken(document, { hostname: "node-01.dev", createdBy: "ops" });
    assert.equal(JSON.stringify(document).includes(issued.token), false);
    const first = submitNodeCsr(document, { token: issued.token, csrPem: csr(root, "node-01.dev", "one").pem });
    assert.equal(first.row.status, "pending");
    assert.equal(submitNodeCsr(document, { token: issued.token, csrPem: first.row.csrPem }).created, false);
    const second = submitNodeCsr(document, { token: issued.token, csrPem: csr(root, "node-01.dev", "two").pem });
    assert.equal(second.row.status, "conflict");
    assert.equal(document.requests.length, 2);
    assert.throws(
      () => submitNodeCsr(document, { token: issued.token, csrPem: csr(root, "node-01.dev", "three").pem }),
      (error: unknown) => (error as { statusCode?: number }).statusCode === 429,
    );
    const structurallyPem = "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n";
    assert.throws(
      () => submitNodeCsr(document, { token: issued.token, csrPem: structurallyPem }),
      (error: unknown) => (error as { statusCode?: number }).statusCode === 429,
      "the host cap must reject before invoking OpenSSL on a new CSR",
    );
    rejectNodeCsr(document, second.row.id, "ops-review", "unexpected replacement key");
    assert.equal(second.row.status, "rejected");
  });

  it("accepts the offline signer profile and returns it only to the submitting token", () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-enroll-cert-")); const ca = join(root, "pki");
    execFileSync("node", ["bin/heliopause-pki.ts", "init", ca], { cwd: process.cwd() });
    const document = emptyEnrollmentDocument(); const issued = createNodeToken(document, { hostname: "node-02.dev" });
    const material = csr(root, "node-02.dev", "host");
    const request = submitNodeCsr(document, { token: issued.token, csrPem: material.pem }).row;
    const cert = join(root, "agent.pem");
    execFileSync("node", ["bin/heliopause-pki.ts", "sign-csr", ca, material.path, cert,
      "--name=node-02.dev", `--expect-sha256=${request.csrSha256}`], { cwd: process.cwd() });
    storeNodeCertificate(document, { requestId: request.id, certificatePem: readFileSync(cert, "utf8"),
      caPem: readFileSync(join(ca, "ca.pem"), "utf8"), caName: "dev", actor: "ops" });
    const bundle = fetchNodeCertificate(document, request.id, issued.token);
    assert.match(bundle.certificatePem, /BEGIN CERTIFICATE/);
    assert.equal(request.status, "signed"); assert.ok(request.retrievedAt);
    const auditLength = document.audit.length;
    fetchNodeCertificate(document, request.id, issued.token);
    assert.equal(document.audit.length, auditLength, "repeated certificate fetch grew the store");
    const other = createNodeToken(document, { hostname: "other.dev" });
    assert.throws(() => fetchNodeCertificate(document, request.id, other.token), /not ready/);
  });

  it("expires node tokens and bounds legacy tokens from their original issue time", () => {
    const now = new Date("2026-08-15T00:00:00.000Z");
    const document = emptyEnrollmentDocument();
    const issued = createNodeToken(document, { hostname: "expires.dev", ttlSec: 300, now });
    assert.equal(issued.row.expiresAt, "2026-08-15T00:05:00.000Z");
    assert.ok(lookupNodeToken(document, issued.token, new Date("2026-08-15T00:04:59.999Z")));
    assert.equal(lookupNodeToken(document, issued.token, new Date("2026-08-15T00:05:00.000Z")), null);

    const root = mkdtempSync(join(tmpdir(), "heliopause-enroll-legacy-"));
    const path = join(root, "store.json");
    const legacy = structuredClone(document) as unknown as { tokens: Array<Record<string, unknown>> };
    delete legacy.tokens[0]!.expiresAt;
    saveEnrollmentDocument(path, legacy as never);
    assert.ok(Number.isFinite(Date.parse(loadEnrollmentDocument(path).tokens[0]!.expiresAt)));
  });

  it("migrates a missing lifecycle as legacy but refuses a malformed persisted lifecycle", () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-enroll-lifecycle-"));
    const path = join(root, "store.json");
    try {
      const document = emptyEnrollmentDocument();
      createNodeToken(document, { hostname: "legacy.dev" });
      const legacy = structuredClone(document) as unknown as { tokens: Array<Record<string, unknown>> };
      delete legacy.tokens[0]!.hostLifecycleId;
      writeFileSync(path, JSON.stringify(legacy));
      const loadedLegacy = loadEnrollmentDocument(path);
      assert.equal(loadedLegacy.tokens[0]!.hostLifecycleId, null);
      assert.deepEqual(loadedLegacy.hostLifecycleBindings, [], "legacy schema did not migrate missing bindings closed");
      for (const malformed of [7, {}, "", " lifecycle "]) {
        legacy.tokens[0]!.hostLifecycleId = malformed;
        writeFileSync(path, JSON.stringify(legacy));
        assert.throws(() => loadEnrollmentDocument(path), /hostLifecycleId/);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("binds only explicitly evidenced legacy inventory and audits both sides of the mutation", () => {
    const document = emptyEnrollmentDocument();
    const token = createNodeToken(document, { hostname: "legacy-bind.dev" }).row;
    const otherwiseOmissible = createNodeToken(document, { hostname: "legacy-bind.dev" }).row;
    const request = storedRequest({ id: "legacy-csr", hostname: "legacy-bind.dev", nodeTokenId: token.id });
    document.requests.push(request);
    const evidence = {
      stardustCreateOperationId: "create-uuid-1", provider: "vultr" as const, providerInstanceId: "vm-77",
      nodeTokenIds: [token.id, otherwiseOmissible.id], csrRequestIds: [request.id], certificateFingerprints: [],
    };
    assert.throws(() => bindLegacyHostLifecycle(document, {
      hostname: "legacy-bind.dev", hostLifecycleId: "create-uuid-1",
      evidence: { ...evidence, nodeTokenIds: [token.id] }, trustedCaPems: [], actor: "ops",
    }), /complete legacy inventory/);
    assert.equal(token.hostLifecycleId, null, "a rejected partial inventory changed the token");
    assert.equal(otherwiseOmissible.hostLifecycleId, null, "a rejected partial inventory changed an omitted token");
    const result = bindLegacyHostLifecycle(document, {
      hostname: "legacy-bind.dev", hostLifecycleId: "create-uuid-1", evidence, trustedCaPems: [], actor: "ops",
    });
    assert.equal(result.tokensBound, 2); assert.equal(result.requestsBound, 1);
    assert.equal(token.hostLifecycleId, "create-uuid-1"); assert.equal(request.hostLifecycleId, "create-uuid-1");
    assert.equal(otherwiseOmissible.hostLifecycleId, "create-uuid-1");
    assert.deepEqual(document.hostLifecycleBindings.map(({ hostname, hostLifecycleId, provider, providerInstanceId }) =>
      ({ hostname, hostLifecycleId, provider, providerInstanceId })), [{
      hostname: "legacy-bind.dev", hostLifecycleId: "create-uuid-1", provider: "vultr", providerInstanceId: "vm-77",
    }]);
    assert.deepEqual(document.audit.slice(-2).map((event) => event.action), [
      "host-lifecycle.bind-before", "host-lifecycle.bind-after",
    ]);
    assert.throws(() => bindLegacyHostLifecycle(document, {
      hostname: "legacy-bind.dev", hostLifecycleId: "create-uuid-1", evidence, trustedCaPems: [], actor: "ops",
    }), /rebinding is refused/);
    assert.throws(() => bindLegacyHostLifecycle(document, {
      hostname: "some-other-name.dev", hostLifecycleId: "create-uuid-2",
      evidence: { ...evidence, stardustCreateOperationId: "create-uuid-2" }, trustedCaPems: [], actor: "ops",
    }), /complete legacy inventory/);
    const operation = beginHostDeregistration(document, {
      hostname: "legacy-bind.dev", hostLifecycleId: "create-uuid-1", externalOperationId: "destroy-uuid-1",
      reason: "instance-destroy", requestedBy: "stardust:ops", actor: "app:destroyer", relayNames: ["dev"],
      scope: { appTokenId: "app-1", label: "destroyer", hostnamePattern: "*.dev" }, trustedCaPems: [],
    }).row;
    assert.equal(operation.infrastructure.expectedProviderInstanceId, "vm-77");
    recordHostDeregistrationReplication(document, [{ name: "dev", ok: true, count: 0, snapshotFingerprints: [] }], ["dev"]);
    const destroyedAt = new Date(Date.now() - 1_000).toISOString();
    assert.throws(() => confirmHostInfrastructureDestroyed(document, {
      hostname: operation.hostname, hostLifecycleId: operation.hostLifecycleId,
      externalOperationId: operation.externalOperationId, provider: "vultr",
      providerInstanceId: "vm-other", destroyedAt, actor: "ops",
    }), /conflicts with the lifecycle binding inventory/);
    assert.equal(confirmHostInfrastructureDestroyed(document, {
      hostname: operation.hostname, hostLifecycleId: operation.hostLifecycleId,
      externalOperationId: operation.externalOperationId, provider: "vultr",
      providerInstanceId: "vm-77", destroyedAt, actor: "ops",
    }).infrastructure.providerInstanceId, "vm-77");
  });

  it("loads lifecycle bindings as strict unique immutable enforcement records", () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-lifecycle-binding-")); const path = join(root, "store.json");
    try {
      const document = emptyEnrollmentDocument();
      const token = createNodeToken(document, { hostname: "binding.dev" }).row;
      bindLegacyHostLifecycle(document, {
        hostname: "binding.dev", hostLifecycleId: "create-binding-1", trustedCaPems: [], actor: "ops",
        evidence: { stardustCreateOperationId: "create-binding-1", provider: "vultr",
          providerInstanceId: "vm-binding-1", nodeTokenIds: [token.id], csrRequestIds: [], certificateFingerprints: [] },
      });
      saveEnrollmentDocument(path, document);
      const loaded = loadEnrollmentDocument(path);
      assert.deepEqual(loaded.hostLifecycleBindings, document.hostLifecycleBindings);
      const malformed = structuredClone(document);
      malformed.hostLifecycleBindings.push({ ...malformed.hostLifecycleBindings[0]!, hostLifecycleId: "create-binding-2" });
      writeFileSync(path, JSON.stringify(malformed));
      assert.throws(() => loadEnrollmentDocument(path), /duplicate lifecycle binding/);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("binds signed legacy inventory only from trusted PEM truth, never cached certificate metadata",
    { timeout: 15_000 }, () => {
      const root = mkdtempSync(join(tmpdir(), "heliopause-bind-cert-truth-")); const ca = join(root, "pki");
      try {
        execFileSync("node", ["bin/heliopause-pki.ts", "init", ca], { cwd: process.cwd() });
        const document = emptyEnrollmentDocument();
        const issued = createNodeToken(document, { hostname: "legacy-cert.dev" });
        const material = csr(root, "legacy-cert.dev", "legacy");
        const request = submitNodeCsr(document, { token: issued.token, csrPem: material.pem }).row;
        const certPath = join(root, "legacy.pem");
        execFileSync("node", ["bin/heliopause-pki.ts", "sign-csr", ca, material.path, certPath,
          "--name=legacy-cert.dev", `--expect-sha256=${request.csrSha256}`], { cwd: process.cwd() });
        const caPem = readFileSync(join(ca, "ca.pem"), "utf8");
        storeNodeCertificate(document, { requestId: request.id, certificatePem: readFileSync(certPath, "utf8"),
          caPem, caName: "dev", actor: "ops" });
        const actualFingerprint = request.certificateSha256!;
        const evidence = { stardustCreateOperationId: "create-legacy-cert-1", provider: "vultr" as const,
          providerInstanceId: "vm-legacy-cert", nodeTokenIds: [issued.row.id], csrRequestIds: [request.id],
          certificateFingerprints: [actualFingerprint] };
        assert.throws(() => bindLegacyHostLifecycle(document, {
          hostname: "legacy-cert.dev", hostLifecycleId: "create-legacy-cert-1",
          evidence, trustedCaPems: [], actor: "ops",
        }), /not valid under a configured trusted CA/);
        const actualNotAfter = request.certificateNotAfter;
        request.certificateNotAfter = "2020-01-01T00:00:00.000Z";
        assert.throws(() => bindLegacyHostLifecycle(document, {
          hostname: "legacy-cert.dev", hostLifecycleId: "create-legacy-cert-1",
          evidence, trustedCaPems: [caPem], actor: "ops",
        }), /metadata conflicts with its trusted PEM/);
        assert.equal(issued.row.hostLifecycleId, null); assert.equal(request.hostLifecycleId, null);
        request.certificateNotAfter = actualNotAfter;
        assert.equal(bindLegacyHostLifecycle(document, {
          hostname: "legacy-cert.dev", hostLifecycleId: "create-legacy-cert-1",
          evidence, trustedCaPems: [caPem], actor: "ops",
        }).requestsBound, 1);
      } finally { rmSync(root, { recursive: true, force: true }); }
    });

  it("revokes a trusted unexpired PEM even when cached metadata falsely says expired",
    { timeout: 15_000 }, () => {
      const root = mkdtempSync(join(tmpdir(), "heliopause-dereg-cert-truth-")); const ca = join(root, "pki");
      try {
        execFileSync("node", ["bin/heliopause-pki.ts", "init", ca], { cwd: process.cwd() });
        const document = emptyEnrollmentDocument();
        const issued = createNodeToken(document, { hostname: "metadata-lie.dev", hostLifecycleId: "create-metadata-lie" });
        const material = csr(root, "metadata-lie.dev", "host");
        const request = submitNodeCsr(document, { token: issued.token, csrPem: material.pem }).row;
        const certPath = join(root, "agent.pem");
        execFileSync("node", ["bin/heliopause-pki.ts", "sign-csr", ca, material.path, certPath,
          "--name=metadata-lie.dev", `--expect-sha256=${request.csrSha256}`], { cwd: process.cwd() });
        const caPem = readFileSync(join(ca, "ca.pem"), "utf8");
        storeNodeCertificate(document, { requestId: request.id, certificatePem: readFileSync(certPath, "utf8"),
          caPem, caName: "dev", actor: "ops" });
        const actualFingerprint = request.certificateSha256!;
        const untrustedDocument = structuredClone(document);
        const untrustedOperation = beginHostDeregistration(untrustedDocument, {
          hostname: "metadata-lie.dev", hostLifecycleId: "create-metadata-lie",
          externalOperationId: "destroy-untrusted", reason: "instance-destroy",
          requestedBy: "stardust:ops", actor: "app:destroyer", relayNames: ["dev"],
          scope: { appTokenId: "app-1", label: "destroyer", hostnamePattern: "*.dev" }, trustedCaPems: [],
        }).row;
        assert.equal(untrustedOperation.blocked?.code, "certificate_inventory_incomplete");
        assert.deepEqual(untrustedOperation.credentials.requiredRevocationFingerprints, []);
        assert.equal(untrustedDocument.revocations.length, 0);
        request.certificateNotAfter = "2020-01-01T00:00:00.000Z";
        request.certificateSha256 = "f".repeat(64);
        const operation = beginHostDeregistration(document, {
          hostname: "metadata-lie.dev", hostLifecycleId: "create-metadata-lie",
          externalOperationId: "destroy-metadata-lie", reason: "instance-destroy",
          requestedBy: "stardust:ops", actor: "app:destroyer", relayNames: ["dev"],
          scope: { appTokenId: "app-1", label: "destroyer", hostnamePattern: "*.dev" },
          trustedCaPems: [caPem],
        }).row;
        assert.equal(operation.blocked?.code, "certificate_inventory_incomplete");
        assert.equal(operation.credentials.certificates.expired, 0);
        assert.deepEqual(operation.credentials.requiredRevocationFingerprints, [actualFingerprint]);
        assert.equal(document.revocations.some((row) => row.fingerprint256 === actualFingerprint), true);
        assert.equal(document.revocations.some((row) => row.fingerprint256 === "f".repeat(64)), false);
      } finally { rmSync(root, { recursive: true, force: true }); }
    });

  it("repairs incomplete certificate inventory and resumes the same durable operation", { timeout: 15_000 }, () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-dereg-cert-repair-")); const ca = join(root, "pki");
    try {
      execFileSync("node", ["bin/heliopause-pki.ts", "init", ca], { cwd: process.cwd() });
      const document = emptyEnrollmentDocument();
      const issued = createNodeToken(document, { hostname: "repair-cert.dev", hostLifecycleId: "create-repair-1" });
      const material = csr(root, "repair-cert.dev", "host");
      const request = submitNodeCsr(document, { token: issued.token, csrPem: material.pem }).row;
      const certPath = join(root, "agent.pem");
      execFileSync("node", ["bin/heliopause-pki.ts", "sign-csr", ca, material.path, certPath,
        "--name=repair-cert.dev", `--expect-sha256=${request.csrSha256}`], { cwd: process.cwd() });
      storeNodeCertificate(document, { requestId: request.id, certificatePem: readFileSync(certPath, "utf8"),
        caPem: readFileSync(join(ca, "ca.pem"), "utf8"), caName: "dev", actor: "ops" });
      const missingPem = request.certificatePem!; request.certificatePem = null; request.certificateSha256 = null;
      const operation = beginHostDeregistration(document, {
        hostname: "repair-cert.dev", externalOperationId: "destroy-repair-1", hostLifecycleId: "create-repair-1",
        reason: "instance-destroy", requestedBy: "stardust:ops", actor: "app:destroyer", relayNames: ["dev"],
        scope: { appTokenId: "app-1", label: "destroyer", hostnamePattern: "*.dev" },
        trustedCaPems: [readFileSync(join(ca, "ca.pem"), "utf8")],
      }).row;
      assert.equal(operation.blocked?.code, "certificate_inventory_incomplete");
      const selfSignedPath = join(root, "self-signed.pem");
      const profilePath = join(root, "self-signed.ext");
      writeFileSync(profilePath, ["basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature",
        "extendedKeyUsage=critical,clientAuth"].join("\n"));
      execFileSync("openssl", ["x509", "-req", "-in", material.path, "-signkey", material.key,
        "-days", "1", "-sha256", "-extfile", profilePath, "-out", selfSignedPath]);
      const selfSignedPem = readFileSync(selfSignedPath, "utf8");
      assert.throws(() => repairHostDeregistrationCertificateInventory(document, {
        hostname: operation.hostname, externalOperationId: operation.externalOperationId,
        hostLifecycleId: operation.hostLifecycleId,
        certificates: [{ requestId: request.id, certificatePem: selfSignedPem }],
        trustedCaPems: [readFileSync(join(ca, "ca.pem"), "utf8")], actor: "ops",
      }), /configured trusted CA/);
      assert.equal(request.certificatePem, null, "a rejected certificate repair mutated inventory");
      const repaired = repairHostDeregistrationCertificateInventory(document, {
        hostname: operation.hostname, externalOperationId: operation.externalOperationId,
        hostLifecycleId: operation.hostLifecycleId, certificates: [{ requestId: request.id, certificatePem: missingPem }],
        trustedCaPems: [readFileSync(join(ca, "ca.pem"), "utf8")], actor: "ops",
      });
      assert.equal(repaired.id, operation.id); assert.equal(repaired.credentials.state, "replicating");
      assert.equal(repaired.blocked, null); assert.equal(repaired.credentials.certificates.revoked, 1);
      assert.equal(JSON.stringify(repaired).includes(missingPem), false, "operation leaked repaired certificate PEM");
      assert.equal(JSON.stringify(document.audit).includes("BEGIN CERTIFICATE"), false, "audit leaked certificate PEM");
      assert.deepEqual(document.audit.slice(-2).map((event) => event.action), [
        "certificate.revoke", "host-deregistration.certificate-repair-after",
      ]);
      assert.ok(document.audit.some((event) => event.action === "host-deregistration.certificate-repair-before"));
      const auditRows = document.audit.length;
      assert.equal(repairHostDeregistrationCertificateInventory(document, {
        hostname: operation.hostname, externalOperationId: operation.externalOperationId,
        hostLifecycleId: operation.hostLifecycleId, certificates: [{ requestId: request.id, certificatePem: missingPem }],
        trustedCaPems: [readFileSync(join(ca, "ca.pem"), "utf8")], actor: "ops",
      }).id, operation.id, "response-loss retry did not return the same operation");
      assert.equal(document.audit.length, auditRows, "response-loss retry appended duplicate audit evidence");
      assert.throws(() => repairHostDeregistrationCertificateInventory(document, {
        hostname: operation.hostname, externalOperationId: operation.externalOperationId,
        hostLifecycleId: operation.hostLifecycleId,
        certificates: [{ requestId: request.id, certificatePem: selfSignedPem }],
        trustedCaPems: [readFileSync(join(ca, "ca.pem"), "utf8")], actor: "ops",
      }), /replay conflicts/);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("compacts only proven-expired revocations and resumes the capacity-blocked operation", { timeout: 15_000 }, () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-dereg-capacity-repair-")); const ca = join(root, "pki");
    try {
      execFileSync("node", ["bin/heliopause-pki.ts", "init", ca], { cwd: process.cwd() });
      const document = emptyEnrollmentDocument();
      const issued = createNodeToken(document, { hostname: "repair-capacity.dev", hostLifecycleId: "create-cap-1" });
      const material = csr(root, "repair-capacity.dev", "host");
      const request = submitNodeCsr(document, { token: issued.token, csrPem: material.pem }).row;
      const certPath = join(root, "agent.pem");
      execFileSync("node", ["bin/heliopause-pki.ts", "sign-csr", ca, material.path, certPath,
        "--name=repair-capacity.dev", `--expect-sha256=${request.csrSha256}`], { cwd: process.cwd() });
      storeNodeCertificate(document, { requestId: request.id, certificatePem: readFileSync(certPath, "utf8"),
        caPem: readFileSync(join(ca, "ca.pem"), "utf8"), caName: "dev", actor: "ops" });
      const oldIssued = createNodeToken(document, { hostname: "old.dev", hostLifecycleId: "create-old-1" });
      const oldMaterial = csr(root, "old.dev", "old");
      const oldRequest = submitNodeCsr(document, { token: oldIssued.token, csrPem: oldMaterial.pem }).row;
      const oldCertPath = join(root, "old.pem");
      signClientCertificate(oldMaterial.path, oldCertPath, join(ca, "ca.pem"), join(ca, "ca.key"), join(root, "old.ext"));
      storeNodeCertificate(document, { requestId: oldRequest.id, certificatePem: readFileSync(oldCertPath, "utf8"),
        caPem: readFileSync(join(ca, "ca.pem"), "utf8"), caName: "dev", actor: "ops" });
      const oldFingerprint = oldRequest.certificateSha256!;
      const repairNow = new Date(Date.parse(oldRequest.certificateNotAfter!) + 60_000);
      const capacityFixtureRows = 1_588;
      document.revocations = Array.from({ length: capacityFixtureRows }, (_, index) => ({
        fingerprint256: index === 0 ? oldFingerprint : index.toString(16).padStart(64, "0"),
        subject: null, reason: "x", actor: "x",
        revokedAt: "2026-08-01T00:00:00.000Z",
      }));
      const operation = beginHostDeregistration(document, {
        hostname: "repair-capacity.dev", externalOperationId: "destroy-cap-1", hostLifecycleId: "create-cap-1",
        reason: "instance-destroy", requestedBy: "stardust:ops", actor: "app:destroyer", relayNames: ["dev"],
        scope: { appTokenId: "app-1", label: "destroyer", hostnamePattern: "*.dev" },
        trustedCaPems: [readFileSync(join(ca, "ca.pem"), "utf8")],
        now: repairNow,
      }).row;
      assert.equal(operation.blocked?.code, "revocation_capacity_exhausted");
      const retained = document.revocations.filter((entry) => entry.fingerprint256 !== oldFingerprint)
        .map((entry) => entry.fingerprint256).sort();
      const digest = createHash("sha256").update(JSON.stringify(retained)).digest("hex");
      const oldPem = oldRequest.certificatePem; oldRequest.certificatePem = null;
      assert.throws(() => repairHostDeregistrationRevocationCapacity(document, {
        hostname: operation.hostname, externalOperationId: operation.externalOperationId,
        hostLifecycleId: operation.hostLifecycleId, relayNames: ["dev"], trustedCaPems: [readFileSync(join(ca, "ca.pem"), "utf8")], actor: "ops",
        relayConfirmations: [{ name: "dev", compactedAt: new Date(repairNow.getTime() - 1_000).toISOString(), retainedFingerprintSha256: digest }],
        now: repairNow,
      }), /no expired revocations are safely compactable/);
      oldRequest.certificatePem = oldPem;
      const actualNotAfter = oldRequest.certificateNotAfter; oldRequest.certificateNotAfter = "2020-01-01T00:00:00.000Z";
      assert.throws(() => repairHostDeregistrationRevocationCapacity(document, {
        hostname: operation.hostname, externalOperationId: operation.externalOperationId,
        hostLifecycleId: operation.hostLifecycleId, relayNames: ["dev"], trustedCaPems: [readFileSync(join(ca, "ca.pem"), "utf8")], actor: "ops",
        relayConfirmations: [{ name: "dev", compactedAt: new Date(repairNow.getTime() - 1_000).toISOString(), retainedFingerprintSha256: digest }],
        now: repairNow,
      }), /no expired revocations are safely compactable/);
      oldRequest.certificateNotAfter = actualNotAfter;
      assert.throws(() => repairHostDeregistrationRevocationCapacity(document, {
        hostname: operation.hostname, externalOperationId: operation.externalOperationId,
        hostLifecycleId: operation.hostLifecycleId, relayNames: ["dev"], trustedCaPems: [readFileSync(join(ca, "ca.pem"), "utf8")], actor: "ops",
        relayConfirmations: [{ name: "dev", compactedAt: new Date(repairNow.getTime() - 1_000).toISOString(), retainedFingerprintSha256: "0".repeat(64) }],
        now: repairNow,
      }), /exact compacted snapshot/);
      const compactedAt = new Date(repairNow.getTime() - 1_000).toISOString();
      const repaired = repairHostDeregistrationRevocationCapacity(document, {
        hostname: operation.hostname, externalOperationId: operation.externalOperationId,
        hostLifecycleId: operation.hostLifecycleId, relayNames: ["dev"], trustedCaPems: [readFileSync(join(ca, "ca.pem"), "utf8")], actor: "ops",
        relayConfirmations: [{ name: "dev", compactedAt, retainedFingerprintSha256: digest }],
        now: repairNow,
      });
      assert.equal(repaired.id, operation.id); assert.equal(repaired.credentials.state, "replicating");
      assert.equal(document.revocations.length, capacityFixtureRows);
      assert.equal(document.revocations.some((entry) => entry.fingerprint256 === oldFingerprint), false);
      assert.ok(document.audit.some((event) => event.action === "host-deregistration.capacity-repair-before"));
      assert.ok(document.audit.some((event) => event.action === "host-deregistration.capacity-repair-after"));
      const auditRows = document.audit.length;
      assert.equal(repairHostDeregistrationRevocationCapacity(document, {
        hostname: operation.hostname, externalOperationId: operation.externalOperationId,
        hostLifecycleId: operation.hostLifecycleId, relayNames: ["dev"], trustedCaPems: [readFileSync(join(ca, "ca.pem"), "utf8")], actor: "ops",
        relayConfirmations: [{ name: "dev", compactedAt, retainedFingerprintSha256: digest }], now: repairNow,
      }).id, operation.id);
      assert.equal(document.audit.length, auditRows);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("fails closed when persisted policy evidence skips credential and infrastructure ordering", () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-enroll-order-"));
    const path = join(root, "store.json");
    try {
      const document = emptyEnrollmentDocument();
      createNodeToken(document, { hostname: "ordered.dev", hostLifecycleId: "life-1" });
      const row = beginHostDeregistration(document, {
        hostname: "ordered.dev", externalOperationId: "destroy-1", hostLifecycleId: "life-1",
        reason: "instance-destroy", requestedBy: "stardust:ops", actor: "app:destroyer",
        scope: { appTokenId: "app-1", label: "destroyer", hostnamePattern: "*.dev" }, relayNames: ["dev"],
        trustedCaPems: [],
      }).row;
      const ordered = structuredClone(document);
      row.policy = {
        state: "completed", queuedAt: row.createdAt, completedAt: row.createdAt, completedBy: "ops",
        pullRequestUrl: "https://example.invalid/pull/1", commitSha: "a".repeat(40),
        publishedGeneration: "generation-1", relays: [{ name: "dev", absentAt: row.createdAt }],
      };
      row.status = "completed";
      writeFileSync(path, JSON.stringify(document));
      assert.throws(() => loadEnrollmentDocument(path), /advanced policy before infrastructure destruction/);

      const waitingWithEvidence = structuredClone(ordered);
      waitingWithEvidence.hostDeregistrations[0]!.infrastructure = {
        state: "waiting", provider: "vultr", providerInstanceId: "vm-1", expectedProviderInstanceId: null,
        destroyedAt: ordered.hostDeregistrations[0]!.createdAt,
      };
      writeFileSync(path, JSON.stringify(waitingWithEvidence));
      assert.throws(() => loadEnrollmentDocument(path), /waiting infrastructure carries destruction evidence/);

      const destroyedWithoutEvidence = structuredClone(ordered);
      const malformed = destroyedWithoutEvidence.hostDeregistrations[0]!;
      malformed.credentials.state = "ready_for_infrastructure_destroy";
      malformed.credentials.relays[0]!.state = "installed";
      malformed.infrastructure.state = "destroyed";
      malformed.policy.state = "queued";
      malformed.policy.queuedAt = malformed.createdAt;
      malformed.status = "policy_pending";
      writeFileSync(path, JSON.stringify(destroyedWithoutEvidence));
      assert.throws(() => loadEnrollmentDocument(path), /destroyed infrastructure lacks confirmation evidence/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("runs attacker-controlled OpenSSL parsing off the event-loop thread", async () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-enroll-worker-"));
    const fakeOpenSsl = join(root, "openssl");
    writeFileSync(fakeOpenSsl, "#!/bin/sh\nsleep 0.5\nexit 1\n");
    chmodSync(fakeOpenSsl, 0o700);
    const originalPath = process.env.PATH;
    process.env.PATH = `${root}:${originalPath ?? ""}`;
    try {
      const shaped = "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n";
      let timerFired = false;
      const timer = setTimeout(() => { timerFired = true; }, 25);
      const validation = validateNodeCsrAsync(shaped, "responsive.dev");
      await new Promise((resolve) => setTimeout(resolve, 75));
      assert.equal(timerFired, true, "CSR parsing blocked the manager event loop");
      await assert.rejects(validation, /OpenSSL rejected/);
      clearTimeout(timer);
    } finally {
      if (originalPath === undefined) delete process.env.PATH;
      else process.env.PATH = originalPath;
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("bounds CSR validation from enqueue and removes timed-out waiters", async () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-enroll-queue-"));
    const fakeOpenSsl = join(root, "openssl");
    writeFileSync(join(root, "current"), "0\n");
    writeFileSync(join(root, "max"), "0\n");
    writeFileSync(fakeOpenSsl, `#!/bin/sh
while ! mkdir "$HELIOPAUSE_TEST_COUNTER_DIR/lock" 2>/dev/null; do sleep 0.005; done
current=$(cat "$HELIOPAUSE_TEST_COUNTER_DIR/current")
next=$((current + 1))
maximum=$(cat "$HELIOPAUSE_TEST_COUNTER_DIR/max")
echo "$next" > "$HELIOPAUSE_TEST_COUNTER_DIR/current"
if [ "$next" -gt "$maximum" ]; then echo "$next" > "$HELIOPAUSE_TEST_COUNTER_DIR/max"; fi
rmdir "$HELIOPAUSE_TEST_COUNTER_DIR/lock"
sleep 0.3
while ! mkdir "$HELIOPAUSE_TEST_COUNTER_DIR/lock" 2>/dev/null; do sleep 0.005; done
current=$(cat "$HELIOPAUSE_TEST_COUNTER_DIR/current")
echo $((current - 1)) > "$HELIOPAUSE_TEST_COUNTER_DIR/current"
rmdir "$HELIOPAUSE_TEST_COUNTER_DIR/lock"
exit 1
`);
    chmodSync(fakeOpenSsl, 0o700);
    const originalPath = process.env.PATH;
    const originalCounter = process.env.HELIOPAUSE_TEST_COUNTER_DIR;
    process.env.PATH = `${root}:${originalPath ?? ""}`;
    process.env.HELIOPAUSE_TEST_COUNTER_DIR = root;
    const shaped = "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n";
    try {
      const occupied = Promise.allSettled([
        validateNodeCsrAsync(shaped, "queue-a.dev", { timeoutMs: 8_000 }),
        validateNodeCsrAsync(shaped, "queue-b.dev", { timeoutMs: 8_000 }),
      ]);
      const started = Date.now();
      await assert.rejects(
        validateNodeCsrAsync(shaped, "queue-timeout.dev", { timeoutMs: 50 }),
        /timed out/,
      );
      assert.ok(Date.now() - started < 250, "queue time was not included in the overall deadline");

      // If the expired waiter remains in the queue it consumes the next handoff. This request must
      // receive that slot, execute OpenSSL, and fail for certificate material rather than timeout.
      await assert.rejects(
        validateNodeCsrAsync(shaped, "queue-after-timeout.dev", { timeoutMs: 8_000 }),
        /OpenSSL rejected/,
      );
      await occupied;
      assert.equal(Number(readFileSync(join(root, "max"), "utf8")), 2, "worker cap was exceeded or never exercised");
    } finally {
      if (originalPath === undefined) delete process.env.PATH;
      else process.env.PATH = originalPath;
      if (originalCounter === undefined) delete process.env.HELIOPAUSE_TEST_COUNTER_DIR;
      else process.env.HELIOPAUSE_TEST_COUNTER_DIR = originalCounter;
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("serializes load-mutate-save across processes", async () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-enroll-lock-"));
    const path = join(root, "store.json");
    saveEnrollmentDocument(path, emptyEnrollmentDocument());
    const moduleUrl = new URL("./enrollment-store.ts", import.meta.url).href;

    const run = (hostname: string) => new Promise<void>((resolve, reject) => {
      const script = `
        import { createNodeToken, withEnrollmentTransaction } from ${JSON.stringify(moduleUrl)};
        const pause = new Int32Array(new SharedArrayBuffer(4));
        withEnrollmentTransaction(${JSON.stringify(path)}, (document) => {
          Atomics.wait(pause, 0, 0, 150);
          createNodeToken(document, { hostname: ${JSON.stringify(hostname)} });
        });
      `;
      const child = spawn(process.execPath, ["--input-type=module", "--eval", script], { stdio: ["ignore", "ignore", "pipe"] });
      let stderr = "";
      child.stderr.setEncoding("utf8");
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.on("error", reject);
      child.on("exit", (code) => code === 0 ? resolve() : reject(new Error(`transaction child exited ${code}: ${stderr}`)));
    });

    await Promise.all([run("lock-a.dev"), run("lock-b.dev")]);
    assert.deepEqual(loadEnrollmentDocument(path).tokens.map((token) => token.hostname).sort(), ["lock-a.dev", "lock-b.dev"]);
    // Also prove the public transaction helper leaves no stale lock on a normal return.
    withEnrollmentTransaction(path, () => undefined);
  });

  it("never reclaims stale dead or malformed transaction locks automatically", () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-enroll-stale-lock-"));
    const path = join(root, "store.json");
    const lock = `${path}.lock`;
    const stale = new Date(Date.now() - 3 * 60_000);
    try {
      saveEnrollmentDocument(path, emptyEnrollmentDocument());
      for (const content of ["", "not-json", JSON.stringify({ pid: 2_147_483_647, createdAt: 0 })]) {
        writeFileSync(lock, content, { mode: 0o600, flag: "wx" });
        utimesSync(lock, stale, stale);
        assert.throws(
          () => withEnrollmentTransaction(path, () => undefined, { waitMs: 0 }),
          (error: unknown) => (error as { statusCode?: number }).statusCode === 503,
        );
        assert.equal(readFileSync(lock, "utf8"), content, "transaction code must not unlink a stale pathname");
        rmSync(lock);
      }
      withEnrollmentTransaction(path, (document) => createNodeToken(document, { hostname: "operator-cleared.dev" }));
      assert.equal(loadEnrollmentDocument(path).tokens.length, 1);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

// ── The shape gate in front of the certificate-less routes ────────────────────
//
// `POST /infra/node-csrs` and `GET /infra/node-csrs/<id>/certificate` run before operator
// authentication, and the manager listens with `rejectUnauthorized: false` — anyone who completes a
// handshake reaches them, and each admitted request costs a synchronous read and parse of the whole
// enrollment store on the event loop. One of them additionally takes the `O_EXCL` lock, which is
// waited on with `Atomics.wait`, also synchronously.
//
// The gate was `token.startsWith(NODE_TOKEN_PREFIX)`, with a comment claiming it left only "a caller
// holding a well-formed but wrong token, and that one is worth a read". `NODE_TOKEN_PREFIX` is seven
// characters of public source, so the remaining set was *everyone* and the mitigation was worth
// nothing. These pin the difference.
describe("looksLikeNodeToken", () => {
  it("accepts exactly what createNodeToken emits", () => {
    const { token } = createNodeToken(emptyEnrollmentDocument(), { hostname: "gw-01.dev" });
    assert.equal(looksLikeNodeToken(token), true);
  });

  it("refuses the bare prefix, which is what the old gate accepted", () => {
    // The whole point: anyone can type this, and nobody should get a file read for it.
    assert.equal(looksLikeNodeToken(NODE_TOKEN_PREFIX), false);
    assert.equal(looksLikeNodeToken(`${NODE_TOKEN_PREFIX}x`), false);
    assert.equal(looksLikeNodeToken(`${NODE_TOKEN_PREFIX}${"a".repeat(63)}`), false);
    assert.equal(looksLikeNodeToken(`${NODE_TOKEN_PREFIX}${"a".repeat(65)}`), false);
  });

  it("refuses the right length in the wrong alphabet, and a missing prefix", () => {
    // `randomHex` emits lowercase hex; anything else did not come from this store.
    assert.equal(looksLikeNodeToken(`${NODE_TOKEN_PREFIX}${"A".repeat(64)}`), false);
    assert.equal(looksLikeNodeToken(`${NODE_TOKEN_PREFIX}${"z".repeat(64)}`), false);
    assert.equal(looksLikeNodeToken("a".repeat(64)), false);
    assert.equal(looksLikeNodeToken(""), false);
  });

  it("is what lookupNodeToken screens on, so the two cannot disagree", () => {
    // If the route's gate and the lookup's gate diverged, the route would admit shapes the lookup
    // rejects — which is the file read this is here to prevent.
    const document = emptyEnrollmentDocument();
    createNodeToken(document, { hostname: "gw-01.dev" });
    assert.equal(lookupNodeToken(document, NODE_TOKEN_PREFIX), null);
  });
});

// ── App tokens: the credential a program holds ────────────────────────────────
//
// The whole grant is "mint node tokens inside one hostname pattern, and read the CSR queue". Every
// check below exists because the value of that narrowness is entirely in the checks: a scope list
// that accepts an unknown string, or a pattern that matches one label too many, gives away exactly
// the thing this credential was designed not to give away.
describe("app tokens", () => {
  it("stores only a hash, hands the plaintext back once, and records use", () => {
    const now = new Date("2026-08-26T00:00:00.000Z");
    const document = emptyEnrollmentDocument();
    const issued = createAppToken(document, {
      label: "stardust dispatcher", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev",
      createdBy: "ops-alice", ttlSec: 3_600, now,
    });
    assert.equal(looksLikeAppToken(issued.token), true);
    assert.equal(issued.token.startsWith(APP_TOKEN_PREFIX), true);
    assert.equal(JSON.stringify(document).includes(issued.token), false, "the plaintext reached the store");
    assert.equal(issued.row.expiresAt, "2026-08-26T01:00:00.000Z");
    assert.equal(issued.row.lastUsedAt, null);

    const used = new Date("2026-08-26T00:30:00.000Z");
    assert.equal(lookupAppToken(document, issued.token, used)?.id, issued.row.id);
    assert.equal(issued.row.lastUsedAt, used.toISOString());
    assert.equal(lookupAppToken(document, issued.token, new Date("2026-08-26T01:00:00.000Z")), null, "an expired token was honoured");

    revokeAppToken(document, issued.row.id, "ops-alice", used);
    assert.equal(lookupAppToken(document, issued.token, used), null, "a revoked token was honoured");
    assert.throws(() => revokeAppToken(document, "no-such-id"), (e: unknown) => (e as { statusCode?: number }).statusCode === 404);
  });

  it("writes an audit trail that names the token and never its secret", () => {
    const document = emptyEnrollmentDocument();
    const issued = createAppToken(document, {
      label: "dispatcher", scopes: ["enrollment:requests-read", "enrollment:token-create"],
      hostnamePattern: "*.dev", createdBy: "ops-alice",
    });
    const created = document.audit.at(-1)!;
    assert.equal(created.action, "app-token.create");
    assert.equal(created.target, issued.row.id);
    assert.deepEqual(created.detail, {
      label: "dispatcher", scopes: "enrollment:requests-read,enrollment:token-create", hostnamePattern: "*.dev",
    });
    revokeAppToken(document, issued.row.id, "ops-bob");
    assert.equal(document.audit.at(-1)!.action, "app-token.revoke");
    const trail = JSON.stringify(document.audit);
    assert.equal(trail.includes(issued.token), false, "the audit trail carries the plaintext");
    assert.equal(trail.includes(issued.row.tokenHash), false, "the audit trail carries the hash");
  });

  it("refuses an empty, unknown or non-string scope, and keeps one copy of a repeated one", () => {
    const document = emptyEnrollmentDocument();
    const attempt = (scopes: readonly unknown[]) =>
      createAppToken(document, { label: "x", scopes: scopes as readonly string[], hostnamePattern: "*.dev" });
    assert.throws(() => attempt([]), /at least one/);
    assert.throws(() => attempt(["enrollment:sign"]), /unknown app token scope/);
    assert.throws(() => attempt(["enrollment:token-create", "enrollment:everything"]), /unknown app token scope/);
    assert.throws(() => attempt([1]), /unknown app token scope/);
    assert.throws(
      () => createAppToken(document, { label: "x", scopes: "enrollment:token-create" as unknown as string[], hostnamePattern: "*.dev" }),
      /at least one/,
      "a bare string must not be read as a list of scopes",
    );
    assert.equal(document.appTokens.length, 0, "a refused creation left a row behind");
    const issued = attempt(["enrollment:token-create", "enrollment:token-create"]);
    assert.deepEqual(issued.row.scopes, ["enrollment:token-create"]);
  });

  it("refuses a label that is empty after trimming or longer than 120", () => {
    const document = emptyEnrollmentDocument();
    const attempt = (label: string) =>
      createAppToken(document, { label, scopes: ["enrollment:token-create"], hostnamePattern: "*.dev" });
    assert.throws(() => attempt("   "), /label must be 1-120/);
    assert.throws(() => attempt("x".repeat(121)), /label must be 1-120/);
    assert.equal(attempt("  dispatcher  ").row.label, "dispatcher");
    // A label is not an identifier: rotation needs the replacement to exist before the old one dies.
    assert.equal(attempt("dispatcher").row.label, "dispatcher");
    assert.equal(document.appTokens.filter((row) => row.label === "dispatcher" && !row.revokedAt).length, 2);
  });

  it("bounds the TTL at both ends", () => {
    const document = emptyEnrollmentDocument();
    const attempt = (ttlSec: number) =>
      createAppToken(document, { label: "x", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev", ttlSec });
    assert.throws(() => attempt(60 * 60 - 1), /ttlSec must be/);
    assert.throws(() => attempt(366 * 24 * 60 * 60), /ttlSec must be/);
    assert.throws(() => attempt(Number.NaN), /ttlSec must be/);
    assert.ok(attempt(60 * 60).row.expiresAt);
  });

  it("refuses a wildcard anywhere but the whole first label", () => {
    const document = emptyEnrollmentDocument();
    const attempt = (hostnamePattern: string) =>
      createAppToken(document, { label: "x", scopes: ["enrollment:token-create"], hostnamePattern });
    for (const bad of ["", "   ", "*", "**.dev", "*dev", "a.*.dev", "*.dev.*", "*.*", "dev.*", "k3s-*.dev"]) {
      assert.throws(() => attempt(bad), /hostnamePattern/, `${JSON.stringify(bad)} was accepted as a pattern`);
    }
    assert.equal(attempt("  *.DEV  ").row.hostnamePattern, "*.dev", "a pattern was not normalised");
    assert.equal(attempt("K3S-01.dev").row.hostnamePattern, "k3s-01.dev");
  });

  it("matches exactly one wildcard label, and never a suffix", () => {
    // The `a.b.dev` row is the one that matters: a suffix match would make `*.dev` cover
    // `k3s-01.attacker.dev`, and the token holder chooses the hostname it asks for.
    const table: Array<[string, string, boolean]> = [
      ["*.dev", "k3s-01.dev", true],
      ["*.dev", "gw-01.dev", true],
      ["*.dev", "MAILER-01.DEV", true],
      ["*.a.b.dev", "host.a.b.dev", true],
      ["k3s-01.dev", "k3s-01.dev", true],
      ["k3s-01.dev", "K3S-01.DEV", true],
      ["*.dev", "dev", false],
      ["*.dev", "a.b.dev", false],
      ["*.dev", ".dev", false],
      ["*.dev", "k3s-01.prod", false],
      ["*.dev", "k3s-01.dev.attacker.example", false],
      ["k3s-01.dev", "k3s-02.dev", false],
      ["k3s-01.dev", "k3s-01.dev.evil", false],
      ["*.dev", "", false],
      ["", "k3s-01.dev", false],
    ];
    for (const [pattern, candidate, expected] of table) {
      assert.equal(
        appTokenAllowsHostname(pattern, candidate), expected,
        `${JSON.stringify(pattern)} vs ${JSON.stringify(candidate)}`,
      );
    }
  });

  it("refuses the bare prefix and the wrong alphabet, like the node token gate", () => {
    assert.equal(looksLikeAppToken(APP_TOKEN_PREFIX), false);
    assert.equal(looksLikeAppToken(`${APP_TOKEN_PREFIX}${"a".repeat(63)}`), false);
    assert.equal(looksLikeAppToken(`${APP_TOKEN_PREFIX}${"a".repeat(65)}`), false);
    assert.equal(looksLikeAppToken(`${APP_TOKEN_PREFIX}${"A".repeat(64)}`), false);
    assert.equal(looksLikeAppToken(`${APP_TOKEN_PREFIX}${"z".repeat(64)}`), false);
    assert.equal(looksLikeAppToken(""), false);
    // A node token is not an app token and must not be admitted by the app-token gate, or the two
    // credentials would be interchangeable at the routes that screen on shape.
    const node = createNodeToken(emptyEnrollmentDocument(), { hostname: "gw-01.dev" }).token;
    assert.equal(looksLikeAppToken(node), false);
    assert.equal(lookupAppToken(emptyEnrollmentDocument(), APP_TOKEN_PREFIX), null);
  });

  it("refuses a row whose scopes are a string, because `includes` would authorise substrings", () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-enroll-apptoken-rows-"));
    const path = join(root, "store.json");
    try {
      const document = emptyEnrollmentDocument();
      const row = createAppToken(document, {
        label: "dispatcher", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev",
      }).row;
      const write = (patch: Record<string, unknown>) =>
        writeFileSync(path, JSON.stringify({ ...document, appTokens: [{ ...row, ...patch }] }));

      // 🔑 The one that matters. Authority is decided by `row.scopes.includes(scope)`, and a string
      // answers that call: "enrollment:token-create,enrollment:requests-read".includes(…) is true,
      // and so is .includes("token-cre"). A flattened row must never load.
      write({ scopes: "enrollment:token-create,enrollment:requests-read" });
      assert.throws(() => loadEnrollmentDocument(path), /scopes must be an array of strings/);
      assert.equal(
        "enrollment:token-create,enrollment:requests-read".includes("token-cre"), true,
        "the check this test defends against changed shape",
      );
      write({ scopes: ["enrollment:token-create", 7] });
      assert.throws(() => loadEnrollmentDocument(path), /scopes must be an array of strings/);

      for (const field of ["id", "label", "tokenHash", "hostnamePattern"]) {
        write({ [field]: 7 });
        assert.throws(() => loadEnrollmentDocument(path), new RegExp(`app token ${field} must be a string`));
      }
      writeFileSync(path, JSON.stringify({ ...document, appTokens: ["not-a-row"] }));
      assert.throws(() => loadEnrollmentDocument(path), /app token rows must be objects/);

      write({});
      assert.equal(loadEnrollmentDocument(path).appTokens.length, 1, "a well-formed row stopped loading");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("records which app token minted a node token, since two may share a label", () => {
    const document = emptyEnrollmentDocument();
    const one = createAppToken(document, { label: "dispatcher", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev" }).row;
    const two = createAppToken(document, { label: "dispatcher", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev" }).row;
    assert.notEqual(one.id, two.id);

    createNodeToken(document, { hostname: "k3s-01.dev", createdBy: `app:${two.label}#${two.id}`, appTokenId: two.id });
    const event = document.audit.at(-1)!;
    assert.equal(event.action, "node-token.create");
    assert.equal(event.actor, `app:dispatcher#${two.id}`);
    assert.equal(event.detail.appTokenId, two.id, "the trail cannot say which of two same-label tokens minted this");
    assert.equal(event.detail.hostname, "k3s-01.dev");

    // An operator issuing by hand has no app token, and the field must not appear for them.
    createNodeToken(document, { hostname: "k3s-02.dev", createdBy: "ops-alice" });
    assert.equal("appTokenId" in document.audit.at(-1)!.detail, false);
  });

  it("keeps the id whole in createdBy when the label is long enough to have eaten it", () => {
    // 🔴 `createNodeToken` slices `createdBy` to 120 characters. A 120-character label made
    // `app:<label>#<id>` 141 long, and the slice took the tail — the id, which is the only half that
    // says *which* credential minted the token. The bug was invisible for short labels.
    const document = emptyEnrollmentDocument();
    const label = "x".repeat(120);
    const issued = createAppToken(document, {
      label, scopes: ["enrollment:token-create"], hostnamePattern: "*.dev",
    });
    const createdBy = appTokenCreatedBy(issued.row.label, issued.row.id);
    assert.equal(createdBy.length <= MAX_CREATED_BY_CHARS, true, "the composed value does not fit the field");
    assert.equal(createdBy.endsWith(`#${issued.row.id}`), true, "the id was truncated away");

    // Through the store, which is where the slice lives.
    const minted = createNodeToken(document, { hostname: "long.dev", createdBy, appTokenId: issued.row.id });
    assert.equal(minted.row.createdBy, createdBy, "the store truncated a value built to fit it");
    assert.equal(minted.row.createdBy!.endsWith(`#${issued.row.id}`), true);
    assert.equal(document.audit.at(-1)!.detail.appTokenId, issued.row.id);

    // A short label loses nothing at all.
    assert.equal(appTokenCreatedBy("dispatcher", "abc123"), "app:dispatcher#abc123");
  });

  it("refuses a row whose timestamps are the wrong type, since expiresAt decides liveness", () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-enroll-apptoken-times-"));
    const path = join(root, "store.json");
    try {
      const document = emptyEnrollmentDocument();
      const row = createAppToken(document, {
        label: "dispatcher", scopes: ["enrollment:token-create"], hostnamePattern: "*.dev",
      }).row;
      const write = (patch: Record<string, unknown>) =>
        writeFileSync(path, JSON.stringify({ ...document, appTokens: [{ ...row, ...patch }] }));

      for (const bad of [7, null, "not-a-date", undefined]) {
        write({ expiresAt: bad });
        assert.throws(() => loadEnrollmentDocument(path), /expiresAt must be an ISO timestamp/, `expiresAt: ${bad}`);
      }
      write({ createdAt: 7 });
      assert.throws(() => loadEnrollmentDocument(path), /createdAt must be a string/);
      // Nullable, but not anything. `revokedAt` is read for truthiness, so `0` or `false` would read
      // as "not revoked" — the one direction this must never be wrong in.
      for (const field of ["revokedAt", "lastUsedAt", "createdBy"]) {
        write({ [field]: 0 });
        assert.throws(() => loadEnrollmentDocument(path), new RegExp(`${field} must be a string or null`));
        write({ [field]: null });
        assert.equal(loadEnrollmentDocument(path).appTokens.length, 1, `${field}: null must be accepted`);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("opens a store written before app tokens existed, and still refuses an unknown field", () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-enroll-apptoken-"));
    const path = join(root, "store.json");
    try {
      // Schema 1 was deliberately not raised. A store from before this field is a correct store.
      writeFileSync(path, JSON.stringify({ schemaVersion: 1, tokens: [], requests: [], audit: [] }));
      assert.deepEqual(loadEnrollmentDocument(path).appTokens, []);

      writeFileSync(path, JSON.stringify({ schemaVersion: 1, tokens: [], requests: [], audit: [], appTokens: {} }));
      assert.throws(() => loadEnrollmentDocument(path), /appTokens must be an array/);

      writeFileSync(path, JSON.stringify({ schemaVersion: 1, tokens: [], requests: [], audit: [], surprise: [] }));
      assert.throws(() => loadEnrollmentDocument(path), /unsupported fields/);

      const document = emptyEnrollmentDocument();
      const issued = createAppToken(document, { label: "dispatcher", scopes: ["enrollment:requests-read"], hostnamePattern: "*.dev" });
      rmSync(path);
      saveEnrollmentDocument(path, document);
      const reloaded = loadEnrollmentDocument(path);
      assert.equal(reloaded.appTokens.length, 1);
      assert.equal(reloaded.appTokens[0]!.id, issued.row.id);
      assert.deepEqual(reloaded.appTokens[0]!.scopes, ["enrollment:requests-read"]);
      assert.ok(lookupAppToken(reloaded, issued.token), "a round-tripped token stopped authenticating");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
