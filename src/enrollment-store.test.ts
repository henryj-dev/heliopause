import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  createNodeToken, emptyEnrollmentDocument, fetchNodeCertificate, initializeEnrollmentDocument,
  loadEnrollmentDocument, lookupNodeToken,
  rejectNodeCsr, saveEnrollmentDocument, storeNodeCertificate, submitNodeCsr, validateNodeCsrAsync,
  withEnrollmentTransaction,
} from "./enrollment-store.ts";

function csr(root: string, name: string, suffix: string) {
  const key = join(root, `${suffix}.key`); const path = join(root, `${suffix}.csr`);
  execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", key]);
  execFileSync("openssl", ["req", "-new", "-key", key, "-subj", `/CN=${name}`, "-out", path]);
  return { path, pem: readFileSync(path, "utf8") };
}

describe("standalone enrollment store", () => {
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
