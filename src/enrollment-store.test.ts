import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  APP_TOKEN_PREFIX, appTokenAllowsHostname, createAppToken, createNodeToken, emptyEnrollmentDocument,
  fetchNodeCertificate, initializeEnrollmentDocument,
  loadEnrollmentDocument, looksLikeAppToken, looksLikeNodeToken, lookupAppToken, lookupNodeToken, NODE_TOKEN_PREFIX,
  rejectNodeCsr, revokeAppToken, saveEnrollmentDocument, storeNodeCertificate, submitNodeCsr, validateNodeCsrAsync,
  withEnrollmentTransaction,
} from "./enrollment-store.ts";

function csr(root: string, name: string, suffix: string) {
  const key = join(root, `${suffix}.key`); const path = join(root, `${suffix}.csr`);
  execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", key]);
  execFileSync("openssl", ["req", "-new", "-key", key, "-subj", `/CN=${name}`, "-out", path]);
  return { path, pem: readFileSync(path, "utf8") };
}

describe("standalone enrollment store", () => {
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
