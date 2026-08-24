// The write path, end to end: a real manager, a real relay, real client certificates.
//
// ## Why this is an integration test and not a unit test
//
// `approval.test.ts` already pins the state machine as data, and it would pass with the endpoints
// wired to the wrong list, checking the wrong CN, or pushing to the wrong VPC. The property that
// matters here lives in the seams:
//
//   · the identity used for the check is the one from the certificate, not from the body
//   · a reader cannot write
//   · the plan actually reaches the relay's artifact directory and the relay serves it
//
// That last one is V46's lesson applied to the write path: the failing direction has to be called by
// something, or a manager can be perfectly `Ready` and unable to publish. Here the test is what calls
// it — and `heliopause-approve` is what calls it in production.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, unlinkSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:https";
import { execFileSync, spawn } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { startManager } from "./manager-server.ts";
import { startRelay } from "./relay.ts";
import { initializeEnrollmentDocument } from "./enrollment-store.ts";
import { initializeRevocationSnapshot } from "./revocation-snapshot.ts";
import { startRevocationWriter } from "./revocation-writer.ts";
import { bundleHash, planHash, type PlanBundle } from "./bundle.ts";
import { AUTHORIZED_ARTIFACT_BUNDLE_FILE } from "./artifact-signature.ts";
import { SCHEMA_VERSION, type Manifest } from "./protocol.ts";
import { contains } from "./test-util.ts";

const dir = mkdtempSync(join(tmpdir(), "hp-write-"));
const artifactDir = join(dir, "artifacts");
const revocationFile = join(dir, "relay-revocations.json");
const revocationWriterSocket = join(dir, "revocation-writer.sock");
const enrollmentFile = join(dir, "enrollment.json");
let managerPort = 0;
let relayPort = 0;
const closers: Array<() => void> = [];

const sha = (s: string) => "sha256:" + createHash("sha256").update(s).digest("hex");
const read = (f: string) => readFileSync(join(dir, f));

/**
 * A CA, a server certificate for each of the two servers, and four client identities.
 *
 * Four, because the interesting refusals need distinct callers: a proposer, an approver, a reader who
 * may not write, and an outsider whose certificate does not chain to this CA at all.
 */
function pki() {
  const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
      "-days", "1", "-subj", "/CN=test-ca");

  const leaf = (name: string, cn: string, eku: string, san?: string) => {
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", `/CN=${cn}`);
    writeFileSync(join(dir, `${name}.ext`), `extendedKeyUsage=critical,${eku}\n` + (san ? `subjectAltName=${san}\n` : ""));
    run("x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", `${name}.pem`, "-days", "1", "-extfile", `${name}.ext`);
  };

  leaf("mgr-server", "manager", "serverAuth", "IP:127.0.0.1");
  leaf("relay-server", "relay", "serverAuth", "IP:127.0.0.1");
  leaf("operator-henry", "ops-alice", "clientAuth");
  leaf("operator-jae", "ops-jae", "clientAuth");
  leaf("operator-watcher", "ops-watcher", "clientAuth");

  // The manager pushes to the relay with an operator certificate out of `pkiDir`. Only one
  // `operator-*.pem` may be present or `loadRelayCreds` refuses to guess, so the manager's credential
  // lives in its own directory.
  mkdirSync(join(dir, "relay-pki"), { recursive: true });
  for (const f of ["ca.pem"]) writeFileSync(join(dir, "relay-pki", f), read(f));
  leaf("operator-hp-manager", "hp-manager", "clientAuth");
  for (const ext of ["pem", "key"]) {
    writeFileSync(join(dir, "relay-pki", `operator-hp-manager.${ext}`), read(`operator-hp-manager.${ext}`));
  }

  // The outsider: a different CA entirely, whose leaf claims a name the manager trusts.
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "rogue-ca.key", "-out", "rogue-ca.pem",
      "-days", "1", "-subj", "/CN=rogue-ca");
  run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "rogue.key", "-out", "rogue.csr", "-subj", "/CN=ops-jae");
  writeFileSync(join(dir, "rogue.ext"), "extendedKeyUsage=critical,clientAuth\n");
  run("x509", "-req", "-in", "rogue.csr", "-CA", "rogue-ca.pem", "-CAkey", "rogue-ca.key", "-CAcreateserial",
      "-out", "rogue.pem", "-days", "1", "-extfile", "rogue.ext");
}

type Who = "henry" | "jae" | "watcher" | "rogue" | "none";

const certFor = (who: Who): { cert?: Buffer; key?: Buffer } =>
  who === "none"
    ? {}
    : who === "rogue"
      ? { cert: read("rogue.pem"), key: read("rogue.key") }
      : { cert: read(`operator-${who}.pem`), key: read(`operator-${who}.key`) };

function call<T = unknown>(
  port: number,
  path: string,
  method: "GET" | "POST",
  body: unknown,
  who: Who,
): Promise<{ status: number; json: T; text: string }> {
  const payload = body === undefined ? null : JSON.stringify(body);
  return new Promise((ok, fail) => {
    const req = request(
      {
        host: "127.0.0.1", port, path, method,
        ca: [read("ca.pem")],
        ...certFor(who),
        ...(payload !== null
          ? { headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } }
          : {}),
      },
      (res) => {
        let t = "";
        res.on("data", (d) => (t += d));
        res.on("end", () => {
          let json: unknown = null;
          try { json = JSON.parse(t); } catch { /* some bodies are not JSON; `text` carries them */ }
          ok({ status: res.statusCode ?? 0, json: json as T, text: t });
        });
      },
    );
    req.on("error", fail);
    if (payload !== null) req.write(payload);
    req.end();
  });
}

// ── the bundle under test ─────────────────────────────────────────────────────

/**
 * A rendered artifact, in the shape the renderer actually emits: an **nftables JSON** command list.
 *
 * Not nft text, which is what this fixture was at first — and that made the rule-count assertion
 * below pass against a counter that could not count anything. The real generation reported `0 rules`
 * to an approver while carrying three. Measured against a live relay; no test caught it, because the
 * fixture and the counter were wrong in the same direction.
 */
const RULES = JSON.stringify({
  nftables: [
    { add: { table: { family: "inet", name: "heliopause" } } },
    { delete: { table: { family: "inet", name: "heliopause" } } },
    { add: { table: { family: "inet", name: "heliopause" } } },
    {
      add: {
        chain: { family: "inet", table: "heliopause", name: "input", type: "filter", hook: "input", prio: 0, policy: "drop" },
      },
    },
    {
      add: {
        rule: {
          family: "inet", table: "heliopause", chain: "input",
          expr: [{ match: { op: "==", left: { payload: { protocol: "tcp", field: "dport" } }, right: 22 } }, { accept: null }],
          comment: "BASE-SSH",
        },
      },
    },
  ],
});
/** A materially different ruleset: the same shape, a different port. */
const RULES2 = RULES.replace('"right":22', '"right":2222');

/** Guards the fixture pair rather than trusting the `replace` above to have matched. */
assert.notEqual(RULES2, RULES, "RULES2 is identical to RULES — the fixture pair proves nothing");

function bundle(rules = RULES): PlanBundle {
  const manifest: Manifest = {
    generation: rules === RULES ? "gen-aaa" : "gen-bbb",
    issuedAt: "2026-08-03T00:00:00.000Z",
    schemaVersion: SCHEMA_VERSION,
    hosts: {
      "gw-01.dev": {
        stage: "canary",
        rulesetHash: sha(rules),
        confirmTimeoutSec: 120,
        mustContain: ["BASE-SSH"],
        expectFilters: [],
      },
    },
  };
  return { manifest, rulesets: { "gw-01.dev": rules }, workload: {} };
}

/** Propose as henry, approve as jae. Returns the plan hash. */
async function approved(b = bundle()): Promise<string> {
  const p = await call<{ hash: string }>(managerPort, "/plan", "POST", { target: "dev", bundle: b }, "henry");
  assert.equal(p.status, 200, p.text);
  const a = await call(managerPort, "/approve", "POST", { hash: p.json.hash }, "jae");
  assert.equal(a.status, 200, a.text);
  return p.json.hash;
}

before(async () => {
  pki();
  mkdirSync(artifactDir, { recursive: true });
  await initializeRevocationSnapshot(revocationFile);
  const writer = await startRevocationWriter({
    snapshotFile: revocationFile,
    socketPath: revocationWriterSocket,
    log: () => {},
  });
  closers.push(() => writer.server.close());

  const relay = await startRelay({
    artifactDir,
    port: 0,
    hostname: "127.0.0.1",
    tls: {
      certFile: join(dir, "relay-server.pem"),
      keyFile: join(dir, "relay-server.key"),
      caFile: join(dir, "ca.pem"),
    },
    operatorCNs: ["hp-manager", "ops-alice"],
    // The manager's identity, and deliberately not `ops-alice` — the relay's own check is what this
    // separation is for, and a test where both lists are equal cannot see it.
    publisherCNs: ["hp-manager"],
    revocationFile,
    revocationWriterSocket,
    log: () => {},
  });
  relayPort = (relay.server.address() as { port: number }).port;
  closers.push(() => relay.server.close());

  initializeEnrollmentDocument(enrollmentFile);
  const manager = await startManager({
    port: 0,
    hostname: "127.0.0.1",
    relays: [{ name: "dev", url: `https://127.0.0.1:${relayPort}/`, pkiDir: join(dir, "relay-pki") }],
    tls: {
      certFile: join(dir, "mgr-server.pem"),
      keyFile: join(dir, "mgr-server.key"),
      caFile: join(dir, "ca.pem"),
    },
    operatorCNs: ["ops-alice", "ops-jae", "ops-watcher"],
    // `ops-watcher` is deliberately absent: a reader who may not write.
    writerCNs: ["ops-alice", "ops-jae"],
    enrollment: { storeFile: enrollmentFile },
    // This is the documented manager.env combination: the manager checks its full enrollment store
    // while publishing only a minimal projection to the relay. It must not parse the full file as a
    // relay snapshot and fail closed on every otherwise-valid mTLS request.
    revocationFile: enrollmentFile,
    // Publishing signs the bundle, and a manager with no signing key refuses rather than pushing an
    // unsigned one — so this is not test scaffolding, it is the configuration the path requires. A
    // fresh key per run: the agent pins the key id, and a fixture key checked into the repository
    // would be a signing key whose private half is public.
    artifactSigning: { privateKey: generateKeyPairSync("ed25519").privateKey },
    timeoutMs: 2_000,
    publishTimeoutMs: 5_000,
    log: () => {},
  });
  managerPort = (manager.server.address() as { port: number }).port;
  closers.push(() => manager.server.close());
});

after(() => {
  for (const c of closers) c();
  rmSync(dir, { recursive: true, force: true });
});

describe("relay revocation state at startup", () => {
  it("refuses to start when the configured denylist is missing", async () => {
    const fresh = join(dir, "fresh-relay-revocations.json");
    assert.equal(existsSync(fresh), false, "the point of the test is that this file is absent");

    await assert.rejects(
      () => startRelay({
        artifactDir,
        port: 0,
        hostname: "127.0.0.1",
        tls: {
          certFile: join(dir, "relay-server.pem"),
          keyFile: join(dir, "relay-server.key"),
          caFile: join(dir, "ca.pem"),
        },
        operatorCNs: ["ops-alice"],
        publisherCNs: ["ops-alice"],
        revocationFile: fresh,
        revocationWriterSocket,
        log: () => {},
      }),
      /revocation denylist is unavailable/,
    );
    assert.equal(existsSync(fresh), false, "runtime startup must not initialize revocation state");
  });

  it("refuses to start when the privilege-separated writer socket is missing", async () => {
    const snapshot = join(dir, "writerless-revocations.json");
    await initializeRevocationSnapshot(snapshot);
    await assert.rejects(
      () => startRelay({
        artifactDir,
        port: 0,
        hostname: "127.0.0.1",
        tls: {
          certFile: join(dir, "relay-server.pem"),
          keyFile: join(dir, "relay-server.key"),
          caFile: join(dir, "ca.pem"),
        },
        operatorCNs: ["ops-alice"],
        publisherCNs: ["ops-alice"],
        revocationFile: snapshot,
        revocationWriterSocket: join(dir, "missing-writer.sock"),
        log: () => {},
      }),
      /revocation writer is unavailable/,
    );
  });

  it("rejects un-revoke/rewrite and fails closed on runtime deletion or corruption", async () => {
    // Startup validates the existing file without replacing it. Replacing it here would un-revoke
    // every certificate on restart, which is the exact outcome the fail-closed rule prevents.
    const populated = join(dir, "populated-revocations.json");
    const row = {
      fingerprint256: "a".repeat(64),
      subject: "CN=gone",
      reason: "key compromise",
      actor: "ops-alice",
      revokedAt: "2026-08-10T00:00:00Z",
    };
    writeFileSync(populated, JSON.stringify({ schemaVersion: 1, revocations: [row] }));
    const socket = join(dir, "populated-revocation-writer.sock");
    const writer = await startRevocationWriter({ snapshotFile: populated, socketPath: socket, log: () => {} });

    const relay = await startRelay({
      artifactDir,
      port: 0,
      hostname: "127.0.0.1",
      tls: {
        certFile: join(dir, "relay-server.pem"),
        keyFile: join(dir, "relay-server.key"),
        caFile: join(dir, "ca.pem"),
      },
      operatorCNs: ["ops-alice"],
      publisherCNs: ["ops-alice"],
      revocationFile: populated,
      revocationWriterSocket: socket,
      log: () => {},
    });
    const port = (relay.server.address() as { port: number }).port;
    try {
      assert.deepEqual(JSON.parse(readFileSync(populated, "utf8")).revocations, [row]);
      const empty = await call(port, "/revocations", "POST", { schemaVersion: 1, revocations: [] }, "henry");
      assert.equal(empty.status, 400, empty.text);
      const rewritten = await call(
        port,
        "/revocations",
        "POST",
        { schemaVersion: 1, revocations: [{ ...row, reason: "rewritten" }] },
        "henry",
      );
      assert.equal(rewritten.status, 400, rewritten.text);
      assert.deepEqual(JSON.parse(readFileSync(populated, "utf8")).revocations, [row]);

      unlinkSync(populated);
      assert.equal((await call(port, "/status", "GET", undefined, "henry")).status, 401);
      writeFileSync(populated, JSON.stringify({}));
      assert.equal((await call(port, "/status", "GET", undefined, "henry")).status, 401);
    } finally {
      relay.server.close();
      writer.server.close();
    }
  });
});

describe("who may write", () => {
  it("replicates only the minimal revocation snapshot to the relay", async () => {
    for (let i = 0; i < 50 && !existsSync(revocationFile); i++) await new Promise((resolve) => setTimeout(resolve, 20));
    const snapshot = JSON.parse(readFileSync(revocationFile, "utf8"));
    assert.deepEqual(Object.keys(snapshot).sort(), ["revocations", "schemaVersion"]);
    assert.deepEqual(snapshot.revocations, []);
  });

  it("refuses every write endpoint to a reader who is not a writer", async () => {
    // The reason the two lists are separate. `ops-watcher` can read /site — issuing a read-only
    // credential must not silently hand out publish rights.
    for (const [path, body] of [["/plan", { target: "dev", bundle: bundle() }], ["/approve", { hash: "x" }], ["/publish", { hash: "x" }]] as const) {
      const r = await call(managerPort, path, "POST", body, "watcher");
      assert.equal(r.status, 403, `${path} let a non-writer through`);
    }
    // And the same identity really can read, or the test above would prove nothing.
    assert.equal((await call(managerPort, "/site", "GET", undefined, "watcher")).status, 200);
  });

  it("refuses a certificate that does not chain to the CA, even claiming a writer's name", async () => {
    // `rejectUnauthorized: false` means this handshake completes and the subject really does say
    // `ops-jae`. The chain check in `peerCN` is the only thing between that and approving a plan.
    const r = await call(managerPort, "/plan", "POST", { target: "dev", bundle: bundle() }, "rogue");
    assert.equal(r.status, 401);
  });

  it("refuses a caller with no certificate", async () => {
    assert.equal((await call(managerPort, "/plan", "POST", { target: "dev", bundle: bundle() }, "none")).status, 401);
  });
});

describe("proposing", () => {
  it("returns a hash the client can compute independently", async () => {
    // The content address has to be a function of the bundle and the target, or the CLI cannot verify
    // that the plan it is about to approve is the one it rendered.
    const b = bundle();
    const r = await call<{ hash: string; generation: string }>(
      managerPort, "/plan", "POST", { target: "dev", bundle: b }, "henry",
    );
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.hash, planHash("dev", b));
    assert.equal(r.json.generation, "gen-aaa");
  });

  it("ignores any hash the proposer supplies", async () => {
    // The defect this would be: a proposer naming the hash of a plan someone already approved. The
    // server computes it from the bytes, so the extra field is inert.
    const b = bundle(RULES2);
    const r = await call<{ hash: string }>(
      managerPort, "/plan", "POST", { target: "dev", bundle: b, hash: "sha256:" + "0".repeat(64) }, "henry",
    );
    assert.equal(r.json.hash, planHash("dev", b));
  });

  it("gives the same bundle different hashes for different targets", async () => {
    // Otherwise proposing for prod would silently return dev's plan — proposing is idempotent — and
    // publishing it would push to the wrong VPC while reporting success.
    const b = bundle();
    assert.notEqual(planHash("dev", b), planHash("prod", b));
    assert.equal(bundleHash(b), bundleHash(b));
  });

  it("refuses an unknown target and names the ones it knows", async () => {
    const r = await call<{ error: string }>(managerPort, "/plan", "POST", { target: "prod", bundle: bundle() }, "henry");
    assert.equal(r.status, 400);
    contains(r.json.error, "dev");
  });

  it("refuses a bundle whose manifest digest disagrees with its rules", async () => {
    const b = bundle();
    const r = await call<{ error: string }>(
      managerPort, "/plan", "POST", { target: "dev", bundle: { ...b, rulesets: { "gw-01.dev": RULES2 } } }, "henry",
    );
    assert.equal(r.status, 400);
    contains(r.json.error, "hashes to");
  });

  it("summarises each host without carrying the rules", async () => {
    const r = await call<{ summary: { hosts: Array<{ host: string; ruleCount: number }> } }>(
      managerPort, "/plan", "POST", { target: "dev", bundle: bundle() }, "henry",
    );
    assert.deepEqual(r.json.summary.hosts.map((h) => h.host), ["gw-01.dev"]);
    // Exact, not `> 0`. The counter that shipped first returned 0 for every real artifact, and a
    // `> 0` assertion on an nft-text fixture passed anyway — the fixture and the counter agreed with
    // each other and both disagreed with the renderer. The fixture holds exactly one `add: rule`.
    assert.equal(r.json.summary.hosts[0]!.ruleCount, 1, "the summary miscounts the rules it was given");
    // And the rules themselves stay out of the summary: an approval screen that requires reading a
    // fleet's rendered rulesets is one nobody reads.
    assert.equal(r.text.includes("BASE-SSH"), false, "the summary carries the ruleset text");
  });
});

describe("the two-person rule over HTTP", () => {
  it("refuses an approval from the proposer's certificate", async () => {
    const p = await call<{ hash: string }>(managerPort, "/plan", "POST", { target: "dev", bundle: bundle() }, "henry");
    const r = await call<{ error: string }>(managerPort, "/approve", "POST", { hash: p.json.hash }, "henry");
    assert.equal(r.status, 403);
    contains(r.json.error, "cannot approve");
  });

  it("takes the approver's identity from the certificate, not the body", async () => {
    // The bypass that would make the whole mechanism decorative: henry approving as jae by saying so.
    const p = await call<{ hash: string }>(managerPort, "/plan", "POST", { target: "dev", bundle: bundle() }, "henry");
    const r = await call<{ error: string }>(
      managerPort, "/approve", "POST", { hash: p.json.hash, by: "ops-jae", approved: true }, "henry",
    );
    assert.equal(r.status, 403);
  });

  it("refuses to publish a plan nobody approved", async () => {
    const p = await call<{ hash: string }>(managerPort, "/plan", "POST", { target: "dev", bundle: bundle() }, "henry");
    const r = await call<{ error: string }>(managerPort, "/publish", "POST", { hash: p.json.hash }, "henry");
    assert.equal(r.status, 403);
    contains(r.json.error, "not been approved");
  });
});

describe("publishing reaches the relay", () => {
  // **First in this block, and it has to be.** The base is what this process last published, so this
  // branch is only reachable before anything has. Placed anywhere later it would pass or fail on the
  // order tests happen to run in, which is not a property of the code.
  //
  // It is the state after a restart, and after a generation published through the direct path —
  // which 결정 5 keeps as the way out when this process is broken. A diff against a base the fleet
  // is not running would read as authoritative, so there is none.
  it("says it has no base rather than comparing against nothing", async () => {
    const p = await call<{ hash: string }>(managerPort, "/plan", "POST", { target: "dev", bundle: bundle() }, "henry");
    const d = await call<{ unavailable?: string; changes?: unknown }>(
      managerPort, `/plans/${encodeURIComponent(p.json.hash)}/ruleset-diff?host=gw-01.dev`, "GET", undefined, "henry",
    );
    assert.equal(d.status, 200, d.text);
    contains(d.json.unavailable ?? "", "has not published to that VPC");
    assert.equal(d.json.changes, undefined, "an unavailable diff must not also carry an empty one");
  });

  it("writes the generation and the relay serves it", async () => {
    // The V46 property: the failing direction is exercised. Everything up to here could pass with the
    // relay push completely broken.
    const hash = await approved();
    const r = await call<{ published: boolean; generation: string; serving: string; approvedBy: string }>(
      managerPort, "/publish", "POST", { hash }, "henry",
    );
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.published, true);
    assert.equal(r.json.generation, "gen-aaa");
    // The relay's own report of what it is now serving, which is the difference between "written" and
    // "being served".
    assert.equal(r.json.serving, "gen-aaa");
    assert.equal(r.json.approvedBy, "ops-jae");

    // And on disk, where an agent will fetch it.
    //
    // The artifact of record is the **signed** bundle, not a loose manifest and a tree of rulesets.
    // That distinction is the point of the envelope: a relay that stored the expanded files would be
    // storing content whose authorisation it had already thrown away, and anything able to write that
    // directory could then change a ruleset without breaking a signature that no longer covers it.
    const authorized = JSON.parse(readFileSync(join(artifactDir, AUTHORIZED_ARTIFACT_BUNDLE_FILE), "utf8"));
    assert.equal(authorized.manifest.generation, "gen-aaa");
    // Read the ruleset back out of the signed payload rather than from a field beside it. The bundle
    // carries one envelope per host and the ruleset is *inside* what the signature covers; asserting
    // against anything outside it would pass just as well if the signed half were empty.
    const envelope = authorized.artifacts["gw-01.dev"];
    assert.ok(envelope, "no envelope for gw-01.dev");
    const payload = JSON.parse(Buffer.from(envelope.payload, "base64url").toString("utf8"));
    assert.equal(payload.host, "gw-01.dev");
    assert.equal(payload.ruleset, RULES);
    // The expanded layout must not survive beside it. A stale `manifest.json` from an older
    // generation is worse than no file: it names a generation the relay is not serving, and it is
    // exactly what a reader checking "what is on disk" would find first.
    assert.ok(!existsSync(join(artifactDir, "manifest.json")), "the unsigned manifest layout is still being written");
  });

  it("records all three identities in the answer", async () => {
    // The audit trail's whole point. `git` records the policy change; this records who moved it.
    const hash = await approved(bundle(RULES2));
    const r = await call<{ proposedBy: string; approvedBy: string; publishedBy: string }>(
      managerPort, "/publish", "POST", { hash }, "jae",
    );
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(
      [r.json.proposedBy, r.json.approvedBy, r.json.publishedBy],
      ["ops-alice", "ops-jae", "ops-jae"],
      "the publisher need not be the proposer, but all three must be recorded",
    );
  });

  it("refuses to publish the same plan twice", async () => {
    const hash = await approved();
    assert.equal((await call(managerPort, "/publish", "POST", { hash }, "henry")).status, 200);
    const again = await call<{ error: string }>(managerPort, "/publish", "POST", { hash }, "henry");
    assert.equal(again.status, 409);
    contains(again.json.error, "already been published");
  });

  it("refuses a hash this manager never saw", async () => {
    const r = await call(managerPort, "/publish", "POST", { hash: "sha256:" + "f".repeat(64) }, "henry");
    assert.equal(r.status, 404);
  });

  // ── What the next plan changes about the rules ────────────────────────────
  //
  // `/plans/<hash>/changes` compares the policy **source**, which is the text a person wrote. It
  // cannot say what the rules become: one edit to an address object moves every rule that names it,
  // and a rule can move with no line of policy changing at all — a resolver returning a different
  // set, a selector that widened, a geofeed that grew. An approver reading only the source is taking
  // the rendering on trust.
  //
  // Driven through a real publish rather than against the diff function, because the half worth
  // proving here is the wiring: that the bundle the relay accepted is the one remembered as the base.

  it("names the rule a pending plan would change, against what was actually published", async () => {
    const first = await approved();
    assert.equal((await call(managerPort, "/publish", "POST", { hash: first }, "henry")).status, 200);

    // The same shape, one port different — so the diff has exactly one thing to say.
    const second = await call<{ hash: string }>(
      managerPort, "/plan", "POST", { target: "dev", bundle: bundle(RULES2) }, "henry",
    );
    assert.equal(second.status, 200, second.text);

    const d = await call<{ base: string; head: string; changes: Array<{ comment: string; kind: string }>; unchanged: number }>(
      managerPort,
      `/plans/${encodeURIComponent(second.json.hash)}/ruleset-diff?host=gw-01.dev`,
      "GET", undefined, "henry",
    );
    assert.equal(d.status, 200, d.text);
    assert.equal(d.json.base, "gen-aaa", "the base must be what the relay accepted");
    assert.equal(d.json.head, "gen-bbb");
    assert.deepEqual(d.json.changes, [{ comment: "BASE-SSH", kind: "changed" }]);
    assert.equal(d.json.unchanged, 0);
  });

  // ## The route had no caller, and that is what this asserts
  //
  // `/plans/<hash>/ruleset-diff` was implemented and tested and fetched by nothing — not the Svelte
  // console, not any command. So the tests above proved the manager could answer a question nobody
  // asked, and the CLI approver was still comparing hashes, which is the thing the route was added
  // to end.
  //
  // Driven by spawning the real command against this manager, because "the command calls it" is not
  // a property of the server and cannot be checked from here any other way.
  it("is what `heliopause-approve --show` reads", async () => {
    const first = await approved();
    assert.equal((await call(managerPort, "/publish", "POST", { hash: first }, "henry")).status, 200);
    const second = await call<{ hash: string }>(
      managerPort, "/plan", "POST", { target: "dev", bundle: bundle(RULES2) }, "henry",
    );
    assert.equal(second.status, 200, second.text);

    // ⚠️ `execFileSync` cannot be used here, and the reason is the same defect this batch keeps
    // finding: the manager under test runs **in this process**, so a synchronous child blocks the
    // event loop that would answer the request. Measured — the spawn sat for the full 120-second
    // test timeout talking to a server that could not run.
    const out = await new Promise<string>((resolveOut, rejectOut) => {
      const child = spawn(
        process.execPath,
        [
          join(import.meta.dirname, "..", "bin", "heliopause-approve.ts"),
          `https://127.0.0.1:${managerPort}`,
          second.json.hash,
          "--show",
          `--pki=${dir}`,
          "--operator=henry",
        ],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      let stdout = "";
      let stderr = "";
      child.stdout.setEncoding("utf8").on("data", (c: string) => { stdout += c; });
      child.stderr.setEncoding("utf8").on("data", (c: string) => { stderr += c; });
      child.once("error", rejectOut);
      child.once("close", (code) =>
        code === 0 ? resolveOut(stdout) : rejectOut(new Error(`--show exited ${code}: ${stderr || stdout}`)));
    });

    // The rule that moved, by name — the whole point of showing a diff rather than a count.
    contains(out, "BASE-SSH");
    contains(out, "gw-01.dev");
    // And the policy half, which answers `unavailable` here (no repository credential in this
    // harness) — reported rather than swallowed, because an approver shown nothing concludes
    // nothing changed.
    contains(out, "what changed in the policy");
  });

  it("refuses a diff for a host or a plan it does not carry", async () => {
    const p = await call<{ hash: string }>(managerPort, "/plan", "POST", { target: "dev", bundle: bundle() }, "henry");
    const host = await call(
      managerPort, `/plans/${encodeURIComponent(p.json.hash)}/ruleset-diff?host=not-a-host`, "GET", undefined, "henry",
    );
    assert.equal(host.status, 404);
    const plan = await call(
      managerPort, `/plans/${encodeURIComponent("sha256:" + "0".repeat(64))}/ruleset-diff?host=gw-01.dev`,
      "GET", undefined, "henry",
    );
    assert.equal(plan.status, 404);
  });
});

describe("the relay's own check", () => {
  it("refuses a push from an operator who is not a publisher", async () => {
    // Defence in depth, and not redundant: the manager's writer list and the relay's publisher list
    // are configured separately, on different machines. `ops-alice` may write via the manager and may
    // read this relay's status, and still must not push to it directly.
    const r = await call(relayPort, "/publish", "POST", bundle(), "henry");
    assert.equal(r.status, 403);
  });

  it("refuses a push from a caller with no certificate", async () => {
    // The relay uses `rejectUnauthorized: true`, so this fails in the handshake rather than at the
    // route. Either way it must not write — the assertion is on the outcome, not the mechanism.
    await assert.rejects(() => call(relayPort, "/publish", "POST", bundle(), "none"));
  });

  it("refuses an inconsistent bundle even from a publisher", async () => {
    // The relay validates rather than trusting the manager. A manager that had been talked into
    // forwarding a mismatched bundle would otherwise write artifacts every agent then reverts.
    const b = bundle();
    const bad = { ...b, rulesets: { "gw-01.dev": RULES2 } };
    // Pushed with the manager's own credential, out of the directory it uses.
    const r = await new Promise<{ status: number }>((ok, fail) => {
      const payload = JSON.stringify(bad);
      const req = request(
        {
          host: "127.0.0.1", port: relayPort, path: "/publish", method: "POST",
          ca: [read("ca.pem")],
          cert: read("relay-pki/operator-hp-manager.pem"),
          key: read("relay-pki/operator-hp-manager.key"),
          headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) },
        },
        (res) => { res.resume(); res.on("end", () => ok({ status: res.statusCode ?? 0 })); },
      );
      req.on("error", fail);
      req.write(payload);
      req.end();
    });
    assert.equal(r.status, 400);
  });
});

describe("cross-site requests", () => {
  // ## Why this is the console's prerequisite
  //
  // mTLS authenticates the client, and a browser attaches its client certificate to every request to
  // this origin — including one another site caused. So the moment an operator keeps the console's
  // certificate in their keychain, any page they visit can post to `/approve` with their identity
  // already attached. `content-type: text/plain` is what an HTML form can send with no preflight, so
  // there is not even a CORS check in the way.
  //
  // Measured 2026-08-03 against the deployed manager, before the console had any write control: a
  // request with `Origin: https://evil.example` and `Sec-Fetch-Site: cross-site` reached the approval
  // logic and was refused only because that plan hash did not exist.

  /** POST with arbitrary headers, so the browser-shaped attack can be reproduced exactly. */
  function post(path: string, body: unknown, who: Who, headers: Record<string, string>) {
    const payload = JSON.stringify(body);
    return new Promise<{ status: number; text: string }>((ok, fail) => {
      const req = request(
        {
          host: "127.0.0.1", port: managerPort, path, method: "POST",
          ca: [read("ca.pem")],
          ...certFor(who),
          headers: { "content-length": Buffer.byteLength(payload), ...headers },
        },
        (res) => {
          let t = "";
          res.on("data", (d) => (t += d));
          res.on("end", () => ok({ status: res.statusCode ?? 0, text: t }));
        },
      );
      req.on("error", fail);
      req.write(payload);
      req.end();
    });
  }

  it("refuses a write carrying a foreign Origin, even from a valid writer", async () => {
    const r = await post("/approve", { hash: "x" }, "henry", {
      "content-type": "text/plain",
      origin: "https://evil.example",
    });
    assert.equal(r.status, 403);
    contains(r.text, "cross-site");
  });

  it("refuses an opaque browser Origin instead of treating it like the CLI", async () => {
    // Sandboxed documents send the literal value `null`. A real CLI omits the header, so there is
    // no compatibility reason to admit this browser-only shape with ambient mTLS authority.
    const r = await post("/approve", { hash: "x" }, "henry", {
      "content-type": "text/plain",
      origin: "null",
    });
    assert.equal(r.status, 403);
    contains(r.text, "cross-site");
  });

  it("refuses a write whose Sec-Fetch-Site says cross-site", async () => {
    // Set by the browser and not forgeable from page script, so it catches the case where `Origin` is
    // absent on a navigation.
    const r = await post("/approve", { hash: "x" }, "henry", {
      "content-type": "application/json",
      "sec-fetch-site": "cross-site",
    });
    assert.equal(r.status, 403);
  });

  it("refuses a cross-site /plan and /publish too, not just /approve", async () => {
    for (const path of ["/plan", "/publish"]) {
      const r = await post(path, { target: "dev" }, "henry", { origin: "https://evil.example" });
      assert.equal(r.status, 403, `${path} allowed a cross-site write`);
      contains(r.text, "cross-site");
    }
  });

  it("allows a write with no Origin at all — that is the CLI", async () => {
    // The CLI is not a browser and sends no `Origin`. If absence were treated as suspicious, fixing
    // the browser hole would break every existing caller.
    const r = await post("/approve", { hash: "sha256:" + "f".repeat(64) }, "henry", {
      "content-type": "application/json",
    });
    // 404 rather than 200: the hash does not exist. What matters is that it reached the approval logic
    // instead of being refused as cross-site.
    assert.equal(r.status, 404);
  });

  it("allows a write whose Origin is this server", async () => {
    const r = await post("/approve", { hash: "sha256:" + "f".repeat(64) }, "henry", {
      "content-type": "application/json",
      origin: `https://127.0.0.1:${managerPort}`,
      "sec-fetch-site": "same-origin",
    });
    assert.equal(r.status, 404);
  });

  it("does not refuse reads, which cannot be exfiltrated cross-origin anyway", async () => {
    // A cross-site GET cannot read the response without CORS headers this server never sends, and
    // refusing them would give the console a confusing way to fail without denying an attacker
    // anything.
    const r = await new Promise<number>((ok, fail) => {
      const rq = request(
        {
          host: "127.0.0.1", port: managerPort, path: "/site", method: "GET",
          ca: [read("ca.pem")], ...certFor("henry"),
          headers: { origin: "https://evil.example", "sec-fetch-site": "cross-site" },
        },
        (res) => { res.resume(); res.on("end", () => ok(res.statusCode ?? 0)); },
      );
      rq.on("error", fail);
      rq.end();
    });
    assert.equal(r, 200);
  });
});

describe("listing plans", () => {
  it("shows a pending plan to any reader and its approval state", async () => {
    const p = await call<{ hash: string }>(managerPort, "/plan", "POST", { target: "dev", bundle: bundle() }, "henry");
    const r = await call<{ plans: Array<{ hash: string; approval: unknown; target: string | null }> }>(
      managerPort, "/plans", "GET", undefined, "watcher",
    );
    assert.equal(r.status, 200);
    const found = r.json.plans.find((x) => x.hash === p.json.hash);
    assert.ok(found, "the proposed plan is not listed");
    assert.equal(found.approval, null);
    assert.equal(found.target, "dev");
  });

  // ## Why the identity travels with the list
  //
  // The console decides what to *offer* from these two fields. Without `you` it cannot tell which plans
  // the viewer proposed, so it would render an approve button that always fails — and a control that
  // exists to be refused teaches an operator that refusals are noise. Without `canWrite` a reader sees
  // buttons they can never use.
  //
  // Neither is an authorisation decision: `POST /approve` re-checks both against the certificate on
  // that request. These tests pin that the *display* is honest, not that the check lives here.
  it("tells the caller who they are and whether they may write", async () => {
    const w = await call<{ you: string; canWrite: boolean }>(managerPort, "/plans", "GET", undefined, "henry");
    assert.equal(w.json.you, "ops-alice");
    assert.equal(w.json.canWrite, true);

    const r = await call<{ you: string; canWrite: boolean }>(managerPort, "/plans", "GET", undefined, "watcher");
    assert.equal(r.json.you, "ops-watcher");
    assert.equal(r.json.canWrite, false, "a reader must not be told it can write");
  });

  it("still refuses the write itself to a reader who was told canWrite=false", async () => {
    // The pair that matters. If `canWrite` were the authorisation, hiding a button would be the whole
    // defence — and anyone can send the request without the button.
    const p = await call<{ hash: string }>(managerPort, "/plan", "POST", { target: "dev", bundle: bundle() }, "henry");
    const r = await call(managerPort, "/approve", "POST", { hash: p.json.hash }, "watcher");
    assert.equal(r.status, 403);
  });
});

// ## The classic console's write surface was removed with the page it drew
//
// This file used to assert against `consolePage` — its plans list, its approve gating, its confirm
// dialog, its full-hash rendering. The manager stopped serving that HTML (GET /changes is a 302 to
// /app/changes) and the block's own comment said so while still testing it.
//
// Every property it held has a live equivalent in the Svelte console, which is what is served:
//
//   approve offered to a writer who is not the proposer   changes/plans.test.ts
//   publish offered only after approval, never after      changes/plans.test.ts
//   same-origin JSON with the CSRF header                 changes/write.test.ts
//   a confirm step before a write that needs one          shell/write-ask.test.ts
//   the full plan hash, untruncated, in the path          changes/present.test.ts
//
// The API assertions above are untouched: `canWrite` is what the console *offers*, and the server
// re-checks it on every request — which is the pair this file exists to keep apart.

