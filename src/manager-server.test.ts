// The manager's HTTP surface, exercised against a real TLS server.
//
// These are integration tests on purpose. The property under test — "an unauthenticated caller can
// reach /healthz and nothing else" — lives in the interaction between Node's TLS layer and the
// route handler, and a unit test of either half would pass while the pair is wrong. That pairing is
// exactly what V46 got wrong for five hours.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:https";
import { createHash } from "node:crypto";
import { SCHEMA_VERSION } from "./protocol.ts";
import { collectPolicySource } from "./policy-source.ts";
import { DEFAULT_CONFIG } from "./config.ts";
import { connect as tlsConnect } from "node:tls";
import { execFileSync } from "node:child_process";
import { createSign, generateKeyPairSync } from "node:crypto";
import { CSRF_HEADER } from "./session.ts";
import { policyPage } from "./policy-ui.ts";
import { CONSOLE_ROUTES } from "./app-shell.ts";
import {
  consumePendingOidcLogin,
  MAX_PENDING_OIDC_LOGINS,
  API_ROUTES,
  API_ROUTE_PATTERNS,
  rateLimited,
  startManager,
  trimPendingOidcLogins,
} from "./manager-server.ts";
import type { CertBundle } from "./cert-api.ts";

/** The `events` key this test's issuer uses. Not a constant in `set.ts` any more — it is a fact
 * about a deployment's IdP, so every caller declares it and the type checker enforces that. */
const ROLE_CHANGE_EVENT = "https://idp.example.invalid/event/role-change";

const dir = mkdtempSync(join(tmpdir(), "hp-mgr-"));
let port = 0;
let close: () => void = () => {};
const policyExecutionMarker = join(dir, "policy-top-level-ran");

/** A throwaway CA plus a server and a client leaf, built with openssl the way the real PKI does. */
function pki() {
  const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
      "-days", "1", "-subj", "/CN=test-ca");
  // A second, untrusted CA. Its leaf claims the *same* CN as the real operator, which is the only
  // shape of attack that `socket.authorized` stands between: a certless caller has no CN to check,
  // so the CN check alone already refuses it. Without this pair the suite passes with the
  // authorisation check deleted — measured.
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "rogue-ca.key", "-out", "rogue-ca.pem",
      "-days", "1", "-subj", "/CN=rogue-ca");
  run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "rogue.key", "-out", "rogue.csr",
      "-subj", "/CN=ops-alice");
  writeFileSync(join(dir, "rogue.ext"), "extendedKeyUsage=critical,clientAuth\n");
  run("x509", "-req", "-in", "rogue.csr", "-CA", "rogue-ca.pem", "-CAkey", "rogue-ca.key",
      "-CAcreateserial", "-out", "rogue.pem", "-days", "1", "-extfile", "rogue.ext");

  // Trusted by the same CA, and not in `operatorCNs`. Without this the allowlist check has no known
  // positive: every other refused caller is refused earlier, by the chain check or by having no
  // certificate at all, so deleting `operators.has(...)` breaks nothing.
  run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "stranger.key", "-out", "stranger.csr",
      "-subj", "/CN=ops-stranger");
  writeFileSync(join(dir, "stranger.ext"), "extendedKeyUsage=critical,clientAuth\n");
  run("x509", "-req", "-in", "stranger.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", "stranger.pem", "-days", "1", "-extfile", "stranger.ext");

  for (const [name, eku] of [["server", "serverAuth"], ["ops", "clientAuth"]] as const) {
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`,
        "-subj", `/CN=${name === "server" ? "manager" : "ops-alice"}`);
    writeFileSync(join(dir, `${name}.ext`),
      `extendedKeyUsage=critical,${eku}\n` + (name === "server" ? "subjectAltName=IP:127.0.0.1\n" : ""));
    run("x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", `${name}.pem`, "-days", "1", "-extfile", `${name}.ext`);
  }
}

/** One request. `who` chooses which client certificate, if any, is presented. */
function get(
  path: string,
  who: "none" | "operator" | "rogue" | "stranger",
): Promise<{ status: number; body: string; headers: Record<string, string | string[] | undefined> }> {
  return new Promise((resolve, reject) => {
    const req = request({
      host: "127.0.0.1", port, path, method: "GET",
      ca: [readCa()],
      ...(who === "operator" ? { cert: read("ops.pem"), key: read("ops.key") } : {}),
      ...(who === "rogue" ? { cert: read("rogue.pem"), key: read("rogue.key") } : {}),
      ...(who === "stranger" ? { cert: read("stranger.pem"), key: read("stranger.key") } : {}),
    }, (res) => {
      let b = ""; res.on("data", (d) => (b += d));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b, headers: res.headers }));
    });
    req.on("error", reject);
    req.end();
  });
}

const read = (f: string) => readFileSync(join(dir, f));
const readCa = () => read("ca.pem");

before(async () => {
  pki();
  const policyModule = join(dir, "untrusted-policy.ts");
  writeFileSync(
    policyModule,
    `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(policyExecutionMarker)}, "executed");\nexport const site = {};\n`,
  );
  // Keep the removed option in this runtime fixture. If a future manager route starts consulting a
  // legacy deployment object again, opening `/policy` below executes the marker immediately.
  const started = await startManager({
    port: 0,
    hostname: "127.0.0.1",
    // No relays are reachable; every /site answer is "all down", which is fine — these tests are
    // about who may ask, not about what comes back.
    relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
    tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
    operatorCNs: ["ops-alice"],
    timeoutMs: 200,
    policySite: policyModule,
  } as Parameters<typeof startManager>[0] & { policySite: string });
  port = (started.server.address() as { port: number }).port;
  close = () => started.server.close();
});

after(() => {
  close();
  rmSync(dir, { recursive: true, force: true });
});

describe("who may change the fleet", () => {
  it("answers /authz to an operator and refuses it to anyone else", async () => {
    // Same certificate as `/site`. A caller who can enumerate every host and open port learns
    // nothing dangerous from the names allowed to publish — but a caller who cannot must not read it
    // either, because it is still a map of who to attack.
    const ok = await get("/authz", "operator");
    assert.equal(ok.status, 200);
    assert.equal((await get("/authz", "none")).status, 401);
    assert.equal((await get("/authz", "stranger")).status, 403);
  });

  it("reports the certificate allowlists", async () => {
    const body = JSON.parse((await get("/authz", "operator")).body);
    assert.deepEqual(body.certificate.operators, ["ops-alice"]);
  });

  it("names the caller and whether they may write", async () => {
    // The chrome reads these off `/authz` so identity does not depend on `/plans`.
    // This suite has no writer CN — a button that exists to return 403 is noise.
    const body = JSON.parse((await get("/authz", "operator")).body);
    assert.equal(body.you, "ops-alice");
    assert.equal(body.canWrite, false);
    assert.equal(typeof body.pendingPlans, "number");
    // No enrollment store in this suite. 0 would claim the store was read.
    assert.equal(body.pendingCsrs, undefined);
  });

  it("carries no secret, token or key", async () => {
    // The reason this endpoint is safe to put behind the read certificate rather than the write one.
    // Asserted rather than assumed: a later field that carries a service token would be a leak with
    // no other alarm on it.
    //
    // ⚠️ This manager is certificate-only, so the one value here that *is* per-caller — the session's
    // CSRF token — never appears in this body. Do not "improve" this by pointing it at a session and
    // leaving the substring loop as it is: a CSRF token is random base64url, and a random 43-character
    // string over `[A-Za-z0-9-_]` contains `key` often enough to make this fail on a Tuesday. The
    // session case is asserted structurally instead, in the OIDC suite below — see "hands a session
    // its CSRF token at /authz too".
    const raw = (await get("/authz", "operator")).body;
    assert.equal(JSON.parse(raw).csrf, undefined, "a certificate caller has no session and must get no token");
    for (const forbidden of ["secret", "token", "key", "password"]) {
      assert.equal(raw.toLowerCase().includes(forbidden), false, `${forbidden} appears in /authz: ${raw}`);
    }
  });

  it("says null for a door this deployment did not configure", async () => {
    // This suite runs a certificate-only manager. `null` and an empty object are different answers —
    // the second reads as "configured, and nobody is allowed", which is a different deployment.
    const body = JSON.parse((await get("/authz", "operator")).body);
    assert.equal(body.oidc, null);
    assert.equal(body.otp, null);
  });
});

describe("solo approval configuration", () => {
  it("refuses to start when a solo role has no OTP second factor", async () => {
    await assert.rejects(
      () => startManager({
        port: 0,
        hostname: "127.0.0.1",
        relays: [],
        // Deliberately unreadable: configuration validation must fail before secret files or sockets
        // are touched, so a bad deployment never starts in a weaker mode.
        tls: { certFile: "/not-read", keyFile: "/not-read", caFile: "/not-read" },
        oidc: {
          issuer: "https://idp.example.invalid",
          clientId: "manager",
          redirectUri: "https://manager.example.invalid/auth/callback",
          operatorGroups: ["operator"],
          writerGroups: ["writer"],
          soloApprovalRoles: ["admin"],
          aliases: new Map(),
          roleChangeEvent: ROLE_CHANGE_EVENT,
        },
      }),
      /soloApprovalRoles requires otp/,
    );
  });
});

describe("in-flight OIDC login bounds", () => {
  it("expires abandoned states and keeps the map at its hard cap", () => {
    const pending = new Map<string, { verifier: string; nonce: string; at: number }>();
    const now = Date.now();
    pending.set("expired", { verifier: "v", nonce: "n", at: now - 11 * 60_000 });

    for (let i = 0; i < MAX_PENDING_OIDC_LOGINS + 10; i++) {
      trimPendingOidcLogins(pending, now);
      pending.set(`state-${i}`, { verifier: "v", nonce: "n", at: now });
    }

    assert.equal(pending.size, MAX_PENDING_OIDC_LOGINS);
    assert.equal(pending.has("expired"), false);
    assert.equal(pending.has("state-0"), false, "the oldest live state was not evicted");
    assert.equal(pending.has(`state-${MAX_PENDING_OIDC_LOGINS + 9}`), true);
  });

  it("expires an abandoned state at lookup even when insertion order cannot be trusted", () => {
    const pending = new Map<string, { verifier: string; nonce: string; at: number }>();
    const now = Date.now();
    // A wall-clock correction can make a later insertion older than the first map entry. Lookup
    // must check the selected entry itself rather than relying only on oldest-first cleanup.
    pending.set("live", { verifier: "v", nonce: "n", at: now });
    pending.set("expired", { verifier: "v", nonce: "n", at: now - 11 * 60_000 });

    assert.equal(consumePendingOidcLogin(pending, "expired", now), undefined);

    assert.equal(pending.has("expired"), false);
    assert.equal(pending.has("live"), true, "callback lookup evicted another live login");
  });
});

describe("the manager's HTTP surface", () => {
  it("answers /healthz to a caller with no certificate at all", () => {
    // The probe's whole job. Under `rejectUnauthorized: true` this failed in the handshake, so the
    // endpoint documented as unauthenticated was reachable only by callers who could already read
    // everything — and the Kubernetes probe fell back to `tcpSocket`, which proves only that a port
    // is open. That is what let a manager serving an unusable certificate report Ready for hours.
    return get("/healthz", "none").then((r) => {
      assert.equal(r.status, 200);
      assert.equal(JSON.parse(r.body).ok, true);
    });
  });

  it("still refuses /site to that same caller", () => {
    // The other half, and the reason relaxing TLS is safe: authorisation is not in the TLS layer.
    // `peerCN` returns null unless `socket.authorized`, so a peer with no certificate — or a
    // self-signed one — is refused at the route regardless of the handshake succeeding.
    return get("/site", "none").then((r) => assert.equal(r.status, 401));
  });

  it("tells an unauthenticated caller nothing about the fleet", () => {
    // A health endpoint that leaked a host name or a generation would make this trade a bad one.
    return get("/healthz", "none").then((r) => {
      assert.equal(r.body.includes("host"), false);
      assert.equal(r.body.includes("generation"), false);
    });
  });

  it("serves /site to a valid operator", () => {
    return get("/site", "operator").then((r) => {
      assert.equal(r.status, 200);
      const v = JSON.parse(r.body);
      assert.equal(v.asked, 1);
      assert.equal(v.reachable, 0, "the relay is deliberately unreachable here");
    });
  });

  it("refuses a self-signed certificate claiming the operator's name", () => {
    // The test the rest of this file was missing. Deleting `if (!socket.authorized) return null;`
    // from `peerCN` left every other case passing — a caller with no certificate has no CN either,
    // so the CN check refuses it on its own and the deletion is invisible.
    //
    // This is what actually depends on it. `rejectUnauthorized: false` lets this handshake complete,
    // so the certificate reaches the handler and its subject really does say `ops-alice`. The only
    // thing between that and the whole fleet is the chain check.
    return get("/site", "rogue").then((r) => assert.equal(r.status, 401));
  });

  it("sends the classic screens to /app and refuses them to everyone else", () => {
    // The HTML page used to live here. `/app/fleet` is the console now; this path keeps
    // bookmarks. The APIs under `/enrollment/…` and `/policy/…` are a different path.
    return Promise.all([get("/fleet", "operator"), get("/fleet", "none"), get("/fleet", "rogue")]).then(([ok, none, rogue]) => {
      assert.equal(ok.status, 302);
      assert.equal(ok.headers.location, "/app/fleet");
      assert.equal(none.status, 401);
      assert.equal(rogue.status, 401);
    });
  });

  it("has no policy-code route and never evaluates a legacy policy module", async () => {
    const r = await get("/policy", "operator");
    assert.equal(r.status, 404);
    assert.equal(existsSync(policyExecutionMarker), false, "the manager evaluated policy top-level code");
  });

  it("names the screen at / instead of being a second address for it", async () => {
    // `/` used to render the fleet, and so did `/ui`. Two addresses for one screen is what the menu
    // is here to end: a link an operator sends to the colleague who must approve what is on it has
    // to name the thing, and a bookmark has to keep meaning what it meant.
    //
    // A redirect rather than a render also keeps a later overview cheap — it becomes what `/` points
    // at, and `/fleet` goes on meaning the fleet. Serving the fleet at both would recreate `/ui`.
    const r = await get("/", "operator");
    assert.equal(r.status, 302);
    assert.equal(r.headers.location, "/app");
  });

  it("keeps the deleted /ui alias pointing somewhere useful", async () => {
    // Nothing in this repository ever linked to `/ui` — no page, no document, no script — and no
    // comment said why it existed. It is gone; a 301 costs the same as a 404 and a bookmark from a
    // month ago still lands on a screen.
    const r = await get("/ui", "operator");
    assert.equal(r.status, 301);
    assert.equal(r.headers.location, "/app");
  });

  it("sends every SPA screen to the same path under /app", async () => {
    // Exact match only — `/enrollment/tokens` is the token list, not this screen.
    for (const route of CONSOLE_ROUTES.filter((r) => r.spa)) {
      const r = await get(route.path, "operator");
      assert.equal(r.status, 302, `${route.path} did not move`);
      assert.equal(r.headers.location, `/app${route.path}`);
    }
  });

  it("does not move a data path that shares a stem with a screen", async () => {
    const r = await get("/enrollment/tokens", "operator");
    assert.notEqual(r.status, 302);
    assert.notEqual(r.headers.location, "/app/enrollment/tokens");
  });

  it("does not answer a path the menu does not name", async () => {
    // The router leaves an unknown path to the server, which is the only thing that can 404 honestly.
    // A console that renders its landing screen for any URL tells an operator they are somewhere they
    // are not.
    const r = await get("/fleeet", "operator");
    assert.notEqual(r.status, 200);
    assert.notEqual(r.status, 302);
  });

  it("answers 404 rather than 401 for an unknown path from an operator", () => {
    // So a typo reads as a typo. Answering 401 to an authorised caller would send them looking at
    // their certificate for a routing mistake.
    return get("/nope", "operator").then((r) => assert.equal(r.status, 404));
  });
});

describe("SNI — two certificates behind one port", () => {
  // The manager has to answer to a browser and to the operator CLI at the same time, and they
  // require different certificates: the CLI verifies against `heliopause-ca` and connects by IP,
  // a browser trusts neither that CA nor an IP-only SAN. Serving one of them means breaking the
  // other, so it serves both and the name decides.
  const dir2 = mkdtempSync(join(tmpdir(), "hp-sni-"));
  let port2 = 0;
  let close2: () => void = () => {};

  before(async () => {
    const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir2, stdio: "pipe" });
    // A stand-in for the public CA: a second root that the internal one knows nothing about.
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "pub-ca.key", "-out", "pub-ca.pem",
        "-days", "1", "-subj", "/CN=public-ca");
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "pub.key", "-out", "pub.csr",
        "-subj", "/CN=heliopause.example.invalid");
    writeFileSync(join(dir2, "pub.ext"),
      "extendedKeyUsage=critical,serverAuth\nsubjectAltName=DNS:heliopause.example.invalid\n");
    run("x509", "-req", "-in", "pub.csr", "-CA", "pub-ca.pem", "-CAkey", "pub-ca.key", "-CAcreateserial",
        "-out", "pub.pem", "-days", "1", "-extfile", "pub.ext");

    publicBundle = () => ({
      cert: readFileSync(join(dir2, "pub.pem"), "utf8"),
      key: readFileSync(join(dir2, "pub.key"), "utf8"),
      fingerprint: "fp-1",
      // The names this fixture's certificate really carries. Kept in step with the SANs the
      // openssl invocation above requests — a bundle claiming names its certificate lacks would
      // make the manager's mismatch warning fire on a healthy setup.
      sans: ["heliopause.example.invalid", "node-ingest.example.invalid"],
    });

    const started = await startManager({
      port: 0,
      hostname: "127.0.0.1",
      relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
      tls: {
        certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem"),
        public: {
          serverNames: ["heliopause.example.invalid", "node-ingest.example.invalid"],
          load: async () => publicBundle(),
        },
      },
      operatorCNs: ["ops-alice"],
      timeoutMs: 200,
    });
    port2 = (started.server.address() as { port: number }).port;
    close2 = () => started.server.close();
  });

  /** What the fake cert-api hands back. Mutable, so a test can rotate or break it. */
  let publicBundle: () => CertBundle = () => {
    throw new Error("not initialised");
  };

  after(() => { close2(); rmSync(dir2, { recursive: true, force: true }); });

  /** The subject CN of whatever certificate the server presents for `servername`. */
  function servedCN(servername?: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const s = tlsConnect(
        { host: "127.0.0.1", port: port2, servername, rejectUnauthorized: false },
        () => { const c = s.getPeerCertificate(); s.end(); resolve(String(c.subject?.CN ?? "")); },
      );
      s.on("error", reject);
    });
  }

  it("serves the public certificate to a client asking for that name", async () => {
    assert.equal(await servedCN("heliopause.example.invalid"), "heliopause.example.invalid");
    assert.equal(await servedCN("node-ingest.example.invalid"), "heliopause.example.invalid");
  });

  it("serves the internal certificate when there is no SNI at all — the IP path", async () => {
    // This is the case the operator CLI is in. It connects to an address, sends no server_name, and
    // verifies against `heliopause-ca`. If SNI selection defaulted the other way every CLI breaks.
    assert.equal(await servedCN(undefined), "manager");
  });

  it("does not hand the public certificate to a lookalike name", async () => {
    // Exact match, not a suffix. `servername` is text the caller chose.
    assert.equal(await servedCN("notheliopause.example.invalid"), "manager");
    assert.equal(await servedCN("heliopause.example.invalid.evil.test"), "manager");
  });

  it("matches the name case-insensitively, as the TLS RFC requires", async () => {
    assert.equal(await servedCN("HELIOPAUSE.Example.INVALID"), "heliopause.example.invalid");
  });

  it("still requires a client certificate on the public name", async () => {
    // The whole point is that the *server* certificate changed and nothing else did. A browser that
    // now trusts the page must still be authorised, or this swapped a warning for a hole.
    const body = await new Promise<{ status: number }>((resolve, reject) => {
      const r = request({ host: "127.0.0.1", port: port2, path: "/site", method: "GET",
                          servername: "heliopause.example.invalid", rejectUnauthorized: false },
        (res) => { res.resume(); res.on("end", () => resolve({ status: res.statusCode ?? 0 })); });
      r.on("error", reject); r.end();
    });
    assert.equal(body.status, 401);
  });

  it("accepts an operator certificate offered under the public name", async () => {
    // The known positive the refusal above cannot be. That test passes whether or not the public
    // context carries the client CA — a server that verifies nobody refuses everybody, and a
    // refusal is what it asserts. So it stayed green through a release in which mTLS was off for
    // every connection that used the name.
    //
    // This is the same request with a valid certificate attached. It can only pass if the context
    // selected by SNI shares the internal CA with the default one, which is exactly the line that
    // was missing. Delete `ca` from `createSecureContext` and this returns 401.
    const status = await new Promise<number>((resolve, reject) => {
      const r = request({
        host: "127.0.0.1", port: port2, path: "/plans", method: "GET",
        servername: "heliopause.example.invalid", rejectUnauthorized: false,
        cert: readFileSync(join(dir, "ops.pem")),
        key: readFileSync(join(dir, "ops.key")),
      }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
      r.on("error", reject); r.end();
    });
    assert.equal(status, 200, "an operator certificate must authenticate under the public name too");
  });
});

describe("the public certificate is optional at runtime", () => {
  // The manager decides firewall rules. If the certificate source is unreachable when it starts, the
  // right outcome is a manager that runs — the operator CLI verifies against the internal CA and
  // never touches this — and a browser that sees a warning. The wrong outcome is a control plane
  // that will not start because a cosmetic dependency is down.
  const dir3 = mkdtempSync(join(tmpdir(), "hp-nopub-"));

  after(() => rmSync(dir3, { recursive: true, force: true }));

  it("starts and serves when the certificate source throws", async (t) => {
    const started = await startManager({
      port: 0,
      hostname: "127.0.0.1",
      relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
      tls: {
        certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem"),
        public: {
          serverNames: ["heliopause.example.invalid"],
          load: async () => { throw new Error("dispatcher unreachable"); },
        },
      },
      operatorCNs: ["ops-alice"],
      timeoutMs: 200,
    });
    // Registered the moment the server exists, so a failing assertion below still closes it. A
    // listening handle left open makes `node --test` wait forever — which is how defect injection
    // stopped being usable: the tool that reports whether a check is load-bearing hung instead.
    t.after(() => started.server.close());
    const p = (started.server.address() as { port: number }).port;

    // It is up, and the name falls back to the internal certificate rather than failing the
    // handshake. A warning in a browser beats an unreachable console.
    const cn = await new Promise<string>((resolve, reject) => {
      const s = tlsConnect({ host: "127.0.0.1", port: p, servername: "heliopause.example.invalid",
                             rejectUnauthorized: false },
        () => { const c = s.getPeerCertificate(); s.end(); resolve(String(c.subject?.CN ?? "")); });
      s.on("error", reject);
    });
    assert.equal(cn, "manager", "an unavailable public certificate must not break the handshake");
  });

  it("keeps trying, and picks the certificate up without a restart", async (t) => {
    // 🔑 The test above stops one assertion short: it proves the manager *survives* a failed start
    // and never asks whether it ever recovers. It did not. One attempt was spent at startup and the
    // next was a whole `refreshSec` away, so a cert API that was slow for a second cost both public
    // names for an hour — the console, and `node-enroll`, which every fleet host posts its CSR to.
    //
    // Measured 2026-08-18 in production: the pod sat `Running 1/1` with `/healthz` green while
    // `curl https://heliopause.tinyuniver.se/healthz` answered "no alternative certificate subject
    // name matches target host name". The cert API answered in 138ms the whole time.
    const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir3, stdio: "pipe" });
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "r.key", "-out", "r.pem",
        "-days", "1", "-subj", "/CN=retried", "-addext", "subjectAltName=DNS:retry.example.invalid");

    let calls = 0;
    const started = await startManager({
      port: 0, hostname: "127.0.0.1",
      relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
      tls: {
        certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem"),
        public: {
          serverNames: ["retry.example.invalid"],
          // Fails twice, then answers — the shape of a dependency that is briefly slow rather than
          // gone. One failure would be satisfied by a single extra attempt; two needs the ladder.
          load: async () => {
            if (++calls <= 2) throw new Error("dispatcher unreachable");
            return {
              cert: readFileSync(join(dir3, "r.pem"), "utf8"),
              key: readFileSync(join(dir3, "r.key"), "utf8"),
              fingerprint: "fp-retry",
              sans: ["retry.example.invalid"],
            };
          },
          // Fractional seconds so the whole ladder runs inside a test. `refreshSec` is left at its
          // default hour, which is what makes this a test of the retry and not of the interval —
          // remove the retry and nothing else can rescue it before the suite ends.
          retrySec: 0.02,
        },
      },
      operatorCNs: ["ops-alice"],
      timeoutMs: 200,
    });
    t.after(() => started.server.close());
    const p = (started.server.address() as { port: number }).port;

    const servedCN = () => new Promise<string>((resolve, reject) => {
      const s = tlsConnect({ host: "127.0.0.1", port: p, servername: "retry.example.invalid",
                             rejectUnauthorized: false },
        () => { const c = s.getPeerCertificate(); s.end(); resolve(String(c.subject?.CN ?? "")); });
      s.on("error", reject);
    });

    // The known negative, taken first: right after start there is genuinely nothing to serve.
    assert.equal(await servedCN(), "manager", "it cannot already hold a certificate it has not loaded");

    const deadline = Date.now() + 5_000;
    let cn = "";
    while (Date.now() < deadline) {
      cn = await servedCN();
      if (cn === "retried") break;
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(cn, "retried", `the certificate was never picked up — load() was called ${calls} time(s)`);
    assert.ok(calls >= 3, `expected the ladder to have retried, saw ${calls} call(s)`);

    // And it stops. Without this the test is satisfied by a retry that never gives up, which against
    // a cert API that is down for a week is this process hammering it every few milliseconds — the
    // opposite failure, and the one nobody would notice from here.
    const settled = calls;
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(calls, settled, "the retry kept running after the certificate was loaded");
  });

  it("installs a rotated certificate without a restart, and keeps the old one when a refresh fails", async (t) => {
    // cert-manager rotates roughly every 75 days and this process is meant to stay up, so a manager
    // that only read the certificate once would serve an expired one. The second half matters just
    // as much: a transient failure must not throw away a certificate that still works.
    const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir3, stdio: "pipe" });
    for (const n of ["a", "b"]) {
      run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${n}.key`, "-out", `${n}.pem`,
          "-days", "1", "-subj", `/CN=rotated-${n}`, "-addext", "subjectAltName=DNS:rot.example.invalid");
    }
    const bundle = (n: string, fp: string) => ({
      cert: readFileSync(join(dir3, `${n}.pem`), "utf8"),
      key: readFileSync(join(dir3, `${n}.key`), "utf8"),
      fingerprint: fp,
      // Matches the `subjectAltName` the certificates above were issued with.
      sans: ["rot.example.invalid"],
    });
    let mode: "a" | "b" | "fail" = "a";
    const started = await startManager({
      port: 0, hostname: "127.0.0.1",
      relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
      tls: {
        certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem"),
        public: {
          serverNames: ["rot.example.invalid"],
          refreshSec: 60,
          load: async () => {
            if (mode === "fail") throw new Error("cert-api 503");
            return bundle(mode, `fp-${mode}`);
          },
        },
      },
      operatorCNs: ["ops-alice"], timeoutMs: 200,
    });
    t.after(() => started.server.close());
    const p = (started.server.address() as { port: number }).port;
    const served = () => new Promise<string>((resolve, reject) => {
      const s = tlsConnect({ host: "127.0.0.1", port: p, servername: "rot.example.invalid",
                             rejectUnauthorized: false },
        () => { const c = s.getPeerCertificate(); s.end(); resolve(String(c.subject?.CN ?? "")); });
      s.on("error", reject);
    });

    assert.equal(await served(), "rotated-a");

    // The interval is a minute; drive the same code path directly rather than waiting for it.
    mode = "b";
    const second = await startManager({
      port: 0, hostname: "127.0.0.1",
      relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
      tls: {
        certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem"),
        public: { serverNames: ["rot.example.invalid"], load: async () => bundle("b", "fp-b") },
      },
      operatorCNs: ["ops-alice"], timeoutMs: 200,
    });
    t.after(() => second.server.close());
    const p2 = (second.server.address() as { port: number }).port;
    const cn2 = await new Promise<string>((resolve, reject) => {
      const s = tlsConnect({ host: "127.0.0.1", port: p2, servername: "rot.example.invalid",
                             rejectUnauthorized: false },
        () => { const c = s.getPeerCertificate(); s.end(); resolve(String(c.subject?.CN ?? "")); });
      s.on("error", reject);
    });
    assert.equal(cn2, "rotated-b", "a new fingerprint must replace the installed context");
  });
});

describe("OIDC login routes", () => {
  // No IdP is reachable here, and that is the point: every case below is one this server decides on
  // its own. The token exchange itself is covered in `oidc.test.ts` against signed tokens.
  const dir4 = mkdtempSync(join(tmpdir(), "hp-oidc-"));
  let port4 = 0;
  let close4: () => void = () => {};

  before(async () => {
    const started = await startManager({
      port: 0, hostname: "127.0.0.1",
      relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
      tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
      operatorCNs: ["ops-alice"],
      timeoutMs: 200,
      oidc: {
        issuer: "https://idp.example.invalid",
        clientId: "heliopause-manager",
        clientSecret: "s3cret",
        redirectUri: "https://heliopause.example.invalid/auth/callback",
        roleChangeEvent: ROLE_CHANGE_EVENT,
        operatorGroups: ["heliopause-operators"],
        writerGroups: ["heliopause-writers"],
        aliases: new Map([["jang@example.invalid", "ops-alice"]]),
        // An IdP that only ever serves its discovery document. Every case in this block is decided
        // by the manager before a token is involved; the exchange itself is covered in oidc.test.ts.
        fetchImpl: (async (u: string | URL) => {
          if (String(u).endsWith("/.well-known/openid-configuration")) {
            return new Response(JSON.stringify({
              issuer: "https://idp.example.invalid",
              authorization_endpoint: "https://idp.example.invalid/oidc/authorize",
              token_endpoint: "https://idp.example.invalid/oidc/token",
              jwks_uri: "https://idp.example.invalid/oidc/jwks",
              code_challenge_methods_supported: ["S256"],
            }), { status: 200 });
          }
          return new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 });
        }) as unknown as typeof fetch,
      },
    });
    port4 = (started.server.address() as { port: number }).port;
    close4 = () => started.server.close();
  });

  after(() => { close4(); rmSync(dir4, { recursive: true, force: true }); });

  function call(path: string, method = "GET", headers: Record<string, string> = {}) {
    return new Promise<{ status: number; body: string; location?: string; setCookie: string[] }>(
      (resolve, reject) => {
        const r = request({ host: "127.0.0.1", port: port4, path, method, ca: [readCa()], headers },
          (res) => {
            let b = ""; res.on("data", (d) => (b += d));
            res.on("end", () => resolve({
              status: res.statusCode ?? 0, body: b,
              location: typeof res.headers.location === "string" ? res.headers.location : undefined,
              setCookie: ([] as string[]).concat((res.headers["set-cookie"] as string[]) ?? []),
            }));
          });
        r.on("error", reject); r.end();
      });
  }

  /** What a browser would send back: `name=value` pairs, minus the ones being cleared. */
  const cookieHeaderFrom = (r: { setCookie: string[] }): string =>
    r.setCookie.map((c) => c.split(";")[0]!).filter((c) => !c.endsWith("=")).join("; ");

  it("tells an unauthenticated caller where to sign in", async () => {
    // Certificate-only deployments say "no subject CN", which is useless advice to a browser that
    // has no certificate to offer. With OIDC configured there is something to suggest.
    const r = await call("/site");
    assert.equal(r.status, 401);
    assert.match(r.body, /\/auth\/login/);
  });

  it("redirects a login to the IdP with PKCE, state and nonce", async () => {
    const r = await call("/auth/login");
    assert.equal(r.status, 302);
    const u = new URL(r.location!);
    assert.equal(u.origin + u.pathname, "https://idp.example.invalid/oidc/authorize");
    assert.equal(u.searchParams.get("response_type"), "code");
    assert.equal(u.searchParams.get("client_id"), "heliopause-manager");
    assert.equal(u.searchParams.get("code_challenge_method"), "S256");
    assert.ok(u.searchParams.get("code_challenge"));
    assert.ok(u.searchParams.get("state"));
    assert.ok(u.searchParams.get("nonce"));
    // Authorisation is decided from group claims, so a login that does not ask for them produces a
    // principal with no access and a confusing refusal.
    assert.match(u.searchParams.get("scope") ?? "", /\bgroups\b/);
  });

  it("gives a different state and nonce to every login", async () => {
    const [a, b] = await Promise.all([call("/auth/login"), call("/auth/login")]);
    const p = (r: { location?: string }) => new URL(r.location!).searchParams;
    assert.notEqual(p(a).get("state"), p(b).get("state"));
    assert.notEqual(p(a).get("nonce"), p(b).get("nonce"));
    assert.notEqual(p(a).get("code_challenge"), p(b).get("code_challenge"));
  });

  it("refuses a callback whose state this server never issued", async () => {
    // A captured callback URL is exactly this shape.
    const r = await call("/auth/callback?code=x&state=not-one-of-ours");
    assert.equal(r.status, 400);
    assert.match(r.body, /did not start here/);
  });

  it("refuses a callback with no state at all", async () => {
    assert.equal((await call("/auth/callback?code=x")).status, 400);
  });

  it("uses a state once", async () => {
    // Single use is what stops a replay of a callback that did start here.
    const login = await call("/auth/login");
    const state = new URL(login.location!).searchParams.get("state")!;
    const cookie = cookieHeaderFrom(login);
    const first = await call(`/auth/callback?code=bad&state=${encodeURIComponent(state)}`, "GET", { cookie });
    // The exchange fails — there is no IdP — but the state was consumed by getting that far.
    assert.notEqual(first.status, 400, "the first use should reach the token exchange");
    const second = await call(`/auth/callback?code=bad&state=${encodeURIComponent(state)}`, "GET", { cookie });
    assert.equal(second.status, 400);
    assert.match(second.body, /did not start here/);
  });

  // ── Login CSRF ──────────────────────────────────────────────────────────────
  //
  // `state` proves the login started *here*. It does not prove it started in *this browser*, and
  // those are different claims:
  //
  //   1. the attacker opens `/auth/login` in their own browser and authenticates at the IdP
  //   2. they hold the resulting `code` and `state` instead of following the redirect
  //   3. they walk the victim to `/auth/callback?state=…&code=…`
  //   4. the victim's browser is handed **the attacker's session**
  //
  // On this console that session can approve and publish, and `approval.ts` compares proposer and
  // approver as strings — so whatever the victim then does is recorded under the attacker's name.
  // Neither `safeReturnTo` nor single-use `state` touches it: both are about the *redirect* and the
  // *replay*, and this is neither.
  it("hands the browser a login binder and requires it back at the callback", async () => {
    const login = await call("/auth/login");
    const binder = login.setCookie.find((c) => c.startsWith("__Host-heliopause-login="));
    assert.ok(binder, "the login must give this browser something only it holds");
    // `Lax`, and it has to be: the callback is a top-level navigation the *IdP* sends the browser
    // on, so it is cross-site by construction and `Strict` would withhold the cookie from the one
    // request that needs it — the check would enforce itself into an outage.
    assert.match(binder, /SameSite=Lax/);
    assert.match(binder, /HttpOnly/);
    assert.match(binder, /Secure/);
  });

  it("refuses a callback whose state is valid but arrives without the browser that started it", async () => {
    // Exactly the attack: a real `state`, and no cookie — a victim's browser has never seen this
    // login. Before the binder existed this reached the token exchange.
    const login = await call("/auth/login");
    const state = new URL(login.location!).searchParams.get("state")!;
    const r = await call(`/auth/callback?code=bad&state=${encodeURIComponent(state)}`);
    assert.equal(r.status, 400);
    assert.match(r.body, /did not start in this browser/);
  });

  it("refuses a callback carrying somebody else's login binder", async () => {
    // Two logins in flight. Presenting A's `state` with B's cookie must fail — otherwise an attacker
    // who can get *any* binder into the victim's browser is back where they started.
    const a = await call("/auth/login");
    const b = await call("/auth/login");
    const stateA = new URL(a.location!).searchParams.get("state")!;
    const r = await call(
      `/auth/callback?code=bad&state=${encodeURIComponent(stateA)}`,
      "GET",
      { cookie: cookieHeaderFrom(b) },
    );
    assert.equal(r.status, 400);
    assert.match(r.body, /did not start in this browser/);
  });

  it("clears the binder on a refusal, so it cannot be spent twice", async () => {
    const login = await call("/auth/login");
    const state = new URL(login.location!).searchParams.get("state")!;
    const r = await call(`/auth/callback?code=bad&state=${encodeURIComponent(state)}`);
    assert.ok(
      r.setCookie.some((c) => c.startsWith("__Host-heliopause-login=;")),
      "a spent binder must not be left in the browser",
    );
  });

  it("passes an IdP refusal through rather than reporting a generic failure", async () => {
    // "access_denied" after clicking cancel is not the same problem as a misconfigured client.
    const r = await call("/auth/callback?error=access_denied&state=x");
    assert.equal(r.status, 400);
    assert.match(r.body, /access_denied/);
  });

  it("refuses a cross-site logout", async () => {
    const r = await call("/auth/logout", "POST", { origin: "https://evil.example.invalid" });
    assert.equal(r.status, 403);
  });

  it("accepts a logout with no session and says nothing about it", async () => {
    // Ending a session you do not have is not an error worth reporting, and a different answer here
    // would tell an unauthenticated caller whether a cookie was live.
    assert.equal((await call("/auth/logout", "POST")).status, 204);
  });

  it("does not invent routes under /auth", async () => {
    assert.equal((await call("/auth/nope")).status, 404);
  });

  it("leaves the certificate path exactly as it was", async () => {
    // The whole design claim: OIDC adds a door, it does not move the existing one.
    const r = await get("/site", "operator");
    assert.equal(r.status, 200);
  });
});

describe("a real OIDC session, end to end", () => {
  // The CSRF check could not be pinned by the block above: removing it broke nothing, because no test
  // there ever held a session. A check with no known positive is not a check, so this one completes a
  // whole login — signed token and all — and then tries to use it the way an attacker would.
  const d5 = mkdtempSync(join(tmpdir(), "hp-oidc2-"));
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");

  // ── the policy repository, as far as `/policy/edit` can tell ────────────────────────────────────
  //
  // RSA because a GitHub App JWT is RS256 (`appJwt`). The route table answers exactly the calls
  // `commitToBranch` makes and throws on anything else, so a change in that sequence fails here
  // rather than passing against a permissive stub.
  const ghKey = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
  }).privateKey;
  const ghSeen: Array<{ url: string; method: string }> = [];
  const ghFetch = (async (url: string, init?: { method?: string }) => {
    const method = init?.method ?? "GET";
    ghSeen.push({ url, method });
    const reply = (status: number, body: unknown) =>
      ({ ok: status < 400, status, text: async () => JSON.stringify(body) });
    if (method === "POST" && /access_tokens$/.test(url)) return reply(200, { token: "t" });
    if (method === "GET" && /git\/ref\/heads\/main$/.test(url)) return reply(200, { object: { sha: "basesha" } });
    if (method === "POST" && /git\/refs$/.test(url)) return reply(200, {});
    // 404 is "this file is not on the branch yet", which `commitToBranch` swallows on purpose.
    if (method === "GET" && /contents\//.test(url)) return reply(404, { message: "Not Found" });
    if (method === "PUT" && /contents\//.test(url)) return reply(200, { commit: { sha: "c0ffee1234567890" } });
    throw new Error(`no route for ${method} ${url}`);
  }) as unknown as NonNullable<Parameters<typeof startManager>[0]["policyWrite"]>["fetch"];

  let port5 = 0;
  let close5: () => void = () => {};
  /** Set by the test before the callback, so the fake IdP can echo the nonce this server chose. */
  let mintNonce = "";
  let mintGroups: string[] = [];

  before(async () => {
    const fetchImpl = (async (u: string | URL) => {
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
          keys: [{ ...publicKey.export({ format: "jwk" }), kid: "k1", use: "sig", alg: "ES256" }],
        }), { status: 200 });
      }
      // Token endpoint: mint an ID token carrying the nonce this manager generated.
      const now = Math.floor(Date.now() / 1000);
      const header = b64({ alg: "ES256", kid: "k1", typ: "JWT" });
      const payload = b64({
        iss: "https://idp.example.invalid", aud: "heliopause-manager", sub: "idp-sub-1",
        nonce: mintNonce, exp: now + 300, iat: now,
        email: "jang@example.invalid", preferred_username: "henry", groups: mintGroups,
      });
      const sig = createSign("sha256").update(`${header}.${payload}`)
        .sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
      return new Response(JSON.stringify({ id_token: `${header}.${payload}.${sig}` }), { status: 200 });
    }) as unknown as typeof fetch;

    const started = await startManager({
      port: 0, hostname: "127.0.0.1",
      relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
      tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
      operatorCNs: ["ops-alice"], writerCNs: ["ops-alice"],
      timeoutMs: 200,
      oidc: {
        issuer: "https://idp.example.invalid", clientId: "heliopause-manager",
        redirectUri: "https://heliopause.example.invalid/auth/callback",
        roleChangeEvent: ROLE_CHANGE_EVENT,
        operatorGroups: ["heliopause-operators"], writerGroups: ["heliopause-writers"],
        // Solo approval switches the two-person rule off for a role. The constructor refuses it
        // without a second factor, which is why this harness also carries `otp`.
        soloApprovalRoles: ["heliopause-admins"],
        aliases: new Map([["jang@example.invalid", "ops-alice"]]),
        fetchImpl,
      },
      otp: {
        issuerUrl: "https://otp.example.invalid",
        serviceToken: "svc",
        users: new Map([["ops-alice", "keystone-user-1"]]),
        // Always accepts. This block exists so `soloApprovalRoles` is configurable at all; what a
        // wrong code does is covered by its own harness below.
        fetchImpl: (async () => new Response(JSON.stringify({ ok: true }), { status: 200 })) as unknown as typeof fetch,
      },
      // Added so the policy screen's editor is a live route here rather than a 404. Nothing else in
      // this suite depended on its absence, and without it the editor's write path — the one that was
      // broken for every cookie session — has no end-to-end test anywhere in the repository.
      policyWrite: {
        creds: { appId: "1", installationId: "2", privateKey: ghKey },
        target: { owner: "o", repo: "r", base: "main" },
        allowPaths: ["policies.json"],
        fetch: ghFetch,
      },
    });
    port5 = (started.server.address() as { port: number }).port;
    close5 = () => started.server.close();
  });

  after(() => { close5(); rmSync(d5, { recursive: true, force: true }); });

  function call(path: string, method = "GET", headers: Record<string, string> = {}, body?: string) {
    return new Promise<{ status: number; body: string; headers: Record<string, string | string[] | undefined> }>(
      (resolve, reject) => {
        const r = request({ host: "127.0.0.1", port: port5, path, method, ca: [readCa()], headers }, (res) => {
          let b = ""; res.on("data", (d) => (b += d));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b, headers: res.headers }));
        });
        r.on("error", reject);
        if (body) r.write(body);
        r.end();
      });
  }

  /** The `name=value` pairs a browser would send back, from a `Set-Cookie` list. */
  function cookiesFrom(res: { headers: Record<string, string | string[] | undefined> }): string {
    return ([] as string[])
      .concat((res.headers["set-cookie"] as string[]) ?? [])
      .map((c) => c.split(";")[0]!)
      .filter((c) => !c.endsWith("="))
      .join("; ");
  }

  /**
   * Complete a login and return the session cookie.
   *
   * **Carries the login binder from `/auth/login` into `/auth/callback`, which a browser does and
   * this helper did not.** That omission is the whole of the login-CSRF hole: the callback used to
   * be accepted on `state` alone, so anyone holding a `state` could have it completed in *somebody
   * else's* browser and hand them the attacker's session. Now the callback demands the cookie, and
   * a helper that does not send one is not simulating a browser.
   */
  async function signIn(groups: string[]): Promise<string> {
    mintGroups = groups;
    const login = await call("/auth/login");
    const q = new URL(String((login.headers.location ?? "") as string)).searchParams;
    mintNonce = q.get("nonce")!;
    const cb = await call(
      `/auth/callback?code=any&state=${encodeURIComponent(q.get("state")!)}`,
      "GET",
      { cookie: cookiesFrom(login) },
    );
    assert.equal(cb.status, 302, `callback should have set a session, got ${cb.status}: ${cb.body}`);
    const session = ([] as string[])
      .concat((cb.headers["set-cookie"] as string[]) ?? [])
      .map((c) => c.split(";")[0]!)
      .find((c) => c.startsWith("__Host-heliopause-session="));
    assert.ok(session, "callback did not set a session cookie");
    return session;
  }

  /** Same as `call`, but presenting the operator certificate the CLI uses. */
  function callWithCert(path: string, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; body: string; headers: Record<string, string | string[] | undefined> }>(
      (resolve, reject) => {
        const r = request({
          host: "127.0.0.1", port: port5, path, method: "GET", ca: [readCa()], headers,
          cert: readFileSync(join(dir, "ops.pem")), key: readFileSync(join(dir, "ops.key")),
        }, (res) => {
          let b = ""; res.on("data", (d) => (b += d));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b, headers: res.headers }));
        });
        r.on("error", reject);
        r.end();
      });
  }

  it("still lets the certificate speak for the CLI — the known positive for the change below", async () => {
    // Written first and deliberately: the next three tests assert that a certificate stops working
    // somewhere, and a matrix of negatives with no positive cannot tell "correctly refused" from
    // "the certificate never worked in this harness". `heliopause-publish`, `-status`, `-approve`
    // and `-enrollment` have no credential but this one, and it is also the way in when the IdP is
    // down, so it keeps working for everything that is not a page.
    const r = await callWithCert("/site");
    assert.equal(r.status, 200, "the CLI path must keep working");
  });

  it("lets the session win when the browser also holds a certificate", async () => {
    // The `Accept` rule below fixes the page and nothing the page calls. The console's `fetch` sets
    // no `Accept`, so the browser sends `*/*` — a signed-in operator whose browser also holds a
    // client certificate had every API call behind the console resolved as the certificate. That
    // takes away the group claims (`maySoloApprove` needs them), swaps `canWrite` for the
    // `writerCNs` answer, and skips CSRF, which is gated on `via === "oidc"` too.
    //
    // `/plans` is the assertion because it carries `maySoloApprove`, which is derived from the
    // claims a certificate cannot hold: if the certificate had won, it would be false here.
    const cookie = await signIn(["heliopause-operators", "heliopause-admins"]);
    const r = await callWithCert("/plans", { cookie });
    assert.equal(r.status, 200, r.body);
    assert.equal(
      JSON.parse(r.body).maySoloApprove,
      true,
      "the certificate overrode the session and took the operator's roles with it",
    );
  });

  it("does not let a certificate sign a browser in", async () => {
    // A certificate carries a CN and no group claim, so an operator arriving that way is a name with
    // no role — which is why `maySoloApprove` requires `via === "oidc"`. Worse, the certificate used
    // to win over a session that was already established, so a signed-in operator's roles vanished
    // the moment their browser offered a certificate to the same host.
    const r = await callWithCert("/", { accept: "text/html" });
    assert.equal(r.status, 302, "an HTML request was authenticated by certificate");
    assert.match(String(r.headers.location), /^\/auth\/login/);
  });

  it("sends every page to the IdP, not just the console root", async () => {
    // `/policy` answered 401 JSON to a browser that followed a link to it, which reads as a broken
    // site rather than as "sign in first".
    const r = await call("/policy", "GET", { accept: "text/html" });
    assert.equal(r.status, 302);
    assert.match(String(r.headers.location), /next=%2Fpolicy/);
  });

  it("still answers a poll with 401 rather than login HTML", async () => {
    // The distinction is `Accept`, not the path. A `fetch` from the loaded page whose session has
    // expired must see the status code; a redirect would fill the page with the IdP's markup.
    const r = await call("/site", "GET", { accept: "application/json" });
    assert.equal(r.status, 401);
  });

  it("returns the browser to the page it was trying to open", async () => {
    mintGroups = ["heliopause-operators"];
    const login = await call("/auth/login?next=%2Fpolicy");
    const q = new URL(String(login.headers.location as string)).searchParams;
    mintNonce = q.get("nonce")!;
    const cb = await call(`/auth/callback?code=any&state=${encodeURIComponent(q.get("state")!)}`, "GET", { cookie: cookiesFrom(login) });
    assert.equal(cb.status, 302);
    assert.equal(cb.headers.location, "/policy", "login threw away where the operator was going");
  });

  it("refuses to be turned into an open redirect", async () => {
    // The value never round-trips through the browser — it is stored under a `state` this server
    // minted — but it is validated on the way in and again on the way out, because a redirect target
    // is worth checking where it becomes a `Location` header.
    mintGroups = ["heliopause-operators"];
    for (const evil of ["//evil.example", "https://evil.example", "/\\evil.example", "/auth/login"]) {
      const login = await call(`/auth/login?next=${encodeURIComponent(evil)}`);
      const q = new URL(String(login.headers.location as string)).searchParams;
      mintNonce = q.get("nonce")!;
      const cb = await call(`/auth/callback?code=any&state=${encodeURIComponent(q.get("state")!)}`, "GET", { cookie: cookiesFrom(login) });
      assert.equal(cb.headers.location, "/", `login followed ${evil}`);
    }
  });

  it("signs a group member in and lets them read — the known positive", async () => {
    const cookie = await signIn(["heliopause-operators"]);
    const r = await call("/site", "GET", { cookie });
    assert.equal(r.status, 200, "a valid session must read the site view");
  });

  it("refuses someone whose groups grant nothing", async () => {
    mintGroups = ["some-other-team"];
    const login = await call("/auth/login");
    const q = new URL(String(login.headers.location as string)).searchParams;
    mintNonce = q.get("nonce")!;
    const cb = await call(`/auth/callback?code=any&state=${encodeURIComponent(q.get("state")!)}`, "GET", { cookie: cookiesFrom(login) });
    assert.equal(cb.status, 403);
    assert.match(cb.body, /not authorised/);
  });

  it("tells the console whether this caller may approve their own plan", async () => {
    // The capability existed and could not be reached. `POST /approve` has taken `mayApproveOwn`
    // since the role was added, but `/plans` never carried it, and the screen hides the approve
    // button whenever the viewer proposed the plan — so solo approval had no way to be used. It is
    // OIDC-only by design (a certificate carries no role claim), which makes the console its only
    // surface, and the console was the half that did not know.
    const admin = await signIn(["heliopause-operators", "heliopause-writers", "heliopause-admins"]);
    const asAdmin = JSON.parse((await call("/plans", "GET", { cookie: admin })).body);
    assert.equal(asAdmin.maySoloApprove, true, "an admin session must be told it may approve its own plan");

    // The known negative on the same field. Without it this passes on a server that hardcodes true,
    // which would offer every operator a button the server then refuses — and a control that exists
    // to be refused teaches an operator to ignore refusals.
    const plain = await signIn(["heliopause-operators", "heliopause-writers"]);
    const asPlain = JSON.parse((await call("/plans", "GET", { cookie: plain })).body);
    assert.equal(asPlain.maySoloApprove, false, "a session without the role must not be offered it");

    // Never for a certificate: no role claim, so the two-person rule stays on for the CLI.
    const asCert = JSON.parse((await get("/plans", "operator")).body);
    assert.equal(asCert.maySoloApprove, false, "a certificate caller may never approve its own plan");
  });

  it("hands the session its CSRF token, and only to a session", async () => {
    const cookie = await signIn(["heliopause-operators"]);
    const withSession = JSON.parse((await call("/plans", "GET", { cookie })).body);
    assert.ok(typeof withSession.csrf === "string" && withSession.csrf.length > 20);
    // A certificate caller has none and needs none.
    const withCert = JSON.parse((await get("/plans", "operator")).body);
    assert.equal(withCert.csrf, undefined);
  });

  it("hands a session its CSRF token at /authz too", async () => {
    // The policy screen's editor reads its token off `/authz`, not `/plans`, and for the whole life of
    // that editor the field was not there. `token()` coalesces the miss to `''` and caches it, so the
    // write went out with no header and `checkCsrf` refused it — every save and every proposal on
    // `/policy`, for any cookie session. The certificate path skips CSRF entirely, which is why the
    // suite stayed green.
    const cookie = await signIn(["heliopause-operators", "heliopause-writers"]);
    const authz = JSON.parse((await call("/authz", "GET", { cookie })).body);
    assert.ok(typeof authz.csrf === "string" && authz.csrf.length > 20, "no CSRF token at /authz for a session");

    // 🔑 The same token, not merely *a* token. A per-request value would pass the line above and still
    // be refused by `checkCsrf`, which compares against the one held on the session.
    const plans = JSON.parse((await call("/plans", "GET", { cookie })).body);
    assert.equal(authz.csrf, plans.csrf, "the two routes handed out different tokens for one session");
    assert.equal(authz.you, plans.you);
    assert.equal(authz.canWrite, plans.canWrite);

    // Structural, because the substring check in the certificate suite cannot be pointed at a body
    // carrying random base64url. Nothing but `csrf` may have been added.
    const cert = JSON.parse((await get("/authz", "operator")).body);
    assert.deepEqual(
      Object.keys(authz).filter((k) => !Object.keys(cert).includes(k)),
      ["csrf"],
      "a session's /authz gained a field other than csrf",
    );

    // A certificate caller has no session, so no token — the same asymmetry `/plans` has.
    assert.equal(cert.csrf, undefined);
  });

  it("saves from the policy screen's own script, against this server", async () => {
    // 🔑 The known positive the editor never had. It runs the **rendered page's own script** — not a
    // re-implementation of what it does — and every request it makes goes to the live manager.
    //
    // The fixture is deliberately not a canned `/authz` body. The defect was that the page read a
    // field off a real response that did not carry it, and a response written by this test would
    // carry whatever its author assumed — which is the same mistake in a new place.
    const cookie = await signIn(["heliopause-operators", "heliopause-writers"]);

    const html = policyPage([], {
      site: "policy/dev.ts", generation: "abc1234", hosts: ["gw-01.dev"],
      edit: {
        path: "policies.json",
        content: JSON.stringify({
          schemaVersion: 1,
          groups: { gwPolicies: [{
            id: "A", name: "a", enabled: true, priority: 100, proto: "tcp", ports: "22",
            action: "allow", denyMode: "drop", notes: "",
            src: { kind: "cidr", value: "10.0.0.0/8" }, dst: { kind: "any", value: "" },
          }] },
        }),
        nonce: "N",
      },
    });
    const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html)?.[1] ?? "";
    assert.ok(script.length > 100, "the editor rendered no script, so this test proves nothing");

    const listeners = new Map<string, () => Promise<void>>();
    const element = (id: string) => ({
      addEventListener: (ev: string, fn: () => Promise<void>) => listeners.set(`${id}:${ev}`, fn),
      textContent: "", className: "", style: {}, appendChild() {}, setAttribute() {},
      value: "", innerHTML: "",
    });

    const sent: Array<{ path: string; method: string; csrf?: string; status: number }> = [];
    // The browser's part: it attaches the cookie and the Origin, and the script attaches the rest.
    const browser = async (path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) => {
      const method = init.method ?? "GET";
      const headers = { ...(init.headers ?? {}), cookie, origin: `https://127.0.0.1:${port5}` };
      const r = await call(path, method, headers, init.body);
      sent.push({ path, method, csrf: (init.headers ?? {})[CSRF_HEADER], status: r.status });
      return { ok: r.status < 400, status: r.status, json: async () => JSON.parse(r.body) };
    };

    new Function("document", "fetch", "CSS", script)(
      { getElementById: element, querySelector: () => null, createElement: element },
      browser,
      { escape: (s: string) => s },
    );

    const save = listeners.get("rule-save:click");
    assert.ok(save, "the save button had no handler");
    await save();

    const write = sent.find((s) => s.method === "POST");
    assert.ok(write, `the script sent no write — it made ${JSON.stringify(sent)}`);
    // Named separately from the status: a save that is refused for some *other* reason would leave
    // the header assertion the only thing standing between this and the bug coming back.
    assert.ok(write.csrf, `the write carried no ${CSRF_HEADER} — the token lookup came back empty`);
    assert.equal(write.status, 200, `the manager refused the save: ${JSON.stringify(sent)}`);

    // And it reached the repository rather than stopping at the console.
    assert.ok(ghSeen.some((c) => c.method === "PUT"), "no file was committed");
  });

  it("asks again for the token after a lookup that came back empty", async () => {
    // The half that made the missing field invisible. `token()` used to cache on "not null", so one
    // failed or fieldless `/authz` was remembered as `''` for the life of the page: every later write
    // went out bare and was refused, and reloading was the only cure nobody knew to reach for.
    const cookie = await signIn(["heliopause-operators", "heliopause-writers"]);
    const html = policyPage([], {
      site: "policy/dev.ts", generation: "abc1234", hosts: ["gw-01.dev"],
      edit: { path: "policies.json", content: JSON.stringify({ schemaVersion: 1, groups: {} }), nonce: "N" },
    });
    const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html)?.[1] ?? "";

    const listeners = new Map<string, () => Promise<void>>();
    const element = (id: string) => ({
      addEventListener: (ev: string, fn: () => Promise<void>) => listeners.set(`${id}:${ev}`, fn),
      textContent: "", className: "", style: {}, appendChild() {}, setAttribute() {},
      value: "", innerHTML: "",
    });

    // The first `/authz` fails the way a redeployed manager or a dropped connection does. Everything
    // after it is the real server.
    let authzCalls = 0;
    const sent: Array<{ path: string; method: string; csrf?: string; status: number }> = [];
    const browser = async (path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) => {
      const method = init.method ?? "GET";
      if (path.endsWith("/authz") && ++authzCalls === 1) return { ok: false, status: 503, json: async () => ({}) };
      const headers = { ...(init.headers ?? {}), cookie, origin: `https://127.0.0.1:${port5}` };
      const r = await call(path, method, headers, init.body);
      sent.push({ path, method, csrf: (init.headers ?? {})[CSRF_HEADER], status: r.status });
      return { ok: r.status < 400, status: r.status, json: async () => JSON.parse(r.body) };
    };

    new Function("document", "fetch", "CSS", script)(
      { getElementById: element, querySelector: () => null, createElement: element },
      browser,
      { escape: (s: string) => s },
    );

    const save = listeners.get("rule-save:click")!;
    await save();   // token lookup fails; this write is refused, and that is expected
    await save();   // the page must recover on its own

    assert.equal(authzCalls, 2, "the page never asked for the token again");
    const second = sent.filter((s) => s.method === "POST").at(-1);
    assert.ok(second?.csrf, "the retry still went out with no token");
    assert.equal(second.status, 200, `the retry was refused: ${JSON.stringify(sent)}`);
  });

  it("refuses a session POST with no CSRF header", async () => {
    // The injection that removed this check broke no test until now.
    const cookie = await signIn(["heliopause-operators", "heliopause-writers"]);
    const r = await call("/approve", "POST", {
      cookie, origin: `https://127.0.0.1:${port5}`, "content-type": "application/json",
    }, JSON.stringify({ hash: "sha256:whatever" }));
    assert.equal(r.status, 403);
    assert.match(r.body, /CSRF/i);
  });

  it("refuses a session POST carrying another session's token", async () => {
    const a = await signIn(["heliopause-operators", "heliopause-writers"]);
    const b = await signIn(["heliopause-operators", "heliopause-writers"]);
    const bTok = JSON.parse((await call("/plans", "GET", { cookie: b })).body).csrf as string;
    const r = await call("/approve", "POST", {
      cookie: a, origin: `https://127.0.0.1:${port5}`, [CSRF_HEADER]: bTok,
      "content-type": "application/json",
    }, JSON.stringify({ hash: "sha256:whatever" }));
    assert.equal(r.status, 403);
  });

  it("refuses a session POST from another origin even with the right token", async () => {
    const cookie = await signIn(["heliopause-operators", "heliopause-writers"]);
    const tok = JSON.parse((await call("/plans", "GET", { cookie })).body).csrf as string;
    const r = await call("/approve", "POST", {
      cookie, origin: "https://evil.example.invalid", [CSRF_HEADER]: tok,
      "content-type": "application/json",
    }, JSON.stringify({ hash: "sha256:whatever" }));
    assert.equal(r.status, 403);
  });

  it("lets a correct session POST through to the approval logic", async () => {
    // The known positive for the whole write path: with cookie, origin and token all correct the
    // request reaches `approve()` and is refused on the plan hash — not on authentication.
    const cookie = await signIn(["heliopause-operators", "heliopause-writers"]);
    const tok = JSON.parse((await call("/plans", "GET", { cookie })).body).csrf as string;
    const r = await call("/approve", "POST", {
      cookie, origin: `https://127.0.0.1:${port5}`, [CSRF_HEADER]: tok,
      "content-type": "application/json",
      // A code is required now that this harness configures one; the plan lookup is still what
      // must refuse this request, which is the point of the case.
    }, JSON.stringify({ hash: "sha256:not-a-real-plan", otp: "123456" }));
    assert.equal(r.status, 404, `expected the plan lookup to be what refuses this, got ${r.status}: ${r.body}`);
  });

  it("refuses writes to a writer with no alias, and still lets them read", async () => {
    // The two-person rule. `approval.ts` compares proposer and approver as strings, so one human
    // under two names would satisfy it alone.
    mintGroups = ["heliopause-operators", "heliopause-writers"];
    const login = await call("/auth/login");
    const q = new URL(String(login.headers.location as string)).searchParams;
    mintNonce = q.get("nonce")!;
    // Same login, but the identity is one no alias covers.
    const cb = await call(`/auth/callback?code=any&state=${encodeURIComponent(q.get("state")!)}`, "GET", { cookie: cookiesFrom(login) });
    const cookie = ([] as string[]).concat(cb.headers["set-cookie"] as string[] ?? [])[0]!.split(";")[0]!;
    const plans = JSON.parse((await call("/plans", "GET", { cookie })).body);
    assert.equal(plans.canWrite, true, "this identity IS aliased, so it may write");
    assert.equal(plans.you, "ops-alice", "and its name collapses onto the certificate's");
  });

  it("refuses a write from a session that is only in an operator group", async () => {
    // Without this, granting every session write access passes the whole suite: the write tests all
    // sign in as a writer, so the read-only case is never exercised against a write route.
    const cookie = await signIn(["heliopause-operators"]);
    const plans = JSON.parse((await call("/plans", "GET", { cookie })).body);
    assert.equal(plans.canWrite, false, "an operator group alone is not write access");
    const r = await call("/approve", "POST", {
      cookie, origin: `https://127.0.0.1:${port5}`, [CSRF_HEADER]: plans.csrf,
      "content-type": "application/json",
    }, JSON.stringify({ hash: "sha256:whatever" }));
    assert.equal(r.status, 403, "CSRF was satisfied; this must be refused on authority");
    assert.match(r.body, /not authorised to change the fleet/);
  });

  it("drops authority on a role change, without waiting for the session to expire", async () => {
    // The window this whole mechanism exists to close. `admin` permits approving a plan one proposed
    // oneself — the two-person rule switched off — so revoking it has to take effect now, not in
    // eight hours.
    const cookie = await signIn(["heliopause-operators", "heliopause-writers"]);
    assert.equal(JSON.parse((await call("/plans", "GET", { cookie })).body).canWrite, true);

    const now = Math.floor(Date.now() / 1000);
    const head = b64({ alg: "ES256", kid: "k1", typ: "secevent+jwt" });
    const pay = b64({
      iss: "https://idp.example.invalid", sub: "idp-sub-1", aud: "heliopause-manager",
      iat: now, exp: now + 300, jti: "set-demote-1", txn: String(Date.now()),
      events: { [ROLE_CHANGE_EVENT]:
        { roles: ["heliopause-operators"], entitlements: [] } },
    });
    const sig = createSign("sha256").update(`${head}.${pay}`)
      .sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");

    const r = await call("/auth/role-change", "POST", { "content-type": "application/x-www-form-urlencoded" },
      new URLSearchParams({ role_change_token: `${head}.${pay}.${sig}` }).toString());
    assert.equal(r.status, 204);

    // Same cookie, same session — and it may no longer write.
    const after = JSON.parse((await call("/plans", "GET", { cookie })).body);
    assert.equal(after.canWrite, false, "the demotion must apply to the live session");
    assert.equal(after.you, "ops-alice", "the name must survive, or the two-person rule breaks");
  });

  it("ends the session when the role change leaves no operator role", async () => {
    // Demoting to a principal with no access would leave a session that authenticates and can do
    // nothing, which reads like a bug to whoever hits it.
    const cookie = await signIn(["heliopause-operators"]);
    assert.equal((await call("/site", "GET", { cookie })).status, 200);

    const now = Math.floor(Date.now() / 1000);
    const head = b64({ alg: "ES256", kid: "k1", typ: "secevent+jwt" });
    const pay = b64({
      iss: "https://idp.example.invalid", sub: "idp-sub-1", aud: "heliopause-manager",
      iat: now, exp: now + 300, jti: "set-revoke-1", txn: String(Date.now() + 1000),
      events: { [ROLE_CHANGE_EVENT]: { roles: [], entitlements: [] } },
    });
    const sig = createSign("sha256").update(`${head}.${pay}`)
      .sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");

    assert.equal((await call("/auth/role-change", "POST",
      { "content-type": "application/x-www-form-urlencoded" },
      new URLSearchParams({ role_change_token: `${head}.${pay}.${sig}` }).toString())).status, 204);

    assert.equal((await call("/site", "GET", { cookie })).status, 401, "the session must be gone");
  });

  it("ends a live session on a back-channel logout, through the real route", async () => {
    // The route, not just the verifier. `verifyBackchannelLogout` returning a subject proves nothing
    // about whether any session ended — that is the seam this repository keeps discovering, most
    // recently with `membershipJumps`, which was correct and unreachable for weeks.
    //
    // Until this endpoint existed the only way to end someone's session from outside was restarting
    // the pod, and the client's Back-channel Logout URI was left blank because registering one
    // without a route would show the administrator a successful logout while the session lived on.
    const cookie = await signIn(["heliopause-operators"]);
    assert.equal((await call("/site", "GET", { cookie })).status, 200, "signed in to begin with");

    const now = Math.floor(Date.now() / 1000);
    const head = b64({ alg: "ES256", kid: "k1", typ: "secevent+jwt" });
    const pay = b64({
      iss: "https://idp.example.invalid", sub: "idp-sub-1", aud: "heliopause-manager",
      iat: now, exp: now + 300, jti: "logout-1",
      // No `txn`: a logout is not a snapshot and has nothing to be ordered against.
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    });
    const sig = createSign("sha256").update(`${head}.${pay}`)
      .sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");

    const r = await call("/auth/backchannel-logout", "POST",
      { "content-type": "application/x-www-form-urlencoded" },
      new URLSearchParams({ logout_token: `${head}.${pay}.${sig}` }).toString());
    assert.equal(r.status, 204);

    assert.equal((await call("/site", "GET", { cookie })).status, 401, "the session must be gone");
  });

  it("refuses a logout token carrying nonce, and the session survives", async () => {
    // An ID token is signed by the same key and carries `nonce`. Refusing it here is what stops a
    // captured one from being replayed to end a session — and the session outliving the attempt is
    // the half that says the refusal happened before anything was applied.
    const cookie = await signIn(["heliopause-operators"]);
    const now = Math.floor(Date.now() / 1000);
    const head = b64({ alg: "ES256", kid: "k1", typ: "secevent+jwt" });
    const pay = b64({
      iss: "https://idp.example.invalid", sub: "idp-sub-1", aud: "heliopause-manager",
      iat: now, exp: now + 300, jti: "logout-nonce-1", nonce: "n-1",
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    });
    const sig = createSign("sha256").update(`${head}.${pay}`)
      .sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");

    const r = await call("/auth/backchannel-logout", "POST",
      { "content-type": "application/x-www-form-urlencoded" },
      new URLSearchParams({ logout_token: `${head}.${pay}.${sig}` }).toString());
    assert.ok(r.status >= 400, `expected a refusal, got ${r.status}`);
    assert.equal((await call("/site", "GET", { cookie })).status, 200,
      "a refused logout must leave the session alone");
  });

  it("answers 204 for a subject with no sessions", async () => {
    // A person who is not signed in has been logged out as far as the administrator is concerned.
    // An error here would read as a delivery failure in the IdP's log — and the IdP does not retry.
    const now = Math.floor(Date.now() / 1000);
    const head = b64({ alg: "ES256", kid: "k1", typ: "secevent+jwt" });
    const pay = b64({
      iss: "https://idp.example.invalid", sub: "nobody-here", aud: "heliopause-manager",
      iat: now, exp: now + 300, jti: "logout-absent-1",
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    });
    const sig = createSign("sha256").update(`${head}.${pay}`)
      .sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");

    assert.equal((await call("/auth/backchannel-logout", "POST",
      { "content-type": "application/x-www-form-urlencoded" },
      new URLSearchParams({ logout_token: `${head}.${pay}.${sig}` }).toString())).status, 204);
  });

  it("refuses an unsigned or malformed role change without touching sessions", async () => {
    const cookie = await signIn(["heliopause-operators", "heliopause-writers"]);
    const bad = await call("/auth/role-change", "POST",
      { "content-type": "application/x-www-form-urlencoded" },
      new URLSearchParams({ role_change_token: "not.a.token" }).toString());
    assert.ok(bad.status >= 400, `expected a refusal, got ${bad.status}`);
    assert.equal(JSON.parse((await call("/plans", "GET", { cookie })).body).canWrite, true,
      "a refused token must change nothing");

    const empty = await call("/auth/role-change", "POST",
      { "content-type": "application/x-www-form-urlencoded" }, "");
    assert.equal(empty.status, 400);
  });

  it("ends a session on logout", async () => {
    const cookie = await signIn(["heliopause-operators"]);
    assert.equal((await call("/site", "GET", { cookie })).status, 200);
    const out = await call("/auth/logout", "POST", { cookie, origin: `https://127.0.0.1:${port5}` });
    assert.equal(out.status, 204);
    assert.equal((await call("/site", "GET", { cookie })).status, 401, "the cookie must stop working");
  });
});

describe("the allowlists, with a caller who is refused by them and nothing else", () => {
  it("refuses a properly issued certificate that is not in operatorCNs", async () => {
    // Every other refused caller in this file is refused *before* the allowlist: no certificate, or
    // one from an untrusted CA. So deleting `operators.has(...)` passed the whole suite — measured.
    // This certificate is valid, chains to the CA the server trusts, and simply is not on the list.
    const r = await get("/site", "stranger");
    assert.equal(r.status, 403);
    assert.match(r.body, /not authorised/);
  });

  it("refuses that certificate the console too", async () => {
    assert.equal((await get("/", "stranger")).status, 403);
  });
});

describe("one-time codes on approve and publish", () => {
  // The point of this block is that the *certificate* path is covered. Requiring a code only from
  // browsers would leave the CLI as a documented way around the second factor.
  const d6 = mkdtempSync(join(tmpdir(), "hp-otp-"));
  let port6 = 0;
  let close6: () => void = () => {};
  let idpAnswer: { status: number; body: unknown } = { status: 200, body: { ok: true } };
  let asked: { userId?: string; code?: string }[] = [];

  before(async () => {
    const started = await startManager({
      port: 0, hostname: "127.0.0.1",
      relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
      tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
      operatorCNs: ["ops-alice"], writerCNs: ["ops-alice"],
      timeoutMs: 200,
      otp: {
        issuerUrl: "https://idp.example.invalid",
        serviceToken: "svc",
        users: new Map([["ops-alice", "keystone-user-1"]]),
        fetchImpl: (async (_u: string | URL, init?: RequestInit) => {
          asked.push(JSON.parse(String(init?.body ?? "{}")));
          return new Response(JSON.stringify(idpAnswer.body), { status: idpAnswer.status });
        }) as unknown as typeof fetch,
      },
    });
    port6 = (started.server.address() as { port: number }).port;
    close6 = () => started.server.close();
  });

  after(() => { close6(); rmSync(d6, { recursive: true, force: true }); });

  function post(path: string, body: unknown, headers: Record<string, string> = {}) {
    const payload = JSON.stringify(body);
    return new Promise<{ status: number; body: string }>((resolve, reject) => {
      const r = request({
        host: "127.0.0.1", port: port6, path, method: "POST",
        ca: [readCa()], cert: read("ops.pem"), key: read("ops.key"),
        headers: { "content-type": "application/json", ...headers },
      }, (res) => {
        let b = ""; res.on("data", (d) => (b += d));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b }));
      });
      r.on("error", reject); r.write(payload); r.end();
    });
  }

  it("refuses an approval from the CLI with no code at all", async () => {
    // The whole reason this block exists.
    asked = [];
    const r = await post("/approve", { hash: "sha256:x" });
    assert.equal(r.status, 401);
    // The exact message, not just "one-time code". A missing code and a malformed one both end in
    // 401 and both mention the phrase, but they are different operator actions — one is "you did not
    // send it", the other is "what you sent is not six digits". Asserting the loose pattern let the
    // missing-code branch be deleted with the suite still green; measured.
    assert.match(r.body, /send it as .?otp.? in the request body/);
    assert.equal(asked.length, 0, "no code means nothing should reach the IdP");
  });

  it("refuses Origin: null on the certificate write path", async () => {
    // A sandboxed browser document has an opaque `null` Origin but still receives an ambient client
    // certificate. With no Origin header the CLI reaches the OTP check above; the literal browser
    // value must instead stop at the cross-site boundary.
    asked = [];
    const r = await post("/approve", { hash: "sha256:x" }, { origin: "null" });
    assert.equal(r.status, 403);
    assert.match(r.body, /cross-site/);
    assert.equal(asked.length, 0);
  });

  it("refuses a publish from the CLI with no code", async () => {
    assert.equal((await post("/publish", { hash: "sha256:x" })).status, 401);
  });

  it("sends the mapped IdP user id for a certificate caller — the known positive", async () => {
    // A certificate has no `sub`, so the mapping is what makes the check possible at all.
    asked = [];
    idpAnswer = { status: 200, body: { ok: true } };
    const r = await post("/approve", { hash: "sha256:not-a-plan", otp: "123456" });
    assert.deepEqual(asked[0], { userId: "keystone-user-1", code: "123456" });
    // The code passed; the plan lookup is what refuses this.
    assert.equal(r.status, 404, `expected the plan to be what fails, got ${r.status}: ${r.body}`);
  });

  it("refuses when the IdP says the code is wrong", async () => {
    idpAnswer = { status: 401, body: { ok: false } };
    const r = await post("/approve", { hash: "sha256:x", otp: "000000" });
    assert.equal(r.status, 401);
    assert.match(r.body, /already been used|not valid/);
  });

  it("answers 503, not 401, when the manager's own service token is refused", async () => {
    // Retyping a code will not fix this, and 401 would tell the operator it might.
    idpAnswer = { status: 401, body: "unauthorized" };
    const r = await post("/approve", { hash: "sha256:x", otp: "123456" });
    assert.equal(r.status, 503);
  });

  it("passes the IdP's rate limit through", async () => {
    idpAnswer = { status: 429, body: "slow down" };
    assert.equal((await post("/approve", { hash: "sha256:x", otp: "123456" })).status, 429);
  });

  it("says so when the account has no code enrolled", async () => {
    idpAnswer = { status: 404, body: "TOTP not enrolled" };
    const r = await post("/approve", { hash: "sha256:x", otp: "123456" });
    assert.equal(r.status, 403);
    assert.match(r.body, /enrolled/);
  });

  it("does not reach the IdP for a code that cannot be one", async () => {
    // The IdP rate limits per user; nonsense must not spend that budget.
    asked = [];
    idpAnswer = { status: 200, body: { ok: true } };
    const r = await post("/approve", { hash: "sha256:x", otp: "abc" });
    assert.equal(r.status, 401);
    assert.match(r.body, /six digits/, "a malformed code must not read as a missing one");
    assert.equal(asked.length, 0);
  });
});

describe("a writer with no IdP mapping", () => {
  it("may not approve, and is told what is missing", async (t) => {
    // The safe direction: a writer this deployment cannot identify to the IdP is one whose second
    // factor cannot be checked. Refused rather than waved through.
    const d7 = mkdtempSync(join(tmpdir(), "hp-otp2-"));
    const started = await startManager({
      port: 0, hostname: "127.0.0.1",
      relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
      tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
      operatorCNs: ["ops-alice"], writerCNs: ["ops-alice"],
      timeoutMs: 200,
      otp: {
        issuerUrl: "https://idp.example.invalid", serviceToken: "svc",
        users: new Map(), // ops-alice is deliberately absent
        fetchImpl: (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch,
      },
    });
    t.after(() => started.server.close());
    const p = (started.server.address() as { port: number }).port;
    const r = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const q = request({
        host: "127.0.0.1", port: p, path: "/approve", method: "POST",
        ca: [readCa()], cert: read("ops.pem"), key: read("ops.key"),
        headers: { "content-type": "application/json" },
      }, (res) => {
        let b = ""; res.on("data", (d) => (b += d));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b }));
      });
      q.on("error", reject); q.write(JSON.stringify({ hash: "sha256:x", otp: "123456" })); q.end();
    });
    assert.equal(r.status, 403);
    assert.match(r.body, /OTP user map/);
    rmSync(d7, { recursive: true, force: true });
  });
});

// ── Two certificates, one human ───────────────────────────────────────────────
//
// The exact shape of the live dev deployment, read from its Deployment on 2026-08-24:
//
//     HELIOPAUSE_WRITER_CNS = ops-henry,ops-henry-review
//     HELIOPAUSE_OTP_USERS  = ops-henry=5b1ed54b-…, ops-henry-review=5b1ed54b-…
//
// Two writer certificate names, **one identity-provider account**. `approval.ts` compared names, so
// the two-person rule passed — and the one-time code did not catch it either, because both names
// resolve to the same account and the same TOTP credential answers for both.
//
// The harm is the record. This site already permits one person to publish alone through
// `soloApprovalRoles`, and that path writes `solo: true`. Two names produced the same outcome with
// the plan claiming two people signed off.
//
// Driven end to end rather than in `approval.test.ts` alone, because the unit tests take
// `alsoKnownAs` as an argument and what could be wrong here is the wiring that derives it.
describe("two writer certificates that map to one identity-provider account", () => {
  /** The smallest bundle `validateBundle` accepts. What it renders does not matter here. */
  function sameHumanBundle() {
    const rules = JSON.stringify({
      nftables: [{ add: { rule: { family: "inet", table: "heliopause", chain: "input", comment: "BASE-SSH" } } }],
    });
    return {
      manifest: {
        generation: "gen-same",
        issuedAt: "2026-08-24T00:00:00.000Z",
        schemaVersion: SCHEMA_VERSION,
        hosts: {
          "gw-01.dev": {
            stage: "canary",
            rulesetHash: "sha256:" + createHash("sha256").update(rules).digest("hex"),
            confirmTimeoutSec: 120,
            mustContain: ["BASE-SSH"],
            expectFilters: [],
          },
        },
      },
      rulesets: { "gw-01.dev": rules },
      workload: {},
    };
  }

  const dSame = mkdtempSync(join(tmpdir(), "hp-same-human-"));
  let portSame = 0;
  let closeSame: () => void = () => {};

  before(async () => {
    const started = await startManager({
      port: 0, hostname: "127.0.0.1",
      relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
      tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
      // `ops-stranger` stands in for `ops-henry-review`: a second trusted certificate, a second
      // writer, and — below — the same person.
      operatorCNs: ["ops-alice", "ops-stranger"],
      writerCNs: ["ops-alice", "ops-stranger"],
      timeoutMs: 200,
      otp: {
        issuerUrl: "https://idp.example.invalid",
        serviceToken: "svc",
        users: new Map([["ops-alice", "one-account"], ["ops-stranger", "one-account"]]),
        fetchImpl: (async () => new Response(JSON.stringify({ ok: true }), { status: 200 })) as unknown as typeof fetch,
      },
      log: () => {},
    });
    portSame = (started.server.address() as { port: number }).port;
    closeSame = () => started.server.close();
  });

  after(() => { closeSame(); rmSync(dSame, { recursive: true, force: true }); });

  function post(path: string, body: unknown, who: "operator" | "stranger") {
    const payload = JSON.stringify(body);
    return new Promise<{ status: number; body: string }>((resolve, reject) => {
      const r = request({
        host: "127.0.0.1", port: portSame, path, method: "POST", ca: [readCa()],
        ...(who === "operator"
          ? { cert: read("ops.pem"), key: read("ops.key") }
          : { cert: read("stranger.pem"), key: read("stranger.key") }),
        headers: { "content-type": "application/json" },
      }, (res) => {
        let b = ""; res.on("data", (d) => (b += d));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b }));
      });
      r.on("error", reject); r.write(payload); r.end();
    });
  }

  it("refuses the second certificate's approval of the first's plan", async () => {
    const proposed = await post("/plan", { target: "dev", bundle: sameHumanBundle() }, "operator");
    assert.equal(proposed.status, 200, proposed.body);
    const hash = (JSON.parse(proposed.body) as { hash: string }).hash;

    const approved = await post("/approve", { hash, otp: "123456" }, "stranger");
    assert.equal(approved.status, 403, approved.body);
    // The reason has to say why two different names are one person, or it reads as the rule
    // malfunctioning and the operator goes looking at their certificate.
    assert.match(approved.body, /same person as ops-alice/);
    assert.match(approved.body, /recorded as two/);
  });
});

describe("the console can propose a plan, which is the step it could not take", () => {
  // Approve and publish existed here long before propose did, so the browser could act on a plan it
  // had no way to create and an operator had to go to a workstation for exactly one step. The reason
  // was real — proposing means rendering, and the policy repository must not be in this image — and
  // it stopped being true when the policy started arriving as JSON from a pod that holds no
  // credential.
  //
  // The renderer here is a stub serving a fixed `PolicySource`, because what is under test is the
  // manager: that it renders what it was given, refuses a checkout it cannot name, and records the
  // result through the same path the CLI's `POST /plan` uses.
  let port7 = 0;
  let close7: () => void = () => {};
  let renderer: import("node:http").Server;
  let head: { sha: string | null; dirty: boolean } = { sha: "abc1234", dirty: false };
  /**
   * What build the fake renderer claims. `same` is the truth — it runs `collectPolicySource` in this
   * process, so it genuinely is this build, which is what makes the silent case a real negative
   * rather than a banner that was never given anything to disagree with.
   */
  let rendererBuild: "same" | "different" | "absent" = "same";

  const fixture = () => ({
    // ## The baseline is not decoration in this fixture
    //
    // It read `hookPolicy.input: "drop"` with `baseline: []` until 2026-08-22 — the one combination
    // `defineConfig` refuses outright, because a host that drops by default with nothing accepted
    // first answers nothing, including the way in to undo it. The rendered artifact's only assertion
    // would be `baseline: loopback`, so the agent's `mustContain` check passes and the heartbeat
    // still reaches the relay through the output chain, and the host confirms with SSH gone.
    //
    // It rendered anyway, because `planPublish` did not re-validate what the renderer handed it.
    // Now it does, and this fixture had to gain the management path a real site would have. That it
    // did not have one is the finding, not the test breaking.
    cfg: {
      ...DEFAULT_CONFIG,
      hookPolicy: { input: "drop" as const, output: "accept" as const },
      baseline: [{ desc: "management SSH", proto: "tcp" as const, ports: "22", srcCidrs: [] }],
    },
    hosts: [{
      id: "h1",
      stage: "canary" as const,
      items: [{
        policy: {
          id: "P1", name: "n", src: { kind: "cidr", value: "198.51.100.0/24" },
          dst: { kind: "host", value: "h1" }, proto: "tcp", ports: "22",
          action: "allow", denyMode: "drop", priority: 100, enabled: true,
        },
        srcCidrs: ["198.51.100.0/24"],
        dstCidrs: ["198.51.100.1/32"],
      }],
    }],
  });

  before(async () => {
    const { createServer } = await import("node:http");
    renderer = createServer((_req, res) => {
      const source = collectPolicySource({
        site: fixture() as never, sitePath: "/nonexistent/policy/site.ts",
        label: "test-site", allowPaths: [],
      });
      const payload: Record<string, unknown> = { ...source, head };
      if (rendererBuild === "different") payload.build = "b32a7c6b32a7";
      if (rendererBuild === "absent") delete payload.build;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(payload));
    });
    await new Promise<void>((r) => renderer.listen(0, "127.0.0.1", r));
    const rendererPort = (renderer.address() as { port: number }).port;

    const started = await startManager({
      port: 0, hostname: "127.0.0.1",
      relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
      tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
      operatorCNs: ["ops-alice"], writerCNs: ["ops-alice"],
      timeoutMs: 2000,
      policySource: { url: `http://127.0.0.1:${rendererPort}` },
    });
    port7 = (started.server.address() as { port: number }).port;
    close7 = () => started.server.close();
  });

  after(() => { close7(); renderer.close(); });

  const propose = (target: unknown) => new Promise<{ status: number; body: string }>((resolve, reject) => {
    const r = request({
      host: "127.0.0.1", port: port7, path: "/policy/plan", method: "POST",
      rejectUnauthorized: false,
      cert: readFileSync(join(dir, "ops.pem")), key: readFileSync(join(dir, "ops.key")),
      headers: { "content-type": "application/json" },
    }, (res) => {
      let body = ""; res.on("data", (c) => { body += c; });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    r.on("error", reject);
    r.end(JSON.stringify({ target }));
  });

  const read = (hash: string, host: string) => new Promise<{ status: number; body: string }>((resolve, reject) => {
    const r = request({
      host: "127.0.0.1", port: port7,
      path: `/plans/${encodeURIComponent(hash)}/ruleset?host=${encodeURIComponent(host)}`,
      method: "GET", rejectUnauthorized: false,
      cert: readFileSync(join(dir, "ops.pem")), key: readFileSync(join(dir, "ops.key")),
    }, (res) => {
      let body = ""; res.on("data", (c) => { body += c; });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    r.on("error", reject); r.end();
  });

  const getPolicy = (path = "/policy") => new Promise<{ status: number; body: string; location: string }>((resolve, reject) => {
    const r = request({
      host: "127.0.0.1", port: port7, path, method: "GET",
      rejectUnauthorized: false,
      cert: readFileSync(join(dir, "ops.pem")), key: readFileSync(join(dir, "ops.key")),
    }, (res) => {
      let body = ""; res.on("data", (c) => { body += c; });
      res.on("end", () => resolve({
        status: res.statusCode ?? 0,
        body,
        location: typeof res.headers.location === "string" ? res.headers.location : "",
      }));
    });
    r.on("error", reject); r.end();
  });

  const getPolicyScreen = () => new Promise<{ status: number; body: string }>((resolve, reject) => {
    const r = request({
      host: "127.0.0.1", port: port7, path: "/api/policy/screen", method: "GET",
      rejectUnauthorized: false,
      cert: readFileSync(join(dir, "ops.pem")), key: readFileSync(join(dir, "ops.key")),
    }, (res) => {
      let body = ""; res.on("data", (c) => { body += c; });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    r.on("error", reject); r.end();
  });

  it("answers the policy tables as JSON, not as the HTML page", async () => {
    head = { sha: "abc1234", dirty: false };
    const r = await getPolicyScreen();
    assert.equal(r.status, 200, r.body);
    const body = JSON.parse(r.body) as { rows?: unknown; extra?: unknown; generation?: unknown };
    assert.ok(Array.isArray(body.rows), "the screen payload has no policy rows");
    assert.equal(typeof body.extra, "object");
    assert.equal(body.generation, "abc1234");
    assert.doesNotMatch(r.body, /<!doctype html/i);
  });

  it("says it could not check freshness when it has no repository credential", async () => {
    // This harness configures no `policyWrite`, so the question cannot be put. The screen must say
    // that rather than stay quiet: "could not check" and "checked, fine" are the same silence, and
    // the silence is what let the policy screen sit eleven hours behind on 2026-08-16.
    head = { sha: "abc1234", dirty: false };
    const r = await getPolicyScreen();
    assert.equal(r.status, 200, r.body);
    const body = JSON.parse(r.body) as { freshness?: { state?: string; why?: string } };
    assert.equal(body.freshness?.state, "unknown", "the payload said nothing about whether it was current");
    assert.equal(typeof body.freshness?.why, "string");
  });

  it("says when the policy renderer is not the build this console is", async () => {
    // The manager and the renderer are separate Deployments and nothing keeps them in step: the
    // deploy pipeline rewrites one manifest per component directory, and the renderer's manifest is
    // a second file inside the manager's. Measured 2026-08-18 — manager `3e1c248`, renderer eleven
    // commits behind, and every instrument green because everything below this line was correct.
    rendererBuild = "different";
    const r = await getPolicyScreen();
    assert.equal(r.status, 200, r.body);
    const body = JSON.parse(r.body) as { renderer?: { build?: string | null; mine?: string } };
    assert.equal(body.renderer?.build, "b32a7c6b32a7", "it did not name the renderer's build");
    assert.notEqual(body.renderer?.build, body.renderer?.mine);
  });

  it("says so when the renderer is too old to name itself", async () => {
    // Absent is not agreement. Every renderer deployed before this field existed omits it, and that
    // omission is a lower bound on how far behind it is.
    rendererBuild = "absent";
    const r = await getPolicyScreen();
    assert.equal(r.status, 200, r.body);
    const body = JSON.parse(r.body) as { renderer?: { build?: string | null } };
    assert.equal(body.renderer?.build ?? null, null);
  });

  it("stays quiet when the renderer really is this build", async () => {
    // 🔑 The known negative. The fake renderer builds its payload in this process, so it is this
    // build — and the page must say nothing. Without this the two assertions above are satisfied by
    // a banner that is always on, which is the state that let the real drift go unread.
    rendererBuild = "same";
    const r = await getPolicyScreen();
    assert.equal(r.status, 200, r.body);
    const body = JSON.parse(r.body) as { renderer?: { build?: string | null; mine?: string } };
    assert.ok(body.renderer?.mine);
    assert.equal(body.renderer?.build, body.renderer?.mine);
  });

  const lookup = (q: string) => new Promise<{ status: number; body: string }>((resolve, reject) => {
    const r = request({
      host: "127.0.0.1", port: port7, path: `/policy/lookup?${q}`, method: "GET",
      rejectUnauthorized: false,
      cert: readFileSync(join(dir, "ops.pem")), key: readFileSync(join(dir, "ops.key")),
    }, (res) => {
      let body = ""; res.on("data", (c) => { body += c; });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    r.on("error", reject); r.end();
  });

  const changes = (hash: string) => new Promise<{ status: number; body: string }>((resolve, reject) => {
    const r = request({
      host: "127.0.0.1", port: port7, path: `/plans/${encodeURIComponent(hash)}/changes`, method: "GET",
      rejectUnauthorized: false,
      cert: readFileSync(join(dir, "ops.pem")), key: readFileSync(join(dir, "ops.key")),
    }, (res) => {
      let body = ""; res.on("data", (c) => { body += c; });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    r.on("error", reject); r.end();
  });

  it("says why it cannot show what changed, rather than showing nothing", async () => {
    // The branch that matters most. An approver shown an empty box concludes nothing changed, and
    // this control exists so the second person can see what they are agreeing to — a silent failure
    // here is worse than no button, because it answers the question wrongly instead of not at all.
    //
    // This harness has no repository credential, so the honest answer is that it cannot compare.
    head = { sha: "abc1234", dirty: false };
    const p = await propose("dev");
    assert.equal(p.status, 200, p.body);
    const r = await changes(JSON.parse(p.body).hash);
    assert.equal(r.status, 200, r.body);
    const body = JSON.parse(r.body);
    assert.ok(body.unavailable, "it returned no diff and no reason for the absence");
    assert.equal(body.files, undefined);
  });

  it("refuses a malformed plan hash rather than reaching for a repository", async () => {
    const r = await changes("not-a-hash");
    assert.equal(r.status, 400);
  });

  it("does not compare a plan it is not holding", async () => {
    const r = await changes(`sha256:${"0".repeat(64)}`);
    assert.equal(r.status, 404);
  });

  it("answers which declared rules name a flow, and stamps the answer with a generation", async () => {
    // The known positive for the whole lookup: it reads the same policy the screen draws, so the two
    // cannot disagree about which rules exist. The generation travels with the result because an
    // answer read an hour later against a policy that has moved is the same failure as a screen that
    // will not say how old it is.
    head = { sha: "abc1234", dirty: false };
    const r = await lookup("src=10.0.0.5&dst=10.0.0.6&port=443&proto=tcp");
    assert.equal(r.status, 200, r.body);
    const body = JSON.parse(r.body);
    assert.equal(body.generation, "abc1234");
    assert.ok(Array.isArray(body.matches) && Array.isArray(body.undecidable), "both lists must be present");
    assert.equal(typeof body.considered, "number");
  });

  const whereUsedCall = (q: string) => new Promise<{ status: number; body: string }>((resolve, reject) => {
    const r = request({
      host: "127.0.0.1", port: port7, path: `/policy/where-used?q=${encodeURIComponent(q)}`, method: "GET",
      rejectUnauthorized: false,
      cert: readFileSync(join(dir, "ops.pem")), key: readFileSync(join(dir, "ops.key")),
    }, (res) => {
      let body = ""; res.on("data", (c) => { body += c; });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    r.on("error", reject); r.end();
  });

  it("says there is no traffic reader rather than showing an empty table", async () => {
    // "No reader" and "no traffic" are opposite findings and this harness configures no reader, so
    // the honest answer is a 404 the screen turns into a sentence. An empty summary here would tell
    // an operator their allows carry nothing, which is the strongest claim this feature can make and
    // the last one it should make by accident.
    const r = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const q = request({
        host: "127.0.0.1", port: port7, path: "/workload-traffic", method: "GET",
        rejectUnauthorized: false,
        cert: readFileSync(join(dir, "ops.pem")), key: readFileSync(join(dir, "ops.key")),
      }, (res) => {
        let body = ""; res.on("data", (c) => { body += c; });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      });
      q.on("error", reject); q.end();
    });
    assert.equal(r.status, 404);
    assert.match(r.body, /no traffic reader/);
  });

  it("answers where a value is written, and says what it read", async () => {
    head = { sha: "abc1234", dirty: false };
    const r = await whereUsedCall("10.0.0.0/8");
    assert.equal(r.status, 200, r.body);
    const b = JSON.parse(r.body);
    assert.equal(b.generation, "abc1234");
    assert.ok(Array.isArray(b.usages) && Array.isArray(b.repeated));
    assert.equal(typeof b.considered, "number");
  });

  it("returns the naming candidates even when nothing was searched for", async () => {
    // The repeated-literal list does not depend on the query, and an operator arriving at this screen
    // should see the case for naming before they think of something to type.
    const r = await whereUsedCall("");
    assert.equal(r.status, 200);
    const b = JSON.parse(r.body);
    assert.deepEqual(b.usages, [], "an empty query matched something");
    assert.ok(Array.isArray(b.repeated));
  });

  it("refuses a port that is not a port rather than treating it as none", async () => {
    // `Number("http")` is NaN and `Number("")` is 0; either one silently becomes "any port", which
    // turns a typo into a broader answer than the operator asked for.
    for (const q of ["port=http", "port=0", "port=70000", "port=-1"]) {
      const r = await lookup(`src=10.0.0.5&${q}`);
      assert.equal(r.status, 400, `${q} was accepted`);
    }
  });

  it("refuses a protocol it does not model", async () => {
    const r = await lookup("proto=sctp");
    assert.equal(r.status, 400);
  });

  it("sends the HTML policy screen to /app/policy", async () => {
    // The manager used to render `policyPage` here. `/app/policy` is the console now; this
    // path keeps bookmarks and the classic sidenav. The data routes under `/policy/…` are
    // a different path and must not follow.
    head = { sha: "abc1234", dirty: false };
    const r = await getPolicy();
    assert.equal(r.status, 302, r.body);
    assert.equal(r.location, "/app/policy");
  });

  it("keeps ?s= as a path under /app/policy", async () => {
    head = { sha: "abc1234", dirty: false };
    const files = await getPolicy("/policy?s=files");
    assert.equal(files.location, "/app/policy/files");
    const all = await getPolicy("/policy?s=all");
    assert.equal(all.location, "/app/policy/all");
  });

  it("does not turn ?s= into an open path", async () => {
    head = { sha: "abc1234", dirty: false };
    const r = await getPolicy("/policy?s=../secret");
    assert.equal(r.status, 302);
    assert.equal(r.location, "/app/policy");
  });

  it("renders the policy it was handed and records a plan", async () => {
    head = { sha: "abc1234", dirty: false };
    const r = await propose("dev");
    assert.equal(r.status, 200, r.body);
    const plan = JSON.parse(r.body);
    // The generation names the commit the renderer reported — not something the browser chose.
    assert.equal(plan.generation, "abc1234");
    assert.match(plan.hash, /^sha256:[0-9a-f]{64}$/);
    assert.equal(plan.proposedBy, "ops-alice");
  });

  it("refuses a checkout it cannot name, and says which state it is in", async () => {
    // A generation *is* a commit id. `heliopause-publish` refuses both of these for the same reason;
    // the read-only screen tolerates them because a label is not a name.
    head = { sha: "abc1234", dirty: true };
    const dirty = await propose("dev");
    assert.equal(dirty.status, 409);
    assert.match(dirty.body, /uncommitted edits/);

    head = { sha: null, dirty: false };
    const unknown = await propose("dev");
    assert.equal(unknown.status, 409);
    assert.match(unknown.body, /does not report a commit/);
  });

  it("serves the rules an approver is being asked to approve, tied to their digest", async () => {
    // Approving was a comparison of a count and a digest — a check against tampering in transit and
    // no check on what the rules say. The two-person rule rests on the second person reading
    // something the first could not choose, and there was nothing to read.
    head = { sha: "abc1234", dirty: false };
    const proposed = JSON.parse((await propose("dev")).body);
    const host = proposed.summary.hosts[0].host;

    const r = await read(proposed.hash, host);
    assert.equal(r.status, 200, r.body);
    const got = JSON.parse(r.body);
    assert.equal(got.host, host);
    assert.equal(got.rulesetHash, proposed.summary.hosts[0].rulesetHash);

    // **The bytes are the ones the digest covers.** A route that served a fresh render of the same
    // policy would look identical here and be a different artifact from the one that lands.
    const digest = "sha256:" + createHash("sha256").update(got.ruleset).digest("hex");
    assert.equal(digest, got.rulesetHash, "what is read must hash to what is approved");
    // Not empty, and actually the ruleset: without this the two assertions above pass on "".
    assert.match(got.ruleset, /nftables/);
  });

  it("refuses a host or a plan it does not carry", async () => {
    head = { sha: "abc1234", dirty: false };
    const proposed = JSON.parse((await propose("dev")).body);
    assert.equal((await read(proposed.hash, "not-a-host")).status, 404);
    assert.equal((await read("sha256:" + "0".repeat(64), "h1")).status, 404);
  });

  it("refuses a target this manager does not know", async () => {
    head = { sha: "abc1234", dirty: false };
    const r = await propose("not-a-vpc");
    assert.equal(r.status, 400);
    assert.match(r.body, /unknown target/);
  });
});

describe("the data routes answer under /api/ as well", () => {
  // ## Step one of three
  //
  // Screens and data grew into one namespace. `/policy` is a screen and the stem of five data
  // routes; `/enrollment` is a screen and the stem of four. `manager-ui.ts` records what that cost:
  // the `/changes` screen reads `/plans` and **could not be named `/plans`**, because the data had
  // the name. The screens have been picking names around the API ever since.
  //
  // Additive first because four binaries and two rendered pages call these paths while **the fleet
  // runs a deployed manager image**. An old CLI meeting a new server fails as a 404 that reads like
  // an outage. The top-level paths come out only after every deployed caller is on the new image —
  // a third step this repository has not taken.

  it("serves the same answer at /api/authz as at /authz", async () => {
    const bare = await get("/authz", "operator");
    const prefixed = await get("/api/authz", "operator");
    assert.equal(prefixed.status, bare.status);
    assert.equal(prefixed.body, bare.body);
  });

  it("keeps the certificate check on the prefixed path", async () => {
    // The rewrite changes the path and nothing else. A route that authenticated at `/x` but not at
    // `/api/x` is the worst outcome available here, and it is one line away — putting the rewrite
    // after the certificate check instead of before it.
    assert.equal((await get("/api/authz", "none")).status, 401);
    assert.equal((await get("/api/authz", "stranger")).status, 403);
  });

  it("does not serve screens under the prefix", async () => {
    // 🔑 The negative control. A blanket `startsWith("/api/")` strip would make `/api/fleet` render
    // the console and `/api/policy` render the policy page — new addresses for screens, the opposite
    // of what this change is for. Only the named set is rewritten.
    for (const screen of ["/fleet", "/changes", "/policy"]) {
      const r = await get(`/api${screen}`, "operator");
      assert.equal(r.status, 404, `/api${screen} answered ${r.status}; screens must not gain an /api address`);
    }
  });

  it("names every route the server has, so a new one cannot be forgotten", () => {
    // The honesty check, in the shape `manager-ui.test.ts` already uses for its exemption list. A
    // route added without a line in `API_ROUTES` silently has no alias, and the collision this
    // change exists to end quietly continues for it.
    const code = readFileSync(new URL("./manager-server.ts", import.meta.url), "utf8")
      .split("\n").filter((l) => !/^\s*\/\//.test(l)).join("\n")
      .replace(/\/\*[\s\S]*?\*\//g, "");
    const served = new Set([...code.matchAll(/url\.pathname === "([^"]+)"/g)].map((m) => m[1]!));
    // ⚠️ **Both dispatch shapes.** The first version of this test read only `=== "…"`, so the six
    // routes matched by regex were invisible to it — including four the console fetches. The alias
    // would have covered none of them and the callers would have been moved onto 404s. A check that
    // reads one of two shapes reports "everything is accounted for" about half the file.
    //
    // Counted rather than parsed. Comparing regex *sources* to the alias list means normalising two
    // spellings of the same shape, and that machinery is more likely to be wrong than the thing it
    // checks. A count forces the same decision: add a regex route and this fails until it is either
    // aliased or written down as not-data.
    const regexRoutes = [...code.matchAll(/\.exec\(url\.pathname\)/g)].length;
    const NOT_DATA_REGEX = 1;   // /infra/node-csrs/<name>/certificate — an agent fetches its own
    assert.equal(
      regexRoutes, API_ROUTE_PATTERNS.length + NOT_DATA_REGEX,
      `the server dispatches ${regexRoutes} routes by shape; API_ROUTE_PATTERNS covers ` +
        `${API_ROUTE_PATTERNS.length} and ${NOT_DATA_REGEX} is external. A new one needs a line in ` +
        `one column or the other.`,
    );
    // Named, not pattern-matched: each says why it is not data. A blanket allowance is how the next
    // one hides.
    const NOT_DATA: Record<string, string> = {
      "/": "the console shell",
      "/ui": "a 301 to the shell",
      "/policy": "a 302 to /app/policy — the HTML page moved",
      "/healthz": "the kubelet probe — unauthenticated by design",
      "/auth/login": "a browser navigation to the identity provider",
      "/auth/callback": "the identity provider redirects the browser here",
      "/auth/logout": "a browser navigation",
      "/auth/backchannel-logout": "the identity provider posts here; not a caller of ours",
      // Found by this test, not by the hand-written list above it — which is the argument for
      // having it. The IdP posts a signed Security Event Token here and the signature is the
      // authentication; it holds no session and no certificate. Same class as the line above.
      "/auth/role-change": "the identity provider posts a signed SET here",
      "/infra/node-csrs": "an external contract — agents post here through node-enroll.tinyuniver.se",
    };
    const missing = [...served].filter((p) => !API_ROUTES.has(p) && !(p in NOT_DATA)).sort();
    assert.deepEqual(missing, [], `these routes are neither aliased nor explained: ${missing.join(", ")}`);
  });
});

// ── The bound on the certificate-less enrollment routes ───────────────────────
//
// What is being limited is not "requests" in the abstract: both routes read and parse the whole
// enrollment store synchronously, and one takes the `O_EXCL` lock via `Atomics.wait` — also
// synchronously. Each admitted request is a slice of the event loop during which nothing else is
// served. Pure and clock-injected, so the window can be crossed without waiting a minute.
describe("the enrollment rate limiter", () => {
  const fresh = () => new Map<string, { windowStartedAt: number; count: number }>();

  it("admits up to the limit and refuses past it", () => {
    const seen = fresh();
    for (let i = 0; i < 5; i++) {
      assert.equal(rateLimited(seen, "10.0.0.1", 1_000, 5, 60_000), false, `request ${i + 1} refused`);
    }
    assert.equal(rateLimited(seen, "10.0.0.1", 1_000, 5, 60_000), true);
  });

  it("counts each source separately", () => {
    // A busy host must not lock out the rest of the fleet enrolling at the same time.
    const seen = fresh();
    for (let i = 0; i < 6; i++) rateLimited(seen, "10.0.0.1", 1_000, 5, 60_000);
    assert.equal(rateLimited(seen, "10.0.0.2", 1_000, 5, 60_000), false);
  });

  it("forgives once the window has passed", () => {
    // A real agent polls for its certificate for as long as signing takes. A limiter that never
    // resets would turn a slow operator into a host that can never enrol.
    const seen = fresh();
    for (let i = 0; i < 6; i++) rateLimited(seen, "10.0.0.1", 1_000, 5, 60_000);
    assert.equal(rateLimited(seen, "10.0.0.1", 1_000 + 60_000, 5, 60_000), false);
  });

  it("bounds how many sources it remembers, dropping the oldest window", () => {
    // Otherwise the limiter is itself the memory leak: one entry per source address, and the
    // addresses are chosen by whoever is calling.
    const seen = fresh();
    for (let i = 0; i < 10; i++) rateLimited(seen, `10.0.0.${i}`, 1_000 + i, 5, 60_000, 4);
    assert.equal(seen.size, 4);
    assert.equal(seen.has("10.0.0.9"), true, "the newest source must survive eviction");
    assert.equal(seen.has("10.0.0.0"), false, "the oldest must not");
  });
});
