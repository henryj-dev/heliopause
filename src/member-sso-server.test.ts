// SSO for members, against a real TLS manager: linking an SSO account to a member, signing in with
// it (and the writer's one-time-code step that follows), unlinking, `HELIOPAUSE_MEMBERS=on`,
// certificates bound to a member, and member solo approval.
//
// The fake IdP signs whatever `mint` holds at the moment of the token request, so each case sets the
// subject, email and groups it wants the IdP to assert. The manager's member clock is shifted forward
// a minute before each sign-in so the per-address limit (10 a minute) does not leak between cases.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:https";
import { execFileSync } from "node:child_process";
import { createHash, createSign, generateKeyPairSync, randomUUID } from "node:crypto";
import { startManager } from "./manager-server.ts";
import { SCHEMA_VERSION } from "./protocol.ts";
import {
  confirmOtp, createMember, deleteMember, initializeMemberDocument, linkIdentity, loadMemberDocument, setOtpUserId, setPassword,
  suspendMember, unsuspendMember, withMemberTransaction, type MemberRole,
} from "./member-store.ts";
import { hashPassword } from "./password.ts";
import { CSRF_HEADER } from "./session.ts";
import { BACKCHANNEL_LOGOUT_EVENT } from "./set.ts";

const ISSUER = "https://idp.example.invalid";
const PASSWORD = "Correct horse battery staple";
const GOOD_OTP = "123456";

const dir = mkdtempSync(join(tmpdir(), "hp-member-sso-"));
const read = (f: string) => readFileSync(join(dir, f));

function pki() {
  const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=test-ca");
  for (const [name, eku, cn] of [["server", "serverAuth", "manager"], ["ops", "clientAuth", "ops-alice"], ["bob", "clientAuth", "ops-bob"]] as const) {
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", `/CN=${cn}`);
    writeFileSync(join(dir, `${name}.ext`), `extendedKeyUsage=critical,${eku}\n` + (name === "server" ? "subjectAltName=IP:127.0.0.1\n" : ""));
    run("x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", `${name}.pem`, "-days", "1", "-extfile", `${name}.ext`);
  }
}

/** KeyStone's verify endpoint: GOOD_OTP is right for every user. `duringOtp`, when set, runs before the verdict. */
const otpCalls: Array<{ userId: string; code: string }> = [];
let duringOtp: (() => void) | null = null;
const otpFetch = (async (_u: string | URL, init?: { body?: string }) => {
  const body = JSON.parse(String(init?.body ?? "{}")) as { userId: string; code: string };
  otpCalls.push(body);
  duringOtp?.();
  return body.code === GOOD_OTP
    ? new Response(JSON.stringify({ ok: true }), { status: 200 })
    : new Response(JSON.stringify({ ok: false }), { status: 401 });
}) as unknown as typeof fetch;

const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jws = (header: Record<string, unknown>, payload: Record<string, unknown>): string => {
  const h = b64(header); const p = b64(payload);
  const sig = createSign("sha256").update(`${h}.${p}`).sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return `${h}.${p}.${sig}`;
};
/** What the IdP asserts at the next token request. */
const mint = { sub: "nobody", email: "nobody@example.invalid", groups: [] as string[], nonce: "" };
const idp = (async (u: string | URL) => {
  const url = String(u);
  if (url.endsWith("/.well-known/openid-configuration")) {
    return new Response(JSON.stringify({
      issuer: ISSUER, authorization_endpoint: `${ISSUER}/oidc/authorize`, token_endpoint: `${ISSUER}/oidc/token`,
      jwks_uri: `${ISSUER}/oidc/jwks`, code_challenge_methods_supported: ["S256"],
    }), { status: 200 });
  }
  if (url.endsWith("/oidc/jwks")) {
    return new Response(JSON.stringify({ keys: [{ ...publicKey.export({ format: "jwk" }), kid: "k1", use: "sig", alg: "ES256" }] }), { status: 200 });
  }
  const t = Math.floor(Date.now() / 1000);
  const idToken = jws({ alg: "ES256", kid: "k1", typ: "JWT" }, {
    iss: ISSUER, aud: "heliopause-manager", sub: mint.sub, nonce: mint.nonce, exp: t + 300, iat: t,
    email: mint.email, email_verified: true, groups: mint.groups,
  });
  return new Response(JSON.stringify({ id_token: idToken }), { status: 200 });
}) as unknown as typeof fetch;

let skewMs = 0;
const clock = () => new Date(Date.now() + skewMs);

type Started = { port: number; close: () => void };
async function start(store: string, mode: "shadow" | "on", extra: Partial<Parameters<typeof startManager>[0]> = {}): Promise<Started> {
  const started = await startManager({
    port: 0, hostname: "127.0.0.1",
    relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
    tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
    operatorCNs: ["ops-alice", "ops-bob"], writerCNs: ["ops-alice", "ops-bob"],
    timeoutMs: 200,
    oidc: {
      issuer: ISSUER, clientId: "heliopause-manager",
      redirectUri: "https://heliopause.example.invalid/auth/callback", roleChangeEvent: "https://idp.example.invalid/event/role-change",
      operatorGroups: ["heliopause-operators"], writerGroups: ["heliopause-writers"],
      aliases: new Map([["sub-alias", "ops-alice"]]), fetchImpl: idp,
    },
    otp: { issuerUrl: "https://otp.example.invalid", serviceToken: "svc", users: new Map([["ops-alice", "ks-cert-alice"], ["ops-bob", "ks-cert-bob"]]), fetchImpl: otpFetch },
    members: { mode, storeFile: store },
    now: clock,
    log: () => {},
    ...extra,
  });
  return {
    port: (started.server.address() as { port: number }).port,
    close: () => { started.stopProblemWatch(); started.server.closeAllConnections(); started.server.close(); },
  };
}

interface Reply { status: number; body: Record<string, unknown>; setCookie: string[]; location: string | undefined }
function call(port: number, method: string, path: string, o: {
  body?: unknown; cookie?: string; csrf?: string; origin?: string | null; cert?: "ops" | "bob"; headers?: Record<string, string>;
} = {}): Promise<Reply> {
  const payload = o.body === undefined ? undefined : JSON.stringify(o.body);
  const headers: Record<string, string> = {
    ...(o.origin === null ? {} : { origin: o.origin ?? `https://127.0.0.1:${port}` }),
    ...(payload !== undefined ? { "content-type": "application/json", "content-length": String(Buffer.byteLength(payload)) } : {}),
    ...(o.cookie ? { cookie: o.cookie } : {}),
    ...(o.csrf ? { [CSRF_HEADER]: o.csrf } : {}),
    ...o.headers,
  };
  return new Promise((resolve, reject) => {
    const r = request({
      host: "127.0.0.1", port, path, method, ca: [read("ca.pem")], headers, agent: false,
      ...(o.cert ? { cert: read(`${o.cert}.pem`), key: read(`${o.cert}.key`) } : {}),
      signal: AbortSignal.timeout(10_000),
    }, (res) => {
      let b = ""; res.on("data", (d) => (b += d));
      res.on("end", () => {
        let body: Record<string, unknown> = {};
        try { body = JSON.parse(b) as Record<string, unknown>; } catch { body = { raw: b }; }
        resolve({
          status: res.statusCode ?? 0, body, location: res.headers.location,
          setCookie: ([] as string[]).concat((res.headers["set-cookie"] as string[]) ?? []),
        });
      });
    });
    r.on("error", reject);
    if (payload !== undefined) r.write(payload);
    r.end();
  });
}

const cookieNamed = (r: Reply, name: string): string | null => {
  const c = r.setCookie.find((x) => x.startsWith(`${name}=`) && !x.startsWith(`${name}=;`));
  return c ? c.split(";")[0]! : null;
};
const sessionCookie = (r: Reply): string => {
  const c = cookieNamed(r, "__Host-heliopause-session");
  assert.ok(c, `no session cookie in ${JSON.stringify(r.setCookie)}`);
  return c;
};

async function seed(store: string, username: string, roles: MemberRole[], o: { otpUserId?: string; certCNs?: string[]; password?: boolean } = {}): Promise<string> {
  const hash = await hashPassword(PASSWORD);
  return withMemberTransaction(store, (d) => {
    const m = createMember(d, {
      username, email: `${username}@example.com`, emailVerified: true, status: "active", roles,
      otpUserId: o.otpUserId ?? null, ...(o.certCNs ? { certCNs: o.certCNs } : {}),
    }, { actor: "cli" });
    if (o.password !== false) setPassword(d, m.id, hash, { mustChange: false }, { actor: "cli" });
    if (o.otpUserId) confirmOtp(d, m.id, o.otpUserId, { actor: "cli" });
    return m.id;
  });
}

interface Login { cookie: string; csrf: string }
async function login(port: number, username: string, otp?: string): Promise<Login> {
  skewMs += 61_000;
  const r = await call(port, "POST", "/auth/password/login", { body: { username, password: PASSWORD, ...(otp ? { otp } : {}) } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return { cookie: sessionCookie(r), csrf: String(r.body.csrf) };
}

/** The IdP's half of a login: authenticate as `as`, come back to the callback with the binder. */
async function viaIdp(port: number, started: { location: string; binder: string }, as: Partial<typeof mint>): Promise<Reply> {
  const q = new URL(started.location).searchParams;
  Object.assign(mint, { email: `${as.sub}@idp.example.invalid`, groups: [] }, as, { nonce: q.get("nonce")! });
  return call(port, "GET", `/auth/callback?code=any&state=${encodeURIComponent(q.get("state")!)}`, { origin: null, cookie: started.binder });
}
/** `GET /auth/login`, then the IdP. */
async function sso(port: number, as: Partial<typeof mint>, path = "/auth/login", bump = true): Promise<Reply> {
  if (bump) skewMs += 61_000;
  const r = await call(port, "GET", path, { origin: null });
  assert.equal(r.status, 302, JSON.stringify(r.body));
  return viaIdp(port, { location: r.location!, binder: cookieNamed(r, "__Host-heliopause-login")! }, as);
}
async function linkStart(port: number, s: Login, body: Record<string, unknown> = { password: PASSWORD }): Promise<Reply> {
  return call(port, "POST", "/auth/link/start", { cookie: s.cookie, csrf: s.csrf, body });
}
async function link(port: number, s: Login, as: Partial<typeof mint>, body?: Record<string, unknown>): Promise<Reply> {
  const r = await linkStart(port, s, body);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return viaIdp(port, { location: String(r.body.location), binder: cookieNamed(r, "__Host-heliopause-login")! }, as);
}
/** A writer's or admin's SSO sign-in through its one-time-code step. */
async function ssoWithCode(port: number, as: Partial<typeof mint>): Promise<Login> {
  const cb = await sso(port, as);
  assert.equal(cb.status, 302, JSON.stringify(cb.body));
  assert.match(String(cb.location), /^\/app\/login\?sso=otp/);
  const pending = cookieNamed(cb, "__Host-heliopause-sso");
  assert.ok(pending, JSON.stringify(cb.setCookie));
  const r = await call(port, "POST", "/auth/sso/otp", { cookie: pending, body: { otp: GOOD_OTP } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return { cookie: sessionCookie(r), csrf: String(r.body.csrf) };
}
const identitiesOf = (store: string, memberId: string) => loadMemberDocument(store).identities.filter((i) => i.memberId === memberId);

function bundle(generation: string) {
  const rules = JSON.stringify({ nftables: [{ add: { rule: { family: "inet", table: "heliopause", chain: "input", comment: "BASE-SSH" } } }] });
  return {
    manifest: {
      generation, issuedAt: "2026-08-24T00:00:00.000Z", schemaVersion: SCHEMA_VERSION,
      hosts: { "gw-01.dev": { stage: "canary", rulesetHash: "sha256:" + createHash("sha256").update(rules).digest("hex"), confirmTimeoutSec: 120, mustContain: ["BASE-SSH"], expectFilters: [] } },
    },
    rulesets: { "gw-01.dev": rules }, workload: {},
  };
}
const propose = async (port: number, by: Login | "ops" | "bob", generation: string): Promise<string> => {
  const body = { target: "dev", bundle: bundle(generation) };
  const r = typeof by === "string"
    ? await call(port, "POST", "/plan", { cert: by, origin: null, body })
    : await call(port, "POST", "/plan", { cookie: by.cookie, csrf: by.csrf, body });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return String(r.body.hash);
};

const store = join(dir, "members.json");
let main: Started;
const ids: Record<string, string> = {};

before(async () => {
  pki();
  initializeMemberDocument(store);
  ids.root = await seed(store, "root", ["reader", "writer", "admin"], { otpUserId: "ks-root" });
  ids.rita = await seed(store, "rita", ["reader"]);
  ids.wade = await seed(store, "wade", ["reader", "writer"], { otpUserId: "ks-wade" });
  ids.erin = await seed(store, "erin", ["reader"]);
  ids.bobby = await seed(store, "bobby", ["reader", "writer"], { otpUserId: "ks-bobby", certCNs: ["ops-bob"] });
  ids.vera = await seed(store, "vera", ["reader"]);
  ids.nopw = await seed(store, "nopw", ["reader"], { password: false });
  ids.gone = await seed(store, "gone", ["reader"]);
  withMemberTransaction(store, (d) => {
    linkIdentity(d, { memberId: ids.nopw!, issuer: ISSUER, subject: "sub-nopw" }, { actor: "cli" });
    linkIdentity(d, { memberId: ids.gone!, issuer: ISSUER, subject: "sub-gone" }, { actor: "cli" });
    deleteMember(d, ids.gone!, { actor: "cli" });
  });
  main = await start(store, "shadow");
});

after(() => {
  main?.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("linking an SSO account", () => {
  it("a member links an SSO account and then signs in with it", async () => {
    const rita = await login(main.port, "rita");
    // No group claims at all: linking and signing in read the member record, never the IdP's groups.
    const linked = await link(main.port, rita, { sub: "sub-rita", groups: [] });
    assert.deepEqual([linked.status, linked.location], [302, "/app/account?link=ok"]);
    assert.ok(linked.setCookie.some((c) => c.startsWith("__Host-heliopause-login=;")), "the binder is cleared");
    assert.deepEqual(identitiesOf(store, ids.rita!).map((i) => [i.issuer, i.subject, i.linkedBy]), [[ISSUER, "sub-rita", ids.rita]]);

    const signedIn = await sso(main.port, { sub: "sub-rita", groups: [] });
    assert.deepEqual([signedIn.status, signedIn.location], [302, "/"]);
    const cookie = sessionCookie(signedIn);
    const authz = await call(main.port, "GET", "/api/authz", { cookie, origin: null });
    assert.deepEqual([authz.status, authz.body.via, authz.body.you, authz.body.canWrite], [200, "sso", "rita", false]);
    const me = await call(main.port, "GET", "/api/me", { cookie, origin: null });
    assert.equal(me.status, 200, JSON.stringify(me.body));
    const shown = me.body.identities as Array<Record<string, unknown>>;
    assert.deepEqual(shown.map((i) => [i.issuer, i.subject]), [[ISSUER, "…rita"]]);
    assert.equal(JSON.stringify(me.body).includes("sub-rita"), false, "the subject is shown masked");
  });

  it("link start needs the current password, and a writer's code", async () => {
    const rita = await login(main.port, "rita");
    assert.equal((await linkStart(main.port, rita, { password: "not it" })).status, 403);
    assert.equal((await call(main.port, "POST", "/auth/link/start", { cookie: rita.cookie, body: { password: PASSWORD } })).status, 403, "no CSRF token");
    assert.equal((await call(main.port, "POST", "/auth/link/start", { cookie: rita.cookie, csrf: rita.csrf, origin: "https://evil.example", body: { password: PASSWORD } })).status, 403);
    assert.equal((await call(main.port, "POST", "/auth/link/start", { origin: undefined, body: { password: PASSWORD } })).status, 403, "no session");
    const wade = await login(main.port, "wade", GOOD_OTP);
    const noCode = await linkStart(main.port, wade);
    assert.equal(noCode.status, 401, JSON.stringify(noCode.body));
    const withCode = await linkStart(main.port, wade, { password: PASSWORD, otp: GOOD_OTP });
    assert.equal(withCode.status, 200, JSON.stringify(withCode.body));
    assert.match(String(withCode.body.location), /^https:\/\/idp\.example\.invalid\/oidc\/authorize\?/);
    // An SSO session cannot start a link: it would bind an identity without the password.
    const viaSso = await sso(main.port, { sub: "sub-rita" });
    const ssoSession = { cookie: sessionCookie(viaSso), csrf: String((await call(main.port, "GET", "/api/me", { cookie: sessionCookie(viaSso), origin: null })).body.csrf) };
    const refused = await linkStart(main.port, ssoSession);
    assert.equal(refused.status, 403, JSON.stringify(refused.body));
    assert.match(String(refused.body.error), /password session/);
  });

  it("a link callback re-reads the session that started it", async () => {
    const vera = await login(main.port, "vera");
    const started = await linkStart(main.port, vera);
    assert.equal(started.status, 200, JSON.stringify(started.body));
    // Direct store edit: unlike the API password route, this cannot proactively end the session.
    // The callback itself has to notice the credential revision changed during the IdP round trip.
    const replacement = await hashPassword("Another correct horse 2!");
    withMemberTransaction(store, (d) => setPassword(d, ids.vera!, replacement, { mustChange: false }, { actor: "cli" }));
    const cb = await viaIdp(main.port, { location: String(started.body.location), binder: cookieNamed(started, "__Host-heliopause-login")! }, { sub: "sub-vera-raced" });
    assert.equal(cb.location, "/app/account?link=ended");
    assert.deepEqual(identitiesOf(store, ids.vera!), []);
    const original = await hashPassword(PASSWORD);
    withMemberTransaction(store, (d) => setPassword(d, ids.vera!, original, { mustChange: false }, { actor: "cli" }));
  });

  it("linking refuses an identity bound to another member or kept as a tombstone", async () => {
    const vera = await login(main.port, "vera");
    const taken = await link(main.port, vera, { sub: "sub-rita" });
    assert.equal(taken.location, "/app/account?link=taken");
    const tomb = await link(main.port, vera, { sub: "sub-gone" });
    assert.equal(tomb.location, "/app/account?link=tombstone");
    assert.deepEqual(identitiesOf(store, ids.vera!), []);
    assert.equal(identitiesOf(store, ids.rita!).length, 1);
  });

  it("the link intent comes from the server, and needs the session that started it", async () => {
    // A request cannot ask for a link: these parameters are ignored and an ordinary login runs.
    const asked = await sso(main.port, { sub: "sub-intent", groups: ["heliopause-operators"] }, `/auth/login?intent=link&memberId=${ids.vera}`);
    assert.equal(asked.status, 302);
    const authz = await call(main.port, "GET", "/api/authz", { cookie: sessionCookie(asked), origin: null });
    assert.equal(authz.body.via, "oidc");
    assert.deepEqual(identitiesOf(store, ids.vera!), []);
    // A link whose session ended before the callback links nothing.
    const vera = await login(main.port, "vera");
    const started = await linkStart(main.port, vera);
    assert.equal(started.status, 200);
    assert.equal((await call(main.port, "POST", "/auth/logout", { cookie: vera.cookie, csrf: vera.csrf })).status, 200);
    const cb = await viaIdp(main.port, { location: String(started.body.location), binder: cookieNamed(started, "__Host-heliopause-login")! }, { sub: "sub-vera" });
    assert.equal(cb.location, "/app/account?link=ended");
    assert.deepEqual(identitiesOf(store, ids.vera!), []);
  });
});

describe("signing in with SSO", () => {
  it("an SSO account whose email is a member's does not become that member", async () => {
    const cb = await sso(main.port, { sub: "sub-stranger", email: "erin@example.com", groups: ["heliopause-operators"] });
    assert.equal(cb.status, 302, JSON.stringify(cb.body));
    const authz = await call(main.port, "GET", "/api/authz", { cookie: sessionCookie(cb), origin: null });
    assert.deepEqual([authz.body.via, authz.body.you], ["oidc", "erin@example.com"]);
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: sessionCookie(cb), origin: null })).status, 403);
    assert.deepEqual(identitiesOf(store, ids.erin!), []);
  });

  it("a suspended or deleted member's identity is refused, not treated as unlinked", async () => {
    withMemberTransaction(store, (d) => suspendMember(d, ids.rita!, { actor: "cli" }));
    try {
      const held = await sso(main.port, { sub: "sub-rita", groups: ["heliopause-operators"] });
      assert.deepEqual([held.status, held.location, cookieNamed(held, "__Host-heliopause-session")], [302, "/app/login?sso=refused", null]);
    } finally {
      withMemberTransaction(store, (d) => unsuspendMember(d, ids.rita!, { actor: "cli" }));
    }
    const tomb = await sso(main.port, { sub: "sub-gone", groups: ["heliopause-operators"] });
    assert.deepEqual([tomb.location, cookieNamed(tomb, "__Host-heliopause-session")], ["/app/login?sso=refused", null]);
  });

  it("a writer's SSO sign-in needs the one-time-code step", async () => {
    const wade = await login(main.port, "wade", GOOD_OTP);
    assert.equal((await link(main.port, wade, { sub: "sub-wade" }, { password: PASSWORD, otp: GOOD_OTP })).location, "/app/account?link=ok");
    const cb = await sso(main.port, { sub: "sub-wade" });
    assert.equal(cookieNamed(cb, "__Host-heliopause-session"), null, "no session before the code");
    assert.equal(cb.location, "/app/login?sso=otp");
    const pending = cookieNamed(cb, "__Host-heliopause-sso");
    assert.ok(pending);
    assert.match(cb.setCookie.find((c) => c.startsWith("__Host-heliopause-sso="))!, /HttpOnly; SameSite=Strict/);
    otpCalls.length = 0;
    const r = await call(main.port, "POST", "/auth/sso/otp", { cookie: pending, body: { otp: GOOD_OTP } });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(otpCalls.map((c) => c.userId), ["ks-wade"]);
    const authz = await call(main.port, "GET", "/api/authz", { cookie: sessionCookie(r), origin: null });
    assert.deepEqual([authz.body.via, authz.body.you, authz.body.canWrite], ["sso", "wade", true]);
  });

  it("the pending SSO step is single-use and expires", async () => {
    const pendingFor = async (): Promise<string> => {
      const cb = await sso(main.port, { sub: "sub-wade" });
      return cookieNamed(cb, "__Host-heliopause-sso")!;
    };
    const once = await pendingFor();
    assert.equal((await call(main.port, "POST", "/auth/sso/otp", { cookie: once, body: { otp: GOOD_OTP } })).status, 200);
    const again = await call(main.port, "POST", "/auth/sso/otp", { cookie: once, body: { otp: GOOD_OTP } });
    assert.deepEqual([again.status, again.body.restart], [400, true]);
    // A wrong code spends it too.
    const wrong = await pendingFor();
    assert.equal((await call(main.port, "POST", "/auth/sso/otp", { cookie: wrong, body: { otp: "000000" } })).status, 401);
    assert.equal((await call(main.port, "POST", "/auth/sso/otp", { cookie: wrong, body: { otp: GOOD_OTP } })).status, 400);
    // Five minutes.
    const late = await pendingFor();
    skewMs += 5 * 60_000;
    assert.equal((await call(main.port, "POST", "/auth/sso/otp", { cookie: late, body: { otp: GOOD_OTP } })).status, 400);
    // Only the console's own page.
    const cross = await pendingFor();
    assert.equal((await call(main.port, "POST", "/auth/sso/otp", { cookie: cross, origin: "https://evil.example", body: { otp: GOOD_OTP } })).status, 403);
  });

  it("a suspended writer is refused before the code step", async () => {
    withMemberTransaction(store, (d) => suspendMember(d, ids.wade!, { actor: "cli" }));
    try {
      const cb = await sso(main.port, { sub: "sub-wade" });
      assert.deepEqual([cb.location, cookieNamed(cb, "__Host-heliopause-sso")], ["/app/login?sso=refused", null]);
    } finally {
      withMemberTransaction(store, (d) => unsuspendMember(d, ids.wade!, { actor: "cli" }));
    }
  });

  it("the code step re-reads the member before the code is checked, and again after", async () => {
    const suspendWade = () => withMemberTransaction(store, (d) => suspendMember(d, ids.wade!, { actor: "cli" }));
    const unsuspendWade = () => withMemberTransaction(store, (d) => unsuspendMember(d, ids.wade!, { actor: "cli" }));
    const before = cookieNamed(await sso(main.port, { sub: "sub-wade" }), "__Host-heliopause-sso")!;
    suspendWade();
    try {
      otpCalls.length = 0;
      const r = await call(main.port, "POST", "/auth/sso/otp", { cookie: before, body: { otp: GOOD_OTP } });
      assert.deepEqual([r.status, r.body.restart, otpCalls.length], [401, true, 0]);
    } finally { unsuspendWade(); }
    const during = cookieNamed(await sso(main.port, { sub: "sub-wade" }), "__Host-heliopause-sso")!;
    duringOtp = suspendWade;
    try {
      const r = await call(main.port, "POST", "/auth/sso/otp", { cookie: during, body: { otp: GOOD_OTP } });
      assert.deepEqual([r.status, cookieNamed(r, "__Host-heliopause-session")], [401, null]);
    } finally { duringOtp = null; unsuspendWade(); }
  });

  it("the IdP's back-channel logout ends a linked member's SSO sessions, not their password ones", async () => {
    const viaSso = await sso(main.port, { sub: "sub-rita" });
    const ssoCookie = sessionCookie(viaSso);
    const rita = await login(main.port, "rita");
    const t = Math.floor(Date.now() / 1000);
    const token = jws({ alg: "ES256", kid: "k1", typ: "secevent+jwt" }, {
      iss: ISSUER, aud: "heliopause-manager", sub: "sub-rita", iat: t, exp: t + 60, jti: randomUUID(), events: { [BACKCHANNEL_LOGOUT_EVENT]: {} },
    });
    const r = await new Promise<number>((resolve, reject) => {
      const body = `logout_token=${encodeURIComponent(token)}`;
      const q = request({
        host: "127.0.0.1", port: main.port, path: "/auth/backchannel-logout", method: "POST", ca: [read("ca.pem")], agent: false,
        headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(Buffer.byteLength(body)) },
      }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
      q.on("error", reject); q.write(body); q.end();
    });
    assert.equal(r, 204);
    assert.equal((await call(main.port, "GET", "/api/authz", { cookie: ssoCookie, origin: null })).status, 401);
    assert.equal((await call(main.port, "GET", "/api/authz", { cookie: rita.cookie, origin: null })).status, 200);
  });
});

describe("unlinking", () => {
  it("unlinking needs the password, and ends the sessions that identity signed in", async () => {
    const viaSso = await sso(main.port, { sub: "sub-rita" });
    const ssoCookie = sessionCookie(viaSso);
    const rita = await login(main.port, "rita");
    const me = await call(main.port, "GET", "/api/me", { cookie: rita.cookie, origin: null });
    const handle = String((me.body.identities as Array<{ id: string }>)[0]!.id);
    const wrong = await call(main.port, "DELETE", `/api/me/identities/${handle}`, { cookie: rita.cookie, csrf: rita.csrf, body: { password: "not it" } });
    assert.equal(wrong.status, 403, JSON.stringify(wrong.body));
    assert.equal(identitiesOf(store, ids.rita!).length, 1);
    const ok = await call(main.port, "DELETE", `/api/me/identities/${handle}`, { cookie: rita.cookie, csrf: rita.csrf, body: { password: PASSWORD } });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.deepEqual(identitiesOf(store, ids.rita!), []);
    assert.equal((await call(main.port, "GET", "/api/authz", { cookie: ssoCookie, origin: null })).status, 401);
    assert.equal((await call(main.port, "GET", "/api/authz", { cookie: rita.cookie, origin: null })).status, 200, "the password session stays");
  });

  // Self-service unlink requires password reauthentication, so a member with no password is refused
  // there (409, "the account has none") before the store's last-login-method guard is reached. That
  // guard is reached by the admin path: "an admin unlinks another member's identity with a code, never
  // their own", and directly in member-store.test.ts "refuses removing the last login method of a
  // member without a password".
  it("a member without a password cannot self-unlink: reauthentication needs a password", async () => {
    const cb = await sso(main.port, { sub: "sub-nopw" });
    const cookie = sessionCookie(cb);
    const me = await call(main.port, "GET", "/api/me", { cookie, origin: null });
    assert.equal(me.body.hasPassword, false);
    const handle = String((me.body.identities as Array<{ id: string }>)[0]!.id);
    const r = await call(main.port, "DELETE", `/api/me/identities/${handle}`, { cookie, csrf: String(me.body.csrf), body: { password: PASSWORD } });
    assert.equal(r.status, 409, JSON.stringify(r.body));
    assert.match(String(r.body.error), /the account has none/);
    assert.equal(identitiesOf(store, ids.nopw!).length, 1);
  });
});

describe("certificates bound to a member", () => {
  it("a certificate bound to a member signs as that member, and not while they are suspended", async () => {
    const authz = await call(main.port, "GET", "/authz", { cert: "bob", origin: null });
    assert.deepEqual([authz.status, authz.body.you, authz.body.via, authz.body.canWrite], [200, "bobby", "certificate", true]);
    // Its one-time codes are checked against the member's KeyStone user, not the CN's mapping.
    const hash = await propose(main.port, "ops", "gen-bound-cert-otp");
    otpCalls.length = 0;
    const approved = await call(main.port, "POST", "/approve", { cert: "bob", origin: null, body: { hash, otp: GOOD_OTP } });
    assert.equal(approved.status, 200, JSON.stringify(approved.body));
    assert.deepEqual(otpCalls.map((c) => c.userId), ["ks-bobby"]);
    withMemberTransaction(store, (d) => suspendMember(d, ids.bobby!, { actor: "cli" }));
    try {
      const refused = await call(main.port, "GET", "/authz", { cert: "bob", origin: null });
      assert.equal(refused.status, 403, JSON.stringify(refused.body));
    } finally {
      withMemberTransaction(store, (d) => unsuspendMember(d, ids.bobby!, { actor: "cli" }));
    }
    // An unbound CN is unchanged while the store is healthy. When it cannot be read, even this read
    // fails closed: the manager cannot know whether the certificate was bound to a suspended member.
    const alice = await call(main.port, "GET", "/authz", { cert: "ops", origin: null });
    assert.deepEqual([alice.status, alice.body.you], [200, "ops-alice"]);
    const savedStore = readFileSync(store);
    try {
      writeFileSync(store, "{not-json", "utf8");
      const unavailable = await call(main.port, "GET", "/authz", { cert: "ops", origin: null });
      assert.deepEqual([unavailable.status, unavailable.body.error], [503, "the member store is unavailable"]);
    } finally {
      writeFileSync(store, savedStore);
    }
  });

  it("a member's SSO session and their bound certificate are one approver", async () => {
    const bobby = await login(main.port, "bobby", GOOD_OTP);
    assert.equal((await link(main.port, bobby, { sub: "sub-bobby" }, { password: PASSWORD, otp: GOOD_OTP })).location, "/app/account?link=ok");
    const viaSso = await ssoWithCode(main.port, { sub: "sub-bobby" });
    const hash = await propose(main.port, viaSso, "gen-sso-then-cert");
    const r = await call(main.port, "POST", "/approve", { cert: "bob", origin: null, body: { hash, otp: GOOD_OTP } });
    assert.equal(r.status, 403, JSON.stringify(r.body));
    // The bound certificate carries the member's name, so this is the proposer by name.
    assert.match(String(r.body.error), /bobby proposed this plan/);
  });
});

describe("SSO code failures and admin unlinking", () => {
  it("wrong SSO codes wait like wrong passwords, and reach the account cap", async () => {
    // The source each code is counted against comes from a header here, so one test can be many addresses.
    const multi = await start(store, "shadow", {
      members: { mode: "shadow", storeFile: store, sourceOf: (req) => String(req.headers["x-test-source"] ?? "127.0.0.1") },
    });
    try {
      const code = async (otp: string, from: string, bump = false): Promise<Reply> => {
        const pending = cookieNamed(await sso(multi.port, { sub: "sub-bobby" }, "/auth/login", bump), "__Host-heliopause-sso")!;
        return call(multi.port, "POST", "/auth/sso/otp", { cookie: pending, body: { otp }, headers: { "x-test-source": from } });
      };
      skewMs += 61_000;
      for (let i = 0; i < 5; i++) assert.equal((await code("000000", "198.51.100.1")).status, 401);
      // From the fifth failure this (account, source) waits, even with the right code.
      const waiting = await code(GOOD_OTP, "198.51.100.1");
      assert.equal(waiting.status, 429, JSON.stringify(waiting.body));
      assert.match(String(waiting.body.error), /try again in \d+s/);
      // Another address is not made to wait by these.
      assert.equal((await code(GOOD_OTP, "198.51.100.2")).status, 200);
      // Fifty failures from fifty addresses cap the account for an address it has not signed in from.
      skewMs += 16 * 60_000;
      for (let i = 0; i < 50; i++) assert.equal((await code("000000", `203.0.113.${i}`, i % 9 === 0)).status, 401);
      const capped = await code(GOOD_OTP, "192.0.2.77");
      assert.equal(capped.status, 429, JSON.stringify(capped.body));
      assert.match(String(capped.body.error), /try again later/);
      // An address that signed this account in recently still gets in.
      assert.equal((await code(GOOD_OTP, "198.51.100.2")).status, 200);
    } finally { multi.close(); }
  });

  it("an admin unlinks another member's identity with a code, never their own", async () => {
    withMemberTransaction(store, (d) => {
      linkIdentity(d, { memberId: ids.root!, issuer: ISSUER, subject: "sub-root" }, { actor: "cli" });
      linkIdentity(d, { memberId: ids.erin!, issuer: ISSUER, subject: "sub-erin" }, { actor: "cli" });
    });
    const root = await login(main.port, "root", GOOD_OTP);
    const list = (await call(main.port, "GET", "/api/members", { cookie: root.cookie, origin: null })).body.members as Array<{ id: string; identities: Array<{ id: string; subject: string }> }>;
    const handleOf = (memberId: string, subject: string) => list.find((m) => m.id === memberId)!.identities.find((i) => i.subject === `…${subject.slice(-4)}`)!.id;
    const path = (memberId: string, handle: string) => `/api/members/${memberId}/identities/${handle}/unlink`;
    const erin = path(ids.erin!, handleOf(ids.erin!, "sub-erin"));
    assert.equal((await call(main.port, "POST", erin, { cookie: root.cookie, body: { otp: GOOD_OTP } })).status, 403, "no CSRF token");
    assert.equal((await call(main.port, "POST", erin, { cookie: root.cookie, csrf: root.csrf, body: {} })).status, 401, "no code");
    const self = await call(main.port, "POST", path(ids.root!, handleOf(ids.root!, "sub-root")), { cookie: root.cookie, csrf: root.csrf, body: { otp: GOOD_OTP } });
    assert.equal(self.status, 403, JSON.stringify(self.body));
    assert.equal(identitiesOf(store, ids.root!).length, 1);
    const erinSso = await sso(main.port, { sub: "sub-erin" });
    const erinSsoCookie = sessionCookie(erinSso);
    assert.equal((await call(main.port, "GET", "/api/authz", { cookie: erinSsoCookie, origin: null })).status, 200);
    const ok = await call(main.port, "POST", erin, { cookie: root.cookie, csrf: root.csrf, body: { otp: GOOD_OTP } });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.equal(ok.body.endedSessions, 1);
    assert.equal((await call(main.port, "GET", "/api/authz", { cookie: erinSsoCookie, origin: null })).status, 401, "the unlinked identity's session ends before its next request");
    assert.deepEqual(identitiesOf(store, ids.erin!), []);
    assert.ok(loadMemberDocument(store).audit.some((a) => a.action === "member.identity-unlink" && a.actor === ids.root && a.target === ids.erin));
    // The store's rules still hold: a member's last way in, and a deleted member's tombstone. This
    // admin path, unlike self-service, needs no password, so it reaches the store's last-login guard.
    const last = await call(main.port, "POST", path(ids.nopw!, handleOf(ids.nopw!, "sub-nopw")), { cookie: root.cookie, csrf: root.csrf, body: { otp: GOOD_OTP } });
    assert.equal(last.status, 409, JSON.stringify(last.body));
    assert.match(String(last.body.error), /last login method/);
    const tomb = await call(main.port, "POST", path(ids.gone!, handleOf(ids.gone!, "sub-gone")), { cookie: root.cookie, csrf: root.csrf, body: { otp: GOOD_OTP } });
    assert.equal(tomb.status, 409, JSON.stringify(tomb.body));
    assert.equal(identitiesOf(store, ids.gone!).length, 1);
    const wade = await login(main.port, "wade", GOOD_OTP);
    assert.equal((await call(main.port, "POST", erin, { cookie: wade.cookie, csrf: wade.csrf, body: { otp: GOOD_OTP } })).status, 403, "not an admin");
  });
});

describe("member solo approval", () => {
  it("solo approval needs soloApprove, a confirmed code and a session that passed it", async () => {
    const wade = await login(main.port, "wade", GOOD_OTP);
    const hash = await propose(main.port, wade, "gen-solo-1");
    const plans = async (s: Login) => (await call(main.port, "GET", "/plans", { cookie: s.cookie, origin: null })).body;
    assert.equal((await plans(wade)).maySoloApprove, false);
    const own = await call(main.port, "POST", "/approve", { cookie: wade.cookie, csrf: wade.csrf, body: { hash, otp: GOOD_OTP } });
    assert.equal(own.status, 403, "two people without soloApprove");

    const root = await login(main.port, "root", GOOD_OTP);
    const set = await call(main.port, "POST", `/api/members/${ids.wade}/solo-approve`, { cookie: root.cookie, csrf: root.csrf, body: { soloApprove: true, otp: GOOD_OTP } });
    assert.equal(set.status, 200, JSON.stringify(set.body));
    assert.equal((await plans(wade)).maySoloApprove, true);
    const solo = await call(main.port, "POST", "/approve", { cookie: wade.cookie, csrf: wade.csrf, body: { hash, otp: GOOD_OTP } });
    assert.equal(solo.status, 200, JSON.stringify(solo.body));

    // An otpUserId no sign-in code has confirmed (a store edit; the API would end the session).
    withMemberTransaction(store, (d) => setOtpUserId(d, ids.wade!, "ks-wade-2", { actor: "cli" }));
    try {
      assert.equal((await plans(wade)).maySoloApprove, false);
    } finally {
      withMemberTransaction(store, (d) => { setOtpUserId(d, ids.wade!, "ks-wade", { actor: "cli" }); confirmOtp(d, ids.wade!, "ks-wade", { actor: "cli" }); });
    }
    // A member who may not write gets no solo approval from the flag, even with a confirmed code.
    withMemberTransaction(store, (d) => {
      d.members.find((m) => m.id === ids.rita)!.soloApprove = true;
      setOtpUserId(d, ids.rita!, "ks-rita", { actor: "cli" }); confirmOtp(d, ids.rita!, "ks-rita", { actor: "cli" });
    });
    const rita = await login(main.port, "rita");
    assert.equal((await plans(rita)).maySoloApprove, false);
    // A certificate never does, even bound to a member who has it.
    withMemberTransaction(store, (d) => { d.members.find((m) => m.id === ids.bobby)!.soloApprove = true; });
    const byCert = await propose(main.port, "bob", "gen-solo-cert");
    const certOwn = await call(main.port, "POST", "/approve", { cert: "bob", origin: null, body: { hash: byCert, otp: GOOD_OTP } });
    assert.equal(certOwn.status, 403, JSON.stringify(certOwn.body));
  });

  it("an admin sets another member's solo approval with a code, never their own", async () => {
    const root = await login(main.port, "root", GOOD_OTP);
    const noCode = await call(main.port, "POST", `/api/members/${ids.vera}/solo-approve`, { cookie: root.cookie, csrf: root.csrf, body: { soloApprove: true } });
    assert.equal(noCode.status, 401, JSON.stringify(noCode.body));
    const self = await call(main.port, "POST", `/api/members/${ids.root}/solo-approve`, { cookie: root.cookie, csrf: root.csrf, body: { soloApprove: true, otp: GOOD_OTP } });
    assert.equal(self.status, 403, JSON.stringify(self.body));
    assert.equal(loadMemberDocument(store).members.find((m) => m.id === ids.root)!.soloApprove, false);
    const bad = await call(main.port, "POST", `/api/members/${ids.vera}/solo-approve`, { cookie: root.cookie, csrf: root.csrf, body: { soloApprove: "yes", otp: GOOD_OTP } });
    assert.equal(bad.status, 400);
    const wade = await login(main.port, "wade", GOOD_OTP);
    const notAdmin = await call(main.port, "POST", `/api/members/${ids.vera}/solo-approve`, { cookie: wade.cookie, csrf: wade.csrf, body: { soloApprove: true, otp: GOOD_OTP } });
    assert.equal(notAdmin.status, 403);
  });
});

describe("HELIOPAUSE_MEMBERS=on", () => {
  it("on refuses an unlinked SSO account and admits members and the CLI", async () => {
    const on = await start(store, "on");
    try {
      const unlinked = await sso(on.port, { sub: "sub-unlinked", groups: ["heliopause-operators", "heliopause-writers"] });
      assert.deepEqual([unlinked.status, unlinked.location, cookieNamed(unlinked, "__Host-heliopause-session")], [302, "/app/login?sso=unlinked", null]);
      const member = await login(on.port, "vera");
      assert.equal((await call(on.port, "GET", "/api/authz", { cookie: member.cookie, origin: null })).body.via, "password");
      const linked = await ssoWithCode(on.port, { sub: "sub-wade" });
      assert.equal((await call(on.port, "GET", "/api/authz", { cookie: linked.cookie, origin: null })).body.via, "sso");
      const cli = await call(on.port, "GET", "/authz", { cert: "ops", origin: null });
      assert.deepEqual([cli.status, cli.body.via], [200, "certificate"]);
      const browser = await call(on.port, "GET", "/authz", { cert: "ops" });
      assert.equal(browser.status, 401, "a browser does not sign in by certificate");
      const bound = await call(on.port, "GET", "/authz", { cert: "bob", origin: null });
      assert.equal(bound.body.you, "bobby");
    } finally { on.close(); }
  });

  it("refuses to start with JIT member creation", async () => {
    // A manager that does start is closed, so a missing refusal fails here instead of hanging the run.
    const attempt = start(store, "shadow", { members: { mode: "shadow", storeFile: store, jit: true as unknown as false } });
    await assert.rejects(attempt.then((s) => { s.close(); }), /members\.jit/);
  });
});
