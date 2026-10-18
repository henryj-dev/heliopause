// Member password sign-in, against a real TLS manager (`member-auth.ts` wired by `manager-server.ts`).
//
// One manager with OTP configured carries most cases; a second without OTP, a third with a one-second
// idle limit, and an `off` one are started for the cases that need them. The manager's clock is
// shifted forward a minute before each sign-in helper call so the per-address limit (10 a minute)
// does not leak between cases; the cases about limits shift it once and then hold it.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:https";
import { execFileSync } from "node:child_process";
import { createSign, generateKeyPairSync, createHash } from "node:crypto";
import { startManager } from "./manager-server.ts";
import { normalizeSource, recordFailureIn } from "./member-auth.ts";
import { SCHEMA_VERSION } from "./protocol.ts";
import {
  confirmOtp, createMember, initializeMemberDocument, loadMemberDocument, MEMBER_LOGIN_AUDIT_MAX, saveMemberDocument, setOtpUserId,
  setPassword, setRoles, suspendMember, withMemberTransaction,
  type MemberRole,
} from "./member-store.ts";
import { hashPassword } from "./password.ts";
import { CSRF_HEADER } from "./session.ts";

const ROLE_CHANGE_EVENT = "https://idp.example.invalid/event/role-change";
const PASSWORD = "correct horse battery staple";
const NEW_PASSWORD = "an entirely different passphrase";
const GOOD_OTP = "123456";

const dir = mkdtempSync(join(tmpdir(), "hp-member-auth-"));
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

/**
 * KeyStone's verify endpoint: GOOD_OTP is right for every user except `ks-broken`, which answers 500,
 * and `ks-inactive`, which answers 403 the way KeyStone does for a user who is not active there.
 * `duringOtp[userId]`, when set, runs before the verdict — the window between the check and the write.
 */
const otpCalls: Array<{ userId: string; code: string }> = [];
const duringOtp: Record<string, () => void> = {};
const otpFetch = (async (_u: string | URL, init?: { body?: string }) => {
  const body = JSON.parse(String(init?.body ?? "{}")) as { userId: string; code: string };
  otpCalls.push(body);
  duringOtp[body.userId]?.();
  if (body.userId === "ks-broken") return new Response("boom", { status: 500 });
  if (body.userId === "ks-inactive") return new Response(JSON.stringify({ error: "user is not active" }), { status: 403 });
  return body.code === GOOD_OTP
    ? new Response(JSON.stringify({ ok: true }), { status: 200 })
    : new Response(JSON.stringify({ ok: false }), { status: 401 });
}) as unknown as typeof fetch;

const idpFetch = (async (u: string | URL) => { throw new Error(`the IdP should not be called here: ${String(u)}`); }) as unknown as typeof fetch;

let skewMs = 0;
const clock = () => new Date(Date.now() + skewMs);

type Started = { port: number; close: () => void };
async function start(store: string, extra: Partial<Parameters<typeof startManager>[0]> = {}, mode: "off" | "shadow" = "shadow"): Promise<Started> {
  const started = await startManager({
    port: 0, hostname: "127.0.0.1",
    relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
    tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
    operatorCNs: ["ops-alice"], writerCNs: ["ops-alice"],
    timeoutMs: 200,
    oidc: {
      issuer: "https://idp.example.invalid", clientId: "heliopause-manager",
      redirectUri: "https://heliopause.example.invalid/auth/callback", roleChangeEvent: ROLE_CHANGE_EVENT,
      operatorGroups: ["heliopause-operators"], writerGroups: ["heliopause-writers"],
      aliases: new Map([["jang@example.invalid", "ops-alias"]]), fetchImpl: idpFetch,
    },
    members: mode === "shadow" ? { mode, storeFile: store } : { mode },
    now: clock,
    log: () => {},
    ...extra,
  });
  return {
    port: (started.server.address() as { port: number }).port,
    close: () => { started.stopProblemWatch(); started.server.closeAllConnections(); started.server.close(); },
  };
}

interface Reply { status: number; body: Record<string, unknown>; setCookie: string[] }
function call(port: number, method: string, path: string, o: {
  body?: unknown; cookie?: string; csrf?: string; origin?: string | null; cert?: boolean; headers?: Record<string, string>;
} = {}): Promise<Reply> {
  const payload = o.body === undefined ? undefined : typeof o.body === "string" ? o.body : JSON.stringify(o.body);
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
      ...(o.cert ? { cert: read("ops.pem"), key: read("ops.key") } : {}),
      signal: AbortSignal.timeout(10_000),
    }, (res) => {
      let b = ""; res.on("data", (d) => (b += d));
      res.on("end", () => {
        let body: Record<string, unknown> = {};
        try { body = JSON.parse(b) as Record<string, unknown>; } catch { body = { raw: b }; }
        resolve({ status: res.statusCode ?? 0, body, setCookie: ([] as string[]).concat((res.headers["set-cookie"] as string[]) ?? []) });
      });
    });
    r.on("error", reject);
    if (payload !== undefined) r.write(payload);
    r.end();
  });
}

const cookieOf = (r: Reply): string => {
  const c = r.setCookie.find((x) => x.startsWith("__Host-heliopause-session="));
  assert.ok(c, `no session cookie in ${JSON.stringify(r.setCookie)}`);
  return c.split(";")[0]!;
};

async function seed(store: string, username: string, roles: MemberRole[], o: { otpUserId?: string; mustChange?: boolean; certCNs?: string[]; principalName?: string } = {}): Promise<string> {
  const hash = await hashPassword(PASSWORD);
  return withMemberTransaction(store, (d) => {
    const m = createMember(d, {
      username, email: `${username}@example.com`, emailVerified: true, status: "active", roles,
      otpUserId: o.otpUserId ?? null, ...(o.certCNs ? { certCNs: o.certCNs } : {}), ...(o.principalName ? { principalName: o.principalName } : {}),
    }, { actor: "cli" });
    setPassword(d, m.id, hash, { mustChange: o.mustChange === true }, { actor: "cli" });
    return m.id;
  });
}

interface Login { cookie: string; csrf: string; body: Record<string, unknown> }
async function login(port: number, username: string, password = PASSWORD, otp?: string): Promise<Login> {
  skewMs += 61_000;
  const r = await call(port, "POST", "/auth/password/login", { body: { username, password, ...(otp ? { otp } : {}) } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return { cookie: cookieOf(r), csrf: String(r.body.csrf), body: r.body };
}

const store = join(dir, "members.json");
let main: Started;
const ids: Record<string, string> = {};

before(async () => {
  pki();
  initializeMemberDocument(store);
  ids.root = await seed(store, "root", ["reader", "writer", "admin"], { otpUserId: "ks-root" });
  ids.rita = await seed(store, "rita", ["reader"]);
  ids.wade = await seed(store, "wade", ["reader", "writer"], { otpUserId: "ks-wade" });
  ids.nora = await seed(store, "nora", ["reader", "writer"]);
  ids.brok = await seed(store, "brok", ["reader", "writer"], { otpUserId: "ks-broken" });
  ids.inac = await seed(store, "inac", ["reader", "writer"], { otpUserId: "ks-inactive" });
  ids.mia = await seed(store, "mia", ["reader"], { mustChange: true });
  ids.sam = await seed(store, "sam", ["reader"]);
  withMemberTransaction(store, (d) => suspendMember(d, ids.sam!, { actor: "cli" }));
  main = await start(store, {
    otp: { issuerUrl: "https://otp.example.invalid", serviceToken: "svc", users: new Map([["ops-alice", "ks-cert-alice"]]), fetchImpl: otpFetch },
  });
});

after(() => {
  main?.close();
  rmSync(dir, { recursive: true, force: true });
});

const adminLogin = () => login(main.port, "root", PASSWORD, GOOD_OTP);

describe("signing in", () => {
  it("signs a reader in and answers who they are", async () => {
    const s = await login(main.port, "rita");
    assert.deepEqual({ ...s.body, csrf: typeof s.body.csrf }, { you: "rita", canWrite: false, isAdmin: false, csrf: "string", mustChange: false });
    const me = await call(main.port, "GET", "/api/me", { cookie: s.cookie });
    assert.equal(me.status, 200);
    assert.deepEqual(me.body, {
      id: ids.rita, username: "rita", principalName: "rita", email: "rita@example.com", roles: ["reader"],
      status: "active", mustChange: false, via: "password", otpConfirmedAt: null,
    });
  });

  it("answers an unknown username and a wrong password identically", async () => {
    skewMs += 61_000;
    const unknown = await call(main.port, "POST", "/auth/password/login", { body: { username: "nobody-here", password: PASSWORD } });
    const wrong = await call(main.port, "POST", "/auth/password/login", { body: { username: "rita", password: "not the password at all" } });
    const suspended = await call(main.port, "POST", "/auth/password/login", { body: { username: "sam", password: PASSWORD } });
    for (const r of [unknown, wrong, suspended]) {
      assert.equal(r.status, 401);
      assert.deepEqual(r.body, { error: "invalid username or password" });
      assert.deepEqual(r.setCookie, []);
    }
  });

  it("an unknown username spends a password check: concurrent ones hit the limiter", async () => {
    // Only `dummyVerify` takes a limiter slot on this path, so a 429 here is the proof it ran.
    skewMs += 61_000;
    const replies = await Promise.all([1, 2, 3, 4, 5].map((i) =>
      call(main.port, "POST", "/auth/password/login", { body: { username: `ghost-${i}`, password: PASSWORD } })));
    const busy = replies.filter((r) => r.status === 429);
    assert.ok(busy.length >= 1, `statuses ${replies.map((r) => r.status).join(",")}`);
    assert.match(String(busy[0]!.body.error), /too many password checks/);
  });

  it("issues a new session id on every sign-in and ends the one presented", async () => {
    const a = await login(main.port, "rita");
    skewMs += 61_000;
    const second = await call(main.port, "POST", "/auth/password/login", { cookie: a.cookie, body: { username: "rita", password: PASSWORD } });
    assert.equal(second.status, 200);
    const b = cookieOf(second);
    assert.notEqual(a.cookie, b);
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: a.cookie })).status, 401);
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: b })).status, 200);
  });

  it("refuses a sign-in from another origin, or without one", async () => {
    const body = { username: "rita", password: PASSWORD };
    assert.equal((await call(main.port, "POST", "/auth/password/login", { body, origin: "https://evil.example" })).status, 403);
    assert.equal((await call(main.port, "POST", "/auth/password/login", { body, origin: null })).status, 403);
    assert.equal((await call(main.port, "POST", "/auth/password/login", { body, headers: { "sec-fetch-site": "cross-site" } })).status, 403);
  });

  it("refuses badly typed or oversized fields before hashing", async () => {
    skewMs += 61_000;
    const tooLong = await call(main.port, "POST", "/auth/password/login", { body: { username: "rita", password: "x".repeat(1025) } });
    assert.equal(tooLong.status, 400);
    assert.match(String(tooLong.body.error), /password is too long/);
    assert.equal((await call(main.port, "POST", "/auth/password/login", { body: { username: 7, password: PASSWORD } })).status, 400);
    assert.equal((await call(main.port, "POST", "/auth/password/login", { body: { username: "rita", password: PASSWORD, extra: 1 } })).status, 400);
  });
});

describe("writer and admin sign-in needs a one-time code", () => {
  it("asks for the code and makes no session without it", async () => {
    skewMs += 61_000;
    const r = await call(main.port, "POST", "/auth/password/login", { body: { username: "wade", password: PASSWORD } });
    assert.equal(r.status, 401);
    assert.equal(r.body.needOtp, true);
    assert.deepEqual(r.setCookie, []);
  });

  it("refuses a wrong code", async () => {
    skewMs += 61_000;
    const r = await call(main.port, "POST", "/auth/password/login", { body: { username: "wade", password: PASSWORD, otp: "000000" } });
    assert.equal(r.status, 401);
    assert.deepEqual(r.setCookie, []);
  });

  it("signs a writer in with the right code, checked against the member's otpUserId", async () => {
    otpCalls.length = 0;
    const s = await login(main.port, "wade", PASSWORD, GOOD_OTP);
    assert.equal(s.body.canWrite, true);
    assert.deepEqual(otpCalls, [{ userId: "ks-wade", code: GOOD_OTP }]);
  });

  it("refuses a writer with no otpUserId (403)", async () => {
    skewMs += 61_000;
    const r = await call(main.port, "POST", "/auth/password/login", { body: { username: "nora", password: PASSWORD, otp: GOOD_OTP } });
    assert.equal(r.status, 403);
    assert.deepEqual(r.setCookie, []);
  });

  it("refuses when KeyStone fails, with no fallback", async () => {
    skewMs += 61_000;
    const r = await call(main.port, "POST", "/auth/password/login", { body: { username: "brok", password: PASSWORD, otp: GOOD_OTP } });
    assert.equal(r.status, 503);
    assert.deepEqual(r.setCookie, []);
  });

  it("refuses a writer KeyStone reports as not active: 403, not an outage and not a pass", async () => {
    skewMs += 61_000;
    const r = await call(main.port, "POST", "/auth/password/login", { body: { username: "inac", password: PASSWORD, otp: GOOD_OTP } });
    assert.equal(r.status, 403);
    assert.equal(r.body.needOtp, undefined);
    assert.deepEqual(r.setCookie, []);
  });

  it("refuses writer sign-in when the manager has no OTP verifier, and still lets a reader in", async () => {
    const plain = await start(store, {});
    try {
      skewMs += 61_000;
      const r = await call(plain.port, "POST", "/auth/password/login", { body: { username: "wade", password: PASSWORD, otp: GOOD_OTP } });
      assert.equal(r.status, 503);
      assert.match(String(r.body.error), /no OTP verifier/);
      assert.deepEqual(r.setCookie, []);
      assert.equal((await call(plain.port, "POST", "/auth/password/login", { body: { username: "rita", password: PASSWORD } })).status, 200);
    } finally { plain.close(); }
  });
});

describe("otpUserId confirmation", () => {
  it("the first sign-in code confirms the otpUserId, once", async () => {
    const id = await seed(store, "cora", ["reader", "writer"], { otpUserId: "ks-cora" });
    const before = loadMemberDocument(store).members.find((m) => m.id === id)!;
    assert.equal(before.otpConfirmedAt, null);
    const s = await login(main.port, "cora", PASSWORD, GOOD_OTP);
    const first = loadMemberDocument(store).members.find((m) => m.id === id)!.otpConfirmedAt;
    assert.ok(first, "confirmed by the first sign-in");
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: s.cookie })).body.otpConfirmedAt, first);
    await login(main.port, "cora", PASSWORD, GOOD_OTP);
    const doc = loadMemberDocument(store);
    assert.equal(doc.members.find((m) => m.id === id)!.otpConfirmedAt, first);
    assert.equal(doc.audit.filter((a) => a.action === "member.otp.confirmed" && a.target === id).length, 1);
  });

  it("a reader's sign-in confirms nothing", async () => {
    const id = await seed(store, "rudy", ["reader"], { otpUserId: "ks-rudy" });
    await login(main.port, "rudy");
    assert.equal(loadMemberDocument(store).members.find((m) => m.id === id)!.otpConfirmedAt, null);
  });

  it("an admin otp-user change resets the confirmation, shown in /api/members", async () => {
    const id = await seed(store, "cleo", ["reader", "writer"], { otpUserId: "ks-cleo" });
    await login(main.port, "cleo", PASSWORD, GOOD_OTP);
    const admin = await adminLogin();
    const listed = async () => ((await call(main.port, "GET", "/api/members", { cookie: admin.cookie })).body.members as Array<{ id: string; otpConfirmedAt: string | null }>).find((m) => m.id === id)!;
    assert.notEqual((await listed()).otpConfirmedAt, null);
    const r = await call(main.port, "POST", `/api/members/${id}/otp-user`, { cookie: admin.cookie, csrf: admin.csrf, body: { otpUserId: "ks-cleo-2", otp: GOOD_OTP } });
    assert.equal(r.status, 200);
    assert.equal((await listed()).otpConfirmedAt, null);
  });

  it("an unconfirmed otpUserId refuses the approval code", async () => {
    const id = await seed(store, "vera", ["reader", "writer"], { otpUserId: "ks-vera" });
    const s = await login(main.port, "vera", PASSWORD, GOOD_OTP);
    const approve = () => call(main.port, "POST", "/approve", { cookie: s.cookie, csrf: s.csrf, body: { hash: "0".repeat(64), otp: GOOD_OTP } });
    const confirmed = await approve();
    assert.equal(confirmed.status, 404, JSON.stringify(confirmed.body));
    // A store edit outside the API: the session survives it, the confirmation does not.
    withMemberTransaction(store, (d) => setOtpUserId(d, id, "ks-vera-2", { actor: "cli" }));
    const r = await approve();
    assert.equal(r.status, 403);
    assert.deepEqual(r.body, { error: "confirm your one-time code by signing in again" });
  });
});

describe("authority is re-read on every request", () => {
  it("suspension takes effect on the next request", async () => {
    const id = await seed(store, "sue", ["reader"]);
    const s = await login(main.port, "sue");
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: s.cookie })).status, 200);
    withMemberTransaction(store, (d) => suspendMember(d, id, { actor: "cli" }));
    const after = await call(main.port, "GET", "/site", { cookie: s.cookie });
    assert.equal(after.status, 401);
    // The session is gone, not just refused once.
    withMemberTransaction(store, (d) => { d.members.find((m) => m.id === id)!.status = "active"; });
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: s.cookie })).status, 401);
  });

  it("a role taken away drops canWrite on the next request", async () => {
    const id = await seed(store, "walt", ["reader", "writer"], { otpUserId: "ks-walt" });
    const s = await login(main.port, "walt", PASSWORD, GOOD_OTP);
    assert.equal((await call(main.port, "GET", "/authz", { cookie: s.cookie })).body.canWrite, true);
    withMemberTransaction(store, (d) => setRoles(d, id, ["reader"], { actor: "cli" }));
    const r = await call(main.port, "GET", "/authz", { cookie: s.cookie });
    assert.equal(r.status, 200);
    assert.equal(r.body.canWrite, false);
  });

  it("a role added outside sign-in does not grant writing without the sign-in code", async () => {
    const id = await seed(store, "rory", ["reader"], { otpUserId: "ks-rory" });
    const s = await login(main.port, "rory");
    withMemberTransaction(store, (d) => setRoles(d, id, ["reader", "writer"], { actor: "cli" }));
    assert.equal((await call(main.port, "GET", "/authz", { cookie: s.cookie })).body.canWrite, false);
  });

  it("a password set elsewhere ends the session", async () => {
    const id = await seed(store, "pete", ["reader"]);
    const s = await login(main.port, "pete");
    const hash = await hashPassword(NEW_PASSWORD);
    withMemberTransaction(store, (d) => setPassword(d, id, hash, { mustChange: false }, { actor: "cli" }));
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: s.cookie })).status, 401);
  });

  it("an unreadable store answers 503, not the old answer", async () => {
    const s = await login(main.port, "rita");
    const saved = readFileSync(store);
    try {
      writeFileSync(store, "{ not json");
      const r = await call(main.port, "GET", "/api/me", { cookie: s.cookie });
      assert.equal(r.status, 503);
    } finally { writeFileSync(store, saved); }
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: s.cookie })).status, 200);
  });

  it("ends an idle session", async () => {
    const idle = await start(store, { members: { mode: "shadow", storeFile: store, sessionIdleSec: 1 } });
    try {
      skewMs += 61_000;
      const r = await call(idle.port, "POST", "/auth/password/login", { body: { username: "rita", password: PASSWORD } });
      const cookie = cookieOf(r);
      assert.equal((await call(idle.port, "GET", "/api/me", { cookie })).status, 200);
      await new Promise((resolve) => setTimeout(resolve, 1_300));
      assert.equal((await call(idle.port, "GET", "/api/me", { cookie })).status, 401);
    } finally { idle.close(); }
  });
});

describe("a password that must change", () => {
  it("answers only /api/me, the change itself, and logout until it changes", async () => {
    const s = await login(main.port, "mia");
    assert.equal(s.body.mustChange, true);
    const site = await call(main.port, "GET", "/site", { cookie: s.cookie });
    assert.equal(site.status, 403);
    assert.deepEqual(site.body, { error: "password change required" });
    assert.equal((await call(main.port, "GET", "/api/me/sessions", { cookie: s.cookie })).status, 403);
    assert.equal((await call(main.port, "GET", "/api/site", { cookie: s.cookie })).status, 403);
    const plan = await call(main.port, "POST", "/api/plan", { cookie: s.cookie, csrf: s.csrf, body: {} });
    assert.deepEqual([plan.status, plan.body], [403, { error: "password change required" }]);
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: s.cookie })).body.mustChange, true);
    const change = await call(main.port, "POST", "/api/me/password", { cookie: s.cookie, csrf: s.csrf, body: { current: PASSWORD, next: NEW_PASSWORD } });
    assert.equal(change.status, 200, JSON.stringify(change.body));
    assert.equal((await call(main.port, "GET", "/site", { cookie: s.cookie })).status, 200);
  });

  it("changing a password ends the member's other sessions and keeps this one", async () => {
    await seed(store, "olga", ["reader"]);
    const a = await login(main.port, "olga");
    const b = await login(main.port, "olga");
    const wrong = await call(main.port, "POST", "/api/me/password", { cookie: b.cookie, csrf: b.csrf, body: { current: "wrong wrong wrong", next: NEW_PASSWORD } });
    assert.equal(wrong.status, 403);
    const r = await call(main.port, "POST", "/api/me/password", { cookie: b.cookie, csrf: b.csrf, body: { current: PASSWORD, next: NEW_PASSWORD } });
    assert.equal(r.status, 200);
    assert.equal(r.body.endedSessions, 1);
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: a.cookie })).status, 401);
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: b.cookie })).status, 200);
  });
});

describe("CSRF is required on POST, PUT and DELETE for a member session", () => {
  it("refuses each method without the token and lets it through with it", async () => {
    const s = await login(main.port, "rita");
    for (const method of ["POST", "PUT", "DELETE"]) {
      const without = await call(main.port, method, "/api/me/sessions", { cookie: s.cookie, ...(method === "DELETE" ? {} : { body: {} }) });
      assert.equal(without.status, 403, `${method} without token: ${JSON.stringify(without.body)}`);
      assert.match(String(without.body.error), /CSRF/);
    }
    const ok = await call(main.port, "DELETE", "/api/me/sessions", { cookie: s.cookie, csrf: s.csrf });
    assert.equal(ok.status, 200);
    const put = await call(main.port, "PUT", "/no-such-route", { cookie: s.cookie, csrf: s.csrf, body: {} });
    assert.equal(put.status, 404, JSON.stringify(put.body));
  });

  it("logout of a member session needs the CSRF token", async () => {
    const s = await login(main.port, "rita");
    assert.equal((await call(main.port, "POST", "/auth/logout", { cookie: s.cookie })).status, 403);
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: s.cookie })).status, 200);
    const out = await call(main.port, "POST", "/auth/logout", { cookie: s.cookie, csrf: s.csrf });
    assert.equal(out.status, 200);
    assert.deepEqual(out.body, { endSession: null });
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: s.cookie })).status, 401);
  });
});

describe("own sessions", () => {
  it("lists them with opaque ids and ends one by id", async () => {
    await seed(store, "lena", ["reader"]);
    const a = await login(main.port, "lena");
    const b = await login(main.port, "lena");
    const list = await call(main.port, "GET", "/api/me/sessions", { cookie: b.cookie });
    const rows = list.body.sessions as Array<{ id: string; current: boolean; via: string }>;
    assert.equal(rows.length, 2);
    assert.ok(rows.every((r) => /^[0-9a-f]{16}$/.test(r.id) && r.via === "password"));
    const other = rows.find((r) => !r.current)!;
    assert.equal((await call(main.port, "DELETE", `/api/me/sessions/${other.id}`, { cookie: b.cookie, csrf: b.csrf })).status, 200);
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: a.cookie })).status, 401);
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: b.cookie })).status, 200);
  });
});

describe("invitations and resets", () => {
  it("an invitation is accepted once and creates an active member", async () => {
    const admin = await adminLogin();
    const inv = await call(main.port, "POST", "/api/members/invites", { cookie: admin.cookie, csrf: admin.csrf, body: { email: "ivy@example.com", roles: ["reader"], otp: GOOD_OTP } });
    assert.equal(inv.status, 201, JSON.stringify(inv.body));
    const token = String(inv.body.inviteUrl).split("/invite/")[1]!;
    // Built on the configured origin (the OIDC redirect URI's), not on the request's Host.
    assert.match(String(inv.body.inviteUrl), /^https:\/\/heliopause\.example\.invalid\/invite\/hpmem_/);
    const clash = await call(main.port, "POST", "/auth/invite/accept", { body: { token, username: "ops-alice", password: PASSWORD } });
    assert.equal(clash.status, 409);
    assert.deepEqual(clash.body, { error: "username is not available" });
    const taken = await call(main.port, "POST", "/auth/invite/accept", { body: { token, username: "rita", password: PASSWORD } });
    assert.deepEqual(taken.body, { error: "username is not available" });
    const ok = await call(main.port, "POST", "/auth/invite/accept", { body: { token, username: "ivy", password: PASSWORD } });
    assert.equal(ok.status, 201, JSON.stringify(ok.body));
    assert.deepEqual(ok.setCookie, []);
    const again = await call(main.port, "POST", "/auth/invite/accept", { body: { token, username: "ivy2", password: PASSWORD } });
    assert.equal(again.status, 400);
    const s = await login(main.port, "ivy");
    const me = await call(main.port, "GET", "/api/me", { cookie: s.cookie });
    assert.equal(me.body.email, "ivy@example.com");
    assert.deepEqual(me.body.roles, ["reader"]);
  });

  it("a reset token sets the password once and ends every session of that member", async () => {
    const id = await seed(store, "rhea", ["reader"]);
    const victim = await login(main.port, "rhea");
    const admin = await adminLogin();
    const issued = await call(main.port, "POST", `/api/members/${id}/password-reset`, { cookie: admin.cookie, csrf: admin.csrf, body: { otp: GOOD_OTP } });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const token = String(issued.body.resetUrl).split("/reset/")[1]!;
    const r = await call(main.port, "POST", "/auth/password/reset", { body: { token, password: NEW_PASSWORD } });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const fresh = await login(main.port, "rhea", NEW_PASSWORD);
    // Ended at reset, not merely refused when next presented: before the old cookie is shown again,
    // the list holds only the new session.
    const list = await call(main.port, "GET", "/api/me/sessions", { cookie: fresh.cookie });
    assert.equal((list.body.sessions as unknown[]).length, 1);
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: victim.cookie })).status, 401);
    assert.equal((await call(main.port, "POST", "/auth/password/reset", { body: { token, password: PASSWORD } })).status, 400);
  });

  it("a writer's reset also needs the one-time code", async () => {
    const id = await seed(store, "wren", ["reader", "writer"], { otpUserId: "ks-wren" });
    await login(main.port, "wren", PASSWORD, GOOD_OTP); // confirms ks-wren
    const admin = await adminLogin();
    const issued = await call(main.port, "POST", `/api/members/${id}/password-reset`, { cookie: admin.cookie, csrf: admin.csrf, body: { otp: GOOD_OTP } });
    const token = String(issued.body.resetUrl).split("/reset/")[1]!;
    const without = await call(main.port, "POST", "/auth/password/reset", { body: { token, password: NEW_PASSWORD } });
    assert.equal(without.status, 401);
    assert.equal(without.body.needOtp, true);
    const withCode = await call(main.port, "POST", "/auth/password/reset", { body: { token, password: NEW_PASSWORD, otp: GOOD_OTP } });
    assert.equal(withCode.status, 200);
  });
});

describe("member administration", () => {
  it("is refused to a member without the admin role", async () => {
    const s = await login(main.port, "rita");
    assert.equal((await call(main.port, "GET", "/api/members", { cookie: s.cookie })).status, 403);
    assert.equal((await call(main.port, "POST", "/api/members/invites", { cookie: s.cookie, csrf: s.csrf, body: { email: "x@example.com", roles: ["reader"], otp: GOOD_OTP } })).status, 403);
  });

  it("lists members without secrets", async () => {
    const admin = await adminLogin();
    const r = await call(main.port, "GET", "/api/members", { cookie: admin.cookie });
    assert.equal(r.status, 200);
    const text = JSON.stringify(r.body);
    assert.doesNotMatch(text, /scrypt\$/);
    assert.ok((r.body.members as unknown[]).length >= 7);
  });

  it("needs the one-time code on every write", async () => {
    const admin = await adminLogin();
    const r = await call(main.port, "POST", `/api/members/${ids.rita}/suspend`, { cookie: admin.cookie, csrf: admin.csrf, body: {} });
    assert.equal(r.status, 401);
    assert.match(String(r.body.error), /one-time code/);
    const wrong = await call(main.port, "POST", `/api/members/${ids.rita}/suspend`, { cookie: admin.cookie, csrf: admin.csrf, body: { otp: "000000" } });
    assert.equal(wrong.status, 401);
  });

  it("suspending or deleting a member ends their sessions at once", async () => {
    const idA = await seed(store, "tess", ["reader"]);
    const idB = await seed(store, "tara", ["reader"]);
    const a = await login(main.port, "tess");
    const b = await login(main.port, "tara");
    const admin = await adminLogin();
    const sus = await call(main.port, "POST", `/api/members/${idA}/suspend`, { cookie: admin.cookie, csrf: admin.csrf, body: { otp: GOOD_OTP } });
    assert.equal(sus.status, 200, JSON.stringify(sus.body));
    assert.equal(sus.body.endedSessions, 1);
    const del = await call(main.port, "POST", `/api/members/${idB}/delete`, { cookie: admin.cookie, csrf: admin.csrf, body: { otp: GOOD_OTP } });
    assert.equal(del.body.endedSessions, 1);
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: a.cookie })).status, 401);
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: b.cookie })).status, 401);
  });

  it("refuses to leave no active admin (409)", async () => {
    const admin = await adminLogin();
    const r = await call(main.port, "POST", `/api/members/${ids.root}/suspend`, { cookie: admin.cookie, csrf: admin.csrf, body: { otp: GOOD_OTP } });
    assert.equal(r.status, 409);
    assert.match(String(r.body.error), /no active admin/);
  });

  it("an admin cannot change their own roles or otpUserId", async () => {
    const admin = await adminLogin();
    const roles = await call(main.port, "POST", `/api/members/${ids.root}/roles`, { cookie: admin.cookie, csrf: admin.csrf, body: { roles: ["reader", "writer", "admin"], otp: GOOD_OTP } });
    assert.equal(roles.status, 403);
    const otp = await call(main.port, "POST", `/api/members/${ids.root}/otp-user`, { cookie: admin.cookie, csrf: admin.csrf, body: { otpUserId: "ks-mine", otp: GOOD_OTP } });
    assert.equal(otp.status, 403);
    assert.match(String(otp.body.error), /another admin must/);
  });

  it("otp-user refuses a KeyStone user mapped to another certificate, or held by another member", async () => {
    const id = await seed(store, "otto", ["reader", "writer"]);
    const admin = await adminLogin();
    const cert = await call(main.port, "POST", `/api/members/${id}/otp-user`, { cookie: admin.cookie, csrf: admin.csrf, body: { otpUserId: "ks-cert-alice", otp: GOOD_OTP } });
    assert.equal(cert.status, 409);
    assert.match(String(cert.body.error), /belongs to certificate ops-alice/);
    const member = await call(main.port, "POST", `/api/members/${id}/otp-user`, { cookie: admin.cookie, csrf: admin.csrf, body: { otpUserId: "ks-wade", otp: GOOD_OTP } });
    assert.equal(member.status, 409);
    assert.match(String(member.body.error), /already used by another member/);
    const ok = await call(main.port, "POST", `/api/members/${id}/otp-user`, { cookie: admin.cookie, csrf: admin.csrf, body: { otpUserId: "ks-otto", otp: GOOD_OTP } });
    assert.equal(ok.status, 200);
  });

  it("sets an otpUserId and refuses a CN removal that would clash with an operator CN", async () => {
    const id = await seed(store, "ops-alice", ["reader"], { certCNs: ["ops-alice"] });
    const admin = await adminLogin();
    const otp = await call(main.port, "POST", `/api/members/${id}/otp-user`, { cookie: admin.cookie, csrf: admin.csrf, body: { otpUserId: "ks-alice", otp: GOOD_OTP } });
    assert.equal(otp.status, 200);
    assert.equal((otp.body.member as { otpUserId: string }).otpUserId, "ks-alice");
    const rm = await call(main.port, "POST", `/api/members/${id}/cert-cns`, { cookie: admin.cookie, csrf: admin.csrf, body: { remove: "ops-alice", otp: GOOD_OTP } });
    assert.equal(rm.status, 409, JSON.stringify(rm.body));
  });
});

describe("limits", () => {
  it("refuses an address past ten sign-ins a minute (429)", async () => {
    skewMs += 61_000;
    const statuses: number[] = [];
    for (let i = 0; i < 11; i++) {
      statuses.push((await call(main.port, "POST", "/auth/password/login", { body: { username: `limit-${i}`, password: PASSWORD } })).status);
    }
    assert.deepEqual(statuses, [...Array(10).fill(401), 429]);
  });

  it("makes an account wait after five failures, even for the right password", async () => {
    await seed(store, "dora", ["reader"]);
    skewMs += 61_000;
    for (let i = 0; i < 5; i++) {
      assert.equal((await call(main.port, "POST", "/auth/password/login", { body: { username: "dora", password: "wrong wrong wrong" } })).status, 401);
    }
    const r = await call(main.port, "POST", "/auth/password/login", { body: { username: "dora", password: PASSWORD } });
    assert.equal(r.status, 429);
    assert.match(String(r.body.error), /failed sign-ins/);
  });
});

describe("startup", () => {
  async function refusal(storeFile: string, extra: Partial<Parameters<typeof startManager>[0]> = {}): Promise<string | null> {
    let started: Started | null = null;
    try { started = await start(storeFile, extra); return null; } catch (e) { return (e as Error).message; } finally { started?.close(); }
  }

  it("refuses to start without the store", async () => {
    assert.match(String(await refusal(join(dir, "absent.json"))), /member store is unavailable/);
  });

  it("refuses a principalName that is an unbound operator or writer CN, or an alias target", async () => {
    const cnStore = join(dir, "clash-cn.json");
    initializeMemberDocument(cnStore);
    withMemberTransaction(cnStore, (d) => createMember(d, { username: "ops-alice", status: "active", roles: ["reader"] }, { actor: "cli" }));
    assert.match(String(await refusal(cnStore)), /principalName ops-alice is an operator or writer certificate CN/);

    const bound = join(dir, "bound-cn.json");
    initializeMemberDocument(bound);
    withMemberTransaction(bound, (d) => createMember(d, { username: "ops-alice", status: "active", roles: ["reader"], certCNs: ["ops-alice"] }, { actor: "cli" }));
    assert.equal(await refusal(bound), null, "a member bound to its own CN may carry that name");

    const aliasStore = join(dir, "clash-alias.json");
    initializeMemberDocument(aliasStore);
    withMemberTransaction(aliasStore, (d) => createMember(d, { username: "ops-alias", status: "active", roles: ["reader"] }, { actor: "cli" }));
    assert.match(String(await refusal(aliasStore)), /OIDC alias target/);
  });

  it("requires a store file in shadow", async () => {
    assert.match(String(await refusal(store, { members: { mode: "shadow" } })), /requires members\.storeFile/);
  });
});

describe("off", () => {
  it("serves no member route and leaves the certificate path as it was", async () => {
    const off = await start(store, {}, "off");
    try {
      assert.equal((await call(off.port, "POST", "/auth/password/login", { body: { username: "rita", password: PASSWORD } })).status, 404);
      assert.equal((await call(off.port, "GET", "/api/me", { cert: true, origin: null })).status, 404);
      assert.equal((await call(off.port, "GET", "/site", { cert: true, origin: null })).status, 200);
    } finally { off.close(); }
  });
});

describe("state that changes while a check is in flight", () => {
  it("a sign-in whose member changed during the check is refused", async () => {
    const id = await seed(store, "tomo", ["reader", "writer"], { otpUserId: "ks-tomo" });
    duringOtp["ks-tomo"] = () => withMemberTransaction(store, (d) => suspendMember(d, id, { actor: "cli" }));
    try {
      skewMs += 61_000;
      const r = await call(main.port, "POST", "/auth/password/login", { body: { username: "tomo", password: PASSWORD, otp: GOOD_OTP } });
      assert.equal(r.status, 401);
      assert.deepEqual(r.body, { error: "invalid username or password" });
      assert.deepEqual(r.setCookie, []);
    } finally { delete duringOtp["ks-tomo"]; }
  });

  it("a reset whose member changed during the check is refused", async () => {
    const id = await seed(store, "tita", ["reader", "writer"], { otpUserId: "ks-tita" });
    await login(main.port, "tita", PASSWORD, GOOD_OTP);
    const admin = await adminLogin();
    const issued = await call(main.port, "POST", `/api/members/${id}/password-reset`, { cookie: admin.cookie, csrf: admin.csrf, body: { otp: GOOD_OTP } });
    const token = String(issued.body.resetUrl).split("/reset/")[1]!;
    duringOtp["ks-tita"] = () => withMemberTransaction(store, (d) => setOtpUserId(d, id, "ks-tita-2", { actor: "cli" }));
    try {
      const r = await call(main.port, "POST", "/auth/password/reset", { body: { token, password: NEW_PASSWORD, otp: GOOD_OTP } });
      assert.equal(r.status, 409, JSON.stringify(r.body));
    } finally { delete duringOtp["ks-tita"]; }
    skewMs += 61_000;
    assert.equal((await call(main.port, "POST", "/auth/password/login", { body: { username: "tita", password: NEW_PASSWORD, otp: GOOD_OTP } })).status, 401);
  });

  it("a reset of a writer whose otpUserId is unconfirmed is refused", async () => {
    const id = await seed(store, "uma", ["reader", "writer"], { otpUserId: "ks-uma" });
    const admin = await adminLogin();
    const issued = await call(main.port, "POST", `/api/members/${id}/password-reset`, { cookie: admin.cookie, csrf: admin.csrf, body: { otp: GOOD_OTP } });
    const token = String(issued.body.resetUrl).split("/reset/")[1]!;
    const r = await call(main.port, "POST", "/auth/password/reset", { body: { token, password: NEW_PASSWORD, otp: GOOD_OTP } });
    assert.equal(r.status, 403);
    assert.match(String(r.body.error), /not confirmed/);
  });
});

describe("session budgets", () => {
  it("a sixth sign-in ends the member's oldest session", async () => {
    await seed(store, "sixer", ["reader"]);
    const logins = [];
    for (let i = 0; i < 6; i++) logins.push(await login(main.port, "sixer"));
    assert.equal((await call(main.port, "GET", "/api/me", { cookie: logins[0]!.cookie })).status, 401);
    const list = await call(main.port, "GET", "/api/me/sessions", { cookie: logins[5]!.cookie });
    assert.equal((list.body.sessions as unknown[]).length, 5);
  });

  it("refuses a sixth wrong current password in the window", async () => {
    await seed(store, "pia", ["reader"]);
    const s = await login(main.port, "pia");
    for (let i = 0; i < 5; i++) {
      assert.equal((await call(main.port, "POST", "/api/me/password", { cookie: s.cookie, csrf: s.csrf, body: { current: "wrong wrong wrong", next: NEW_PASSWORD } })).status, 403);
    }
    const r = await call(main.port, "POST", "/api/me/password", { cookie: s.cookie, csrf: s.csrf, body: { current: PASSWORD, next: NEW_PASSWORD } });
    assert.equal(r.status, 429);
  });
});

describe("addresses", () => {
  it("normalizes IPv4-mapped addresses and an IPv6 /64", () => {
    assert.equal(normalizeSource("::ffff:192.0.2.3"), "192.0.2.3");
    assert.equal(normalizeSource("192.0.2.3"), "192.0.2.3");
    assert.equal(normalizeSource("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64");
    assert.equal(normalizeSource("2001:db8:1:2:ffff:ffff:ffff:ffff"), "2001:db8:1:2::/64");
    assert.equal(normalizeSource("2001:db8::1"), "2001:db8:0:0::/64");
    assert.equal(normalizeSource(undefined), "unknown");
  });

  it("a flood of new names does not evict an account that is waiting", () => {
    const failures = new Map<string, { count: number; until: number }>();
    for (let i = 0; i < 5; i++) recordFailureIn(failures, "target", 1_000, 8);
    for (let i = 0; i < 50; i++) recordFailureIn(failures, `noise-${i}`, 2_000, 8);
    assert.equal(failures.size, 8);
    assert.ok((failures.get("target")?.until ?? 0) > 1_000, "the waiting entry survived the flood");
  });

  it("another address's failures do not make the owner wait", async () => {
    // The source is injected, so two addresses need no second listener.
    const ds = await start(store, { members: { mode: "shadow", storeFile: store, sourceOf: (req) => String(req.headers["x-test-source"] ?? "none") } });
    const as = (from: string, password: string) =>
      call(ds.port, "POST", "/auth/password/login", { headers: { "x-test-source": from }, body: { username: "owen", password } });
    try {
      await seed(store, "owen", ["reader"]);
      skewMs += 61_000;
      for (let i = 0; i < 5; i++) assert.equal((await as("192.0.2.1", "wrong wrong wrong")).status, 401);
      assert.equal((await as("192.0.2.1", PASSWORD)).status, 429, "the failing address waits");
      assert.equal((await as("192.0.2.2", PASSWORD)).status, 200, "the owner from elsewhere does not");
    } finally { ds.close(); }
  });

  it("failures from many sources reach the account cap; a known source still signs in", async () => {
    const ds = await start(store, { members: { mode: "shadow", storeFile: store, sourceOf: (req) => String(req.headers["x-test-source"] ?? "none") } });
    const as = (from: string, password: string) =>
      call(ds.port, "POST", "/auth/password/login", { headers: { "x-test-source": from }, body: { username: "cappy", password } });
    try {
      await seed(store, "cappy", ["reader"]);
      skewMs += 61_000;
      assert.equal((await as("198.51.100.200", PASSWORD)).status, 200, "the owner's address, trusted from here on");
      // Eleven sources, five failures each (under each source's own wait): 55 for one account.
      for (let src = 0; src < 11; src++) {
        for (let i = 0; i < 5; i++) {
          const r = await as(`198.51.100.${src}`, "wrong wrong wrong");
          if (src * 5 + i < 50) assert.equal(r.status, 401, `failure ${src * 5 + i + 1}`);
          else assert.equal(r.status, 429, `failure ${src * 5 + i + 1} is past the account cap`);
        }
      }
      const fresh = await as("198.51.100.99", PASSWORD);
      assert.equal(fresh.status, 429);
      assert.match(String(fresh.body.error), /try again later/);
      assert.equal((await as("198.51.100.200", PASSWORD)).status, 200, "a source that signed in before is exempt");
    } finally { ds.close(); }
  });
});

describe("the sign-in audit", () => {
  it("keeps only the newest sign-in audit rows", async () => {
    const audited = join(dir, "audited.json");
    initializeMemberDocument(audited);
    await seed(audited, "aud", ["reader"]);
    const d = loadMemberDocument(audited);
    for (let i = 0; i < MEMBER_LOGIN_AUDIT_MAX; i++) {
      d.audit.push({ at: new Date(Date.UTC(2026, 0, 1, 0, 0, i % 60)).toISOString(), actor: "old", action: "member.login", target: "old", sourceIp: null });
    }
    saveMemberDocument(audited, d);
    const server = await start(audited);
    try {
      skewMs += 61_000;
      assert.equal((await call(server.port, "POST", "/auth/password/login", { body: { username: "aud", password: PASSWORD } })).status, 200);
      const after = loadMemberDocument(audited).audit;
      const logins = after.filter((a) => a.action === "member.login");
      assert.equal(logins.length, MEMBER_LOGIN_AUDIT_MAX);
      assert.notEqual(logins.at(-1)!.actor, "old");
      assert.ok(after.some((a) => a.action === "member.create"), "other rows are kept");
    } finally { server.close(); }
  });

  it("off ignores the members' public origin", async () => {
    const off = await start(store, {
      oidc: {
        issuer: "https://idp.example.invalid", clientId: "c", redirectUri: "http://heliopause.example.invalid/auth/callback",
        roleChangeEvent: ROLE_CHANGE_EVENT, operatorGroups: ["o"], writerGroups: ["w"], aliases: new Map(), fetchImpl: idpFetch,
      },
    }, "off");
    off.close();
  });

  it("refuses an OIDC redirect URI that is not https, since links are built on it", async () => {
    let started: Started | null = null;
    let error: unknown = null;
    try {
      started = await start(store, {
        oidc: {
          issuer: "https://idp.example.invalid", clientId: "c", redirectUri: "http://heliopause.example.invalid/auth/callback",
          roleChangeEvent: ROLE_CHANGE_EVENT, operatorGroups: ["o"], writerGroups: ["w"], aliases: new Map(), fetchImpl: idpFetch,
        },
      });
    } catch (e) { error = e; } finally { started?.close(); }
    assert.match(String((error as Error | null)?.message), /public origin must be https/);
  });
});

// ── One human, two doors: approval and merge compare people by KeyStone user ──────────────────────
describe("approval compares people, not names", () => {
  const apStore = join(dir, "approval.json");
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const ghKey = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs1", format: "pem" }, publicKeyEncoding: { type: "pkcs1", format: "pem" } }).privateKey;
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  let mintNonce = "";
  let prProposer = "henry";
  let server: Started;

  const idp = (async (u: string | URL) => {
    const url = String(u);
    if (url.endsWith("/.well-known/openid-configuration")) {
      return new Response(JSON.stringify({
        issuer: "https://idp.example.invalid", authorization_endpoint: "https://idp.example.invalid/oidc/authorize",
        token_endpoint: "https://idp.example.invalid/oidc/token", jwks_uri: "https://idp.example.invalid/oidc/jwks",
        code_challenge_methods_supported: ["S256"],
      }), { status: 200 });
    }
    if (url.endsWith("/oidc/jwks")) {
      return new Response(JSON.stringify({ keys: [{ ...publicKey.export({ format: "jwk" }), kid: "k1", use: "sig", alg: "ES256" }] }), { status: 200 });
    }
    const t = Math.floor(Date.now() / 1000);
    const header = b64({ alg: "ES256", kid: "k1", typ: "JWT" });
    // The KeyStone user id is the OIDC subject, and here it is henry's member otpUserId.
    const payload = b64({
      iss: "https://idp.example.invalid", aud: "heliopause-manager", sub: "ks-henry", nonce: mintNonce, exp: t + 300, iat: t,
      email: "jang@example.invalid", email_verified: true, groups: ["heliopause-operators", "heliopause-writers"],
    });
    const sig = createSign("sha256").update(`${header}.${payload}`).sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    return new Response(JSON.stringify({ id_token: `${header}.${payload}.${sig}` }), { status: 200 });
  }) as unknown as typeof fetch;

  const ghFetch = (async (url: string, init?: { method?: string }) => {
    const method = init?.method ?? "GET";
    const r = (status: number, body: unknown) => ({ ok: status < 400, status, text: async () => JSON.stringify(body) });
    if (method === "POST" && /access_tokens$/.test(url)) return r(200, { token: "t" });
    if (method === "GET" && /pulls\/7$/.test(url)) {
      return r(200, {
        number: 7, html_url: "https://example.invalid/pull/7", state: "open", merged: false,
        head: { sha: "a".repeat(40), ref: "policy/x" }, base: { sha: "b", ref: "main" }, mergeable: true, mergeable_state: "clean",
        body: `heliopause-proposed-by: \`${prProposer}\``,
      });
    }
    if (method === "GET" && /check-runs/.test(url)) return r(200, { total_count: 1, check_runs: [{ name: "ci", status: "completed", conclusion: "success" }] });
    if (method === "GET" && /commits\/[0-9a-f]+\/status/.test(url)) return r(200, { statuses: [] });
    if (method === "PUT" && /pulls\/7\/merge$/.test(url)) return r(200, { merged: true, sha: "d".repeat(40) });
    throw new Error(`no route for ${method} ${url}`);
  }) as unknown as NonNullable<Parameters<typeof startManager>[0]["policyWrite"]>["fetch"];

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

  before(async () => {
    initializeMemberDocument(apStore);
    await seed(apStore, "henry", ["reader", "writer"], { otpUserId: "ks-henry" });
    await seed(apStore, "bobby", ["reader", "writer"], { otpUserId: "ks-bobby", certCNs: ["ops-bob"] });
    for (let i = 0; i < 13; i++) await seed(apStore, `crowd-${i}`, ["reader"]);
    withMemberTransaction(apStore, (d) => { for (const m of d.members) if (m.otpUserId) confirmOtp(d, m.id, m.otpUserId, { actor: "cli" }); });
    server = await start(apStore, {
      operatorCNs: ["ops-alice", "ops-bob"], writerCNs: ["ops-alice", "ops-bob"],
      otp: {
        issuerUrl: "https://otp.example.invalid", serviceToken: "svc", fetchImpl: otpFetch,
        // ops-alice is henry's certificate by KeyStone user; ops-bob is bobby's by certCN binding only.
        users: new Map([["ops-alice", "ks-henry"], ["ops-bob", "ks-bob-cert"]]),
      },
      oidc: {
        issuer: "https://idp.example.invalid", clientId: "heliopause-manager",
        redirectUri: "https://heliopause.example.invalid/auth/callback", roleChangeEvent: ROLE_CHANGE_EVENT,
        operatorGroups: ["heliopause-operators"], writerGroups: ["heliopause-writers"],
        aliases: new Map([["jang@example.invalid", "ops-alias"]]), fetchImpl: idp,
      },
      policyWrite: { creds: { appId: "1", installationId: "2", privateKey: ghKey }, target: { owner: "o", repo: "r", base: "main" }, allowPaths: ["policies.json"], fetch: ghFetch },
    });
  });
  after(() => server?.close());

  const certCall = (who: "ops" | "bob", method: string, path: string, body?: unknown) => new Promise<Reply>((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const r = request({
      host: "127.0.0.1", port: server.port, path, method, ca: [read("ca.pem")], agent: false, cert: read(`${who}.pem`), key: read(`${who}.key`),
      headers: payload ? { "content-type": "application/json", "content-length": String(Buffer.byteLength(payload)) } : {},
      signal: AbortSignal.timeout(10_000),
    }, (res) => {
      let b = ""; res.on("data", (d) => (b += d));
      res.on("end", () => { let j: Record<string, unknown> = {}; try { j = JSON.parse(b); } catch { j = { raw: b }; } resolve({ status: res.statusCode ?? 0, body: j, setCookie: [] }); });
    });
    r.on("error", reject); if (payload) r.write(payload); r.end();
  });

  async function oidcSession(): Promise<{ cookie: string; csrf: string }> {
    const locationReply = await new Promise<{ location: string; cookies: string }>((resolve, reject) => {
      const r = request({ host: "127.0.0.1", port: server.port, path: "/auth/login", method: "GET", ca: [read("ca.pem")], agent: false }, (res) => {
        res.resume();
        res.on("end", () => resolve({
          location: String(res.headers.location ?? ""),
          cookies: ([] as string[]).concat((res.headers["set-cookie"] as string[]) ?? []).map((c) => c.split(";")[0]!).join("; "),
        }));
      });
      r.on("error", reject); r.end();
    });
    const q = new URL(locationReply.location).searchParams;
    mintNonce = q.get("nonce")!;
    const cb = await call(server.port, "GET", `/auth/callback?code=any&state=${encodeURIComponent(q.get("state")!)}`, { origin: null, cookie: locationReply.cookies });
    assert.equal(cb.status, 302, JSON.stringify(cb.body));
    const cookie = cookieOf(cb);
    const authz = await call(server.port, "GET", "/authz", { origin: null, cookie });
    return { cookie, csrf: String(authz.body.csrf) };
  }

  const propose = async (by: { cookie: string; csrf: string } | "ops" | "bob", generation: string): Promise<string> => {
    const body = { target: "dev", bundle: bundle(generation) };
    const r = typeof by === "string" ? await certCall(by, "POST", "/plan", body) : await call(server.port, "POST", "/plan", { cookie: by.cookie, csrf: by.csrf, body });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    return String(r.body.hash);
  };

  it("a member and their own certificate are one approver", async () => {
    const henry = await login(server.port, "henry", PASSWORD, GOOD_OTP);
    const hash = await propose(henry, "gen-member-then-cert");
    const r = await certCall("ops", "POST", "/approve", { hash, otp: GOOD_OTP });
    assert.equal(r.status, 403, JSON.stringify(r.body));
    assert.match(String(r.body.error), /same person as henry/);
    // And the other way round.
    const hash2 = await propose("ops", "gen-cert-then-member");
    const back = await call(server.port, "POST", "/approve", { cookie: henry.cookie, csrf: henry.csrf, body: { hash: hash2, otp: GOOD_OTP } });
    assert.equal(back.status, 403, JSON.stringify(back.body));
  });

  it("a member and the certificate bound to them are one approver", async () => {
    const bobby = await login(server.port, "bobby", PASSWORD, GOOD_OTP);
    const hash = await propose(bobby, "gen-bound-cert");
    const r = await certCall("bob", "POST", "/approve", { hash, otp: GOOD_OTP });
    assert.equal(r.status, 403, JSON.stringify(r.body));
    assert.match(String(r.body.error), /same person as bobby/);
  });

  it("a member and an OIDC session whose subject is their KeyStone user are one approver", async () => {
    const henry = await login(server.port, "henry", PASSWORD, GOOD_OTP);
    const hash = await propose(henry, "gen-member-then-oidc");
    const oidc = await oidcSession();
    const r = await call(server.port, "POST", "/approve", { cookie: oidc.cookie, csrf: oidc.csrf, body: { hash, otp: GOOD_OTP } });
    assert.equal(r.status, 403, JSON.stringify(r.body));
    assert.match(String(r.body.error), /same person as henry/);
  });

  it("the proposer's KeyStone user is kept on the plan, so re-pointing it afterwards does not free the approval", async () => {
    const id = loadMemberDocument(apStore).members.find((m) => m.username === "henry")!.id;
    const henry = await login(server.port, "henry", PASSWORD, GOOD_OTP);
    const hash = await propose(henry, "gen-repointed");
    // After the proposal, henry's member record no longer names ks-henry, so no name links henry to
    // ops-alice any more. Only the KeyStone user recorded on the plan does.
    withMemberTransaction(apStore, (d) => setOtpUserId(d, id, "ks-henry-new", { actor: "cli" }));
    try {
      const r = await certCall("ops", "POST", "/approve", { hash, otp: GOOD_OTP });
      assert.equal(r.status, 403, JSON.stringify(r.body));
      assert.match(String(r.body.error), /same person as henry/);
    } finally {
      withMemberTransaction(apStore, (d) => { setOtpUserId(d, id, "ks-henry", { actor: "cli" }); confirmOtp(d, id, "ks-henry", { actor: "cli" }); });
    }
  });

  it("a different person still approves", async () => {
    const henry = await login(server.port, "henry", PASSWORD, GOOD_OTP);
    const hash = await propose(henry, "gen-two-people");
    const r = await certCall("bob", "POST", "/approve", { hash, otp: GOOD_OTP });
    assert.equal(r.status, 200, JSON.stringify(r.body));
  });

  it("refuses a self-merge across a member and their certificate", async () => {
    prProposer = "henry";
    const pr = await certCall("ops", "GET", "/policy/pr?number=7");
    assert.equal(pr.status, 200, JSON.stringify(pr.body));
    assert.equal(pr.body.mayMerge, false);
    assert.match(String(pr.body.why), /same person/);
    const merge = await certCall("ops", "POST", "/policy/merge", { number: 7, otp: GOOD_OTP });
    assert.equal(merge.status, 409);
    prProposer = "ops-alice";
    const henry = await login(server.port, "henry", PASSWORD, GOOD_OTP);
    const back = await call(server.port, "POST", "/policy/merge", { cookie: henry.cookie, csrf: henry.csrf, body: { number: 7, otp: GOOD_OTP } });
    assert.equal(back.status, 409, JSON.stringify(back.body));
    prProposer = "ops-bob";
    const other = await call(server.port, "POST", "/policy/merge", { cookie: henry.cookie, csrf: henry.csrf, body: { number: 7, otp: GOOD_OTP } });
    assert.equal(other.status, 200, JSON.stringify(other.body));
  });

  it("password sign-ins cannot evict an OIDC session", async () => {
    const oidc = await oidcSession();
    for (let i = 0; i < 13; i++) for (let j = 0; j < 5; j++) await login(server.port, `crowd-${i}`);
    assert.equal((await call(server.port, "GET", "/authz", { origin: null, cookie: oidc.cookie })).status, 200);
  });
});
