// Reset and invite mail, against a real TLS manager in `shadow` and a fake SMTP relay speaking
// implicit TLS (the pattern of `mail.test.ts`, reduced to what these cases need).
//
// Every wait here is bounded: the HTTP calls carry `AbortSignal.timeout`, and waiting for a mail or
// a log line polls for at most a few seconds and then fails by name. A hang is not a red.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:https";
import { execFileSync } from "node:child_process";
import { createServer, type Server, type TLSSocket } from "node:tls";
import { startManager } from "./manager-server.ts";
import { RESET_MAILS_PER_MEMBER, RESET_REQUESTED, RESET_REQUESTS_PER_SOURCE } from "./member-auth.ts";
import {
  createMember, initializeMemberDocument, loadMemberDocument, setPassword, suspendMember, withMemberTransaction,
  type MemberRole,
} from "./member-store.ts";
import { hashPassword } from "./password.ts";
import type { MailConfig } from "./mail.ts";

const PASSWORD = "Correct horse battery staple";
const NEW_PASSWORD = "An entirely different passphrase";
const GOOD_OTP = "123456";
const ORIGIN = "https://heliopause.example.invalid";

const dir = mkdtempSync(join(tmpdir(), "hp-member-mail-"));
const read = (f: string) => readFileSync(join(dir, f));

function pki() {
  const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=test-ca");
  run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=manager");
  writeFileSync(join(dir, "server.ext"), "extendedKeyUsage=critical,serverAuth\nsubjectAltName=IP:127.0.0.1\n");
  run("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.pem", "-days", "1", "-extfile", "server.ext");
}

// ── the fake relay ────────────────────────────────────────────────────────────────────────────

interface Received { to: string; text: string; headers: string }
const received: Received[] = [];
/** Recipient → how the relay refuses it: at `RCPT` (550), or after taking the data (554 at end of data). */
const refuseFor: Record<string, "rcpt" | "data-end"> = {
  "fail@example.com": "data-end",
  "bounce@example.com": "rcpt",
};
/** The next connection gets no greeting until the test destroys it. */
let stallNext = false;
const stalled: TLSSocket[] = [];
const relaySockets = new Set<TLSSocket>();
let relay: Server;
let relayPort = 0;

function decode(data: string): Received {
  const [headers = "", body = ""] = data.split("\r\n\r\n");
  const to = /^To: <([^>]+)>$/m.exec(headers)?.[1] ?? "";
  return { to, headers, text: Buffer.from(body.replace(/\r\n/g, ""), "base64").toString("utf8") };
}

function startRelay(): Promise<void> {
  relay = createServer({ key: read("server.key"), cert: read("server.pem") }, (s) => {
    relaySockets.add(s);
    s.on("error", () => {});
    s.on("close", () => relaySockets.delete(s));
    if (stallNext) { stallNext = false; stalled.push(s); return; }
    s.write("220 relay ready\r\n");
    let buf = "";
    let inData = false;
    let rcpt = "";
    s.on("data", (d) => {
      buf += d.toString("latin1");
      for (;;) {
        if (inData) {
          const end = buf.indexOf("\r\n.\r\n");
          if (end < 0) return;
          const got = decode(buf.slice(0, end + 2));
          buf = buf.slice(end + 5);
          inData = false;
          received.push(got);
          s.write(refuseFor[rcpt] === "data-end" ? "554 rejected\r\n" : "250 queued\r\n");
          continue;
        }
        const nl = buf.indexOf("\r\n");
        if (nl < 0) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        const verb = line.split(" ")[0]!.toUpperCase();
        if (verb === "EHLO") s.write("250-relay\r\n250 AUTH PLAIN\r\n");
        else if (verb === "MAIL") s.write("250 ok\r\n");
        else if (verb === "RCPT") {
          rcpt = /<([^>]+)>/.exec(line)?.[1] ?? "";
          s.write(refuseFor[rcpt] === "rcpt" ? "550 no such user\r\n" : "250 ok\r\n");
        }
        else if (verb === "DATA") { s.write("354 go\r\n"); inData = true; }
        else if (verb === "QUIT") { s.write("221 bye\r\n"); s.end(); }
        else s.write("502 unknown\r\n");
      }
    });
  });
  return new Promise((r) => relay.listen(0, "127.0.0.1", () => { relayPort = (relay.address() as { port: number }).port; r(); }));
}

// ── managers ──────────────────────────────────────────────────────────────────────────────────

const otpFetch = (async (_u: string | URL, init?: { body?: string }) => {
  const body = JSON.parse(String(init?.body ?? "{}")) as { code: string };
  return body.code === GOOD_OTP
    ? new Response(JSON.stringify({ ok: true }), { status: 200 })
    : new Response(JSON.stringify({ ok: false }), { status: 401 });
}) as unknown as typeof fetch;

const logs: string[] = [];
let skewMs = 0;
const clock = () => new Date(Date.now() + skewMs);
type Started = { port: number; close: () => void };
async function start(store: string, mail: MailConfig | null): Promise<Started> {
  const started = await startManager({
    port: 0, hostname: "127.0.0.1",
    relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
    tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
    operatorCNs: ["ops-alice"], writerCNs: ["ops-alice"],
    timeoutMs: 200,
    otp: { issuerUrl: "https://otp.example.invalid", serviceToken: "svc", users: new Map(), fetchImpl: otpFetch },
    members: {
      mode: "shadow", storeFile: store, publicOrigin: ORIGIN,
      // Each request names its own source, so the per-address limit is reached only where a case means to.
      sourceOf: (req) => String(req.headers["x-test-source"] ?? "default"),
      // No random wait here: a case that checks nothing happened needs the work done by its next round trip.
      resetDelayMs: () => 0,
      ...(mail ? { mail } : {}),
    },
    log: (m) => logs.push(m),
    now: clock,
  });
  return {
    port: (started.server.address() as { port: number }).port,
    close: () => { started.stopProblemWatch(); started.server.closeAllConnections(); started.server.close(); },
  };
}

interface Reply { status: number; raw: string; body: Record<string, unknown>; setCookie: string[] }
let sourceSeq = 0;
function call(port: number, method: string, path: string, o: {
  body?: unknown; cookie?: string; csrf?: string; origin?: string | null; source?: string;
} = {}): Promise<Reply> {
  const payload = o.body === undefined ? undefined : JSON.stringify(o.body);
  const headers: Record<string, string> = {
    ...(o.origin === null ? {} : { origin: o.origin ?? `https://127.0.0.1:${port}` }),
    "x-test-source": o.source ?? `s${++sourceSeq}`,
    ...(payload !== undefined ? { "content-type": "application/json", "content-length": String(Buffer.byteLength(payload)) } : {}),
    ...(o.cookie ? { cookie: o.cookie } : {}),
    ...(o.csrf ? { "x-heliopause-csrf": o.csrf } : {}),
  };
  return new Promise((resolve, reject) => {
    const r = request({
      host: "127.0.0.1", port, path, method, ca: [read("ca.pem")], headers, agent: false,
      signal: AbortSignal.timeout(5_000),
    }, (res) => {
      let b = ""; res.on("data", (d) => (b += d));
      res.on("end", () => {
        let body: Record<string, unknown> = {};
        try { body = JSON.parse(b) as Record<string, unknown>; } catch { body = { raw: b }; }
        resolve({ status: res.statusCode ?? 0, raw: b, body, setCookie: ([] as string[]).concat((res.headers["set-cookie"] as string[]) ?? []) });
      });
    });
    r.on("error", reject);
    if (payload !== undefined) r.write(payload);
    r.end();
  });
}

/** Poll `check` until it is truthy; fail naming `what` after `ms`. */
async function waitFor<T>(what: string, check: () => T | undefined | false | null, ms = 5_000): Promise<T> {
  const deadline = Date.now() + ms;
  for (;;) {
    const v = check();
    if (v) return v;
    if (Date.now() > deadline) assert.fail(`still waiting for ${what} after ${ms}ms`);
    await new Promise((r) => setTimeout(r, 20));
  }
}
const mailsTo = (to: string): Received[] => received.filter((m) => m.to === to);
const linkIn = (m: Received): string => {
  const link = /https:\/\/\S+/.exec(m.text)?.[0];
  assert.ok(link, `no link in ${m.text}`);
  return link;
};
const resetRequest = (port: number, login: string, source?: string) =>
  call(port, "POST", "/auth/password/reset-request", { body: { login }, ...(source ? { source } : {}) });

async function seed(store: string, username: string, roles: MemberRole[], o: { verified?: boolean; otpUserId?: string } = {}): Promise<string> {
  const hash = await hashPassword(PASSWORD);
  return withMemberTransaction(store, (d) => {
    const m = createMember(d, {
      username, email: `${username}@example.com`, emailVerified: o.verified !== false, status: "active", roles,
      otpUserId: o.otpUserId ?? null,
    }, { actor: "cli" });
    setPassword(d, m.id, hash, { mustChange: false }, { actor: "cli" });
    return m.id;
  });
}
const unusedResetTokens = (store: string, memberId: string) =>
  loadMemberDocument(store).tokens.filter((t) => t.kind === "password-reset" && t.memberId === memberId && t.usedAt === null);

async function login(port: number, username: string, password: string, otp?: string): Promise<{ cookie: string; csrf: string }> {
  const r = await call(port, "POST", "/auth/password/login", { body: { username, password, ...(otp ? { otp } : {}) } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const c = r.setCookie.find((x) => x.startsWith("__Host-heliopause-session="));
  assert.ok(c);
  return { cookie: c.split(";")[0]!, csrf: String(r.body.csrf) };
}

const store = join(dir, "members.json");
const quietStore = join(dir, "members-nomail.json");
let main: Started;
let quiet: Started;
const ids: Record<string, string> = {};
const unhandled: unknown[] = [];
const onUnhandled = (e: unknown) => { unhandled.push(e); };

before(async () => {
  pki();
  await startRelay();
  process.on("unhandledRejection", onUnhandled);
  initializeMemberDocument(store);
  ids.root = await seed(store, "root", ["reader", "writer", "admin"], { otpUserId: "ks-root" });
  ids.vera = await seed(store, "vera", ["reader"]);
  ids.unv = await seed(store, "unv", ["reader"], { verified: false });
  ids.susp = await seed(store, "susp", ["reader"]);
  withMemberTransaction(store, (d) => suspendMember(d, ids.susp!, { actor: "cli" }));
  ids.lim = await seed(store, "lim", ["reader"]);
  ids.fail = await seed(store, "fail", ["reader"]);
  ids.slow = await seed(store, "slow", ["reader"]);
  ids.kp = await seed(store, "kp", ["reader"]);
  ids.lockd = await seed(store, "lockd", ["reader"]);
  for (const name of ["adm", "kp2", "kp3", "kp4", "burn", "ps1", "ps2", "ps3", "ps4"]) ids[name] = await seed(store, name, ["reader"]);
  // SSO only: a verified address and no password credential.
  ids.sso = withMemberTransaction(store, (d) => createMember(d, {
    username: "sso", email: "sso@example.com", emailVerified: true, status: "active", roles: ["reader"],
  }, { actor: "cli" }).id);
  initializeMemberDocument(quietStore);
  ids.qroot = await seed(quietStore, "root", ["reader", "writer", "admin"], { otpUserId: "ks-root" });
  ids.qvera = await seed(quietStore, "vera", ["reader"]);
  main = await start(store, { host: "127.0.0.1", port: relayPort, from: "heliopause@example.net", ca: read("ca.pem").toString() });
  quiet = await start(quietStore, null);
});

after(() => {
  process.off("unhandledRejection", onUnhandled);
  main?.close();
  quiet?.close();
  for (const s of relaySockets) s.destroy();
  relay?.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("self-service password reset by mail", () => {
  it("mails a verified member a link that works once", async () => {
    const r = await resetRequest(main.port, "vera");
    assert.equal(r.status, 202);
    assert.deepEqual(r.body, RESET_REQUESTED);
    const [m] = await waitFor("vera's reset mail", () => mailsTo("vera@example.com").length >= 1 && mailsTo("vera@example.com"));
    const link = linkIn(m!);
    assert.match(link, /^https:\/\/heliopause\.example\.invalid\/app\/reset#hpmem_[0-9a-f]{64}$/);
    // Plain text, Korean first, the expiry in both languages and the "did not ask" line.
    assert.match(m!.headers, /^Content-Type: text\/plain; charset=utf-8$/m);
    assert.match(m!.headers, /^From: <heliopause@example\.net>$/m);
    assert.ok(!/<html|<a /i.test(m!.text));
    assert.ok(m!.text.indexOf("비밀번호 재설정") < m!.text.indexOf("A password reset was requested"));
    assert.match(m!.text, /30분/);
    assert.match(m!.text, /30 minutes/);
    assert.match(m!.text, /요청하지 않았다면 이 메일을 무시하십시오/);
    assert.match(m!.text, /If you did not ask for this, ignore this mail/);

    const token = link.split("#")[1]!;
    const used = await call(main.port, "POST", "/auth/password/reset", { body: { token, password: NEW_PASSWORD } });
    assert.equal(used.status, 200, JSON.stringify(used.body));
    await login(main.port, "vera", NEW_PASSWORD);
    const again = await call(main.port, "POST", "/auth/password/reset", { body: { token, password: PASSWORD } });
    assert.equal(again.status, 400);
  });

  it("finds the account by email address too", async () => {
    const before = mailsTo("vera@example.com").length;
    assert.equal((await resetRequest(main.port, "  VERA@example.com ")).status, 202);
    await waitFor("vera's second reset mail", () => mailsTo("vera@example.com").length > before);
  });

  it("answers every reset request with the same 202, and mails only the verified active member", async () => {
    const before = received.length;
    const answers = [
      await resetRequest(main.port, "nobody-here"),
      await resetRequest(main.port, "nobody@example.com"),
      await resetRequest(main.port, "unv"),
      await resetRequest(main.port, "susp"),
      await resetRequest(main.port, "kp"),
    ];
    for (const a of answers) {
      assert.equal(a.status, 202);
      assert.equal(a.raw, answers[0]!.raw);
    }
    // Known positive: kp's mail arrives, and it is the only one these five requests caused.
    await waitFor("kp's mail", () => received.length > before && received.slice(before).some((m) => m.to === "kp@example.com"));
    assert.deepEqual(received.slice(before).map((m) => m.to), ["kp@example.com"]);
    assert.deepEqual(unusedResetTokens(store, ids.unv!), []);
    assert.deepEqual(unusedResetTokens(store, ids.susp!), []);
  });

  it("with mail not configured answers the same 202 and issues nothing", async () => {
    const before = received.length;
    const r = await resetRequest(quiet.port, "vera");
    assert.equal(r.status, 202);
    assert.equal(r.raw, JSON.stringify(RESET_REQUESTED));
    // A second round trip lets the first request's after-answer step run; it must have issued nothing.
    await resetRequest(quiet.port, "nobody-here");
    // No token was even issued: a withdrawn one would leave no row, so the audit is what is read.
    assert.deepEqual(loadMemberDocument(quietStore).audit.filter((a) => a.action === "token.issue.password-reset"), []);
    assert.equal(received.length, before);
  });

  it("answers before the mail is sent", async () => {
    stallNext = true;
    const r = await resetRequest(main.port, "slow");
    assert.equal(r.status, 202);
    const s = await waitFor("the stalled relay connection", () => stalled[0]);
    s.destroy();
    await waitFor("the stalled send's withdrawal", () => logs.find((l) => /reset mail for member .* failed at greeting .*withdrawn/.test(l) && l.includes(ids.slow!)));
    assert.deepEqual(unusedResetTokens(store, ids.slow!), []);
  });

  it("a failed send withdraws its token and rejects nothing unhandled", async () => {
    const r = await resetRequest(main.port, "fail");
    assert.equal(r.status, 202);
    // The relay took the data and then refused it, so the test holds the link the member may have got.
    const [m] = await waitFor("the refused mail's data", () => mailsTo("fail@example.com").length >= 1 && mailsTo("fail@example.com"));
    await waitFor("the withdrawal log line", () => logs.find((l) => l.includes(`reset mail for member ${ids.fail} failed at data-end (554); its link was withdrawn`)));
    assert.deepEqual(unusedResetTokens(store, ids.fail!), []);
    const token = linkIn(m!).split("#")[1]!;
    const tried = await call(main.port, "POST", "/auth/password/reset", { body: { token, password: NEW_PASSWORD } });
    assert.equal(tried.status, 400);
    assert.deepEqual(unhandled, []);
  });

  it("a request leaves an outstanding link alone, an admin's included", async () => {
    const admin = await login(main.port, "root", PASSWORD, GOOD_OTP);
    const issued = await call(main.port, "POST", `/api/members/${ids.adm}/password-reset`, { cookie: admin.cookie, csrf: admin.csrf, body: { otp: GOOD_OTP } });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const adminToken = String(issued.body.resetUrl).split("#")[1]!;
    const tokensBefore = unusedResetTokens(store, ids.adm!).map((t) => t.id);
    assert.equal(tokensBefore.length, 1);
    const before = received.length;
    assert.deepEqual((await resetRequest(main.port, "adm")).body, RESET_REQUESTED);
    // Known positive after it: kp2's mail arrives, and adm got none.
    await resetRequest(main.port, "kp2");
    await waitFor("kp2's mail", () => received.slice(before).some((m) => m.to === "kp2@example.com"));
    assert.deepEqual(received.slice(before).map((m) => m.to), ["kp2@example.com"]);
    assert.deepEqual(unusedResetTokens(store, ids.adm!).map((t) => t.id), tokensBefore);
    const used = await call(main.port, "POST", "/auth/password/reset", { body: { token: adminToken, password: NEW_PASSWORD } });
    assert.equal(used.status, 200, JSON.stringify(used.body));
  });

  it("sends at most three reset mails an hour to one member, still answering 202", async () => {
    // Each link is used before the next request, so none is outstanding and only the hourly limit can hold.
    for (let i = 0; i < RESET_MAILS_PER_MEMBER; i++) {
      const before = mailsTo("lim@example.com").length;
      assert.equal((await resetRequest(main.port, "lim")).status, 202);
      const got = await waitFor(`lim's mail ${i + 1}`, () => mailsTo("lim@example.com").length > before && mailsTo("lim@example.com"));
      const used = await call(main.port, "POST", "/auth/password/reset", { body: { token: linkIn(got.at(-1)!).split("#")[1]!, password: NEW_PASSWORD } });
      assert.equal(used.status, 200, JSON.stringify(used.body));
    }
    const before = received.length;
    assert.equal((await resetRequest(main.port, "lim")).status, 202);
    // Known positive after the over-limit request: another member's mail arrives, and lim got none more.
    await resetRequest(main.port, "kp3");
    await waitFor("kp3's mail", () => received.slice(before).some((m) => m.to === "kp3@example.com"));
    assert.deepEqual(received.slice(before).map((m) => m.to), ["kp3@example.com"]);
    assert.ok(logs.some((l) => l.includes(`reset mail for member ${ids.lim} not sent: hourly limit`)));
  });

  it("a fourth request from one source in an hour sends nothing, still 202", async () => {
    const before = received.length;
    const answers = [];
    for (const name of ["ps1", "ps2", "ps3", "ps4"].slice(0, RESET_REQUESTS_PER_SOURCE + 1)) answers.push(await resetRequest(main.port, name, "hour-source"));
    for (const a of answers) assert.equal(a.raw, JSON.stringify(RESET_REQUESTED));
    // Known positive: ps4 asked from another source gets its mail, so it was the source that held.
    await resetRequest(main.port, "ps4");
    await waitFor("ps1-3 and ps4's mails", () => received.slice(before).length >= 4);
    assert.deepEqual(received.slice(before).map((m) => m.to).sort(), ["ps1@example.com", "ps2@example.com", "ps3@example.com", "ps4@example.com"]);
    assert.ok(logs.some((l) => l.includes("reset request from hour-source not handled: per-source hourly limit")));
  });

  it("a store that cannot be written is logged after the 202, not thrown", async () => {
    // A lock file nobody owns makes every write wait out its bound and fail; reads still work.
    writeFileSync(`${store}.lock`, "held by the test\n", { mode: 0o600 });
    try {
      const r = await resetRequest(main.port, "lockd");
      assert.equal(r.status, 202);
      assert.equal(r.raw, JSON.stringify(RESET_REQUESTED));
      await waitFor("the not-handled log line", () => logs.find((l) => l.includes("reset request not handled")));
    } finally {
      rmSync(`${store}.lock`, { force: true });
    }
    assert.deepEqual(unusedResetTokens(store, ids.lockd!), []);
    assert.equal(mailsTo("lockd@example.com").length, 0);
    assert.deepEqual(unhandled, []);
  });

  it("an SSO-only member is not mailed a reset link", async () => {
    const before = received.length;
    assert.deepEqual((await resetRequest(main.port, "sso")).body, RESET_REQUESTED);
    // Known positive after it: kp4's mail arrives, and sso got no mail and holds no token.
    await resetRequest(main.port, "kp4");
    await waitFor("kp4's mail", () => received.slice(before).some((m) => m.to === "kp4@example.com"));
    assert.deepEqual(received.slice(before).map((m) => m.to), ["kp4@example.com"]);
    assert.deepEqual(unusedResetTokens(store, ids.sso!), []);
  });

  it("refuses a foreign origin and a source past its limit, like the other anonymous routes", async () => {
    const foreign = await call(main.port, "POST", "/auth/password/reset-request", { body: { login: "vera" }, origin: "https://evil.example" });
    assert.equal(foreign.status, 403);
    const statuses: number[] = [];
    for (let i = 0; i < 11; i++) statuses.push((await resetRequest(main.port, "nobody-here", "one-source")).status);
    // The 10-a-minute limit answers 429; past the hourly 3 these were already sent nothing.
    assert.deepEqual(statuses, [...Array(10).fill(202), 429]);
    const extra = await call(main.port, "POST", "/auth/password/reset-request", { body: { login: "vera", email: "x" } });
    assert.equal(extra.status, 400);
  });
});

describe("the hourly allowance and an outstanding link", () => {
  it("requests while a link is out do not use up the hourly allowance", async () => {
    assert.equal((await resetRequest(main.port, "burn")).status, 202);
    await waitFor("burn's first mail", () => mailsTo("burn@example.com").length === 1);
    // Three more while that link is out: none mails, and none may count against burn's allowance.
    for (let i = 0; i < RESET_MAILS_PER_MEMBER; i++) assert.equal((await resetRequest(main.port, "burn")).status, 202);
    // Past the link's 30 minutes and still inside the hour, the owner asks again and is mailed.
    skewMs += 31 * 60_000;
    assert.equal((await resetRequest(main.port, "burn")).status, 202);
    await waitFor("burn's second mail", () => mailsTo("burn@example.com").length === 2);
    assert.ok(!logs.some((l) => l.includes(`reset mail for member ${ids.burn} not sent: hourly limit`)));
  });
});

describe("invitation mail", () => {
  it("mails the invitation and says so", async () => {
    const admin = await login(main.port, "root", PASSWORD, GOOD_OTP);
    const r = await call(main.port, "POST", "/api/members/invites", { cookie: admin.cookie, csrf: admin.csrf, body: { email: "newbie@example.com", roles: ["reader"], otp: GOOD_OTP } });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    assert.equal(r.body.mailed, true);
    assert.equal(r.body.mailError, undefined);
    const m = mailsTo("newbie@example.com")[0];
    assert.ok(m, "the invite mail was awaited before the answer");
    assert.equal(linkIn(m), r.body.inviteUrl);
    assert.match(m.text, /72시간/);
    assert.match(m.text, /72 hours/);
    assert.ok(m.text.indexOf("초대") < m.text.indexOf("You have been invited"));
  });

  it("an invitation whose mail fails keeps a working link", async () => {
    const admin = await login(main.port, "root", PASSWORD, GOOD_OTP);
    const r = await call(main.port, "POST", "/api/members/invites", { cookie: admin.cookie, csrf: admin.csrf, body: { email: "bounce@example.com", roles: ["reader"], otp: GOOD_OTP } });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    assert.equal(r.body.mailed, false);
    assert.equal(r.body.mailError, "rcpt-to");
    const token = String(r.body.inviteUrl).split("/app/invite#")[1]!;
    const accepted = await call(main.port, "POST", "/auth/invite/accept", { body: { token, username: "bounce", password: PASSWORD } });
    assert.equal(accepted.status, 201, JSON.stringify(accepted.body));
  });

  it("without mail configured answers mailed false and the link", async () => {
    const admin = await login(quiet.port, "root", PASSWORD, GOOD_OTP);
    const r = await call(quiet.port, "POST", "/api/members/invites", { cookie: admin.cookie, csrf: admin.csrf, body: { email: "quiet@example.com", roles: ["reader"], otp: GOOD_OTP } });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    assert.equal(r.body.mailed, false);
    assert.equal(r.body.mailError, undefined);
    assert.match(String(r.body.inviteUrl), /^https:\/\/heliopause\.example\.invalid\/app\/invite#hpmem_/);
    assert.equal(mailsTo("quiet@example.com").length, 0);
  });
});

describe("what the mail path logs", () => {
  it("names no token and no address", () => {
    // Known positive: the mail lines this file waited for are in the log.
    assert.ok(logs.some((l) => l.includes("reset mail sent for member")));
    assert.deepEqual(logs.filter((l) => /hpmem_|@example\.(com|net)/.test(l)), []);
  });
});
