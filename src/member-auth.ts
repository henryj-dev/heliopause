/**
 * Member password sign-in for the manager: the `/auth/password/*`, `/auth/invite/accept`,
 * `/api/me*` and `/api/members*` routes, and the per-request re-read of a password session's member.
 *
 * `manager-server.ts` builds one of these when `members.mode` is not `off` and calls it at three
 * points: `resolve` for a session whose principal is `via: "password"`, `handleAuthRoute` before its
 * own `/auth/*` routes, and `handleApiRoute` after authorisation and the CSRF check.
 *
 * Bodies are JSON, every field is type- and length-checked before any hashing, and a write is a
 * `withMemberTransaction` with a short lock wait. Sessions stay in the manager's one `SessionStore`.
 */
import { createHash } from "node:crypto";
import { isIPv6 } from "node:net";
import { statSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  activeMember, bindCertCN, confirmOtp, consumeToken, createMember, deleteMember, findByEmail, findByUsername,
  issueToken, loadMemberDocument, MemberError, normalizeMemberName, passwordCredential, peekToken,
  recordAudit, setOtpUserId, setPassword, setRoles, suspendMember, trimLoginAudit, unbindCertCN, unsuspendMember,
  withMemberTransaction, type Member, type MemberDocument,
} from "./member-store.ts";
import {
  checkPasswordPolicy, dummyVerify, hashPassword, MAX_PASSWORD_BYTES, PasswordBusyError, verifyPassword,
} from "./password.ts";
import { statusFor, verifyOtp } from "./otp.ts";
import { clearCookieHeader, cookieHeader, COOKIE, readCookie, type Principal, type Session, type SessionStore } from "./session.ts";

/** Lock wait for a transaction taken on the request path; see `ENROLLMENT_HTTP_LOCK_WAIT_MS`. */
const MEMBER_HTTP_LOCK_WAIT_MS = 100;
/** Per source address, per window, for each of the two anonymous route groups. */
export const MEMBER_AUTH_RATE_MAX = 10;
export const MEMBER_AUTH_RATE_WINDOW_MS = 60_000;
const MEMBER_AUTH_RATE_SOURCES = 1024;
/** Failed sign-ins for one username before each further attempt must wait. */
export const MEMBER_FAILURES_BEFORE_DELAY = 5;
/** The wait doubles from 1 s per failure past the threshold, up to this. */
const MEMBER_MAX_DELAY_SEC = 300;
const MEMBER_FAILURE_KEYS = 4096;
/** Sessions one member may hold at once; a further sign-in ends that member's oldest. */
export const MEMBER_SESSIONS_PER_MEMBER = 5;
/** Wrong current passwords on `/api/me/password`, per member, per window. */
const ME_PASSWORD_FAILURES_MAX = 5;
const ME_PASSWORD_WINDOW_MS = 15 * 60_000;
/** Failed sign-ins for one username, from every source together, per window, before it refuses. */
export const MEMBER_ACCOUNT_FAILURES_MAX = 50;
const MEMBER_ACCOUNT_WINDOW_MS = 15 * 60_000;
/** A source that signed this account in within this long is exempt from the account-wide cap. */
const MEMBER_TRUSTED_SOURCE_MS = 30 * 24 * 60 * 60_000;
const MEMBER_TRUSTED_SOURCES_PER_ACCOUNT = 16;
const MAX_BODY_BYTES = 16 * 1024;
const INVALID_LOGIN = "invalid username or password";

type Hits = Map<string, { windowStartedAt: number; count: number }>;

export interface MemberAuthDeps {
  storeFile: string;
  sessions: SessionStore;
  /** Idle limit, in seconds, given to every password session. */
  idleSec: number;
  otp?: { issuerUrl: string; serviceToken: string; fetchImpl?: typeof fetch };
  /** `operatorCNs` ∪ `writerCNs`. A member's principalName may equal one only if it is in its own `certCNs`. */
  certificateNames: ReadonlySet<string>;
  /** The values of the OIDC alias map. No member's principalName may equal one. */
  aliasNames: ReadonlySet<string>;
  /** `HELIOPAUSE_OTP_USERS`: certificate CN → KeyStone user id. */
  otpUsers: ReadonlyMap<string, string>;
  /** `https://<host>` that invite and reset links are built on; null refuses to build them. */
  publicOrigin: string | null;
  now: () => Date;
  log: (en: string, ko: string) => void;
  rateLimited: (seen: Hits, key: string, nowMs: number, limit: number, windowMs: number, maxKeys: number) => boolean;
  /** The address a per-source limit counts. Defaults to `normalizeSource(req.socket.remoteAddress)`; a test seam. */
  sourceOf?: (req: IncomingMessage) => string;
  /** The manager's `requireOtp`; for a password principal it checks `otpUserId`. */
  requireOtp: (p: Principal, body: { otp?: unknown }, res: ServerResponse, path: string) => Promise<"ok" | "answered">;
}

export type Resolved = { ok: true; principal: Principal } | { ok: false; status: 401 | 503; error: string };

class BadRequest extends Error {}
/** The store could not be read, or its names clash with the deployment's. Answered 503. */
class StoreUnavailable extends Error {}

function reply(res: ServerResponse, status: number, body: unknown, headers: Record<string, string | string[]> = {}): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    ...headers,
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(payload);
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new BadRequest("request body too large");
    chunks.push(chunk as Buffer);
  }
  let body: unknown;
  try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw new BadRequest("request body must be JSON"); }
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new BadRequest("request body must be an object");
  return body as Record<string, unknown>;
}

/** Refuse a body carrying a field outside `allowed`. */
function fields(body: Record<string, unknown>, allowed: readonly string[]): void {
  const extra = Object.keys(body).filter((k) => !allowed.includes(k));
  if (extra.length) throw new BadRequest(`unsupported field ${extra[0]}`);
}
function str(body: Record<string, unknown>, key: string, maxBytes: number): string {
  const v = body[key];
  if (typeof v !== "string" || v.length === 0) throw new BadRequest(`${key} must be a non-empty string`);
  if (Buffer.byteLength(v, "utf8") > maxBytes) throw new BadRequest(`${key} is too long`);
  return v;
}
function optStr(body: Record<string, unknown>, key: string, maxBytes: number): string | undefined {
  return body[key] === undefined ? undefined : str(body, key, maxBytes);
}
function stringList(body: Record<string, unknown>, key: string): string[] {
  const v = body[key];
  if (!Array.isArray(v) || v.length > 8 || v.some((x) => typeof x !== "string" || x.length > 32)) {
    throw new BadRequest(`${key} must be a list of short strings`);
  }
  return v as string[];
}

const sessionShortId = (id: string): string => createHash("sha256").update(id).digest("hex").slice(0, 16);
const mayWriteRoles = (m: Member): boolean => m.roles.includes("writer") || m.roles.includes("admin");

/** Throws when the store and the deployment's names disagree; see `MemberAuthDeps.certificateNames`. */
function assertNoNameClash(document: MemberDocument, deps: Pick<MemberAuthDeps, "certificateNames" | "aliasNames">): void {
  for (const m of document.members) {
    if (m.status === "deleted") continue;
    if (deps.certificateNames.has(m.principalName) && !m.certCNs.includes(m.principalName)) {
      throw new MemberError(`member ${m.username}: principalName ${m.principalName} is an operator or writer certificate CN not bound to this member`, 409);
    }
    if (deps.aliasNames.has(m.principalName)) {
      throw new MemberError(`member ${m.username}: principalName ${m.principalName} is an OIDC alias target`, 409);
    }
  }
}

/**
 * The source a per-address limit counts: an IPv4 address (IPv4-mapped IPv6 unwrapped), or the /64
 * of an IPv6 address, since one host is commonly given a whole /64.
 */
export function normalizeSource(address: string | undefined): string {
  if (!address) return "unknown";
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped) return mapped[1]!;
  if (!isIPv6(address)) return address;
  const [head = "", tail = ""] = address.split("%")[0]!.split("::");
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const groups = address.includes("::") ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right] : left;
  return `${groups.slice(0, 4).map((g) => parseInt(g || "0", 16).toString(16)).join(":")}::/64`;
}

/**
 * Count a failed sign-in for `key` and set its wait. The map is in last-failure order; past
 * `maxKeys`, entries still below the delay threshold go first (oldest of them), so a flood of fresh
 * names cannot push out an entry that is serving a wait.
 * @see member-auth-server.test.ts "a flood of new names does not evict an account that is waiting"
 */
export function recordFailureIn(
  failures: Map<string, { count: number; until: number }>, key: string, nowMs: number, maxKeys = MEMBER_FAILURE_KEYS,
): void {
  const f = failures.get(key) ?? { count: 0, until: 0 };
  failures.delete(key);
  f.count += 1;
  if (f.count >= MEMBER_FAILURES_BEFORE_DELAY) {
    f.until = nowMs + Math.min(2 ** (f.count - MEMBER_FAILURES_BEFORE_DELAY), MEMBER_MAX_DELAY_SEC) * 1000;
  }
  failures.set(key, f);
  while (failures.size > maxKeys) {
    let victim: string | undefined;
    for (const [k, v] of failures) { if (v.count < MEMBER_FAILURES_BEFORE_DELAY) { victim = k; break; } }
    victim ??= failures.keys().next().value as string | undefined;
    if (victim === undefined) break;
    failures.delete(victim);
  }
}

export function createMemberAuth(deps: MemberAuthDeps) {
  const { storeFile, sessions, log } = deps;
  let cache: { key: string; document: MemberDocument } | null = null;

  /** The store as of now, re-read when its inode, size, mtime or ctime moved. Throws when unreadable or clashing. */
  function current(): MemberDocument {
    try {
      const st = statSync(storeFile);
      const key = `${st.ino}:${st.size}:${st.mtimeMs}:${st.ctimeMs}`;
      if (cache && cache.key === key) return cache.document;
      const document = loadMemberDocument(storeFile);
      assertNoNameClash(document, deps);
      cache = { key, document };
      return document;
    } catch (e) {
      cache = null;
      throw new StoreUnavailable(`member store is unavailable: ${(e as Error).message}`);
    }
  }
  // Startup: a missing, unreadable or clashing store refuses to start.
  current();

  const write = <T>(mutate: (document: MemberDocument) => T): T =>
    withMemberTransaction(storeFile, (document) => {
      const result = mutate(document);
      assertNoNameClash(document, deps);
      return result;
    }, { waitMs: MEMBER_HTTP_LOCK_WAIT_MS });

  const loginHits: Hits = new Map();
  const tokenHits: Hits = new Map();
  const failures = new Map<string, { count: number; until: number }>();
  const meFailures: Hits = new Map();

  const source = (req: IncomingMessage): string => (deps.sourceOf ?? ((r) => normalizeSource(r.socket.remoteAddress)))(req);
  // The per-source wait above is not a cap: an attacker with many sources (an IPv6 /64 each) could
  // keep guessing. So failures also count per username alone, and past the cap the account refuses
  // every source except ones that signed it in recently — a stranger cannot lock the owner out.
  // @see member-auth-server.test.ts "failures from many sources reach the account cap; a known source still signs in"
  const accountFailures: Hits = new Map();
  const trustedSources = new Map<string, Map<string, number>>();
  const accountKey = (username: string): string => username.normalize("NFKC").toLowerCase().slice(0, 128);
  function accountCapped(account: string, from: string, nowMs: number): boolean {
    const seen = trustedSources.get(account)?.get(from);
    if (seen !== undefined && nowMs - seen < MEMBER_TRUSTED_SOURCE_MS) return false;
    const f = accountFailures.get(account);
    return !!f && nowMs - f.windowStartedAt < MEMBER_ACCOUNT_WINDOW_MS && f.count >= MEMBER_ACCOUNT_FAILURES_MAX;
  }
  function trustSource(account: string, from: string, nowMs: number): void {
    const known = trustedSources.get(account) ?? new Map<string, number>();
    known.delete(from); known.set(from, nowMs);
    while (known.size > MEMBER_TRUSTED_SOURCES_PER_ACCOUNT) known.delete(known.keys().next().value as string);
    trustedSources.delete(account); trustedSources.set(account, known);
    while (trustedSources.size > MEMBER_FAILURE_KEYS) trustedSources.delete(trustedSources.keys().next().value as string);
  }
  const selfOrigin = (req: IncomingMessage): string => `https://${req.headers["host"] ?? ""}`;

  /** These routes are for the console's own page: `Origin` must be present and ours. */
  function sameOrigin(req: IncomingMessage): boolean {
    const origin = req.headers["origin"];
    const site = req.headers["sec-fetch-site"];
    if (typeof origin !== "string" || origin !== selfOrigin(req)) return false;
    return site === undefined || site === "same-origin";
  }

  /**
   * The wait is per (account, source), so a stranger's failures do not make the owner wait.
   * @see member-auth-server.test.ts "another address's failures do not make the owner wait"
   */
  function failureKey(username: string, from: string): string {
    return `${username.normalize("NFKC").toLowerCase().slice(0, 128)}\u0000${from}`;
  }
  function delayedFor(key: string, nowMs: number): number {
    const f = failures.get(key);
    return f && f.until > nowMs ? Math.ceil((f.until - nowMs) / 1000) : 0;
  }
  const recordFailure = (key: string, nowMs: number): void => recordFailureIn(failures, key, nowMs);
  /** Links are built on the configured public origin, never on the request's `Host`. Checked before a token is issued. */
  const requirePublicOrigin = (): string => {
    if (!deps.publicOrigin) throw new MemberError("no public origin is configured to build links on (HELIOPAUSE_PUBLIC_ORIGIN)", 503);
    return deps.publicOrigin;
  };
  const linkTo = (kind: "invite" | "reset", token: string): string => `${requirePublicOrigin()}/${kind}/${token}`;

  function storeUnavailable(res: ServerResponse, e: unknown): void {
    log(`member store unavailable: ${(e as Error).message}`, `회원 저장소를 읽을 수 없음: ${(e as Error).message}`);
    reply(res, 503, { error: "the member store is unavailable" });
  }

  function sendError(res: ServerResponse, e: unknown): void {
    if (e instanceof StoreUnavailable) return storeUnavailable(res, e);
    if (e instanceof BadRequest) return reply(res, 400, { error: e.message });
    if (e instanceof PasswordBusyError) return reply(res, 429, { error: e.message });
    if (e instanceof MemberError) return reply(res, e.statusCode, { error: e.message });
    throw e;
  }

  /** The one-time code a writer or admin needs at sign-in and at reset. `null` means it passed. */
  async function memberOtp(member: Member, code: string | undefined, path: string): Promise<{ status: number; body: Record<string, unknown> } | null> {
    const otp = deps.otp;
    if (!otp) {
      log(`${path} refused for ${member.username}: no OTP verifier configured`, `${member.username}의 ${path} 거부: OTP 검증기가 설정되지 않음`);
      return { status: 503, body: { error: "writer and admin accounts need a one-time code, and this manager has no OTP verifier configured" } };
    }
    if (!member.otpUserId) {
      return { status: 403, body: { error: "this account needs a one-time code but has no OTP user id — ask an admin to set one" } };
    }
    if (code === undefined) return { status: 401, body: { error: "this account needs a one-time code", needOtp: true } };
    // KeyStone's verify does not look at the KeyStone user's status, so a passing code says nothing
    // about whether the person may still sign in. That authority is the local member status alone
    // (user decision, 2026-10-18), which every caller checks before reaching this.
    const r = await verifyOtp({ baseUrl: otp.issuerUrl, serviceToken: otp.serviceToken, userId: member.otpUserId, code }, otp.fetchImpl ?? fetch);
    if (r.ok) return null;
    log(`${path} refused for ${member.username}: one-time code ${r.reason} (${r.detail})`, `${member.username}의 ${path} 거부: 일회용 코드 ${r.reason} (${r.detail})`);
    return { status: statusFor(r.reason), body: { error: r.detail, ...(r.reason === "wrong-code" ? { needOtp: true } : {}) } };
  }

  /**
   * Rebuild a password session's principal from the store. A member who is missing, not active, or
   * whose credential is gone or changed since sign-in ends the session (401); an unreadable store is 503.
   * @see member-auth-server.test.ts "suspension takes effect on the next request"
   */
  function resolve(session: Session): Resolved {
    let document: MemberDocument;
    try { document = current(); } catch (e) {
      log(`member store unavailable: ${(e as Error).message}`, `회원 저장소를 읽을 수 없음: ${(e as Error).message}`);
      return { ok: false, status: 503, error: "the member store is unavailable" };
    }
    const id = session.principal.memberId ?? "";
    const member = activeMember(document, id);
    const credential = member ? passwordCredential(document, member.id) : null;
    if (!member || !credential || credential.changedAt !== session.principal.credentialChangedAt) {
      sessions.destroy(session.id);
      return { ok: false, status: 401, error: "this session has ended — sign in again" };
    }
    const mfa = session.principal.loginMfa === true;
    const principal: Principal = {
      name: member.principalName, sub: `member:${member.id}`, groups: [], via: "password",
      canWrite: mfa && member.roles.includes("writer"),
      memberId: member.id, loginMfa: mfa, credentialChangedAt: credential.changedAt,
      mustChange: credential.mustChange, isAdmin: mfa && member.roles.includes("admin"), otpUserId: member.otpUserId,
      otpConfirmed: member.otpConfirmedAt !== null,
    };
    session.principal = principal;
    return { ok: true, principal };
  }

  /** While a password must change, only these three requests are answered. */
  function mustChangeRefuses(principal: Principal, method: string | undefined, path: string): boolean {
    if (principal.via !== "password" || !principal.mustChange) return false;
    return !((method === "GET" && path === "/api/me") || (method === "POST" && path === "/api/me/password"));
  }

  function newSession(req: IncomingMessage, member: Member, mfa: boolean, credentialChangedAt: string): Session {
    // A cookie presented with the sign-in is ended, so a planted id never becomes a signed-in one.
    sessions.destroy(readCookie(req.headers["cookie"], COOKIE));
    return sessions.create({
      name: member.principalName, sub: `member:${member.id}`, groups: [], via: "password",
      canWrite: mfa && member.roles.includes("writer"), memberId: member.id, loginMfa: mfa, credentialChangedAt,
    }, { idleSec: deps.idleSec, perMemberMax: MEMBER_SESSIONS_PER_MEMBER });
  }

  async function login(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJson(req);
    fields(body, ["username", "password", "otp"]);
    const username = str(body, "username", 128);
    const password = str(body, "password", MAX_PASSWORD_BYTES);
    const code = optStr(body, "otp", 16);
    const from = source(req);
    const key = failureKey(username, from);
    const account = accountKey(username);
    const nowMs = deps.now().getTime();
    const wait = delayedFor(key, nowMs);
    if (wait > 0) return reply(res, 429, { error: `too many failed sign-ins for this account — try again in ${wait}s` }, { "retry-after": String(wait) });
    if (accountCapped(account, from, nowMs)) {
      log(`sign-in refused from ${from}: account-wide failure cap`, `${from}의 로그인 거부: 계정 실패 상한`);
      return reply(res, 429, { error: "too many failed sign-ins for this account — try again later" });
    }
    const failed = (): void => {
      recordFailure(key, nowMs);
      deps.rateLimited(accountFailures, account, nowMs, MEMBER_ACCOUNT_FAILURES_MAX, MEMBER_ACCOUNT_WINDOW_MS, MEMBER_FAILURE_KEYS);
    };

    const document = current();
    const member = findByUsername(document, username);
    const credential = member ? passwordCredential(document, member.id) : null;
    let ok = false;
    let needsRehash = false;
    if (!member || !credential) {
      await dummyVerify(password);
    } else {
      ({ ok, needsRehash } = await verifyPassword(password, credential.hash));
    }
    if (!ok || !member || !credential || member.status !== "active") {
      failed();
      log(`sign-in refused from ${source(req)}`, `${source(req)}의 로그인 거부`);
      return reply(res, 401, { error: INVALID_LOGIN });
    }

    const mfa = mayWriteRoles(member);
    if (mfa) {
      const refused = await memberOtp(member, code, "/auth/password/login");
      if (refused) {
        if (refused.status === 401 && code !== undefined) failed();
        return reply(res, refused.status, refused.body);
      }
    }

    let rehash: string | null = null;
    if (needsRehash) {
      try { rehash = await hashPassword(password); } catch (e) {
        log(`rehash skipped for ${member.username}: ${(e as Error).message}`, `${member.username}의 재해시 건너뜀: ${(e as Error).message}`);
      }
    }
    let changedAt: string;
    try {
      changedAt = write((d) => {
        const ctx = { actor: member.id, sourceIp: source(req), now: deps.now() };
        // Re-checked under the lock: the member read before the awaits may have been suspended, or
        // had its password or roles changed, in the meantime. A rehash never lands on a changed credential.
        // @see member-auth-server.test.ts "a sign-in whose member changed during the check is refused"
        const live = activeMember(d, member.id);
        const liveCredential = live ? passwordCredential(d, member.id) : null;
        if (!live || !liveCredential || liveCredential.hash !== credential.hash || liveCredential.changedAt !== credential.changedAt
          || mayWriteRoles(live) !== mfa || live.otpUserId !== member.otpUserId) {
          throw new MemberError(INVALID_LOGIN, 401);
        }
        recordAudit(d, ctx, "member.login", member.id);
        trimLoginAudit(d);
        // The first verified sign-in code confirms the otpUserId an admin set.
        // @see member-auth-server.test.ts "the first sign-in code confirms the otpUserId, once"
        if (mfa && member.otpUserId) confirmOtp(d, member.id, member.otpUserId, ctx);
        if (rehash) return setPassword(d, member.id, rehash, { mustChange: credential.mustChange }, ctx).changedAt;
        return passwordCredential(d, member.id)?.changedAt ?? credential.changedAt;
      });
    } catch (e) { return sendError(res, e); }
    failures.delete(key);
    trustSource(account, from, nowMs);

    const s = newSession(req, member, mfa, changedAt);
    log(`password session for ${member.principalName} (${member.id})`, `${member.principalName}(${member.id})의 비밀번호 세션`);
    reply(res, 200, {
      you: member.principalName, canWrite: mfa && member.roles.includes("writer"), isAdmin: mfa && member.roles.includes("admin"),
      csrf: s.csrf, mustChange: credential.mustChange,
    }, { "set-cookie": cookieHeader(s) });
  }

  async function acceptInvite(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJson(req);
    fields(body, ["token", "username", "password"]);
    const token = str(body, "token", 128);
    const rawName = str(body, "username", 128);
    const password = str(body, "password", MAX_PASSWORD_BYTES);
    let document: MemberDocument;
    try { document = loadMemberDocument(storeFile); } catch (e) { throw new StoreUnavailable((e as Error).message); }
    const row = peekToken(document, { kind: "invite", token }, deps.now());
    if (row.memberId !== null) throw new MemberError("token is invalid, used, or expired");
    const username = normalizeMemberName(rawName);
    const input = { username, email: row.email ?? null, emailVerified: true, status: "active" as const, roles: row.roles ?? [] };
    // The same creation on the copy just read, so a taken name or address is refused before hashing.
    // Every name clash answers the same sentence, so the route does not say which names exist.
    const unavailable = (e: unknown): never => {
      if (e instanceof MemberError && e.statusCode === 409) throw new MemberError("username is not available", 409);
      throw e;
    };
    try { createMember(document, input, { actor: `invite:${row.id}`, now: deps.now() }); } catch (e) { unavailable(e); }
    const problems = checkPasswordPolicy(password, { username, email: row.email ?? null });
    if (problems.length) return reply(res, 400, { error: "password refused", problems });
    const hash = await hashPassword(password);
    let member: Member;
    try {
      member = write((d) => {
        const ctx = { actor: `invite:${row.id}`, sourceIp: source(req), now: deps.now() };
        // `consumeToken` re-checks the token under the lock and `createMember` the names.
        consumeToken(d, { kind: "invite", token }, ctx);
        const created = createMember(d, input, ctx);
        setPassword(d, created.id, hash, { mustChange: false }, ctx);
        return created;
      });
    } catch (e) { return unavailable(e); }
    log(`invitation ${row.id} accepted as ${member.username} (${member.id})`, `초대 ${row.id} 수락: ${member.username}(${member.id})`);
    reply(res, 201, { ok: true, username: member.username });
  }

  async function resetPassword(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJson(req);
    fields(body, ["token", "password", "otp"]);
    const token = str(body, "token", 128);
    const password = str(body, "password", MAX_PASSWORD_BYTES);
    const code = optStr(body, "otp", 16);
    let document: MemberDocument;
    try { document = loadMemberDocument(storeFile); } catch (e) { throw new StoreUnavailable((e as Error).message); }
    const row = peekToken(document, { kind: "password-reset", token }, deps.now());
    const member = document.members.find((m) => m.id === row.memberId);
    if (!member) throw new MemberError("token is invalid, used, or expired");
    const problems = checkPasswordPolicy(password, { username: member.username, email: member.email });
    if (problems.length) return reply(res, 400, { error: "password refused", problems });
    const privileged = mayWriteRoles(member);
    if (privileged) {
      // A writer's or admin's reset needs a code from an otpUserId the member already confirmed by
      // signing in. An admin who re-points it cannot then reset the password with their own code.
      // @see member-auth-server.test.ts "a reset of a writer whose otpUserId is unconfirmed is refused"
      if (member.otpConfirmedAt === null) return reply(res, 403, { error: "this account's one-time code is not confirmed — the member must sign in first, or use the CLI" });
      const refused = await memberOtp(member, code, "/auth/password/reset");
      if (refused) return reply(res, refused.status, refused.body);
    }
    const hash = await hashPassword(password);
    write((d) => {
      const ctx = { actor: member.id, sourceIp: source(req), now: deps.now() };
      // Re-checked under the lock: the OTP decision above holds only for the state it read.
      // @see member-auth-server.test.ts "a reset whose member changed during the check is refused"
      const live = d.members.find((m) => m.id === member.id);
      if (!live || mayWriteRoles(live) !== privileged || live.otpUserId !== member.otpUserId || live.otpConfirmedAt !== member.otpConfirmedAt) {
        throw new MemberError("this account changed during the reset — ask for a new link", 409);
      }
      const used = consumeToken(d, { kind: "password-reset", token }, ctx);
      if (used.memberId !== member.id) throw new MemberError("token is invalid, used, or expired");
      setPassword(d, member.id, hash, { mustChange: false }, ctx);
    });
    const ended = sessions.endMember(member.id);
    log(`password reset for ${member.username} by token; ${ended} session(s) ended`, `${member.username}의 토큰 재설정; 세션 ${ended}개 종료`);
    reply(res, 200, { ok: true });
  }

  /** `/auth/password/login`, `/auth/password/reset`, `/auth/invite/accept`. False for any other path. */
  async function handleAuthRoute(url: URL, req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const route = req.method === "POST" ? ({
      "/auth/password/login": { run: login, hits: loginHits },
      "/auth/password/reset": { run: resetPassword, hits: tokenHits },
      "/auth/invite/accept": { run: acceptInvite, hits: tokenHits },
    } as const)[url.pathname as "/auth/password/login"] : undefined;
    if (!route) return false;
    if (!sameOrigin(req)) {
      reply(res, 403, { error: "this route only answers the console's own page" });
      return true;
    }
    if (deps.rateLimited(route.hits, source(req), deps.now().getTime(), MEMBER_AUTH_RATE_MAX, MEMBER_AUTH_RATE_WINDOW_MS, MEMBER_AUTH_RATE_SOURCES)) {
      log(`${url.pathname} refused for ${source(req)}: rate limit`, `${source(req)}의 ${url.pathname} 거부: 속도 제한`);
      reply(res, 429, { error: "too many requests from this address" });
      return true;
    }
    try { await route.run(req, res); } catch (e) { sendError(res, e); }
    return true;
  }

  function memberView(document: MemberDocument, m: Member): Record<string, unknown> {
    const credential = passwordCredential(document, m.id);
    return {
      id: m.id, username: m.username, principalName: m.principalName, email: m.email, emailVerifiedAt: m.emailVerifiedAt,
      status: m.status, roles: m.roles, soloApprove: m.soloApprove, otpUserId: m.otpUserId, otpConfirmedAt: m.otpConfirmedAt,
      certCNs: m.certCNs,
      hasPassword: credential !== null, mustChange: credential?.mustChange ?? false,
      createdAt: m.createdAt, updatedAt: m.updatedAt,
    };
  }

  async function me(principal: Principal, session: Session, url: URL, req: IncomingMessage, res: ServerResponse): Promise<void> {
    const memberId = principal.memberId ?? "";
    const gone = (): void => reply(res, 401, { error: "this session has ended — sign in again" });
    if (req.method === "GET" && url.pathname === "/api/me") {
      const document = current();
      const m = activeMember(document, memberId);
      if (!m) return gone();
      return reply(res, 200, {
        id: m.id, username: m.username, principalName: m.principalName, email: m.email, roles: m.roles,
        status: m.status, mustChange: principal.mustChange === true, via: principal.via, otpConfirmedAt: m.otpConfirmedAt,
      });
    }
    if (req.method === "POST" && url.pathname === "/api/me/password") {
      const body = await readJson(req);
      fields(body, ["current", "next"]);
      const currentPassword = str(body, "current", MAX_PASSWORD_BYTES);
      const next = str(body, "next", MAX_PASSWORD_BYTES);
      const document = current();
      const m = activeMember(document, memberId);
      const credential = m ? passwordCredential(document, memberId) : null;
      if (!m || !credential) return gone();
      const failed = meFailures.get(memberId);
      const nowMs = deps.now().getTime();
      if (failed && nowMs - failed.windowStartedAt < ME_PASSWORD_WINDOW_MS && failed.count >= ME_PASSWORD_FAILURES_MAX) {
        return reply(res, 429, { error: "too many wrong current passwords — try again later" });
      }
      const { ok } = await verifyPassword(currentPassword, credential.hash);
      if (!ok) {
        deps.rateLimited(meFailures, memberId, nowMs, ME_PASSWORD_FAILURES_MAX, ME_PASSWORD_WINDOW_MS, MEMBER_FAILURE_KEYS);
        return reply(res, 403, { error: "the current password is not correct" });
      }
      const problems = checkPasswordPolicy(next, { username: m.username, email: m.email });
      if (problems.length) return reply(res, 400, { error: "password refused", problems });
      const hash = await hashPassword(next);
      const changed = write((d) => setPassword(d, memberId, hash, { mustChange: false }, { actor: memberId, sourceIp: source(req), now: deps.now() }));
      const ended = sessions.endMember(memberId, session.id);
      session.principal = { ...session.principal, credentialChangedAt: changed.changedAt, mustChange: false };
      log(`password changed by ${m.username}; ${ended} other session(s) ended`, `${m.username} 비밀번호 변경; 다른 세션 ${ended}개 종료`);
      return reply(res, 200, { ok: true, endedSessions: ended });
    }
    if (req.method === "GET" && url.pathname === "/api/me/sessions") {
      return reply(res, 200, {
        sessions: sessions.forMember(memberId).map((s) => ({
          id: sessionShortId(s.id), createdAt: s.createdAt.toISOString(), lastSeenAt: s.lastSeenAt.toISOString(),
          via: s.principal.via, current: s.id === session.id,
        })),
      });
    }
    if (req.method === "DELETE" && url.pathname === "/api/me/sessions") {
      return reply(res, 200, { ended: sessions.endMember(memberId, session.id) });
    }
    const one = /^\/api\/me\/sessions\/([0-9a-f]{16})$/.exec(url.pathname);
    if (req.method === "DELETE" && one) {
      const target = sessions.forMember(memberId).find((s) => sessionShortId(s.id) === one[1]);
      if (!target) return reply(res, 404, { error: "no such session" });
      sessions.destroy(target.id);
      return reply(res, 200, { ended: 1 }, target.id === session.id ? { "set-cookie": clearCookieHeader() } : {});
    }
    reply(res, 404, { error: `no such route ${url.pathname}` });
  }

  /**
   * Member administration. One admin cannot change their own roles or otpUserId here, cannot point a
   * member at a KeyStone user another member or another certificate holds, and approval compares
   * people by KeyStone user. What remains: an admin who controls a second KeyStone account can still
   * invite a second writer bound to it, and that writer counts as a different person. Approval by OTP
   * identity stops one KeyStone account counting twice, not one human holding two.
   */
  async function admin(principal: Principal, url: URL, req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!principal.isAdmin) return reply(res, 403, { error: "member administration needs the admin role" });
    if (req.method === "GET" && url.pathname === "/api/members") {
      const document = current();
      return reply(res, 200, { members: document.members.map((m) => memberView(document, m)) });
    }
    if (req.method !== "POST") return reply(res, 404, { error: `no such route ${url.pathname}` });
    const actor = principal.memberId ?? "";
    const body = await readJson(req);
    if (url.pathname === "/api/members/invites") {
      fields(body, ["email", "roles", "otp"]);
      const email = str(body, "email", 254);
      const roles = stringList(body, "roles");
      requirePublicOrigin();
      if ((await deps.requireOtp(principal, body, res, url.pathname)) === "answered") return;
      const issued = write((d) => {
        if (findByEmail(d, email)) throw new MemberError("email is already in use", 409);
        return issueToken(d, { kind: "invite", email, roles }, { actor, sourceIp: source(req), now: deps.now() });
      });
      log(`invitation ${issued.row.id} issued by ${principal.name}`, `${principal.name}이(가) 초대 ${issued.row.id} 발급`);
      return reply(res, 201, { id: issued.row.id, expiresAt: issued.row.expiresAt, inviteUrl: linkTo("invite", issued.token) });
    }
    const m = /^\/api\/members\/([0-9a-f-]{36})\/(roles|suspend|unsuspend|delete|otp-user|cert-cns|password-reset)$/.exec(url.pathname);
    if (!m) return reply(res, 404, { error: `no such route ${url.pathname}` });
    const [, id, action] = m as unknown as [string, string, string];
    const allowed: Record<string, readonly string[]> = {
      "roles": ["roles", "otp"], "otp-user": ["otpUserId", "otp"], "cert-cns": ["add", "remove", "otp"],
    };
    fields(body, allowed[action] ?? ["otp"]);
    const roles = action === "roles" ? stringList(body, "roles") : null;
    const otpUser = action === "otp-user"
      ? (body.otpUserId === null ? null : str(body, "otpUserId", 128))
      : undefined;
    const add = action === "cert-cns" ? optStr(body, "add", 128) : undefined;
    const remove = action === "cert-cns" ? optStr(body, "remove", 128) : undefined;
    if (action === "cert-cns" && (add === undefined) === (remove === undefined)) throw new BadRequest("send exactly one of add or remove");
    // An admin may not raise or re-point their own authority here; another admin, or the CLI, must.
    // @see member-auth-server.test.ts "an admin cannot change their own roles or otpUserId"
    if (id === actor && (action === "roles" || action === "otp-user")) {
      return reply(res, 403, { error: "an admin cannot change their own roles or one-time code — another admin must" });
    }
    if (action === "password-reset") requirePublicOrigin();
    if ((await deps.requireOtp(principal, body, res, url.pathname)) === "answered") return;
    const ctx = { actor, sourceIp: source(req), now: deps.now() };
    const { endSessions, resetToken } = write((d): { endSessions: boolean; resetToken: string | null } => {
      if (action === "roles") {
        const before = d.members.find((x) => x.id === id)?.roles ?? [];
        const after = setRoles(d, id, roles!, ctx).roles;
        return { endSessions: before.length !== after.length || before.some((r) => !after.includes(r)), resetToken: null };
      }
      if (action === "suspend") suspendMember(d, id, ctx);
      else if (action === "unsuspend") unsuspendMember(d, id, ctx);
      else if (action === "delete") deleteMember(d, id, ctx);
      else if (action === "otp-user") {
        // A KeyStone user mapped to a certificate is that certificate holder's; only the member that
        // holds the certificate may take it. Another member's otpUserId is refused by the store.
        // @see member-auth-server.test.ts "otp-user refuses a KeyStone user mapped to another certificate"
        const own = d.members.find((x) => x.id === id)?.certCNs ?? [];
        for (const [cn, uid] of deps.otpUsers) {
          if (uid === otpUser && !own.includes(cn)) throw new MemberError(`that one-time-code user belongs to certificate ${cn}`, 409);
        }
        setOtpUserId(d, id, otpUser!, ctx);
      }
      else if (action === "cert-cns") { if (add !== undefined) bindCertCN(d, id, add, ctx); else unbindCertCN(d, id, remove!, ctx); }
      else return { endSessions: false, resetToken: issueToken(d, { kind: "password-reset", memberId: id }, ctx).token };
      return { endSessions: action === "suspend" || action === "delete" || action === "otp-user", resetToken: null };
    });
    const ended = endSessions ? sessions.endMember(id) : 0;
    log(`member ${id}: ${action} by ${principal.name}; ${ended} session(s) ended`, `회원 ${id}: ${principal.name}의 ${action}; 세션 ${ended}개 종료`);
    const after = current();
    const target = after.members.find((x) => x.id === id);
    return reply(res, 200, {
      ...(target ? { member: memberView(after, target) } : {}),
      endedSessions: ended,
      ...(resetToken ? { resetUrl: linkTo("reset", resetToken) } : {}),
    });
  }

  /** `/api/me*` and `/api/members*`, for a password session only. False for any other path. */
  async function handleApiRoute(principal: Principal, session: Session | null, url: URL, req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const p = url.pathname;
    const isMe = p === "/api/me" || p.startsWith("/api/me/");
    const isMembers = p === "/api/members" || p.startsWith("/api/members/");
    if (!isMe && !isMembers) return false;
    if (principal.via !== "password" || !session) {
      reply(res, 403, { error: "this route needs a member session" });
      return true;
    }
    try {
      await (isMe ? me(principal, session, url, req, res) : admin(principal, url, req, res));
    } catch (e) { sendError(res, e); }
    return true;
  }

  /** The store as of now, for callers outside this module. Throws when it cannot be read. */
  const document = (): MemberDocument => current();

  return { resolve, mustChangeRefuses, handleAuthRoute, handleApiRoute, document };
}
