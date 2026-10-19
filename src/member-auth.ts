/**
 * Member sign-in for the manager: the `/auth/password/*`, `/auth/invite/accept`, `/auth/sso/otp`,
 * `/api/me*` and `/api/members*` routes, the per-request re-read of a member session's member, and
 * the member half of SSO (`ssoSignIn`, `linkStart`, `completeLink`).
 *
 * `manager-server.ts` builds one of these when `members.mode` is not `off` and calls `resolve` for a
 * member session (`via: "password"` or `"sso"`), `handleAuthRoute` before its own `/auth/*` routes,
 * `handleApiRoute` after authorisation and the CSRF check, and the three SSO functions from its OIDC
 * routes.
 *
 * Bodies are JSON, every field is type- and length-checked before any hashing, and a write is a
 * `withMemberTransaction` with a short lock wait. Sessions stay in the manager's one `SessionStore`.
 *
 * With `mail` configured, a self-service reset request and an admin's invitation are mailed through
 * `mail.ts`; without it, neither sends anything and the invite link is only in the admin's answer.
 */
import { createHash, randomBytes, randomInt } from "node:crypto";
import { isIPv6 } from "node:net";
import { statSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  activeMember, bindCertCN, confirmOtp, consumeToken, createMember, DEFAULT_TOKEN_TTL_SEC, deleteMember, findByEmail, findByUsername,
  identityHandle, identityOwner, issueToken, linkIdentity, loadMemberDocument, MemberError, normalizeMemberName, passwordCredential, peekToken,
  recordAudit, setOtpUserId, setPassword, setRoles, setSoloApprove, suspendMember, trimLoginAudit, unbindCertCN, unlinkIdentity, unsuspendMember,
  withMemberTransaction, type Member, type MemberDocument,
} from "./member-store.ts";
import {
  checkPasswordPolicy, dummyVerify, hashPassword, PasswordBusyError, verifyPassword,
} from "./password.ts";
import { statusFor, verifyOtp } from "./otp.ts";
import { MailError, sendMail, type MailConfig, type MailMessage } from "./mail.ts";
import {
  checkCsrf, clearCookieHeader, cookieHeader, COOKIE, CSRF_HEADER, isMemberSession, readCookie, type Principal, type Session, type SessionStore,
} from "./session.ts";

/**
 * The browser's half of an SSO sign-in that still needs a writer's or admin's one-time code. Only
 * its digest is kept here; the entry is single-use and short-lived.
 */
export const SSO_PENDING_COOKIE = "__Host-heliopause-sso";
/** How long the browser has to enter the code after the IdP sent it back. */
export const SSO_PENDING_TTL_SEC = 5 * 60;
const SSO_PENDING_MAX = 256;
const ssoPendingCookie = (value: string): string =>
  `${SSO_PENDING_COOKIE}=${value}; Max-Age=${SSO_PENDING_TTL_SEC}; Path=/; Secure; HttpOnly; SameSite=Strict`;
const clearSsoPendingCookie = (): string => `${SSO_PENDING_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict`;

/** What `/auth/link/start` stores beside the OIDC `state`, server-side. The browser never sends it. */
export interface LinkIntent { kind: "link"; memberId: string; sessionId: string }

/** What an SSO callback with a verified `(issuer, subject)` turned into. */
export type SsoSignIn =
  | { kind: "unlinked" }
  | { kind: "refused"; status: 403 | 503; error: string }
  | { kind: "session"; session: Session }
  | { kind: "otp"; cookie: string };

/** Lock wait for a transaction taken on the request path; see `ENROLLMENT_HTTP_LOCK_WAIT_MS`. */
const MEMBER_HTTP_LOCK_WAIT_MS = 100;
/** Per source address, per window, for each of the two anonymous route groups. */
export const MEMBER_AUTH_RATE_MAX = 10;
export const MEMBER_AUTH_RATE_WINDOW_MS = 60_000;
const MEMBER_AUTH_RATE_SOURCES = 1024;
// These counters live in this process's memory, not a shared store: a documented product exception
// to the common "shared counter" rule, since the manager runs as a single instance.
/** Failed sign-ins for one (account, source) before each further attempt must wait. */
export const MEMBER_FAILURES_BEFORE_DELAY = 5;
/** The wait starts at 1 s at the threshold and doubles per failure, up to this (15 min). */
export const MEMBER_MAX_DELAY_SEC = 15 * 60;
/** A failure record is forgotten once this long has passed since its last failure. */
export const MEMBER_FAILURE_RESET_MS = 15 * 60_000;
// Cap and reset together: past the threshold each attempt waits up to 15 min, so one (account, source)
// gets about 28 attempts an hour at most, and the account-wide cap bounds all sources together.
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
/**
 * Body cap for the four routes that carry a password (sign-in, invite accept, reset, change). There
 * is no password length rule; this bounds what reaches scrypt. A password field's own limit is this
 * same number, so it adds nothing beyond the body cap.
 */
export const PASSWORD_BODY_MAX_BYTES = 64 * 1024;
const INVALID_LOGIN = "invalid username or password";
/** Reset mails one member may be sent per window, whoever asks; requests past it still answer 202. */
export const RESET_MAILS_PER_MEMBER = 3;
const RESET_MAIL_WINDOW_MS = 60 * 60_000;
/**
 * Reset requests one source may make per hour that can lead to mail. Past it the answer is still the
 * same 202 and nothing is looked up: a 429 keyed on the source alone would reveal nothing about an
 * account either, but one answer for everything leaves nothing to compare. The 10-a-minute limit
 * shared with the other anonymous routes still answers 429 before this.
 * @see member-mail-server.test.ts "a fourth request from one source in an hour sends nothing, still 202"
 */
export const RESET_REQUESTS_PER_SOURCE = 3;
/**
 * The one answer `POST /auth/password/reset-request` gives to every well-formed request it lets
 * through, whatever the account's state and whether mail is configured.
 * @see member-mail-server.test.ts "answers every reset request with the same 202"
 */
const resetMinutes = DEFAULT_TOKEN_TTL_SEC["password-reset"] / 60;
export const RESET_REQUESTED = {
  ok: true, note: "if this account can receive a reset link, one has been sent to its verified address",
  // The console's confirmation states the link's lifetime from here, so the number lives in one place.
  linkExpiresInMinutes: resetMinutes,
} as const;
/** Upper bound of the random wait before a reset request's lookup, in milliseconds. */
const RESET_JITTER_MAX_MS = 2000;
const inviteHours = DEFAULT_TOKEN_TTL_SEC.invite / 3600;

/** Plain text, Korean first, then English. No HTML, no tracking. */
export function resetMail(to: string, link: string): MailMessage {
  return {
    to,
    subject: "heliopause 비밀번호 재설정 / password reset",
    text: [
      "heliopause 계정의 비밀번호 재설정을 요청받았습니다.",
      `아래 링크에서 새 비밀번호를 정하십시오. 링크는 ${resetMinutes}분 뒤 만료되고 한 번만 쓸 수 있습니다.`,
      "",
      link,
      "",
      "요청하지 않았다면 이 메일을 무시하십시오. 비밀번호는 바뀌지 않습니다.",
      "",
      "---",
      "",
      "A password reset was requested for your heliopause account.",
      `Set a new password at the link below. It expires in ${resetMinutes} minutes and works once.`,
      "",
      link,
      "",
      "If you did not ask for this, ignore this mail. Your password stays as it is.",
      "",
    ].join("\n"),
  };
}
export function inviteMail(to: string, link: string): MailMessage {
  return {
    to,
    subject: "heliopause 초대 / invitation",
    text: [
      "heliopause 매니저 콘솔에 초대받았습니다.",
      `아래 링크에서 사용자 이름과 비밀번호를 정하십시오. 링크는 ${inviteHours}시간 뒤 만료되고 한 번만 쓸 수 있습니다.`,
      "",
      link,
      "",
      "초대받을 일이 없다면 이 메일을 무시하십시오.",
      "",
      "---",
      "",
      "You have been invited to the heliopause manager console.",
      `Choose a username and password at the link below. It expires in ${inviteHours} hours and works once.`,
      "",
      link,
      "",
      "If you did not expect this, ignore this mail.",
      "",
    ].join("\n"),
  };
}
/** What a failed send is logged and answered as: the step and reply code, never the server's text. */
const mailFailure = (e: unknown): { step: string; code: number } =>
  e instanceof MailError ? { step: e.step, code: e.code } : { step: "unknown", code: 0 };

type Hits = Map<string, { windowStartedAt: number; count: number }>;

export interface MemberAuthDeps {
  storeFile: string;
  sessions: SessionStore;
  /** Idle limit, in seconds, given to every password session. */
  idleSec: number;
  /** Absolute lifetime, in seconds, of every password session. */
  ttlSec: number;
  otp?: { issuerUrl: string; serviceToken: string; fetchImpl?: typeof fetch };
  /** `operatorCNs` ∪ `writerCNs`. A member's principalName may equal one only if it is in its own `certCNs`. */
  certificateNames: ReadonlySet<string>;
  /** The values of the OIDC alias map. No member's principalName may equal one. */
  aliasNames: ReadonlySet<string>;
  /** `HELIOPAUSE_OTP_USERS`: certificate CN → KeyStone user id. */
  otpUsers: ReadonlyMap<string, string>;
  /** `https://<host>` that invite and reset links are built on. `startManager` refuses to start without one. */
  publicOrigin: string;
  now: () => Date;
  log: (en: string, ko: string) => void;
  rateLimited: (seen: Hits, key: string, nowMs: number, limit: number, windowMs: number, maxKeys: number) => boolean;
  /** The address a per-source limit counts. Defaults to `normalizeSource(req.socket.remoteAddress)`; a test seam. */
  sourceOf?: (req: IncomingMessage) => string;
  /** The wait before a reset request's lookup. Defaults to a random 0..2000 ms; a test seam. */
  resetDelayMs?: () => number;
  /** SMTP relay for reset and invite mail. Absent or null: nothing is mailed. */
  mail?: MailConfig | null;
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

async function readJson(req: IncomingMessage, maxBytes = MAX_BODY_BYTES): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > maxBytes) throw new BadRequest("request body too large");
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
  failures: Map<string, { count: number; until: number; last: number }>, key: string, nowMs: number, maxKeys = MEMBER_FAILURE_KEYS,
): void {
  const previous = failures.get(key);
  // @see member-auth-server.test.ts "a failure record is forgotten 15 minutes after its last failure"
  const f = previous && nowMs - previous.last < MEMBER_FAILURE_RESET_MS ? previous : { count: 0, until: 0, last: nowMs };
  failures.delete(key);
  f.count += 1;
  f.last = nowMs;
  if (f.count >= MEMBER_FAILURES_BEFORE_DELAY) {
    f.until = nowMs + Math.min(2 ** (f.count - MEMBER_FAILURES_BEFORE_DELAY), MEMBER_MAX_DELAY_SEC) * 1000;
  }
  failures.set(key, f);
  while (failures.size > maxKeys) {
    let victim: string | undefined;
    // Expired records first (they would reset anyway), then ones below the threshold, then the oldest.
    // @see member-auth-server.test.ts "eviction takes an expired record before one below the threshold"
    for (const [k, v] of failures) { if (nowMs - v.last >= MEMBER_FAILURE_RESET_MS) { victim = k; break; } }
    if (victim === undefined) for (const [k, v] of failures) { if (v.count < MEMBER_FAILURES_BEFORE_DELAY) { victim = k; break; } }
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
    }, { waitMs: MEMBER_HTTP_LOCK_WAIT_MS, now: deps.now() });

  const loginHits: Hits = new Map();
  const tokenHits: Hits = new Map();
  const resetRequestHits: Hits = new Map();
  const resetMailHits: Hits = new Map();
  const resetSourceHits: Hits = new Map();
  const failures = new Map<string, { count: number; until: number; last: number }>();
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
  // The token is in the fragment, which a browser never sends to any server, so it stays out of this
  // server's and any front proxy's access log. The page reads it and clears it from the address bar
  // and the current history entry; the browser's own history and autocomplete may still keep it.
  // What protects the link is that it works once and expires.
  // Links are built on the configured public origin, never on the request's `Host`.
  const linkTo = (kind: "invite" | "reset", token: string): string => `${deps.publicOrigin}/app/${kind}#${token}`;

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
   * Rebuild a member session's principal from the store. A member who is missing or not active ends
   * the session (401), and so does, for a password session, a credential gone or changed since
   * sign-in, and for an SSO session, the identity it signed in with no longer linked to the member.
   * An unreadable store is 503.
   * @see member-auth-server.test.ts "suspension takes effect on the next request"
   * @see member-sso-server.test.ts "unlinking ends the sessions that identity signed in"
   */
  function resolve(session: Session): Resolved {
    let document: MemberDocument;
    try { document = current(); } catch (e) {
      log(`member store unavailable: ${(e as Error).message}`, `회원 저장소를 읽을 수 없음: ${(e as Error).message}`);
      return { ok: false, status: 503, error: "the member store is unavailable" };
    }
    const id = session.principal.memberId ?? "";
    const member = activeMember(document, id);
    const sso = session.principal.via === "sso";
    const credential = member ? passwordCredential(document, member.id) : null;
    const stillValid = sso
      ? !!member && identityOwner(document, session.principal.ssoIssuer ?? "", session.principal.ssoSubject ?? "")?.id === member.id
      : !!member && !!credential && credential.changedAt === session.principal.credentialChangedAt;
    if (!member || !stillValid) {
      sessions.destroy(session.id);
      return { ok: false, status: 401, error: "this session has ended — sign in again" };
    }
    const mfa = session.principal.loginMfa === true;
    const principal: Principal = {
      name: member.principalName, sub: `member:${member.id}`, groups: [], via: sso ? "sso" : "password",
      canWrite: mfa && member.roles.includes("writer"),
      memberId: member.id, loginMfa: mfa,
      ...(sso
        ? { ssoIssuer: session.principal.ssoIssuer!, ssoSubject: session.principal.ssoSubject!, mustChange: false }
        : { credentialChangedAt: credential!.changedAt, mustChange: credential!.mustChange }),
      isAdmin: mfa && member.roles.includes("admin"), otpUserId: member.otpUserId,
      otpConfirmed: member.otpConfirmedAt !== null,
      // The flag and a confirmed KeyStone user. The manager also needs `canWrite`, which a member
      // session has only after its sign-in code. @see `maySoloApprove` in manager-server.ts
      // @see member-sso-server.test.ts "solo approval needs soloApprove, a confirmed code and a session that passed it"
      soloApprove: member.soloApprove && member.otpUserId !== null && member.otpConfirmedAt !== null,
    };
    session.principal = principal;
    return { ok: true, principal };
  }

  /** While a password must change, only these three requests are answered. */
  function mustChangeRefuses(principal: Principal, method: string | undefined, path: string): boolean {
    if (principal.via !== "password" || !principal.mustChange) return false;
    return !((method === "GET" && path === "/api/me") || (method === "POST" && path === "/api/me/password"));
  }

  function newSession(
    req: IncomingMessage, member: Member, mfa: boolean,
    proof: { via: "password"; credentialChangedAt: string } | { via: "sso"; issuer: string; subject: string },
  ): Session {
    // A cookie presented with the sign-in is ended, so a planted id never becomes a signed-in one.
    sessions.destroy(readCookie(req.headers["cookie"], COOKIE));
    return sessions.create({
      name: member.principalName, sub: `member:${member.id}`, groups: [], via: proof.via,
      canWrite: mfa && member.roles.includes("writer"), memberId: member.id, loginMfa: mfa,
      ...(proof.via === "password"
        ? { credentialChangedAt: proof.credentialChangedAt }
        : { ssoIssuer: proof.issuer, ssoSubject: proof.subject }),
    }, { idleSec: deps.idleSec, ttlSec: deps.ttlSec, perMemberMax: MEMBER_SESSIONS_PER_MEMBER });
  }

  async function login(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJson(req, PASSWORD_BODY_MAX_BYTES);
    fields(body, ["username", "password", "otp"]);
    const username = str(body, "username", 128);
    const password = str(body, "password", PASSWORD_BODY_MAX_BYTES);
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

    const s = newSession(req, member, mfa, { via: "password", credentialChangedAt: changedAt });
    log(`password session for ${member.principalName} (${member.id})`, `${member.principalName}(${member.id})의 비밀번호 세션`);
    reply(res, 200, {
      you: member.principalName, canWrite: mfa && member.roles.includes("writer"), isAdmin: mfa && member.roles.includes("admin"),
      csrf: s.csrf, mustChange: credential.mustChange,
    }, { "set-cookie": cookieHeader(s) });
  }

  async function acceptInvite(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJson(req, PASSWORD_BODY_MAX_BYTES);
    fields(body, ["token", "username", "password"]);
    const token = str(body, "token", 128);
    const rawName = str(body, "username", 128);
    const password = str(body, "password", PASSWORD_BODY_MAX_BYTES);
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
    const problems = checkPasswordPolicy(password);
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
    const body = await readJson(req, PASSWORD_BODY_MAX_BYTES);
    fields(body, ["token", "password", "otp"]);
    const token = str(body, "token", 128);
    const password = str(body, "password", PASSWORD_BODY_MAX_BYTES);
    const code = optStr(body, "otp", 16);
    let document: MemberDocument;
    try { document = loadMemberDocument(storeFile); } catch (e) { throw new StoreUnavailable((e as Error).message); }
    const row = peekToken(document, { kind: "password-reset", token }, deps.now());
    const member = document.members.find((m) => m.id === row.memberId);
    if (!member) throw new MemberError("token is invalid, used, or expired");
    const problems = checkPasswordPolicy(password);
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

  /**
   * `POST /auth/password/reset-request {login}`, a username or an email address. The 202 is written
   * before the store is looked at, so its body and its own timing do not depend on the account; the
   * lookup, token write and mail that follow still run on this process. They start after a random
   * wait of up to 2 s, which spreads that work out in time; it does not remove the signal.
   * @see member-mail-server.test.ts "answers every reset request with the same 202"
   */
  async function requestReset(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJson(req);
    fields(body, ["login"]);
    const login = str(body, "login", 254);
    const from = source(req);
    reply(res, 202, RESET_REQUESTED);
    if (deps.rateLimited(resetSourceHits, from, deps.now().getTime(), RESET_REQUESTS_PER_SOURCE, RESET_MAIL_WINDOW_MS, MEMBER_AUTH_RATE_SOURCES)) {
      log(`reset request from ${from} not handled: per-source hourly limit`, `${from}의 재설정 요청 처리 안 함: 출처당 시간당 상한`);
      return;
    }
    setTimeout(() => {
      mailReset(login, from).catch((e: unknown) => {
        log(`reset request not handled: ${(e as Error).message}`, `재설정 요청 처리 안 됨: ${(e as Error).message}`);
      });
    }, (deps.resetDelayMs ?? (() => randomInt(0, RESET_JITTER_MAX_MS + 1)))());
  }

  /**
   * Mail a reset link to an active member with a verified address and a password. A send that fails
   * withdraws the token it carried, so a link that may or may not have arrived never stays usable.
   * @see member-mail-server.test.ts "a failed send withdraws its token and rejects nothing unhandled"
   */
  const linkOutstanding = (d: MemberDocument, memberId: string): boolean => d.tokens.some((t) =>
    t.kind === "password-reset" && t.memberId === memberId && t.usedAt === null && Date.parse(t.expiresAt) > deps.now().getTime());

  async function mailReset(login: string, from: string): Promise<void> {
    const mail = deps.mail;
    if (!mail) return;
    const document = current();
    const found = login.includes("@") ? findByEmail(document, login) : findByUsername(document, login);
    if (!found) return;
    const ctx = { actor: "system", sourceIp: from, now: deps.now() };
    const issued = write((d) => {
      // Every condition is read under the lock, where the token is written.
      const live = activeMember(d, found.id);
      if (!live || live.email === null || live.emailVerifiedAt === null) return null;
      // A member without a password (SSO only) does not gain one through mail.
      // @see member-mail-server.test.ts "an SSO-only member is not mailed a reset link"
      if (!passwordCredential(d, live.id)) return null;
      // An unexpired link already out (an admin's or an earlier request's) is left alone: an anonymous
      // request never replaces it, so it cannot void a link an admin handed over.
      // @see member-mail-server.test.ts "a request leaves an outstanding link alone, an admin's included"
      if (linkOutstanding(d, live.id)) return null;
      // Counted only for a token about to be issued, so requests made while a link is out do not use
      // up the owner's hourly allowance.
      // @see member-mail-server.test.ts "sends at most three reset mails an hour to one member"
      // @see member-mail-server.test.ts "requests while a link is out do not use up the hourly allowance"
      if (deps.rateLimited(resetMailHits, live.id, deps.now().getTime(), RESET_MAILS_PER_MEMBER, RESET_MAIL_WINDOW_MS, MEMBER_FAILURE_KEYS)) return "limited" as const;
      return { ...issueToken(d, { kind: "password-reset", memberId: live.id }, ctx), to: live.email };
    });
    if (issued === "limited") {
      log(`reset mail for member ${found.id} not sent: hourly limit`, `회원 ${found.id} 재설정 메일 보내지 않음: 시간당 상한`);
      return;
    }
    if (!issued) return;
    try {
      await sendMail(mail, resetMail(issued.to, linkTo("reset", issued.token)));
    } catch (e) {
      const { step, code } = mailFailure(e);
      let withdrawn = "withdrawn";
      try {
        write((d) => {
          const before = d.tokens.length;
          d.tokens = d.tokens.filter((t) => t.id !== issued.row.id || t.usedAt !== null);
          if (d.tokens.length !== before) recordAudit(d, { ...ctx, now: deps.now() }, "token.withdraw.password-reset", issued.row.id);
        });
      } catch (w) {
        withdrawn = `NOT withdrawn (${(w as Error).message})`;
      }
      log(`reset mail for member ${found.id} failed at ${step} (${code}); its link was ${withdrawn}`,
        `회원 ${found.id} 재설정 메일 실패: ${step} (${code}); 링크 ${withdrawn === "withdrawn" ? "무효화함" : `무효화 못 함: ${withdrawn}`}`);
      return;
    }
    log(`reset mail sent for member ${found.id}`, `회원 ${found.id} 재설정 메일 보냄`);
  }

  // ── SSO: sign-in of a linked member, linking, unlinking ────────────────────────────────────

  /** Writer and admin SSO sign-ins waiting for their one-time code, keyed by the cookie's digest. */
  const ssoPending = new Map<string, { memberId: string; issuer: string; subject: string; otpUserId: string; at: number; returnTo: string | null }>();
  const digestOf = (value: string): string => createHash("sha256").update(value).digest("base64url");
  function trimSsoPending(nowMs: number): void {
    for (const [k, v] of ssoPending) if (nowMs - v.at >= SSO_PENDING_TTL_SEC * 1000) ssoPending.delete(k);
    while (ssoPending.size >= SSO_PENDING_MAX) ssoPending.delete(ssoPending.keys().next().value as string);
  }

  /**
   * An SSO callback whose `(issuer, subject)` the IdP just proved. A linked, active member gets a
   * session from the member record (`via: "sso"`); a writer or admin first owes the sign-in code, so
   * they get a single-use pending entry instead. An identity row of a member who is not active — a
   * tombstone included — refuses: the IdP cannot undo a local suspension or deletion. No row at all
   * is `unlinked`, and the manager decides by mode. Nothing here looks at email or username.
   * @see member-sso-server.test.ts "an SSO account whose email is a member's does not become that member"
   * @see member-sso-server.test.ts "a suspended or deleted member's identity is refused, not treated as unlinked"
   */
  function ssoSignIn(req: IncomingMessage, issuer: string, subject: string, returnTo: string | null): SsoSignIn {
    let document: MemberDocument;
    try { document = current(); } catch (e) {
      log(`member store unavailable: ${(e as Error).message}`, `회원 저장소를 읽을 수 없음: ${(e as Error).message}`);
      return { kind: "refused", status: 503, error: "the member store is unavailable" };
    }
    const owner = identityOwner(document, issuer, subject);
    if (!owner) return { kind: "unlinked" };
    if (owner.status !== "active") {
      log(`SSO sign-in refused for member ${owner.id}: ${owner.status}`, `회원 ${owner.id}의 SSO 로그인 거부: ${owner.status}`);
      return { kind: "refused", status: 403, error: "the member this SSO account is linked to cannot sign in" };
    }
    if (mayWriteRoles(owner)) {
      if (!deps.otp) return { kind: "refused", status: 503, error: "writer and admin accounts need a one-time code, and this manager has no OTP verifier configured" };
      if (!owner.otpUserId) return { kind: "refused", status: 403, error: "this account needs a one-time code but has no OTP user id — ask an admin to set one" };
      const nowMs = deps.now().getTime();
      trimSsoPending(nowMs);
      const value = randomBytes(32).toString("base64url");
      ssoPending.set(digestOf(value), { memberId: owner.id, issuer, subject, otpUserId: owner.otpUserId, at: nowMs, returnTo });
      return { kind: "otp", cookie: ssoPendingCookie(value) };
    }
    // No await separates the read above from this write, and the session is re-read on every
    // request (`resolve`), so the member is not checked again under the lock.
    try {
      write((d) => {
        recordAudit(d, { actor: owner.id, sourceIp: source(req), now: deps.now() }, "member.login", owner.id);
        trimLoginAudit(d);
      });
    } catch (e) {
      log(`SSO sign-in not recorded: ${(e as Error).message}`, `SSO 로그인 기록 실패: ${(e as Error).message}`);
      return { kind: "refused", status: 503, error: "the member store is unavailable" };
    }
    const s = newSession(req, owner, false, { via: "sso", issuer, subject });
    log(`SSO session for ${owner.principalName} (${owner.id})`, `${owner.principalName}(${owner.id})의 SSO 세션`);
    return { kind: "session", session: s };
  }

  /**
   * `POST /auth/sso/otp {otp}`: the writer's or admin's code after an SSO callback. The pending entry
   * is spent by the first attempt, right or wrong, and lives `SSO_PENDING_TTL_SEC`; a wrong code
   * means signing in with SSO again.
   * @see member-sso-server.test.ts "the pending SSO step is single-use and expires"
   */
  async function ssoOtp(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJson(req);
    fields(body, ["otp"]);
    const code = str(body, "otp", 16);
    const clear = { "set-cookie": clearSsoPendingCookie() };
    const raw = readCookie(req.headers["cookie"], SSO_PENDING_COOKIE);
    const pendingKey = raw ? digestOf(raw) : null;
    const entry = pendingKey ? ssoPending.get(pendingKey) : undefined;
    if (pendingKey) ssoPending.delete(pendingKey);
    if (!entry || deps.now().getTime() - entry.at >= SSO_PENDING_TTL_SEC * 1000) {
      return reply(res, 400, { error: "this SSO sign-in has expired or was already used — sign in with SSO again", restart: true }, clear);
    }
    const changed = (): void => reply(res, 401, { error: "this account changed during sign-in — sign in with SSO again", restart: true }, clear);
    const document = current();
    const member = activeMember(document, entry.memberId);
    if (!member || identityOwner(document, entry.issuer, entry.subject)?.id !== member.id || !mayWriteRoles(member) || member.otpUserId !== entry.otpUserId) {
      return changed();
    }
    // Wrong codes count like wrong passwords: the per-(account, source) wait and the account-wide cap.
    // @see member-sso-server.test.ts "wrong SSO codes wait like wrong passwords, and reach the account cap"
    const from = source(req);
    const key = failureKey(member.username, from);
    const account = accountKey(member.username);
    const nowMs = deps.now().getTime();
    const wait = delayedFor(key, nowMs);
    if (wait > 0) {
      return reply(res, 429, { error: `too many failed sign-ins for this account — try again in ${wait}s`, restart: true }, { ...clear, "retry-after": String(wait) });
    }
    if (accountCapped(account, from, nowMs)) {
      log(`SSO code refused from ${from}: account-wide failure cap`, `${from}의 SSO 코드 거부: 계정 실패 상한`);
      return reply(res, 429, { error: "too many failed sign-ins for this account — try again later", restart: true }, clear);
    }
    const refused = await memberOtp(member, code, "/auth/sso/otp");
    if (refused) {
      if (refused.status === 401) {
        recordFailure(key, nowMs);
        deps.rateLimited(accountFailures, account, nowMs, MEMBER_ACCOUNT_FAILURES_MAX, MEMBER_ACCOUNT_WINDOW_MS, MEMBER_FAILURE_KEYS);
      }
      return reply(res, refused.status, { error: refused.body.error, restart: true }, clear);
    }
    try {
      write((d) => {
        const ctx = { actor: member.id, sourceIp: source(req), now: deps.now() };
        // Re-checked under the lock, as a password sign-in is.
        const live = activeMember(d, member.id);
        if (!live || identityOwner(d, entry.issuer, entry.subject)?.id !== member.id || !mayWriteRoles(live) || live.otpUserId !== entry.otpUserId) {
          throw new MemberError("this account changed during sign-in — sign in with SSO again", 401);
        }
        recordAudit(d, ctx, "member.login", member.id);
        trimLoginAudit(d);
        confirmOtp(d, member.id, entry.otpUserId, ctx);
      });
    } catch (e) {
      if (e instanceof MemberError && e.statusCode === 401) return changed();
      throw e;
    }
    failures.delete(key);
    trustSource(account, from, nowMs);
    const s = newSession(req, member, true, { via: "sso", issuer: entry.issuer, subject: entry.subject });
    log(`SSO session for ${member.principalName} (${member.id}) after its one-time code`, `${member.principalName}(${member.id})의 SSO 세션(일회용 코드 확인 후)`);
    reply(res, 200, {
      you: member.principalName, canWrite: member.roles.includes("writer"), isAdmin: member.roles.includes("admin"),
      csrf: s.csrf, mustChange: false, ...(entry.returnTo ? { next: entry.returnTo } : {}),
    }, { "set-cookie": [cookieHeader(s), clearSsoPendingCookie()] });
  }

  /**
   * The current password, and for a writer or admin a one-time code (`requireOtp`). Answers and
   * returns null on refusal. Wrong passwords share `/api/me/password`'s per-member limit.
   */
  async function reauthenticate(principal: Principal, body: Record<string, unknown>, res: ServerResponse, path: string): Promise<Member | null> {
    const memberId = principal.memberId ?? "";
    const password = str(body, "password", PASSWORD_BODY_MAX_BYTES);
    const document = current();
    const m = activeMember(document, memberId);
    if (!m) { reply(res, 401, { error: "this session has ended — sign in again" }); return null; }
    const credential = passwordCredential(document, memberId);
    if (!credential) { reply(res, 409, { error: "this needs the account's current password, and the account has none" }); return null; }
    const nowMs = deps.now().getTime();
    const failed = meFailures.get(memberId);
    if (failed && nowMs - failed.windowStartedAt < ME_PASSWORD_WINDOW_MS && failed.count >= ME_PASSWORD_FAILURES_MAX) {
      reply(res, 429, { error: "too many wrong current passwords — try again later" });
      return null;
    }
    // @see member-sso-server.test.ts "link start needs the current password, and a writer's code"
    if (!(await verifyPassword(password, credential.hash)).ok) {
      deps.rateLimited(meFailures, memberId, nowMs, ME_PASSWORD_FAILURES_MAX, ME_PASSWORD_WINDOW_MS, MEMBER_FAILURE_KEYS);
      reply(res, 403, { error: "the current password is not correct" });
      return null;
    }
    if (mayWriteRoles(m) && (await deps.requireOtp(principal, body, res, path)) === "answered") return null;
    return m;
  }

  /**
   * `POST /auth/link/start {password, otp?}` from a member password session. `begin` starts the
   * manager's OIDC login with the intent stored server-side beside its `state`, and returns where
   * the browser goes next and the login binder cookie.
   * @see member-sso-server.test.ts "a member links an SSO account and then signs in with it"
   */
  async function linkStart(req: IncomingMessage, res: ServerResponse, begin: (intent: LinkIntent) => Promise<{ location: string; setCookie: string }>): Promise<void> {
    if (!sameOrigin(req)) return reply(res, 403, { error: "this route only answers the console's own page" });
    const s = sessions.get(readCookie(req.headers["cookie"], COOKIE));
    if (!s || s.principal.via !== "password") {
      return reply(res, 403, { error: "linking an SSO account needs a password session — sign in with your password" });
    }
    const refusal = checkCsrf(s, {
      origin: typeof req.headers["origin"] === "string" ? req.headers["origin"] : undefined,
      csrf: typeof req.headers[CSRF_HEADER] === "string" ? (req.headers[CSRF_HEADER] as string) : undefined,
    }, selfOrigin(req));
    if (refusal) return reply(res, 403, { error: "missing or invalid CSRF token — reload the console" });
    try {
      const resolved = resolve(s);
      if (!resolved.ok) return reply(res, resolved.status, { error: resolved.error }, resolved.status === 401 ? { "set-cookie": clearCookieHeader() } : {});
      if (resolved.principal.mustChange) return reply(res, 403, { error: "password change required", mustChange: true });
      const body = await readJson(req, PASSWORD_BODY_MAX_BYTES);
      fields(body, ["password", "otp"]);
      const m = await reauthenticate(resolved.principal, body, res, "/auth/link/start");
      if (!m) return;
      const started = await begin({ kind: "link", memberId: m.id, sessionId: s.id });
      log(`SSO link started for ${m.username} (${m.id})`, `${m.username}(${m.id})의 SSO 연결 시작`);
      reply(res, 200, { location: started.location }, { "set-cookie": started.setCookie });
    } catch (e) { sendError(res, e); }
  }

  /**
   * The callback half of a link. The intent came from the pending login record, never from the
   * request. The session that started it must still be alive and the member's, and the identity
   * must be free: one bound to another member, or kept as a deleted member's tombstone, refuses.
   * Group claims play no part.
   * @see member-sso-server.test.ts "linking refuses an identity bound to another member or kept as a tombstone"
   */
  function completeLink(intent: LinkIntent, issuer: string, subject: string, from: string):
    { ok: true } | { ok: false; code: "ended" | "taken" | "tombstone" | "invalid" | "unavailable"; error: string } {
    const s = sessions.get(intent.sessionId);
    if (!s || s.principal.via !== "password" || s.principal.memberId !== intent.memberId) {
      return { ok: false, code: "ended", error: "the session that started this link has ended — sign in and start again" };
    }
    // Rebuild from the store, as every protected request does. A direct credential or status edit
    // during the IdP round trip must not let a session which is already invalid bind an identity.
    // @see member-sso-server.test.ts "a link callback re-reads the session that started it"
    const resolved = resolve(s);
    if (!resolved.ok || resolved.principal.via !== "password" || resolved.principal.memberId !== intent.memberId) {
      return { ok: false, code: resolved.ok ? "invalid" : resolved.status === 503 ? "unavailable" : "ended", error: resolved.ok ? "the link session is not a password session" : resolved.error };
    }
    try {
      write((d) => {
        if (!activeMember(d, intent.memberId)) throw new MemberError("the member that started this link cannot sign in", 401);
        linkIdentity(d, { memberId: intent.memberId, issuer, subject }, { actor: intent.memberId, sourceIp: from, now: deps.now() });
      });
    } catch (e) {
      if (!(e instanceof MemberError)) {
        log(`SSO link failed: ${(e as Error).message}`, `SSO 연결 실패: ${(e as Error).message}`);
        return { ok: false, code: "unavailable", error: "the member store is unavailable" };
      }
      const code = e.statusCode === 401 ? "ended" : e.code === "identity-tombstone" ? "tombstone" : e.code === "identity-taken" ? "taken" : "invalid";
      log(`SSO link refused for member ${intent.memberId}: ${e.message}`, `회원 ${intent.memberId}의 SSO 연결 거부: ${e.message}`);
      return { ok: false, code, error: e.message };
    }
    log(`SSO account linked to member ${intent.memberId}`, `회원 ${intent.memberId}에 SSO 계정 연결`);
    return { ok: true };
  }

  /** An identity as screens show it: the issuer, and only the subject's last four characters. */
  const identityView = (i: { issuer: string; subject: string; linkedAt: string }): Record<string, unknown> => ({
    id: identityHandle(i), issuer: i.issuer, subject: `…${i.subject.length > 4 ? i.subject.slice(-4) : ""}`, linkedAt: i.linkedAt,
  });

  /**
   * `POST /auth/logout` for a member password session: it needs its CSRF token to end, and works
   * whether or not OIDC is configured. False for any other session, which the OIDC handler ends.
   * @see member-auth-server.test.ts "logout of a member session needs the CSRF token"
   * @see member-auth-server.test.ts "signs a member out without OIDC configured"
   */
  function logout(req: IncomingMessage, res: ServerResponse): boolean {
    const id = readCookie(req.headers["cookie"], COOKIE);
    const s = sessions.get(id);
    if (!s || !isMemberSession(s.principal)) return false;
    const origin = req.headers["origin"];
    const refusal = checkCsrf(s, {
      origin: typeof origin === "string" ? origin : undefined,
      referer: typeof req.headers["referer"] === "string" ? req.headers["referer"] : undefined,
      csrf: typeof req.headers[CSRF_HEADER] === "string" ? (req.headers[CSRF_HEADER] as string) : undefined,
    }, selfOrigin(req));
    if (refusal) {
      reply(res, 403, { error: "missing or invalid CSRF token — reload the console" });
      return true;
    }
    log(`session for ${s.principal.name} ended`, `${s.principal.name}의 세션 종료`);
    sessions.destroy(s.id);
    reply(res, 200, { endSession: null }, { "set-cookie": clearCookieHeader() });
    return true;
  }

  /** `/auth/password/{login,reset,reset-request}`, `/auth/invite/accept`, `/auth/sso/otp`, and a member session's `/auth/logout`. False for any other path. */
  async function handleAuthRoute(url: URL, req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    if (req.method === "POST" && url.pathname === "/auth/logout") return logout(req, res);
    const route = req.method === "POST" ? ({
      "/auth/password/login": { run: login, hits: loginHits },
      "/auth/password/reset": { run: resetPassword, hits: tokenHits },
      "/auth/password/reset-request": { run: requestReset, hits: resetRequestHits },
      "/auth/invite/accept": { run: acceptInvite, hits: tokenHits },
      "/auth/sso/otp": { run: ssoOtp, hits: loginHits },
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
      identities: document.identities.filter((i) => i.memberId === m.id).map(identityView),
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
        hasPassword: passwordCredential(document, m.id) !== null, soloApprove: m.soloApprove,
        identities: document.identities.filter((i) => i.memberId === m.id).map(identityView),
        // The session's own token, for the one caller holding its cookie. `/api/authz` carries it
        // too, but answers nothing while the password must change, and sign-out still needs it then.
        csrf: session.csrf,
      });
    }
    if (req.method === "POST" && url.pathname === "/api/me/password") {
      const body = await readJson(req, PASSWORD_BODY_MAX_BYTES);
      fields(body, ["current", "next"]);
      const currentPassword = str(body, "current", PASSWORD_BODY_MAX_BYTES);
      const next = str(body, "next", PASSWORD_BODY_MAX_BYTES);
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
      const problems = checkPasswordPolicy(next);
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
    // Unlinking needs the current password (and a writer's code). A member without a password is
    // therefore refused by `reauthenticate` before the store's last-login-method guard is reached;
    // that guard is reached by the admin unlink route below.
    // @see member-sso-server.test.ts "unlinking needs the password, and ends the sessions that identity signed in"
    // @see member-sso-server.test.ts "a member without a password cannot self-unlink: reauthentication needs a password"
    const linked = /^\/api\/me\/identities\/([0-9a-f]{16})$/.exec(url.pathname);
    if (req.method === "DELETE" && linked) {
      const body = await readJson(req, PASSWORD_BODY_MAX_BYTES);
      fields(body, ["password", "otp"]);
      const target = current().identities.find((i) => i.memberId === memberId && identityHandle(i) === linked[1]);
      if (!target) return reply(res, 404, { error: "no such linked identity" });
      if (!(await reauthenticate(principal, body, res, url.pathname))) return;
      // The SSO sessions it signed in end on their next request: `resolve` checks the link.
      write((d) => unlinkIdentity(d, { memberId, issuer: target.issuer, subject: target.subject }, { actor: memberId, sourceIp: source(req), now: deps.now() }));
      log(`identity unlinked from member ${memberId}`, `회원 ${memberId}의 identity 연결 해제`);
      return reply(res, 200, { ok: true });
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
      if ((await deps.requireOtp(principal, body, res, url.pathname)) === "answered") return;
      const issued = write((d) => {
        if (findByEmail(d, email)) throw new MemberError("email is already in use", 409);
        return issueToken(d, { kind: "invite", email, roles }, { actor, sourceIp: source(req), now: deps.now() });
      });
      log(`invitation ${issued.row.id} issued by ${principal.name}`, `${principal.name}이(가) 초대 ${issued.row.id} 발급`);
      const inviteUrl = linkTo("invite", issued.token);
      // A failed send leaves the invitation valid: unlike a reset, the admin holds the link from this
      // answer and can hand it over. So the answer always carries it, and says whether mail went.
      // @see member-mail-server.test.ts "an invitation whose mail fails keeps a working link"
      let mailed = false;
      let mailError: string | undefined;
      if (deps.mail) {
        try {
          await sendMail(deps.mail, inviteMail(issued.row.email!, inviteUrl));
          mailed = true;
        } catch (e) {
          const { step, code } = mailFailure(e);
          mailError = step;
          log(`invitation ${issued.row.id}: mail failed at ${step} (${code})`, `초대 ${issued.row.id}: 메일 실패 ${step} (${code})`);
        }
      }
      return reply(res, 201, { id: issued.row.id, expiresAt: issued.row.expiresAt, inviteUrl, mailed, ...(mailError ? { mailError } : {}) });
    }
    // An admin removes another member's linked identity. The store keeps refusing a member's last
    // way in and a deleted member's tombstones.
    // @see member-sso-server.test.ts "an admin unlinks another member's identity with a code, never their own"
    const unlink = /^\/api\/members\/([0-9a-f-]{36})\/identities\/([0-9a-f]{16})\/unlink$/.exec(url.pathname);
    if (unlink) {
      const [, id, handle] = unlink as unknown as [string, string, string];
      fields(body, ["otp"]);
      if (id === actor) return reply(res, 403, { error: "an admin cannot unlink their own identities here — use the account page" });
      const target = current().identities.find((i) => i.memberId === id && identityHandle(i) === handle);
      if (!target) return reply(res, 404, { error: "no such linked identity" });
      if ((await deps.requireOtp(principal, body, res, url.pathname)) === "answered") return;
      write((d) => unlinkIdentity(d, { memberId: id, issuer: target.issuer, subject: target.subject }, { actor, sourceIp: source(req), now: deps.now() }));
      const ended = sessions.endIdentity(target.issuer, target.subject);
      log(`identity unlinked from member ${id} by ${principal.name}; ended ${ended} sessions`, `${principal.name}이(가) 회원 ${id}의 identity 연결 해제; 세션 ${ended}개 종료`);
      const after = current();
      const member = after.members.find((x) => x.id === id);
      return reply(res, 200, { ...(member ? { member: memberView(after, member) } : {}), endedSessions: ended });
    }
    const m = /^\/api\/members\/([0-9a-f-]{36})\/(roles|suspend|unsuspend|delete|otp-user|cert-cns|password-reset|solo-approve)$/.exec(url.pathname);
    if (!m) return reply(res, 404, { error: `no such route ${url.pathname}` });
    const [, id, action] = m as unknown as [string, string, string];
    const allowed: Record<string, readonly string[]> = {
      "roles": ["roles", "otp"], "otp-user": ["otpUserId", "otp"], "cert-cns": ["add", "remove", "otp"],
      "solo-approve": ["soloApprove", "otp"],
    };
    fields(body, allowed[action] ?? ["otp"]);
    const roles = action === "roles" ? stringList(body, "roles") : null;
    const otpUser = action === "otp-user"
      ? (body.otpUserId === null ? null : str(body, "otpUserId", 128))
      : undefined;
    const add = action === "cert-cns" ? optStr(body, "add", 128) : undefined;
    const remove = action === "cert-cns" ? optStr(body, "remove", 128) : undefined;
    if (action === "cert-cns" && (add === undefined) === (remove === undefined)) throw new BadRequest("send exactly one of add or remove");
    if (action === "solo-approve" && typeof body.soloApprove !== "boolean") throw new BadRequest("soloApprove must be true or false");
    const solo = body.soloApprove === true;
    // An admin may not raise or re-point their own authority here; another admin, or the CLI, must.
    // @see member-auth-server.test.ts "an admin cannot change their own roles or otpUserId"
    // @see member-sso-server.test.ts "an admin sets another member's solo approval with a code, never their own"
    if (id === actor && (action === "roles" || action === "otp-user" || action === "solo-approve")) {
      return reply(res, 403, { error: "an admin cannot change their own roles, one-time code or solo approval — another admin must" });
    }
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
      else if (action === "solo-approve") setSoloApprove(d, id, solo, ctx);
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

  /** `/api/me*` and `/api/members*`, for a member session only. False for any other path. */
  async function handleApiRoute(principal: Principal, session: Session | null, url: URL, req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const p = url.pathname;
    const isMe = p === "/api/me" || p.startsWith("/api/me/");
    const isMembers = p === "/api/members" || p.startsWith("/api/members/");
    if (!isMe && !isMembers) return false;
    if (!isMemberSession(principal) || !session) {
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

  return { resolve, mustChangeRefuses, handleAuthRoute, handleApiRoute, document, ssoSignIn, linkStart, completeLink };
}
