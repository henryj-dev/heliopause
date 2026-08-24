// Browser sessions for the console, and the CSRF defence that has to come with them.
//
// ## Why this is the dangerous half
//
// A client certificate is not sent by a cross-origin page. A cookie is — that is what cookies do. So
// the moment a session can publish a generation, every page the operator has open becomes a caller
// of `POST /publish`, and the only thing between them is what is in this file.
//
// V55 already found that mTLS does not stop CSRF; the console was vulnerable before it had a single
// button. Cookies make that worse rather than different, and the site's own choice here was full
// parity with certificates — read, propose, approve and publish. So the defence is layered, and each
// layer is written to be sufficient on its own:
//
//   1. `SameSite=Strict` — the browser does not attach the cookie to a cross-site request at all.
//   2. `Origin` must equal the console's own origin on every state-changing request.
//   3. A per-session CSRF token, echoed in a **custom header**.
//
// The third is the one that holds when the others are wrong. A cross-origin form POST cannot set a
// custom header, and a cross-origin `fetch` that sets one triggers a preflight — which this server
// answers for nobody, because it sends no CORS headers at all. An attacker therefore cannot make the
// browser produce a request this accepts, even if a future browser bug weakens `SameSite`.
//
// ## Why sessions live in memory
//
// The manager is one pod. A restart ends every session, and that is the correct trade: it makes
// revocation trivial and total, and the cost is a login. A signed cookie carrying its own claims
// would survive restarts and would also be un-revocable without building the very table this avoids.
//
// **That restart is still the only way to force-terminate a session from outside, and the reason has
// moved.** It used to be the identity provider's: back-channel logout found its targets through
// `oidcGrants` (garbage-collected minutes after login) and `oidcRefreshTokens` (only issued for
// `offline_access`, which this client does not request), so this console dropped off the notify list
// shortly after anyone signed in. **KeyStone fixed that** — since 2026-08-06 they discover targets by
// subject, from assignments, and an administrator's force-logout does reach clients that registered
// an endpoint.
//
// **That gap is now closed on our side.** `/auth/backchannel-logout` verifies the SET and ends every
// session the subject holds — `backchannel_logout_session_required` off, so a `sub` and no `sid`,
// because "end this person's session" is a statement about a person and is true of every session
// they hold, including one in a browser they have forgotten about.
//
// **What remains is registration.** The client's Back-channel Logout URI is still blank in KeyStone,
// and filling it in is a human step there. Until it is filled, an administrator's force-logout still
// reaches nobody here — the route exists and is never called. The order matters only in one
// direction: a URI registered without a route would show a successful logout while every session
// kept working, and that is why this was built first.
//
// The Role Change SET closes the *authority* half today — a revoked role arrives and the session is
// re-evaluated. It does not close the *session* half: logging somebody out without changing their
// role produces no event.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** Who a session belongs to, and what the IdP said about them. */
export interface Principal {
  /**
   * The name authorisation is decided on — the same string space as a certificate CN.
   *
   * This is deliberate and load-bearing. `approval.ts` refuses an approval when
   * `plan.proposedBy === input.by`, a plain string comparison, so one human arriving twice under two
   * names would satisfy the two-person rule alone. Mapping an OIDC identity onto its certificate CN
   * is what keeps that check meaningful — see `canonical` in the manager's OIDC wiring.
   */
  name: string;
  /** The IdP's subject, kept for the audit line rather than for decisions. */
  sub: string;
  /** Group and role claims as they arrived. Authorisation reads these; nothing else does. */
  groups: readonly string[];
  /** How this identity was proved. Recorded so a log line can say which door was used. */
  via: "certificate" | "oidc";
  /**
   * Whether this principal may propose, approve and publish.
   *
   * Decided once, when the session is created, and carried. Re-deriving it per request from the
   * stored group claims would produce the same answer from the same stale data while looking like a
   * fresh check — and the honest statement is that these claims are as old as the session.
   *
   * For a certificate this is read from `writerCNs` on every request instead, because that list is
   * configuration the process already holds and nothing about it goes stale mid-session.
   */
  canWrite: boolean;
}

export interface Session {
  id: string;
  principal: Principal;
  csrf: string;
  createdAt: Date;
  expiresAt: Date;
}

export interface SessionLimits {
  /** Absolute lifetime. A session does not extend past this however active it is. */
  ttlSec: number;
  /** Ceiling on concurrent sessions, so a login loop cannot grow this map without bound. */
  max: number;
}

export const DEFAULT_LIMITS: SessionLimits = { ttlSec: 8 * 3600, max: 64 };

/** The cookie name. `__Host-` forces the browser to enforce Secure, no Domain, and Path=/. */
export const COOKIE = "__Host-heliopause-session";

/** The header a state-changing request must carry. Its presence is half the CSRF defence. */
export const CSRF_HEADER = "x-heliopause-csrf";

export class SessionStore {
  private readonly sessions = new Map<string, Session>();
  private readonly limits: SessionLimits;
  private readonly now: () => Date;

  constructor(limits: SessionLimits = DEFAULT_LIMITS, now: () => Date = () => new Date()) {
    this.limits = limits;
    this.now = now;
  }

  /**
   * Start a session.
   *
   * Both identifiers come from the CSPRNG and neither is derived from the other. A CSRF token
   * derived from the session id would be recoverable by anything that ever saw the id — including a
   * proxy log, if the id ever ended up in a URL.
   */
  create(principal: Principal): Session {
    this.sweep();
    if (this.sessions.size >= this.limits.max) {
      // Oldest first. Refusing the new login instead would let anyone lock out the operator by
      // filling the table, and the failure would look like a broken IdP.
      const oldest = [...this.sessions.values()].sort((a, b) => +a.createdAt - +b.createdAt)[0];
      if (oldest) this.sessions.delete(oldest.id);
    }
    const at = this.now();
    const s: Session = {
      id: randomBytes(32).toString("base64url"),
      principal,
      csrf: randomBytes(32).toString("base64url"),
      createdAt: at,
      expiresAt: new Date(at.getTime() + this.limits.ttlSec * 1000),
    };
    this.sessions.set(s.id, s);
    return s;
  }

  /** The live session for a cookie value, or null. Expiry is checked here, not by a sweep. */
  get(id: string | null): Session | null {
    if (!id) return null;
    const s = this.sessions.get(id);
    if (!s) return null;
    if (s.expiresAt <= this.now()) {
      this.sessions.delete(id);
      return null;
    }
    return s;
  }

  /** End one session. Idempotent — logging out twice is not an error worth reporting. */
  destroy(id: string | null): void {
    if (id) this.sessions.delete(id);
  }

  /**
   * Apply an authority change to every session belonging to one IdP subject.
   *
   * Subject-scoped because that is what a role change is: the IdP's Security Event Token carries
   * `sub` and no `sid`, and "this person's authority is now X" is true of every session they hold,
   * including the one in a browser they forgot about.
   *
   * `decide` returns the new principal, or `null` to end the session. Returning null is the
   * important case — an identity that no longer holds an operator role must not keep reading the
   * fleet, and demoting it to a principal with no access would leave a session that authenticates
   * and can do nothing, which reads like a bug to whoever hits it.
   *
   * Returns what happened, for the log line. A role change that matched no session is not an error:
   * the person may simply not be signed in.
   */
  applyToSubject(
    sub: string,
    decide: (current: Principal) => Principal | null,
  ): { updated: number; ended: number } {
    let updated = 0;
    let ended = 0;
    for (const [id, s] of this.sessions) {
      if (s.principal.sub !== sub) continue;
      const next = decide(s.principal);
      if (next === null) {
        this.sessions.delete(id);
        ended++;
      } else {
        s.principal = next;
        updated++;
      }
    }
    return { updated, ended };
  }

  get size(): number {
    return this.sessions.size;
  }

  private sweep(): void {
    const t = this.now();
    for (const [id, s] of this.sessions) if (s.expiresAt <= t) this.sessions.delete(id);
  }
}

// ── Cookies ───────────────────────────────────────────────────────────────────

/**
 * Read one cookie from a `Cookie` header.
 *
 * Hand-parsed rather than split-and-trust: a header may carry several cookies with the same name
 * (different Path or Domain), and taking the last would let a subdomain overwrite the session for
 * the host. Taking the first match is what the browser's own precedence gives.
 */
export function readCookie(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    const v = part.slice(eq + 1).trim();
    return v.length ? v : null;
  }
  return null;
}

/**
 * The `Set-Cookie` value for a session.
 *
 * `__Host-` is not decoration: the prefix makes the browser refuse the cookie unless it is `Secure`,
 * has no `Domain`, and has `Path=/`. That removes a whole class of mistake — a cookie scoped to a
 * parent domain is readable by every sibling host on it.
 *
 * `SameSite=Strict` rather than `Lax`. `Lax` still sends the cookie on a top-level GET navigation,
 * and this console has no GET that changes anything today — but "no state-changing GET" is a property
 * that has to be maintained forever for `Lax` to be safe, and nothing enforces it.
 */
export function cookieHeader(s: Session): string {
  const maxAge = Math.max(0, Math.floor((+s.expiresAt - Date.now()) / 1000));
  return `${COOKIE}=${s.id}; Max-Age=${maxAge}; Path=/; Secure; HttpOnly; SameSite=Strict`;
}

/** The `Set-Cookie` that removes it. Same attributes, or the browser keeps the original. */
export function clearCookieHeader(): string {
  return `${COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict`;
}

// ── The login itself, which was not tied to a browser ─────────────────────────
//
// ## What was wrong
//
// `state` was minted here and kept in a server-side map, and the comment on that map said the map
// lookup *is* the check: "`state` was generated here, from the CSPRNG, and only this server has ever
// held it." Both halves are true and they do not add up to the property that was wanted.
//
// The map is not keyed to a browser. So:
//
//   1. the attacker opens `/auth/login` in **their own** browser and authenticates at the IdP
//   2. they stop before the redirect completes and keep the `code` and `state`
//   3. they get the victim to open `/auth/callback?state=…&code=…`
//   4. this server finds the state, exchanges the code, and sets **the attacker's session** as a
//      cookie in the victim's browser
//
// The victim is now signed in as somebody else, on a console that can approve and publish a firewall
// change — and `approval.ts` compares proposer and approver as strings, so whatever they do is
// recorded under the attacker's name. Neither `safeReturnTo` (which stops the redirect being open)
// nor single-use `state` (which stops the *same* callback being replayed twice) touches this.
//
// ## What closes it
//
// A second value minted at the same time: kept in the pending record as a digest, and handed to the
// browser as a cookie. The callback must present a cookie whose digest matches the record the
// `state` names. The attacker can produce the `state` — it travels through the IdP in the URL — and
// cannot produce a cookie in the victim's browser.
//
// The digest rather than the value, for the same reason a session id is not derived from anything:
// the pending map is the thing an attacker would have to read anyway, and there is no reason for it
// to hold the secret in the clear.
export const LOGIN_COOKIE = "__Host-heliopause-login";

/**
 * How long the browser keeps it. Matches the pending-login TTL; the record expires either way, and a
 * cookie outliving the thing it unlocks is just a value sitting in a browser.
 */
const LOGIN_COOKIE_MAX_AGE_SEC = 10 * 60;

/**
 * `SameSite=Lax`, and this is the one cookie here that **must not** be `Strict`.
 *
 * The callback is a top-level navigation the *identity provider* sends the browser on, so it is
 * cross-site by construction. `Strict` withholds the cookie on exactly that request, and the login
 * would fail for everybody with a message about a missing binder — the check would be enforcing
 * itself into an outage. `Lax` sends it on a top-level GET, which is what a redirect is, and
 * withholds it from every subresource and every form post, which is what matters.
 */
export function loginCookieHeader(value: string): string {
  return `${LOGIN_COOKIE}=${value}; Max-Age=${LOGIN_COOKIE_MAX_AGE_SEC}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

/** Removes it. Sent on every callback, including the refusals — it is spent either way. */
export function clearLoginCookieHeader(): string {
  return `${LOGIN_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

/**
 * A login binder and the digest to store beside `state`.
 *
 * Two concurrent logins in one browser overwrite each other's cookie, so the newer one wins and the
 * older refuses. That is correct rather than merely acceptable: the older attempt's `state` is still
 * single-use and still expires, and a browser that started two logins is answering the second.
 */
export function loginBinder(): { value: string; digest: string } {
  const value = randomBytes(32).toString("base64url");
  return { value, digest: createHash("sha256").update(value).digest("base64url") };
}

/** Does this cookie unlock that pending record? Constant-time, and false for anything absent. */
export function loginBinderMatches(cookie: string | null, digest: string | undefined): boolean {
  if (!cookie || !digest) return false;
  return constantEquals(createHash("sha256").update(cookie).digest("base64url"), digest);
}

// ── CSRF ──────────────────────────────────────────────────────────────────────

/** Why a state-changing request was refused. `null` means it was accepted. */
export type CsrfRefusal = "origin" | "token" | null;

/**
 * Check a state-changing request from a cookie session.
 *
 * Only for cookie sessions. A request authenticated by a client certificate is not subject to this:
 * a browser does not attach a certificate to a cross-origin request the way it attaches a cookie, and
 * requiring the header there would break every CLI caller for no gain.
 *
 * `expectedOrigin` is the console's own origin, built from the request's own Host. Comparing against
 * a configured value would be stricter, and would also make the manager unreachable by any name its
 * configuration did not anticipate — including the IP the operator CLI uses.
 */
export function checkCsrf(
  session: Session,
  headers: { origin?: string; referer?: string; csrf?: string },
  expectedOrigin: string,
): CsrfRefusal {
  // `Origin` is set by the browser on every request that can change state and cannot be forged by
  // page script. When it is absent — some older clients omit it — `Referer` carries the same fact.
  const stated = headers.origin ?? (headers.referer ? originOf(headers.referer) : null);
  if (stated === null || stated !== expectedOrigin) return "origin";
  if (!headers.csrf || !constantEquals(headers.csrf, session.csrf)) return "token";
  return null;
}

function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

function constantEquals(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}
