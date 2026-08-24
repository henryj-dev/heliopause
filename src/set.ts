// Security Event Tokens — the IdP telling us somebody's authority changed.
//
// ## Why this exists
//
// Authorisation is decided once, at login, and carried on the session (`Principal.canWrite`). That is
// honest — the group and role claims really are as old as the session — but it leaves a window: a
// revoked role stays effective until the session expires, up to eight hours.
//
// For most of what this console does that window is tolerable. It is not tolerable for one thing:
// the `admin` role permits approving a plan one proposed oneself, which is the two-person rule
// switched off. Revoking that role has to take effect now, not eventually.
//
// So KeyStone pushes a signed token when an assignment changes, and this reads it.
//
// ## What a SET is not
//
// It is not an ID token, and the difference is load-bearing. An ID token proves "this person just
// authenticated"; a SET asserts "this person's authority is now X" with no authentication event
// behind it. Accepting one where the other is expected is how a login token becomes a privilege
// grant. `typ` is checked for exactly that reason, before anything else in the payload is read.
//
// ## Ordering is our problem too, and it is the sharper one
//
// The token carries the **whole state after a change**, not a delta, and delivery is fire-and-forget
// with no retry. So two changes moments apart can arrive backwards:
//
//     T+0.0s  granted   → { entitlements: ["plan.publish"] }
//     T+0.3s  revoked   → { entitlements: [] }
//     arrives backwards → the revocation is undone and nobody can tell
//
// `iat` is in seconds and cannot separate those. `txn` is the issuing millisecond, and the rule is
// to keep the last one applied **per subject** and discard anything not newer. Per subject, because
// one user's ordering says nothing about another's.
//
// ## Replay is our problem here
//
// An ID token carries a nonce this server generated, so a captured one cannot be reused. A SET
// carries none — deliberately, per the RFC and per KeyStone's own comment ("id_token 오용을 막기
// 위해 nonce 는 절대 넣지 않는다").
//
// That matters in one direction only, and it is the dangerous one: a captured SET saying
// `roles: ["admin"]` replayed after a demotion would **restore** the role. So freshness and
// single-use are enforced here — an `iat` window and a seen-`jti` set.

import { OidcError, verifyJws, type Provider } from "./oidc.ts";

// The event key is **configuration, not a constant.** It was one, and it named a specific identity
// provider's domain in tracked source — which made this file both a site-data leak and a hard
// dependency on one deployment's IdP. A default here is worse than no default: a deployment behind a
// different provider would compile, start, and silently discard every role change as "carries no
// role-change event", which is the failure this whole module exists to prevent.
//
// RFC 8417 does not define the key. The issuer chooses it and tells the RP, so the RP has to be told.

/** Bound on remembered `jti` values. Far above any plausible burst; a cap, not a policy. */
const MAX_SEEN = 4096;

/**
 * Bound on remembered per-subject watermarks. Same reasoning as `MAX_SEEN`, and it was missing.
 *
 * Far above the number of people who can sign in to this console — the session table itself holds
 * 64 — so reaching it means something other than ordinary use.
 */
const MAX_SUBJECTS = 4096;

/** Upper bound on a token's own lifetime, whatever `exp` says. */
const MAX_LIFETIME_SEC = 3600;

/** The authoritative state after the change. Empty arrays mean "everything revoked", not "unchanged". */
export interface RoleChange {
  /** KeyStone user id — the same value as the `sub` claim on an ID token. */
  sub: string;
  roles: string[];
  entitlements: string[];
}

/**
 * Remembers which tokens have been applied.
 *
 * Separate from the verifier so a caller can hold one across requests, and so a test can drive it.
 */
export class RoleChangeLedger {
  private readonly seen = new Set<string>();
  private readonly lastTxn = new Map<string, bigint>();

  /**
   * True when this `txn` is newer than the last one applied for this subject.
   *
   * Compared as `bigint` rather than `Number`: the value is a millisecond timestamp as a string, and
   * while it fits in a double today, parsing a timestamp with `Number` is the kind of thing that is
   * fine until it is not. Equal is rejected as well as older — two snapshots cannot share an instant,
   * so an equal `txn` is the same token arriving twice.
   */
  accepts(sub: string, txn: bigint): boolean {
    const last = this.lastTxn.get(sub);
    return last === undefined || txn > last;
  }

  /**
   * Record that this subject's state has been advanced to `txn`.
   *
   * Bounded like `seen`, and it was not — `MAX_SEEN` capped the `jti` set while this map grew one
   * entry per subject for the lifetime of the process. Every entry requires a signed token from the
   * issuer, so it is not reachable by an anonymous caller; it is still a table that only ever grows
   * in a process meant to stay up for months.
   *
   * Eviction is least-recently-advanced, and losing an entry is safe in the direction that matters:
   * a subject with no watermark accepts the next token whatever its `txn`. The exposure that
   * reintroduces is a *stale* snapshot arriving after its eviction — and `MAX_LIFETIME_SEC` already
   * bounds a token to an hour, so anything old enough to have been evicted from a table this size
   * has expired on its own.
   */
  advance(sub: string, txn: bigint): void {
    // Re-inserted rather than updated, so `Map` order tracks recency and the eviction below drops
    // the subject nobody has heard about in longest.
    this.lastTxn.delete(sub);
    this.lastTxn.set(sub, txn);
    while (this.lastTxn.size > MAX_SUBJECTS) {
      const oldest = this.lastTxn.keys().next().value;
      if (oldest === undefined) break;
      this.lastTxn.delete(oldest);
    }
  }

  /** True the first time a `jti` is offered, false afterwards. */
  claim(jti: string): boolean {
    if (this.seen.has(jti)) return false;
    // Oldest-first eviction by insertion order, which is what a Set gives. A replayed token older
    // than the last 4096 would be accepted again — and would also be well outside `MAX_AGE_SEC`,
    // which is the check that actually bounds this.
    if (this.seen.size >= MAX_SEEN) {
      const oldest = this.seen.values().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    this.seen.add(jti);
    return true;
  }

  get size(): number {
    return this.seen.size;
  }
}

/**
 * Verify a role-change SET and return what it asserts.
 *
 * Throws `OidcError` on every refusal, with a status the caller can answer with. There is no
 * "probably fine" path: a token this cannot fully verify changes nothing.
 */
export async function verifyRoleChange(
  provider: Provider,
  token: string,
  o: { clientId: string; issuer: string; ledger: RoleChangeLedger; eventKey: string },
  nowMs: () => number = Date.now,
): Promise<RoleChange> {
  const { header, payload } = await verifyJws(provider, token, "role-change token");

  // First, before any claim is trusted for anything. An ID token has a valid signature from this
  // same key, and without this check one would be accepted here as an authority assertion.
  if (header.typ !== "secevent+jwt") {
    throw new OidcError(`role-change token has typ ${String(header.typ)}, expected secevent+jwt`, 401);
  }

  if (payload.iss !== o.issuer) {
    throw new OidcError(`role-change token issuer ${String(payload.iss)} is not ${o.issuer}`, 401);
  }
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(o.clientId)) {
    throw new OidcError("role-change token is addressed to another client", 401);
  }

  // Freshness. Both directions: an old token is a replay, and one from the future is a clock that
  // cannot be reasoned about — accepting it would make the expiry meaningless.
  const now = Math.floor(nowMs() / 1000);
  if (typeof payload.iat !== "number") throw new OidcError("role-change token has no iat", 401);
  if (payload.iat > now + 60) throw new OidcError("role-change token is issued in the future", 401);
  if (typeof payload.exp !== "number") throw new OidcError("role-change token has no exp", 401);
  if (payload.exp <= now) throw new OidcError("role-change token has expired", 401);
  // The issuer sets `exp`; this bounds how long it may set it for. A token good for a year would be
  // a replay window disguised as a configuration value, and the RP is the side that pays for it.
  if (payload.exp - payload.iat > MAX_LIFETIME_SEC) {
    throw new OidcError(`role-change token lifetime exceeds ${MAX_LIFETIME_SEC}s`, 401);
  }

  // Single use. Claimed after the signature and freshness checks so an attacker cannot burn a `jti`
  // this server has not verified.
  if (typeof payload.jti !== "string" || !payload.jti) {
    throw new OidcError("role-change token has no jti", 401);
  }
  if (!o.ledger.claim(payload.jti)) {
    throw new OidcError("role-change token has already been applied", 409);
  }

  if (typeof payload.sub !== "string" || !payload.sub) {
    throw new OidcError("role-change token has no sub", 401);
  }

  // Ordering, before the payload is read and before anything is recorded. Required rather than
  // optional: a snapshot that cannot be ordered is one whose effect might be to undo a revocation,
  // and a refusal here is visible in the log while a silent revert is not.
  if (typeof payload.txn !== "string" || !/^[0-9]+$/.test(payload.txn)) {
    throw new OidcError("role-change token has no txn — cannot order it against what was applied", 401);
  }
  const txn = BigInt(payload.txn);
  if (!o.ledger.accepts(payload.sub, txn)) {
    throw new OidcError("role-change token is older than the last one applied for this subject", 409);
  }

  const events = payload.events;
  if (typeof events !== "object" || events === null) {
    throw new OidcError("role-change token has no events", 400);
  }
  const ev = (events as Record<string, unknown>)[o.eventKey];
  if (typeof ev !== "object" || ev === null) {
    // A SET carrying only events we do not handle is not an error to shout about, but it is also
    // not something to apply. Refusing with 400 says "this reached the right place and said nothing
    // I act on", which is what an operator reading the IdP's delivery log needs.
    throw new OidcError("role-change token carries no role-change event", 400);
  }

  // Both arrays are always present on a SET, unlike the login claims where an empty `entitlements`
  // is omitted. That difference is deliberate on KeyStone's side and it is the whole point: here an
  // empty array means "everything revoked", and a missing key would be indistinguishable from
  // "unchanged".
  const e = ev as Record<string, unknown>;
  // Advanced only once everything has verified. Recording earlier would let a token this refuses
  // move the watermark, and the next genuine snapshot would then be discarded as stale.
  o.ledger.advance(payload.sub, txn);
  return {
    sub: payload.sub,
    roles: stringList(e.roles, "roles"),
    entitlements: stringList(e.entitlements, "entitlements"),
  };
}

function stringList(v: unknown, what: string): string[] {
  if (!Array.isArray(v)) throw new OidcError(`role-change event ${what} is not an array`, 400);
  return v.filter((x): x is string => typeof x === "string");
}

/** What a verified back-channel logout says: end this person's sessions. */
export interface BackchannelLogout {
  /** KeyStone user id, the same value as an ID token's `sub`. */
  sub: string;
}

/**
 * Verify an OIDC Back-Channel Logout token and say whose sessions it ends.
 *
 * ## Why this is separate from `verifyRoleChange` rather than a flag on it
 *
 * The two share every check that makes a SET trustworthy — signature, `typ`, issuer, audience,
 * freshness, single-use `jti` — and differ on the one that decides what the token *means*. A role
 * change is a snapshot and must be ordered, or a stale one arriving late would undo a revocation;
 * `txn` is required there for exactly that reason. A logout is not a snapshot. It cannot be undone
 * by a later token, there is nothing for it to revert, and demanding an ordering field would refuse
 * a valid logout from any provider that does not send one.
 *
 * Folding both into one function behind a boolean would put that difference in a parameter, where
 * the next person to read it has to work out which branch their token takes. It is a different
 * claim about the world, so it is a different function.
 *
 * ## `sub`, and `sid` is deliberately ignored
 *
 * The client is registered with `backchannel_logout_session_required` off, so KeyStone sends a
 * subject and no session id. That is the right shape here: an administrator forcing a logout means
 * "end this person's session", which is true of every session they hold — including the one in a
 * browser they have forgotten about. Acting on `sid` would end one and leave the others, and the
 * administrator would see a successful logout.
 *
 * A token carrying `sid` is not refused; it is simply not narrowed by it. Refusing would make this
 * endpoint fail against a provider that sends more than we asked for.
 *
 * ## What the spec forbids, and why it is checked
 *
 * A logout token must **not** carry `nonce` — that claim belongs to an ID token, and accepting one
 * here is the documented confusion attack: an ID token replayed to this endpoint would otherwise log
 * the user out on someone else's say-so. The `events` key must be the exact URI, for the same reason
 * `verifyRoleChange` refuses a SET with no event it handles.
 */
export async function verifyBackchannelLogout(
  provider: Provider,
  token: string,
  o: { clientId: string; issuer: string; ledger: RoleChangeLedger },
  nowMs: () => number = Date.now,
): Promise<BackchannelLogout> {
  const { header, payload } = await verifyJws(provider, token, "logout token");

  if (header.typ !== "secevent+jwt") {
    throw new OidcError(`logout token has typ ${String(header.typ)}, expected secevent+jwt`, 401);
  }
  if (payload.iss !== o.issuer) {
    throw new OidcError(`logout token issuer ${String(payload.iss)} is not ${o.issuer}`, 401);
  }
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(o.clientId)) {
    throw new OidcError("logout token is addressed to another client", 401);
  }

  // Required by the specification and load-bearing: an ID token has a valid signature from the same
  // key and carries `nonce`. Without this check one could be replayed here to end a session.
  if ("nonce" in payload) {
    throw new OidcError("logout token carries nonce — an ID token cannot be used to log out", 401);
  }

  const now = Math.floor(nowMs() / 1000);
  if (typeof payload.iat !== "number") throw new OidcError("logout token has no iat", 401);
  if (payload.iat > now + 60) throw new OidcError("logout token is issued in the future", 401);
  if (typeof payload.exp !== "number") throw new OidcError("logout token has no exp", 401);
  if (payload.exp <= now) throw new OidcError("logout token has expired", 401);
  if (payload.exp - payload.iat > MAX_LIFETIME_SEC) {
    throw new OidcError(`logout token lifetime exceeds ${MAX_LIFETIME_SEC}s`, 401);
  }

  // After signature and freshness, so an unverified `jti` cannot be burned by an attacker.
  if (typeof payload.jti !== "string" || !payload.jti) {
    throw new OidcError("logout token has no jti", 401);
  }
  if (!o.ledger.claim(payload.jti)) {
    // 409 rather than 401: the token was genuine and has already had its effect. The IdP's delivery
    // log should show this as "already applied", not as a rejected credential.
    throw new OidcError("logout token has already been applied", 409);
  }

  if (typeof payload.sub !== "string" || !payload.sub) {
    throw new OidcError("logout token has no sub", 401);
  }

  const events = payload.events;
  if (typeof events !== "object" || events === null) {
    throw new OidcError("logout token has no events", 400);
  }
  const ev = (events as Record<string, unknown>)[BACKCHANNEL_LOGOUT_EVENT];
  if (typeof ev !== "object" || ev === null) {
    throw new OidcError("logout token carries no back-channel logout event", 400);
  }

  return { sub: payload.sub };
}

/**
 * The event URI a logout token must carry, fixed by the specification.
 *
 * Unlike `roleChangeEvent` this is **not** configuration: the role-change event is an extension one
 * provider defines, so naming a default there would silently discard events from any other. This URI
 * is in OpenID Connect Back-Channel Logout 1.0 §2.4 and is the same for every provider.
 */
export const BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";
