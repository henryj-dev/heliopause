// OIDC Authorization Code + PKCE, with no dependencies.
//
// ## Why this file exists at all
//
// `manager-ui.ts` argues that the console sits behind the same client certificate as the API because
// "a session login is a new authentication system, and this page shows exactly what `GET /site`
// shows". That argument was right and is not withdrawn. What changed is the measured cost: browser
// client certificates on macOS turned out to be genuinely hard to make work — an identity imported
// correctly, with the right EKU, from the CA the server advertises, still was not offered to the
// server. The console became unreachable to a person while `curl` with the same files kept working.
//
// So this adds a second way to prove who you are. It does **not** add a second way to decide what
// you may do: identity arrives here, authorisation stays where it was.
//
// ## Why no library
//
// The package has zero runtime dependencies and that is a stated property, not an accident — this
// process holds an operator certificate for three VPCs and runs inside the cluster its own firewall
// protects. Every dependency here is a package that can change what that process trusts. Authorization
// Code + PKCE is a small protocol; JWS verification over a JWKS is `node:crypto`. What follows is
// long because it is commented, not because it is large.
//
// ## What is deliberately not implemented
//
// - **Refresh tokens.** The session outlives the ID token by design (see `session.ts`); refreshing
//   would mean holding a credential that can mint new tokens for as long as the session lives.
// - **Dynamic client registration.** The client is registered once, by hand, and its id is config.
// - **`alg: none`, and every symmetric alg.** Listed in `ALLOWED_ALGS` and enforced before any
//   signature check runs, because "verify with the algorithm the token asks for" is how a token
//   signed by nobody gets accepted.

import { constants, createHash, createPublicKey, createVerify, randomBytes, timingSafeEqual } from "node:crypto";
import { BodyTooLargeError, declaredTooLarge, readBoundedStream, readBoundedText } from "./bounded-body.ts";

/** Signature algorithms this accepts. Asymmetric only — see the header. */
const ALLOWED_ALGS = new Set(["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]);

/** Clock skew tolerated on `exp` and `iat`, in seconds. */
const LEEWAY_SEC = 60;

/** Discovery documents and public key sets are configuration, not bulk data. */
export const MAX_OIDC_DOCUMENT_BYTES = 1024 * 1024;

/** The subset of the discovery document this uses. */
export interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
  code_challenge_methods_supported?: string[];
}

/** A verified end-user identity. Nothing here decides what the user may do. */
export interface Identity {
  /** The IdP's stable subject. Unique within the issuer, and never reused. */
  sub: string;
  /** Preferred human-readable name, when the IdP sends one. */
  username: string | null;
  email: string | null;
  /**
   * Whether the issuer says it has verified that address.
   *
   * 🔴 **Carried because an alias keyed on email decides who may write.** `oidc-authz.ts` resolves
   * `email → certificate name`, that alias raises `canWrite`, and the name it resolves to is the
   * identity the two-person approval rule compares. An IdP that lets a user set their own profile
   * address — and many do, for anything but the verified one — would let one member of a writer
   * group claim a colleague's alias and satisfy both halves of that rule alone.
   *
   * `email_verified` is the claim OIDC defines for exactly this question. **Absent counts as
   * false**: an issuer that will not say has not said yes, and this is the wrong place to guess.
   */
  emailVerified: boolean;
  /** Group and role claims, flattened. Empty when the IdP sends none — never null. */
  groups: string[];
  /** When the ID token expires. The session may be shorter; it must not be longer. */
  expiresAt: Date;
}

export class OidcError extends Error {
  // Declared and assigned rather than a constructor parameter property. Node runs this file by
  // stripping types, and a parameter property is not a type — it emits an assignment, so the
  // runtime refuses it with ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX while `tsc --noEmit` is perfectly
  // happy. The build-step-free property of this repository is what makes that a hard constraint.
  readonly status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.name = "OidcError";
    this.status = status;
  }
}

/**
 * Parse a provider document without letting `Response.json()` buffer an attacker-sized body.
 *
 * `Content-Length` is only an early refusal: it can be absent or dishonest, and transparent HTTP
 * decompression can make the decoded body larger than the wire value. The streaming byte count is
 * therefore the enforcing check.
 */
async function boundedProviderJson(res: Response, url: string): Promise<unknown> {
  if (declaredTooLarge(res.headers, MAX_OIDC_DOCUMENT_BYTES)) {
    throw new OidcError(`${url} response exceeds ${MAX_OIDC_DOCUMENT_BYTES} bytes`, 502);
  }

  // A `Response` with no body is not an empty document — it is a provider that answered nothing
  // where a discovery document or a key set was required. Kept as its own sentence rather than
  // folded into the reader below, because "the IdP sent nothing" and "the IdP sent too much" send
  // an operator to different places.
  if (!res.body) throw new OidcError(`${url} returned an empty JSON response`, 502);

  // The byte counting itself lives in `bounded-body.ts`. This function keeps the two decisions that
  // are OIDC's own — what an absent body means, and that every failure here is a 502 rather than
  // the caller's fault.
  let encoded: Buffer;
  try {
    encoded = await readBoundedStream(res.body, MAX_OIDC_DOCUMENT_BYTES, url);
  } catch (e) {
    throw new OidcError((e as Error).message, 502);
  }

  try {
    return JSON.parse(encoded.toString("utf8")) as unknown;
  } catch {
    throw new OidcError(`${url} returned invalid JSON`, 502);
  }
}

// ── PKCE and one-time values ──────────────────────────────────────────────────

/**
 * A PKCE verifier and its S256 challenge.
 *
 * S256 only. `plain` is in the RFC and is worthless: it puts the same value in the redirect that the
 * token request will present, so an attacker who can read one has the other. The discovery document
 * for this deployment advertises S256 alone, and this refuses to fall back even if that changes.
 */
export function pkce(): { verifier: string; challenge: string } {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

/** A URL-safe random value for `state` and `nonce`. 256 bits, from the CSPRNG. */
export function nonce(): string {
  return b64url(randomBytes(32));
}

const b64url = (b: Buffer): string => b.toString("base64url");

/**
 * Constant-time string comparison for values an attacker can influence.
 *
 * `state` and `nonce` are compared with this rather than `===`. The timing signal on a short string
 * is small, but these are the two values whose whole job is to be unguessable.
 */
export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}

// ── Discovery and keys ────────────────────────────────────────────────────────

/**
 * Fetches and caches the discovery document and JWKS.
 *
 * Cached because the alternative is a network round trip to the IdP on every login, and refreshed on
 * an unknown `kid` because that is what a key rotation looks like from here. The refresh is rate
 * limited: an attacker who can send tokens with arbitrary `kid` values would otherwise have a way to
 * make this process hammer the IdP.
 */
export class Provider {
  private discovery: Discovery | null = null;
  private keys = new Map<string, ReturnType<typeof createPublicKey>>();
  private lastJwksFetch = 0;

  private readonly issuer: string;
  private readonly fetchImpl: typeof fetch;
  /** Minimum gap between JWKS fetches, in ms. */
  private readonly jwksMinIntervalMs: number;
  private readonly now: () => number;

  constructor(issuer: string, fetchImpl: typeof fetch = fetch, jwksMinIntervalMs = 60_000, now: () => number = Date.now) {
    this.issuer = issuer;
    this.fetchImpl = fetchImpl;
    this.jwksMinIntervalMs = jwksMinIntervalMs;
    this.now = now;
  }

  async load(): Promise<Discovery> {
    if (this.discovery) return this.discovery;
    const url = `${this.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
    const d = (await this.getJson(url)) as Discovery;
    // The issuer in the document must be the one we asked about. Without this an open redirect on
    // the discovery URL, or a misconfigured proxy, silently repoints every later check.
    if (d.issuer !== this.issuer) {
      throw new OidcError(`discovery issuer ${d.issuer} does not match configured ${this.issuer}`, 502);
    }
    for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri"] as const) {
      if (typeof d[k] !== "string" || !d[k]) throw new OidcError(`discovery document has no ${k}`, 502);
    }
    if (d.code_challenge_methods_supported && !d.code_challenge_methods_supported.includes("S256")) {
      throw new OidcError("the IdP does not advertise PKCE S256, which this requires", 502);
    }
    this.discovery = d;
    return d;
  }

  /** The verification key for a `kid`, refreshing the key set once if it is unknown. */
  async keyFor(kid: string): Promise<ReturnType<typeof createPublicKey>> {
    const hit = this.keys.get(kid);
    if (hit) return hit;
    const since = this.now() - this.lastJwksFetch;
    if (since < this.jwksMinIntervalMs) {
      throw new OidcError(`no key ${kid} and the key set was refreshed ${Math.round(since / 1000)}s ago`, 401);
    }
    await this.refreshKeys();
    const k = this.keys.get(kid);
    if (!k) throw new OidcError(`the IdP's key set has no key ${kid}`, 401);
    return k;
  }

  private async refreshKeys(): Promise<void> {
    const d = await this.load();
    this.lastJwksFetch = this.now();
    const jwks = (await this.getJson(d.jwks_uri)) as { keys?: unknown[] };
    if (!Array.isArray(jwks.keys)) throw new OidcError("the IdP's key set has no `keys` array", 502);
    const next = new Map<string, ReturnType<typeof createPublicKey>>();
    for (const jwk of jwks.keys) {
      if (typeof jwk !== "object" || jwk === null) continue;
      const j = jwk as Record<string, unknown>;
      // `use: "enc"` keys are for encryption and must not verify signatures.
      if (j.use && j.use !== "sig") continue;
      if (typeof j.kid !== "string") continue;
      try {
        next.set(j.kid, createPublicKey({ key: j as never, format: "jwk" }));
      } catch {
        // A key this Node cannot import is skipped rather than fatal: one unusable entry in a key
        // set must not stop the usable ones from being read.
      }
    }
    if (next.size === 0) throw new OidcError("the IdP's key set has no usable signing keys", 502);
    this.keys = next;
  }

  private async getJson(url: string): Promise<unknown> {
    // https only. The whole chain of trust in this file rests on the answer coming from the IdP, and
    // a plaintext fetch is a document an on-path party can write.
    if (!url.startsWith("https://")) throw new OidcError(`refusing to fetch ${url} over plaintext`, 502);
    const res = await this.fetchImpl(url, { redirect: "error", signal: AbortSignal.timeout(10_000) });
    if (!res.ok) throw new OidcError(`${url} answered ${res.status}`, 502);
    return await boundedProviderJson(res, url);
  }
}

// ── The authorization request ─────────────────────────────────────────────────

/**
 * Build the URL to send the browser to. `state` and `nonce` must be stored server-side.
 *
 * ## `prompt=login`, and why it is not a preference
 *
 * `/auth/logout` destroys this server's session and clears its cookie. It does not touch the IdP's
 * session, and without `prompt` the next authorization request is answered from that session with no
 * credential asked for. So "sign out" followed by "sign in" put the same operator back in, silently
 * — measured 2026-08-24, and on a shared workstation it means the sign-out button ends nothing an
 * attacker at that keyboard cares about.
 *
 * The RP-initiated logout in `endSessionUrl` is the other half and the better one: it ends the IdP
 * session too. This is here as well because that half depends on a `post_logout_redirect_uri` being
 * registered at the IdP, and an unregistered one fails by doing nothing. A console that re-prompts
 * is a cost paid on every login; a console that silently re-authenticates after a logout is a
 * different kind of thing entirely.
 */
export function authorizeUrl(
  d: Discovery,
  o: { clientId: string; redirectUri: string; state: string; nonce: string; challenge: string; scopes: string[] },
): string {
  const u = new URL(d.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", o.clientId);
  u.searchParams.set("redirect_uri", o.redirectUri);
  u.searchParams.set("scope", o.scopes.join(" "));
  u.searchParams.set("state", o.state);
  u.searchParams.set("nonce", o.nonce);
  u.searchParams.set("code_challenge", o.challenge);
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("prompt", "login");
  return u.toString();
}

/**
 * Where to send the browser so the **IdP's** session ends too, or `null`.
 *
 * `null` when the provider advertises no `end_session_endpoint`. That is a normal answer, not an
 * error: RP-initiated logout is optional in OpenID Connect, and a deployment whose IdP does not
 * offer it still gets a destroyed local session and `prompt=login` on the way back in.
 *
 * ## No `id_token_hint`
 *
 * The spec calls it RECOMMENDED, and sending it would mean keeping the raw ID token in the session
 * for the lifetime of that session. This process already holds the artifact signing key; adding a
 * bearer artifact to its memory to save the user one confirmation click is not a trade worth making
 * quietly. `client_id` is what the spec requires instead when a `post_logout_redirect_uri` is sent
 * without the hint, and the IdP may ask the user to confirm — which for a sign-out button is fine.
 *
 * ⚠️ **`post_logout_redirect_uri` has to be registered at the IdP.** An unregistered one is refused
 * by the IdP, and what the operator sees is a logout that lands on an error page rather than back on
 * the console — loud, unlike the back-channel URI whose absence was silent. The manager prints the
 * exact value at startup for that reason.
 */
export function endSessionUrl(
  d: Discovery,
  o: { clientId: string; postLogoutRedirectUri: string },
): string | null {
  if (!d.end_session_endpoint) return null;
  let u: URL;
  try {
    u = new URL(d.end_session_endpoint);
  } catch {
    // A provider document that parses but carries a nonsense endpoint. Treated as "not offered"
    // rather than thrown: this is called while ending a session, and the session is already gone.
    return null;
  }
  u.searchParams.set("client_id", o.clientId);
  u.searchParams.set("post_logout_redirect_uri", o.postLogoutRedirectUri);
  return u.toString();
}

// ── The token exchange ────────────────────────────────────────────────────────

/**
 * Exchange the code for an ID token and verify it.
 *
 * The nonce is checked against the one this server generated for this login. Without that check a
 * token obtained elsewhere — legitimately, for another session — can be replayed into this one.
 */
export async function exchange(
  p: Provider,
  o: {
    code: string;
    clientId: string;
    clientSecret?: string;
    redirectUri: string;
    verifier: string;
    expectedNonce: string;
  },
  fetchImpl: typeof fetch = fetch,
): Promise<Identity> {
  const d = await p.load();
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: o.code,
    redirect_uri: o.redirectUri,
    client_id: o.clientId,
    code_verifier: o.verifier,
  });
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  // Confidential client when a secret is configured; public client (PKCE only) when it is not.
  // Sent as Basic auth rather than in the body: the body ends up in more logs.
  if (o.clientSecret) {
    headers.authorization =
      "Basic " + Buffer.from(`${encodeURIComponent(o.clientId)}:${encodeURIComponent(o.clientSecret)}`).toString("base64");
  }
  const res = await fetchImpl(d.token_endpoint, {
    method: "POST",
    headers,
    body: body.toString(),
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  // ## The third read from this IdP, which was not bounded like the other two
  //
  // `boundedProviderJson` exists forty lines up and says why: `Response.json()` buffers whatever
  // arrives, `Content-Length` is a claim, and transparent decompression can make the decoded body
  // larger than the wire value. It guards the discovery document and the key set. The token
  // exchange — same IdP, same process, same `fetch` — went through a bare `res.json()`.
  //
  // `AbortSignal.timeout` above bounds the duration and not the size, and this process holds the
  // artifact signing key in a single pod. The reasoning was already written down; only this call
  // was missing from it.
  //
  // Failures here stay 502 like every other token-endpoint failure: the caller cannot act on the
  // difference between "the IdP sent too much" and "the IdP sent nonsense", and both are the IdP's.
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(await readBoundedText(res, MAX_OIDC_DOCUMENT_BYTES, d.token_endpoint)) as Record<string, unknown>;
  } catch (e) {
    // A body that is too large is a different sentence from one that is not JSON, and `res.ok`
    // below needs a value either way — an unparseable error response should still report its status.
    if (e instanceof BodyTooLargeError) throw new OidcError(e.message, 502);
    json = {};
  }
  if (!res.ok) {
    // The IdP's own error, surfaced. `invalid_grant` on a replayed code reads very differently from
    // a network failure, and collapsing them costs an operator the diagnosis.
    throw new OidcError(`token endpoint answered ${res.status}: ${String(json.error ?? "")}`, 502);
  }
  if (typeof json.id_token !== "string") throw new OidcError("token response carries no id_token", 502);
  return await verifyIdToken(p, json.id_token, o.clientId, o.expectedNonce);
}

/**
 * Verify an ID token's signature and claims.
 *
 * Order matters. The algorithm is checked before anything is verified with it, and the signature
 * before any claim is read — a claim from an unverified token is attacker-controlled input, and
 * reading `iss` to decide which key to use is exactly the mistake that makes it so.
 */
export async function verifyIdToken(
  p: Provider,
  token: string,
  clientId: string,
  expectedNonce: string,
  nowMs: () => number = Date.now,
): Promise<Identity> {
  const { header, payload: c } = await verifyJws(p, token, "id_token");
  void header;
  const d = await p.load();
  if (c.iss !== d.issuer) throw new OidcError(`id_token issuer ${String(c.iss)} is not ${d.issuer}`, 401);

  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!aud.includes(clientId)) throw new OidcError("id_token is not addressed to this client", 401);
  // `azp` matters when the token has several audiences: it names which client it was actually for.
  if (aud.length > 1 && c.azp !== clientId) throw new OidcError("id_token azp is another client", 401);

  const now = Math.floor(nowMs() / 1000);
  if (typeof c.exp !== "number" || c.exp + LEEWAY_SEC < now) throw new OidcError("id_token has expired", 401);
  if (typeof c.iat === "number" && c.iat - LEEWAY_SEC > now) throw new OidcError("id_token is issued in the future", 401);

  if (typeof c.nonce !== "string" || !safeEqual(c.nonce, expectedNonce)) {
    throw new OidcError("id_token nonce does not match this login", 401);
  }
  if (typeof c.sub !== "string" || !c.sub) throw new OidcError("id_token has no sub", 401);

  return {
    sub: c.sub,
    username: typeof c.preferred_username === "string" ? c.preferred_username : null,
    email: typeof c.email === "string" ? c.email : null,
    // Strictly `true`. Some issuers send the string "true"; accepting it here would mean trusting a
    // type coercion to decide who can approve a firewall change, so a non-boolean is not verified.
    emailVerified: c.email_verified === true,
    groups: claimList(c.groups).concat(claimList(c.roles)),
    expiresAt: new Date(c.exp * 1000),
  };
}

/**
 * Verify a JWS from this issuer and return its parsed parts.
 *
 * Shared by the ID token and the Security Event Token, because "check the algorithm, fetch the key,
 * verify the signature" is the part that must not exist twice. Two copies drift, and the copy that
 * drifts is the one nobody is reading when it matters.
 *
 * **Signature only.** Every claim — issuer, audience, expiry, type — is the caller's to check,
 * because the two token kinds require different ones. What this guarantees is narrower and is the
 * thing both need: the bytes came from a key this issuer publishes.
 *
 * `what` names the token kind in error messages. An operator reading "signature does not verify"
 * needs to know which of two tokens it was.
 */
export async function verifyJws(
  p: Provider,
  token: string,
  what: string,
): Promise<{ header: Record<string, unknown>; payload: Record<string, unknown> }> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new OidcError(`${what} is not a three-part JWS`, 401);
  const [h, pl, sig] = parts as [string, string, string];

  const header = parseJson(h, "header") as Record<string, unknown>;
  if (typeof header.alg !== "string" || !ALLOWED_ALGS.has(header.alg)) {
    throw new OidcError(`${what} algorithm ${String(header.alg)} is not accepted`, 401);
  }
  if (typeof header.kid !== "string") throw new OidcError(`${what} header has no kid`, 401);

  const key = await p.keyFor(header.kid);
  if (!verifySignature(header.alg, `${h}.${pl}`, sig, key)) {
    throw new OidcError(`${what} signature does not verify`, 401);
  }
  // Only now is the payload trustworthy.
  return { header, payload: parseJson(pl, "payload") as Record<string, unknown> };
}

/**
 * Group-shaped claims, as a list.
 *
 * IdPs disagree about the shape: an array, a space-separated string, or a single string. Accepting
 * all three here keeps that disagreement out of the authorisation code, which should be reading a
 * list and nothing else.
 */
function claimList(v: unknown): string[] {
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string");
  if (typeof v === "string") return v.split(/\s+/).filter(Boolean);
  return [];
}

function parseJson(segment: string, what: string): unknown {
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  } catch {
    throw new OidcError(`id_token ${what} is not valid JSON`, 401);
  }
}

function verifySignature(alg: string, signingInput: string, sig: string, key: ReturnType<typeof createPublicKey>): boolean {
  const digest = `sha${alg.slice(2)}`;
  const signature = Buffer.from(sig, "base64url");
  try {
    if (alg.startsWith("ES")) {
      // JWS uses the raw r||s form; Node's verifier wants DER unless told otherwise.
      return createVerify(digest).update(signingInput).verify({ key, dsaEncoding: "ieee-p1363" }, signature);
    }
    if (alg.startsWith("PS")) {
      // PSS, with the salt length equal to the digest — what RFC 7518 specifies for PS*. Naming the
      // constant matters: `padding: 1` is PKCS#1 v1.5, and a PSS token verified with v1.5 padding is
      // not a weaker check, it is a different one.
      return createVerify(digest).update(signingInput).verify(
        { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
        signature,
      );
    }
    return createVerify(digest).update(signingInput).verify(key, signature);
  } catch {
    // A malformed signature is a failed verification, not a crash. Returning false keeps the one
    // decision in one place.
    return false;
  }
}
