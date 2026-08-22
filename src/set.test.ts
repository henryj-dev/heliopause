// Security Event Token verification, against tokens this test signs.
//
// Two cases carry the file. **An ID token must not be accepted here** — it has a valid signature from
// the same key, and taking one as an authority assertion turns a login into a privilege grant. And a
// **captured SET must not be replayable**, because a token saying `roles: ["admin"]` replayed after a
// demotion restores the role — the exact window this whole mechanism exists to close.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createSign, generateKeyPairSync } from "node:crypto";
import { Provider } from "./oidc.ts";
import {
  BACKCHANNEL_LOGOUT_EVENT,
  RoleChangeLedger,
  verifyBackchannelLogout,
  verifyRoleChange,
} from "./set.ts";

/** The key this test's issuer uses. RFC 8417 leaves it to the issuer, so the test owns it. */
const ROLE_CHANGE_EVENT = "https://idp.example.invalid/event/role-change";

const ISSUER = "https://idp.example.invalid";
const CLIENT = "heliopause-manager";
const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");

let jtiSeq = 0;

/** Sign a SET the way KeyStone does. `over` mutates the payload, `head` the header. */
function set(over: Record<string, unknown> = {}, head: Record<string, unknown> = {}) {
  const header = { alg: "ES256", kid: "k1", typ: "secevent+jwt", ...head };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: ISSUER, sub: "user-1", aud: CLIENT, iat: now, exp: now + 300,
    jti: `jti-${++jtiSeq}`, txn: String(Date.now() + ++jtiSeq),
    events: { [ROLE_CHANGE_EVENT]: { roles: ["admin"], entitlements: ["plan.approve_own"] } },
    ...over,
  };
  const input = `${b64(header)}.${b64(payload)}`;
  const sig = createSign("sha256").update(input).sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${input}.${sig.toString("base64url")}`;
}

function provider() {
  const fake = (async (url: string | URL) => {
    const body = String(url).endsWith("/oidc/jwks")
      ? { keys: [{ ...publicKey.export({ format: "jwk" }), kid: "k1", use: "sig" }] }
      : {
          issuer: ISSUER, authorization_endpoint: `${ISSUER}/a`, token_endpoint: `${ISSUER}/t`,
          jwks_uri: `${ISSUER}/oidc/jwks`, code_challenge_methods_supported: ["S256"],
        };
    return new Response(JSON.stringify(body), { status: 200 });
  }) as unknown as typeof fetch;
  return new Provider(ISSUER, fake, 0);
}

const opts = () => ({ clientId: CLIENT, issuer: ISSUER, ledger: new RoleChangeLedger(),
                      eventKey: ROLE_CHANGE_EVENT });

describe("applying a role change", () => {
  it("accepts a SET this test signed — the known positive", async () => {
    const c = await verifyRoleChange(provider(), set(), opts());
    assert.equal(c.sub, "user-1");
    assert.deepEqual(c.roles, ["admin"]);
    assert.deepEqual(c.entitlements, ["plan.approve_own"]);
  });

  it("reads an empty roles array as revocation, not as absence", async () => {
    // The reason KeyStone always sends both arrays. A missing key would be indistinguishable from
    // "nothing changed", and this is the message that says everything was taken away.
    const c = await verifyRoleChange(
      provider(), set({ events: { [ROLE_CHANGE_EVENT]: { roles: [], entitlements: [] } } }), opts());
    assert.deepEqual(c.roles, []);
    assert.deepEqual(c.entitlements, []);
  });

  it("refuses an ID token, which is signed by the same key", async () => {
    // The case this module is most exposed to. Without the `typ` check a login token would be
    // accepted as an authority assertion.
    await assert.rejects(
      () => verifyRoleChange(provider(), set({}, { typ: "JWT" }), opts()), /expected secevent\+jwt/);
  });

  it("refuses a token with no typ at all", async () => {
    await assert.rejects(
      () => verifyRoleChange(provider(), set({}, { typ: undefined }), opts()), /expected secevent\+jwt/);
  });

  it("refuses a signature from another key", async () => {
    const other = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const header = b64({ alg: "ES256", kid: "k1", typ: "secevent+jwt" });
    const payload = b64({ iss: ISSUER, sub: "x", aud: CLIENT, iat: Math.floor(Date.now() / 1000), jti: "j" });
    const sig = createSign("sha256").update(`${header}.${payload}`)
      .sign({ key: other.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    await assert.rejects(
      () => verifyRoleChange(provider(), `${header}.${payload}.${sig}`, opts()), /does not verify/);
  });

  it("refuses another issuer and another audience", async () => {
    await assert.rejects(() => verifyRoleChange(provider(), set({ iss: "https://evil.invalid" }), opts()), /issuer/);
    await assert.rejects(() => verifyRoleChange(provider(), set({ aud: "someone-else" }), opts()), /another client/);
  });
});

describe("replay", () => {
  it("applies a token once and refuses it afterwards", async () => {
    // A captured SET saying roles:["admin"], replayed after a demotion, would restore the role.
    const p = provider();
    const o = opts();
    const t = set();
    assert.deepEqual((await verifyRoleChange(p, t, o)).roles, ["admin"]);
    await assert.rejects(() => verifyRoleChange(p, t, o), /already been applied/);
  });

  it("refuses a token older than the freshness window", async () => {
    // Belt to the jti braces: a `jti` set is bounded, so age is what actually stops an old capture.
    const now = Math.floor(Date.now() / 1000);
    await assert.rejects(() => verifyRoleChange(provider(), set({ iat: now - 3600, exp: now - 3300 }), opts()), /has expired/);
  });

  it("refuses a token from the future", async () => {
    // Accepting one would make the age check meaningless — a token dated tomorrow never expires.
    const soon = Math.floor(Date.now() / 1000) + 3600;
    await assert.rejects(() => verifyRoleChange(provider(), set({ iat: soon }), opts()), /in the future/);
  });

  it("refuses a token with no jti or no iat", async () => {
    await assert.rejects(() => verifyRoleChange(provider(), set({ jti: undefined }), opts()), /no jti/);
    await assert.rejects(() => verifyRoleChange(provider(), set({ iat: undefined }), opts()), /no iat/);
  });

  it("does not burn a jti on a token that failed verification", async () => {
    // Otherwise anyone who can reach this endpoint could pre-consume the identifier of a token they
    // guessed, and the genuine delivery would then be refused as a replay.
    const p = provider();
    const o = opts();
    await assert.rejects(() => verifyRoleChange(p, set({ iss: "https://evil.invalid", jti: "shared" }), o), /issuer/);
    assert.equal(o.ledger.size, 0);
    const good = await verifyRoleChange(p, set({ jti: "shared" }), o);
    assert.equal(good.sub, "user-1");
  });

  it("bounds what it remembers", () => {
    const s = new RoleChangeLedger();
    for (let i = 0; i < 5000; i++) s.claim(`j-${i}`);
    assert.ok(s.size <= 4096, `remembered ${s.size}`);
    assert.equal(s.claim("j-4999"), false, "recent ones are still remembered");
  });
});

describe("ordering — the reason txn exists", () => {
  it("discards a snapshot older than the one already applied", async () => {
    // The failure this closes: a grant and a revocation moments apart, delivered backwards, leave the
    // grant standing and nobody can tell. `iat` is in seconds and cannot separate them.
    const p = provider();
    const o = opts();
    const base = Date.now();
    const revoke = set({
      txn: String(base + 300),
      events: { [ROLE_CHANGE_EVENT]: { roles: [], entitlements: [] } },
    });
    const grant = set({ txn: String(base) });

    assert.deepEqual((await verifyRoleChange(p, revoke, o)).roles, [], "the revocation applies");
    await assert.rejects(() => verifyRoleChange(p, grant, o), /older than the last one applied/);
  });

  it("refuses an equal txn — two snapshots cannot share an instant", async () => {
    const p = provider();
    const o = opts();
    const t = String(Date.now());
    await verifyRoleChange(p, set({ txn: t }), o);
    await assert.rejects(() => verifyRoleChange(p, set({ txn: t }), o), /older than the last one applied/);
  });

  it("orders per subject, not globally", async () => {
    // One user's ordering says nothing about another's. A global watermark would discard a genuine
    // change for B because A had a later one.
    const p = provider();
    const o = opts();
    const base = Date.now();
    await verifyRoleChange(p, set({ sub: "user-a", txn: String(base + 500) }), o);
    const b = await verifyRoleChange(p, set({ sub: "user-b", txn: String(base) }), o);
    assert.equal(b.sub, "user-b");
  });

  it("does not advance the watermark on a token it refuses", async () => {
    // Otherwise a refused token moves the mark and the next genuine snapshot is discarded as stale.
    const p = provider();
    const o = opts();
    const t = String(Date.now() + 1000);
    await assert.rejects(() => verifyRoleChange(p, set({ txn: t, aud: "other" }), o), /another client/);
    const ok = await verifyRoleChange(p, set({ txn: t }), o);
    assert.equal(ok.sub, "user-1");
  });

  it("refuses a txn that is absent or not a number", async () => {
    await assert.rejects(() => verifyRoleChange(provider(), set({ txn: undefined }), opts()), /no txn/);
    await assert.rejects(() => verifyRoleChange(provider(), set({ txn: "later" }), opts()), /no txn/);
  });
});

describe("expiry", () => {
  it("refuses an expired token", async () => {
    const now = Math.floor(Date.now() / 1000);
    await assert.rejects(
      () => verifyRoleChange(provider(), set({ iat: now - 600, exp: now - 300 }), opts()), /has expired/);
  });

  it("refuses a token with no exp", async () => {
    await assert.rejects(() => verifyRoleChange(provider(), set({ exp: undefined }), opts()), /no exp/);
  });

  it("refuses a lifetime the issuer set too generously", async () => {
    // `exp` is the issuer's to set and this is the bound on what it may set. A token good for a year
    // is a replay window wearing a configuration value, and the RP pays for it.
    const now = Math.floor(Date.now() / 1000);
    await assert.rejects(
      () => verifyRoleChange(provider(), set({ iat: now, exp: now + 86400 }), opts()), /lifetime exceeds/);
  });
});

describe("the event payload", () => {
  it("refuses a SET carrying no role-change event", async () => {
    await assert.rejects(
      () => verifyRoleChange(provider(), set({ events: { "https://other/event": {} } }), opts()),
      /no role-change event/);
  });

  it("refuses events that are not arrays", async () => {
    await assert.rejects(
      () => verifyRoleChange(provider(), set({ events: { [ROLE_CHANGE_EVENT]: { roles: "admin", entitlements: [] } } }), opts()),
      /roles is not an array/);
  });

  it("drops non-string members rather than trusting them", async () => {
    const c = await verifyRoleChange(
      provider(),
      set({ events: { [ROLE_CHANGE_EVENT]: { roles: ["admin", 7, null], entitlements: [] } } }),
      opts());
    assert.deepEqual(c.roles, ["admin"]);
  });
});

describe("back-channel logout", () => {
  // ## What this endpoint buys, and what it cost to not have
  //
  // KeyStone has discovered logout targets by subject since 2026-08-06, so an administrator's
  // force-logout reaches any client that registered an endpoint. This console had none, and the
  // client's Back-channel Logout URI was left blank on purpose — **registering a URI with no route
  // is worse than registering nothing**, because the administrator sees a successful logout while
  // every session keeps working.
  //
  // Until this landed, the only way to end someone's session from outside was restarting the pod.

  /** A logout token: no `txn` (nothing to order), and the spec's event URI. */
  const logout = (over: Record<string, unknown> = {}, head: Record<string, unknown> = {}) =>
    set({ txn: undefined, events: { [BACKCHANNEL_LOGOUT_EVENT]: {} }, ...over }, head);

  const lopts = () => ({ clientId: CLIENT, issuer: ISSUER, ledger: new RoleChangeLedger() });

  it("accepts a logout token this test signed — the known positive", async () => {
    const r = await verifyBackchannelLogout(provider(), logout(), lopts());
    assert.equal(r.sub, "user-1");
  });

  it("refuses a token carrying nonce — an ID token cannot log anyone out", async () => {
    // The documented confusion attack, and the reason the spec forbids the claim. An ID token is
    // signed by the same key; without this check a captured one could be replayed here to end a
    // session on nobody's authority.
    await assert.rejects(
      () => verifyBackchannelLogout(provider(), logout({ nonce: "n-1" }), lopts()),
      /nonce/,
    );
  });

  it("refuses a token whose events name something else", async () => {
    // A SET that reached the right endpoint and said nothing this acts on. Refusing says so; a 204
    // would tell the IdP's delivery log that a logout happened.
    await assert.rejects(
      () => verifyBackchannelLogout(provider(), logout({ events: { "https://other/event": {} } }), lopts()),
      /no back-channel logout event/,
    );
  });

  it("does not require txn — a logout is not a snapshot", async () => {
    // The difference from `verifyRoleChange`, asserted rather than left to the reader. A role change
    // must be ordered or a stale one could undo a revocation; a logout cannot be undone by a later
    // token, and demanding the field would refuse valid logouts from providers that omit it.
    const r = await verifyBackchannelLogout(provider(), logout(), lopts());
    assert.equal(r.sub, "user-1");
  });

  it("is single-use, and says so with 409", async () => {
    // Shares the ledger with role changes: one `jti` space, because a token is spent whatever it
    // says. 409 rather than 401 — the token was genuine and has already had its effect, which is
    // what the delivery log should show.
    const o = lopts();
    const t = logout();
    await verifyBackchannelLogout(provider(), t, o);
    await assert.rejects(
      () => verifyBackchannelLogout(provider(), t, o),
      (e: { status?: number }) => e.status === 409,
    );
  });

  it("refuses a token addressed to another client", async () => {
    await assert.rejects(
      () => verifyBackchannelLogout(provider(), logout({ aud: "someone-else" }), lopts()),
      /another client/,
    );
  });

  it("refuses one that is not a SET at all", async () => {
    // `typ` is checked before any claim is trusted, for the same reason as on the role-change path.
    await assert.rejects(
      () => verifyBackchannelLogout(provider(), logout({}, { typ: "JWT" }), lopts()),
      /expected secevent\+jwt/,
    );
  });

  it("refuses an expired token", async () => {
    const now = Math.floor(Date.now() / 1000);
    await assert.rejects(
      () => verifyBackchannelLogout(provider(), logout({ iat: now - 400, exp: now - 100 }), lopts()),
      /expired/,
    );
  });

  it("accepts a token that also carries sid, without narrowing to it", async () => {
    // `backchannel_logout_session_required` is off, so KeyStone sends no `sid`. A provider that
    // sends one anyway must not be refused — and the result is still subject-wide, because ending
    // one session and leaving the others is exactly the outcome an administrator would misread.
    const r = await verifyBackchannelLogout(provider(), logout({ sid: "sess-9" }), lopts());
    assert.equal(r.sub, "user-1");
  });
});
