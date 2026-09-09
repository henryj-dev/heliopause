// Sessions and the CSRF defence.
//
// This is the file where a mistake is a firewall change made by somebody else's web page, so each
// layer is tested on its own: the suite must fail if any one of `SameSite`, the `Origin` check or the
// CSRF token stops working, not only if all three do.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  checkCsrf, clearCookieHeader, cookieHeader, COOKIE, CSRF_HEADER,
  readCookie, SessionStore, type Principal,
} from "./session.ts";

const ORIGIN = "https://console.example.com";
const who: Principal = {
  name: "ops-alice", sub: "idp-1", groups: ["fleet-operators"], via: "oidc", canWrite: false,
};

describe("the session store", () => {
  it("issues a session that can be looked up — the known positive", () => {
    const s = new SessionStore();
    const a = s.create(who);
    assert.equal(s.get(a.id)?.principal.name, "ops-alice");
    assert.equal(s.get(a.id)?.principal.via, "oidc");
  });

  it("gives the session id and the CSRF token independent values", () => {
    // A token derived from the id would be recoverable by anything that ever saw the id.
    const s = new SessionStore();
    const a = s.create(who);
    assert.notEqual(a.id, a.csrf);
    assert.ok(a.id.length >= 40 && a.csrf.length >= 40, "both must be 256-bit values");
  });

  it("does not repeat ids across many sessions", () => {
    const s = new SessionStore({ ttlSec: 3600, max: 1000 });
    const ids = new Set(Array.from({ length: 300 }, () => s.create(who).id));
    assert.equal(ids.size, 300);
  });

  it("stops returning a session once it has expired", () => {
    let t = new Date("2026-08-05T00:00:00Z");
    const s = new SessionStore({ ttlSec: 60, max: 10 }, () => t);
    const a = s.create(who);
    assert.ok(s.get(a.id));
    t = new Date("2026-08-05T00:01:01Z");
    assert.equal(s.get(a.id), null, "an expired session must not authenticate anything");
  });

  it("forgets an expired session rather than holding it", () => {
    let t = new Date("2026-08-05T00:00:00Z");
    const s = new SessionStore({ ttlSec: 60, max: 10 }, () => t);
    s.create(who);
    t = new Date("2026-08-05T01:00:00Z");
    s.create(who);
    assert.equal(s.size, 1, "the swept session must be gone, not merely unreturnable");
  });

  it("evicts the oldest rather than refusing a new login at the cap", () => {
    // Refusing would let anyone lock the operator out by filling the table, and the symptom would
    // look like a broken IdP.
    let n = 0;
    const s = new SessionStore({ ttlSec: 3600, max: 3 }, () => new Date(1_800_000_000_000 + n++ * 1000));
    const first = s.create(who);
    s.create(who);
    s.create(who);
    const fourth = s.create(who);
    assert.equal(s.get(first.id), null, "the oldest session should have been evicted");
    assert.ok(s.get(fourth.id), "the newest login must succeed");
    assert.equal(s.size, 3);
  });

  it("destroys a session on request, and does not mind being asked twice", () => {
    const s = new SessionStore();
    const a = s.create(who);
    s.destroy(a.id);
    assert.equal(s.get(a.id), null);
    s.destroy(a.id);
    s.destroy(null);
  });

  it("treats a missing cookie as no session", () => {
    assert.equal(new SessionStore().get(null), null);
  });
});

describe("the cookie", () => {
  it("carries every attribute the browser needs to protect it", () => {
    const h = cookieHeader(new SessionStore().create(who));
    assert.match(h, /^__Host-heliopause-session=/, "the __Host- prefix forces Secure, no Domain, Path=/");
    assert.match(h, /; Secure/);
    assert.match(h, /; HttpOnly/, "page script must not be able to read the session");
    assert.match(h, /; SameSite=Strict/, "Lax would still travel on a top-level GET navigation");
    assert.match(h, /; Path=\//);
    assert.doesNotMatch(h, /; Domain=/, "a Domain would expose the session to sibling hosts");
  });

  it("clears with the same attributes, or the browser keeps the original", () => {
    const h = clearCookieHeader();
    assert.match(h, /Max-Age=0/);
    assert.match(h, /; Secure/);
    assert.match(h, /; SameSite=Strict/);
    assert.match(h, /; Path=\//);
  });

  it("reads its own cookie back out of a header", () => {
    const s = new SessionStore().create(who);
    const sent = cookieHeader(s).split(";")[0]!;
    assert.equal(readCookie(`other=1; ${sent}; another=2`, COOKIE), s.id);
  });

  it("takes the first of a repeated name, not the last", () => {
    // A subdomain can set a cookie of the same name. Taking the last would let it replace the
    // session for the host; the browser's own precedence gives the first.
    assert.equal(readCookie(`${COOKIE}=host-one; ${COOKIE}=subdomain-two`, COOKIE), "host-one");
  });

  it("returns null for absent, empty or malformed headers", () => {
    assert.equal(readCookie(undefined, COOKIE), null);
    assert.equal(readCookie("", COOKIE), null);
    assert.equal(readCookie("novalue", COOKIE), null);
    assert.equal(readCookie(`${COOKIE}=`, COOKIE), null);
    assert.equal(readCookie("somethingelse=x", COOKIE), null);
  });
});

describe("CSRF on a state-changing request", () => {
  const store = new SessionStore();
  const s = store.create(who);
  const good = { origin: ORIGIN, csrf: s.csrf };

  it("accepts the console's own request — the known positive", () => {
    assert.equal(checkCsrf(s, good, ORIGIN), null);
  });

  it("refuses a request from another origin even with a valid token", () => {
    // The token is only secret until it is not. The Origin check is what holds if it leaks.
    assert.equal(checkCsrf(s, { origin: "https://evil.example.invalid", csrf: s.csrf }, ORIGIN), "origin");
  });

  it("refuses a same-origin request with no token", () => {
    // And this is what holds if SameSite is ever weakened: a cross-origin form POST cannot set a
    // custom header at all, and a fetch that tries triggers a preflight this server answers for
    // nobody.
    assert.equal(checkCsrf(s, { origin: ORIGIN }, ORIGIN), "token");
  });

  it("refuses a token belonging to a different session", () => {
    const other = store.create(who);
    assert.equal(checkCsrf(s, { origin: ORIGIN, csrf: other.csrf }, ORIGIN), "token");
  });

  it("refuses when neither Origin nor Referer is present", () => {
    // Absent is not permission. A request that cannot say where it came from is refused.
    assert.equal(checkCsrf(s, { csrf: s.csrf }, ORIGIN), "origin");
  });

  it("falls back to Referer when Origin is absent, and compares the origin only", () => {
    assert.equal(checkCsrf(s, { referer: `${ORIGIN}/plans?x=1`, csrf: s.csrf }, ORIGIN), null);
    assert.equal(checkCsrf(s, { referer: "https://evil.example.invalid/x", csrf: s.csrf }, ORIGIN), "origin");
  });

  it("does not accept a Referer that is not a URL", () => {
    assert.equal(checkCsrf(s, { referer: "not a url", csrf: s.csrf }, ORIGIN), "origin");
  });

  it("does not accept an origin that merely starts with the expected one", () => {
    // `https://console.example.com.evil.test` starts with the right string and is a different
    // site. Exact comparison, never a prefix.
    assert.equal(checkCsrf(s, { origin: `${ORIGIN}.evil.test`, csrf: s.csrf }, ORIGIN), "origin");
  });

  it("does not accept a truncated token", () => {
    assert.equal(checkCsrf(s, { origin: ORIGIN, csrf: s.csrf.slice(0, -1) }, ORIGIN), "token");
  });

  it("names the header it expects", () => {
    // The value is part of the contract with the console page; a rename that misses one side would
    // refuse every write with a message about a missing token.
    assert.equal(CSRF_HEADER, "x-heliopause-csrf");
  });
});

// ── Acting on one identity's sessions ─────────────────────────────────────────
//
// 🔴 **`applyToSubject` had no test at all**, and the line that makes it "to subject" rather than
// "to everyone" is one `continue`. Deleting it left all 1,835 tests green, because every session in
// this file was issued for the same `sub`.
//
// `manager-server.ts` calls it twice against a **Security Event Token from the IdP**: once to apply
// a role change (`:3304`) and once for a back-channel logout (`:3376`, `() => null`). Without the
// filter, one person signing out anywhere ends every operator's session on the fleet console — and
// a role change applies somebody else's new role to everyone.
describe("applyToSubject", () => {
  const alice: Principal = { name: "ops-alice", sub: "idp-1", groups: ["fleet-operators"], via: "oidc", canWrite: false };
  const bob: Principal = { name: "ops-bob", sub: "idp-2", groups: ["fleet-operators"], via: "oidc", canWrite: false };

  const twoPeople = () => {
    const s = new SessionStore();
    return { s, a: s.create(alice), b: s.create(bob), b2: s.create(bob) };
  };

  it("ends only the named subject's sessions — the back-channel logout case", () => {
    const { s, a, b, b2 } = twoPeople();
    const outcome = s.applyToSubject("idp-2", () => null);
    assert.deepEqual(outcome, { updated: 0, ended: 2 });
    assert.equal(s.get(b.id), null, "bob's first session must be gone");
    assert.equal(s.get(b2.id), null, "bob's second session must be gone");
    assert.equal(s.get(a.id)?.principal.name, "ops-alice", "alice must still be signed in");
  });

  it("re-roles only the named subject — the role-change case", () => {
    const { s, a, b } = twoPeople();
    // Bob holds two sessions — both must be re-roled, which is also what makes "updated" a count
    // rather than a boolean.
    const outcome = s.applyToSubject("idp-2", (current) => ({ ...current, canWrite: true }));
    assert.deepEqual(outcome, { updated: 2, ended: 0 });
    assert.equal(s.get(b.id)?.principal.canWrite, true);
    assert.equal(s.get(a.id)?.principal.canWrite, false, "alice must not inherit bob's new role");
  });

  it("matching no session is an answer, not an error", () => {
    // The person may simply not be signed in; the caller logs the counts.
    const { s } = twoPeople();
    assert.deepEqual(s.applyToSubject("idp-nobody", () => null), { updated: 0, ended: 0 });
    assert.equal(s.size, 3);
  });

  it("matches on the subject, not on the display name", () => {
    // `sub` is the IdP's stable identifier; `name` is what a directory shows and can be edited or
    // repeated. A SET names the former, and matching the latter would let a renamed profile end
    // somebody else's session.
    const s = new SessionStore();
    const impostor: Principal = { ...bob, name: "ops-alice" };
    const real = s.create(alice);
    s.create(impostor);
    assert.deepEqual(s.applyToSubject("idp-2", () => null), { updated: 0, ended: 1 });
    assert.equal(s.get(real.id)?.principal.name, "ops-alice");
  });
});
