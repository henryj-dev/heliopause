// The authorisation decision for an OIDC identity.
//
// The case this file exists for is the last one: a writer with no alias. Everything else here is
// ordinary allowlist logic; that one is the two-person approval rule holding or not holding.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { authorize, parseAliases, type OidcAuthzConfig } from "./oidc-authz.ts";
import type { Identity } from "./oidc.ts";

const id = (over: Partial<Identity> = {}): Identity => ({
  sub: "idp-sub-1",
  username: "henry",
  email: "jang@example.invalid",
  // The default is a **verified** address, because that is the ordinary case these tests are
  // about. The unverified one gets its own describe below — it is the interesting half.
  emailVerified: true,
  groups: ["heliopause-operators"],
  expiresAt: new Date("2026-08-06T00:00:00Z"),
  ...over,
});

const cfg = (over: Partial<OidcAuthzConfig> = {}): OidcAuthzConfig => ({
  operatorGroups: ["heliopause-operators"],
  writerGroups: ["heliopause-writers"],
  aliases: new Map([["jang@example.invalid", "ops-alice"]]),
  ...over,
});

describe("reading", () => {
  it("admits an identity in an operator group — the known positive", () => {
    const d = authorize(id(), cfg());
    assert.equal(d.principal?.name, "ops-alice");
    assert.equal(d.principal?.via, "oidc");
    assert.equal(d.canWrite, false, "an operator group alone is not write access");
  });

  it("refuses an identity in no operator group", () => {
    const d = authorize(id({ groups: ["some-other-team"] }), cfg());
    assert.equal(d.principal, null);
    assert.match(d.reason, /none of \[some-other-team\]/);
  });

  it("says the scope is probably missing when there are no group claims at all", () => {
    // The difference matters when debugging a login: an absent claim is a client registration
    // problem, a present-but-wrong one is a group membership problem.
    const d = authorize(id({ groups: [] }), cfg());
    assert.equal(d.principal, null);
    assert.match(d.reason, /`groups` scope/);
  });

  it("grants nothing when no operator groups are configured", () => {
    // Empty means OIDC is registered but nobody has been given anything yet — the safe default.
    assert.equal(authorize(id(), cfg({ operatorGroups: [] })).principal, null);
  });
});

describe("writing, and the two-person rule", () => {
  const writer = id({ groups: ["heliopause-operators", "heliopause-writers"] });

  it("grants write to a writer whose identity is aliased to a certificate name", () => {
    const d = authorize(writer, cfg());
    assert.equal(d.canWrite, true);
    assert.equal(d.principal?.name, "ops-alice", "the name must collapse onto the certificate's");
  });

  it("refuses write to a writer with no alias, and says why", () => {
    // The case this module exists for. `approval.ts` compares proposer and approver as strings, so
    // one human under two names satisfies the two-person rule alone. Reading stays allowed.
    const d = authorize(writer, cfg({ aliases: new Map() }));
    assert.equal(d.canWrite, false);
    assert.ok(d.principal, "an unaliased writer may still read");
    assert.match(d.reason, /two-person approval rule/);
  });

  it("refuses write to an operator who is not in a writer group", () => {
    const d = authorize(id(), cfg());
    assert.equal(d.canWrite, false);
    assert.match(d.reason, /not a writer group/);
  });

  it("matches an alias by email, then username, then sub", () => {
    const byUser = authorize(id({ email: null }), cfg({ aliases: new Map([["henry", "ops-alice"]]) }));
    assert.equal(byUser.principal?.name, "ops-alice");
    const bySub = authorize(id({ email: null, username: null }), cfg({ aliases: new Map([["idp-sub-1", "ops-x"]]) }));
    assert.equal(bySub.principal?.name, "ops-x");
  });

  it("prefers the email alias when several could match", () => {
    const d = authorize(writer, cfg({
      aliases: new Map([["jang@example.invalid", "by-email"], ["henry", "by-username"], ["idp-sub-1", "by-sub"]]),
    }));
    assert.equal(d.principal?.name, "by-email");
  });

  it("falls back to a readable name when nothing is aliased", () => {
    const d = authorize(id({ email: "x@example.invalid" }), cfg({ aliases: new Map() }));
    assert.equal(d.principal?.name, "x@example.invalid");
    const noEmail = authorize(id({ email: null }), cfg({ aliases: new Map() }));
    assert.equal(noEmail.principal?.name, "henry");
    const bare = authorize(id({ email: null, username: null }), cfg({ aliases: new Map() }));
    assert.equal(bare.principal?.name, "idp-sub-1");
  });

  it("always gives a reason", () => {
    for (const d of [authorize(id(), cfg()), authorize(id({ groups: [] }), cfg()), authorize(writer, cfg())]) {
      assert.ok(d.reason.length > 0, "a decision without a reason is not reviewable");
    }
  });
});

describe("parsing the alias configuration", () => {
  it("reads pairs", () => {
    const m = parseAliases("a@x=ops-a, b@y=ops-b");
    assert.equal(m.get("a@x"), "ops-a");
    assert.equal(m.get("b@y"), "ops-b");
  });

  it("is empty for an empty spec", () => {
    assert.equal(parseAliases("").size, 0);
    assert.equal(parseAliases("  ,  ").size, 0);
  });

  it("refuses a malformed entry rather than skipping it", () => {
    // Skipping would present as "my writes are refused and I do not know why", with the operator
    // staring at a line that looks correct.
    assert.throws(() => parseAliases("a@x"), /expected <oidc-identity>=/);
    assert.throws(() => parseAliases("=ops-a"), /expected <oidc-identity>=/);
    assert.throws(() => parseAliases("a@x="), /expected <oidc-identity>=/);
  });

  it("refuses a duplicate left-hand side", () => {
    // Silently taking one of them would make which certificate name a person maps to depend on
    // configuration order.
    assert.throws(() => parseAliases("a@x=ops-a,a@x=ops-b"), /declared twice/);
  });
});

// ── An address the issuer has not verified is not an identity ─────────────────
//
// 🔴 `email_verified` appeared **nowhere in this repository** — not in `src`, `bin`, `agent` or
// `packages`. The alias map is keyed on email, that alias is what raises `canWrite`, and the name it
// resolves to is what `approval.ts` compares for the two-person rule. Many IdPs let a user edit
// their own profile address; only the verified one is the issuer's claim rather than the user's.
//
// So the hole was: a member of a writer group sets their profile email to a colleague's address,
// takes the colleague's alias, and satisfies both halves of the two-person rule alone — with the
// colleague's name in the audit line.
describe("an unverified email is not an alias key", () => {
  const writer = { groups: ["heliopause-operators", "heliopause-writers"] };

  it("grants write on a verified address — the known positive", () => {
    const d = authorize(id({ ...writer, emailVerified: true }), cfg());
    assert.equal(d.canWrite, true);
    assert.equal(d.principal?.name, "ops-alice");
  });

  it("refuses the same address when the issuer did not verify it", () => {
    const d = authorize(id({ ...writer, emailVerified: false }), cfg());
    assert.equal(d.canWrite, false);
    assert.notEqual(d.principal?.name, "ops-alice", "the colleague's alias must not be taken");
  });

  it("says which of the two refusals it is, because the fixes differ", () => {
    // "no alias is declared" and "an alias is declared but your address is unverified" want
    // completely different actions, and the second is invisible from the configuration line.
    const unverified = authorize(id({ ...writer, emailVerified: false }), cfg());
    assert.match(unverified.reason, /email_verified=true/);
    const noAlias = authorize(id({ ...writer, email: "nobody@example.invalid", emailVerified: true }), cfg());
    assert.match(noAlias.reason, /no alias to a certificate name/);
    assert.doesNotMatch(noAlias.reason, /email_verified/);
  });

  // The other two keys are not user-settable in the deployments this serves, and `sub` is the
  // issuer's own identifier — so an unverified address must not disable them.
  it("still resolves an alias keyed on the subject when the address is unverified", () => {
    const aliases = new Map([["idp-sub-1", "ops-alice"]]);
    const d = authorize(id({ ...writer, emailVerified: false }), cfg({ aliases }));
    assert.equal(d.canWrite, true);
    assert.equal(d.principal?.name, "ops-alice");
  });

  it("still resolves an alias keyed on preferred_username", () => {
    const aliases = new Map([["henry", "ops-alice"]]);
    const d = authorize(id({ ...writer, emailVerified: false }), cfg({ aliases }));
    assert.equal(d.canWrite, true);
  });

  // A missing claim is not a yes. An issuer that will not say has not said yes, and guessing here
  // would be guessing about who may approve a firewall change.
  it("treats an absent email_verified claim as unverified", () => {
    const withoutClaim = { ...id({ ...writer }), emailVerified: false };
    assert.equal(authorize(withoutClaim, cfg()).canWrite, false);
  });
});
