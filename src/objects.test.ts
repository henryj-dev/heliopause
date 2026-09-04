// `normalizeObject` — the validator for reusable address and service groups.
//
// 🔴 **It had no test, and no runtime caller.** A repository-wide search finds it defined in
// `objects.ts`, re-exported from `index.ts`, and named in a comment in `device-policy.ts` — and
// nowhere else. `site.objects` reaches the renderer through `bin/heliopause-publish.ts` typed as
// `FirewallObject[]`, and `policy-source.ts` checks only `Array.isArray`, so nothing on the publish
// path runs these rules.
//
// That is worth writing down twice, because it means two different things:
//
//   · the `device-policy.ts` comment that read "`normalizeObject` already refuses an empty member
//     list, so this is the case where every member expanded to nothing" was resting on a premise
//     that does not hold. It has been corrected there;
//   · this function is nonetheless **exported from `index.ts`** — public API of the published
//     package — so a consumer can and should call it. A public validator whose rules nothing pins
//     is a validator that will drift into agreeing with whatever it is handed.
//
// The stakes if it is wired in later, or called by a consumer now: one group is reused across many
// policies, so a member wrongly accepted here silently changes the meaning of every rule that names
// it. And an **empty** group is the inversion this module keeps warning about — empty means "from
// anywhere", not "from nobody".
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { normalizeObject } from "./objects.ts";
import { PolicyError } from "./policy.ts";

const address = (over: Record<string, unknown> = {}) => ({
  kind: "address",
  name: "operators",
  members: [{ kind: "cidr", value: "10.1.0.0/16" }],
  ...over,
});

describe("normalizeObject — the shape of an object", () => {
  it("accepts an address group and keeps its members — the known positive", () => {
    const o = normalizeObject(address(), "grp-1");
    assert.equal(o.id, "grp-1");
    assert.equal(o.kind, "address");
    assert.deepEqual(o.members, [{ kind: "cidr", value: "10.1.0.0/16" }]);
  });

  it("accepts a service group and orders its ports", () => {
    const o = normalizeObject({ kind: "service", name: "web", members: ["443", "80"] }, "svc-1");
    assert.deepEqual(o.members, ["80", "443"]);
  });

  it("refuses a kind that is neither address nor service", () => {
    assert.throws(() => normalizeObject({ ...address(), kind: "workload" }, "x"), PolicyError);
    assert.throws(() => normalizeObject({ ...address(), kind: "" }, "x"), PolicyError);
  });

  it("holds the name to the same character set as an @reference", () => {
    // If the two ever diverge, a group can be declared under a name no policy can name.
    for (const name of ["ops team.1", "a", "x".repeat(60)]) {
      assert.equal(normalizeObject(address({ name }), "x").name, name);
    }
    for (const name of ["", " ", "x".repeat(61), "ops/team", "ops@team", "ops,team"]) {
      assert.throws(() => normalizeObject(address({ name }), "x"), PolicyError, `accepted ${JSON.stringify(name)}`);
    }
  });

  // 🔴 The inversion. An empty group is not "matches nothing" — downstream, an empty address list
  // is "any address". `device-policy.ts` refuses an empty *expansion* for the same reason; this is
  // the refusal one level earlier, on a group that was declared empty to begin with.
  it("refuses an empty member list, which would otherwise mean 'from anywhere'", () => {
    assert.throws(() => normalizeObject(address({ members: [] }), "x"), /empty group matches all traffic/);
    assert.throws(() => normalizeObject(address({ members: undefined }), "x"), /empty group matches all traffic/);
    assert.throws(() => normalizeObject(address({ members: "10.0.0.0/8" }), "x"), /empty group matches all traffic/);
  });
});

describe("normalizeObject — address members", () => {
  const member = (m: unknown) => () => normalizeObject(address({ members: [m] }), "x");

  it("accepts the kinds a group is for, including the identity ones", () => {
    // `cf-device` and `cf-user` are members on purpose — see the comment in `objects.ts`. They
    // resolve against the approved device registry, not against another object, so they are not the
    // nesting refused below.
    for (const kind of ["host", "host-group", "cidr"]) {
      const value = kind === "cidr" ? "10.0.0.0/8" : "db-01";
      assert.equal(normalizeObject(address({ members: [{ kind, value }] }), "x").members.length, 1);
    }
  });

  // The rule that keeps a group from being a graph. A member that names another object means the
  // renderer has to chase a reference it cannot see the end of.
  it("refuses a nested object reference as a member", () => {
    assert.throws(member({ kind: "object", value: "@other" }), /nested objects and internet\/any are not allowed/);
  });

  // And the rule that keeps a group from quietly meaning "everything". `internet` or `any` inside a
  // group would widen every policy that names the group, from a line that reads like a member.
  it("refuses internet and any as members", () => {
    assert.throws(member({ kind: "internet", value: "" }), /internet\/any are not allowed/);
    assert.throws(member({ kind: "any", value: "" }), /internet\/any are not allowed/);
  });

  it("requires a value", () => {
    assert.throws(member({ kind: "cidr", value: "" }), /value is required/);
    assert.throws(member({ kind: "host" }), /value is required/);
  });

  it("requires a CIDR member to be a CIDR", () => {
    // A bare address here would render as a host route and quietly narrow the group by 65,535
    // addresses, or widen it, depending on which end of the prefix was meant.
    assert.throws(member({ kind: "cidr", value: "10.0.0.0" }), /must be a CIDR/);
    assert.throws(member({ kind: "cidr", value: "not-an-address/16" }), /must be a CIDR/);
    assert.equal(normalizeObject(address({ members: [{ kind: "cidr", value: "fd00::/8" }] }), "x").members.length, 1);
  });

  it("says which member is wrong", () => {
    // A group can hold dozens; "one of them is malformed" is not an actionable message.
    assert.throws(
      () => normalizeObject(address({ members: [{ kind: "cidr", value: "10.0.0.0/8" }, { kind: "cidr", value: "bad" }] }), "x"),
      /members\[1\]/,
    );
  });

  it("drops duplicates rather than carrying them into the fingerprint", () => {
    const o = normalizeObject(address({
      members: [
        { kind: "cidr", value: "10.1.0.0/16" },
        { kind: "cidr", value: "10.1.0.0/16" },
        { kind: "host", value: "10.1.0.0/16" },
      ],
    }), "x");
    // Same value, different kind, is a different member — the key is the pair.
    assert.deepEqual(o.members, [
      { kind: "cidr", value: "10.1.0.0/16" },
      { kind: "host", value: "10.1.0.0/16" },
    ]);
  });
});

describe("normalizeObject — service members", () => {
  const svc = (members: unknown[]) => () => normalizeObject({ kind: "service", name: "web", members }, "x");

  it("refuses a list inside one member", () => {
    // Otherwise "80,443" is one member here and two ports downstream, and the two counts disagree.
    assert.throws(svc(["80,443"]), /must hold one port spec/);
  });

  it("refuses a reference to another service object", () => {
    assert.throws(svc(["@web"]), /cannot reference another service object/);
  });

  it("refuses an empty member", () => {
    assert.throws(svc([""]), /is empty/);
    assert.throws(svc(["   "]), /is empty/);
  });

  it("validates the port shape through the same function policies use", () => {
    assert.throws(svc(["99999"]), PolicyError);
    assert.throws(svc(["http"]), PolicyError);
    assert.deepEqual(normalizeObject({ kind: "service", name: "w", members: ["9000:9100"] }, "x").members, ["9000:9100"]);
  });

  it("deduplicates and sorts by the first port", () => {
    assert.deepEqual(
      normalizeObject({ kind: "service", name: "w", members: ["443", "80", "443"] }, "x").members,
      ["80", "443"],
    );
  });
});
