import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { diffRulesets } from "./ruleset-diff.ts";

/** An nft JSON document carrying the rules named, in order. */
const doc = (...rules: Array<{ comment: string; expr?: unknown }>) =>
  JSON.stringify({
    nftables: [
      { add: { table: { family: "inet", name: "heliopause" } } },
      ...rules.map((r) => ({ add: { rule: { family: "inet", table: "heliopause", chain: "input", ...r } } })),
    ],
  });

const ssh = { comment: "baseline: management SSH", expr: [{ match: { left: "dport", right: 22 } }] };
const pg = { comment: "P12 postgres", expr: [{ match: { left: "dport", right: 5432 } }] };
const old = { comment: "P07 legacy", expr: [{ match: { left: "dport", right: 8080 } }] };

describe("what a plan changes about a host's rules", () => {
  // The known positive. Every assertion below would also pass against a function that reported every
  // rule as changed, and that failure looks exactly like a diff working hard.
  it("reports nothing when the two renderings are the same", () => {
    const d = diffRulesets(doc(ssh, pg), doc(ssh, pg))!;
    assert.deepEqual(d.changes, []);
    assert.equal(d.unchanged, 2);
    assert.equal(d.before, 2);
    assert.equal(d.after, 2);
  });

  it("names a rule that appeared", () => {
    const d = diffRulesets(doc(ssh), doc(ssh, pg))!;
    assert.deepEqual(d.changes, [{ comment: "P12 postgres", kind: "added" }]);
    assert.equal(d.unchanged, 1);
  });

  it("names a rule that disappeared", () => {
    const d = diffRulesets(doc(ssh, old), doc(ssh))!;
    assert.deepEqual(d.changes, [{ comment: "P07 legacy", kind: "removed" }]);
  });

  // The case the source diff cannot show at all: no line of policy moved, and the rule did — a
  // resolver returning a different set, a Service selector that widened, a geofeed that grew.
  it("names a rule whose match changed while its policy did not", () => {
    const widened = { comment: "P12 postgres", expr: [{ match: { left: "dport", right: [5432, 5433] } }] };
    const d = diffRulesets(doc(pg), doc(widened))!;
    assert.deepEqual(d.changes, [{ comment: "P12 postgres", kind: "changed" }]);
    assert.equal(d.unchanged, 0);
  });

  // Removals first: a rule that disappeared is the one that opens a port, and it is what an approver
  // is least likely to spot unaided. Then changes, then additions; alphabetical inside each group so
  // the same two bundles always draw the same page.
  it("puts removals first, then changes, then additions", () => {
    const changed = { comment: "baseline: management SSH", expr: [{ match: { left: "dport", right: 2222 } }] };
    const d = diffRulesets(doc(ssh, old), doc(changed, pg))!;
    assert.deepEqual(d.changes.map((c) => c.kind), ["removed", "changed", "added"]);
  });

  // One policy renders as two rules when its addresses span both families. A change to either half
  // has to show as a change to that policy rather than being averaged away.
  it("treats the two halves of a family split as one policy", () => {
    const v4 = { comment: "P20 mesh", expr: [{ match: { left: "ip saddr", right: "10.0.0.0/8" } }] };
    const v6 = { comment: "P20 mesh", expr: [{ match: { left: "ip6 saddr", right: "fd00::/8" } }] };
    const v6wider = { comment: "P20 mesh", expr: [{ match: { left: "ip6 saddr", right: "fd00::/7" } }] };
    assert.deepEqual(diffRulesets(doc(v4, v6), doc(v4, v6))!.changes, []);
    assert.deepEqual(diffRulesets(doc(v4, v6), doc(v4, v6wider))!.changes,
      [{ comment: "P20 mesh", kind: "changed" }]);
  });

  it("ignores a rule with no comment rather than inventing a key for it", () => {
    // Every rule this project renders carries one. An uncommented rule came from somewhere else, and
    // a synthetic key would make it read as a policy change on whichever side it turned up.
    const bare = { expr: [{ match: { left: "dport", right: 9999 } }] } as unknown as { comment: string };
    assert.deepEqual(diffRulesets(doc(ssh), doc(ssh, bare))!.changes, []);
  });

  it("counts both sides, so an empty plan and an unchanged one are distinguishable", () => {
    const emptied = diffRulesets(doc(ssh, pg), doc())!;
    assert.equal(emptied.before, 2);
    assert.equal(emptied.after, 0);
    assert.equal(emptied.changes.length, 2);
  });

  // `null` rather than an empty diff. "Nothing changed" and "I could not compare" send an approver to
  // opposite conclusions, and only one of them is safe to act on.
  it("says it could not compare rather than reporting no change", () => {
    assert.equal(diffRulesets("not json", doc(ssh)), null);
    assert.equal(diffRulesets(doc(ssh), "not json"), null);
    assert.equal(diffRulesets(JSON.stringify({ something: "else" }), doc(ssh)), null);
  });
});
