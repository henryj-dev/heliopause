// What "where is this written" must not answer.
//
// The failure mode is the opposite of the lookup's. There, folding "cannot decide" into "no" hid the
// rule the reader wanted. Here the danger is folding "writes a range containing it" into "writes
// it": somebody renaming a literal would be shown six rules and only one of them has the text they
// are about to change, and they would edit the other five into something they did not mean.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { whereUsed, repeatedLiterals } from "./where-used.ts";
import type { Policy } from "./policy.ts";

// Ends that do not contain each other, so a test about exact matching is not quietly also a test
// about containment. The first draft used `10.0.0.0/8` as the source and every "exact" assertion
// picked up a second hit — the code was right and the fixture was doing two things at once.
const policy = (over: Partial<Policy> = {}): Policy => ({
  id: "P", name: "n", src: { kind: "cidr", value: "192.0.2.0/24" }, dst: { kind: "cidr", value: "10.17.192.45/32" },
  proto: "tcp", ports: "5432", action: "allow", denyMode: "drop", priority: 100, enabled: true, ...over,
});

describe("where a value is written", () => {
  it("finds the rule that writes it — the known positive", () => {
    const u = whereUsed([policy()], "10.17.192.45/32");
    assert.equal(u.length, 1);
    assert.equal(u[0]?.where, "dst");
    assert.equal(u[0]?.match, "exact");
    // The rule's own text, not the query echoed back. The reader is looking for a line to edit.
    assert.equal(u[0]?.text, "cidr 10.17.192.45/32");
  });

  it("keeps a containing range apart from the text itself", () => {
    // The distinction the whole module rests on. A `/17` covers the address and is not the address:
    // renaming the literal touches one line and changing the address touches the other, and a merged
    // list serves whichever job the reader assumed.
    const u = whereUsed([policy({ src: { kind: "cidr", value: "10.17.128.0/17" } })], "10.17.192.45");
    assert.equal(u.length, 2);
    assert.ok(u.every((x) => x.match === "contains"), "an address is not the text of a range");
    assert.deepEqual(u.map((x) => x.where).sort(), ["dst", "src"]);
  });

  it("finds a port where a port was asked for", () => {
    // A port search that quietly only looked at addresses would answer "nowhere" about a port that
    // is in six rules, which is worse than refusing the query.
    const u = whereUsed([policy({ ports: "80,443" })], "443");
    assert.deepEqual(u.map((x) => x.where), ["ports"]);
  });

  it("includes a disabled rule and says it is disabled", () => {
    // It is still a place the value is written, and somebody renaming has to change that line too.
    // Excluding it leaves a stale literal exactly where nobody looks.
    const u = whereUsed([policy({ enabled: false })], "10.17.192.45/32");
    assert.equal(u.length, 1);
    assert.equal(u[0]?.enabled, false);
  });

  it("finds a workload selector by the part of it a person would quote", () => {
    const u = whereUsed(
      [policy({ src: { kind: "k8s-label", value: "k8s:io.kubernetes.pod.namespace=dispatcher,app=dispatcher" } })],
      "app=dispatcher",
    );
    assert.equal(u.length, 1);
    assert.equal(u[0]?.match, "exact");
  });

  it("answers nothing for an empty query rather than everything", () => {
    assert.deepEqual(whereUsed([policy()], "   "), []);
  });

  it("puts the line to edit first", () => {
    const rules = [
      policy({ id: "RANGE", dst: { kind: "cidr", value: "10.17.0.0/17" } }),
      policy({ id: "EXACT", dst: { kind: "cidr", value: "10.17.192.45" } }),
    ];
    const u = whereUsed(rules, "10.17.192.45");
    assert.equal(u[0]?.policyId, "EXACT");
    assert.equal(u[0]?.match, "exact");
  });
});

describe("which literals are asking for a name", () => {
  it("counts a range written in more than one rule", () => {
    const u = repeatedLiterals([
      policy({ id: "A", src: { kind: "cidr", value: "10.17.0.0/17" }, dst: { kind: "any", value: "" } }),
      policy({ id: "B", src: { kind: "cidr", value: "10.17.0.0/17" }, dst: { kind: "any", value: "" } }),
      policy({ id: "C", src: { kind: "cidr", value: "198.51.100.0/24" }, dst: { kind: "any", value: "" } }),
    ]);
    assert.deepEqual(u.map((x) => [x.value, x.count]), [["10.17.0.0/17", 2]]);
    assert.deepEqual(u[0]?.policyIds, ["A", "B"]);
  });

  it("says nothing about a range written once", () => {
    // A range in one rule is a rule. A range in six is a thing with a name nobody wrote down, and
    // the day it changes somebody has to find all six — that is the whole claim this makes.
    assert.deepEqual(repeatedLiterals([policy({ id: "A" })]).map((x) => x.value), []);
  });

  it("counts a rule once however many of its ends use the range", () => {
    // Otherwise a rule from a range to itself reads as two rules needing the name.
    const u = repeatedLiterals([
      policy({ id: "A", src: { kind: "cidr", value: "10.0.0.0/8" }, dst: { kind: "cidr", value: "10.0.0.0/8" } }),
      policy({ id: "B", src: { kind: "cidr", value: "10.0.0.0/8" }, dst: { kind: "any", value: "" } }),
    ]);
    assert.deepEqual(u.map((x) => [x.value, x.count]), [["10.0.0.0/8", 2]]);
  });

  it("ignores the kinds a name would not replace", () => {
    // `any` and `internet` are already names.
    const u = repeatedLiterals([
      policy({ id: "A", src: { kind: "any", value: "" }, dst: { kind: "internet", value: "" } }),
      policy({ id: "B", src: { kind: "any", value: "" }, dst: { kind: "internet", value: "" } }),
    ]);
    assert.deepEqual(u, []);
  });
});
