// The policy projection — screen 10's data, without a browser.
//
// The case that carries this file is **`renders-nowhere`**. Every other flag here describes a rule
// that does something an operator might not want; that one describes a rule that does nothing at
// all, while sitting in the policy file looking like protection. It is the only finding in this
// table that cannot be seen by reading the source.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { policyRows, policySummary } from "./policy-view.ts";
import type { Policy } from "./policy.ts";
import type { PublishHost } from "./publish.ts";

const policy = (over: Partial<Policy> = {}): Policy => ({
  id: "p1", name: "ssh from mgmt",
  src: { kind: "cidr", value: "10.254.0.0/16" }, dst: { kind: "cidr", value: "10.16.0.0/16" },
  proto: "tcp", ports: "22", action: "allow", denyMode: "drop",
  priority: 100, enabled: true, ...over,
});

const host = (id: string, items: PublishHost["items"], egress: PublishHost["egress"] = []): PublishHost =>
  ({ id, stage: "general", items, egress });

const item = (p: Policy, srcCidrs: string[] = ["10.254.0.0/16"]) =>
  ({ policy: p, srcCidrs, dstCidrs: ["10.16.0.0/16"] });

describe("one row per policy, not per host", () => {
  it("collects the hosts a policy renders on", () => {
    // The identity of the row is the rule. The hosts are what it does, and folding them into
    // separate rows would make a five-host rule look like five rules.
    const p = policy();
    const rows = policyRows({ hosts: [host("a", [item(p)]), host("b", [item(p)])] });
    assert.equal(rows.length, 1);
    assert.deepEqual(rows[0]!.hosts, ["a", "b"]);
  });

  it("keeps egress separate from input", () => {
    // They are different hooks. A rule that filters inbound on one host and outbound on another is
    // doing two different things and the table must not merge them into one count.
    const p = policy({ id: "egress-1" });
    const rows = policyRows({ hosts: [host("a", [], [{ policy: p, dstCidrs: null }])] });
    assert.deepEqual(rows[0]!.hosts, []);
    assert.deepEqual(rows[0]!.egressHosts, ["a"]);
  });

  it("orders by priority, then id — the order the renderer evaluates", () => {
    // Module order would let a reader conclude the wrong thing about which rule wins once a chain
    // defaults to deny.
    const rows = policyRows({
      hosts: [host("a", [
        item(policy({ id: "z", priority: 10 })),
        item(policy({ id: "a", priority: 50 })),
        item(policy({ id: "b", priority: 10 })),
      ])],
    });
    assert.deepEqual(rows.map((r) => r.id), ["b", "z", "a"]);
  });
});

describe("risk flags", () => {
  it("flags a policy the renderer placed nowhere — the finding worth having", () => {
    // It is in the file, it reads as protection, and no host got a rule from it. The source cannot
    // show this: the site module lists it on the host either way, and the renderer is what decides.
    const p = policy({ id: "ghost" });
    const site = { hosts: [host("a", [item(p)]), host("b", [item(p)])] };
    const skipped = new Map([["a", new Set(["ghost"])], ["b", new Set(["ghost"])]]);

    const known = policyRows({ ...site, skipped });
    assert.deepEqual(known[0]!.hosts, [], "no host rendered it");
    assert.deepEqual(known[0]!.skippedOn, ["a", "b"]);
    assert.ok(known[0]!.risks.includes("renders-nowhere"));
  });

  it("does not flag one the renderer placed on any host", () => {
    const p = policy({ id: "real" });
    const rows = policyRows({
      hosts: [host("a", [item(p)]), host("b", [item(p)])],
      skipped: new Map([["a", new Set(["real"])]]),
    });
    assert.deepEqual(rows[0]!.hosts, ["b"]);
    assert.deepEqual(rows[0]!.skippedOn, ["a"]);
    assert.equal(rows[0]!.risks.includes("renders-nowhere"), false);
  });

  it("refuses to claim placement it was not told", () => {
    // Without render results every listed policy would look placed, and the flag would be
    // structurally unable to fire — which is exactly how the first draft of this module shipped.
    // Saying so on the row beats a count that quietly means something else.
    const rows = policyRows({ hosts: [host("a", [item(policy())])] });
    assert.equal(rows[0]!.placementKnown, false);
    assert.equal(rows[0]!.risks.includes("renders-nowhere"), false);
    const told = policyRows({ hosts: [host("a", [item(policy())])], skipped: new Map() });
    assert.equal(told[0]!.placementKnown, true);
  });

  it("flags any-source only when the action allows", () => {
    // A deny from anywhere is the point of a deny. An allow from anywhere is the shape a mistake
    // takes, and the two must not carry the same badge.
    const allowAny = policyRows({ hosts: [host("a", [item(policy({ action: "allow" }), [])])] });
    const denyAny = policyRows({ hosts: [host("a", [item(policy({ action: "deny" }), [])])] });
    assert.ok(allowAny[0]!.risks.includes("any-source"));
    assert.equal(denyAny[0]!.risks.includes("any-source"), false);
  });

  it("reads an explicit all-addresses CIDR as any-source too", () => {
    // `[]` and `["0.0.0.0/0"]` render identically. Flagging only the empty spelling would miss the
    // commoner one.
    for (const cidrs of [[], ["0.0.0.0/0"], ["::/0"]]) {
      const rows = policyRows({ hosts: [host("a", [item(policy(), cidrs)])] });
      assert.ok(rows[0]!.risks.includes("any-source"), `missed for ${JSON.stringify(cidrs)}`);
    }
  });

  it("flags every port, and does not flag a port list", () => {
    const all = policyRows({ hosts: [host("a", [item(policy({ ports: "" }))])] });
    const some = policyRows({ hosts: [host("a", [item(policy({ ports: "80,443" }))])] });
    assert.ok(all[0]!.risks.includes("all-ports"));
    assert.equal(some[0]!.risks.includes("all-ports"), false);
  });

  it("shows a disabled policy rather than hiding it", () => {
    // 규약 9 — 삭제는 없다. A rule switched off is a decision somebody made, and it has to stay
    // readable or the next person re-adds it.
    const rows = policyRows({ hosts: [host("a", [item(policy({ enabled: false }))])] });
    assert.equal(rows.length, 1);
    assert.ok(rows[0]!.risks.includes("disabled"));
  });

  it("says nothing about a narrow, enabled, placed rule", () => {
    const rows = policyRows({ hosts: [host("a", [item(policy())])] });
    assert.deepEqual(rows[0]!.risks, []);
  });
});

describe("resolved sources", () => {
  it("unions across hosts and sorts, without duplicating", () => {
    // The same rule can resolve differently per host. The row shows the union because the question
    // is "who can reach this", not "who can reach host a".
    const p = policy();
    const rows = policyRows({
      hosts: [host("a", [item(p, ["10.254.0.0/16"])]), host("b", [item(p, ["10.255.0.0/16", "10.254.0.0/16"])])],
    });
    assert.deepEqual(rows[0]!.srcCidrs, ["10.254.0.0/16", "10.255.0.0/16"]);
  });
});

describe("the summary", () => {
  it("counts what the header claims", () => {
    const rows = policyRows({
      hosts: [host("a", [
        item(policy({ id: "a1", action: "allow" })),
        item(policy({ id: "d1", action: "deny" })),
        item(policy({ id: "x1", enabled: false })),
      ])],
    });
    const s = policySummary(rows);
    assert.equal(s.total, 3);
    assert.equal(s.allow, 2);
    assert.equal(s.deny, 1);
    assert.equal(s.disabled, 1);
  });
});
