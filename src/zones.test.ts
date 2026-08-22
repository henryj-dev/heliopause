// Zones, and the one thing that makes a trust level worth rendering.
//
// The screen this supports was designed on 2026-07-29 and could not be built for two weeks: there is
// no zone in `EndpointKind` and no trust anywhere in the model. The risk in adding it now is not
// getting the arithmetic wrong — it is shipping a number that appears in a column and decides
// nothing. So most of these tests are about `crossings`, which is the thing that has to work for the
// column to mean anything.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { normalizePolicy, type Policy } from "./policy.ts";
import { crossings, zoneConflicts, zoneOf, zoneRows, type Zone } from "./zones.ts";

const ZONES: Zone[] = [
  { id: "mgmt", name: "management", cidrs: ["10.254.0.0/16"], trust: 3 },
  { id: "dev-nodes", name: "dev nodes", cidrs: ["10.17.0.0/17"], trust: 2 },
  { id: "dev-pods", name: "dev pods", cidrs: ["10.17.128.0/18"], trust: 1 },
  { id: "internet", name: "internet", cidrs: ["0.0.0.0/0"], trust: 0 },
];

const policy = (over: Partial<Policy> = {}): Policy =>
  normalizePolicy(
    {
      name: "test",
      src: { kind: "cidr", value: "10.17.128.0/18" },
      dst: { kind: "cidr", value: "10.254.0.0/16" },
      proto: "tcp",
      ports: "443",
      action: "allow",
      priority: 100,
      ...over,
    },
    over.id ?? "P1",
  );

describe("placing an address in a zone", () => {
  it("prefers the most specific zone", () => {
    // `10.17.128.0/18` is inside `10.17.0.0/17`. Answering "dev nodes" for a pod range would lose
    // exactly the distinction the pod range exists to make — and it is the distinction that decides
    // whether a crossing is reported.
    assert.equal(zoneOf(ZONES, "10.17.128.0/18")?.id, "dev-pods");
    assert.equal(zoneOf(ZONES, "10.17.0.0/18")?.id, "dev-nodes");
  });

  it("falls back to the widest zone that contains it", () => {
    assert.equal(zoneOf(ZONES, "203.0.113.9/32")?.id, "internet");
  });

  it("says null for an address no zone claims", () => {
    // A range outside every zone is not "internet" unless a zone says so. Guessing would put traffic
    // in a trust level nobody assigned.
    assert.equal(zoneOf([ZONES[0]!], "192.0.2.1/32"), null);
  });

  it("says null for a malformed CIDR rather than throwing", () => {
    assert.equal(zoneOf(ZONES, "not-a-cidr"), null);
  });
});

describe("crossings — the reason the trust column is not decoration", () => {
  it("reports a policy admitting less trust into more", () => {
    const c = crossings(ZONES, [{ policy: policy() }]);
    assert.equal(c.length, 1);
    assert.equal(c[0]!.from.id, "dev-pods");
    assert.equal(c[0]!.to.id, "mgmt");
    assert.equal(c[0]!.gain, 2);
  });

  it("says nothing about traffic moving toward less trust", () => {
    // The known negative, and the one that keeps this list short enough to read. Management reaching
    // a pod is the normal direction and reporting it would bury the rows that matter.
    const outward = policy({ src: { kind: "cidr", value: "10.254.0.0/16" }, dst: { kind: "cidr", value: "10.17.128.0/18" } });
    assert.deepEqual(crossings(ZONES, [{ policy: outward }]), []);
  });

  it("says nothing between zones of equal trust", () => {
    // The gap a defect injection found: `gain < 0` instead of `gain <= 0` passed every other test
    // here, because none of them had two zones at the same level. Two peers exchanging traffic is
    // not a trust crossing, and reporting it would fill the table with rows that mean nothing —
    // which is how a review list stops being read.
    const peers: Zone[] = [
      { id: "a", name: "a", cidrs: ["10.20.0.0/16"], trust: 2 },
      { id: "b", name: "b", cidrs: ["10.21.0.0/16"], trust: 2 },
    ];
    const between = policy({
      src: { kind: "cidr", value: "10.20.0.0/16" },
      dst: { kind: "cidr", value: "10.21.0.0/16" },
    });
    assert.deepEqual(crossings(peers, [{ policy: between }]), []);
  });

  it("says nothing about traffic inside one zone", () => {
    const internal = policy({ src: { kind: "cidr", value: "10.17.128.0/18" }, dst: { kind: "cidr", value: "10.17.128.0/18" } });
    assert.deepEqual(crossings(ZONES, [{ policy: internal }]), []);
  });

  it("keeps denies, and marks them", () => {
    // A deny crossing inward is usually the opposite of a concern. Dropping it would make the table
    // read as "these are the allows" while calling itself crossings.
    const c = crossings(ZONES, [{ policy: policy({ action: "deny" }) }]);
    assert.equal(c[0]!.action, "deny");
  });

  it("sorts the largest trust gain first", () => {
    const fromInternet = policy({ id: "P-INET", src: { kind: "cidr", value: "0.0.0.0/0" } });
    const c = crossings(ZONES, [{ policy: policy() }, { policy: fromInternet }]);
    assert.equal(c[0]!.policyId, "P-INET", "internet → mgmt is the row a reviewer wants at the top");
    assert.equal(c[0]!.gain, 3);
  });

  it("uses resolved addresses when the endpoint is not a literal CIDR", () => {
    // What the site module hands the renderer. A policy written against a host group is placed by
    // the addresses it actually expands to, not by the fact that it names a group.
    const byName = policy({ src: { kind: "host", value: "some-host" } });
    const c = crossings(ZONES, [{ policy: byName, srcCidrs: ["10.17.128.5/32"] }]);
    assert.equal(c[0]!.from.id, "dev-pods");
  });

  it("takes the least trusted zone when a source spans several", () => {
    // **This asserted the opposite** — that a spanning source is unplaceable and reports nothing —
    // on the reasoning that a rule with no single origin has no honest crossing. Measured against
    // the real policy set, that silently dropped exactly the rules most worth reading: a source list
    // holding an internet address and an internal one vanished from the table.
    //
    // Least-trusted cannot understate. If any part of a source is untrusted, the policy admits
    // untrusted traffic, and the trusted remainder does not make that less true.
    const spanning = policy({ src: { kind: "host-group", value: "mixed" } });
    const c = crossings(ZONES, [{ policy: spanning, srcCidrs: ["10.17.128.5/32", "10.254.0.9/32"] }]);
    assert.equal(c.length, 1);
    assert.equal(c[0]!.from.id, "dev-pods", "the lower of the two, not the first listed");
  });

  it("places a source by the lowest trust regardless of list order", () => {
    // The property that makes the rule above safe to rely on. Order-dependence here would make a
    // finding appear or disappear with an edit that changed nothing about the firewall.
    const spanning = policy({ src: { kind: "host-group", value: "mixed" } });
    const a = crossings(ZONES, [{ policy: spanning, srcCidrs: ["10.254.0.9/32", "10.17.128.5/32"] }]);
    const b = crossings(ZONES, [{ policy: spanning, srcCidrs: ["10.17.128.5/32", "10.254.0.9/32"] }]);
    assert.deepEqual(a.map((x) => x.from.id), b.map((x) => x.from.id));
  });
});

describe("configuration errors in the zone list itself", () => {
  // The first version of this check looked for ranges that overlap without nesting. **That cannot
  // happen** — CIDR prefixes are aligned, so two ranges are always nested or disjoint. It was a
  // check for an impossible state, which passes on every input including the broken ones.

  it("reports the same range claimed by two zones", () => {
    // What actually goes wrong. One address then carries two trust levels and `zoneOf` answers by
    // list order, so a crossing appears or disappears depending on how the site module was written.
    const bad: Zone[] = [
      { id: "a", name: "a", cidrs: ["10.9.0.0/16"], trust: 1 },
      { id: "b", name: "b", cidrs: ["10.9.0.0/16"], trust: 3 },
    ];
    assert.equal(zoneConflicts(bad).length, 1);
  });

  it("reports a malformed CIDR rather than placing it nowhere", () => {
    // Silently unplaceable is the worse failure: every policy touching that range drops out of the
    // crossings list, so the screen gets quieter as the configuration gets more broken.
    const bad: Zone[] = [{ id: "a", name: "a", cidrs: ["10.9.0.0/33"], trust: 1 }];
    assert.equal(zoneConflicts(bad).length, 1);
  });

  it("accepts nesting, which is how pods sit inside nodes", () => {
    assert.deepEqual(zoneConflicts(ZONES), []);
  });
});

describe("the table", () => {
  it("counts each zone as source, as destination, and as admitting", () => {
    const rows = zoneRows(ZONES, [{ policy: policy() }]);
    const mgmt = rows.find((r) => r.zone.id === "mgmt")!;
    const pods = rows.find((r) => r.zone.id === "dev-pods")!;
    assert.equal(pods.asSource, 1);
    assert.equal(mgmt.asDestination, 1);
    assert.equal(mgmt.admits, 1, "mgmt admits one thing less trusted than itself");
    assert.equal(pods.admits, 0);
  });

  it("keeps a zone no policy mentions", () => {
    // An unreferenced zone is a finding — a range someone named and nothing uses — and dropping it
    // from the table is how it stays invisible.
    const rows = zoneRows(ZONES, []);
    assert.equal(rows.length, ZONES.length);
  });
});
