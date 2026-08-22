// The three remaining workstation projections.
//
// The case that carries this file is **baseline order**. Every other assertion here is about a count
// or a label; that one is about precedence in the layer policy cannot override, and a table that
// sorts it would be wrong in a way nobody would notice by reading it.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { baselineRows, hostRows, joinFleet, workloadRows } from "./site-view.ts";
import type { Policy } from "./policy.ts";
import type { PublishHost } from "./publish.ts";

const baseline = [
  { desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: ["10.254.0.0/16"] },
  { desc: "ICMP", proto: "icmp", ports: "", srcCidrs: [] },
  { desc: "DHCP renewal", proto: "udp", ports: "68", srcCidrs: [] },
] as const;

const policy = (over: Partial<Policy> = {}): Policy => ({
  id: "p1", name: "n", src: { kind: "cidr", value: "10.0.0.0/8" },
  dst: { kind: "host", value: "h" }, proto: "tcp", ports: "22",
  action: "allow", denyMode: "drop", priority: 100, enabled: true, ...over,
});

const host = (id: string, n: number, egress = 0): PublishHost => ({
  id, stage: "general",
  items: Array.from({ length: n }, (_, i) => ({
    policy: policy({ id: `in-${i}` }), srcCidrs: ["10.0.0.0/8"], dstCidrs: ["10.0.0.1/32"],
  })),
  egress: Array.from({ length: egress }, (_, i) => ({ policy: policy({ id: `eg-${i}` }), dstCidrs: null })),
});

describe("baseline", () => {
  it("keeps the authored order", () => {
    // Baseline order is render order, in the one layer where precedence is not negotiable. Sorting
    // by name or protocol would produce a table that is wrong about which rule wins, and nothing on
    // the page would look off.
    const rows = baselineRows({ baseline: [...baseline] });
    assert.deepEqual(rows.map((r) => r.desc), ["management SSH", "ICMP", "DHCP renewal"]);
  });

  it("marks an unrestricted rule without grading it", () => {
    // ICMP and NDP are unrestricted deliberately — a host that cannot be pinged is harder to debug.
    // The flag exists so a reader sees it, not so the page can call it a finding.
    const rows = baselineRows({ baseline: [...baseline] });
    assert.equal(rows[0]!.anySource, false, "SSH is source-scoped");
    assert.equal(rows[1]!.anySource, true, "ICMP is not");
  });

  it("carries ports through as authored, including empty", () => {
    const rows = baselineRows({ baseline: [...baseline] });
    assert.equal(rows[0]!.ports, "22");
    assert.equal(rows[1]!.ports, "", "empty means every port on that protocol");
  });

  it("handles a site with no baseline", () => {
    assert.deepEqual(baselineRows({ baseline: [] }), []);
  });
});

describe("hosts", () => {
  it("counts input and egress separately", () => {
    // Different hooks. A host filtering inbound and outbound is doing two things, and one number
    // would hide which.
    const rows = hostRows({ cfg: { protectedHosts: [] }, hosts: [host("a", 3, 2)] });
    assert.equal(rows[0]!.inputCount, 3);
    assert.equal(rows[0]!.egressCount, 2);
  });

  it("marks the host the config protects from lockout", () => {
    // `protectedHosts` is what stops a generation from locking the relay out of its own VPC. A
    // reader deciding whether a change is safe needs to see which host that is.
    const rows = hostRows(
      { cfg: { protectedHosts: ["^gw-01\\."] }, hosts: [host("gw-01.dev", 1), host("k3s-01.dev", 1)] },
    );
    assert.equal(rows[0]!.protected, true);
    assert.equal(rows[1]!.protected, false);
  });

  it("lists what the renderer skipped, sorted", () => {
    const rows = hostRows(
      { cfg: { protectedHosts: [] }, hosts: [host("a", 3)] },
      new Map([["a", new Set(["in-2", "in-0"])]]),
    );
    assert.deepEqual(rows[0]!.skipped, ["in-0", "in-2"]);
    assert.equal(rows[0]!.placementKnown, true);
  });

  it("says when the counts are 'listed' rather than 'renders'", () => {
    // Same distinction the policy screen carries. Without render results the number is what the
    // module says, not what the host gets.
    const rows = hostRows({ cfg: { protectedHosts: [] }, hosts: [host("a", 3)] });
    assert.equal(rows[0]!.placementKnown, false);
    assert.deepEqual(rows[0]!.skipped, []);
  });
});

describe("workload", () => {
  it("labels an endpoint with its kind first", () => {
    // `arc-runners` alone does not say whether it is a namespace, a host or a CIDR, and those select
    // completely different traffic. The kind is the load-bearing half of the label.
    const rows = workloadRows([{
      policy: policy({
        id: "W1", src: { kind: "k8s-namespace", value: "arc-runners" } as Policy["src"],
        dst: { kind: "any" } as Policy["dst"],
      }),
    }]);
    assert.equal(rows[0]!.src, "k8s-namespace:arc-runners");
    assert.equal(rows[0]!.dst, "any", "a kind with no value renders as the kind alone");
  });

  it("has no placement column, because a CNP is not addressed to a host", () => {
    // The asymmetry with the nftables screen is real: cluster-scoped policy has no host to land on.
    // Asserted so a later change that adds a fake placement has to argue with this.
    const rows = workloadRows([{ policy: policy({ id: "W1" }) }]);
    assert.equal("hosts" in rows[0]!, false);
    assert.equal("skipped" in rows[0]!, false);
  });

  it("keeps a disabled policy", () => {
    const rows = workloadRows([{ policy: policy({ id: "W1", enabled: false }) }]);
    assert.equal(rows.length, 1);
    assert.equal(rows[0]!.enabled, false);
  });
});

describe("joining the manager's view", () => {
  const rows = hostRows({ cfg: { protectedHosts: [] }, hosts: [host("a", 1), host("b", 1)] });
  const fleet = (over = {}) => ({
    host: "a", state: "confirmed", generation: "abc1234",
    current: true, drifted: false, ageSec: 3, blockedBy: null, ...over,
  });

  it("folds state onto the matching host", () => {
    const out = joinFleet(rows, [fleet()]);
    assert.equal(out[0]!.fleet?.state, "confirmed");
    assert.equal(out[0]!.fleet?.generation, "abc1234");
  });

  it("leaves a host this manager does not know without a fleet field", () => {
    // Not the same as "reported nothing". A policy can list hosts in a VPC this manager does not
    // aggregate, and filling those in would send somebody to check an agent that is fine.
    const out = joinFleet(rows, [fleet()]);
    assert.equal(out[1]!.id, "b");
    assert.equal(out[1]!.fleet, undefined);
  });

  it("carries the fields the console needed and the policy screen did not have", () => {
    // `drifted`, `current` and `blockedBy` are the three that say something is wrong. They are the
    // reason this join exists — the policy half cannot know any of them.
    const out = joinFleet(rows, [fleet({ drifted: true, current: false, blockedBy: "canary not confirmed" })]);
    assert.equal(out[0]!.fleet?.drifted, true);
    assert.equal(out[0]!.fleet?.current, false);
    assert.equal(out[0]!.fleet?.blockedBy, "canary not confirmed");
  });

  it("changes nothing when the manager returned no hosts", () => {
    assert.deepEqual(joinFleet(rows, []), rows);
  });
});
