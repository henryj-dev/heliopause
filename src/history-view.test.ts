// Publication history, projected from the policy repository's commit log.
//
// The case that carries this file is **not overstating what a commit proves**. Neither the manager
// nor the relay keeps a record of what shipped, so every row here is an inference from "this commit
// exists" plus "a manager says this generation is live". Marking a commit `applied` would be a much
// stronger claim than that supports, and it would be a claim nothing else in the system checks.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { historyRows, liveGenerations, type Commit } from "./history-view.ts";

const c = (id: string): Commit => ({ id, subject: `s-${id}`, author: "a", at: "2026-08-07T00:00:00Z" });

/** Newest first, the order `git log` gives. */
const log = [c("e5"), c("d4"), c("c3"), c("b2"), c("a1")];

describe("marking commits against what is live", () => {
  it("marks a live generation and names its VPCs", () => {
    const rows = historyRows(log, new Map([["c3", ["prod", "util"]]]));
    const hit = rows.find((r) => r.commit.id === "c3")!;
    assert.equal(hit.status, "live");
    assert.deepEqual(hit.liveOn, ["prod", "util"]);
  });

  it("calls what is older than the live commit 'superseded' and what is newer 'not published'", () => {
    // `git log` is newest-first, so "older" means a larger index. Getting this backwards would say a
    // commit that has not shipped anywhere was already replaced.
    const rows = historyRows(log, new Map([["c3", ["dev"]]]));
    assert.equal(rows.find((r) => r.commit.id === "d4")!.status, "not-published", "d4 is newer");
    assert.equal(rows.find((r) => r.commit.id === "b2")!.status, "superseded", "b2 is older");
  });

  it("treats commits newer than everything live as not published", () => {
    const rows = historyRows(log, new Map([["a1", ["dev"]]]));
    assert.deepEqual(
      rows.filter((r) => r.status === "not-published").map((r) => r.commit.id),
      ["e5", "d4", "c3", "b2"],
    );
  });

  it("anchors on the newest live commit when VPCs disagree", () => {
    // The normal state mid-rollout, and the state this fleet was in for two days: dev on one commit
    // and prod·util on an older one. A commit *between* the two is neither purely unshipped nor
    // purely replaced — anchoring on the newest makes `superseded` mean "something moved past it",
    // which is true of every row it lands on.
    const rows = historyRows(log, new Map([["d4", ["dev"]], ["b2", ["prod", "util"]]]));
    assert.equal(rows.find((r) => r.commit.id === "d4")!.status, "live");
    assert.equal(rows.find((r) => r.commit.id === "b2")!.status, "live");
    assert.equal(rows.find((r) => r.commit.id === "c3")!.status, "superseded", "between the two live ones");
    assert.equal(rows.find((r) => r.commit.id === "e5")!.status, "not-published", "newer than both");
  });

  it("says unknown — not superseded — when no manager answered", () => {
    // The first version returned `superseded` here, which reads as "these shipped and were
    // replaced": a statement about the fleet, made without asking the fleet.
    const rows = historyRows(log);
    assert.ok(rows.every((r) => r.status === "unknown"), JSON.stringify(rows.map((r) => r.status)));
  });

  it("preserves log order", () => {
    // A history sorted any other way stops being a history.
    const rows = historyRows(log, new Map([["c3", ["dev"]]]));
    assert.deepEqual(rows.map((r) => r.commit.id), ["e5", "d4", "c3", "b2", "a1"]);
  });
});

describe("reading the live set from a site view", () => {
  it("takes generations the manager already computed", () => {
    const live = liveGenerations([{ generation: "abc1234", vpcs: ["dev"] }]);
    assert.deepEqual([...live.keys()], ["abc1234"]);
  });

  it("ignores a dirty generation", () => {
    // A `-dirty-…` id names a commit that does not describe what was published. Marking that commit
    // live would say the repository holds those rules when by construction it does not — the whole
    // reason the policy moved into its own repository.
    const live = liveGenerations([
      { generation: "59a3752-dirty-ee8986c7", vpcs: ["prod"] },
      { generation: "abc1234", vpcs: ["dev"] },
    ]);
    assert.deepEqual([...live.keys()], ["abc1234"]);
  });

  it("ignores a VPC with no generation at all", () => {
    assert.equal(liveGenerations([{ generation: null, vpcs: ["dev"] }]).size, 0);
  });
});
