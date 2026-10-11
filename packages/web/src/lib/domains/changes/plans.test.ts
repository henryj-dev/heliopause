import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  canOfferApprove,
  canOfferApproveAndPublish,
  canOfferPublish,
  planStage,
  readPlansView,
  type PlanRow,
} from "./plans.ts";

const pending: PlanRow = {
  hash: "abc",
  generation: "gen-1",
  proposedBy: "ops-alice",
  proposedAt: "2026-08-18T00:00:00.000Z",
  summary: { hosts: [{ host: "gw-01.dev", stage: "general", ruleCount: 3, rulesetHash: "deadbeef" }] },
  approval: null,
  publishedAt: null,
  target: "dev",
};

describe("readPlansView", () => {
  it("accepts a listing the manager would send", () => {
    const read = readPlansView({
      plans: [pending],
      limits: { ttlSec: 3600 },
      you: "ops-bob",
      canWrite: true,
      maySoloApprove: false,
      targets: ["dev"],
      csrf: "token",
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.equal(read.view.plans[0]?.hash, "abc");
      assert.equal(read.view.plans[0]?.target, "dev");
      assert.equal(read.view.csrf, "token");
      assert.equal(read.view.limits.maxPending, null);
    }
  });

  it("keeps a missing plan target as unread, not as a missing VPC", () => {
    const { target: _dropped, ...bare } = pending;
    const read = readPlansView({
      plans: [bare],
      limits: { ttlSec: 3600 },
      you: "ops-bob",
      canWrite: true,
    });
    assert.equal(read.ok && read.view.plans[0]?.target, null);
  });

  it("reads the pending cap when the manager sends it", () => {
    const read = readPlansView({
      plans: [],
      limits: { ttlSec: 600, maxPending: 32 },
      you: "ops-alice",
      canWrite: true,
    });
    assert.equal(read.ok && read.view.limits.maxPending, 32);
  });

  it("treats a missing targets list as empty rather than malformed", () => {
    const read = readPlansView({
      plans: [],
      limits: { ttlSec: 60 },
      you: "ops-alice",
      canWrite: false,
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.deepEqual(read.view.targets, []);
      assert.equal(read.view.csrf, null);
    }
  });

  it("refuses a payload that is missing who is asking", () => {
    const read = readPlansView({ plans: [], limits: { ttlSec: 60 }, canWrite: true });
    assert.equal(read.ok, false);
  });
});

describe("target generation payloads", () => {
  const listing = (targetGeneration: unknown) => readPlansView({
    plans: [{ ...pending, targetGeneration }], limits: { ttlSec: 3600 }, you: "ops-bob", canWrite: true,
  });
  const at = "2026-10-11T00:00:00.000Z";

  it("reads one, mixed and unknown observations with their time", () => {
    for (const observation of [
      { kind: "one", generation: "gen-1", observedAt: at },
      { kind: "mixed", observedAt: at },
      { kind: "unknown", why: "timeout", observedAt: at },
      { kind: "unknown", why: "missing target", observedAt: null },
    ]) {
      const read = listing(observation);
      assert.ok(read.ok);
      assert.deepEqual(read.view.plans[0]?.targetGeneration, observation);
    }
  });

  it("keeps the plan when an old manager omits the observation or sends an invalid one", () => {
    for (const observation of [undefined, null, 1, {},
      { kind: "one", generation: "", observedAt: at },
      { kind: "one", generation: "gen-1", observedAt: null },
      { kind: "mixed", observedAt: "bad date" },
      { kind: "unknown", why: 1, observedAt: at },
      { kind: "other", observedAt: at },
    ]) {
      const read = listing(observation);
      assert.ok(read.ok);
      assert.equal(read.view.plans.length, 1);
      assert.equal(read.view.plans[0]?.hash, pending.hash);
      assert.equal(read.view.plans[0]?.targetGeneration?.kind, "unknown");
      assert.equal(read.view.plans[0]?.targetGeneration?.observedAt, null);
    }
  });

  it("does not change any action offer when an observation is added", () => {
    for (const observation of [
      { kind: "one", generation: "gen-1", observedAt: at },
      { kind: "mixed", observedAt: at },
      { kind: "unknown", why: "timeout", observedAt: at },
    ]) {
      const read = listing(observation);
      assert.ok(read.ok);
      const observed = read.view.plans[0]!;
      for (const writer of [true, false]) for (const solo of [true, false]) for (const you of ["ops-alice", "ops-bob"]) {
        for (const approval of [null, { by: "ops-bob", at }]) for (const publishedAt of [null, at]) {
          const before = { ...pending, approval, publishedAt };
          const after = { ...observed, approval, publishedAt };
          assert.equal(canOfferApprove(after, you, writer, solo), canOfferApprove(before, you, writer, solo));
          assert.equal(canOfferApproveAndPublish(after, you, writer, solo), canOfferApproveAndPublish(before, you, writer, solo));
          assert.equal(canOfferPublish(after, writer), canOfferPublish(before, writer));
        }
      }
    }
  });
});

describe("plan actions", () => {
  it("offers approve to a different writer, not to the proposer", () => {
    assert.equal(canOfferApprove(pending, "ops-bob", true, false), true);
    assert.equal(canOfferApprove(pending, "ops-alice", true, false), false);
    assert.equal(canOfferApprove(pending, "ops-alice", true, true), true);
    assert.equal(canOfferApprove(pending, "ops-bob", false, false), false);
  });

  it("offers publish only after approval, and never after publish", () => {
    assert.equal(canOfferPublish(pending, true), false);
    const approved = { ...pending, approval: { by: "ops-bob", at: "2026-08-18T00:01:00.000Z" } };
    assert.equal(canOfferPublish(approved, true), true);
    assert.equal(canOfferPublish(approved, false), false);
    assert.equal(canOfferPublish({ ...approved, publishedAt: "2026-08-18T00:02:00.000Z" }, true), false);
    assert.equal(planStage(pending), "awaiting");
    assert.equal(planStage(approved), "approved");
    assert.equal(planStage({ ...approved, publishedAt: "2026-08-18T00:02:00.000Z" }), "published");
  });
});

describe("approve and publish in one step", () => {
  // The server refuses everything this does not offer, before it spends the code. The page offers it
  // only where it would succeed, so the button is never one that exists to be refused.
  it("offers it to the proposer with solo approval, on a plan nobody has approved", () => {
    assert.equal(canOfferApproveAndPublish(pending, "ops-alice", true, true), true);
  });

  it("does not offer it without solo approval, to anyone else, or to a reader", () => {
    assert.equal(canOfferApproveAndPublish(pending, "ops-alice", true, false), false, "no solo role");
    assert.equal(canOfferApproveAndPublish(pending, "ops-bob", true, true), false, "someone else's plan");
    assert.equal(canOfferApproveAndPublish(pending, "ops-alice", false, true), false, "may not write");
  });

  it("does not offer it once the plan is approved or published", () => {
    const approved = { ...pending, approval: { by: "ops-alice", at: "2026-08-18T00:01:00.000Z" } };
    assert.equal(canOfferApproveAndPublish(approved, "ops-alice", true, true), false, "the publish button is the way on");
    assert.equal(
      canOfferApproveAndPublish({ ...pending, publishedAt: "2026-08-18T00:02:00.000Z" }, "ops-alice", true, true), false,
    );
  });
});
