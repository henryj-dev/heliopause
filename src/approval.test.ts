// The two-person rule, tested as data.
//
// Every test here is a way the rule could be defeated while every endpoint still returns 200. That is
// the failure shape that matters: an approval mechanism that can be bypassed is worse than none,
// because the audit trail records approvals that did not constrain anything.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ApprovalError,
  approve,
  claimForPublish,
  emptyApprovals,
  listPlans,
  propose,
  release,
  sweep,
  type PlanSummary,
} from "./approval.ts";

const H = "sha256:" + "a".repeat(64);
const H2 = "sha256:" + "b".repeat(64);
const SUMMARY: PlanSummary = {
  hosts: [{ host: "gw-01.dev", stage: "canary", ruleCount: 12, rulesetHash: H }],
};
const T0 = new Date("2026-08-03T00:00:00Z");
const at = (sec: number) => new Date(T0.getTime() + sec * 1000);

/** A pending plan proposed by `henry`. */
function pending() {
  const st = emptyApprovals();
  propose(st, { hash: H, generation: "abc1234", summary: SUMMARY, by: "ops-henry", now: T0 });
  return st;
}

function refusal(fn: () => unknown): ApprovalError {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof ApprovalError, `expected ApprovalError, got ${e}`);
    return e;
  }
  return assert.fail("expected a refusal");
}

describe("proposing", () => {
  it("records who proposed it, from the certificate rather than the payload", () => {
    const st = pending();
    assert.equal(st.plans.get(H)!.proposedBy, "ops-henry");
    assert.equal(st.plans.get(H)!.approval, null);
  });

  it("refuses a hash that is not a sha256 digest", () => {
    const st = emptyApprovals();
    const e = refusal(() =>
      propose(st, { hash: "../../etc/passwd", generation: "g", summary: SUMMARY, by: "ops-henry", now: T0 }),
    );
    assert.equal(e.status, 400);
  });

  it("refuses a caller with no identity", () => {
    const st = emptyApprovals();
    const e = refusal(() =>
      propose(st, { hash: H, generation: "g", summary: SUMMARY, by: "", now: T0 }),
    );
    assert.equal(e.status, 401);
  });

  it("is idempotent for identical content", () => {
    // A CLI that retried after a timeout must not create a second plan.
    const st = pending();
    propose(st, { hash: H, generation: "abc1234", summary: SUMMARY, by: "ops-henry", now: at(5) });
    assert.equal(st.plans.size, 1);
  });

  it("does not let re-proposing reset an approval already given", () => {
    const st = pending();
    approve(st, { hash: H, by: "ops-jae", now: at(10) });
    propose(st, { hash: H, generation: "abc1234", summary: SUMMARY, by: "ops-henry", now: at(20) });
    assert.equal(st.plans.get(H)!.approval?.by, "ops-jae", "the approval was lost by a replay");
  });

  it("does not let a second proposer take over the plan", () => {
    // The bypass this guards. If re-proposing overwrote `proposedBy`, two operators could trade: jae
    // re-proposes henry's plan, becoming its proposer, which frees henry to approve his own work.
    const st = pending();
    propose(st, { hash: H, generation: "abc1234", summary: SUMMARY, by: "ops-jae", now: at(5) });
    assert.equal(st.plans.get(H)!.proposedBy, "ops-henry");
    const e = refusal(() => approve(st, { hash: H, by: "ops-henry", now: at(6) }));
    assert.equal(e.status, 403);
  });

  it("bounds how many plans can be held at once", () => {
    const st = emptyApprovals();
    const limits = { ttlSec: 600, maxPending: 2 };
    for (const c of ["a", "b"]) {
      propose(st, { hash: `sha256:${c.repeat(64)}`, generation: "g", summary: SUMMARY, by: "ops-henry", now: T0 }, limits);
    }
    const e = refusal(() =>
      propose(st, { hash: `sha256:${"c".repeat(64)}`, generation: "g", summary: SUMMARY, by: "ops-henry", now: T0 }, limits),
    );
    assert.equal(e.status, 429);
  });
});

describe("approving", () => {
  it("refuses the proposer", () => {
    // The whole point of the mechanism.
    const st = pending();
    const e = refusal(() => approve(st, { hash: H, by: "ops-henry", now: at(10) }));
    assert.equal(e.status, 403);
    assert.match(e.message, /cannot approve/);
    assert.equal(st.plans.get(H)!.approval, null);
  });

  it("accepts a second operator and records who", () => {
    const st = pending();
    const p = approve(st, { hash: H, by: "ops-jae", now: at(10) });
    assert.equal(p.approval?.by, "ops-jae");
    assert.equal(p.approval?.at, at(10).toISOString());
  });

  it("is idempotent for the same approver and refuses a different one", () => {
    const st = pending();
    approve(st, { hash: H, by: "ops-jae", now: at(10) });
    approve(st, { hash: H, by: "ops-jae", now: at(11) });
    assert.equal(st.plans.get(H)!.approval?.at, at(10).toISOString(), "the first approval was overwritten");
    const e = refusal(() => approve(st, { hash: H, by: "ops-min", now: at(12) }));
    assert.equal(e.status, 409);
  });

  it("refuses an unknown hash", () => {
    const st = pending();
    const e = refusal(() => approve(st, { hash: H2, by: "ops-jae", now: at(10) }));
    assert.equal(e.status, 404);
  });
});

describe("publishing", () => {
  it("refuses a plan nobody approved", () => {
    const st = pending();
    const e = refusal(() => claimForPublish(st, { hash: H, by: "ops-henry", now: at(10) }));
    assert.equal(e.status, 403);
  });

  it("lets an approved plan through once and refuses the second attempt", () => {
    const st = pending();
    approve(st, { hash: H, by: "ops-jae", now: at(10) });
    const p = claimForPublish(st, { hash: H, by: "ops-henry", now: at(20) });
    assert.equal(p.approval?.by, "ops-jae");
    const e = refusal(() => claimForPublish(st, { hash: H, by: "ops-henry", now: at(30) }));
    assert.equal(e.status, 409);
  });

  it("does not require the publisher to be either the proposer or the approver", () => {
    // Deliberate. The check is that two people signed off, not that a particular one runs the push —
    // and requiring one of them to be present would make the fleet unpublishable when they are not.
    const st = pending();
    approve(st, { hash: H, by: "ops-jae", now: at(10) });
    assert.ok(claimForPublish(st, { hash: H, by: "ops-min", now: at(20) }));
  });

  it("refuses an approved plan that has expired, and says so distinctly", () => {
    // "It expired" and "it never existed" send an operator to different places.
    const st = pending();
    approve(st, { hash: H, by: "ops-jae", now: at(10) });
    const e = refusal(() => claimForPublish(st, { hash: H, by: "ops-henry", now: at(601) }));
    assert.equal(e.status, 410);
    assert.match(e.message, /expired/);
  });

  it("expires from the proposal, not from the approval", () => {
    // The risk being bounded is the policy tree moving under a rendering, and that clock starts when
    // the rendering happened. Approving late must not extend the window.
    const st = pending();
    approve(st, { hash: H, by: "ops-jae", now: at(590) });
    const e = refusal(() => claimForPublish(st, { hash: H, by: "ops-henry", now: at(605) }));
    assert.equal(e.status, 410);
  });

  it("releases a claim so a publish that reached nothing can be retried", () => {
    const st = pending();
    approve(st, { hash: H, by: "ops-jae", now: at(10) });
    claimForPublish(st, { hash: H, by: "ops-henry", now: at(20) });
    release(st, H);
    assert.ok(claimForPublish(st, { hash: H, by: "ops-henry", now: at(25) }));
  });
});

describe("expiry", () => {
  it("sweeps expired and published plans", () => {
    const st = pending();
    sweep(st, at(601));
    assert.equal(st.plans.size, 0);
  });

  it("keeps a plan that is still inside its window", () => {
    const st = pending();
    sweep(st, at(599));
    assert.equal(st.plans.size, 1);
  });

  it("lists newest first", () => {
    const st = pending();
    propose(st, { hash: H2, generation: "def", summary: SUMMARY, by: "ops-henry", now: at(5) });
    assert.deepEqual(listPlans(st, at(10)).map((p) => p.hash), [H2, H]);
  });
});

describe("solo approval — the two-person rule, switched off on purpose", () => {
  // `approve` refuses `proposedBy === by` and that refusal is the reason this module exists. One
  // site with one operator decided the alternative — nothing publishable through the API — was
  // worse. What must survive the exception is the audit trail's ability to tell the two apart.
  const now = new Date("2026-08-06T00:00:00Z");
  const summary = { generation: "g1", hosts: [] };
  const A = "sha256:" + "a".repeat(64);

  it("still refuses self-approval by default — every existing caller keeps that", () => {
    const st = emptyApprovals();
    propose(st, { hash: A, generation: "g1", by: "ops-henry", now, summary });
    assert.throws(() => approve(st, { hash: A, by: "ops-henry", now }), /cannot approve it/);
  });

  it("allows it when the caller says the approver may, and marks the record", () => {
    const st = emptyApprovals();
    propose(st, { hash: A, generation: "g1", by: "ops-henry", now, summary });
    const plan = approve(st, { hash: A, by: "ops-henry", now, mayApproveOwn: true });
    assert.equal(plan.approval?.by, "ops-henry");
    assert.equal(plan.approval?.solo, true, "an audit must be able to see that one person did this alone");
  });

  it("leaves an ordinary approval unmarked even when the permission is held", () => {
    // `solo` absent rather than false: the record should show the rare event, not deny it on every
    // normal plan. And the mark follows what happened, not what was permitted.
    const st = emptyApprovals();
    propose(st, { hash: A, generation: "g1", by: "ops-a", now, summary });
    const plan = approve(st, { hash: A, by: "ops-b", now, mayApproveOwn: true });
    assert.equal(plan.approval?.solo, undefined);
  });
});
