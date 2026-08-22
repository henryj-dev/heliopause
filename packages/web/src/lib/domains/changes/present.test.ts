import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { clockLabel, expireTone, hostRuleTotal, planDomId, planPath, remainingSec, shortPlanHash } from "./present.ts";
import type { PlanRow } from "./plans.ts";

const plan = (over: Partial<PlanRow> = {}): PlanRow => ({
  hash: "sha256:" + "ab".repeat(32),
  generation: "4a91c7f",
  proposedBy: "ops-alice",
  proposedAt: "2026-08-18T00:00:00.000Z",
  summary: {
    hosts: [
      { host: "gw-01.dev", stage: "canary", ruleCount: 148, rulesetHash: "a" },
      { host: "edge-07.dev", stage: "rest", ruleCount: 139, rulesetHash: "b" },
    ],
  },
  approval: null,
  publishedAt: null,
  target: "dev",
  ...over,
});

describe("planPath", () => {
  it("puts the hash in the path, encoded, so a link is a place", () => {
    assert.equal(planPath("sha256:ab"), "/changes/sha256%3Aab");
    assert.equal(planDomId("sha256:ab"), "plan-sha256ab");
  });
});

describe("shortPlanHash", () => {
  it("keeps the prefix and the tail the 시안 shows", () => {
    assert.equal(shortPlanHash("sha256:" + "9f31c0a4" + "0".repeat(52) + "7be2"), "sha256:9f31c0a4…7be2");
    assert.equal(shortPlanHash("abc"), "abc");
  });
});

describe("hostRuleTotal", () => {
  it("sums the rules the summary already counted per host", () => {
    assert.equal(hostRuleTotal(plan()), 287);
  });
});

describe("remainingSec", () => {
  it("counts down from proposedAt, not from the approval", () => {
    const start = Date.parse("2026-08-18T00:00:00.000Z");
    assert.equal(remainingSec("2026-08-18T00:00:00.000Z", 600, start), 600);
    assert.equal(remainingSec("2026-08-18T00:00:00.000Z", 600, start + 553_000), 47);
    assert.equal(remainingSec("2026-08-18T00:00:00.000Z", 600, start + 700_000), 0);
  });

  it("treats a broken timestamp as already gone rather than as infinite", () => {
    assert.equal(remainingSec("not-a-date", 600, Date.now()), 0);
  });
});

describe("expireTone", () => {
  it("turns red in the last minute, and warns in the last five", () => {
    assert.equal(expireTone(400), "ok");
    assert.equal(expireTone(300), "warn");
    assert.equal(expireTone(61), "warn");
    assert.equal(expireTone(60), "bad");
    assert.equal(expireTone(0), "bad");
  });

  it("pads the 시안 clock", () => {
    assert.equal(clockLabel(47), "00:47");
    assert.equal(clockLabel(252), "04:12");
  });
});
