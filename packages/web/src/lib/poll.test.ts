import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { applyHeldPoll, type Held } from "./poll.ts";

const held = (over: Partial<Held<string>> = {}): Held<string> => ({
  value: "site",
  lastOkAt: 1_000,
  failCount: 0,
  lastFail: null,
  ...over,
});

describe("applyHeldPoll", () => {
  it("keeps the last view when a later poll fails, and counts the misses", () => {
    const first = applyHeldPoll(null, { kind: "ok", value: "site", at: 1_000 });
    const next = applyHeldPoll(first, { kind: "fail", reason: "fetch failed" });
    assert.equal(next?.value, "site");
    assert.equal(next?.lastOkAt, 1_000);
    assert.equal(next?.failCount, 1);
    assert.equal(next?.lastFail, "fetch failed");
    assert.equal(applyHeldPoll(next, { kind: "fail", reason: "timeout" })?.failCount, 2);
  });

  it("does not invent a view when the first poll fails", () => {
    assert.equal(applyHeldPoll(null, { kind: "fail", reason: "offline" }), null);
  });

  it("drops the view when the session ended", () => {
    assert.equal(applyHeldPoll(held(), { kind: "unauth" }), null);
  });

  it("clears the miss count when a later poll succeeds", () => {
    const stale = applyHeldPoll(held({ failCount: 9, lastFail: "x" }), {
      kind: "ok",
      value: "next",
      at: 9_000,
    });
    assert.equal(stale?.failCount, 0);
    assert.equal(stale?.lastFail, null);
    assert.equal(stale?.lastOkAt, 9_000);
    assert.equal(stale?.value, "next");
  });
});
