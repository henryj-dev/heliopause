import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ageLabel } from "./age.ts";

describe("ageLabel", () => {
  it("writes the 시안 A4 forms, not a raw millisecond count", () => {
    assert.equal(ageLabel(0), "0s");
    assert.equal(ageLabel(4), "4s");
    assert.equal(ageLabel(134), "2m 14s");
    assert.equal(ageLabel(120), "2m");
    assert.equal(ageLabel(3780), "1h 3m");
    assert.equal(ageLabel(3600), "1h");
  });
});
