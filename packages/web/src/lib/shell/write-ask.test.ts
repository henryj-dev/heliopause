import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { finishWrite, readOtpInput, readReason, writeIsReady, writeNeedsDialog } from "./write-ask.ts";

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(path));
    else if (entry.name.endsWith(".svelte") || entry.name.endsWith(".ts")) out.push(path);
  }
  return out;
}

describe("readOtpInput", () => {
  it("trims a typed code and treats blank as cancel", () => {
    assert.equal(readOtpInput("123456"), "123456");
    assert.equal(readOtpInput(" 123456 "), "123456");
    assert.equal(readOtpInput(""), null);
    assert.equal(readOtpInput("   "), null);
  });
});

describe("readReason", () => {
  it("trims and refuses a blank reason", () => {
    assert.equal(readReason(" retired "), "retired");
    assert.equal(readReason(""), null);
  });
});

describe("writeNeedsDialog", () => {
  it("skips the window when there is nothing to ask", () => {
    assert.equal(writeNeedsDialog({ needsOtp: false }), false);
    assert.equal(writeNeedsDialog({ needsOtp: true }), true);
    assert.equal(writeNeedsDialog({ needsOtp: false, reason: true }), true);
    assert.equal(writeNeedsDialog({ needsOtp: false, warning: "this changes the fleet" }), true);
    assert.equal(writeNeedsDialog({ needsOtp: false, warning: "" }), false);
  });
});

describe("finishWrite", () => {
  it("requires the fields this write asked for, and only those", () => {
    assert.equal(writeIsReady({ reason: "", otp: "" }, { needsOtp: false }), true);
    assert.equal(finishWrite({ reason: "", otp: " 123456 " }, { needsOtp: true })?.otp, "123456");
    assert.equal(finishWrite({ reason: "retired", otp: "" }, { reason: true, needsOtp: false })?.reason, "retired");
    assert.equal(finishWrite({ reason: "", otp: "123456" }, { reason: true, needsOtp: true }), null);
    assert.equal(finishWrite({ reason: "retired", otp: "" }, { reason: true, needsOtp: true }), null);
  });
});

describe("the screens do not call the browser prompt", () => {
  it("keeps prompt and confirm out of the Svelte console", () => {
    const root = fileURLToPath(new URL("../domains", import.meta.url));
    for (const file of walk(root)) {
      const text = readFileSync(file, "utf8");
      assert.doesNotMatch(text, /\bprompt\s*\(/, file);
      assert.doesNotMatch(text, /\bconfirm\s*\(/, file);
    }
  });
});
