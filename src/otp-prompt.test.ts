// Getting the one-time code out of the operator and into the request.
//
// The case that carries this file is the **order of precedence**, because getting it wrong is
// invisible: a stale `HELIOPAUSE_OTP` in the environment silently beating the code the operator just
// typed would send the wrong six digits, and the manager's answer — "that code is not valid" — points
// at the phone rather than at the shell.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { NoPromptError, otpFor, readSecret } from "./otp-prompt.ts";

/** A stand-in terminal. `send` delivers what the operator types, one chunk at a time. */
function fakeTty() {
  const stdin = new EventEmitter() as EventEmitter & {
    isTTY: boolean;
    setRawMode: (v: boolean) => void;
    resume: () => void;
    pause: () => void;
    setEncoding: (e: string) => void;
    raw: boolean[];
  };
  stdin.isTTY = true;
  stdin.raw = [];
  stdin.setRawMode = (v: boolean) => void stdin.raw.push(v);
  stdin.resume = () => {};
  stdin.pause = () => {};
  stdin.setEncoding = () => {};
  const written: string[] = [];
  const stderr = { write: (s: string) => void written.push(s) };
  return { stdin, stderr, written, send: (s: string) => stdin.emit("data", s) };
}

const read = (t: ReturnType<typeof fakeTty>) =>
  readSecret("code: ", t.stdin as never, t.stderr as never);

// Every test here has a timeout, and that is load-bearing rather than tidy. These assertions await a
// promise that a broken `readSecret` simply never settles — remove the Ctrl-C branch and the suite
// stops instead of failing. A suite that hangs is worse than one that fails: `node --test` waits
// forever, CI burns its whole budget, and the defect-injection sweep that would have caught the bug
// is the thing that stalls. Measured 2026-08-06, and the same shape as f5fe429.
describe("reading a code from the terminal", { timeout: 5_000 }, () => {
  it("returns what was typed — the known positive", async () => {
    const t = fakeTty();
    const p = read(t);
    t.send("123456\r");
    assert.equal(await p, "123456");
  });

  it("never writes the code to the terminal", async () => {
    // The whole reason this is not `readline` with echo. If the digits appear here they appear on a
    // shared screen, and in a recorded session.
    const t = fakeTty();
    const p = read(t);
    t.send("123456\r");
    await p;
    assert.ok(!t.written.join("").includes("123456"), `echoed: ${JSON.stringify(t.written)}`);
  });

  it("accepts a paste, which arrives as one chunk", async () => {
    const t = fakeTty();
    const p = read(t);
    t.send("654321\r");
    assert.equal(await p, "654321");
  });

  it("handles backspace, because there is nothing to look at", async () => {
    // With no echo the operator cannot see what they typed, so an unfixable typo would mean starting
    // the whole command again — and burning a code.
    const t = fakeTty();
    const p = read(t);
    t.send("1234x56\r");
    assert.equal(await p, "123456");
  });

  it("drops control sequences rather than storing them", async () => {
    // An arrow key is three bytes. Stored, they become three characters of a code that then fails to
    // verify, and the failure reads as "the IdP rejected my code".
    const t = fakeTty();
    const p = read(t);
    t.send("12\u001b[A34\r");
    assert.equal(await p, "1234");
  });

  it("drops a stray control character instead of typing it", async () => {
    // Not the same case as an arrow key: this is one byte with no sequence around it — a Tab, a
    // fat-fingered Ctrl-A. Stored, it becomes a seventh character in a six-digit code, and the
    // manager answers "that code is not valid" for a code the operator read correctly.
    const t = fakeTty();
    const p = read(t);
    t.send("123\u00014\t56\r");
    assert.equal(await p, "123456");
  });

  it("rejects on Ctrl-C instead of leaving the terminal in raw mode", async () => {
    const t = fakeTty();
    const p = read(t);
    t.send("12");
    await assert.rejects(() => p, /cancelled/);
    assert.deepEqual(t.stdin.raw, [true, false], "raw mode must be turned back off");
  });

  it("restores the terminal after a normal read too", async () => {
    const t = fakeTty();
    const p = read(t);
    t.send("111111\r");
    await p;
    assert.deepEqual(t.stdin.raw, [true, false]);
  });

  it("refuses when there is no terminal to ask", async () => {
    const t = fakeTty();
    t.stdin.isTTY = false;
    await assert.rejects(() => read(t), NoPromptError);
  });
});

describe("where the code comes from", { timeout: 5_000 }, () => {
  it("prefers the flag over the environment", async () => {
    // A leftover `HELIOPAUSE_OTP` beating an explicit flag would send digits the operator did not
    // choose, and the manager's refusal would point at the phone rather than at the shell.
    assert.equal(await otpFor("x", "111111", { HELIOPAUSE_OTP: "222222" }), "111111");
  });

  it("falls back to the environment, for scripts", async () => {
    assert.equal(await otpFor("x", undefined, { HELIOPAUSE_OTP: "222222" }), "222222");
  });

  it("strips whitespace, because phones show the code in two groups", async () => {
    assert.equal(await otpFor("x", "123 456", {}), "123456");
  });

  it("refuses rather than hanging when there is nothing to ask and nothing given", async () => {
    // Only meaningful when the suite itself has no TTY, which is how CI runs it. Guarded so a
    // developer running this from a terminal does not get a prompt in the middle of the suite.
    if (process.stdin.isTTY) return;
    await assert.rejects(() => otpFor("approving", undefined, {}), NoPromptError);
  });
});
