// The lifecycle's ordering rules, driven with a thread whose events the test controls.
//
// A real worker produces the order that broke this — `exit` delivered while the reply is still on the
// port — about 1 time in 2,000 (measured). A test that waits for it is a test that passes on a re-run.
// So the thread here is a fake that answers on the port it is handed and then emits whatever the test
// says, **in the same synchronous turn**: the reply is queued on the port and its `message` event has
// not been delivered when `exit` fires. That is the order, produced every time.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import type { MessagePort } from "node:worker_threads";
import { evaluateWithLifecycle, type EvalThread, type EvalLifecycleOptions } from "./policy-eval-lifecycle.ts";

/**
 * A thread that replies on the handed-over port, then does `after` — all before returning.
 *
 * `terminate()` behaves like a real worker's: once, it ends the thread with `exit 1` on a later turn
 * (measured: a terminated worker exits 1). The first version of this fake resolved `terminate()` and
 * never emitted `exit`, which was harmless while the count dropped on our own decision — and which
 * would have hidden a count that only drops on `exit`. `t` is returned so a test can drive the thread
 * after the answer.
 */
function fakeThread(
  reply: unknown,
  after: (t: EventEmitter) => void = () => undefined,
): { thread: EvalThread; t: EventEmitter; terminated: () => number } {
  const t = new EventEmitter();
  let terminated = 0;
  let exited = false;
  t.on("exit", () => { exited = true; });
  const thread: EvalThread = {
    postMessage(value) {
      const port = (value as { reply: MessagePort }).reply;
      if (reply !== undefined) port.postMessage(reply);
      after(t);
    },
    on(event: string, listener: (...a: never[]) => void) {
      t.on(event, listener as (...a: unknown[]) => void);
      return thread;
    },
    terminate() {
      terminated += 1;
      if (!exited) setImmediate(() => { if (!exited) t.emit("exit", 1); });
      return Promise.resolve(1);
    },
  } as EvalThread;
  return { thread, t, terminated: () => terminated };
}

/** Lets the fake's `terminate()` → `exit` turn run. */
const turn = () => new Promise((r) => setImmediate(r));

function options(thread: EvalThread, over: Partial<EvalLifecycleOptions> = {}) {
  const logs: string[] = [];
  const late: unknown[] = [];
  let alive = 0;
  const opts: EvalLifecycleOptions = {
    spawn: () => thread,
    budgetMs: 5_000,
    graceMs: 0,
    sitePath: "/policy/beta.ts",
    label: "beta",
    onLateFault: (thrown) => late.push(thrown),
    log: (line) => logs.push(line),
    onAlive: (d) => { alive += d; },
    reasonOf: (thrown) => String((thrown as Error)?.message ?? thrown),
    ...over,
  };
  return { opts, logs, late, alive: () => alive };
}

describe("an evaluation settles once, on the right signal", () => {
  it("reads a reply still queued when the thread's exit arrives first", async () => {
    // The intermittent full-suite failure, produced on demand: the module's own failure text was on
    // the port, `exit 0` arrived first, and the parent reported "exited without producing a result".
    const { thread } = fakeThread({ ok: false, message: "the module's own reason" }, (t) => t.emit("exit", 0));
    const { opts } = options(thread);
    await assert.rejects(evaluateWithLifecycle(opts), /the module's own reason/);
  });

  it("reads a successful reply still queued when the thread's exit arrives first", async () => {
    const { thread } = fakeThread({ ok: true, wire: '{"site":{}}' }, (t) => t.emit("exit", 0));
    const { opts, late } = options(thread);
    assert.equal(await evaluateWithLifecycle(opts), '{"site":{}}');
    assert.deepEqual(late, [], "a clean exit after an answer was counted as a fault");
  });

  it("reads a reply still queued when the thread's error arrives first", async () => {
    // Same rule on the other lifecycle event: the answer was given, so the error is a late fault and
    // the answer stands.
    const { thread } = fakeThread({ ok: true, wire: '{"site":{}}' }, (t) => t.emit("error", new Error("late")));
    const { opts, late } = options(thread);
    assert.equal(await evaluateWithLifecycle(opts), '{"site":{}}');
    assert.equal(late.length, 1, "the error after the answer was not counted");
  });

  it("still reports an exit that produced nothing", async () => {
    // The known negative for the three above: with nothing queued, decision 8 still applies. Without
    // this, a lifecycle that never settled on `exit` at all would pass them.
    const { thread } = fakeThread(undefined, (t) => t.emit("exit", 0));
    const { opts } = options(thread);
    await assert.rejects(evaluateWithLifecycle(opts), /exited \(0\) without producing a result/);
  });

  it("names exit 13 as a top-level await that never settled", async () => {
    const { thread } = fakeThread(undefined, (t) => t.emit("exit", 13));
    const { opts } = options(thread);
    await assert.rejects(evaluateWithLifecycle(opts), /never settled \(exit 13\)/);
  });

  it("keeps the first answer and logs the second", async () => {
    const t = new EventEmitter();
    const thread = {
      postMessage(value: unknown) {
        const port = (value as { reply: MessagePort }).reply;
        port.postMessage({ ok: true, wire: "first" });
        port.postMessage({ ok: true, wire: "second" });
        t.emit("exit", 0);
      },
      on(e: string, l: (...a: never[]) => void) { t.on(e, l as (...a: unknown[]) => void); return thread; },
      terminate: () => Promise.resolve(1),
    } as unknown as EvalThread;
    const { opts, logs } = options(thread);
    assert.equal(await evaluateWithLifecycle(opts), "first");
    assert.ok(logs.some((l) => /ignoring a second message/.test(l)), "the second answer was not logged");
  });

  it("counts an error and the exit that follows it once", async () => {
    // A real worker's uncaught exception is `error` followed by `exit 1` — the fake's first version
    // emitted one or the other, which is how double counting got past it. Measured through the real
    // renderer: one late throw was `faults: 1` on `da80b7b` and `faults: 2` before this fix. Grace is
    // long so the thread is still ours when both events arrive.
    const { thread, t } = fakeThread({ ok: true, wire: "x" });
    const { opts, late } = options(thread, { graceMs: 60_000 });
    assert.equal(await evaluateWithLifecycle(opts), "x");
    t.emit("error", new Error("late"));
    t.emit("exit", 1);
    assert.equal(late.length, 1, "one late throw was counted more than once");
    // The known positive: an abnormal exit with no error before it is still a fault.
    const second = fakeThread({ ok: true, wire: "x" });
    const o2 = options(second.thread, { graceMs: 60_000 });
    assert.equal(await evaluateWithLifecycle(o2.opts), "x");
    second.t.emit("exit", 2);
    assert.equal(o2.late.length, 1, "an abnormal exit after the answer was not counted at all");
  });

  it("counts the module's own exit even when our terminate is in flight", async () => {
    // Round three's race. Our grace-end `terminate()` is called, and before it lands the module ends
    // the thread itself with `process.exit(2)`. `terminatedByUs` alone said "we asked", so this was
    // dropped — measured, 49 of 300 real-worker races. A terminated worker exits **1**; any other
    // non-zero code after our call is the module's own (measured: racing the two over a 0–10 ms gap
    // gave exit 1 when ours won and exit 2 when theirs did, and `terminate()` resolved to the same
    // code either way, so the promise cannot tell them apart).
    const t = new EventEmitter();
    let port: MessagePort | undefined;
    const thread = {
      postMessage(value: unknown) {
        port = (value as { reply: MessagePort }).reply;
        port.postMessage({ ok: true, wire: "x" });
      },
      on(e: string, l: (...a: never[]) => void) { t.on(e, l as (...a: unknown[]) => void); return thread; },
      // The module's own exit wins the race our terminate starts.
      terminate() { t.emit("exit", 2); return Promise.resolve(2); },
    } as unknown as EvalThread;
    const { opts, late } = options(thread, { graceMs: 1 });
    assert.equal(await evaluateWithLifecycle(opts), "x");
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(late.length, 1, "the module's own exit 2 was taken for our termination");
    // And the known negative: our own termination (exit 1) is still not a fault.
    const ours = fakeThread({ ok: true, wire: "x" });
    const o2 = options(ours.thread, { graceMs: 1 });
    assert.equal(await evaluateWithLifecycle(o2.opts), "x");
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(ours.terminated(), 1);
    assert.equal(o2.late.length, 0, "our own terminate was counted as the module's fault");
  });

  it("stops counting a thread the moment it exits", async () => {
    // `workers` on /readyz is this count, and #117's cap is to be chosen from its observed maximum. A
    // thread that answered and then finished on its own was still counted until its grace expired —
    // measured: `workers: 1` 400 ms after a clean exit, inside a 1 s grace. Grace is long here so the
    // only thing that can bring the count to zero is the exit itself.
    const { thread, t } = fakeThread({ ok: true, wire: "x" });
    const { opts, alive } = options(thread, { graceMs: 60_000 });
    assert.equal(await evaluateWithLifecycle(opts), "x");
    assert.equal(alive(), 1, "the thread should still be counted while it is alive inside its grace");
    t.emit("exit", 0);
    assert.equal(alive(), 0, "a thread that exited is still counted");
  });

  it("keeps counting a thread we have decided to terminate until it exits", async () => {
    // The opposite mistake from the test above, and round three found it: the count dropped when we
    // *decided* to reclaim — before `terminate()` was even called — so a thread still running was
    // already uncounted. Here `terminate()` does not end the thread; only a later `exit` does.
    const t = new EventEmitter();
    let terminateCalls = 0;
    const thread = {
      postMessage(value: unknown) { (value as { reply: MessagePort }).reply.postMessage({ ok: false, message: "m" }); },
      on(e: string, l: (...a: never[]) => void) { t.on(e, l as (...a: unknown[]) => void); return thread; },
      terminate() { terminateCalls += 1; return new Promise<number>(() => undefined); },
    } as unknown as EvalThread;
    const { opts, alive } = options(thread);
    await assert.rejects(evaluateWithLifecycle(opts), /m/);
    assert.equal(terminateCalls, 1, "a failed evaluation was not reclaimed");
    assert.equal(alive(), 1, "a thread still running after terminate() was already uncounted");
    t.emit("exit", 1);
    assert.equal(alive(), 0, "the thread's exit did not bring the count down");
  });

  it("balances the thread count on every ending", async () => {
    // `workers` on /readyz is this count, and #117's cap is to be chosen from its observed maximum, so
    // a path that forgets to decrement makes the number a slow leak of its own.
    //
    // `terminate()` is owed only to a thread that has not already ended: never more than once, and
    // exactly once when the thread is still running at the decision. The two "then exit" rows are 1
    // because the `exit` is delivered while the reply is still queued, so `drain()` settles first and
    // reclaims a thread that, at that moment, has not exited.
    //
    // The fake's `terminate()` ends the thread with `exit 1` a turn later, as a real worker does, so the
    // count can only reach zero through an `exit` — which is the property.
    const endings: [string, unknown, (t: EventEmitter) => void, number][] = [
      ["answer then exit", { ok: true, wire: "x" }, (t) => t.emit("exit", 0), 1],
      ["failure then exit", { ok: false, message: "m" }, (t) => t.emit("exit", 0), 1],
      ["exit alone", undefined, (t) => t.emit("exit", 0), 0],
      ["exit 13", undefined, (t) => t.emit("exit", 13), 0],
      ["error alone", undefined, (t) => t.emit("error", new Error("e")), 1],
      ["answer, still running", { ok: true, wire: "x" }, () => undefined, 1],
    ];
    for (const [name, reply, after, wantTerminate] of endings) {
      const { thread, terminated } = fakeThread(reply, after);
      const { opts, alive } = options(thread);
      await evaluateWithLifecycle(opts).catch(() => undefined);
      await turn();
      assert.equal(alive(), 0, `${name}: the thread count did not return to zero`);
      assert.equal(terminated(), wantTerminate, `${name}: terminate() was called ${terminated()} times`);
    }
  });
});
