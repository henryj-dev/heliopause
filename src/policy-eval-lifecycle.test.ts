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

/** A thread that replies on the handed-over port, then does `after` — all before returning. */
function fakeThread(
  reply: unknown,
  after: (t: EventEmitter) => void,
): { thread: EvalThread; terminated: () => number } {
  const t = new EventEmitter();
  let terminated = 0;
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
      return Promise.resolve(1);
    },
  } as EvalThread;
  return { thread, terminated: () => terminated };
}

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

  it("balances the thread count on every ending", async () => {
    // `workers` on /readyz is this count, and #117's cap is to be chosen from its observed maximum, so
    // a path that forgets to decrement makes the number a slow leak of its own.
    const endings: [string, unknown, (t: EventEmitter) => void][] = [
      ["answer then exit", { ok: true, wire: "x" }, (t) => t.emit("exit", 0)],
      ["failure then exit", { ok: false, message: "m" }, (t) => t.emit("exit", 0)],
      ["exit alone", undefined, (t) => t.emit("exit", 0)],
      ["exit 13", undefined, (t) => t.emit("exit", 13)],
      ["error alone", undefined, (t) => t.emit("error", new Error("e"))],
    ];
    for (const [name, reply, after] of endings) {
      const { thread, terminated } = fakeThread(reply, after);
      const { opts, alive } = options(thread);
      await evaluateWithLifecycle(opts).catch(() => undefined);
      assert.equal(alive(), 0, `${name}: the thread count did not return to zero`);
      assert.equal(terminated(), 1, `${name}: the thread was not reclaimed exactly once`);
    }
  });
});
