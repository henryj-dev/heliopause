// # One evaluation's lifecycle, with the thread passed in
//
// `bin/heliopause-policy-render.ts` starts a worker per policy evaluation (`src/policy-eval-worker.ts`).
// This file is what decides, on the parent's side, which signal from that worker is the result, what
// happens when more than one arrives, and when the thread is reclaimed — design §3-a's decisions 6, 7
// and 8, and the three endings of the grace window.
//
// ## Why it is a separate module that takes the thread as an argument
//
// One of its rules is about **ordering between two event sources Node does not order**: the reply
// port and the worker's own `exit`/`error`. The wrong order happened 1 time in 2,000 in a real
// worker (measured), which is a test that passes on a re-run and fails in CI on Tuesday. A test that
// pins the rule has to *produce* that order on demand, and from a real worker it cannot. Taking the
// thread as an argument lets a test hand in one that emits `exit` while the reply is still queued.
//
// @see src/policy-eval-lifecycle.test.ts

import { MessageChannel, receiveMessageOnPort, type MessagePort } from "node:worker_threads";

/** The part of `Worker` this lifecycle uses. A real `Worker` satisfies it. */
export interface EvalThread {
  postMessage(value: unknown, transferList: readonly MessagePort[]): void;
  on(event: "error", listener: (thrown: unknown) => void): unknown;
  on(event: "exit", listener: (code: number) => void): unknown;
  terminate(): Promise<number>;
}

export interface EvalLifecycleOptions {
  /** Starts the thread. Called once, before anything is posted to it. */
  spawn(): EvalThread;
  /** How long the site gets before the thread is terminated and the evaluation refused. */
  budgetMs: number;
  /** How long a thread is kept after a valid answer, so a late fault is still seen. */
  graceMs: number;
  /** What the refusals and log lines call this evaluation — the module's path, the site's label. */
  sitePath: string;
  label: string;
  /** A fault that arrived after the answer: counted, logged, and the answer stands. */
  onLateFault(thrown: unknown): void;
  log(line: string): void;
  /** Called when a thread starts and when one is reclaimed, so the caller can count them. */
  onAlive(delta: 1 | -1): void;
  /** Turns a thrown value into readable text without trusting it. */
  reasonOf(thrown: unknown): string;
}

/**
 * Evaluate once and settle exactly once: with the worker's `wire` on a valid answer, or with an
 * `Error` naming the reason otherwise.
 *
 * The rules this file holds, each with the test that pins it:
 *
 *   · only the dedicated port carries a result — `src/policy-render-service.test.ts` "does not accept
 *     a result from a module that posts on parentPort";
 *   · the first valid reply wins — "keeps the first answer and logs the second";
 *   · a reply already queued is read before an `exit` or `error` may settle anything — "reads a reply
 *     still queued when the thread's exit arrives first", and the `error` variant;
 *   · one late fault is one count — "counts an error and the exit that follows it once";
 *   · the thread count drops when the thread is gone — "stops counting a thread the moment it exits";
 *   · our own `terminate()` is not a fault — `src/policy-render-service.test.ts` "does not count its
 *     own reclaim of a worker as a fault".
 *
 * Unprefixed names are in `src/policy-eval-lifecycle.test.ts`.
 */
export function evaluateWithLifecycle(opts: EvalLifecycleOptions): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const { port1, port2 } = new MessageChannel();
    const thread = opts.spawn();
    opts.onAlive(1);

    let settled = false;
    let reclaimed = false;
    let terminatedByUs = false;
    let lateErrorCounted = false;

    // ## The count goes down once, when the thread is actually gone
    //
    // `onAlive(-1)` used to run only when *we* reclaimed, so a worker that answered and then finished
    // on its own — `exit 0` a few ms later — was still counted for the rest of its grace window
    // (measured: `workers: 1` 400 ms after a clean exit, `0` only after the 1 s grace). `/readyz`
    // reports this count and #117's cap is to be chosen from its observed maximum, so it has to mean
    // "threads alive now". Whichever comes first, our `terminate()` or the thread's own `exit`, ends it.
    // @see src/policy-eval-lifecycle.test.ts "stops counting a thread the moment it exits"
    let gone = false;
    let graceTimer: ReturnType<typeof setTimeout> | undefined;
    const leave = () => {
      if (gone) return;
      gone = true;
      if (graceTimer !== undefined) clearTimeout(graceTimer);
      // The port is ours to close whichever way the thread ended. An open `port1` keeps the event loop
      // alive — measured: the first version of this closed it only on our own reclaim, and a test whose
      // thread exited first left the runner hanging.
      port1.close();
      opts.onAlive(-1);
    };

    // ## Reclaiming, and the three endings that decide when
    //
    // "No grace on failure" is two different reasons, and writing it as one sentence loses one of
    // them:
    //
    //   · a valid result → grace, because that is the only ending with something left to see;
    //   · `error` or an abnormal `exit` → no grace, because the ending already happened and waiting
    //     longer counts nothing;
    //   · the budget expiring → no grace, and for the opposite reason: the time was already spent,
    //     so adding grace spends it twice.
    const reclaim = (graceMs: number) => {
      if (reclaimed) return;
      reclaimed = true;
      const done = () => {
        // A thread that already exited has nothing to terminate.
        if (gone) return;
        // Ours, so its exit is not a fault. `terminate()` makes a worker exit **1** — measured: a worker
        // that answered and was terminated reports 1, one left to finish reports 0 — and without this
        // flag every module that keeps a handle open past its grace would raise `faults` once per
        // evaluation. Set before `leave()`, whose own work does not depend on it but whose caller's does.
        terminatedByUs = true;
        leave();
        void thread.terminate();
      };
      if (graceMs <= 0) {
        done();
        return;
      }
      graceTimer = setTimeout(done, graceMs);
      // The process must be able to exit during a grace window.
      graceTimer.unref();
    };

    // ## The only result path
    //
    // The worker's own message channel (`parentPort` on the far side) is not listened to: design §3-b
    // ① measured a module importing `node:worker_threads` and answering on it *first*.
    const onReply = (reply: unknown) => {
      if (settled) {
        // The decision is "the first valid result wins", and a module that keeps posting does not get
        // to revise it.
        opts.log(`${opts.label}: ignoring a second message from an evaluation that already answered`);
        return;
      }
      // Decision 6: a dedicated channel, a schema, and bytes. The type of `wire` is the whole check
      // here; its content is checked by the caller.
      if (typeof reply === "object" && reply !== null && (reply as { ok?: unknown }).ok === true) {
        const wire = (reply as { wire?: unknown }).wire;
        if (typeof wire === "string") {
          settled = true;
          resolve(wire);
          reclaim(opts.graceMs);
          return;
        }
      }
      if (typeof reply === "object" && reply !== null && (reply as { ok?: unknown }).ok === false) {
        const message = (reply as { message?: unknown }).message;
        settled = true;
        // Prefixed, because the text came from the module: a bare line can be written to read like the
        // renderer's own.
        reject(new Error(`${opts.sitePath}: ${typeof message === "string" ? message : "evaluation failed"}`));
        reclaim(0);
        return;
      }
      // Neither shape. Not a result, so it does not settle anything.
      opts.log(`${opts.label}: discarding a message on the result channel that is not a result`);
    };
    port1.on("message", onReply);

    // ## A reply can still be queued when the thread's `exit` or `error` arrives
    //
    // The port and the thread's lifecycle are two event sources, and Node does not order them. A worker
    // that posts its reply and then ends usually has the message delivered first, but not always:
    // measured, **1 in 2,000** runs saw `exit` while the reply was still on `port1`, and
    // `receiveMessageOnPort` inside the exit handler found it every time. Without this the parent
    // classified a real answer — a success, or the module's own failure text — as decision 8's "exited
    // without producing a result", which is the wrong 503 with the wrong reason. It was found as one
    // intermittent failure in the full suite; the test that pins it produces the order on demand.
    //
    // So before an `exit` or `error` may settle anything, whatever the port already holds is read,
    // synchronously, in arrival order.
    const drain = () => {
      for (let queued = receiveMessageOnPort(port1); queued !== undefined; queued = receiveMessageOnPort(port1)) {
        onReply(queued.message);
      }
    };

    thread.on("error", (thrown) => {
      drain();
      if (settled) {
        // A late failure inside the grace window: counted and logged, and the answer stands.
        opts.onLateFault(thrown);
        lateErrorCounted = true;
        return;
      }
      settled = true;
      reject(new Error(`${opts.sitePath}: ${opts.reasonOf(thrown)}`));
      reclaim(0);
    });

    thread.on("exit", (code) => {
      drain();
      leave();
      if (settled) {
        // ## One late fault, one count
        //
        // A worker's uncaught exception arrives as `error` **and then** `exit 1`. Counting both made one
        // throw two faults — measured: a module throwing once from a timer after its answer read
        // `faults: 1` on `da80b7b` (in-process) and `faults: 2` here, with two log lines. The exit that
        // follows an `error` already counted is the same event, so it is not counted again. An abnormal
        // exit with no `error` before it — `process.exit(2)` after answering — is still a fault.
        // @see src/policy-render-service.test.ts "counts a fault that arrives inside the grace window
        // without changing the answer", which asserts exactly 1
        if (code !== 0 && !terminatedByUs && !lateErrorCounted) {
          opts.onLateFault(new Error(`worker exited ${code} after answering`));
        }
        return;
      }
      // Decision 8: an exit with no result is this site's refusal, and nothing is cached. A module
      // calling `process.exit(0)` leaves neither a reply nor an `error` (§3-b ④), so this is the only
      // place it can be noticed.
      settled = true;
      // ## Exit 13 is a hang that ended itself, and it is not the budget
      //
      // A module whose top level awaits something that never settles leaves the worker's event loop
      // with nothing to run, so Node ends the thread with code 13, "unsettled top-level await", in a few
      // milliseconds. Measured (node 26.4): the `exit` arrives 25 ms after the handover, while a 3 s
      // budget has not fired. So this is decision 8's ending, not the timeout's, and the message says
      // which; "did not finish within" here would report a budget that never ran out.
      const why = code === 13
        ? "the module's top level awaited something that never settled (exit 13)"
        : `the evaluation exited (${code}) without producing a result`;
      reject(new Error(`${opts.sitePath}: ${why}`));
      reclaim(0);
    });

    // ## The budget, and what is different now that it can be enforced
    //
    // In-process, the timer could only reject while the module kept running: a top-level
    // `while (true) {}` was the one hole the renderer's own realm could not close, because a timer
    // cannot preempt synchronous code. `terminate()` can.
    const budget = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error(`evaluation did not finish within ${opts.budgetMs}ms`));
      reclaim(0);
    }, opts.budgetMs);
    budget.unref();

    // Handing the port over as the first message, before the worker imports anything untrusted. The
    // worker takes it and stops reading its own channel; §3-b ② measured what happens if it imports
    // first — the module takes the handover instead.
    thread.postMessage({ reply: port2 }, [port2]);
  });
}
