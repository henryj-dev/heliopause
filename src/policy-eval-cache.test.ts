import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Worker } from "node:worker_threads";
import { evaluateWithLifecycle } from "./policy-eval-lifecycle.ts";
import { currentPolicyWire, type Evaluated, type SourceStamp, type UnreusableMark } from "./policy-eval-cache.ts";
import type { ImportScope } from "./policy-import-scope.ts";

type Cached = { stamp: string; wire: string };
type InFlight = { stamp: string; answer: Promise<string> };

/**
 * The scope every test here judges imports against. `sitePath` is the process's own directory, so
 * the check can resolve it; the tests that are about the judgement pass their own scope instead.
 */
const SCOPE: ImportScope = { sitePath: process.cwd(), ownRoots: [] };

/** An evaluator the existing tests wrote as returning a wire, wrapped as a reusable evaluation. */
const reusable = (wire: string): Evaluated => ({ wire, imports: { complete: true, urls: [] } });
interface Accesses { get: number; set: number; delete: number }

function recorded<V>(accesses: Accesses): Map<string, V> {
  const map = new Map<string, V>();
  const get = map.get.bind(map);
  const set = map.set.bind(map);
  const remove = map.delete.bind(map);
  map.get = (key) => { accesses.get += 1; return get(key); };
  map.set = (key, value) => { accesses.set += 1; return set(key, value); };
  map.delete = (key) => { accesses.delete += 1; return remove(key); };
  return map;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}

describe("dirty metadata does not reuse an evaluation", () => {
  it("reevaluates a dirty tree when an excluded helper changes without moving its stamp", async () => {
    const fixture = mkdtempSync(join(tmpdir(), "policy-eval-cache-"));
    const workers: Worker[] = [];
    const pending: Promise<unknown>[] = [];
    const cached = new Map<string, Cached>();
    const inFlight = new Map<string, InFlight>();
    try {
      mkdirSync(join(fixture, ".excluded"));
      const helper = join(fixture, ".excluded", "helper.ts");
      writeFileSync(helper, "export const marker = 'first-marker';\nexport function run(): string { return marker; }\n");
      const site = join(fixture, "site.ts");
      writeFileSync(site, `import { marker, run } from "./.excluded/helper.ts";\nexport const site = { cfg: {}, hosts: [], marker: run() };\n`);
      // Metadata is injected: this tests coordination and real worker reevaluation, not Git or scanning.
      const metadata: SourceStamp = { stamp: "same-dirty-stamp", reuseAllowed: false };
      let starts = 0;
      const input = {
        sitePath: site, cached, inFlight, unreusable: new Map(), importScope: SCOPE, readStamp: () => metadata,
        evaluate: () => {
          starts += 1;
          const evaluation = evaluateWithLifecycle({
            spawn: () => {
              const worker = new Worker(new URL("./policy-eval-worker.ts", import.meta.url), { workerData: { sitePath: site } });
              workers.push(worker);
              return worker;
            },
            budgetMs: 2_000, graceMs: 0, sitePath: site, label: "synthetic",
            onLateFault: () => undefined, log: () => undefined, onAlive: () => undefined,
            reasonOf: (thrown: unknown) => String((thrown as Error)?.message ?? thrown),
          });
          pending.push(evaluation.catch(() => undefined));
          return evaluation.then((r) => ({ wire: r.wire, imports: r.imports ?? { complete: false, urls: [] } }));
        },
        accepted: (wire: string) => wire,
      };
      assert.equal(JSON.parse(await currentPolicyWire(input)).site.marker, "first-marker");
      writeFileSync(helper, "export const marker = 'second-marker';\nexport function run(): string { throw new Error('excluded-helper-changed'); }\n");
      await assert.rejects(currentPolicyWire(input), /excluded-helper-changed/);
      assert.equal(starts, 2);
    } finally {
      await Promise.all(workers.map((worker) => worker.terminate()));
      await Promise.all(pending);
      rmSync(fixture, { recursive: true, force: true });
    }
  });

  it("does not join an older dirty evaluation after an unstampable dependency changes", async () => {
    const barrier = deferred<void>();
    const cached = new Map<string, Cached>();
    const inFlight = new Map<string, InFlight>();
    const starts: string[] = [];
    let dependency = "old";
    const input = {
      sitePath: "site", cached, inFlight, unreusable: new Map(), importScope: SCOPE,
      readStamp: () => ({ stamp: "dirty", reuseAllowed: false }),
      evaluate: async () => {
        const observed = dependency;
        starts.push(observed);
        if (observed === "old") await barrier.promise;
        return reusable(observed);
      },
      accepted: (wire: string) => wire,
    };
    const first = currentPolicyWire(input);
    dependency = "new";
    const second = currentPolicyWire(input);
    try {
      assert.deepEqual(starts, ["old", "new"]);
    } finally {
      barrier.resolve();
      await Promise.allSettled([first, second]);
    }
    assert.deepEqual(await Promise.all([first, second]), ["old", "new"]);
  });

  it("does not read or write reuse maps for dirty evaluations", async () => {
    const cacheAccesses = { get: 0, set: 0, delete: 0 };
    const flightAccesses = { get: 0, set: 0, delete: 0 };
    const cached = recorded<Cached>(cacheAccesses);
    const inFlight = recorded<InFlight>(flightAccesses);
    const input = { sitePath: "site", cached, inFlight, unreusable: new Map(), importScope: SCOPE, readStamp: () => ({ stamp: "dirty", reuseAllowed: false }) };
    assert.equal(await currentPolicyWire({ ...input, evaluate: async () => reusable("wire"), accepted: () => "accepted" }), "accepted");
    await assert.rejects(currentPolicyWire({ ...input, evaluate: async () => { throw new Error("failed"); }, accepted: () => "unused" }), /failed/);
    await assert.rejects(currentPolicyWire({ ...input, evaluate: async () => reusable("wire"), accepted: () => { throw new Error("parent"); } }), /parent/);
    assert.deepEqual(cacheAccesses, { get: 0, set: 0, delete: 0 });
    assert.deepEqual(flightAccesses, { get: 0, set: 0, delete: 0 });
    // Known positives for each instrumented map operation used by the coordinator.
    assert.equal(await currentPolicyWire({
      ...input, readStamp: () => ({ stamp: "clean", reuseAllowed: true }),
      evaluate: async () => reusable("wire"), accepted: () => "accepted",
    }), "accepted");
    assert.ok(cacheAccesses.get > 0 && cacheAccesses.set > 0 && cacheAccesses.delete === 0);
    assert.ok(flightAccesses.get > 0 && flightAccesses.set > 0 && flightAccesses.delete > 0);
    assert.deepEqual(cached.get("site"), { stamp: "clean", wire: "accepted" });
    cached.delete("site");
    assert.equal(cacheAccesses.delete, 1);
  });

  it("does not hit an injected completed dirty evaluation", async () => {
    const cached = new Map([["site", { stamp: "dirty", wire: "old" }]]);
    let starts = 0;
    assert.equal(await currentPolicyWire({
      sitePath: "site", cached, inFlight: new Map(), unreusable: new Map(), importScope: SCOPE,
      readStamp: () => ({ stamp: "dirty", reuseAllowed: false }),
      evaluate: async () => { starts += 1; return reusable("fresh"); }, accepted: (wire) => wire,
    }), "fresh");
    assert.equal(starts, 1);
    assert.equal(cached.get("site")?.wire, "old");
  });

  it("does not join an injected older dirty evaluation", async () => {
    const barrier = deferred<string>();
    const entry = { stamp: "dirty", answer: barrier.promise };
    const inFlight = new Map([["site", entry]]);
    let starts = 0;
    const fresh = currentPolicyWire({
      sitePath: "site", cached: new Map(), inFlight, unreusable: new Map(), importScope: SCOPE,
      readStamp: () => ({ stamp: "dirty", reuseAllowed: false }),
      evaluate: async () => { starts += 1; return reusable("fresh"); }, accepted: (wire) => wire,
    });
    try {
      assert.equal(starts, 1);
    } finally {
      barrier.resolve("old");
      await Promise.allSettled([fresh, barrier.promise]);
    }
    assert.equal(await fresh, "fresh");
    assert.equal(inFlight.get("site"), entry);
  });

  it("does not overwrite clean reuse entries when a dirty evaluation completes later", async () => {
    const barrier = deferred<string>();
    const cached = new Map<string, Cached>();
    const inFlight = new Map<string, InFlight>();
    const input = { sitePath: "site", cached, inFlight, unreusable: new Map(), importScope: SCOPE, accepted: (wire: string) => wire };
    const dirty = currentPolicyWire({ ...input, readStamp: () => ({ stamp: "dirty", reuseAllowed: false }), evaluate: async () => reusable(await barrier.promise) });
    try {
      assert.equal(await currentPolicyWire({ ...input, readStamp: () => ({ stamp: "clean", reuseAllowed: true }), evaluate: async () => reusable("clean") }), "clean");
    } finally {
      barrier.resolve("dirty");
      await Promise.allSettled([dirty]);
    }
    assert.equal(await dirty, "dirty");
    assert.deepEqual(cached.get("site"), { stamp: "clean", wire: "clean" });
    assert.equal(inFlight.size, 0);
  });
});

describe("clean and nogit reuse remains", () => {
  it("starts one clean evaluation and four dirty evaluations for four concurrent calls", async () => {
    // Injected metadata and deferred evaluators measure starts, not worker cost or Git/scanner behavior.
    const counts: number[] = [];
    for (const reuseAllowed of [true, false]) {
      const cached = new Map<string, Cached>();
      const inFlight = new Map<string, InFlight>();
      const barrier = deferred<string>();
      const metadata: SourceStamp = { stamp: "same-stamp", reuseAllowed };
      let starts = 0;
      const input = {
        sitePath: "site", cached, inFlight, unreusable: new Map(), importScope: SCOPE, readStamp: () => metadata,
        evaluate: async () => { starts += 1; return reusable(await barrier.promise); }, accepted: (wire: string) => wire,
      };
      const answers = Array.from({ length: 4 }, () => currentPolicyWire(input));
      try {
        assert.equal(starts, reuseAllowed ? 1 : 4);
        assert.equal(inFlight.size, reuseAllowed ? 1 : 0);
      } finally {
        barrier.resolve("wire");
        await Promise.allSettled(answers);
      }
      assert.deepEqual(await Promise.all(answers), ["wire", "wire", "wire", "wire"]);
      assert.equal(inFlight.size, 0);
      assert.equal(cached.size, reuseAllowed ? 1 : 0);
      counts.push(starts);
    }
    assert.deepEqual(counts, [1, 4]);
  });

  for (const stamp of ["clean", "nogit"]) {
    it(`reuses a ${stamp} success and coalesces ${stamp} concurrent misses`, async () => {
      const cached = new Map<string, Cached>();
      const inFlight = new Map<string, InFlight>();
      let starts = 0;
      const barrier = deferred<string>();
      const input = {
        sitePath: "site", cached, inFlight, unreusable: new Map(), importScope: SCOPE, readStamp: () => ({ stamp, reuseAllowed: true }),
        evaluate: async () => { starts += 1; return reusable(await barrier.promise); }, accepted: (wire: string) => wire,
      };
      const first = currentPolicyWire(input);
      const second = currentPolicyWire(input);
      try {
        assert.equal(starts, 1);
      } finally {
        barrier.resolve("wire");
        await Promise.allSettled([first, second]);
      }
      assert.deepEqual(await Promise.all([first, second]), ["wire", "wire"]);
      assert.equal(await currentPolicyWire(input), "wire");
      assert.equal(starts, 1);
      assert.equal(inFlight.size, 0);
    });
  }

  it("evaluates again after clean synchronous and asynchronous failures and isolates site and stamp", async () => {
    const cached = new Map<string, Cached>();
    const inFlight = new Map<string, InFlight>();
    const input = { sitePath: "site", cached, inFlight, unreusable: new Map(), importScope: SCOPE, readStamp: () => ({ stamp: "clean", reuseAllowed: true }), accepted: (wire: string) => wire };
    let starts = 0;
    const syncFailure = () => { starts += 1; throw new Error("synchronous"); };
    for (const evaluate of [
      syncFailure,
      async function asyncFailure() { starts += 1; throw new Error("asynchronous"); },
    ]) {
      await assert.rejects(currentPolicyWire({ ...input, evaluate }), evaluate.name === "syncFailure" ? /synchronous/ : /asynchronous/);
      assert.equal(cached.size, 0);
      assert.equal(inFlight.size, 0);
    }
    assert.equal(await currentPolicyWire({ ...input, evaluate: async () => { starts += 1; return reusable("recovered"); } }), "recovered");
    assert.equal(starts, 3);
    assert.equal(await currentPolicyWire({ ...input, sitePath: "other", evaluate: async () => reusable("other") }), "other");
    assert.equal(await currentPolicyWire({ ...input, readStamp: () => ({ stamp: "new", reuseAllowed: true }), evaluate: async () => reusable("new") }), "new");
  });

  it("does not cache a parent rejection and clears the rejected in-flight entry", async () => {
    const cached = new Map<string, Cached>();
    const inFlight = new Map<string, InFlight>();
    const input = { sitePath: "site", cached, inFlight, unreusable: new Map(), importScope: SCOPE, readStamp: () => ({ stamp: "clean", reuseAllowed: true }), evaluate: async () => reusable("wire") };
    await assert.rejects(currentPolicyWire({ ...input, accepted: () => { throw new Error("rejected"); } }), /rejected/);
    assert.equal(cached.size, 0);
    assert.equal(inFlight.size, 0);
    assert.equal(await currentPolicyWire({ ...input, accepted: () => "recovered" }), "recovered");
    assert.equal(cached.get("site")?.wire, "recovered");
  });

  it("isolates sites and preserves newer in-flight entries across completion races", async () => {
    for (const rejectOld of [false, true]) {
      const cached = new Map<string, Cached>();
      const inFlight = new Map<string, InFlight>();
      const oldBarrier = deferred<string>();
      const newBarrier = deferred<string>();
      const input = { sitePath: "site", cached, inFlight, unreusable: new Map(), importScope: SCOPE, accepted: (wire: string) => wire };
      const old = currentPolicyWire({
        ...input, readStamp: () => ({ stamp: "old", reuseAllowed: true }),
        evaluate: async () => { const wire = await oldBarrier.promise; if (rejectOld) throw new Error("old failure"); return reusable(wire); },
      });
      const newer = currentPolicyWire({ ...input, readStamp: () => ({ stamp: "new", reuseAllowed: true }), evaluate: async () => reusable(await newBarrier.promise) });
      const replacement = inFlight.get("site");
      const settledOld = rejectOld ? assert.rejects(old, /old failure/) : old;
      try {
        oldBarrier.resolve("old");
        await settledOld;
        assert.equal(inFlight.get("site"), replacement);
        let starts = 0;
        const joined = currentPolicyWire({ ...input, readStamp: () => ({ stamp: "new", reuseAllowed: true }), evaluate: async () => { starts += 1; return reusable("unexpected"); } });
        assert.equal(starts, 0);
        newBarrier.resolve("new");
        assert.equal(await joined, "new");
      } finally {
        oldBarrier.resolve("old");
        newBarrier.resolve("new");
        await Promise.allSettled([old, newer, settledOld]);
      }
      assert.equal(await newer, "new");
      assert.equal(inFlight.size, 0);
    }
    const cached = new Map<string, Cached>();
    const inFlight = new Map<string, InFlight>();
    const barrier = deferred<string>();
    const input = { sitePath: "site", cached, inFlight, unreusable: new Map(), importScope: SCOPE, accepted: (wire: string) => wire };
    const old = currentPolicyWire({ ...input, readStamp: () => ({ stamp: "old", reuseAllowed: true }), evaluate: async () => reusable(await barrier.promise) });
    try {
      assert.equal(await currentPolicyWire({ ...input, readStamp: () => ({ stamp: "new", reuseAllowed: true }), evaluate: async () => reusable("new") }), "new");
    } finally {
      barrier.resolve("old");
      await Promise.allSettled([old]);
    }
    assert.equal(await old, "old");
    assert.equal(cached.get("site")?.stamp, "old");
    let starts = 0;
    assert.equal(await currentPolicyWire({ ...input, readStamp: () => ({ stamp: "new", reuseAllowed: true }), evaluate: async () => { starts += 1; return reusable("fresh new"); } }), "fresh new");
    assert.equal(starts, 1);
  });

  it("does not evaluate or touch maps when the stamp reader fails", async () => {
    const accesses = { get: 0, set: 0, delete: 0 };
    let starts = 0;
    let reads = 0;
    await assert.rejects(currentPolicyWire({
      sitePath: "site", cached: recorded<Cached>(accesses), inFlight: recorded<InFlight>(accesses), unreusable: new Map(), importScope: SCOPE,
      readStamp: () => { reads += 1; throw new Error("scan failed"); },
      evaluate: async () => { starts += 1; return reusable("unused"); }, accepted: () => "unused",
    }), /scan failed/);
    assert.equal(reads, 1);
    assert.equal(starts, 0);
    assert.deepEqual(accesses, { get: 0, set: 0, delete: 0 });
  });
});

describe("an answer whose imports the stamp cannot see is served and not cached", () => {
  /** A report naming one file outside any site tree, so the scope check refuses it. */
  const OUTSIDE: Evaluated = { wire: "wire", imports: { complete: true, urls: ["file:///no/such/file.ts"] } };

  it("returns the answer and does not store it, then evaluates again on the same stamp", async () => {
    const cached = new Map<string, Cached>();
    const inFlight = new Map<string, InFlight>();
    const unreusable = new Map<string, UnreusableMark>();
    let starts = 0;
    const input = {
      sitePath: "site", cached, inFlight, unreusable, importScope: SCOPE,
      readStamp: () => ({ stamp: "clean", reuseAllowed: true }),
      evaluate: async () => { starts += 1; return OUTSIDE; },
      accepted: (wire: string) => wire,
    };
    assert.equal(await currentPolicyWire(input), "wire");
    assert.equal(cached.size, 0, "an unsafe answer was stored");
    assert.equal(unreusable.get("site")?.stamp, "clean");
    assert.equal(await currentPolicyWire(input), "wire");
    assert.equal(starts, 2, "the second call on the same stamp reused the answer");
  });

  it("shares the first answer with a call that arrived before the judgement", async () => {
    const barrier = deferred<Evaluated>();
    const cached = new Map<string, Cached>();
    const inFlight = new Map<string, InFlight>();
    let starts = 0;
    const input = {
      sitePath: "site", cached, inFlight, unreusable: new Map(), importScope: SCOPE,
      readStamp: () => ({ stamp: "clean", reuseAllowed: true }),
      evaluate: () => { starts += 1; return barrier.promise; },
      accepted: (wire: string) => wire,
    };
    const first = currentPolicyWire(input);
    const second = currentPolicyWire(input);
    try {
      assert.equal(starts, 1, "the call that arrived before the judgement started its own evaluation");
    } finally {
      barrier.resolve(OUTSIDE);
      await Promise.allSettled([first, second]);
    }
    assert.deepEqual(await Promise.all([first, second]), ["wire", "wire"]);
    assert.equal(cached.size, 0);
    // The mark is what makes the *next* call evaluate again; the two above shared one evaluation.
    let later = 0;
    assert.equal(await currentPolicyWire({ ...input, evaluate: async () => { later += 1; return OUTSIDE; } }), "wire");
    assert.equal(later, 1);
  });

  it("rejudges when the stamp moves, in both directions", async () => {
    const cached = new Map<string, Cached>();
    const inFlight = new Map<string, InFlight>();
    const unreusable = new Map<string, UnreusableMark>();
    let mode: "safe" | "unsafe" = "unsafe";
    let starts = 0;
    const input = {
      sitePath: "site", cached, inFlight, unreusable, importScope: SCOPE,
      readStamp: () => ({ stamp: mode, reuseAllowed: true }),
      evaluate: async () => { starts += 1; return mode === "safe" ? reusable("safe") : OUTSIDE; },
      accepted: (wire: string) => wire,
    };
    assert.equal(await currentPolicyWire(input), "wire");
    mode = "safe";
    assert.equal(await currentPolicyWire(input), "safe");
    assert.equal(cached.get("site")?.wire, "safe", "the safe stamp was not stored");
    assert.equal(await currentPolicyWire(input), "safe");
    mode = "unsafe";
    assert.equal(await currentPolicyWire(input), "wire");
    // The safe stamp's stored answer may stay — it names "safe", and the "unsafe" stamp is blocked from
    // reading it. What must not hold is a stored answer on the unsafe stamp.
    assert.notEqual(cached.get("site")?.stamp, "unsafe", "the unsafe stamp's answer was stored");
    assert.equal(starts, 3, "the unchanged safe stamp was evaluated twice");
    // And back again: the stored safe answer is served without a fourth evaluation.
    mode = "safe";
    assert.equal(await currentPolicyWire(input), "safe");
    assert.equal(starts, 3, "the safe stamp was not served from the cache after the unsafe one");
  });

  it("does not let an older evaluation's verdict overwrite the newer stamp's", async () => {
    const old = deferred<Evaluated>();
    const cached = new Map<string, Cached>();
    const inFlight = new Map<string, InFlight>();
    const unreusable = new Map<string, UnreusableMark>();
    const input = { sitePath: "site", cached, inFlight, unreusable, importScope: SCOPE, accepted: (wire: string) => wire };
    const stale = currentPolicyWire({ ...input, readStamp: () => ({ stamp: "old", reuseAllowed: true }), evaluate: () => old.promise });
    try {
      assert.equal(await currentPolicyWire({ ...input, readStamp: () => ({ stamp: "new", reuseAllowed: true }), evaluate: async () => reusable("new") }), "new");
    } finally {
      old.resolve(OUTSIDE);
      await Promise.allSettled([stale]);
    }
    assert.equal(await stale, "wire");
    // The stored answer is the stale evaluation's: an older clean completion replacing the newer value
    // is the race the coordinator already has (`isolates sites` pins it). What this guards is the
    // verdict — the stale evaluation must not mark the newer stamp, which would make the next call on
    // it re-evaluate.
    assert.notEqual(unreusable.get("site")?.stamp, "new", "the stale evaluation marked the newer stamp unreusable");
    let starts = 0;
    assert.equal(await currentPolicyWire({ ...input, readStamp: () => ({ stamp: "new", reuseAllowed: true }), evaluate: async () => { starts += 1; return reusable("again"); } }), "new");
    assert.equal(starts, 0, "the newer stamp was re-evaluated after the stale verdict");
  });

  it("marks a moved stamp that also imports outside, so its next concurrent calls do not join", async () => {
    // One mark per site. A rule that kept the first stamp's mark would leave the second stamp unmarked,
    // and two calls on it would share one evaluation after it had been found unreusable.
    const cached = new Map<string, Cached>();
    const inFlight = new Map<string, InFlight>();
    const unreusable = new Map<string, UnreusableMark>();
    let stamp = "a";
    const input = {
      sitePath: "site", cached, inFlight, unreusable, importScope: SCOPE,
      readStamp: () => ({ stamp, reuseAllowed: true }),
      evaluate: async () => OUTSIDE,
      accepted: (wire: string) => wire,
    };
    await currentPolicyWire(input);
    stamp = "b";
    await currentPolicyWire(input);
    assert.equal(unreusable.get("site")?.stamp, "b", "the moved stamp was not marked");
    const barrier = deferred<Evaluated>();
    let starts = 0;
    const held = { ...input, evaluate: () => { starts += 1; return barrier.promise; } };
    const first = currentPolicyWire(held);
    const second = currentPolicyWire(held);
    try {
      assert.equal(starts, 2, "a call on the marked stamp joined an evaluation in flight");
    } finally {
      barrier.resolve(OUTSIDE);
      await Promise.allSettled([first, second]);
    }
  });

  it("does not let an older unreusable evaluation replace a newer stamp's mark", async () => {
    const old = deferred<Evaluated>();
    const cached = new Map<string, Cached>();
    const inFlight = new Map<string, InFlight>();
    const unreusable = new Map<string, UnreusableMark>();
    const input = { sitePath: "site", cached, inFlight, unreusable, importScope: SCOPE, accepted: (wire: string) => wire };
    const stale = currentPolicyWire({ ...input, readStamp: () => ({ stamp: "old", reuseAllowed: true }), evaluate: () => old.promise });
    try {
      assert.equal(await currentPolicyWire({ ...input, readStamp: () => ({ stamp: "new", reuseAllowed: true }), evaluate: async () => OUTSIDE }), "wire");
      assert.equal(unreusable.get("site")?.stamp, "new");
    } finally {
      old.resolve(OUTSIDE);
      await Promise.allSettled([stale]);
    }
    assert.equal(unreusable.get("site")?.stamp, "new", "the older evaluation replaced the newer stamp's mark");
  });

  /**
   * Marks stamp "s", then starts two evaluations on it that cannot join (the mark blocks joining) and
   * hands back their barriers in start order.
   */
  async function twoOnAMarkedStamp(cached: Map<string, Cached>, unreusable: Map<string, UnreusableMark>) {
    const inFlight = new Map<string, InFlight>();
    let stamp = "s";
    let starts = 0;
    const barriers: ReturnType<typeof deferred<Evaluated>>[] = [];
    const input = {
      sitePath: "site", cached, inFlight, unreusable, importScope: SCOPE,
      readStamp: () => ({ stamp, reuseAllowed: true }),
      evaluate: () => { starts += 1; const b = deferred<Evaluated>(); barriers.push(b); return b.promise; },
      accepted: (wire: string) => wire,
    };
    const marking = currentPolicyWire(input);
    barriers[0]!.resolve(OUTSIDE);
    await marking;
    assert.equal(unreusable.get("site")?.stamp, "s", "the first unsafe evaluation did not mark its stamp");
    const older = currentPolicyWire(input);
    const newer = currentPolicyWire(input);
    assert.equal(starts, 3, "a call on the marked stamp joined an evaluation in flight");
    return {
      input, older, newer, olderBarrier: barriers[1]!, newerBarrier: barriers[2]!,
      moveTo: (s: string) => { stamp = s; },
    };
  }

  it("keeps the mark when an older evaluation that found nothing outside finishes after a newer one that did", async () => {
    const cached = new Map<string, Cached>();
    const unreusable = new Map<string, UnreusableMark>();
    const run = await twoOnAMarkedStamp(cached, unreusable);
    run.newerBarrier.resolve(OUTSIDE);
    await run.newer;
    run.olderBarrier.resolve(reusable("older"));
    assert.equal(await run.older, "older");
    assert.equal(unreusable.get("site")?.stamp, "s", "the older reusable result cleared the newer evaluation's mark");
    let evaluated = 0;
    assert.equal(await currentPolicyWire({ ...run.input, evaluate: async () => { evaluated += 1; return OUTSIDE; } }), "wire");
    assert.equal(evaluated, 1, "the stamp the newer evaluation found unsafe was answered from the older stored result");
  });

  it("drops the stored answer on a stamp a newer evaluation found unsafe, so it is not served once the mark moves", async () => {
    const cached = new Map<string, Cached>();
    const unreusable = new Map<string, UnreusableMark>();
    const run = await twoOnAMarkedStamp(cached, unreusable);
    run.olderBarrier.resolve(reusable("older"));
    assert.equal(await run.older, "older");
    assert.equal(cached.get("site")?.stamp, "s", "the older reusable result was not stored — the path this test needs did not open");
    run.newerBarrier.resolve(OUTSIDE);
    assert.equal(await run.newer, "wire");
    assert.notEqual(cached.get("site")?.stamp, "s", "the stamp the newer evaluation found unsafe kept its stored answer");
    // The mark moves to another stamp, and the stamp comes back (mtime-only stamps can).
    run.moveTo("t");
    await currentPolicyWire({ ...run.input, evaluate: async () => OUTSIDE });
    assert.equal(unreusable.get("site")?.stamp, "t");
    run.moveTo("s");
    let evaluated = 0;
    assert.equal(await currentPolicyWire({ ...run.input, evaluate: async () => { evaluated += 1; return OUTSIDE; } }), "wire");
    assert.equal(evaluated, 1, "the stamp found unsafe was answered from the stored older result");
  });

  it("does not touch the unreusable map for a dirty or unknown stamp", async () => {
    const accesses = { get: 0, set: 0, delete: 0 };
    const unreusable = recorded<UnreusableMark>(accesses);
    const input = {
      sitePath: "site", cached: new Map(), inFlight: new Map(), unreusable, importScope: SCOPE,
      readStamp: () => ({ stamp: "dirty", reuseAllowed: false }),
      evaluate: async () => OUTSIDE, accepted: (wire: string) => wire,
    };
    assert.equal(await currentPolicyWire(input), "wire");
    assert.deepEqual(accesses, { get: 0, set: 0, delete: 0 });
    // Known positive: the same map is read when the stamp may be reused.
    const clean = recorded<UnreusableMark>({ get: 0, set: 0, delete: 0 });
    await currentPolicyWire({ ...input, unreusable: clean, readStamp: () => ({ stamp: "clean", reuseAllowed: true }) });
    assert.ok(clean.size === 1, "a clean unsafe evaluation did not mark its stamp");
  });
});
