import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Worker } from "node:worker_threads";
import { evaluateWithLifecycle } from "./policy-eval-lifecycle.ts";
import { currentPolicyWire, type SourceStamp } from "./policy-eval-cache.ts";

type Cached = { stamp: string; wire: string };
type InFlight = { stamp: string; answer: Promise<string> };
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
        sitePath: site, cached, inFlight, readStamp: () => metadata,
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
          return evaluation;
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
      sitePath: "site", cached, inFlight,
      readStamp: () => ({ stamp: "dirty", reuseAllowed: false }),
      evaluate: async () => {
        const observed = dependency;
        starts.push(observed);
        if (observed === "old") await barrier.promise;
        return observed;
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
    const input = { sitePath: "site", cached, inFlight, readStamp: () => ({ stamp: "dirty", reuseAllowed: false }) };
    assert.equal(await currentPolicyWire({ ...input, evaluate: async () => "wire", accepted: () => "accepted" }), "accepted");
    await assert.rejects(currentPolicyWire({ ...input, evaluate: async () => { throw new Error("failed"); }, accepted: () => "unused" }), /failed/);
    await assert.rejects(currentPolicyWire({ ...input, evaluate: async () => "wire", accepted: () => { throw new Error("parent"); } }), /parent/);
    assert.deepEqual(cacheAccesses, { get: 0, set: 0, delete: 0 });
    assert.deepEqual(flightAccesses, { get: 0, set: 0, delete: 0 });
    // Known positives for each instrumented map operation used by the coordinator.
    assert.equal(await currentPolicyWire({
      ...input, readStamp: () => ({ stamp: "clean", reuseAllowed: true }),
      evaluate: async () => "wire", accepted: () => "accepted",
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
      sitePath: "site", cached, inFlight: new Map(),
      readStamp: () => ({ stamp: "dirty", reuseAllowed: false }),
      evaluate: async () => { starts += 1; return "fresh"; }, accepted: (wire) => wire,
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
      sitePath: "site", cached: new Map(), inFlight,
      readStamp: () => ({ stamp: "dirty", reuseAllowed: false }),
      evaluate: async () => { starts += 1; return "fresh"; }, accepted: (wire) => wire,
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
    const input = { sitePath: "site", cached, inFlight, accepted: (wire: string) => wire };
    const dirty = currentPolicyWire({ ...input, readStamp: () => ({ stamp: "dirty", reuseAllowed: false }), evaluate: () => barrier.promise });
    try {
      assert.equal(await currentPolicyWire({ ...input, readStamp: () => ({ stamp: "clean", reuseAllowed: true }), evaluate: async () => "clean" }), "clean");
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
        sitePath: "site", cached, inFlight, readStamp: () => metadata,
        evaluate: () => { starts += 1; return barrier.promise; }, accepted: (wire: string) => wire,
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
        sitePath: "site", cached, inFlight, readStamp: () => ({ stamp, reuseAllowed: true }),
        evaluate: () => { starts += 1; return barrier.promise; }, accepted: (wire: string) => wire,
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
    const input = { sitePath: "site", cached, inFlight, readStamp: () => ({ stamp: "clean", reuseAllowed: true }), accepted: (wire: string) => wire };
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
    assert.equal(await currentPolicyWire({ ...input, evaluate: async () => { starts += 1; return "recovered"; } }), "recovered");
    assert.equal(starts, 3);
    assert.equal(await currentPolicyWire({ ...input, sitePath: "other", evaluate: async () => "other" }), "other");
    assert.equal(await currentPolicyWire({ ...input, readStamp: () => ({ stamp: "new", reuseAllowed: true }), evaluate: async () => "new" }), "new");
  });

  it("does not cache a parent rejection and clears the rejected in-flight entry", async () => {
    const cached = new Map<string, Cached>();
    const inFlight = new Map<string, InFlight>();
    const input = { sitePath: "site", cached, inFlight, readStamp: () => ({ stamp: "clean", reuseAllowed: true }), evaluate: async () => "wire" };
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
      const input = { sitePath: "site", cached, inFlight, accepted: (wire: string) => wire };
      const old = currentPolicyWire({
        ...input, readStamp: () => ({ stamp: "old", reuseAllowed: true }),
        evaluate: async () => { const wire = await oldBarrier.promise; if (rejectOld) throw new Error("old failure"); return wire; },
      });
      const newer = currentPolicyWire({ ...input, readStamp: () => ({ stamp: "new", reuseAllowed: true }), evaluate: () => newBarrier.promise });
      const replacement = inFlight.get("site");
      const settledOld = rejectOld ? assert.rejects(old, /old failure/) : old;
      try {
        oldBarrier.resolve("old");
        await settledOld;
        assert.equal(inFlight.get("site"), replacement);
        let starts = 0;
        const joined = currentPolicyWire({ ...input, readStamp: () => ({ stamp: "new", reuseAllowed: true }), evaluate: async () => { starts += 1; return "unexpected"; } });
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
    const input = { sitePath: "site", cached, inFlight, accepted: (wire: string) => wire };
    const old = currentPolicyWire({ ...input, readStamp: () => ({ stamp: "old", reuseAllowed: true }), evaluate: () => barrier.promise });
    try {
      assert.equal(await currentPolicyWire({ ...input, readStamp: () => ({ stamp: "new", reuseAllowed: true }), evaluate: async () => "new" }), "new");
    } finally {
      barrier.resolve("old");
      await Promise.allSettled([old]);
    }
    assert.equal(await old, "old");
    assert.equal(cached.get("site")?.stamp, "old");
    let starts = 0;
    assert.equal(await currentPolicyWire({ ...input, readStamp: () => ({ stamp: "new", reuseAllowed: true }), evaluate: async () => { starts += 1; return "fresh new"; } }), "fresh new");
    assert.equal(starts, 1);
  });

  it("does not evaluate or touch maps when the stamp reader fails", async () => {
    const accesses = { get: 0, set: 0, delete: 0 };
    let starts = 0;
    let reads = 0;
    await assert.rejects(currentPolicyWire({
      sitePath: "site", cached: recorded<Cached>(accesses), inFlight: recorded<InFlight>(accesses),
      readStamp: () => { reads += 1; throw new Error("scan failed"); },
      evaluate: async () => { starts += 1; return "unused"; }, accepted: () => "unused",
    }), /scan failed/);
    assert.equal(reads, 1);
    assert.equal(starts, 0);
    assert.deepEqual(accesses, { get: 0, set: 0, delete: 0 });
  });
});
