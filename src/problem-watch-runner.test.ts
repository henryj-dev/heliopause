import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { closeSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { EnvSpecError } from "./env-spec.ts";
import { shutdownManager } from "./manager-server.ts";
import {
  emitLines, emptyWatchState, keyOf, loadWatchState, parseWatchAliases, readRelayStatus, serializeWatchState,
  type RelayRead,
} from "./problem-watch.ts";
import {
  defaultProblemWatchFs, openLockFile, problemWatchFromEnv, ProblemWatchLockError, startProblemWatch,
  type ProblemWatch, type ProblemWatchFs,
} from "./problem-watch-runner.ts";

// Fixture names are RFC 2606: self-evidently not a site.
const RELAY = "zone-a.example";
const H1 = "h1.zone-a.example";
const H2 = "h2.zone-a.example";
const ALIASES_TEXT = JSON.stringify({ relays: { [RELAY]: "za" }, hosts: { [RELAY]: { [H1]: "web", [H2]: "db" } } });
const ALIASES = parseWatchAliases(ALIASES_TEXT, [RELAY]);
const NOW = new Date("2026-10-12T00:00:00Z");

type Ev = "yes" | "no-resolve" | "no";
function body(findings: { kind: string; host: string | null }[] = [], evaluated?: Record<string, Record<string, Ev>>): unknown {
  return JSON.parse(JSON.stringify({
    generation: "g1", issuedAt: null, planHash: null, hosts: [], problems: [], relayAgeSec: 1000,
    findings: findings.map((f) => ({ value: null, count: 1, ...f })),
    evaluated: evaluated ?? { [H1]: { silent: "yes" }, [H2]: { silent: "yes" } },
    fleetEvaluated: { "trust-ring-split": "yes" },
    observability: { manifest: true, graceActive: false },
  }));
}
const reads = (b: unknown): ReadonlyMap<string, RelayRead> => new Map([[RELAY, readRelayStatus(b)]]);
const SILENT_H1 = reads(body([{ kind: "silent", host: H1 }]));
const CLEAN = reads(body());

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}

type Line = Record<string, unknown>;
interface Harness {
  watch: ProblemWatch;
  /** File and emit boundary calls, in order: `<op> <basename>` and `emit <event>/<what|transition>`. */
  calls: string[];
  lines: Line[];
  polls: () => number;
  timers: { ms: number }[];
  cleared: unknown[];
  stateFile: string;
}

let dir = "";
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "hp-watch-")); });
afterEach(() => rmSync(dir, { recursive: true, force: true }));

interface Opts {
  allowEmptyState?: boolean;
  poll?: () => Promise<ReadonlyMap<string, RelayRead>>;
  fs?: Partial<ProblemWatchFs>;
  stateFile?: string;
}

/** Every boundary stubbed on its own: timers and poll fake, files real in a temp directory but recorded, emit captured. */
function start(o: Opts = {}): Harness {
  const calls: string[] = [];
  const lines: Line[] = [];
  const timers: { ms: number }[] = [];
  const cleared: unknown[] = [];
  let polls = 0;
  const stateFile = o.stateFile ?? join(dir, "state.json");
  const pick = <K extends keyof ProblemWatchFs>(k: K): ProblemWatchFs[K] => o.fs?.[k] ?? defaultProblemWatchFs[k];
  const fs: ProblemWatchFs = {
    readFile: (p) => { calls.push(`readFile ${basename(p)}`); return pick("readFile")(p); },
    writeFileAtomic: (p, t) => { calls.push(`writeFileAtomic ${basename(p)}`); pick("writeFileAtomic")(p, t); },
    openLock: (p, owner) => { calls.push(`openLock ${basename(p)}`); pick("openLock")(p, owner); },
    unlink: (p) => { calls.push(`unlink ${basename(p)}`); pick("unlink")(p); },
    rename: (a, b) => { calls.push(`rename ${basename(a)}`); pick("rename")(a, b); },
  };
  const watch = startProblemWatch({
    stateFile, aliases: ALIASES, intervalMs: 30_000, allowEmptyState: o.allowEmptyState ?? true,
    poll: async () => { polls += 1; return (o.poll ?? (async () => CLEAN))(); },
    fs,
    emit: (l) => {
      const parsed = JSON.parse(l) as Line;
      calls.push(`emit ${String(parsed.event)}/${String(parsed.what ?? parsed.transition ?? "")}`);
      lines.push(parsed);
    },
    setInterval: (_fn, ms) => { const h = { ms }; timers.push(h); return h; },
    clearInterval: (h) => cleared.push(h),
    now: () => NOW,
  });
  return { watch, calls, lines, polls: () => polls, timers, cleared, stateFile };
}

const whats = (h: Harness) => h.lines.filter((l) => l.event === "heliopause.problem.watch").map((l) => l.what);
const transitions = (h: Harness) => h.lines.filter((l) => l.event === "heliopause.problem.transition")
  .map((l) => `${String(l.transition)} ${String(l.host)}/${String(l.kind)}`);
const lockPath = (h: Harness) => `${h.stateFile}.lock`;

describe("problem watch runner: cycles", () => {
  it("does not start a second poll while one is in flight", async () => {
    const gate = deferred<ReadonlyMap<string, RelayRead>>();
    let first = true;
    const h = start({ poll: () => { if (first) { first = false; return gate.promise; } return Promise.resolve(CLEAN); } });
    assert.deepEqual(h.timers.map((t) => t.ms), [30_000]);
    const running = h.watch.tick();
    await h.watch.tick();
    await h.watch.tick();
    assert.equal(h.polls(), 1);
    gate.resolve(CLEAN);
    await running;
    await h.watch.tick();
    assert.equal(h.polls(), 2);
    const cycles = h.lines.filter((l) => l.event === "heliopause.problem.cycle").map((l) => l.skippedTicks);
    // The two ticks skipped while the first poll ran are reported by that cycle, which ends after them.
    assert.deepEqual(cycles, [2, 0]);
  });

  it("persist happens before emit", async () => {
    const written: { at: number; text: string }[] = [];
    let h: Harness | undefined;
    h = start({
      poll: async () => SILENT_H1,
      fs: {
        writeFileAtomic: (p, t) => {
          if (basename(p) === "state.json") written.push({ at: h?.calls.length ?? 0, text: t });
          defaultProblemWatchFs.writeFileAtomic(p, t);
        },
      },
    });
    await h.watch.tick();
    await h.watch.tick();
    const opened = h.calls.indexOf("emit heliopause.problem.transition/opened");
    // Known positive: the cycle that opened the problem is in the record.
    assert.ok(opened > 0, h.calls.join("\n"));
    // The last state saved before the `opened` line already holds the opened problem — that cycle's
    // own state, not the previous one's.
    const before = written.filter((w) => w.at <= opened).at(-1);
    assert.ok(before, "no state was saved before the opened line");
    const saved = JSON.parse(before.text) as { keys: { kind: string; active: boolean }[] };
    assert.deepEqual(saved.keys.filter((k) => k.kind === "silent").map((k) => k.active), [true]);
  });

  it("a failed write emits state_write_failed and no transitions", async () => {
    let fail = true;
    const h = start({
      poll: async () => SILENT_H1,
      fs: {
        writeFileAtomic: (p, t) => {
          if (fail && basename(p) === "state.json" && existsSync(p)) throw Object.assign(new Error("disk"), { code: "ENOSPC" });
          defaultProblemWatchFs.writeFileAtomic(p, t);
        },
      },
    });
    for (let i = 0; i < 3; i++) await h.watch.tick();
    assert.deepEqual(whats(h).filter((w) => w === "state_write_failed").length, 3);
    assert.deepEqual(h.lines.filter((l) => l.event !== "heliopause.problem.watch"), []);
    fail = false;
    await h.watch.tick();
    await h.watch.tick();
    // Known positive: once the write succeeds the same observations open the problem.
    assert.deepEqual(transitions(h), ["opened web/silent"]);
  });

  it("no write or emit after stop", async () => {
    const gate = deferred<ReadonlyMap<string, RelayRead>>();
    let n = 0;
    const h = start({ poll: () => (n++ === 0 ? Promise.resolve(SILENT_H1) : gate.promise) });
    await h.watch.tick();
    // Known positive: a cycle before stop wrote and emitted.
    assert.ok(h.calls.includes("writeFileAtomic state.json"));
    assert.ok(h.lines.some((l) => l.event === "heliopause.problem.cycle"));
    const inFlight = h.watch.tick();
    h.watch.stop();
    const at = h.calls.length;
    assert.equal(h.calls[at - 1], "emit heliopause.problem.watch/stopped");
    gate.resolve(SILENT_H1);
    await inFlight;
    await h.watch.tick();
    assert.deepEqual(h.calls.slice(at), []);
    assert.deepEqual(h.cleared, h.timers);
    assert.equal(existsSync(lockPath(h)), false);
  });

  it("state survives restart: an active problem is not opened again", async () => {
    const a = start({ poll: async () => SILENT_H1 });
    await a.watch.tick();
    await a.watch.tick();
    assert.deepEqual(transitions(a), ["opened web/silent"]);
    a.watch.stop();
    const b = start({ poll: async () => SILENT_H1, allowEmptyState: false });
    for (let i = 0; i < 3; i++) await b.watch.tick();
    assert.deepEqual(transitions(b), []);
    const states = b.lines.filter((l) => l.event === "heliopause.problem.state").map((l) => [l.host, l.kind, l.active]);
    assert.deepEqual(states, [["web", "silent", 1], ["web", "silent", 1], ["web", "silent", 1]]);
  });
});

describe("problem watch runner: state file", () => {
  it("a corrupt state file is moved aside and the watch stays off", async () => {
    for (const text of ["{not json", JSON.stringify({ v: 1, seq: 0, keys: [{ relay: "za", host: "web", kind: "silent", active: true, openStreak: 9, resolveStreak: 0, count: 1, tail: 0 }] })]) {
      rmSync(dir, { recursive: true, force: true });
      dir = mkdtempSync(join(tmpdir(), "hp-watch-"));
      writeFileSync(join(dir, "state.json"), text);
      const h = start();
      assert.deepEqual(whats(h), ["lock_acquired", "state_unreadable"]);
      assert.equal(existsSync(h.stateFile), false);
      assert.equal(readdirSync(dir).filter((f) => f.startsWith("state.json.corrupt-")).length, 1);
      assert.equal(existsSync(lockPath(h)), false);
      await h.watch.tick();
      assert.equal(h.polls(), 0);
      assert.ok(!h.calls.includes("writeFileAtomic state.json"));
    }
  });

  it("a missing state file with the initialized marker keeps the watch off", async () => {
    writeFileSync(join(dir, "state.json.initialized"), "x\n");
    const h = start({ allowEmptyState: true });
    assert.deepEqual(whats(h), ["lock_acquired", "state_unreadable"]);
    await h.watch.tick();
    assert.equal(h.polls(), 0);
    assert.equal(existsSync(h.stateFile), false);
  });

  it("ALLOW_EMPTY_STATE starts empty only before the first state file", async () => {
    const refused = start({ allowEmptyState: false });
    assert.deepEqual(whats(refused), ["lock_acquired", "state_unreadable"]);
    assert.deepEqual(readdirSync(dir), []);

    const first = start({ allowEmptyState: true });
    assert.deepEqual(whats(first), ["lock_acquired", "state_initialized", "started"]);
    assert.ok(existsSync(first.stateFile) && existsSync(`${first.stateFile}.initialized`));
    await first.watch.tick();
    assert.equal(first.polls(), 1);
    first.watch.stop();

    unlinkSync(first.stateFile);
    const again = start({ allowEmptyState: true });
    assert.deepEqual(whats(again), ["lock_acquired", "state_unreadable"]);
    assert.equal(existsSync(again.stateFile), false);
  });

  const rec = (relay: string, host: string, kind: string) => ({
    relay, host, kind, active: true, openStreak: 2, resolveStreak: 0, count: 1, tail: 0,
  });
  const PRUNABLE = JSON.stringify({ v: 1, seq: 4, keys: [
    rec("za", "web", "silent"), rec("za", "_fleet", "unaliased-hosts"),
    rec("za", "web", "drifted"), rec("gone", "web", "silent"), rec("za", "olddb", "silent"),
  ] });

  it("state loader drops unknown kinds and keeps stale aliases for scope removal", async () => {
    const loaded = loadWatchState(PRUNABLE, ALIASES);
    assert.ok(loaded.ok);
    assert.deepEqual([loaded.unknownKinds, loaded.staleAliases], [1, 2]);
    assert.deepEqual(Object.keys(loaded.state.keys).sort(), [
      keyOf("za", "_fleet", "unaliased-hosts"), keyOf("za", "web", "silent"), keyOf("gone", "web", "silent"), keyOf("za", "olddb", "silent"),
    ].sort());
    assert.equal(loaded.state.seq, 4);
    // A text in the serialized shape round-trips.
    assert.deepEqual(loadWatchState(serializeWatchState(loaded.state), ALIASES), { ok: true, state: loaded.state, unknownKinds: 0, staleAliases: 2 });
    // An alias the output schema would refuse is not a stale alias but a broken file.
    assert.deepEqual(loadWatchState(JSON.stringify({ v: 1, seq: 0, keys: [rec("ZA", "web", "silent")] }), ALIASES), { ok: false });

    writeFileSync(join(dir, "state.json"), PRUNABLE);
    const h = start({ poll: async () => SILENT_H1, allowEmptyState: false });
    const pruned = h.lines.find((l) => l.what === "state_pruned");
    assert.deepEqual(pruned, { event: "heliopause.problem.watch", v: 1, what: "state_pruned", unknownKinds: 1, staleAliases: 2 });
    await h.watch.tick();
    // The first cycle takes both stale keys out of scope, by name.
    const removed = h.lines.filter((l) => l.transition === "scope_removed").map((l) => `${String(l.relay)}/${String(l.host)}/${String(l.kind)}`);
    assert.deepEqual(removed.sort(), ["gone/web/silent", "za/olddb/silent"]);
    const stale = (l: Line) => l.event === "heliopause.problem.state" && (l.relay === "gone" || l.host === "olddb");
    for (let i = 0; i < 25; i++) await h.watch.tick();
    const zeros = h.lines.filter(stale);
    assert.ok(zeros.every((l) => l.active === 0));
    assert.equal(zeros.length, 2 * 20);
    const saved = JSON.parse(readFileSync(h.stateFile, "utf8")) as { keys: { relay: string; host: string }[] };
    assert.deepEqual(saved.keys.filter((k) => k.relay === "gone" || k.host === "olddb"), []);
    // Known positive: the kept, current key is held, and no cycle was refused.
    assert.ok(h.lines.some((l) => l.event === "heliopause.problem.state" && l.host === "web" && l.kind === "silent" && l.active === 1));
    assert.ok(!whats(h).includes("cycle_failed"));
  });

  it("a stale alias leaves scope even on a cycle where its relay is unobservable", async () => {
    writeFileSync(join(dir, "state.json"), PRUNABLE);
    const h = start({ poll: async () => new Map([[RELAY, { ok: false, reason: "unreachable" } as RelayRead]]), allowEmptyState: false });
    await h.watch.tick();
    const removed = h.lines.filter((l) => l.transition === "scope_removed").map((l) => `${String(l.relay)}/${String(l.host)}`);
    assert.deepEqual(removed.sort(), ["gone/web", "za/olddb"]);
    // Known positive: the current key is held, not removed, on that cycle.
    assert.ok(h.lines.some((l) => l.event === "heliopause.problem.state" && l.host === "web" && l.active === 1 && l.observed === false));
  });

  it("a loaded state without the initialized marker gets one", () => {
    writeFileSync(join(dir, "state.json"), serializeWatchState(emptyWatchState()));
    const h = start({ allowEmptyState: false });
    assert.deepEqual(whats(h), ["lock_acquired", "started"]);
    assert.ok(h.calls.includes("writeFileAtomic state.json.initialized"));
    assert.ok(existsSync(`${h.stateFile}.initialized`));
    h.watch.stop();
    // So losing the state file now keeps the watch off, even with the first-start switch on.
    unlinkSync(h.stateFile);
    assert.deepEqual(whats(start({ allowEmptyState: true })), ["lock_acquired", "state_unreadable"]);
  });

  it("lock_held and state_pruned lines need their own counts, and an empty state serializes to no keys", () => {
    assert.deepEqual(emitLines([{ event: "heliopause.problem.watch", what: "lock_held", holderAgeSec: null }]),
      ['{"event":"heliopause.problem.watch","v":1,"what":"lock_held","holderAgeSec":null}']);
    assert.throws(() => emitLines([{ event: "heliopause.problem.watch", what: "lock_held" }]));
    assert.throws(() => emitLines([{ event: "heliopause.problem.watch", what: "state_pruned", unknownKinds: 1 }]));
    assert.deepEqual(serializeWatchState(emptyWatchState()), '{"v":1,"seq":0,"keys":[]}\n');
  });
});

describe("problem watch runner: lock", () => {
  it("a watcher that could not lock retries each cycle and starts once the lock is released", async () => {
    const a = start();
    const b = start();
    assert.deepEqual(whats(b), ["lock_held"]);
    await b.watch.tick();
    assert.deepEqual(whats(b), ["lock_held", "lock_held"]);
    assert.equal(b.polls(), 0);
    a.watch.stop();
    await b.watch.tick();
    assert.deepEqual(whats(b), ["lock_held", "lock_held", "lock_acquired", "started"]);
    assert.equal(b.polls(), 1);
    assert.ok(b.lines.some((l) => l.event === "heliopause.problem.cycle"));
  });

  it("a lock left by a dead owner is not reclaimed and the watch stays off", async () => {
    const stale = JSON.stringify({ pid: 999_999, nonce: "dead", createdAt: NOW.getTime() - 3_600_000 });
    writeFileSync(join(dir, "state.json.lock"), stale);
    const h = start();
    for (let i = 0; i < 3; i++) await h.watch.tick();
    const held = h.lines.filter((l) => l.what === "lock_held");
    // Known positive: the off state is said, every cycle, with the holder's age.
    assert.equal(held.length, 4);
    assert.ok(held.every((l) => l.holderAgeSec === 3600));
    assert.equal(readFileSync(lockPath(h), "utf8"), stale);
    assert.equal(h.polls(), 0);
  });

  it("stop releases only a lock whose owner record is ours", () => {
    const mine = start();
    mine.watch.stop();
    // Known positive: our own lock is removed.
    assert.equal(existsSync(lockPath(mine)), false);
    const h = start();
    writeFileSync(lockPath(h), JSON.stringify({ pid: 1, nonce: "someone-else", createdAt: 0 }));
    h.watch.stop();
    assert.equal(existsSync(lockPath(h)), true);
    assert.ok(h.calls.includes("readFile state.json.lock"));
    assert.ok(!h.calls.includes("unlink state.json.lock"));
  });

  it("no state read or write happens before the lock is acquired", async () => {
    const a = start();
    const b = start();
    await b.watch.tick();
    assert.ok(b.calls.length > 0);
    assert.deepEqual(b.calls.filter((c) => / state\.json(\.initialized)?$/.test(c)), []);
    a.watch.stop();
    await b.watch.tick();
    const acquired = b.calls.indexOf("emit heliopause.problem.watch/lock_acquired");
    const firstState = b.calls.findIndex((c) => / state\.json(\.initialized)?$/.test(c));
    // Known positive: the state was read once the lock was ours.
    assert.ok(firstState > acquired && acquired > 0, b.calls.join("\n"));
  });

  it("a failed owner-record write leaves no lock behind", () => {
    const path = join(dir, "x.lock");
    assert.throws(() => openLockFile(path, "{}", () => { throw new Error("short write"); }), /short write/);
    assert.equal(existsSync(path), false);
    assert.throws(() => start({ fs: { openLock: (p, o) => openLockFile(p, o, () => { throw new Error("short write"); }) } }),
      ProblemWatchLockError);
    assert.deepEqual(readdirSync(dir), []);
    // Known positive: the default writer leaves the record.
    openLockFile(path, "{\"pid\":1}");
    assert.equal(readFileSync(path, "utf8"), "{\"pid\":1}");
  });

  it("a lock error after start says lock_error with its code and keeps retrying", async () => {
    const codes = ["EEXIST", "EACCES", "EIO", "EXDEV", "EEXIST"];
    const h = start({ fs: { openLock: () => { throw Object.assign(new Error("x"), { code: codes.shift() }); } } });
    for (let i = 0; i < 4; i++) await h.watch.tick();
    assert.deepEqual(h.lines.map((l) => [l.what, l.errno ?? null]), [
      ["lock_held", null], ["lock_error", "EACCES"], ["lock_error", "EIO"], ["lock_error", "other"], ["lock_held", null],
    ]);
    assert.ok(!whats(h).includes("cycle_failed"));
    assert.equal(h.polls(), 0);
    assert.throws(() => emitLines([{ event: "heliopause.problem.watch", what: "lock_error" }]));
    assert.throws(() => emitLines([{ event: "heliopause.problem.watch", what: "lock_error", errno: "ENOSPC" as "other" }]));
  });

  it("a lock whose close fails is not left behind", () => {
    const path = join(dir, "y.lock");
    assert.throws(() => openLockFile(path, "{\"pid\":2}", undefined, (fd) => { closeSync(fd); throw new Error("EIO on close"); }), /EIO on close/);
    assert.equal(existsSync(path), false);
    // Known positive: with a close that succeeds the lock stays, holding the record.
    openLockFile(path, "{\"pid\":2}");
    assert.equal(readFileSync(path, "utf8"), "{\"pid\":2}");
  });

  it("a lock error other than EEXIST refuses to start", () => {
    assert.throws(() => start({ stateFile: join(dir, "missing", "state.json") }), (e: unknown) =>
      e instanceof ProblemWatchLockError && /ENOENT/.test(e.message));
    assert.throws(() => start({ fs: { openLock: () => { throw Object.assign(new Error("no"), { code: "EACCES" }); } } }),
      ProblemWatchLockError);
    // Known positive: EEXIST does not throw.
    assert.doesNotThrow(() => start({ fs: { openLock: () => { throw Object.assign(new Error("held"), { code: "EEXIST" }); } } }));
  });

  it("SIGTERM with a poll in flight releases the lock before exit and the late poll writes nothing", async () => {
    const gate = deferred<ReadonlyMap<string, RelayRead>>();
    let n = 0;
    const h = start({ poll: () => (n++ === 0 ? Promise.resolve(SILENT_H1) : gate.promise) });
    await h.watch.tick();
    const inFlight = h.watch.tick();
    const order: string[] = [];
    let exited: number | null = null;
    shutdownManager({
      server: { close: (cb: () => void) => { order.push(`close lock=${existsSync(lockPath(h))}`); cb(); } },
      stopProblemWatch: () => { order.push("stop"); h.watch.stop(); },
    }, (code) => { exited = code; });
    assert.deepEqual(order, ["stop", "close lock=false"]);
    assert.equal(exited, 0);
    const at = h.calls.length;
    gate.resolve(SILENT_H1);
    await inFlight;
    assert.deepEqual(h.calls.slice(at), []);
  });
});

describe("problem watch runner: manifest aliases", () => {
  it("an alias equal to a manifest host label turns the watch off and releases its lock", async () => {
    const colliding = reads(body([], { [H1]: { silent: "yes" }, "WEB.zone-b.example": { silent: "yes" } }));
    let n = 0;
    const h = start({ poll: async () => (n++ === 0 ? CLEAN : colliding) });
    await h.watch.tick();
    // Known positive: the same watch ran a cycle before the manifest named the alias.
    assert.equal(h.lines.filter((l) => l.event === "heliopause.problem.cycle").length, 1);
    const writes = h.calls.filter((c) => c === "writeFileAtomic state.json").length;
    await h.watch.tick();
    assert.equal(whats(h).at(-1), "alias_collision");
    assert.equal(h.calls.filter((c) => c === "writeFileAtomic state.json").length, writes);
    assert.equal(existsSync(lockPath(h)), false);
    await h.watch.tick();
    assert.equal(h.polls(), 2);
  });
});

describe("problem watch runner: env", () => {
  const ALIASES_FILE = "/aliases.json";
  const reader = () => {
    const seen: string[] = [];
    return { seen, read: (p: string) => { seen.push(p); if (p !== ALIASES_FILE) throw Object.assign(new Error("x"), { code: "ENOENT" }); return ALIASES_TEXT; } };
  };
  const on = { HELIOPAUSE_PROBLEM_WATCH_STATE_FILE: "/state/watch.json", HELIOPAUSE_PROBLEM_WATCH_ALIASES_FILE: ALIASES_FILE };

  it("watch is off unless the state file is set", () => {
    for (const env of [{}, { HELIOPAUSE_PROBLEM_WATCH_STATE_FILE: "  " }, { HELIOPAUSE_PROBLEM_WATCH_ALIASES_FILE: ALIASES_FILE }]) {
      const r = reader();
      assert.equal(problemWatchFromEnv(env, [RELAY], 5_000, r.read), null);
      assert.deepEqual(r.seen, []);
    }
    // Known positive: with the state file set, it is on and reads the alias file.
    const r = reader();
    const config = problemWatchFromEnv(on, [RELAY], 5_000, r.read);
    assert.deepEqual(r.seen, [ALIASES_FILE]);
    assert.deepEqual(config && [config.stateFile, config.intervalMs, config.allowEmptyState], ["/state/watch.json", 30_000, false]);
  });

  it("aliases file is required when on", () => {
    const r = reader();
    assert.throws(() => problemWatchFromEnv({ HELIOPAUSE_PROBLEM_WATCH_STATE_FILE: "/s" }, [RELAY], 5_000, r.read), EnvSpecError);
    assert.throws(() => problemWatchFromEnv({ ...on, HELIOPAUSE_PROBLEM_WATCH_ALIASES_FILE: "/nope" }, [RELAY], 5_000, r.read),
      (e: unknown) => e instanceof EnvSpecError && /ENOENT/.test(e.message));
    // A relay in HELIOPAUSE_RELAYS the alias file does not name refuses, as parseWatchAliases does.
    assert.throws(() => problemWatchFromEnv(on, [RELAY, "zone-c.example"], 5_000, r.read), EnvSpecError);
  });

  it("interval bounds refuse NaN, below 10 and above 60", () => {
    const r = reader();
    const at = (v: string, timeout = 5_000) =>
      problemWatchFromEnv({ ...on, HELIOPAUSE_PROBLEM_WATCH_INTERVAL_SEC: v }, [RELAY], timeout, r.read);
    for (const bad of ["abc", "NaN", "9", "61", "10.5"]) assert.throws(() => at(bad), EnvSpecError, bad);
    assert.equal(at("10")?.intervalMs, 10_000);
    assert.equal(at("60")?.intervalMs, 60_000);
    assert.throws(() => at("10", 10_001), /longer than/);
    assert.equal(at("10", 10_000)?.intervalMs, 10_000);
    assert.throws(() => problemWatchFromEnv({ ...on, HELIOPAUSE_PROBLEM_WATCH_ALLOW_EMPTY_STATE: "yes" }, [RELAY], 5_000, r.read), EnvSpecError);
    assert.equal(problemWatchFromEnv({ ...on, HELIOPAUSE_PROBLEM_WATCH_ALLOW_EMPTY_STATE: "1" }, [RELAY], 5_000, r.read)?.allowEmptyState, true);
    assert.equal(problemWatchFromEnv({ ...on, HELIOPAUSE_PROBLEM_WATCH_ALLOW_EMPTY_STATE: "0" }, [RELAY], 5_000, r.read)?.allowEmptyState, false);
  });
});
