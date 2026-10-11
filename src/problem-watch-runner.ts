/**
 * The problem watch's runner (#148 PR 3): an interval, a lock, a state file and stdout around the
 * pure core in `problem-watch.ts`. Off unless `HELIOPAUSE_PROBLEM_WATCH_STATE_FILE` is set.
 *
 * One cycle is poll → `stepWatch` → save the state → write the lines. The save comes first so a
 * restart never re-opens a problem whose `opened` line was already written.
 * @see "persist happens before emit" in problem-watch-runner.test.ts
 *
 * The lock is `<state>.lock`, created with `wx` and holding `{pid, nonce, createdAt}`, the way
 * `withEnrollmentTransaction` does it; unlike that one it is held for the watch's whole life. A lock
 * another owner holds is never reclaimed: the watch stays off, retries each cycle and says
 * `lock_held`. After a crash an operator checks every manager instance and removes the `.lock`.
 * @see "a lock left by a dead owner is not reclaimed and the watch stays off" in problem-watch-runner.test.ts
 */
import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { discardOwnedPath } from "./enrollment-store.ts";
import { boundedInteger, ENV_BOUNDS, EnvSpecError } from "./env-spec.ts";
import {
  emitLines, emptyWatchState, loadWatchState, manifestAliasCollision, parseWatchAliases, serializeWatchState, stepWatch,
  LOCK_ERRNOS, type LockErrno, type RelayRead, type WatchAliases, type WatchEvent, type WatchState, type WatchWhat,
} from "./problem-watch.ts";

export interface ProblemWatchConfig {
  stateFile: string;
  aliases: WatchAliases;
  intervalMs: number;
  /** Start from an empty state when there is no state file and no `<state>.initialized` marker. */
  allowEmptyState: boolean;
}

const STATE_ENV = "HELIOPAUSE_PROBLEM_WATCH_STATE_FILE";
const ALIASES_ENV = "HELIOPAUSE_PROBLEM_WATCH_ALIASES_FILE";
const INTERVAL_ENV = "HELIOPAUSE_PROBLEM_WATCH_INTERVAL_SEC";
const EMPTY_ENV = "HELIOPAUSE_PROBLEM_WATCH_ALLOW_EMPTY_STATE";

const errno = (e: unknown): string => (e as NodeJS.ErrnoException)?.code ?? "error";

/**
 * The watch's configuration, or null when `HELIOPAUSE_PROBLEM_WATCH_STATE_FILE` is unset or blank.
 * Throws `EnvSpecError` for anything the manager should refuse to start with.
 * @see "watch is off unless the state file is set" in problem-watch-runner.test.ts
 */
export function problemWatchFromEnv(
  env: NodeJS.ProcessEnv,
  relayNames: readonly string[],
  relayTimeoutMs: number,
  readFile: (path: string) => string = (path) => readFileSync(path, "utf8"),
): ProblemWatchConfig | null {
  const stateFile = (env[STATE_ENV] ?? "").trim();
  if (stateFile === "") return null;
  const aliasesFile = (env[ALIASES_ENV] ?? "").trim();
  if (aliasesFile === "") throw new EnvSpecError(`${ALIASES_ENV} is required when ${STATE_ENV} is set`);
  const intervalSec = boundedInteger(INTERVAL_ENV, env[INTERVAL_ENV], ENV_BOUNDS[INTERVAL_ENV]);
  if (relayTimeoutMs > intervalSec * 1000) {
    throw new EnvSpecError(
      `HELIOPAUSE_RELAY_TIMEOUT_MS (${relayTimeoutMs}) is longer than ${INTERVAL_ENV} (${intervalSec}s) — one poll could outlast its cycle`,
    );
  }
  const empty = (env[EMPTY_ENV] ?? "").trim();
  if (empty !== "" && empty !== "0" && empty !== "1") throw new EnvSpecError(`${EMPTY_ENV} must be 1 or 0`);
  let text: string;
  try {
    text = readFile(aliasesFile);
  } catch (e) {
    throw new EnvSpecError(`${ALIASES_ENV}: cannot read the file (${errno(e)})`);
  }
  return { stateFile, aliases: parseWatchAliases(text, relayNames), intervalMs: intervalSec * 1000, allowEmptyState: empty === "1" };
}

/** The file system the runner touches. Each member is replaced on its own in tests. */
export interface ProblemWatchFs {
  /** Throws an errno error, `ENOENT` for a missing file. */
  readFile(path: string): string;
  writeFileAtomic(path: string, text: string): void;
  /** Create `path` exclusively and write `owner` into it. Leaves no file behind when it throws. */
  openLock(path: string, owner: string): void;
  unlink(path: string): void;
  rename(from: string, to: string): void;
}

/**
 * `open(wx, 0600)`, then the owner record; a failed write unlinks the inode it created. A failed
 * close after the record is written does not fail the lock: the file holds our record, so the
 * caller owns it and releases it the usual way.
 * @see "a lock whose close fails is still ours, and stop releases it" in problem-watch-runner.test.ts
 */
export function openLockFile(
  path: string,
  owner: string,
  write: (fd: number, text: string) => void = (fd, text) => writeFileSync(fd, text, "utf8"),
  close: (fd: number) => void = closeSync,
): void {
  const fd = openSync(path, "wx", 0o600);
  try {
    write(fd, owner);
  } catch (error) {
    discardOwnedPath(path, fd);
    throw error;
  }
  try { close(fd); } catch { /* the record is written; the lock is ours */ }
}

/** tmp file with `wx` and 0600, fsync, rename over `path`, fsync the directory. */
function writeFileAtomic(path: string, text: string): void {
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  try {
    writeFileSync(tmp, text, { mode: 0o600, flag: "wx" });
    chmodSync(tmp, 0o600);
    const fd = openSync(tmp, "r");
    try { fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, path);
    const directory = openSync(dirname(path), "r");
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } catch (error) {
    try { unlinkSync(tmp); } catch { /* the rename may already have installed it */ }
    throw error;
  }
}

export const defaultProblemWatchFs: ProblemWatchFs = {
  readFile: (path) => readFileSync(path, "utf8"),
  writeFileAtomic,
  openLock: (path, owner) => openLockFile(path, owner),
  unlink: (path) => unlinkSync(path),
  rename: (from, to) => renameSync(from, to),
};

/** A lock failure other than another owner holding it. The manager refuses to start on this. */
export class ProblemWatchLockError extends Error {
  readonly errno: LockErrno;
  constructor(message: string, code: string) {
    super(message);
    this.name = "ProblemWatchLockError";
    this.errno = LOCK_ERRNOS.has(code) ? (code as LockErrno) : "other";
  }
}

export interface ProblemWatchDeps extends ProblemWatchConfig {
  /** One `RelayRead` per configured relay, by name. */
  poll: () => Promise<ReadonlyMap<string, RelayRead>>;
  fs?: Partial<ProblemWatchFs>;
  /** One JSON line per call. */
  emit?: (line: string) => void;
  setInterval?: (fn: () => void, ms: number) => unknown;
  clearInterval?: (handle: unknown) => void;
  now?: () => Date;
}

export interface ProblemWatch {
  /** Synchronous: no state is written and no line emitted after it returns; releases the lock if ours. */
  stop(): void;
  /** What the interval calls. A call while one is running is counted in `skippedTicks` and returns. */
  tick(): Promise<void>;
}

/**
 * Start the watch. Throws `ProblemWatchLockError` when the lock cannot be created for a reason other
 * than `EEXIST`; every other failure turns only the watch off and says why on its own line.
 */
export function startProblemWatch(deps: ProblemWatchDeps): ProblemWatch {
  const fs: ProblemWatchFs = { ...defaultProblemWatchFs, ...deps.fs };
  // Not `writeLog`: that one prefixes `[manager] ` and goes to stderr, and these lines are parsed as JSON.
  const sink = deps.emit ?? ((line: string) => { process.stdout.write(`${line}\n`); });
  const now = deps.now ?? (() => new Date());
  const setTimer = deps.setInterval ?? ((fn: () => void, ms: number) => {
    const t = setInterval(fn, ms);
    t.unref();
    return t;
  });
  const clearTimer = deps.clearInterval ?? ((h: unknown) => clearInterval(h as ReturnType<typeof setInterval>));
  const lockPath = `${deps.stateFile}.lock`;
  const markerPath = `${deps.stateFile}.initialized`;

  let phase: "waiting" | "running" | "off" = "waiting";
  let owner: string | null = null;
  let state: WatchState = emptyWatchState();
  let cycle = 0;
  let skipped = 0;
  let busy = false;
  let timer: unknown;

  const say = (events: WatchEvent[]) => { for (const line of emitLines(events)) sink(line); };
  const watch = (what: WatchWhat): WatchEvent => ({ event: "heliopause.problem.watch", what });

  const holderAgeSec = (): number | null => {
    try {
      const created = (JSON.parse(fs.readFile(lockPath)) as { createdAt?: unknown }).createdAt;
      if (!Number.isSafeInteger(created)) return null;
      const age = Math.floor((now().getTime() - (created as number)) / 1000);
      return age >= 0 ? age : null;
    } catch {
      return null;
    }
  };

  /** True when the lock is now ours, false when another owner holds it. */
  const acquire = (): boolean => {
    const record = JSON.stringify({ pid: process.pid, nonce: randomBytes(16).toString("hex"), createdAt: now().getTime() });
    try {
      fs.openLock(lockPath, record);
    } catch (e) {
      if (errno(e) === "EEXIST") return false;
      throw new ProblemWatchLockError(`${lockPath}: cannot create the problem watch lock (${errno(e)})`, errno(e));
    }
    owner = record;
    return true;
  };

  const release = () => {
    const mine = owner;
    owner = null;
    if (mine === null) return;
    try {
      if (fs.readFile(lockPath) === mine) fs.unlink(lockPath);
    } catch { /* a missing lock needs no release */ }
  };

  const turnOff = (what: WatchWhat) => {
    phase = "off";
    clearTimer(timer);
    release();
    say([watch(what)]);
  };

  const load = (): "ok" | "unreadable" | "write_failed" => {
    let text: string | null = null;
    try {
      text = fs.readFile(deps.stateFile);
    } catch (e) {
      if (errno(e) !== "ENOENT") return "unreadable";
    }
    if (text === null) {
      let marked = true;
      try { fs.readFile(markerPath); } catch (e) { marked = errno(e) !== "ENOENT"; }
      if (marked || !deps.allowEmptyState) return "unreadable";
      try {
        fs.writeFileAtomic(deps.stateFile, serializeWatchState(state));
        fs.writeFileAtomic(markerPath, `${now().toISOString()}\n`);
      } catch {
        return "write_failed";
      }
      say([watch("state_initialized")]);
      return "ok";
    }
    const loaded = loadWatchState(text, deps.aliases);
    if (!loaded.ok) {
      try { fs.rename(deps.stateFile, `${deps.stateFile}.corrupt-${now().getTime()}`); } catch { /* still off */ }
      return "unreadable";
    }
    state = loaded.state;
    // A state file written before the marker existed: mark it now, so losing the file later is not a first start.
    let marked = true;
    try { fs.readFile(markerPath); } catch (e) { marked = errno(e) !== "ENOENT"; }
    if (!marked) {
      try { fs.writeFileAtomic(markerPath, `${now().toISOString()}\n`); } catch { return "write_failed"; }
    }
    if (loaded.unknownKinds > 0 || loaded.staleAliases > 0) {
      say([{ event: "heliopause.problem.watch", what: "state_pruned", unknownKinds: loaded.unknownKinds, staleAliases: loaded.staleAliases }]);
    }
    return "ok";
  };

  const begin = (): boolean => {
    say([watch("lock_acquired")]);
    const loaded = load();
    if (loaded !== "ok") {
      turnOff(loaded === "write_failed" ? "state_write_failed" : "state_unreadable");
      return false;
    }
    phase = "running";
    say([watch("started")]);
    return true;
  };

  const runCycle = async () => {
    const reads = await deps.poll();
    if (phase === "off") return;
    if (manifestAliasCollision(deps.aliases, reads)) {
      turnOff("alias_collision");
      return;
    }
    const step = stepWatch(state, { cycle: cycle + 1, aliases: deps.aliases, relays: reads, skippedTicks: skipped });
    const lines = emitLines([...step.transitions, ...step.snapshot.states, step.snapshot.cycle]);
    try {
      fs.writeFileAtomic(deps.stateFile, serializeWatchState(step.next));
    } catch {
      say([watch("state_write_failed")]);
      return;
    }
    state = step.next;
    cycle += 1;
    skipped = 0;
    for (const line of lines) sink(line);
  };

  const tick = async (): Promise<void> => {
    if (phase === "off") return;
    if (busy) {
      skipped += 1;
      return;
    }
    busy = true;
    try {
      if (phase === "waiting") {
        let got: boolean;
        try {
          got = acquire();
        } catch (e) {
          say([{ event: "heliopause.problem.watch", what: "lock_error", errno: e instanceof ProblemWatchLockError ? e.errno : "other" }]);
          return;
        }
        if (!got) {
          say([{ event: "heliopause.problem.watch", what: "lock_held", holderAgeSec: holderAgeSec() }]);
          return;
        }
        if (!begin()) return;
      }
      await runCycle();
    } catch {
      // `stop()` may have run during the await; the compiler does not see that assignment.
      if ((phase as string) !== "off") say([watch("cycle_failed")]);
    } finally {
      busy = false;
    }
  };

  const held = !acquire();
  timer = setTimer(() => { void tick(); }, deps.intervalMs);
  if (held) say([{ event: "heliopause.problem.watch", what: "lock_held", holderAgeSec: holderAgeSec() }]);
  else begin();

  return {
    stop() {
      if (phase === "off") return;
      phase = "off";
      clearTimer(timer);
      release();
      say([watch("stopped")]);
    },
    tick,
  };
}
