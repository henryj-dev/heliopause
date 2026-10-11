/**
 * The manager's problem watch, pure core (#148 PR 2).
 *
 * Reads each relay's `/status`, decides when a problem has opened and when it has resolved, and
 * shapes the lines a log pipeline turns into one email per opening and one per resolution. No clock,
 * timer, file or network here: the cycle number and every relay answer are inputs. Running it on an
 * interval, persisting `WatchState`, the lock and the env are the runner's (PR 3).
 *
 * What `emitLines` writes is aliases, reserved names, kind names, enums, booleans and integers. A
 * relay name, a host id, a finding's `value` and anything else a relay sends are not copied into a
 * line. @see "carries only allowed fields, no id, address, value or detail from the relay" in problem-watch.test.ts
 *
 * A host without an alias is counted in one `unaliased-hosts` problem per relay; its own problems do
 * not reach a line, so they reach no email — only the console shows them.
 *
 * The three event-shaped contradictions take a second path (#148 PR 4): no opened or resolved, one
 * `heliopause.problem.event` line when the relay's count for that host and kind goes up after
 * `EVENT_QUIET_CYCLES` cycles without going up.
 */
import { EnvSpecError } from "./env-spec.ts";
import type { EventKind, ProblemEvaluation, ProblemKind } from "./relay.ts";

/** Consecutive counted observations that open or resolve a problem (#148: 30 s, twice). */
export const CONFIRM_CYCLES = 2;
/** Cycles a key keeps emitting `active: 0` after it resolves or leaves scope, then is dropped. */
export const ZERO_TAIL_CYCLES = 20;
/** Cycles an event count must stay put before its next increase raises a new event (#148: 10 × 30 s). */
export const EVENT_QUIET_CYCLES = 10;

// Narrowing this makes `loadWatchState` treat existing state files as broken: it needs a state file migration.
const ALIAS_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const ALIASES_ENV = "HELIOPAUSE_PROBLEM_WATCH_ALIASES_FILE";

/** Every relay kind. A `Record` so the compiler refuses one missing from or added to `ProblemKind`. */
const RELAY_KINDS: Record<ProblemKind, true> = {
  "rolled-back": true,
  "refused-generation": true,
  "table-absent": true,
  "ruleset-changed": true,
  "published-ports": true,
  "cilium-nodeport-unrestricted": true,
  "contradiction-artifact-hash-changed": true,
  "contradiction-artifact-hash-wrong": true,
  "contradiction-unknown-generation": true,
  "contradiction-kernel-unchanged": true,
  "unexpected-filters": true,
  "workload-unreported": true,
  "workload-not-confirmed": true,
  "workload-objects-missing": true,
  "workload-document-mismatch": true,
  "agent-version-behind": true,
  "break-glass-authorization": true,
  "artifact-trust-unreadable": true,
  "authorization-unnamed": true,
  "never-reported": true,
  silent: true,
  "trust-ring-split": true,
};
const KINDS = Object.keys(RELAY_KINDS) as ProblemKind[];

/** The relay's `EVENT_KINDS`, as a `Record` for the same reason as `RELAY_KINDS`. */
const EVENT_KIND_RECORD: Record<EventKind, true> = {
  "contradiction-artifact-hash-changed": true,
  "contradiction-unknown-generation": true,
  "contradiction-kernel-unchanged": true,
};
const EVENT_KINDS = Object.keys(EVENT_KIND_RECORD) as EventKind[];
const EVENT_KIND_SET = new Set<string>(EVENT_KINDS);

/** Problems the watch raises itself, about a relay or about its own configuration. */
export type WatchKind = ProblemKind | "relay-unobservable" | "relay-not-configured" | "unaliased-hosts";
const WATCH_KINDS = new Set<string>([...KINDS, "relay-unobservable", "relay-not-configured", "unaliased-hosts"]);

/** Host names that are not a host: the fleet as a whole, and the relay itself. */
export const FLEET_HOST = "_fleet";
export const RELAY_HOST = "_relay";
const RESERVED_HOSTS = new Set([FLEET_HOST, RELAY_HOST]);

const EVALUATIONS = new Set<string>(["yes", "no-resolve", "no"]);

// ## Aliases

export interface WatchAliases {
  /** Expected relays — the file's own list, not `HELIOPAUSE_RELAYS` — to their alias. */
  relays: ReadonlyMap<string, string>;
  /** Per relay name, host id → alias. A host absent here is counted, never named. */
  hosts: ReadonlyMap<string, ReadonlyMap<string, string>>;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** Every dot-separated label of `name`, and `name` itself, lowercased. */
function labelsOf(name: string): string[] {
  const lower = name.toLowerCase();
  return [lower, ...lower.split(".")];
}

/**
 * Parse the alias file: `{ relays: { name: alias }, hosts: { relayName: { hostId: alias } } }`.
 * `configuredRelays` is the names from `HELIOPAUSE_RELAYS`; every one of them needs an alias. An alias
 * is compared with the names written in this file and in `HELIOPAUSE_RELAYS`, not with a manifest.
 *
 * Refusals name positions, never an id or alias: an alias rejected for equalling a real name would
 * otherwise print that name.
 */
export function parseWatchAliases(text: string, configuredRelays: readonly string[]): WatchAliases {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new EnvSpecError(`${ALIASES_ENV}: not valid JSON`);
  }
  if (!isObject(doc)) throw new EnvSpecError(`${ALIASES_ENV}: expected an object`);
  for (const key of Object.keys(doc)) {
    if (key !== "relays" && key !== "hosts") throw new EnvSpecError(`${ALIASES_ENV}: unknown top-level field`);
  }
  const relaysDoc = doc.relays;
  const hostsDoc = doc.hosts ?? {};
  if (!isObject(relaysDoc)) throw new EnvSpecError(`${ALIASES_ENV}: "relays" must be an object of name → alias`);
  if (!isObject(hostsDoc)) throw new EnvSpecError(`${ALIASES_ENV}: "hosts" must be an object of relay → { host → alias }`);

  const relayNames = Object.keys(relaysDoc);
  const realLabels = new Set<string>();
  for (const name of [...relayNames, ...configuredRelays]) for (const l of labelsOf(name)) realLabels.add(l);
  for (const hostMap of Object.values(hostsDoc)) {
    if (!isObject(hostMap)) continue; // refused below, with its position
    for (const id of Object.keys(hostMap)) for (const l of labelsOf(id)) realLabels.add(l);
  }

  const checkAlias = (alias: unknown, where: string): string => {
    if (typeof alias === "string" && alias.startsWith("_")) {
      throw new EnvSpecError(`${ALIASES_ENV}: ${where} starts with "_", which is reserved`);
    }
    if (typeof alias !== "string" || !ALIAS_RE.test(alias)) {
      throw new EnvSpecError(`${ALIASES_ENV}: ${where} must match ${ALIAS_RE.source}`);
    }
    if (realLabels.has(alias)) {
      throw new EnvSpecError(`${ALIASES_ENV}: ${where} equals a label of a name in this file or in HELIOPAUSE_RELAYS`);
    }
    return alias;
  };

  const relays = new Map<string, string>();
  const relayAliasesSeen = new Set<string>();
  relayNames.forEach((name, i) => {
    const alias = checkAlias(relaysDoc[name], `relay entry ${i + 1}`);
    if (relayAliasesSeen.has(alias)) throw new EnvSpecError(`${ALIASES_ENV}: relay entry ${i + 1} repeats another relay's alias`);
    relayAliasesSeen.add(alias);
    relays.set(name, alias);
  });
  configuredRelays.forEach((name, i) => {
    if (!relays.has(name)) throw new EnvSpecError(`${ALIASES_ENV}: relay ${i + 1} of HELIOPAUSE_RELAYS has no alias`);
  });

  const hosts = new Map<string, Map<string, string>>();
  Object.keys(hostsDoc).forEach((relayName, i) => {
    const hostMap = hostsDoc[relayName];
    if (!relays.has(relayName)) throw new EnvSpecError(`${ALIASES_ENV}: hosts entry ${i + 1} names a relay not in "relays"`);
    if (!isObject(hostMap)) throw new EnvSpecError(`${ALIASES_ENV}: hosts entry ${i + 1} must be an object of host → alias`);
    const out = new Map<string, string>();
    const seen = new Set<string>();
    Object.keys(hostMap).forEach((id, j) => {
      const alias = checkAlias(hostMap[id], `host ${j + 1} of hosts entry ${i + 1}`);
      if (seen.has(alias)) throw new EnvSpecError(`${ALIASES_ENV}: host ${j + 1} of hosts entry ${i + 1} repeats an alias under the same relay`);
      seen.add(alias);
      out.set(id, alias);
    });
    hosts.set(relayName, out);
  });
  return { relays, hosts };
}

// ## One relay's answer

export type RelayUnobservable = "unreachable" | "schema" | "no-manifest";

export type RelayRead =
  | {
    ok: true;
    findings: { kind: ProblemKind; host: string | null; count: number }[];
    /** Manifest host → kind → evaluation, as the relay sent it. A missing kind is not `yes`. */
    evaluated: Map<string, Map<ProblemKind, ProblemEvaluation>>;
    fleetEvaluated: Map<ProblemKind, ProblemEvaluation>;
    /** Distinct kind names this build does not know, skipped in `findings` and both evaluations. */
    unknownKinds: number;
    /** Null from a relay without `events`, or one that did not say when it started: the event path is then off. */
    eventCounts: RelayEventCounts | null;
  }
  | { ok: false; reason: RelayUnobservable };

/** A relay's event counts since `startedAt`, and which of its manifest hosts it currently hears, by host id. */
export interface RelayEventCounts {
  startedAt: string;
  counts: Map<string, Map<EventKind, number>>;
  observable: Map<string, boolean>;
}

const SCHEMA = { ok: false, reason: "schema" } as const;

function readEvaluations(v: unknown, unknown: Set<string>): Map<ProblemKind, ProblemEvaluation> | null {
  if (!isObject(v)) return null;
  const out = new Map<ProblemKind, ProblemEvaluation>();
  for (const [kind, ev] of Object.entries(v)) {
    if (!Object.hasOwn(RELAY_KINDS, kind)) {
      unknown.add(kind);
      continue;
    }
    if (typeof ev !== "string" || !EVALUATIONS.has(ev)) return null;
    out.set(kind as ProblemKind, ev as ProblemEvaluation);
  }
  return out;
}

/**
 * Check a relay `/status` body for the fields the watch reads. A body without `findings` — a relay
 * older than #148 — is `schema`, not an empty fleet; `observability.manifest: false` is `no-manifest`.
 * A kind this build does not know — a relay deployed ahead of the manager — is skipped and counted:
 * only known kinds are walked, so a skipped one can neither open nor resolve anything.
 * @see "an unknown kind is skipped, not a reason to call the relay unobservable" in problem-watch.test.ts
 */
export function readRelayStatus(body: unknown): RelayRead {
  if (!isObject(body)) return SCHEMA;
  const obs = body.observability;
  if (!isObject(obs) || typeof obs.manifest !== "boolean") return SCHEMA;
  if (!Array.isArray(body.findings) || !isObject(body.evaluated)) return SCHEMA;

  const unknown = new Set<string>();
  const findings: { kind: ProblemKind; host: string | null; count: number }[] = [];
  for (const f of body.findings) {
    if (!isObject(f)) return SCHEMA;
    const { kind, host, count } = f;
    if (typeof kind !== "string") return SCHEMA;
    if (!Object.hasOwn(RELAY_KINDS, kind)) {
      unknown.add(kind);
      continue;
    }
    if (host !== null && typeof host !== "string") return SCHEMA;
    if (!Number.isSafeInteger(count) || (count as number) < 0) return SCHEMA;
    findings.push({ kind: kind as ProblemKind, host, count: count as number });
  }
  const evaluated = new Map<string, Map<ProblemKind, ProblemEvaluation>>();
  for (const [host, evs] of Object.entries(body.evaluated)) {
    const read = readEvaluations(evs, unknown);
    if (!read) return SCHEMA;
    evaluated.set(host, read);
  }
  const fleetEvaluated = readEvaluations(body.fleetEvaluated, unknown);
  if (!fleetEvaluated) return SCHEMA;
  const eventCounts = readEventCounts(body, unknown);
  if (eventCounts === "schema") return SCHEMA;
  if (!obs.manifest) return { ok: false, reason: "no-manifest" };
  return { ok: true, findings, evaluated, fleetEvaluated, unknownKinds: unknown.size, eventCounts };
}

/**
 * `events`, `processStartedAt` and `hostObservable` together. A body without `events` is a relay
 * older than them: null, and the state path is unaffected. An event kind this build does not know is
 * skipped and counted, as in `findings`.
 * @see "a relay without events turns only the event path off" in problem-watch.test.ts
 */
function readEventCounts(body: Record<string, unknown>, unknown: Set<string>): RelayEventCounts | null | "schema" {
  if (body.events === undefined) return null;
  const started = body.processStartedAt;
  if (!Array.isArray(body.events) || !isObject(body.hostObservable) || (started !== null && typeof started !== "string")) {
    return "schema";
  }
  const observable = new Map<string, boolean>();
  for (const [host, b] of Object.entries(body.hostObservable)) {
    if (typeof b !== "boolean") return "schema";
    observable.set(host, b);
  }
  const counts = new Map<string, Map<EventKind, number>>();
  for (const e of body.events) {
    if (!isObject(e)) return "schema";
    const { kind, host, count } = e;
    if (typeof kind !== "string" || typeof host !== "string") return "schema";
    if (!EVENT_KIND_SET.has(kind)) {
      unknown.add(kind);
      continue;
    }
    if (!Number.isSafeInteger(count) || (count as number) < 0) return "schema";
    const byKind = counts.get(host) ?? new Map<EventKind, number>();
    if (byKind.has(kind as EventKind)) return "schema";
    byKind.set(kind as EventKind, count as number);
    counts.set(host, byKind);
  }
  return started === null ? null : { startedAt: started, counts, observable };
}

// ## The state machine

export interface KeyState {
  relay: string;
  host: string;
  kind: WatchKind;
  active: boolean;
  openStreak: number;
  resolveStreak: number;
  /** The count last observed while active; 0 once inactive. */
  count: number;
  /** Cycles of `active: 0` still to emit. */
  tail: number;
}

/** One (relay alias, host alias, event kind): the relay's count last read, and cycles since it last went up. */
export interface EventKeyState {
  relay: string;
  host: string;
  kind: EventKind;
  count: number;
  /** Capped at `EVENT_QUIET_CYCLES`; at the cap the next increase raises an event. */
  quiet: number;
}

export interface WatchState {
  /** One sequence for transition and event lines. */
  seq: number;
  keys: Record<string, KeyState>;
  /** Relay alias → the `processStartedAt` its stored event counts were read under. */
  eventRelays: Record<string, string>;
  events: Record<string, EventKeyState>;
}

export const emptyWatchState = (): WatchState => ({ seq: 0, keys: {}, eventRelays: {}, events: {} });

export interface WatchCycle {
  cycle: number;
  aliases: WatchAliases;
  /** One answer per relay in `HELIOPAUSE_RELAYS`, by name. A relay the aliases expect but this lacks is not configured. */
  relays: ReadonlyMap<string, RelayRead>;
  /** Ticks the runner skipped since the last cycle because one was still running. */
  skippedTicks?: number;
}

export type Transition = "opened" | "resolved" | "scope_removed";
export type CycleReason = RelayUnobservable | "not-configured";

export interface StateLine {
  event: "heliopause.problem.state";
  relay: string; host: string; kind: WatchKind; active: 0 | 1; count: number; observed: boolean; cycle: number;
}
export interface TransitionLine {
  event: "heliopause.problem.transition";
  seq: number; transition: Transition; relay: string; host: string; kind: WatchKind; count: number;
}
export interface EventLine {
  event: "heliopause.problem.event";
  /** `count`: how much the relay's count went up on the cycle that raised this line. */
  seq: number; relay: string; host: string; kind: EventKind; count: number;
}
export interface CycleLine {
  event: "heliopause.problem.cycle";
  cycle: number;
  /** `events`: whether this relay's answer carried event counts this cycle — false turns the event path off for it. */
  relays: { relay: string; observed: boolean; reason: CycleReason | null; active: number; events: boolean }[];
  unaliasedHosts: number;
  /** Summed over relays: distinct kind names each relay sent that this build does not know. */
  unknownKinds: number;
  skippedTicks: number;
}
export type WatchWhat =
  | "started" | "stopped" | "state_initialized" | "state_unreadable" | "state_write_failed"
  | "lock_held" | "lock_acquired" | "lock_error" | "state_pruned" | "alias_collision" | "cycle_failed";
export interface WatchLine {
  event: "heliopause.problem.watch";
  what: WatchWhat;
  /** `lock_held` only: seconds since the holder's owner record was written, or null when unreadable. */
  holderAgeSec?: number | null;
  /** `state_pruned` only: loaded keys dropped for a kind this build does not know. */
  unknownKinds?: number;
  /**
   * `state_pruned` only: loaded problem keys, event keys and `eventRelays` entries whose relay or host
   * alias the alias file no longer has. Kept; a problem key is taken out of scope next cycle with
   * `scope_removed`, an event key or entry is deleted without a line.
   */
  staleAliases?: number;
  /** `lock_error` only: the error code, or `other`. */
  errno?: LockErrno;
}
export type LockErrno = "EACCES" | "ENOENT" | "EROFS" | "EPERM" | "EIO" | "other";
export const LOCK_ERRNOS = new Set<string>(["EACCES", "ENOENT", "EROFS", "EPERM", "EIO"]);
export type WatchEvent = StateLine | TransitionLine | EventLine | CycleLine | WatchLine;

export interface StepResult {
  next: WatchState;
  transitions: TransitionLine[];
  /** After every transition of the cycle, so `seq` rises in the order the runner writes them. */
  events: EventLine[];
  snapshot: { states: StateLine[]; cycle: CycleLine };
}

/** The identity of one problem: (relay alias, host alias, kind). */
export const keyOf = (relay: string, host: string, kind: string) => JSON.stringify([relay, host, kind]);

interface Observation { relay: string; host: string; kind: WatchKind; present: boolean; count: number; ev: ProblemEvaluation }

/**
 * One cycle. Keyed by (relay alias, host alias, kind). A kind's `evaluated` decides what its
 * observation may count: `yes` — presence and absence; `no-resolve` — presence only; `no` or
 * missing — neither. A counted observation of the other sign, or one not counted, restarts the
 * streak; the state is held. `CONFIRM_CYCLES` counted observations in a row open or resolve.
 *
 * @see "an unobservable cycle restarts the streak in both directions" in problem-watch.test.ts
 * @see "a kind missing from evaluated is treated as not evaluated" in problem-watch.test.ts
 * @see "this module makes a zero in two ways: a resolution's tail and a scope removal's tail" in problem-watch.test.ts
 */
export function stepWatch(prev: WatchState, input: WatchCycle): StepResult {
  const next: WatchState = structuredClone(prev);
  const transitions: TransitionLine[] = [];
  const observed = new Set<string>();
  const handled = new Set<string>();
  const cycleRelays: CycleLine["relays"] = [];
  let unaliasedTotal = 0;
  let unknownKindsTotal = 0;

  const emit = (rec: KeyState, transition: Transition) => {
    next.seq += 1;
    transitions.push({
      event: "heliopause.problem.transition", seq: next.seq, transition,
      relay: rec.relay, host: rec.host, kind: rec.kind, count: rec.count,
    });
  };

  const apply = (o: Observation) => {
    const k = keyOf(o.relay, o.host, o.kind);
    handled.add(k);
    let rec = next.keys[k];
    if (!rec) {
      if (!o.present || o.ev === "no") return;
      rec = next.keys[k] = {
        relay: o.relay, host: o.host, kind: o.kind, active: false, openStreak: 0, resolveStreak: 0, count: 0, tail: 0,
      };
    }
    if (o.ev === "no" || (!o.present && o.ev === "no-resolve")) {
      rec.openStreak = 0;
      rec.resolveStreak = 0;
      return;
    }
    observed.add(k);
    if (o.present) {
      rec.resolveStreak = 0;
      rec.openStreak = Math.min(rec.openStreak + 1, CONFIRM_CYCLES);
      if (rec.active) rec.count = o.count;
      else if (rec.openStreak >= CONFIRM_CYCLES) {
        rec.active = true;
        rec.count = o.count;
        rec.tail = 0;
        emit(rec, "opened");
      }
    } else {
      rec.openStreak = 0;
      rec.resolveStreak = Math.min(rec.resolveStreak + 1, CONFIRM_CYCLES);
      if (rec.active && rec.resolveStreak >= CONFIRM_CYCLES) {
        rec.active = false;
        rec.count = 0;
        rec.tail = ZERO_TAIL_CYCLES;
        emit(rec, "resolved");
      }
    }
  };

  const hold = (k: string, rec: KeyState) => {
    handled.add(k);
    rec.openStreak = 0;
    rec.resolveStreak = 0;
  };

  const removeFromScope = (k: string, rec: KeyState) => {
    handled.add(k);
    rec.openStreak = 0;
    rec.resolveStreak = 0;
    if (rec.active) {
      rec.active = false;
      rec.count = 0;
      rec.tail = ZERO_TAIL_CYCLES;
      emit(rec, "scope_removed");
    }
  };

  const expectedAliases = new Set(input.aliases.relays.values());
  for (const [name, relay] of input.aliases.relays) {
    const poll = input.relays.get(name);
    const hostAliases = input.aliases.hosts.get(name) ?? new Map<string, string>();
    let inScope: Set<string>;
    if (!poll || !poll.ok) {
      apply({ relay, host: RELAY_HOST, kind: "relay-not-configured", present: !poll, count: poll ? 0 : 1, ev: "yes" });
      if (poll) apply({ relay, host: RELAY_HOST, kind: "relay-unobservable", present: true, count: 1, ev: "yes" });
      inScope = new Set(hostAliases.values());
      cycleRelays.push({ relay, observed: false, reason: poll ? poll.reason : "not-configured", active: 0, events: false });
    } else {
      apply({ relay, host: RELAY_HOST, kind: "relay-not-configured", present: false, count: 0, ev: "yes" });
      apply({ relay, host: RELAY_HOST, kind: "relay-unobservable", present: false, count: 0, ev: "yes" });
      inScope = new Set();
      let unaliased = 0;
      for (const [hostId, evs] of poll.evaluated) {
        const alias = hostAliases.get(hostId);
        if (alias === undefined) {
          unaliased += 1;
          continue;
        }
        inScope.add(alias);
        for (const kind of KINDS) {
          const f = poll.findings.find((x) => x.kind === kind && x.host === hostId);
          apply({ relay, host: alias, kind, present: !!f, count: f?.count ?? 0, ev: evs.get(kind) ?? "no" });
        }
      }
      for (const kind of KINDS) {
        const f = poll.findings.find((x) => x.kind === kind && x.host === null);
        apply({ relay, host: FLEET_HOST, kind, present: !!f, count: f?.count ?? 0, ev: poll.fleetEvaluated.get(kind) ?? "no" });
      }
      apply({ relay, host: FLEET_HOST, kind: "unaliased-hosts", present: unaliased > 0, count: unaliased, ev: "yes" });
      unaliasedTotal += unaliased;
      unknownKindsTotal += poll.unknownKinds;
      cycleRelays.push({ relay, observed: true, reason: null, active: 0, events: poll.eventCounts !== null });
    }
    for (const [k, rec] of Object.entries(next.keys)) {
      if (rec.relay !== relay || handled.has(k)) continue;
      if (RESERVED_HOSTS.has(rec.host) || inScope.has(rec.host)) hold(k, rec);
      else removeFromScope(k, rec);
    }
  }
  for (const [k, rec] of Object.entries(next.keys)) {
    if (!expectedAliases.has(rec.relay)) removeFromScope(k, rec);
  }
  const events = stepEvents(next, input, expectedAliases);

  const states: StateLine[] = [];
  for (const [k, rec] of Object.entries(next.keys).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (rec.active || rec.tail > 0) {
      states.push({
        event: "heliopause.problem.state", relay: rec.relay, host: rec.host, kind: rec.kind,
        active: rec.active ? 1 : 0, count: rec.active ? rec.count : 0, observed: observed.has(k), cycle: input.cycle,
      });
    }
    if (!rec.active && rec.tail > 0) rec.tail -= 1;
    if (!rec.active && rec.tail === 0 && rec.openStreak === 0) delete next.keys[k];
  }
  for (const r of cycleRelays) {
    r.active = Object.values(next.keys).filter((rec) => rec.relay === r.relay && rec.active).length;
  }

  return {
    next,
    transitions,
    events,
    snapshot: {
      states,
      cycle: {
        event: "heliopause.problem.cycle", cycle: input.cycle, relays: cycleRelays,
        unaliasedHosts: unaliasedTotal, unknownKinds: unknownKindsTotal, skippedTicks: input.skippedTicks ?? 0,
      },
    },
  };
}

/**
 * The event path, for every relay whose answer carries event counts. Counts are compared with the
 * stored ones under the same relay `processStartedAt`; under a different one — a relay restart, or
 * this watch's first look at the relay — they are only stored, so beats between the last read and the
 * restart are missed. A key seen for the first time is stored the same way. On a host the relay does
 * not currently hear, an increase is stored and not raised, and that cycle counts as a quiet one. A
 * count lower than the stored one under the same process is ignored: the stored count and the quiet
 * run stay, so only a rise above the stored count is an increase. Mutates `next`.
 *
 * @see "a count that falls under the same process is ignored; only a rise above the stored count raises" in problem-watch.test.ts
 * @see "a relay restart in the middle of a run raises no second event" in problem-watch.test.ts
 * @see "an increase raises one event, and a run of increases raises one" in problem-watch.test.ts
 * @see "an increase after EVENT_QUIET_CYCLES quiet cycles raises a new event" in problem-watch.test.ts
 * @see "a relay restart re-baselines the counts and raises nothing, and the next increase raises" in problem-watch.test.ts
 * @see "an increase on a cycle where the host is unobservable is stored, not raised" in problem-watch.test.ts
 */
function stepEvents(next: WatchState, input: WatchCycle, expectedAliases: ReadonlySet<string>): EventLine[] {
  const lines: EventLine[] = [];
  for (const relay of Object.keys(next.eventRelays)) if (!expectedAliases.has(relay)) delete next.eventRelays[relay];
  for (const [k, rec] of Object.entries(next.events)) if (!expectedAliases.has(rec.relay)) delete next.events[k];
  for (const [name, relay] of input.aliases.relays) {
    const poll = input.relays.get(name);
    if (!poll?.ok || !poll.eventCounts) continue;
    const { startedAt, counts, observable } = poll.eventCounts;
    const sameProcess = Object.hasOwn(next.eventRelays, relay) && next.eventRelays[relay] === startedAt;
    next.eventRelays[relay] = startedAt;
    const hostAliases = input.aliases.hosts.get(name) ?? new Map<string, string>();
    const seen = new Set<string>();
    for (const [hostId, hostObservable] of observable) {
      const host = hostAliases.get(hostId);
      if (host === undefined) continue;
      for (const kind of EVENT_KINDS) {
        const k = keyOf(relay, host, kind);
        seen.add(k);
        const now = counts.get(hostId)?.get(kind) ?? 0;
        const rec = next.events[k];
        if (!rec) {
          next.events[k] = { relay, host, kind, count: now, quiet: EVENT_QUIET_CYCLES };
          continue;
        }
        // A lower count under the same process is no reading to compare with: keep the stored one and the quiet run.
        if (sameProcess && now < rec.count) continue;
        const increase = sameProcess && hostObservable && now > rec.count ? now - rec.count : 0;
        rec.count = now;
        if (increase === 0) {
          rec.quiet = Math.min(rec.quiet + 1, EVENT_QUIET_CYCLES);
          continue;
        }
        if (rec.quiet >= EVENT_QUIET_CYCLES) {
          next.seq += 1;
          lines.push({ event: "heliopause.problem.event", seq: next.seq, relay, host, kind, count: increase });
        }
        rec.quiet = 0;
      }
    }
    for (const [k, rec] of Object.entries(next.events)) if (rec.relay === relay && !seen.has(k)) delete next.events[k];
  }
  return lines;
}

// ## Output

const TRANSITIONS = new Set<string>(["opened", "resolved", "scope_removed"]);
const LOCK_ERRNO_VALUES = new Set<string>([...LOCK_ERRNOS, "other"]);
const REASONS = new Set<string>(["unreachable", "schema", "no-manifest", "not-configured"]);
const WHATS = new Set<string>([
  "started", "stopped", "state_initialized", "state_unreadable", "state_write_failed",
  "lock_held", "lock_acquired", "lock_error", "state_pruned", "alias_collision", "cycle_failed",
]);

class OutOfSchema extends Error {
  constructor(event: string) {
    super(`problem-watch: refusing to emit a ${event} line with a field outside its schema`);
  }
}

const count = (v: unknown, event: string): number => {
  if (!Number.isSafeInteger(v) || (v as number) < 0) throw new OutOfSchema(event);
  return v as number;
};
const oneOf = (v: unknown, allowed: Set<string>, event: string): string => {
  if (typeof v !== "string" || !allowed.has(v)) throw new OutOfSchema(event);
  return v;
};
const relayAlias = (v: unknown, event: string): string => {
  if (typeof v !== "string" || !ALIAS_RE.test(v)) throw new OutOfSchema(event);
  return v;
};
const hostAlias = (v: unknown, event: string): string => {
  if (typeof v !== "string" || !(ALIAS_RE.test(v) || RESERVED_HOSTS.has(v))) throw new OutOfSchema(event);
  return v;
};
const bool = (v: unknown, event: string): boolean => {
  if (typeof v !== "boolean") throw new OutOfSchema(event);
  return v;
};

/**
 * One JSON line per event, rebuilt field by field: only the fields of its event type, and only
 * aliases, reserved names, kinds, enums, booleans and non-negative integers. Anything else throws
 * without quoting the value.
 */
export function emitLines(events: readonly WatchEvent[]): string[] {
  return events.map((e) => {
    const event = (e as { event?: unknown }).event;
    switch (event) {
      case "heliopause.problem.state": {
        const s = e as StateLine;
        const active = count(s.active, event);
        if (active > 1) throw new OutOfSchema(event);
        return JSON.stringify({
          event, v: 1, relay: relayAlias(s.relay, event), host: hostAlias(s.host, event),
          kind: oneOf(s.kind, WATCH_KINDS, event), active, count: count(s.count, event),
          observed: bool(s.observed, event), cycle: count(s.cycle, event),
        });
      }
      case "heliopause.problem.transition": {
        const t = e as TransitionLine;
        return JSON.stringify({
          event, v: 1, seq: count(t.seq, event), transition: oneOf(t.transition, TRANSITIONS, event),
          relay: relayAlias(t.relay, event), host: hostAlias(t.host, event),
          kind: oneOf(t.kind, WATCH_KINDS, event), count: count(t.count, event),
        });
      }
      case "heliopause.problem.event": {
        const x = e as EventLine;
        return JSON.stringify({
          event, v: 1, seq: count(x.seq, event), relay: relayAlias(x.relay, event),
          host: relayAlias(x.host, event), kind: oneOf(x.kind, EVENT_KIND_SET, event), count: count(x.count, event),
        });
      }
      case "heliopause.problem.cycle": {
        const c = e as CycleLine;
        if (!Array.isArray(c.relays)) throw new OutOfSchema(event);
        return JSON.stringify({
          event, v: 1, cycle: count(c.cycle, event),
          relays: c.relays.map((r) => ({
            relay: relayAlias(r.relay, event), observed: bool(r.observed, event),
            reason: r.reason === null ? null : oneOf(r.reason, REASONS, event), active: count(r.active, event),
            events: bool(r.events, event),
          })),
          unaliasedHosts: count(c.unaliasedHosts, event), unknownKinds: count(c.unknownKinds, event),
          skippedTicks: count(c.skippedTicks, event),
        });
      }
      case "heliopause.problem.watch": {
        const w = e as WatchLine;
        const what = oneOf(w.what, WHATS, event);
        if (what === "lock_held") {
          return JSON.stringify({ event, v: 1, what, holderAgeSec: w.holderAgeSec === null ? null : count(w.holderAgeSec, event) });
        }
        if (what === "lock_error") {
          return JSON.stringify({ event, v: 1, what, errno: oneOf(w.errno, LOCK_ERRNO_VALUES, event) });
        }
        if (what === "state_pruned") {
          return JSON.stringify({
            event, v: 1, what, unknownKinds: count(w.unknownKinds, event), staleAliases: count(w.staleAliases, event),
          });
        }
        return JSON.stringify({ event, v: 1, what });
      }
      default:
        throw new OutOfSchema("problem-watch");
    }
  });
}

// ## Persisted state

// Version 2 adds `eventRelays` and `events`. A version 1 file loads with neither.
//
// Rolling back: the #173 manager (a308ebf) reads only version 1 with exactly its three fields, so it
// moves a version 2 file to `.corrupt-<ms>` and turns the watch off. To run the watch on that manager
// again, delete the state file and `<state>.initialized` and start it once with
// HELIOPAUSE_PROBLEM_WATCH_ALLOW_EMPTY_STATE=1.
//
// From version 2 on, a top-level field this loader does not know is ignored, so a later version that
// only adds fields does not lock this one out; a `v` above `STATE_VERSION` is still refused, since its
// fields may mean something else.
const STATE_VERSION = 2;

/** The state file's text: every key as a record, so the loader re-derives each key from its fields. */
export function serializeWatchState(state: WatchState): string {
  return JSON.stringify({
    v: STATE_VERSION, seq: state.seq, keys: Object.values(state.keys),
    eventRelays: state.eventRelays, events: Object.values(state.events),
  }) + "\n";
}

export type LoadedWatchState =
  | { ok: true; state: WatchState; unknownKinds: number; staleAliases: number }
  | { ok: false };

const bounded = (v: unknown, max: number): boolean => Number.isSafeInteger(v) && (v as number) >= 0 && (v as number) <= max;

/**
 * Read a state file's text against the current alias file. Text that is not this shape is
 * `ok: false`. A key whose relay or host alias the current alias file does not have is kept and
 * counted: `stepWatch` takes it out of scope on the next cycle, with `scope_removed` and the zero tail.
 * A key whose kind this build does not know is dropped and counted — kept, it would be held forever
 * and `emitLines` would refuse the cycle — so its resolution, after a downgrade, rests on the series
 * disappearing. Event keys and `eventRelays` are read under the same rules.
 * @see "state loader drops unknown kinds and keeps stale aliases for scope removal" in problem-watch-runner.test.ts
 */
export function loadWatchState(text: string, aliases: WatchAliases): LoadedWatchState {
  let doc: unknown;
  try { doc = JSON.parse(text); } catch { return { ok: false }; }
  if (!isObject(doc) || (doc.v !== 1 && doc.v !== STATE_VERSION) || !Number.isSafeInteger(doc.seq) || (doc.seq as number) < 0
    || !Array.isArray(doc.keys) || (doc.v === 1 && Object.keys(doc).length !== 3)) return { ok: false };
  const relayByAlias = new Map([...aliases.relays].map(([name, alias]) => [alias, name]));
  const state: WatchState = { seq: doc.seq as number, keys: {}, eventRelays: {}, events: {} };
  let unknownKinds = 0;
  let staleAliases = 0;
  /** Whether a relay and host alias pair is in the current alias file; reserved hosts count as in it. */
  const current = (relay: string, host: string): boolean => {
    const relayName = relayByAlias.get(relay);
    const hostAliases = relayName === undefined ? null : new Set(aliases.hosts.get(relayName)?.values() ?? []);
    return !!hostAliases && (RESERVED_HOSTS.has(host) || hostAliases.has(host));
  };
  if (doc.v === STATE_VERSION) {
    if (!isObject(doc.eventRelays) || !Array.isArray(doc.events)) return { ok: false };
    for (const [relay, startedAt] of Object.entries(doc.eventRelays)) {
      if (!ALIAS_RE.test(relay) || typeof startedAt !== "string") return { ok: false };
      if (!relayByAlias.has(relay)) staleAliases += 1;
      state.eventRelays[relay] = startedAt;
    }
    for (const r of doc.events as unknown[]) {
      if (!isObject(r) || typeof r.relay !== "string" || typeof r.host !== "string" || typeof r.kind !== "string"
        || !bounded(r.count, Number.MAX_SAFE_INTEGER) || !bounded(r.quiet, EVENT_QUIET_CYCLES)
        || Object.keys(r).length !== 5) return { ok: false };
      const k = keyOf(r.relay, r.host, r.kind);
      if (Object.hasOwn(state.events, k)) return { ok: false };
      if (!EVENT_KIND_SET.has(r.kind)) {
        unknownKinds += 1;
        continue;
      }
      if (!ALIAS_RE.test(r.relay) || !ALIAS_RE.test(r.host)) return { ok: false };
      if (!current(r.relay, r.host)) staleAliases += 1;
      state.events[k] = { relay: r.relay, host: r.host, kind: r.kind as EventKind, count: r.count as number, quiet: r.quiet as number };
    }
  }
  for (const r of doc.keys as unknown[]) {
    if (!isObject(r) || typeof r.relay !== "string" || typeof r.host !== "string" || typeof r.kind !== "string"
      || typeof r.active !== "boolean" || !bounded(r.openStreak, CONFIRM_CYCLES) || !bounded(r.resolveStreak, CONFIRM_CYCLES)
      || !bounded(r.count, Number.MAX_SAFE_INTEGER) || !bounded(r.tail, ZERO_TAIL_CYCLES)) return { ok: false };
    const k = keyOf(r.relay, r.host, r.kind);
    if (Object.hasOwn(state.keys, k)) return { ok: false };
    if (!WATCH_KINDS.has(r.kind)) {
      unknownKinds += 1;
      continue;
    }
    if (!ALIAS_RE.test(r.relay) || !(ALIAS_RE.test(r.host) || RESERVED_HOSTS.has(r.host))) return { ok: false };
    if (!current(r.relay, r.host)) staleAliases += 1;
    state.keys[k] = {
      relay: r.relay, host: r.host, kind: r.kind as WatchKind, active: r.active,
      openStreak: r.openStreak as number, resolveStreak: r.resolveStreak as number,
      count: r.count as number, tail: r.tail as number,
    };
  }
  return { ok: true, state, unknownKinds, staleAliases };
}

/**
 * Whether any alias equals, ignoring case, a label of a host id in some relay's `evaluated` — the
 * hosts its manifest names. `parseWatchAliases` compares aliases with the names it is given at start;
 * a manifest changes while the manager runs, so this is asked of every cycle's answers.
 * @see "an alias equal to a manifest host label turns the watch off without stopping the manager" in problem-watch-manager.test.ts
 */
export function manifestAliasCollision(aliases: WatchAliases, relays: ReadonlyMap<string, RelayRead>): boolean {
  const all = new Set<string>(aliases.relays.values());
  for (const hostMap of aliases.hosts.values()) for (const alias of hostMap.values()) all.add(alias);
  for (const read of relays.values()) {
    if (!read.ok) continue;
    for (const hostId of read.evaluated.keys()) {
      if (labelsOf(hostId).some((l) => all.has(l))) return true;
    }
  }
  return false;
}
