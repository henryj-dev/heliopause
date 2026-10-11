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
 */
import { EnvSpecError } from "./env-spec.ts";
import type { ProblemEvaluation, ProblemKind } from "./relay.ts";

/** Consecutive counted observations that open or resolve a problem (#148: 30 s, twice). */
export const CONFIRM_CYCLES = 2;
/** Cycles a key keeps emitting `active: 0` after it resolves or leaves scope, then is dropped. */
export const ZERO_TAIL_CYCLES = 20;

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
 * `configuredRelays` is the names from `HELIOPAUSE_RELAYS`; every one of them needs an alias.
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
      throw new EnvSpecError(`${ALIASES_ENV}: ${where} equals a label of a real relay or host name`);
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
  }
  | { ok: false; reason: RelayUnobservable };

const SCHEMA = { ok: false, reason: "schema" } as const;

function readEvaluations(v: unknown): Map<ProblemKind, ProblemEvaluation> | null {
  if (!isObject(v)) return null;
  const out = new Map<ProblemKind, ProblemEvaluation>();
  for (const [kind, ev] of Object.entries(v)) {
    if (!Object.hasOwn(RELAY_KINDS, kind) || typeof ev !== "string" || !EVALUATIONS.has(ev)) return null;
    out.set(kind as ProblemKind, ev as ProblemEvaluation);
  }
  return out;
}

/**
 * Check a relay `/status` body for the fields the watch reads. A body without `findings` — a relay
 * older than #148 — is `schema`, not an empty fleet; `observability.manifest: false` is `no-manifest`.
 */
export function readRelayStatus(body: unknown): RelayRead {
  if (!isObject(body)) return SCHEMA;
  const obs = body.observability;
  if (!isObject(obs) || typeof obs.manifest !== "boolean") return SCHEMA;
  if (!Array.isArray(body.findings) || !isObject(body.evaluated)) return SCHEMA;

  const findings: { kind: ProblemKind; host: string | null; count: number }[] = [];
  for (const f of body.findings) {
    if (!isObject(f)) return SCHEMA;
    const { kind, host, count } = f;
    if (typeof kind !== "string" || !Object.hasOwn(RELAY_KINDS, kind)) return SCHEMA;
    if (host !== null && typeof host !== "string") return SCHEMA;
    if (!Number.isSafeInteger(count) || (count as number) < 0) return SCHEMA;
    findings.push({ kind: kind as ProblemKind, host, count: count as number });
  }
  const evaluated = new Map<string, Map<ProblemKind, ProblemEvaluation>>();
  for (const [host, evs] of Object.entries(body.evaluated)) {
    const read = readEvaluations(evs);
    if (!read) return SCHEMA;
    evaluated.set(host, read);
  }
  const fleetEvaluated = readEvaluations(body.fleetEvaluated);
  if (!fleetEvaluated) return SCHEMA;
  if (!obs.manifest) return { ok: false, reason: "no-manifest" };
  return { ok: true, findings, evaluated, fleetEvaluated };
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

export interface WatchState {
  seq: number;
  keys: Record<string, KeyState>;
}

export const emptyWatchState = (): WatchState => ({ seq: 0, keys: {} });

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
export interface CycleLine {
  event: "heliopause.problem.cycle";
  cycle: number;
  relays: { relay: string; observed: boolean; reason: CycleReason | null; active: number }[];
  unaliasedHosts: number;
  skippedTicks: number;
}
export interface WatchLine {
  event: "heliopause.problem.watch";
  what: "started" | "stopped" | "state_initialized" | "state_unreadable" | "state_write_failed" | "lock_held" | "lock_acquired";
}
export type WatchEvent = StateLine | TransitionLine | CycleLine | WatchLine;

export interface StepResult {
  next: WatchState;
  transitions: TransitionLine[];
  snapshot: { states: StateLine[]; cycle: CycleLine };
}

const keyOf = (relay: string, host: string, kind: WatchKind) => JSON.stringify([relay, host, kind]);

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
      cycleRelays.push({ relay, observed: false, reason: poll ? poll.reason : "not-configured", active: 0 });
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
      cycleRelays.push({ relay, observed: true, reason: null, active: 0 });
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
    snapshot: {
      states,
      cycle: {
        event: "heliopause.problem.cycle", cycle: input.cycle, relays: cycleRelays,
        unaliasedHosts: unaliasedTotal, skippedTicks: input.skippedTicks ?? 0,
      },
    },
  };
}

// ## Output

const TRANSITIONS = new Set<string>(["opened", "resolved", "scope_removed"]);
const REASONS = new Set<string>(["unreachable", "schema", "no-manifest", "not-configured"]);
const WHATS = new Set<string>(["started", "stopped", "state_initialized", "state_unreadable", "state_write_failed", "lock_held", "lock_acquired"]);

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
      case "heliopause.problem.cycle": {
        const c = e as CycleLine;
        if (!Array.isArray(c.relays)) throw new OutOfSchema(event);
        return JSON.stringify({
          event, v: 1, cycle: count(c.cycle, event),
          relays: c.relays.map((r) => ({
            relay: relayAlias(r.relay, event), observed: bool(r.observed, event),
            reason: r.reason === null ? null : oneOf(r.reason, REASONS, event), active: count(r.active, event),
          })),
          unaliasedHosts: count(c.unaliasedHosts, event), skippedTicks: count(c.skippedTicks, event),
        });
      }
      case "heliopause.problem.watch": {
        const w = e as WatchLine;
        return JSON.stringify({ event, v: 1, what: oneOf(w.what, WHATS, event) });
      }
      default:
        throw new OutOfSchema("problem-watch");
    }
  });
}
