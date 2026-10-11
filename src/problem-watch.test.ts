import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { EnvSpecError } from "./env-spec.ts";
import { emptyState, fleetView } from "./relay.ts";
import { SCHEMA_VERSION } from "./protocol.ts";
import {
  CONFIRM_CYCLES, ZERO_TAIL_CYCLES, emitLines, emptyWatchState, parseWatchAliases, readRelayStatus, stepWatch,
  type RelayRead, type StateLine, type StepResult, type TransitionLine, type WatchAliases, type WatchState,
} from "./problem-watch.ts";

// Fixture names are RFC 2606 / RFC 5737: self-evidently not a site.
const RELAY = "zone-a.example";
const H1 = "h1.zone-a.example";
const H2 = "h2.zone-a.example";
const H3 = "h3.zone-a.example";

const ALIASES = parseWatchAliases(
  JSON.stringify({ relays: { [RELAY]: "za" }, hosts: { [RELAY]: { [H1]: "web", [H2]: "db" } } }),
  [RELAY],
);

type Ev = "yes" | "no-resolve" | "no";
interface BodyOpts {
  findings?: { kind: string; host: string | null; value?: string | null; count?: number; [extra: string]: unknown }[];
  evaluated?: Record<string, Record<string, Ev>>;
  fleetEvaluated?: Record<string, Ev>;
  manifest?: boolean;
}

/** A `/status` body in the shape `fleetView` returns, through a JSON round trip. */
function body(o: BodyOpts = {}): unknown {
  return JSON.parse(JSON.stringify({
    generation: "g1", issuedAt: null, planHash: null, hosts: [], problems: [], relayAgeSec: 1000,
    findings: (o.findings ?? []).map((f) => ({ value: null, count: 0, ...f })),
    evaluated: o.evaluated ?? { [H1]: { silent: "yes" }, [H2]: { silent: "yes" } },
    fleetEvaluated: o.fleetEvaluated ?? { "trust-ring-split": "yes" },
    observability: { manifest: o.manifest ?? true, graceActive: false },
  }));
}

const silentOn = (host: string) => ({ kind: "silent", host });
const UNREACHABLE: RelayRead = { ok: false, reason: "unreachable" };
const NOT_CONFIGURED = Symbol("not configured");
type Poll = unknown | typeof NOT_CONFIGURED;

interface Run { state: WatchState; steps: StepResult[]; transitions: TransitionLine[]; states: StateLine[][] }

/** Feed `polls` to one relay, cycle by cycle. A `RelayRead` is passed as is; anything else is a body. */
function run(polls: Poll[], aliases: WatchAliases = ALIASES, start: WatchState = emptyWatchState(), relay = RELAY): Run {
  let state = start;
  const steps: StepResult[] = [];
  polls.forEach((p, i) => {
    const relays = new Map<string, RelayRead>();
    if (p !== NOT_CONFIGURED) {
      const isRead = typeof p === "object" && p !== null && "ok" in p;
      relays.set(relay, isRead ? (p as RelayRead) : readRelayStatus(p));
    }
    const r = stepWatch(state, { cycle: i + 1, aliases, relays });
    state = r.next;
    steps.push(r);
  });
  return { state, steps, transitions: steps.flatMap((s) => s.transitions), states: steps.map((s) => s.snapshot.states) };
}

const brief = (t: TransitionLine) => `${t.transition} ${t.relay}/${t.host}/${t.kind}`;
const repeat = <T>(n: number, v: T): T[] => Array.from({ length: n }, () => v);
const silentH1 = body({ findings: [silentOn(H1)] });
const clean = body();

describe("problem watch: opening and resolving", () => {
  it("opens after two consecutive valid observations, not after one", () => {
    assert.equal(CONFIRM_CYCLES, 2);
    assert.deepEqual(run([silentH1]).transitions, []);
    assert.deepEqual(run([silentH1, silentH1]).transitions.map(brief), ["opened za/web/silent"]);
  });

  it("a persisting problem adds no further opened", () => {
    assert.deepEqual(run(repeat(10, silentH1)).transitions.map(brief), ["opened za/web/silent"]);
  });

  it("resolves only after two consecutive valid observations without it", () => {
    assert.deepEqual(run([silentH1, silentH1, clean]).transitions.map(brief), ["opened za/web/silent"]);
    assert.deepEqual(run([silentH1, silentH1, clean, clean]).transitions.map(brief),
      ["opened za/web/silent", "resolved za/web/silent"]);
  });

  it("recurrence after resolution opens again", () => {
    assert.deepEqual(run([silentH1, silentH1, clean, clean, silentH1, silentH1]).transitions.map(brief),
      ["opened za/web/silent", "resolved za/web/silent", "opened za/web/silent"]);
  });

  it("an opened finding carries its count, and the snapshot follows later counts", () => {
    const pub = (count: number) => body({ findings: [{ kind: "published-ports", host: H2, count }], evaluated: { [H2]: { "published-ports": "yes" } } });
    const r = run([pub(3), pub(3), pub(5)]);
    assert.deepEqual(r.transitions.map((t) => t.count), [3]);
    assert.deepEqual(r.states.map((s) => s.map((l) => l.count)), [[], [3], [5]]);
  });
});

describe("problem watch: unobservable cycles hold state", () => {
  const unobservable: [string, Poll][] = [
    ["a failed poll", UNREACHABLE],
    ["a body that is not an object", "<html>"],
    ["a relay older than findings", (() => { const b = body() as Record<string, unknown>; delete b.findings; return b; })()],
    ["a relay with no manifest", body({ manifest: false })],
  ];
  for (const [name, poll] of unobservable) {
    it(`${name} never resolves, and the snapshot still says active, unobserved`, () => {
      const r = run([silentH1, silentH1, ...repeat(6, poll)]);
      assert.deepEqual(r.transitions.filter((t) => t.kind === "silent").map(brief), ["opened za/web/silent"]);
      for (const states of r.states.slice(2)) {
        assert.deepEqual(states.filter((s) => s.kind === "silent").map((s) => [s.active, s.observed]), [[1, false]]);
      }
    });
  }

  it("readRelayStatus names why: schema for no findings, no-manifest for no manifest", () => {
    const old = body() as Record<string, unknown>;
    delete old.findings;
    assert.deepEqual(readRelayStatus(old), { ok: false, reason: "schema" });
    assert.deepEqual(readRelayStatus(body({ manifest: false })), { ok: false, reason: "no-manifest" });
    assert.deepEqual(readRelayStatus(body({ findings: [{ kind: "not-a-kind", host: H1 }] })), { ok: false, reason: "schema" });
    assert.deepEqual(readRelayStatus(body({ evaluated: { [H1]: { "not-a-kind": "yes" } } })), { ok: false, reason: "schema" });
    assert.deepEqual(readRelayStatus(body({ evaluated: { [H1]: { silent: "maybe" as Ev } } })), { ok: false, reason: "schema" });
    assert.deepEqual(readRelayStatus(body({ findings: [{ kind: "silent", host: H1, count: -1 }] })), { ok: false, reason: "schema" });
    assert.equal(readRelayStatus(body()).ok, true);
  });

  it("an unobservable cycle restarts the streak in both directions", () => {
    assert.deepEqual(run([silentH1, UNREACHABLE, silentH1]).transitions, []);
    assert.deepEqual(run([silentH1, UNREACHABLE, silentH1, silentH1]).transitions.map(brief), ["opened za/web/silent"]);
    const resolving = run([silentH1, silentH1, clean, UNREACHABLE, clean]);
    assert.deepEqual(resolving.transitions.filter((t) => t.kind === "silent").map(brief), ["opened za/web/silent"]);
  });

  it("a kind missing from evaluated is treated as not evaluated", () => {
    const missing = body({ evaluated: { [H1]: {}, [H2]: {} } });
    // Known positive: the same absence with `silent: yes` resolves.
    assert.deepEqual(run([silentH1, silentH1, clean, clean]).transitions.map(brief).at(-1), "resolved za/web/silent");
    assert.deepEqual(run([silentH1, silentH1, ...repeat(6, missing)]).transitions.map(brief), ["opened za/web/silent"]);
    const findingButMissing = body({ findings: [silentOn(H1)], evaluated: { [H1]: {}, [H2]: {} } });
    assert.deepEqual(run(repeat(6, findingButMissing)).transitions, []);
  });

  it("evaluated no with a finding opens nothing", () => {
    const no = body({ findings: [silentOn(H1)], evaluated: { [H1]: { silent: "no" } } });
    assert.deepEqual(run(repeat(6, no)).transitions, []);
  });

  it("no-resolve counts an opening and never a resolution", () => {
    const ev = (e: Ev, present: boolean) => body({
      findings: present ? [{ kind: "ruleset-changed", host: H1 }] : [],
      evaluated: { [H1]: { "ruleset-changed": e } },
    });
    const r = run([ev("no-resolve", true), ev("no-resolve", true), ...repeat(6, ev("no-resolve", false))]);
    assert.deepEqual(r.transitions.map(brief), ["opened za/web/ruleset-changed"]);
    assert.deepEqual(r.states.at(-1)?.map((s) => [s.active, s.observed]), [[1, false]]);
    const then = run([ev("yes", false), ev("yes", false)], ALIASES, r.state);
    assert.deepEqual(then.transitions.map(brief), ["resolved za/web/ruleset-changed"]);
  });

  it("the three event-shaped contradictions open nothing as the relay reports them", () => {
    const events = ["contradiction-artifact-hash-changed", "contradiction-unknown-generation", "contradiction-kernel-unchanged"];
    const asRelaySends = body({
      findings: events.map((kind) => ({ kind, host: H1, count: 1 })),
      evaluated: { [H1]: Object.fromEntries(events.map((k) => [k, "no" as Ev])) },
    });
    assert.deepEqual(run(repeat(10, asRelaySends)).transitions, []);
    // Known positive: the state-shaped contradiction, evaluated yes, opens.
    const stateShaped = body({
      findings: [{ kind: "contradiction-artifact-hash-wrong", host: H1, count: 1 }],
      evaluated: { [H1]: { "contradiction-artifact-hash-wrong": "yes" } },
    });
    assert.deepEqual(run(repeat(2, stateShaped)).transitions.map(brief), ["opened za/web/contradiction-artifact-hash-wrong"]);
  });

  it("trust-ring-split is the fleet's, judged by fleetEvaluated", () => {
    const split = (e: Ev, present: boolean) => body({
      findings: present ? [{ kind: "trust-ring-split", host: null, value: "2,1", count: 2 }] : [],
      fleetEvaluated: { "trust-ring-split": e },
    });
    const r = run([split("yes", true), split("yes", true), split("no-resolve", false), split("no-resolve", false)]);
    assert.deepEqual(r.transitions.map(brief), ["opened za/_fleet/trust-ring-split"]);
    assert.deepEqual(run([split("yes", false), split("yes", false)], ALIASES, r.state).transitions.map(brief),
      ["resolved za/_fleet/trust-ring-split"]);
  });
});

describe("problem watch: relay-level problems", () => {
  it("relay-unobservable opens after two failed polls and resolves after two good ones", () => {
    const r = run([UNREACHABLE, UNREACHABLE, UNREACHABLE, clean, clean]);
    assert.deepEqual(r.transitions.map(brief), ["opened za/_relay/relay-unobservable", "resolved za/_relay/relay-unobservable"]);
    assert.deepEqual(run([UNREACHABLE, clean, UNREACHABLE, clean]).transitions, []);
  });

  it("an expected relay missing from configuration opens relay-not-configured, and only that", () => {
    const two = parseWatchAliases(JSON.stringify({
      relays: { [RELAY]: "za", "zone-b.example": "zb" }, hosts: { [RELAY]: { [H1]: "web", [H2]: "db" } },
    }), [RELAY]);
    let state = emptyWatchState();
    const all: TransitionLine[] = [];
    for (let cycle = 1; cycle <= 4; cycle++) {
      const r = stepWatch(state, { cycle, aliases: two, relays: new Map([[RELAY, readRelayStatus(clean)]]) });
      state = r.next;
      all.push(...r.transitions);
    }
    assert.deepEqual(all.map(brief), ["opened zb/_relay/relay-not-configured"]);
    const cycleLine = stepWatch(state, { cycle: 5, aliases: two, relays: new Map([[RELAY, readRelayStatus(clean)]]) }).snapshot.cycle;
    assert.deepEqual(cycleLine.relays.map((r) => [r.relay, r.observed, r.reason]), [["za", true, null], ["zb", false, "not-configured"]]);
  });
});

describe("problem watch: scope and aliases", () => {
  it("a host removed from the manifest is scope_removed, not resolved", () => {
    const gone = body({ evaluated: { [H2]: { silent: "yes" } } });
    const r = run([silentH1, silentH1, gone]);
    assert.deepEqual(r.transitions.map(brief), ["opened za/web/silent", "scope_removed za/web/silent"]);
    // Removal waits for a valid observation of the manifest: a failed poll holds.
    assert.deepEqual(run([silentH1, silentH1, UNREACHABLE]).transitions.filter((t) => t.host === "web").map(brief),
      ["opened za/web/silent"]);
  });

  it("a host dropped from the alias map is scope_removed even while its relay is unobservable", () => {
    const fewer = parseWatchAliases(JSON.stringify({ relays: { [RELAY]: "za" }, hosts: { [RELAY]: { [H2]: "db" } } }), [RELAY]);
    const opened = run([silentH1, silentH1]);
    assert.deepEqual(run([UNREACHABLE], fewer, opened.state).transitions.map(brief), ["scope_removed za/web/silent"]);
  });

  it("emits exactly ZERO_TAIL_CYCLES zeros after a resolution, then drops the key", () => {
    assert.equal(ZERO_TAIL_CYCLES, 20);
    const r = run([silentH1, silentH1, clean, ...repeat(30, clean)]);
    const lines = r.states.flat().filter((s) => s.kind === "silent");
    assert.equal(lines.filter((s) => s.active === 0).length, ZERO_TAIL_CYCLES);
    assert.deepEqual(Object.keys(r.state.keys), []);
  });

  it("emits exactly ZERO_TAIL_CYCLES zeros after scope_removed, then drops the key", () => {
    const gone = body({ evaluated: { [H2]: { silent: "yes" } } });
    const r = run([silentH1, silentH1, ...repeat(30, gone)]);
    assert.equal(r.states.flat().filter((s) => s.active === 0).length, ZERO_TAIL_CYCLES);
    assert.deepEqual(Object.keys(r.state.keys), []);
  });

  it("unaliased hosts are one fleet problem counting them, never named", () => {
    const three = (present: boolean) => body({
      findings: present ? [silentOn(H3), silentOn("h4.zone-a.example")] : [],
      evaluated: { [H1]: { silent: "yes" }, [H3]: { silent: "yes" }, ...(present ? { "h4.zone-a.example": { silent: "yes" } } : {}) },
    });
    const r = run([three(true), three(true)]);
    assert.deepEqual(r.transitions.map((t) => [brief(t), t.count]), [["opened za/_fleet/unaliased-hosts", 2]]);
    assert.equal(r.steps.at(-1)?.snapshot.cycle.unaliasedHosts, 2);
    const fewer = run([three(false), three(false)], ALIASES, r.state);
    assert.deepEqual(fewer.states.at(-1)?.map((s) => [s.kind, s.active, s.count]), [["unaliased-hosts", 1, 1]]);
    const none = run([clean, clean], ALIASES, fewer.state);
    assert.deepEqual(none.transitions.map(brief), ["resolved za/_fleet/unaliased-hosts"]);
  });
});

describe("problem watch: snapshot", () => {
  it("emits one line per active or tailing key every cycle, observable or not", () => {
    const two = body({ findings: [silentOn(H1), silentOn(H2)] });
    const r = run([two, two, two, UNREACHABLE, two, UNREACHABLE, two, UNREACHABLE]);
    assert.deepEqual(r.states.map((s) => s.length), [0, 2, 2, 2, 2, 2, 2, 2]);
    assert.deepEqual(r.states.slice(1).map((s) => s.map((l) => l.observed)),
      [[true, true], [true, true], [false, false], [true, true], [false, false], [true, true], [false, false]]);
  });

  it("this module makes a zero in two ways: a resolution's tail and a scope removal's tail", () => {
    const gone = body({ evaluated: { [H2]: { silent: "yes" } } });
    const h2 = body({ findings: [silentOn(H2)] });
    const script: Poll[] = [
      silentH1, silentH1, UNREACHABLE, silentH1, clean, UNREACHABLE, clean, clean, ...repeat(3, clean),
      h2, h2, silentH1, silentH1, gone, gone, UNREACHABLE, UNREACHABLE, silentH1, silentH1, ...repeat(25, clean),
    ];
    const r = run(script);
    const lastTransition = new Map<string, { t: string; cycle: number }>();
    const causes = new Set<string>();
    let zeros = 0;
    r.steps.forEach((step, i) => {
      for (const t of step.transitions) lastTransition.set(`${t.relay}/${t.host}/${t.kind}`, { t: t.transition, cycle: i + 1 });
      for (const s of step.snapshot.states) {
        if (s.active !== 0) continue;
        zeros++;
        const last = lastTransition.get(`${s.relay}/${s.host}/${s.kind}`);
        assert.ok(last && (last.t === "resolved" || last.t === "scope_removed"), `zero without a resolution at cycle ${i + 1}`);
        assert.ok(i + 1 - last.cycle < ZERO_TAIL_CYCLES);
        causes.add(last.t);
      }
    });
    // Known positives: both paths happened here, so the check above was not vacuous.
    assert.deepEqual([...causes].sort(), ["resolved", "scope_removed"]);
    assert.ok(zeros > 0);
  });
});

describe("problem watch: output", () => {
  const ALLOWED: Record<string, string[]> = {
    "heliopause.problem.state": ["event", "v", "relay", "host", "kind", "active", "count", "observed", "cycle"],
    "heliopause.problem.transition": ["event", "v", "seq", "transition", "relay", "host", "kind", "count"],
    "heliopause.problem.cycle": ["event", "v", "cycle", "relays", "unaliasedHosts", "skippedTicks"],
  };

  it("carries only allowed fields, no id, address, value or detail from the relay", () => {
    const leaky = body({
      findings: [
        { kind: "published-ports", host: H1, value: "192.0.2.7", count: 1, detail: "listener on 192.0.2.8\nsecond line" },
        { kind: "silent", host: "evil\nh9.zone-a.example", value: "192.0.2.9" },
      ],
      evaluated: { [H1]: { "published-ports": "yes" }, "evil\nh9.zone-a.example": { silent: "yes" } },
    });
    const r = run([leaky, leaky]);
    const lines = emitLines(r.steps.flatMap((s) => [...s.transitions, ...s.snapshot.states, s.snapshot.cycle]));
    // Known positive: the problem did open and reach the output.
    assert.equal(lines.filter((l) => l.includes('"transition":"opened"') && l.includes('"published-ports"')).length, 1);
    for (const line of lines) {
      assert.ok(!line.includes("\n"));
      for (const leak of ["192.0.2", "zone-a.example", "h1.", "evil", "detail", "listener"]) assert.ok(!line.includes(leak), leak);
      const parsed = JSON.parse(line) as Record<string, unknown>;
      assert.deepEqual(Object.keys(parsed), ALLOWED[parsed.event as string]);
    }
  });

  it("rebuilds an event from its own fields and refuses a value outside the schema without quoting it", () => {
    const extra = {
      event: "heliopause.problem.transition", seq: 1, transition: "opened", relay: "za", host: "web",
      kind: "silent", count: 0, value: "192.0.2.10", detail: "x",
    } as unknown as TransitionLine;
    const [line] = emitLines([extra]);
    assert.deepEqual(Object.keys(JSON.parse(line ?? "{}")), ALLOWED["heliopause.problem.transition"]);
    for (const bad of [{ relay: RELAY }, { host: H1 }, { kind: "made-up" }, { transition: "changed" }, { count: -1 }]) {
      assert.throws(() => emitLines([{ ...extra, ...bad } as TransitionLine]), (e: Error) => {
        assert.ok(!e.message.includes(RELAY) && !e.message.includes(H1) && !e.message.includes("made-up"));
        return true;
      });
    }
    assert.throws(() => emitLines([{ event: "heliopause.problem.debug", detail: H1 } as unknown as TransitionLine]),
      (e: Error) => !e.message.includes(H1));
    assert.deepEqual(emitLines([{ event: "heliopause.problem.watch", what: "started" }]),
      ['{"event":"heliopause.problem.watch","v":1,"what":"started"}']);
  });
});

describe("problem watch: aliases", () => {
  const file = (o: unknown) => JSON.stringify(o);
  const refuses = (text: string, relays: string[], ...mustNotQuote: string[]) =>
    assert.throws(() => parseWatchAliases(text, relays), (e: unknown) => {
      assert.ok(e instanceof EnvSpecError);
      for (const s of mustNotQuote) assert.ok(!e.message.includes(s), `quoted ${s}`);
      return true;
    });

  it("refuses an alias equal to any label of a real name, ignoring case", () => {
    refuses(file({ relays: { [RELAY]: "za" }, hosts: { [RELAY]: { "WEB-01.zone-a.example": "web-01" } } }), [RELAY], "WEB-01", "web-01");
    refuses(file({ relays: { [RELAY]: "zone-a" } }), [RELAY], "zone-a");
    refuses(file({ relays: { [RELAY]: "za" }, hosts: { [RELAY]: { [H1]: "example" } } }), [RELAY], "example");
  });

  it("does not refuse an alias that only contains part of a real name", () => {
    const a = parseWatchAliases(file({ relays: { [RELAY]: "zone" }, hosts: { [RELAY]: { "web-01.zone-a.example": "web" } } }), [RELAY]);
    assert.equal(a.hosts.get(RELAY)?.get("web-01.zone-a.example"), "web");
  });

  it("refuses duplicates under one relay and allows them across relays", () => {
    refuses(file({ relays: { [RELAY]: "za" }, hosts: { [RELAY]: { [H1]: "web", [H2]: "web" } } }), [RELAY], H1, H2);
    refuses(file({ relays: { [RELAY]: "za", "zone-b.example": "za" } }), [RELAY], RELAY);
    const ok = parseWatchAliases(file({
      relays: { [RELAY]: "za", "zone-b.example": "zb" },
      hosts: { [RELAY]: { [H1]: "web" }, "zone-b.example": { "h1.zone-b.example": "web" } },
    }), [RELAY]);
    assert.equal(ok.hosts.get("zone-b.example")?.get("h1.zone-b.example"), "web");
  });

  it("refuses reserved, malformed and missing aliases", () => {
    refuses(file({ relays: { [RELAY]: "_fleet" } }), [RELAY]);
    refuses(file({ relays: { [RELAY]: "za" }, hosts: { [RELAY]: { [H1]: "_x" } } }), [RELAY]);
    refuses(file({ relays: { [RELAY]: "Za" } }), [RELAY]);
    refuses(file({ relays: { [RELAY]: "a".repeat(33) } }), [RELAY]);
    refuses(file({ relays: { [RELAY]: "za" } }), [RELAY, "zone-c.example"], "zone-c");
    refuses(file({ relays: { [RELAY]: "za" }, hosts: { "zone-c.example": {} } }), [RELAY], "zone-c");
    refuses(file({ relays: { [RELAY]: "za" }, extra: 1 }), [RELAY]);
    refuses(file({ relays: { [RELAY]: "za" }, hosts: { [RELAY]: "web" } }), [RELAY], RELAY);
    refuses("{not json", [RELAY]);
  });

  it("a host id that names an Object.prototype member is just a host", () => {
    const a = parseWatchAliases(file({ relays: { [RELAY]: "za" }, hosts: { [RELAY]: { constructor: "c1" } } }), [RELAY]);
    assert.equal(a.hosts.get(RELAY)?.get("toString"), undefined);
    assert.equal(a.hosts.get(RELAY)?.get("constructor"), "c1");
  });
});

describe("problem watch: against fleetView", () => {
  it("reads a body fleetView built and opens never-reported for an aliased host", () => {
    const s = emptyState();
    s.manifest = {
      generation: "g1", issuedAt: "2026-07-30T00:00:00Z", schemaVersion: SCHEMA_VERSION,
      hosts: { [H1]: { stage: "general", rulesetHash: "sha256:1", confirmTimeoutSec: 60, mustContain: [] } },
    };
    const now = new Date("2026-07-30T01:00:00Z");
    const view = () => JSON.parse(JSON.stringify(fleetView(s, now, 90, new Date("2026-07-30T00:00:00Z")))) as unknown;
    const r = run([view(), view()]);
    assert.deepEqual(r.transitions.map(brief), ["opened za/web/never-reported"]);
    assert.deepEqual(readRelayStatus(JSON.parse(JSON.stringify(fleetView(emptyState(), now)))), { ok: false, reason: "no-manifest" });
  });
});
