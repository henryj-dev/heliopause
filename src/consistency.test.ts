// H30 — self-contradiction detection, tested as data.
//
// The load-bearing test in this file is the negative one: **the eight publishes done on 2026-08-03
// must not be reported.** Every one of them moved the generation id while rendering rules identical to
// the live ones, which is exactly the shape the design document named as the first H30 symptom. A
// check written from that sentence would alarm on the safest publish this project can make, and this
// suite exists partly to keep that sentence from creeping back into the code.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { reportContradictions, type Reference } from "./consistency.ts";
import { SCHEMA_VERSION, type Heartbeat, type Manifest } from "./protocol.ts";

const A1 = "sha256:" + "a".repeat(64); // artifact for generation 1
const A2 = "sha256:" + "b".repeat(64); // artifact for generation 2
const K1 = "sha256:" + "1".repeat(64); // kernel dump 1
const K2 = "sha256:" + "2".repeat(64); // kernel dump 2

function hb(over: Partial<Heartbeat["applied"]> & { host?: string; state?: Heartbeat["applied"]["state"] } = {}): Heartbeat {
  const { host, ...applied } = over;
  return {
    host: host ?? "gw-01.dev",
    agentVersion: "test",
    schemaVersion: SCHEMA_VERSION,
    applied: {
      generation: "gen-2",
      state: "confirmed",
      artifactHash: A2,
      observedHash: K2,
      ...applied,
    },
  };
}

function manifest(over: Partial<Manifest> = {}): Manifest {
  return {
    generation: "gen-2",
    issuedAt: "2026-08-03T00:00:00.000Z",
    schemaVersion: SCHEMA_VERSION,
    hosts: {
      "gw-01.dev": { stage: "canary", rulesetHash: A2, confirmTimeoutSec: 120, mustContain: [] },
    },
    ...over,
  };
}

const ref = (over: Partial<Reference> = {}): Reference => ({
  generation: "gen-1",
  hash: K1,
  artifactHash: A1,
  ...over,
});

const kinds = (cs: ReturnType<typeof reportContradictions>) => cs.map((c) => c.kind).sort();

describe("the ordinary cases stay silent", () => {
  it("does not report a generation change that renders identical rules", () => {
    // **This is the one that matters.** Measured eight times on 2026-08-03: each publish moved only
    // the generation id because the rendered rules were byte-identical to the live ones. The design
    // document called this H30's first symptom ("룰셋 해시는 그대로인데 세대만 바뀜"); it is the
    // safest publish this project can make.
    const prior = ref({ generation: "gen-1", hash: K1, artifactHash: A1 });
    const beat = hb({ generation: "gen-2", artifactHash: A1, observedHash: K1 });
    const m = manifest({ hosts: { "gw-01.dev": { stage: "canary", rulesetHash: A1, confirmTimeoutSec: 120, mustContain: [] } } });
    assert.deepEqual(reportContradictions(beat, prior, m), []);
  });

  it("does not report a normal rollout where both digests move together", () => {
    assert.deepEqual(reportContradictions(hb(), ref(), manifest()), []);
  });

  it("does not report re-confirming the same generation with the same artifact", () => {
    const prior = ref({ generation: "gen-2", hash: K2, artifactHash: A2 });
    assert.deepEqual(reportContradictions(hb(), prior, manifest()), []);
  });

  it("does not report a host confirmed on the previous generation mid-rollout", () => {
    // Normal while stages are still opening. The relay no longer holds gen-1's manifest, so there is
    // nothing to compare the artifact against — and accusing it would fire on every staged rollout.
    const prior = ref({ generation: "gen-1", hash: K1, artifactHash: A1 });
    const beat = hb({ generation: "gen-1", artifactHash: A1, observedHash: K1 });
    assert.deepEqual(reportContradictions(beat, prior, manifest()), []);
  });

  it("says nothing about a host it has no history for", () => {
    // First contact, or the first beat after a relay restart. Every check that needs a baseline is
    // skipped rather than guessed — otherwise a restart produces a wave of accusations.
    assert.deepEqual(reportContradictions(hb(), undefined, manifest()), []);
  });

  it("says nothing when no manifest is loaded yet", () => {
    assert.deepEqual(reportContradictions(hb(), ref(), null), []);
  });

  it("says nothing about a host that cannot dump its own table", () => {
    // `observedHash: null` is a host that lost its ruleset, which the generation reply handles by
    // telling it to re-apply. Not a contradiction — and treating it as one is how V-series drift
    // alarms got stuck on after the problem was fixed.
    const prior = ref({ generation: "gen-1", hash: K1, artifactHash: A1 });
    const beat = hb({ generation: "gen-2", artifactHash: A2, observedHash: null });
    assert.deepEqual(reportContradictions(beat, prior, manifest()), []);
  });

  it("says nothing when the prior reference predates artifact tracking", () => {
    // `artifactHash` is optional on `Reference` because relays that have been running since before
    // this check existed have references without it. Absent must mean "cannot tell", not "differs".
    const prior: Reference = { generation: "gen-1", hash: K1 };
    const beat = hb({ generation: "gen-2", artifactHash: A2, observedHash: K1 });
    assert.deepEqual(reportContradictions(beat, prior, manifest()), []);
  });
});

describe("one generation names one artifact", () => {
  it("reports the same generation reported with two different artifacts", () => {
    // A published generation is immutable — `writePublish` renames the manifest over atomically — so
    // one of the two reports was false regardless of which.
    const prior = ref({ generation: "gen-2", hash: K2, artifactHash: A1 });
    const beat = hb({ generation: "gen-2", artifactHash: A2, observedHash: K2 });
    const cs = reportContradictions(beat, prior, manifest());
    assert.deepEqual(kinds(cs), ["artifact-hash-changed"]);
    assert.equal(cs[0]!.certainty, "certain");
  });

  it("names both digests, so an operator can tell which beat to distrust", () => {
    const prior = ref({ generation: "gen-2", hash: K2, artifactHash: A1 });
    const cs = reportContradictions(hb({ generation: "gen-2" }), prior, manifest());
    assert.match(cs[0]!.detail, /sha256:aaaa/);
    assert.match(cs[0]!.detail, /sha256:bbbb/);
  });
});

describe("confirming the wrong artifact for the current generation", () => {
  it("reports a confirmed host whose artifact is not what the manifest publishes", () => {
    // The agent checks this itself and reverts on mismatch (`artifactMatches`). Reporting it means the
    // host contradicted its own validator.
    const beat = hb({ generation: "gen-2", artifactHash: A1, observedHash: K2 });
    const prior = ref({ generation: "gen-2", hash: K2, artifactHash: A1 });
    const cs = reportContradictions(beat, prior, manifest());
    assert.ok(cs.some((c) => c.kind === "artifact-hash-wrong"), `expected artifact-hash-wrong, got ${kinds(cs)}`);
    assert.equal(cs.find((c) => c.kind === "artifact-hash-wrong")!.certainty, "certain");
  });

  it("does not fire while the host is still applying", () => {
    // Only `confirmed` is a claim about the finished state. `pending` reporting a partial digest is
    // the middle of the work, not a lie about it.
    const beat = hb({ generation: "gen-2", state: "pending", artifactHash: A1 });
    const prior = ref({ generation: "gen-2", hash: K2, artifactHash: A1 });
    assert.equal(reportContradictions(beat, prior, manifest()).some((c) => c.kind === "artifact-hash-wrong"), false);
  });

  it("does not fire for a host the manifest does not name", () => {
    const beat = hb({ host: "ghost.dev", artifactHash: A1 });
    assert.deepEqual(reportContradictions(beat, ref(), manifest()), []);
  });
});

describe("confirming a generation nobody served", () => {
  it("reports an id that is neither published nor the last confirmed one", () => {
    const prior = ref({ generation: "gen-1", hash: K1, artifactHash: A1 });
    const beat = hb({ generation: "gen-99", artifactHash: A2, observedHash: K2 });
    const cs = reportContradictions(beat, prior, manifest());
    assert.ok(cs.some((c) => c.kind === "unknown-generation"), `got ${kinds(cs)}`);
  });

  it("does not report the published generation or the last confirmed one", () => {
    const prior = ref({ generation: "gen-1", hash: K1, artifactHash: A1 });
    for (const gen of ["gen-2", "gen-1"]) {
      const cs = reportContradictions(hb({ generation: gen, artifactHash: gen === "gen-2" ? A2 : A1 }), prior, manifest());
      assert.equal(cs.some((c) => c.kind === "unknown-generation"), false, `${gen} was called unknown`);
    }
  });
});

describe("new rules, unchanged kernel", () => {
  it("reports a changed artifact with an identical dump", () => {
    const prior = ref({ generation: "gen-1", hash: K1, artifactHash: A1 });
    const beat = hb({ generation: "gen-2", artifactHash: A2, observedHash: K1 });
    const cs = reportContradictions(beat, prior, manifest());
    assert.ok(cs.some((c) => c.kind === "kernel-unchanged"), `got ${kinds(cs)}`);
  });

  it("grades it unexplained rather than certain", () => {
    // Two artifacts can legitimately produce the same stateless dump — the artifact's preamble
    // (`add table`, `delete table`) does not appear in a dump, so a change confined to it is invisible
    // there. Rare, not proof, and calling it a lie would make the `certain` grade meaningless.
    const prior = ref({ generation: "gen-1", hash: K1, artifactHash: A1 });
    const beat = hb({ generation: "gen-2", artifactHash: A2, observedHash: K1 });
    const c = reportContradictions(beat, prior, manifest()).find((x) => x.kind === "kernel-unchanged");
    assert.equal(c?.certainty, "unexplained");
  });
});

describe("reporting shape", () => {
  it("returns every contradiction, not the first", () => {
    // They have different causes and an operator seeing three would act differently than seeing one.
    // Same generation as prior with a different artifact, *and* that artifact is not the published one.
    const prior = ref({ generation: "gen-2", hash: K2, artifactHash: A1 });
    const beat = hb({ generation: "gen-2", artifactHash: K1, observedHash: K2 });
    const cs = reportContradictions(beat, prior, manifest());
    assert.ok(cs.length >= 2, `expected several, got ${JSON.stringify(kinds(cs))}`);
  });

  it("carries the host on every finding", () => {
    const prior = ref({ generation: "gen-2", hash: K2, artifactHash: A1 });
    for (const c of reportContradictions(hb({ generation: "gen-2" }), prior, manifest())) {
      assert.equal(c.host, "gw-01.dev");
    }
  });
});
