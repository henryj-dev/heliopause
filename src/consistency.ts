// H30 — does a host's own reporting contradict itself?
//
// Pure, like `computeGate`. The relay feeds it what it remembered and what just arrived; every
// decision here is a comparison between two things the *same host* said.
//
// ## What this adds that drift detection does not
//
// Drift asks "did the kernel change behind us" — one host, one generation, dump against dump. It
// assumes the reports are honest and looks for a change underneath them. This asks the other
// question: **are the reports consistent with each other at all.** A host that has been taken over
// does not have to alter the kernel to be dangerous; it can simply claim a generation it never
// applied, and drift detection would find nothing because it re-binds its reference on every
// confirmation.
//
// So the two are complementary, and neither subsumes the other:
//
//   drift          the kernel moved while the story stayed the same
//   contradiction  the story moved in a way no honest host's story can
//
// ## The design document's first example was wrong
//
// `docs/구성.md` lists H30 as *"룰셋 해시는 그대로인데 세대만 바뀜"* — the ruleset hash unchanged
// while the generation changes. **That is normal, and it was measured eight times on 2026-08-03.**
// Every publish that day rendered rules identical to the live ones and moved only the generation id;
// the whole point of doing it that way was that it exercised the apply path with zero rule change.
// A check written from that sentence would have alarmed on the safest possible publish.
//
// The honest version is one level deeper: **the artifact changed but the kernel dump did not.** If
// the text a host applied is different and the table it reads back is byte-identical, the host either
// did not apply what it claims or is not reading back what it applied. When the artifact is *also*
// unchanged there is nothing to explain — that is the ordinary case above.
//
// This is why the check needs `artifactHash` remembered alongside the dump digest. Without it the two
// situations are indistinguishable, which is exactly why the original sentence conflated them.

import type { Heartbeat, Manifest } from "./protocol.ts";

/**
 * What the relay remembers about a host's last confirmation.
 *
 * Memory-only and re-derived from heartbeats, like everything else in `RelayState`. A restart costs
 * one generation's worth of history, which means a contradiction spanning a restart is missed — worth
 * stating plainly, and not worth persisting for, because the alternative is a relay whose accusations
 * survive its own reboot and can no longer be checked against anything.
 */
export interface Reference {
  generation: string | null;
  /** Digest of the kernel dump when this generation was first confirmed. The drift baseline. */
  hash: string | null;
  /**
   * Digest of the artifact *text* that was applied then.
   *
   * Kept for this check and not for drift. It is what distinguishes "new generation, same rules"
   * (normal) from "new rules, unchanged kernel" (not).
   */
  artifactHash?: string | null;
}

/** One way a host's reporting does not hold together. */
export interface Contradiction {
  host: string;
  /** Stable slug, for logs and for tests that must not depend on prose. */
  kind:
    | "artifact-hash-changed"
    | "artifact-hash-wrong"
    | "unknown-generation"
    | "kernel-unchanged";
  /**
   * How much this proves.
   *
   * `certain` — no honest host produces this. Worth waking someone.
   * `unexplained` — every benign cause is unlikely but one exists; worth looking at, not worth an
   *   alarm on its own.
   *
   * The distinction is here because a firewall console that grades everything as an emergency gets
   * read as noise, and then the `certain` ones are missed too.
   */
  certainty: "certain" | "unexplained";
  /** Written for an operator: what was observed, and what it would take to be innocent. */
  detail: string;
}

/**
 * Compare one heartbeat against what this host said before, and against what it was served.
 *
 * Returns every contradiction found rather than the first, because they have different causes and an
 * operator seeing one of them would act differently than seeing three.
 *
 * **Never throws and never gates.** A contradiction is a claim about a host's honesty, and refusing
 * to serve it would be the relay acting on a suspicion — locking a host out of updates is how a
 * false positive becomes an outage. Reporting is the whole intervention.
 */
export function reportContradictions(
  hb: Heartbeat,
  prior: Reference | undefined,
  manifest: Manifest | null,
): Contradiction[] {
  const out: Contradiction[] = [];
  const host = hb.host;
  const gen = hb.applied.generation;
  const artifact = hb.applied.artifactHash;
  const observed = hb.applied.observedHash;

  // ## One generation names one artifact per host
  //
  // The manifest maps host → rulesetHash, and a published generation is immutable — `writePublish`
  // renames the manifest over atomically, so a given id never describes two different rulesets. A
  // host reporting the same generation with two different artifact digests has therefore said
  // something false at least once, regardless of which report was the true one.
  if (
    prior &&
    prior.generation !== null &&
    gen === prior.generation &&
    artifact !== null &&
    prior.artifactHash != null &&
    artifact !== prior.artifactHash
  ) {
    out.push({
      host,
      kind: "artifact-hash-changed",
      certainty: "certain",
      detail:
        `reported generation ${gen} with artifact ${short(artifact)} but earlier reported the same ` +
        `generation with ${short(prior.artifactHash)} — a generation names one artifact per host, so ` +
        `one of those reports was false`,
    });
  }

  const entry = manifest && manifest.hosts[host];

  // ## Confirming the current generation with the wrong artifact
  //
  // The agent checks this itself before applying and reverts on mismatch (`artifactMatches`). So a
  // host that reports `confirmed` on the generation we are serving, with a digest that is not the one
  // we published, is contradicting its own validator — either it skipped the check or it did not run
  // the code we think it runs.
  //
  // Only when the claimed generation *is* the manifest's. A host confirmed on the previous generation
  // mid-rollout is normal, and the relay no longer holds that generation's manifest to compare with.
  if (
    entry &&
    manifest &&
    hb.applied.state === "confirmed" &&
    gen === manifest.generation &&
    artifact !== null &&
    artifact !== entry.rulesetHash
  ) {
    out.push({
      host,
      kind: "artifact-hash-wrong",
      certainty: "certain",
      detail:
        `confirmed generation ${gen} with artifact ${short(artifact)}, but the manifest publishes ` +
        `${short(entry.rulesetHash)} for this host — the agent's own hash check should have refused ` +
        `this artifact and reverted`,
    });
  }

  // ## Confirming a generation that was never published to this host
  //
  // The relay only ever tells a host to move to the manifest's generation, and a rollback reports
  // `rolled-back` rather than `confirmed` on an older id. So `confirmed` on an id that is neither the
  // current generation nor the one this host last confirmed means it applied something this relay did
  // not serve.
  //
  // Deliberately requires a prior reference. Without one this is a host whose earlier history the
  // relay lost — on restart, or on first contact — and accusing it then would make every relay
  // restart produce a wave of false positives. That is a real gap and it is the right trade: the
  // check exists to catch a host that keeps talking to a relay that has been watching it.
  if (
    manifest &&
    hb.applied.state === "confirmed" &&
    gen !== null &&
    gen !== manifest.generation &&
    prior &&
    prior.generation !== null &&
    gen !== prior.generation
  ) {
    out.push({
      host,
      kind: "unknown-generation",
      certainty: "certain",
      detail:
        `confirmed generation ${gen}, which is neither the published ${manifest.generation} nor the ` +
        `${prior.generation} it last confirmed — this relay never served it that`,
    });
  }

  // ## New rules, unchanged kernel
  //
  // The honest form of the design document's first example. Both digests must have moved together:
  // if the artifact text differs, the table read back from the kernel should differ too.
  //
  // **`unexplained`, not `certain`.** Two artifacts can legitimately produce the same stateless dump —
  // the artifact is a command list whose preamble (`add table`, `delete table`) does not appear in the
  // dump, so a change confined to it would be invisible there. Rare, and not proof of anything, so it
  // is reported without being called a lie.
  if (
    prior &&
    prior.generation !== null &&
    gen !== null &&
    gen !== prior.generation &&
    artifact !== null &&
    prior.artifactHash != null &&
    artifact !== prior.artifactHash &&
    observed !== null &&
    prior.hash !== null &&
    observed === prior.hash
  ) {
    out.push({
      host,
      kind: "kernel-unchanged",
      certainty: "unexplained",
      detail:
        `moved from generation ${prior.generation} to ${gen} with a different artifact ` +
        `(${short(prior.artifactHash)} → ${short(artifact)}) but an identical kernel dump ` +
        `${short(observed)} — either the new rules were not applied, or the difference is confined to ` +
        `parts of the artifact a stateless dump does not show`,
    });
  }

  return out;
}

/** Digests are long and the leading bytes identify them well enough for a log line. */
function short(digest: string): string {
  return digest.startsWith("sha256:") ? digest.slice(0, 20) : digest.slice(0, 13);
}
