// Gating tests.
//
// The case that matters most is the one where a host locks itself out: the canary rolls back, and
// nothing behind it may advance. Every other case here exists to make sure that one is not
// achieved by simply refusing everything.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { contains } from "./test-util.ts";
import { computeGate, rolloutBlockers, hostVerdict, STALE_SEC, type HostStatus } from "./rollout.ts";
import { SCHEMA_VERSION, type Manifest } from "./protocol.ts";

const GEN = "6f98e0c";

const manifest: Manifest = {
  generation: GEN,
  issuedAt: "2026-07-30T00:00:00Z",
  schemaVersion: SCHEMA_VERSION,
  hosts: {
    "h-canary": { stage: "canary", rulesetHash: "sha256:1", confirmTimeoutSec: 60, mustContain: [] },
    "h-app-01": { stage: "general", rulesetHash: "sha256:2", confirmTimeoutSec: 60, mustContain: [] },
    "h-app-02": { stage: "general", rulesetHash: "sha256:3", confirmTimeoutSec: 60, mustContain: [] },
    "gw-dev": { stage: "gateway", rulesetHash: "sha256:4", confirmTimeoutSec: 120, mustContain: [] },
  },
};

const confirmed: HostStatus = { generation: GEN, state: "confirmed" };

describe("computeGate", () => {
  it("opens the canary immediately — nothing precedes it", () => {
    assert.equal(computeGate(manifest, "h-canary", {}).open, true);
  });

  it("holds general until the canary confirms", () => {
    const gate = computeGate(manifest, "h-app-01", {});
    assert.equal(gate.open, false);
    contains(gate.reason, "h-canary");
  });

  it("opens general once the canary confirms", () => {
    assert.equal(computeGate(manifest, "h-app-01", { "h-canary": confirmed }).open, true);
  });

  // The point of the whole mechanism. A rollback is the strongest evidence available that the
  // generation severs the management path, so it must stop the fleet rather than be retried past.
  it("stops the rollout when the canary rolled back", () => {
    const gate = computeGate(manifest, "h-app-01", {
      "h-canary": { generation: GEN, state: "rolled-back" },
    });
    assert.equal(gate.open, false);
    contains(gate.reason, "rolled back");
  });

  it("holds a host still pending confirmation", () => {
    const gate = computeGate(manifest, "h-app-01", {
      "h-canary": { generation: GEN, state: "pending" },
    });
    assert.equal(gate.open, false);
    contains(gate.reason, "not confirmed");
  });

  // Silence must not read as success, or a host that stopped heartbeating would wave the rest of
  // the fleet through on the strength of a stale confirmation.
  it("treats a host reporting an older generation as not reported", () => {
    const gate = computeGate(manifest, "h-app-01", {
      "h-canary": { generation: "older", state: "confirmed" },
    });
    assert.equal(gate.open, false);
    contains(gate.reason, "has not reported");
  });

  it("holds the gateway until every general host confirms", () => {
    const partial = { "h-canary": confirmed, "h-app-01": confirmed };
    const gate = computeGate(manifest, "gw-dev", partial);
    assert.equal(gate.open, false);
    contains(gate.reason, "h-app-02");
  });

  // The gateway runs the relay. If it locks itself out, the hosts behind it stop receiving
  // artifacts — including the one that would undo the damage. It goes last, after everything.
  it("opens the gateway only when all earlier stages confirm", () => {
    const all = { "h-canary": confirmed, "h-app-01": confirmed, "h-app-02": confirmed };
    assert.equal(computeGate(manifest, "gw-dev", all).open, true);
  });

  it("reports a host that is not part of the generation", () => {
    const gate = computeGate(manifest, "h-unknown", {});
    assert.equal(gate.open, false);
    contains(gate.reason, "not part of this generation");
  });
});

describe("rolloutBlockers", () => {
  it("is empty when every host confirmed", () => {
    const all = {
      "h-canary": confirmed,
      "h-app-01": confirmed,
      "h-app-02": confirmed,
      "gw-dev": confirmed,
    };
    assert.deepEqual(rolloutBlockers(manifest, all), []);
  });

  it("names every host that has not arrived", () => {
    const blockers = rolloutBlockers(manifest, { "h-canary": confirmed });
    assert.deepEqual(blockers.map((b) => b.host).sort(), ["gw-dev", "h-app-01", "h-app-02"]);
  });

  // A fully advanced rollout can still contain a host that reverted an earlier attempt. Gating
  // would say "proceed"; this has to say "look at that host".
  it("reports a rolled-back host even when the stage advanced", () => {
    const blockers = rolloutBlockers(manifest, {
      "h-canary": confirmed,
      "h-app-01": confirmed,
      "h-app-02": { generation: GEN, state: "rolled-back" },
      "gw-dev": confirmed,
    });
    assert.deepEqual(blockers, [{ host: "h-app-02", reason: BLOCKED_ROLLBACK }]);
  });
});

const BLOCKED_ROLLBACK = "rolled back — the generation is suspect";

// ── The workload half ─────────────────────────────────────────────────────────
//
// The combination these tests exist for: `state: confirmed` with a workload half that is not. Every
// other field on such a host reads as success, and the policies involved — pod and service
// destinations — have no host-layer rule behind them (evaluation rule 8). If that opens the next
// stage, a known-broken workload policy set spreads across the fleet.

const wlManifest: Manifest = {
  ...manifest,
  hosts: {
    ...manifest.hosts,
    "h-canary": {
      ...manifest.hosts["h-canary"]!,
      workload: {
        policiesHash: "sha256:w1",
        cluster: "dev",
        mustExist: ["util/hp-dev-p700"],
        confirmTimeoutSec: 300,
        policyCount: 1,
      },
    },
  },
};

const bothConfirmed: HostStatus = { generation: GEN, state: "confirmed", workloadState: "confirmed" };

describe("computeGate — the workload half", () => {
  it("holds general when the canary confirmed nftables but not the workload half", () => {
    const gate = computeGate(wlManifest, "h-app-01", {
      "h-canary": { generation: GEN, state: "confirmed", workloadState: "pending" },
    });
    assert.equal(gate.open, false);
    contains(gate.reason, "workload half");
  });

  it("holds general when the canary's workload half rolled back", () => {
    const gate = computeGate(wlManifest, "h-app-01", {
      "h-canary": { generation: GEN, state: "confirmed", workloadState: "rolled-back" },
    });
    assert.equal(gate.open, false);
    contains(gate.reason, "the generation is suspect");
  });

  it("treats an unreported workload half as blocking, not as satisfied", () => {
    // A schema-2 agent always reports the field when it has an assignment, so absence means it never
    // applied. Passing on unknown is how a cluster-scoped policy that was never written looks done.
    const gate = computeGate(wlManifest, "h-app-01", {
      "h-canary": { generation: GEN, state: "confirmed" },
    });
    assert.equal(gate.open, false);
    contains(gate.reason, "has not reported its workload half");
  });

  it("opens general once both halves confirm", () => {
    assert.equal(computeGate(wlManifest, "h-app-01", { "h-canary": bothConfirmed }).open, true);
  });

  it("does not block a host that was never assigned a workload half", () => {
    // `h-app-01` has no assignment, so its missing workload state must not hold the gateway stage.
    // Otherwise every host without a cluster would stall the rollout behind it.
    const gate = computeGate(wlManifest, "gw-dev", {
      "h-canary": bothConfirmed,
      "h-app-01": confirmed,
      "h-app-02": confirmed,
    });
    assert.equal(gate.open, true);
  });
});

describe("rolloutBlockers — the workload half", () => {
  it("reports a broken workload half on a host whose ruleset is clean", () => {
    const blockers = rolloutBlockers(wlManifest, {
      "h-canary": {
        generation: GEN,
        state: "confirmed",
        workloadState: "rolled-back",
        workloadDetail: "expected object util/hp-dev-p700 absent after apply",
      },
      "h-app-01": confirmed,
      "h-app-02": confirmed,
      "gw-dev": confirmed,
    });
    assert.equal(blockers.length, 1);
    assert.equal(blockers[0]!.host, "h-canary");
    contains(blockers[0]!.reason, "workload half");
    // The detail is what tells an operator which object went missing; without it they are back to
    // reading the host's journal over ssh.
    contains(blockers[0]!.reason, "util/hp-dev-p700");
  });

  it("is empty when both halves confirmed everywhere", () => {
    assert.deepEqual(
      rolloutBlockers(wlManifest, {
        "h-canary": bothConfirmed,
        "h-app-01": confirmed,
        "h-app-02": confirmed,
        "gw-dev": confirmed,
      }),
      [],
    );
  });
});

describe("hostVerdict — silence outranks the last thing a host said", () => {
  // ## The bug this pins
  //
  // On 2026-08-11 `mailer-03` had been dead for nine hours (Vultr migrated it onto a CPU whose
  // instruction set its glibc requires and does not have, so init never ran) and the site view
  // printed a green **confirmed** — because that was, truthfully, the last thing it ever said.
  //
  // The relay view already refused to do that. The site view had its own copy of the decision, and
  // the copy was missing the age check. Two renderers agreeing by inspection is what produced it,
  // so there is now one function and both call it.

  it("calls a host silent when its last report is older than the threshold, whatever it said", () => {
    // The exact regression. `confirmed` plus a stale age must not read as healthy.
    const v = hostVerdict({ ageSec: 31_974, state: "confirmed" });
    assert.deepEqual(v, { kind: "silent", ageSec: 31_974 });
  });

  it("still calls a fresh confirmed host confirmed", () => {
    // The known positive. Without this the test above passes on a function that condemns everything.
    assert.deepEqual(hostVerdict({ ageSec: 5, state: "confirmed" }), { kind: "confirmed" });
  });

  it("puts the boundary where the relay puts it", () => {
    // Exactly at the threshold is not yet stale — the relay's `staleAfterSec` uses `>` too, and the
    // two must agree or the console and the relay's own problem list disagree about one host.
    assert.equal(hostVerdict({ ageSec: STALE_SEC, state: "confirmed" }).kind, "confirmed");
    assert.equal(hostVerdict({ ageSec: STALE_SEC + 1, state: "confirmed" }).kind, "silent");
  });

  it("keeps drift ahead of silence", () => {
    // A host that drifted and then went quiet has a specific, worse problem. Reporting only the
    // silence would lose the fact that its ruleset changed under it.
    assert.deepEqual(hostVerdict({ drifted: true, ageSec: 99_999, state: "confirmed" }), { kind: "drift" });
  });

  it("distinguishes never reported from reported long ago", () => {
    // `null` and a large number are different answers — see `relay.ts`. Only one of them has an age
    // worth printing, and collapsing them hides whether a host was ever heard from at all.
    assert.deepEqual(hostVerdict({ ageSec: null, state: "confirmed" }), { kind: "never-seen" });
    assert.equal(hostVerdict({ ageSec: 91, state: "confirmed" }).kind, "silent");
  });

  it("passes any other fresh state through rather than inventing a word for it", () => {
    assert.deepEqual(hostVerdict({ ageSec: 3, state: "pending" }), { kind: "other", state: "pending" });
  });

  // 🔴 **The `behind` branch had no test at all** — `current`, `behind` and `blockedBy` appeared
  // nowhere in this file, and deleting the line left every case green. Its neighbours (drift,
  // rollback, maintenance, silence) each have a paired test; this one was the gap.
  //
  // What it decides is the same class of thing as the regression at the top of this file: a host
  // that is reporting *healthily about the wrong generation*. `confirmed` describes the generation
  // the host is running, not the one being rolled out — so a green row beside a `wanted elsewhere`
  // generation is the table contradicting itself in two columns, which is exactly how `manager.ts`
  // and `protocol.ts` record having been misled before.
  it("says a host on an older generation is behind, not confirmed", () => {
    assert.deepEqual(
      hostVerdict({ ageSec: 5, state: "confirmed", current: false }),
      { kind: "behind", blockedBy: null, state: "confirmed" },
    );
  });

  it("carries what is blocking it, and the state it is blocked in", () => {
    // Both fields are the reason this is `behind` rather than a bare flag: the row has to say why a
    // host has not moved, or the operator's next question has no answer on the screen.
    assert.deepEqual(
      hostVerdict({ ageSec: 5, state: "pending", current: false, blockedBy: "canary" }),
      { kind: "behind", blockedBy: "canary", state: "pending" },
    );
  });

  it("keeps silence and drift ahead of being behind", () => {
    // Ordering, in the direction that matters. A host that is behind *and* silent has the worse
    // problem, and the same is true of drift — being behind is a rollout fact, those two are host
    // facts. Pinned because the ordering in this function has been wrong before.
    assert.equal(hostVerdict({ ageSec: 99_999, state: "confirmed", current: false }).kind, "silent");
    assert.equal(hostVerdict({ drifted: true, ageSec: 5, state: "confirmed", current: false }).kind, "drift");
  });

  it("a host that is current is judged on its state, not called behind", () => {
    // The known positive for the branch above: without it the tests here pass against a function
    // that calls every host behind.
    assert.deepEqual(hostVerdict({ ageSec: 5, state: "confirmed", current: true }), { kind: "confirmed" });
    // …and an absent `current` is "the caller did not say", which must not read as `false`.
    assert.deepEqual(hostVerdict({ ageSec: 5, state: "confirmed" }), { kind: "confirmed" });
  });

  // ## The ordering around `maintenance`, pinned in both directions
  //
  // `hostVerdict` carried the same `if (h.maintenance)` twice — once above `never-seen` and once
  // below it. The second was unreachable, and **deleting either copy broke no test**, which is why
  // it survived long enough to accumulate a comment arguing for the order it no longer had.
  //
  // Both directions are asserted because only the pair is a statement about ordering. The first
  // case alone passes with the check anywhere above `silent`; the second alone passes with it
  // anywhere below `drift`.
  it("puts a declared exemption above every form of silence", () => {
    // Measured 2026-08-11: relay state is memory-only, so **every** host reads as never-seen for a
    // minute after a relay restart — and a host that is genuinely gone stays there for good.
    // `mailer-03` was declared out of service and the console still drew `never seen`.
    assert.deepEqual(
      hostVerdict({ ageSec: null, state: null, maintenance: "vultr migrated it onto a CPU its libc cannot use" }),
      { kind: "maintenance", reason: "vultr migrated it onto a CPU its libc cannot use" },
    );
    assert.equal(hostVerdict({ ageSec: 99_999, state: "confirmed", maintenance: "out for repair" }).kind, "maintenance");
  });

  it("keeps drift and rollback above a declared exemption", () => {
    // Those are statements the host itself made about the generation. An exemption from being
    // waited on must not erase evidence the host already produced.
    assert.equal(hostVerdict({ drifted: true, ageSec: null, state: "confirmed", maintenance: "out for repair" }).kind, "drift");
    assert.equal(hostVerdict({ ageSec: 5, state: "rolled-back", maintenance: "out for repair" }).kind, "rolled-back");
  });
});

describe("a host declared out of service", () => {
  // ## What this buys and what it deliberately does not
  //
  // On 2026-08-11 `mailer-03` was migrated by its provider onto a CPU whose instruction set its
  // libc requires and does not have. It never booted, never reported, and the `gateway` stage stayed
  // shut for a day behind a host that was not coming back on its own. The fleet was correct and
  // stuck.
  //
  // The tempting fix — advance past hosts that have been quiet long enough — is the one thing this
  // gate must never do. A host that has just locked itself out reports exactly nothing too, and one
  // rule cannot serve both: skipping the dead host and skipping the bricked one are the same code.
  // So `maintenance` is a sentence a person wrote in the policy, not a conclusion drawn from an age.
  const withMaintenance = (host: string, reason: string): Manifest => ({
    ...manifest,
    hosts: { ...manifest.hosts, [host]: { ...manifest.hosts[host]!, maintenance: reason } },
  });

  it("stops holding the next stage shut", () => {
    // The regression this exists for: `h-app-02` is silent and out of service, so `gateway` opens
    // on the strength of the peers that did report.
    const m = withMaintenance("h-app-02", "vultr migrated it onto an unsupported CPU");
    const gate = computeGate(m, "gw-dev", { "h-canary": confirmed, "h-app-01": confirmed });
    // `?? …` because `reason` is optional: the message is only ever printed when this assertion
    // fails, which is when the gate is shut and therefore does carry one — but "the failure message
    // may be undefined" is not a property worth leaving in a test whose whole value is saying why
    // the gate did not open. Newer `@types/node` refuses it outright; that is the type catching a
    // real, if small, hole rather than being pedantic.
    assert.equal(gate.open, true, gate.reason ?? "the gate is shut and reported no reason");
  });

  it("does not excuse the other hosts in that stage, whichever order they are visited in", () => {
    // The known negative, and the property that keeps this from being "skip the stage": one host out
    // of service must not turn its stage into a no-op.
    //
    // **Both orders, because the first version of this test only checked one and a bad
    // implementation walked through it.** Marking the *whole stage* open on meeting a flagged host
    // is wrong, and it survives a test where the flagged host is visited second — the loop stops at
    // the still-silent peer before it ever reaches the flag. `Object.entries` order made the defect
    // invisible, so the flagged host is placed on each side of the silent one here.
    for (const [flagged, silent] of [["h-app-02", "h-app-01"], ["h-app-01", "h-app-02"]] as const) {
      const m = withMaintenance(flagged, "out for repair");
      const gate = computeGate(m, "gw-dev", { "h-canary": confirmed });
      assert.equal(gate.open, false, `${flagged} flagged: gate opened with ${silent} still silent`);
      contains(gate.reason, silent);
    }
  });

  it("still blocks on a host that is merely silent", () => {
    // Without this the test above passes on a gate that ignores silence entirely, which is the
    // failure mode staged rollout exists to prevent.
    const gate = computeGate(manifest, "gw-dev", { "h-canary": confirmed, "h-app-01": confirmed });
    assert.equal(gate.open, false);
    contains(gate.reason, "h-app-02");
  });

  it("does not excuse a host that reported a rollback", () => {
    // Maintenance says "do not wait for this host", not "ignore what it told you". A host that
    // applied the generation and reverted has produced evidence about the generation itself, and
    // that evidence outlives its own availability — marking it out of service must not erase it.
    const m = withMaintenance("h-canary", "scheduled reboot");
    const gate = computeGate(m, "h-app-01", { "h-canary": { generation: GEN, state: "rolled-back" } });
    assert.equal(gate.open, true, "the flag was set, so the peer is not waited on");
    // …and the rollback is still visible to anything that reads statuses. `rolloutBlockers` is what
    // an operator sees, and it must not go quiet because a host was excused from the gate.
    const blockers = rolloutBlockers(m, { "h-canary": { generation: GEN, state: "rolled-back" } });
    assert.ok(blockers.some((b) => b.host === "h-canary"), JSON.stringify(blockers));
  });

  it("still applies to the host itself — it keeps its ruleset", () => {
    // The reason this is not "delete it from the policy". Its rules still render and still ship, so
    // when it comes back it applies the current generation like any other host.
    const m = withMaintenance("h-app-01", "out for repair");
    assert.ok(m.hosts["h-app-01"]!.rulesetHash, "the ruleset must survive the flag");
    assert.equal(computeGate(m, "h-app-01", { "h-canary": confirmed }).open, true);
  });
});
