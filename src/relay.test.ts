// Relay heartbeat-handling tests.
//
// Two things are pinned hardest here, because both fail silently in production:
//   - identity binding, without which staged rollout is decorative
//   - drift references keyed by generation, without which a correct deploy looks like tampering
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { contains, excludes } from "./test-util.ts";
import { emptyState, fleetView, handleHeartbeat, type ProblemKind, type RelayState } from "./relay.ts";
import { SCHEMA_VERSION, type Heartbeat, type HeartbeatReply, type Manifest } from "./protocol.ts";

const GEN = "6f98e0c";
const AT = "2026-07-30T00:00:00Z";

const manifest: Manifest = {
  generation: GEN,
  issuedAt: AT,
  schemaVersion: SCHEMA_VERSION,
  hosts: {
    "h-canary": { stage: "canary", rulesetHash: "sha256:1", confirmTimeoutSec: 60, mustContain: [] },
    "h-app-01": { stage: "general", rulesetHash: "sha256:2", confirmTimeoutSec: 60, mustContain: [] },
  },
};

/**
 * The digest the manifest publishes for a host.
 *
 * Derived rather than hardcoded, because an agent applies what it was served: reporting `sha256:1`
 * while the manifest publishes `sha256:2` for that host is a state no honest host reaches. H30's
 * `artifact-hash-wrong` check found this fixture claiming exactly that — the check working, not a
 * false positive.
 *
 * Module-level so both suites read the same value. A second copy would drift from the manifest the
 * first time one of them is edited.
 */
const artifactFor = (host: string) => manifest.hosts[host]?.rulesetHash ?? "sha256:1";

function state(): RelayState {
  const s = emptyState();
  s.manifest = manifest;
  return s;
}

type HeartbeatOverride = Omit<Partial<Heartbeat>, "applied"> & {
  applied?: Partial<Heartbeat["applied"]>;
};

function hb(over: HeartbeatOverride = {}): Heartbeat {
  return {
    host: "h-canary",
    agentVersion: "0.1.0-pull",
    schemaVersion: SCHEMA_VERSION,
    ...over,
    applied: {
      generation: null,
      state: "none",
      artifactHash: null,
      observedHash: null,
      ...(over.applied ?? {}),
    },
  };
}

const reply = (o: { body: HeartbeatReply | { error: string } }) => o.body as HeartbeatReply;

// ## The heartbeat field the relay used to drop
//
// `handleHeartbeat` copied the heartbeat into `HostStatus` field by field — with a comment on each
// explaining why it was kept — and `artifactTrust` was absent, so it stopped at the relay.
//
// ⚠️ This used to say the agent built and transmitted it every interval. **It did not** — the agent
// defined `artifact_trust_report` and called it nowhere until issue #145. These tests hand the relay
// an object the agent never sent, so they were green while every check here was silent in the
// fleet. What the agent sends is pinned on its side, by `TestTheHeartbeatCarriesArtifactTrust`.
//
// The block that used to be here pinned that. It said, in as many words, that the day it failed
// because something started reading the field would be the day the feature arrived and the note on
// `Heartbeat.artifactTrust` was what to delete. It failed on 2026-08-24. This is what replaced it.
//
// Two readings, and only two. `currentPlanHash` and `currentPayloadHash` would answer "is a host
// enforcing something we did not issue", and they are carried unread on purpose — that comparison
// needs the manifest to name the authorization it published, and the manifest is hashed into the
// approval bundle.
describe("what the fleet reports about which keys may sign", () => {
  const trust = (over: Partial<NonNullable<Heartbeat["artifactTrust"]>> = {}) => ({
    managerKeyIds: ["mk-1"],
    breakGlassKeyIds: ["bg-1"],
    trustDigest: "sha256:aaaaaaaaaaaa",
    currentKeyId: "mk-1",
    currentPayloadHash: "sha256:pppp",
    currentAuthorizationMode: "two-person" as const,
    currentAuthorizedAt: "2026-08-24T00:00:00Z",
    currentPlanHash: "sha256:hhhh",
    ...over,
  });

  it("keeps it, so the manager can be told about it at all", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ artifactTrust: trust() }), AT);
    assert.equal(s.statuses["h-canary"]?.artifactTrust?.trustDigest, "sha256:aaaaaaaaaaaa");
  });

  it("distinguishes an agent that sent none from one that sent an empty ring", () => {
    // The `?? null` contract its neighbours keep. `undefined` is an agent too old to send this;
    // `null` is one that did and trusts nothing — and those are not the same host.
    const s = state();
    handleHeartbeat(s, "h-canary", hb(), AT);
    assert.equal(s.statuses["h-canary"]?.artifactTrust, null);
  });

  it("says nothing when every host agrees", () => {
    // The known negative, and the one that matters most: this line appears on a healthy fleet only
    // if the check is wrong, and a `problems` list that cries wolf is one nobody reads.
    const s = state();
    for (const host of Object.keys(manifest.hosts)) {
      handleHeartbeat(s, host, hb({ host, artifactTrust: trust() }), AT);
    }
    const view = fleetView(s, new Date(AT), 300);
    assert.deepEqual(view.problems.filter((p) => p.includes("may sign")), []);
  });

  it("reports a fleet that does not agree, and names both sides", () => {
    // A rotation that reached some hosts and not others. Nothing else in this system can say so:
    // only the host knows which keys it will accept, and "the new signing key is deployed" is
    // otherwise an assumption about a file.
    const s = state();
    const hosts = Object.keys(manifest.hosts);
    handleHeartbeat(s, hosts[0]!, hb({ host: hosts[0]!, artifactTrust: trust() }), AT);
    for (const host of hosts.slice(1)) {
      handleHeartbeat(s, host, hb({ host, artifactTrust: trust({ trustDigest: "sha256:bbbbbbbbbbbb" }) }), AT);
    }
    const line = fleetView(s, new Date(AT), 300).problems.find((p) => p.includes("may sign"));
    assert.ok(line, "a split ring must be reported");
    assert.match(line!, /sha256:aaaaaaa/);
    assert.match(line!, /sha256:bbbbbbb/);
    assert.match(line!, new RegExp(hosts[0]!));
    // Said as a state, not a fault: mid-rotation this is the expected reading and is supposed to be
    // visible while it lasts.
    assert.match(line!, /rotation/);
  });

  it("does not count a host that reported no ring as a third answer", () => {
    // An agent too old to send this is not a host that disagrees. Counting it would make every
    // partially upgraded fleet report a split that is not there.
    const s = state();
    const hosts = Object.keys(manifest.hosts);
    handleHeartbeat(s, hosts[0]!, hb({ host: hosts[0]!, artifactTrust: trust() }), AT);
    for (const host of hosts.slice(1)) handleHeartbeat(s, host, hb({ host }), AT);
    assert.deepEqual(fleetView(s, new Date(AT), 300).problems.filter((p) => p.includes("may sign")), []);
  });

  it("reports a break-glass authorization that is still in force", () => {
    // The mode that skips the two-person rule. The manager keeps no record of authorizations it
    // issued — `approval.ts` deletes a plan the moment it is published, because an approval that
    // outlives its publish is a standing permission — so the host enforcing it is the only place its
    // duration is visible.
    const s = state();
    handleHeartbeat(
      s, "h-canary",
      hb({ artifactTrust: trust({ currentAuthorizationMode: "break-glass", currentAuthorizedAt: "2026-08-01T00:00:00Z" }) }),
      AT,
    );
    const line = fleetView(s, new Date(AT), 300).problems.find((p) => p.includes("break-glass"));
    assert.ok(line, "a live break-glass must be reported");
    assert.match(line!, /2026-08-01/, "when it was authorized is the whole question");
    assert.match(line!, /h-canary/);
  });

  it("reports a host enforcing a generation it cannot name the authorization for", () => {
    // ## The fifth silence, and it hid inside the alarm above
    //
    // That line compares `=== "break-glass"`, so a `null` mode reads as *not* break-glass — the calm
    // answer, and not an answer. It was the whole fleet's state: `confirm()` never promoted
    // `pendingAuthorization` into `currentAuthorization` until 2026-09-29, which left the
    // expired-but-confirmed re-apply escape dark as well. That is how a gateway came to hold zero nft
    // rules with public v6:22 answering for 39 hours — an expired authorization and no way to
    // re-apply it.
    const s = state();
    handleHeartbeat(
      s, "h-canary",
      hb({
        artifactTrust: trust({ currentAuthorizationMode: null, currentAuthorizedAt: null }),
        applied: { generation: "g-live", state: "confirmed", artifactHash: null, observedHash: null },
      }),
      AT,
    );
    const line = fleetView(s, new Date(AT), 300).problems.find((p) => p.includes("cannot name"));
    assert.ok(line, "a host that cannot name its authorization must be reported");
    assert.match(line!, /g-live/, "which generation it is enforcing is half the sentence");
    assert.match(line!, /h-canary/);
  });

  it("distinguishes a host that cannot name one from an agent that never said", () => {
    // ## The distinction that keeps the line above honest
    //
    // `artifactTrust` absent is an agent too old to send the object — "did not say", not "cannot
    // name". Collapsing the two would turn a reporting gap into an alarm about the firewall, and it
    // would fire hardest on the hosts it knows least about. Same distinction `agentBuildSplit` draws
    // between builds and `unknown`, and the `?? null` contract this file keeps everywhere else.
    const s = state();
    handleHeartbeat(
      s, "h-canary",
      hb({ applied: { generation: "g-live", state: "confirmed", artifactHash: null, observedHash: null } }),
      AT,
    );
    assert.equal(
      fleetView(s, new Date(AT), 300).problems.find((p) => p.includes("cannot name")), undefined,
      "an agent that sent no trust object was reported as enforcing something it cannot name",
    );
  });

  it("says nothing about a healthy first apply that has not been confirmed yet", () => {
    // The agent promotes `pendingAuthorization` into `currentAuthorization` only in `confirm()`, after
    // the relay has answered the `pending` heartbeat. So the first beat of every healthy first apply
    // carries a null mode. This was hidden while the agent sent no `artifactTrust` at all (#145); the
    // review of that fix reproduced the false alarm.
    const s = state();
    handleHeartbeat(
      s, "h-canary",
      hb({
        artifactTrust: trust({ currentAuthorizationMode: null, currentAuthorizedAt: null }),
        applied: { generation: "g-first", state: "pending", artifactHash: null, observedHash: null },
      }),
      AT,
    );
    assert.equal(
      fleetView(s, new Date(AT), 300).problems.find((p) => p.includes("cannot name")), undefined,
      "a pending first apply was reported as enforcing an authorization it cannot name",
    );
  });

  it("says nothing about a host that has applied nothing at all", () => {
    // A host with no generation has no authorization to name, so this would otherwise fire loudest on
    // the hosts it has nothing to say about — every freshly enrolled machine.
    const s = state();
    handleHeartbeat(
      s, "h-canary",
      hb({ artifactTrust: trust({ currentAuthorizationMode: null, currentAuthorizedAt: null }) }),
      AT,
    );
    assert.equal(
      fleetView(s, new Date(AT), 300).problems.find((p) => p.includes("cannot name")), undefined,
      "reported a host that has applied nothing",
    );
  });

  it("says nothing about an ordinary two-person authorization", () => {
    // The known negative. Without it, a check that reported every mode would pass the test above and
    // put a line on the screen for every healthy host.
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ artifactTrust: trust() }), AT);
    assert.deepEqual(
      fleetView(s, new Date(AT), 300).problems.filter((p) => p.includes("break-glass")),
      [],
    );
  });

  it("reports a host that could not read its signing trust, and keeps why", () => {
    // Issue #145. Without this the host looks exactly like an agent too old to send `artifactTrust`,
    // and every check in this block skips it.
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ artifactTrustError: "manager artifact public key directory is not configured" }), AT);
    assert.equal(s.statuses["h-canary"]?.artifactTrustError, "manager artifact public key directory is not configured");
    const line = fleetView(s, new Date(AT), 300).problems.find((p) => p.includes("signing trust"));
    assert.ok(line, "a host that could not read its trust must be reported");
    assert.match(line!, /h-canary/);
    assert.match(line!, /not configured/);
  });

  it("does not report an agent that said nothing about its trust", () => {
    // The known negative: an older agent sends neither field, and that is not a failure to read.
    const s = state();
    handleHeartbeat(s, "h-canary", hb(), AT);
    assert.equal(s.statuses["h-canary"]?.artifactTrustError, null);
    assert.deepEqual(fleetView(s, new Date(AT), 300).problems.filter((p) => p.includes("signing trust")), []);
  });
});

describe("identity binding", () => {
  it("refuses a connection with no subject CN", () => {
    assert.equal(handleHeartbeat(state(), null, hb(), AT).status, 401);
  });

  // The attack this stops: a compromised general host reports as the canary with state
  // "confirmed", the canary gate opens on a generation nobody actually tested, and a locking
  // policy proceeds to the rest of the fleet.
  it("refuses a host reporting under someone else's name", () => {
    const out = handleHeartbeat(state(), "h-app-01", hb({ host: "h-canary" }), AT);
    assert.equal(out.status, 403);
    contains((out.body as { error: string }).error, "h-app-01");
  });

  it("does not silently rewrite the claimed host to the certificate name", () => {
    const s = state();
    handleHeartbeat(s, "h-app-01", hb({ host: "h-canary" }), AT);
    assert.equal(s.statuses["h-canary"], undefined);
    assert.equal(s.statuses["h-app-01"], undefined);
  });

  it("accepts a host whose payload matches its certificate", () => {
    assert.equal(handleHeartbeat(state(), "h-canary", hb(), AT).status, 200);
  });
});

describe("gating", () => {
  it("hands the canary its generation immediately", () => {
    const out = handleHeartbeat(state(), "h-canary", hb(), AT);
    assert.equal(reply(out).generation, GEN);
    assert.equal(reply(out).gate.open, true);
  });

  it("tells a later stage to wait while naming what it waits on", () => {
    const out = handleHeartbeat(state(), "h-app-01", hb({ host: "h-app-01" }), AT);
    assert.equal(reply(out).gate.open, false);
    contains(reply(out).gate.reason, "h-canary");
  });

  // `observedHash` is part of being current, not decoration: a host that cannot dump its own table
  // is not holding the ruleset, whatever its state file says. See the re-apply suite below.
  it("stops handing out work once a host is current", () => {
    const current = hb({ applied: { generation: GEN, state: "confirmed", observedHash: "dump:1" } });
    assert.equal(reply(handleHeartbeat(state(), "h-canary", current, AT)).generation, null);
  });

  it("has nothing for a host outside the generation", () => {
    const out = handleHeartbeat(state(), "h-other", hb({ host: "h-other" }), AT);
    assert.equal(reply(out).generation, null);
  });

  // Answering "wait" beats answering nothing: agents keep a working relay connection and the
  // reason is visible, rather than every host behind this gateway logging a transport failure.
  it("answers with a reason when no manifest is loaded", () => {
    const out = handleHeartbeat(emptyState(), "h-canary", hb(), AT);
    assert.equal(out.status, 200);
    contains(reply(out).gate.reason, "no manifest");
  });

  it("refuses to instruct an agent on a different schema", () => {
    const out = handleHeartbeat(state(), "h-canary", hb({ schemaVersion: 99 }), AT);
    assert.equal(reply(out).generation, null);
    contains(reply(out).gate.reason, "99");
  });
});

describe("drift", () => {
  const confirmed = (generation: string, observedHash: string) =>
    hb({ applied: { generation, state: "confirmed", observedHash, artifactHash: "sha256:1" } });

  it("takes the first confirmation as the baseline", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", confirmed(GEN, "dump:1"), AT);
    assert.equal(s.drifted.has("h-canary"), false);
    assert.equal(s.references["h-canary"]?.hash, "dump:1");
  });

  it("flags a table that changed after confirmation", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", confirmed(GEN, "dump:1"), AT);
    handleHeartbeat(s, "h-canary", confirmed(GEN, "dump:2"), AT);
    assert.equal(s.drifted.has("h-canary"), true);
  });

  it("clears the flag if the table is put back", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", confirmed(GEN, "dump:1"), AT);
    handleHeartbeat(s, "h-canary", confirmed(GEN, "dump:2"), AT);
    handleHeartbeat(s, "h-canary", confirmed(GEN, "dump:1"), AT);
    assert.equal(s.drifted.has("h-canary"), false);
  });

  // Without generation-keyed references, every successful deploy after the first would be
  // reported as tampering — and an alarm that fires on correct behaviour gets switched off.
  it("rebinds the baseline when a new generation is confirmed", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", confirmed(GEN, "dump:1"), AT);
    handleHeartbeat(s, "h-canary", confirmed("next-gen", "dump:2"), AT);
    assert.equal(s.drifted.has("h-canary"), false);
    // Asserted field by field rather than with `deepEqual` on the whole object. The reference gained
    // `artifactHash` for H30, and an exhaustive comparison here would fail every time the reference
    // grows a field that has nothing to do with rebinding — which is what this test is about.
    assert.equal(s.references["h-canary"]?.generation, "next-gen");
    assert.equal(s.references["h-canary"]?.hash, "dump:2");
  });

  // An unconfirmed host must not get to move the baseline — otherwise anything that can make the
  // agent report `pending` can launder a change past drift detection.
  it("ignores dumps reported while not confirmed", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", confirmed(GEN, "dump:1"), AT);
    const pending = hb({
      applied: { generation: GEN, state: "pending", observedHash: "dump:9", artifactHash: null },
    });
    handleHeartbeat(s, "h-canary", pending, AT);
    assert.equal(s.references["h-canary"]?.hash, "dump:1");
  });
});

// A host that cannot see its own table must not poison its drift reference.
//
// Measured on mailer-01: while its table was absent after a reboot it reported `observedHash: null`,
// the relay recorded that null as the baseline, and once the table was correctly restored every
// later beat read as drift against null — permanently. A drift alarm that stays on after the
// problem is fixed is one that gets ignored, which is the same as not having it.
describe("drift reference during an outage", () => {
  const beat = (observedHash: string | null) =>
    hb({ applied: { generation: GEN, state: "confirmed", artifactHash: "sha256:1", observedHash } });

  it("does not take an absent table as the baseline", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", beat(null), AT);
    assert.equal(s.references["h-canary"]?.hash ?? null, null);
    assert.equal(s.drifted.has("h-canary"), false, "a lost table is a re-apply, not drift");
  });

  // The sequence that actually happened: healthy, then table lost, then table restored identically.
  it("clears rather than latches once a real dump returns", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", beat("dump:1"), AT);
    handleHeartbeat(s, "h-canary", beat(null), AT); // reboot: table gone
    handleHeartbeat(s, "h-canary", beat("dump:1"), AT); // re-applied, same ruleset
    assert.equal(s.drifted.has("h-canary"), false, "the alarm must not survive the fix");
    assert.equal(s.references["h-canary"]?.hash, "dump:1");
  });

  // And the real thing must still be caught afterwards, or the exemption above would be a hole.
  it("still detects a genuine change after an outage", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", beat(null), AT);
    handleHeartbeat(s, "h-canary", beat("dump:1"), AT);
    handleHeartbeat(s, "h-canary", beat("dump:2"), AT);
    assert.equal(s.drifted.has("h-canary"), true);
  });
});

// A confirmed host that no longer holds its ruleset must be given the generation back.
//
// Measured on a real host: after a reboot, mailer-01 held only `table inet firewalld` — kernel
// memory does not survive — while its state file still read `confirmed`. The relay replied
// `generation: null` ("nothing to do"), so the agent could not act even though its own dump was
// empty and it had code to handle exactly this. Under default-deny that is a firewall that silently
// ceases to exist while the control plane reports it present.
describe("re-applying after the kernel loses the table", () => {
  const beat = (over: Partial<Heartbeat["applied"]>) =>
    hb({ applied: { generation: GEN, state: "confirmed", artifactHash: "sha256:1", observedHash: "dump:1", ...over } });

  it("withholds the generation from a host that is confirmed and holding it", () => {
    const r = reply(handleHeartbeat(state(), "h-canary", beat({}), AT));
    assert.equal(r.generation, null, "the normal case must not re-apply every beat");
  });

  // `observedHash: null` is what an agent reports when it cannot dump its own table at all.
  it("hands the generation back when the host cannot see its own table", () => {
    const r = reply(handleHeartbeat(state(), "h-canary", beat({ observedHash: null }), AT));
    assert.equal(r.generation, GEN, "a host whose table has vanished must be told to re-apply");
  });
});

// ── fleet view ────────────────────────────────────────────────────────────────
//
// What `/status` returns. The property that matters most is that none of the bad states can be
// mistaken for a good one — a fleet view that reads "fine" while a host is silent or drifted is
// worse than no fleet view, because it is consulted instead of the hosts.

describe("fleetView", () => {
  it("reports the exact plan receipt loaded with the manifest", () => {
    const s = state();
    s.planHash = `sha256:${"a".repeat(64)}`;
    assert.equal(fleetView(s, new Date(AT)).planHash, s.planHash);
  });

  const NOW = new Date("2026-07-30T00:01:00Z");
  // `host` is a parameter because identity binding compares it against the CN — passing the
  // default "h-canary" while claiming to be another host is a 403, which is the mechanism working.
  const confirmed = (generation: string, host = "h-canary", observedHash = "dump:1") =>
    hb({ host, applied: { generation, state: "confirmed", observedHash, artifactHash: artifactFor(host) } });

  it("reports a host that has never been heard from rather than omitting it", () => {
    // Omitting it would make a host that failed to enrol indistinguishable from one that does not
    // exist. The first needs attention; the second is not a fact about this fleet at all.
    const v = fleetView(state(), NOW);
    assert.deepEqual(v.hosts.map((h) => h.host).sort(), ["h-app-01", "h-canary"]);
    assert.equal(v.hosts.find((h) => h.host === "h-canary")!.state, null);
    contains(v.problems.join("|"), "never reported");
  });

  // ── The agent build, finally compared against something ──────────────────
  //
  // `agentVersion` has travelled from the heartbeat to this view since 2026-08-07 and was read by
  // nothing. `MIN_AGENT_SCHEMA` stops a rollout at a host speaking the wrong schema; there was no
  // equivalent for a host speaking the right one from an old build, so a half-upgraded fleet said
  // nothing anywhere — every host confirms, and the version is a column nobody diffs.

  it("says nothing about agent versions when no floor is configured", () => {
    // The known positive for the whole feature, and the one that keeps it from becoming noise on
    // every deployment that never asked the question.
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ agentVersion: "0.1.0-ancient" }), AT);
    const v = fleetView(s, NOW, 90, undefined, undefined);
    assert.equal(v.problems.filter((p) => p.includes("agent")).length, 0);
  });

  it("reports a host running a build below the floor", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ agentVersion: "0.5.0-pull-signed" }), AT);
    const v = fleetView(s, NOW, 90, undefined, [0, 6, 0]);
    contains(v.problems.join("|"), "runs agent 0.5.0-pull-signed, below the 0.6.0 floor");
  });

  it("says nothing about a host at or above the floor", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ agentVersion: "0.6.0-pull-signed-routes" }), AT);
    const v = fleetView(s, NOW, 90, undefined, [0, 6, 0]);
    assert.equal(v.problems.filter((p) => p.includes("floor")).length, 0);
  });

  it("treats an agent too old to send a version as older than any floor", () => {
    // `null` is not "unknown, leave it alone" — the field has been sent since 2026-08-07, so a host
    // omitting it predates that, which is strictly below anything anyone would set as a floor.
    const s = state();
    const beat = hb({ agentVersion: "0.6.0" });
    delete (beat as { agentVersion?: unknown }).agentVersion;
    handleHeartbeat(s, "h-canary", beat, AT);
    const v = fleetView(s, NOW, 90, undefined, [0, 6, 0]);
    contains(v.problems.join("|"), "reports no agent version");
  });

  it("says it cannot read a version rather than calling it old", () => {
    // A build string this manager does not understand is not evidence about the host. Reporting it
    // as "below the floor" would be an accusation drawn from our own parser's limits.
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ agentVersion: "nightly-2026-08-22" }), AT);
    const v = fleetView(s, NOW, 90, undefined, [0, 6, 0]);
    contains(v.problems.join("|"), "cannot read");
  });

  it("marks a host on the published generation as current", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", confirmed(GEN), AT);
    const h = fleetView(s, NOW).hosts.find((x) => x.host === "h-canary")!;
    assert.equal(h.current, true);
    assert.equal(h.state, "confirmed");
  });

  it("says which host is holding a later stage back", () => {
    const s = state();
    const h = fleetView(s, NOW).hosts.find((x) => x.host === "h-app-01")!;
    contains(h.blockedBy ?? "", "h-canary");
  });

  // A confirmed host is not "blocked" — reporting a gate reason for it would read as a problem
  // where there is none, and the whole point of this view is that its warnings mean something.
  it("does not report a blocker for a host that already applied", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", confirmed(GEN), AT);
    handleHeartbeat(s, "h-app-01", confirmed(GEN, "h-app-01"), AT);
    assert.equal(fleetView(s, NOW).hosts.find((x) => x.host === "h-app-01")!.blockedBy, null);
  });

  // Silence is its own failure mode: a host that stopped heartbeating is not applying policy and
  // not reporting drift either, so every other field still looks healthy.
  it("treats a silent host as a problem", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", confirmed(GEN), AT);
    handleHeartbeat(s, "h-app-01", confirmed(GEN, "h-app-01"), AT);
    const later = new Date("2026-07-30T01:00:00Z");
    contains(fleetView(s, later).problems.join("|"), "silent");
  });

  it("surfaces drift as a problem", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", confirmed(GEN, "h-canary", "dump:1"), AT);
    handleHeartbeat(s, "h-canary", confirmed(GEN, "h-canary", "dump:2"), AT);
    contains(fleetView(s, NOW).problems.join("|"), "no longer matches");
  });

  // The reason a rollback happened is the first thing anyone asks. It arrives on the heartbeat and
  // the relay used to discard it, which left the answer only in the host's own journal — reachable
  // by ssh, which is what this endpoint exists to stop being necessary.
  it("carries the host's own explanation of a rollback", () => {
    const s = state();
    const rolled = hb({
      applied: {
        generation: GEN,
        state: "rolled-back",
        artifactHash: "sha256:1",
        observedHash: null,
        detail: "required rules absent after apply: baseline: management SSH",
      },
    });
    handleHeartbeat(s, "h-canary", rolled, AT);
    const v = fleetView(s, NOW);
    contains(v.hosts.find((h) => h.host === "h-canary")!.detail ?? "", "management SSH");
    contains(v.problems.join("|"), "rolled back");
  });

  // Relay state is memory-only. Measured on a real gateway: immediately after
  // `systemctl restart heliopause-relay`, two of three healthy hosts read "has never reported" —
  // they had each beaten seconds earlier and were still active. For a tool whose only job is to say
  // what is wrong, being unable to tell "this host is gone" from "I just restarted" is the worst
  // failure available: the alarm fires on a non-event, and one that does that gets ignored on the
  // day it is real.
  it("does not call a host missing when the relay itself just started", () => {
    const s = state();
    const justStarted = new Date(NOW.getTime() - 5_000);
    const v = fleetView(s, NOW, 90, justStarted);
    assert.deepEqual(v.problems, [], "a fresh relay knows nothing yet — that is not the fleet's fault");
    assert.equal(v.relayAgeSec, 5);
  });

  // The same silence *is* a problem once the relay has been up long enough that every host should
  // have beaten. Otherwise the exemption above would suppress the real case forever.
  it("does call a host missing once the relay has been up long enough", () => {
    const s = state();
    const longAgo = new Date(NOW.getTime() - 3600_000);
    contains(fleetView(s, NOW, 90, longAgo).problems.join("|"), "has never reported");
  });

  it("is quiet when every host is confirmed and recent", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", confirmed(GEN), AT);
    handleHeartbeat(s, "h-app-01", confirmed(GEN, "h-app-01"), AT);
    assert.deepEqual(fleetView(s, NOW).problems, []);
  });

  // ── The workload half ───────────────────────────────────────────────────────
  //
  // One combination is the reason all of this exists: `state: confirmed` with a workload half that
  // is not. Every other field on that row reads as success, and the policies involved have no
  // host-layer rule behind them (evaluation rule 8).

  const wlState = (): RelayState => {
    const s = emptyState();
    s.manifest = {
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
            watchSelectors: { namespaces: ["arc-runners"], labels: ["app=idp"] },
          },
        },
      },
    };
    return s;
  };

  const withWorkload = (wl: NonNullable<Heartbeat["workload"]>) =>
    ({ ...confirmed(GEN), workload: wl }) as Heartbeat;

  it("reports a confirmed workload half without raising a problem", () => {
    const s = wlState();
    handleHeartbeat(
      s,
      "h-canary",
      withWorkload({ state: "confirmed", policiesHash: "sha256:w1", observed: ["util/hp-dev-p700"] }),
      AT,
    );
    // Both hosts have to report, or `h-app-01` raises "has never reported" and the assertion below
    // would pass or fail for a reason unrelated to the workload half.
    handleHeartbeat(s, "h-app-01", confirmed(GEN, "h-app-01"), AT);
    const v = fleetView(s, NOW);
    const h = v.hosts.find((x) => x.host === "h-canary")!;
    assert.equal(h.workload?.state, "confirmed");
    assert.equal(h.workload?.cluster, "dev");
    assert.equal(h.workload?.expected, 1);
    assert.deepEqual(v.problems, []);
  });

  it("raises a problem when the ruleset confirmed and the workload half rolled back", () => {
    const s = wlState();
    handleHeartbeat(
      s,
      "h-canary",
      withWorkload({
        state: "rolled-back",
        policiesHash: null,
        observed: [],
        detail: "expected object util/hp-dev-p700 absent after apply",
      }),
      AT,
    );
    const v = fleetView(s, NOW);
    // The host half still reads as clean, which is exactly why the workload half needs its own line.
    assert.equal(v.hosts.find((x) => x.host === "h-canary")!.state, "confirmed");
    contains(v.problems.join("|"), "workload half is rolled-back");
    contains(v.problems.join("|"), "util/hp-dev-p700");
  });

  it("raises a problem when an assigned host never mentions its workload half", () => {
    // Silence is not success. A schema-2 agent with an assignment always reports the field.
    const s = wlState();
    handleHeartbeat(s, "h-canary", confirmed(GEN), AT);
    contains(fleetView(s, NOW).problems.join("|"), "has not reported the workload half");
  });

  it("leaves workload null on a host that was never assigned one", () => {
    // Otherwise every host outside a cluster would show a permanently unsatisfied field.
    const s = wlState();
    handleHeartbeat(s, "h-app-01", confirmed(GEN, "h-app-01"), AT);
    assert.equal(fleetView(s, NOW).hosts.find((x) => x.host === "h-app-01")!.workload, null);
  });

  it("does not fault an assigned host that has not reached this generation yet", () => {
    // While a host is still on the previous generation its workload silence is a queue position, not
    // a fault — the same distinction `blockedBy` draws for the host half.
    const s = wlState();
    handleHeartbeat(s, "h-canary", confirmed("older00"), AT);
    const problems = fleetView(s, NOW).problems.join("|");
    assert.equal(problems.includes("workload half"), false);
  });
});

// ── H14a: the selector-membership channel ────────────────────────────────────
//
// The manager decides what to ask about, the relay is a courier, the applier answers. Each link is
// pinned because a broken one fails silently: the manager reads "not known", which is a legitimate
// state, so nothing anywhere reports that the channel itself is down.

describe("selector membership channel", () => {
  const GEN2 = "6f98e0c";

  const wlManifest = (): Manifest => ({
    generation: GEN2,
    issuedAt: AT,
    schemaVersion: SCHEMA_VERSION,
    hosts: {
      "h-canary": {
        stage: "canary",
        rulesetHash: "sha256:1",
        confirmTimeoutSec: 60,
        mustContain: [],
        workload: {
          policiesHash: "sha256:w1",
          cluster: "dev",
          mustExist: ["util/x"],
          confirmTimeoutSec: 300,
          policyCount: 1,
          watchSelectors: { namespaces: ["arc-runners"], labels: ["app=idp"] },
        },
      },
      "h-app-01": { stage: "general", rulesetHash: "sha256:2", confirmTimeoutSec: 60, mustContain: [] },
    },
  });

  const st = () => {
    const s = emptyState();
    s.manifest = wlManifest();
    return s;
  };

  it("does not pass an unsigned relay watch list to the applier", () => {
    const r = reply(handleHeartbeat(st(), "h-canary", hb(), AT));
    assert.equal("watchSelectors" in r, false);
  });

  it("records what the applier reported, so the manager can render from it", () => {
    const s = st();
    const m = {
      at: "2026-08-02T05:00:00Z",
      namespaces: { "arc-runners": ["runner-a"] },
      labelled: { "app=idp": [] },
    };
    handleHeartbeat(s, "h-canary", { ...hb(), membership: m } as Heartbeat, AT);
    assert.deepEqual(s.membership["h-canary"], m);
  });

  it("holds the last reading rather than clearing it when a beat omits one", () => {
    // Merging would be worse: a host that reports nothing must not keep an old reading alive under a
    // fresh timestamp, and dropping it would lose the only answer the manager has.
    const s = st();
    const m = { at: "2026-08-02T05:00:00Z", namespaces: { "arc-runners": ["runner-a"] }, labelled: {} };
    handleHeartbeat(s, "h-canary", { ...hb(), membership: m } as Heartbeat, AT);
    handleHeartbeat(s, "h-canary", hb(), AT);
    assert.deepEqual(s.membership["h-canary"], m, "the previous reading, with its own timestamp");
  });

  it("surfaces the reading in the fleet view, timestamp included", () => {
    // The manager reads this back when rendering. Without `at` an operator cannot tell a current
    // reading from one taken before the runners scaled.
    const s = st();
    const m = { at: "2026-08-02T05:00:00Z", namespaces: { "arc-runners": ["runner-a"] }, labelled: {} };
    handleHeartbeat(s, "h-canary", { ...hb(), membership: m } as Heartbeat, AT);
    const v = fleetView(s, new Date("2026-07-30T00:01:00Z"));
    assert.deepEqual(v.hosts.find((h) => h.host === "h-canary")!.workload!.membership, m);
  });

  it("reports null membership on an applier that has not answered yet", () => {
    const v = fleetView(st(), new Date("2026-07-30T00:01:00Z"));
    assert.equal(v.hosts.find((h) => h.host === "h-canary")!.workload!.membership, null);
  });
});

// ── Another firewall on the same host ─────────────────────────────────────────
//
// The failure this exists for, measured 2026-08-02: a generation was published, five hosts reported
// `confirmed`, the kernel held exactly the rendered rules, and not one of the newly declared ports
// was reachable. firewalld was hooked on the same chain and rejecting them. Every check in the
// system passed, because every check asked "are my rules in the kernel" and none asked "are my
// rules the ones deciding".
describe("foreign filters", () => {
  const NOW = new Date("2026-07-30T00:01:00Z");
  const withExpect = (expectFilters?: string[]): RelayState => {
    const s = state();
    s.manifest = {
      ...manifest,
      hosts: { ...manifest.hosts, "h-canary": { ...manifest.hosts["h-canary"]!, ...(expectFilters ? { expectFilters } : {}) } },
    };
    return s;
  };

  it("reports a table the policy did not account for", () => {
    const s = withExpect([]);
    handleHeartbeat(s, "h-canary", hb({ foreignFilters: ["inet firewalld"] }), AT);
    const v = fleetView(s, NOW);
    contains(v.problems.join("|"), "inet firewalld");
  });

  it("says what it means rather than what it saw", () => {
    // "inet firewalld is present" is a fact about a table. What an operator has to act on is that
    // the ruleset this host confirmed is not the thing deciding — which is the sentence that would
    // have shortened the 2026-08-02 investigation from an hour to a glance.
    const s = withExpect([]);
    handleHeartbeat(s, "h-canary", hb({ foreignFilters: ["inet firewalld"] }), AT);
    contains(fleetView(s, NOW).problems.join("|"), "not the only thing deciding");
  });

  it("stays quiet about a table the policy expects", () => {
    // gw-01 runs podman and the cluster node runs kube-proxy; neither can be removed. A check that
    // fires on two of seven hosts every poll is one operators learn to scroll past, and then it is
    // worth less than nothing.
    const s = withExpect(["inet netavark"]);
    handleHeartbeat(s, "h-canary", hb({ foreignFilters: ["inet netavark"] }), AT);
    // Only this check. h-app-01 has genuinely never reported, and asserting an empty list would
    // couple this test to an unrelated one.
    excludes(fleetView(s, NOW).problems.join("|"), "also filters here");
  });

  it("reports only the unexpected member of a mixed list", () => {
    const s = withExpect(["inet netavark"]);
    handleHeartbeat(s, "h-canary", hb({ foreignFilters: ["inet firewalld", "inet netavark"] }), AT);
    const p = fleetView(s, NOW).problems.join("|");
    contains(p, "inet firewalld");
    excludes(p, "inet netavark");
  });

  it("keeps 'did not report' distinct from 'reported none'", () => {
    // The inversion this whole field exists to prevent. An agent that cannot read the kernel is a
    // host we cannot make a claim about; rendering that as a clean result would report the absence
    // of a second firewall on precisely the hosts where we cannot tell.
    const s = withExpect([]);
    handleHeartbeat(s, "h-canary", hb(), AT);
    const quiet = fleetView(s, NOW).hosts.find((h) => h.host === "h-canary")!;
    assert.equal(quiet.unexpectedFilters, null, "not reported");

    handleHeartbeat(s, "h-canary", hb({ foreignFilters: [] }), AT);
    const clear = fleetView(s, NOW).hosts.find((h) => h.host === "h-canary")!;
    assert.deepEqual(clear.unexpectedFilters, [], "reported none");
  });

  it("does not report a problem when the host never reported", () => {
    const s = withExpect([]);
    handleHeartbeat(s, "h-canary", hb(), AT);
    excludes(fleetView(s, NOW).problems.join("|"), "also filters here");
  });

  it("does not hold the rollout", () => {
    // Another firewall being present does not make this generation bad. Gating on it would stop the
    // one change most likely to be the fix, on the host that most needs it.
    const s = withExpect([]);
    handleHeartbeat(s, "h-canary", hb({ applied: { generation: GEN, state: "confirmed" }, foreignFilters: ["inet firewalld"] }), AT);
    const out = handleHeartbeat(s, "h-app-01", hb({ host: "h-app-01" }), AT);
    assert.equal(reply(out).generation, GEN, "the general stage still opens");
  });
});

describe("Cilium eBPF exposure", () => {
  const NOW = new Date("2026-07-30T00:01:00Z");

  it("reports host-facing services when nodeport-addresses is unrestricted", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({
      ciliumExposure: {
        nodePortAddresses: [],
        services: [
          "HostPort 0.0.0.0:443/TCP dispatcher/dispatcher-pod",
          "NodePort 0.0.0.0:30444/TCP heliopause/heliopause-manager",
        ],
      },
    }), AT);
    const view = fleetView(s, NOW);
    contains(view.problems.join("|"), "nodeport-addresses is unrestricted");
    contains(view.problems.join("|"), "0.0.0.0:443");
    assert.equal(view.hosts.find((h) => h.host === "h-canary")!.ciliumExposure?.services.length, 2);
  });

  it("does not call a frontend unprotected when the current workload document governs it", () => {
    const s = state();
    s.manifest = {
      ...manifest,
      hosts: {
        ...manifest.hosts,
        "h-canary": {
          ...manifest.hosts["h-canary"]!,
          workload: {
            policiesHash: "sha256:cnp",
            cluster: "dev",
            mustExist: ["dispatcher/hp-dev-dispatcher-cloudflare", "heliopause/hp-dev-manager-cloudflare"],
            confirmTimeoutSec: 300,
            policyCount: 2,
            ingressProtectedSelectors: [
              { "k8s:io.kubernetes.pod.namespace": "dispatcher", app: "dispatcher" },
              { "k8s:io.kubernetes.pod.namespace": "heliopause", app: "heliopause-manager" },
            ],
          },
        },
      },
    };
    handleHeartbeat(s, "h-canary", hb({
      applied: { generation: GEN, state: "confirmed", observedHash: "dump:1", artifactHash: "sha256:1" },
      workload: {
        state: "confirmed",
        policiesHash: "sha256:cnp",
        observed: ["dispatcher/hp-dev-dispatcher-cloudflare", "heliopause/hp-dev-manager-cloudflare"],
      },
      ciliumExposure: {
        nodePortAddresses: [],
        services: [
          "HostPort 0.0.0.0:443/TCP dispatcher/dispatcher-6bd46bdf49-x49sc",
          "NodePort 0.0.0.0:30444/TCP heliopause/heliopause-manager",
        ],
      },
    }), AT);
    excludes(fleetView(s, NOW).problems.join("|"), "nodeport-addresses is unrestricted");
  });

  it("keeps warning if the confirmed workload hash is not the published one", () => {
    const s = state();
    s.manifest = {
      ...manifest,
      hosts: {
        ...manifest.hosts,
        "h-canary": {
          ...manifest.hosts["h-canary"]!,
          workload: {
            policiesHash: "sha256:published",
            cluster: "dev",
            mustExist: [],
            confirmTimeoutSec: 300,
            policyCount: 1,
            ingressProtectedSelectors: [
              { "k8s:io.kubernetes.pod.namespace": "dispatcher", app: "dispatcher" },
            ],
          },
        },
      },
    };
    handleHeartbeat(s, "h-canary", hb({
      applied: { generation: GEN, state: "confirmed", observedHash: "dump:1", artifactHash: "sha256:1" },
      workload: { state: "confirmed", policiesHash: "sha256:other", observed: [] },
      ciliumExposure: {
        nodePortAddresses: [],
        services: ["HostPort 0.0.0.0:443/TCP dispatcher/dispatcher-pod"],
      },
    }), AT);
    contains(fleetView(s, NOW).problems.join("|"), "nodeport-addresses is unrestricted");
  });

  it("does not claim public exposure while Cilium restricts the accepted node addresses", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({
      ciliumExposure: {
        nodePortAddresses: ["10.17.0.0/18"],
        services: ["HostPort 0.0.0.0:443/TCP dispatcher/dispatcher-pod"],
      },
    }), AT);
    excludes(fleetView(s, NOW).problems.join("|"), "nodeport-addresses is unrestricted");
  });

  it("keeps unreadable distinct from a clean observation", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ ciliumExposure: null }), AT);
    assert.equal(fleetView(s, NOW).hosts.find((h) => h.host === "h-canary")!.ciliumExposure, null);
  });
});

// H30 — the relay actually runs the contradiction check, and the ordering it depends on holds.
//
// `consistency.test.ts` pins the logic as data. None of it proves the relay *calls* it, or that it
// calls it before overwriting the baseline every check compares against — and a detector handed the
// new report as its own history can never find anything. That ordering is what this suite exists for.
describe("self-contradiction detection", () => {
  const NOW = new Date("2026-07-30T00:01:00Z");
  const beat = (over: Partial<Heartbeat["applied"]> = {}, host = "h-canary"): Heartbeat =>
    hb({ host, applied: { generation: GEN, state: "confirmed", observedHash: "dump:1", artifactHash: artifactFor(host), ...over } });

  it("records a contradiction the relay found and surfaces it as a problem", () => {
    const s = state();
    // First beat establishes the baseline. Second claims the same generation with a different
    // artifact — a published generation names one artifact per host, so one report was false.
    handleHeartbeat(s, "h-canary", beat(), AT);
    handleHeartbeat(s, "h-canary", beat({ artifactHash: "sha256:other" }), AT);
    assert.ok(s.contradictions["h-canary"]?.length, "nothing was recorded");
    contains(fleetView(s, NOW).problems.join("|"), "reporting contradicts itself");
  });

  it("compares before rebinding the reference, or nothing is ever found", () => {
    // The ordering bug this guards: if the drift reference were updated first, every check would
    // compare the new report against itself. Same-generation-different-artifact is the case that
    // depends on it — after a rebind the prior artifact is the current one.
    const s = state();
    handleHeartbeat(s, "h-canary", beat(), AT);
    assert.equal(s.references["h-canary"]?.artifactHash, "sha256:1", "the reference did not record the artifact");
    handleHeartbeat(s, "h-canary", beat({ artifactHash: "sha256:changed" }), AT);
    assert.equal(s.contradictions["h-canary"]?.[0]?.kind, "artifact-hash-changed");
  });

  it("clears the finding once the host reports consistently again", () => {
    // A host that was reinstalled must be able to stop being accused. Accumulating findings would make
    // the accusation permanent, and a permanent alarm is one nobody reads.
    //
    // Measured while writing this: a *same-generation* bad beat does not rebind the reference — the
    // rebind branch only runs when the generation or the dump changes — so re-reporting the bad digest
    // stays a contradiction, correctly. The way back is a real new generation, which is also what
    // actually happens when a host is fixed and re-enrolled.
    const s = state();
    handleHeartbeat(s, "h-canary", beat(), AT);
    handleHeartbeat(s, "h-canary", beat({ artifactHash: "sha256:other" }), AT);
    assert.ok(s.contradictions["h-canary"]?.length);

    s.manifest = { ...manifest, generation: "gen-fixed" };
    handleHeartbeat(s, "h-canary", beat({ generation: "gen-fixed", observedHash: "dump:2" }), AT);
    assert.equal(s.contradictions["h-canary"], undefined);
    excludes(fleetView(s, NOW).problems.join("|"), "contradicts itself");
  });

  it("stays quiet through an ordinary rollout", () => {
    // The property that matters most. Every publish on 2026-08-03 moved only the generation id
    // because the rendered rules were identical to the live ones — the shape the design document
    // wrongly named as H30's first symptom. A check that fires here is worse than no check.
    const s = state();
    handleHeartbeat(s, "h-canary", beat(), AT);
    s.manifest = { ...manifest, generation: "gen-next" };
    handleHeartbeat(s, "h-canary", beat({ generation: "gen-next" }), AT);
    assert.equal(s.contradictions["h-canary"], undefined);
    excludes(fleetView(s, NOW).problems.join("|"), "contradicts itself");
  });

  it("does not refuse the heartbeat — reporting is the whole intervention", () => {
    // Gating on a suspicion is how a false positive becomes an outage: the host would stop receiving
    // generations, including the one that fixes whatever made it look dishonest.
    const s = state();
    handleHeartbeat(s, "h-canary", beat(), AT);
    const out = handleHeartbeat(s, "h-canary", beat({ artifactHash: "sha256:other" }), AT);
    assert.equal(out.status, 200);
  });

  it("carries the finding into the host row, not only the problem list", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", beat(), AT);
    handleHeartbeat(s, "h-canary", beat({ artifactHash: "sha256:other" }), AT);
    const row = fleetView(s, NOW).hosts.find((h) => h.host === "h-canary");
    // Two, not one — and asserting `1` was my own mistake, caught by running it. That beat is wrong in
    // two independent ways: the digest differs from what this host reported before
    // (`artifact-hash-changed`) *and* it is not what the manifest publishes (`artifact-hash-wrong`).
    // Reporting both is the point; they have different causes and an operator would chase them
    // differently.
    assert.deepEqual(
      row?.contradictions.map((c) => c.kind).sort(),
      ["artifact-hash-changed", "artifact-hash-wrong"],
    );
    assert.ok(row?.contradictions.every((c) => c.certainty === "certain"));
  });

  it("reports an empty list for a host with nothing wrong", () => {
    // `[]` and not null: the relay does the checking, so unlike `unexpectedFilters` there is nothing
    // it can fail to look at.
    const s = state();
    handleHeartbeat(s, "h-canary", beat(), AT);
    assert.deepEqual(fleetView(s, NOW).hosts.find((h) => h.host === "h-canary")?.contradictions, []);
  });
});

// H27/H28 — the agent's intrusion detection reaching somewhere an operator looks.
//
// `nft monitor` subscription, PID attribution and the `UNAUTHORISED` log line all predate this suite.
// What did not exist was anything on the relay side reading the events the agent was already sending:
// measured 2026-08-03, zero mentions in `relay.ts` and `manager.ts`. Detection worked and was invisible
// unless you sshed to the host and read its journal — the thing `/status` exists to remove the need for.
describe("intrusion events", () => {
  const NOW = new Date("2026-07-30T00:01:00Z");
  const ev = (over: Partial<Heartbeat["events"] extends (infer E)[] | undefined ? E : never> = {}) => ({
    at: "2026-07-30T00:00:30Z",
    table: "inet heliopause",
    raw: "add rule inet heliopause input tcp dport 9999 accept",
    pid: 4242,
    process: "nft",
    byAgent: false,
    ...over,
  });

  it("records the agent build, and carries it to the fleet view", () => {
    // The only server-side evidence that a host-unit deployment took. stardust's runbook makes the
    // point about its own node-agent — fail-silent, `rc=0` even against a wrong URL, so judge from
    // the server. The agent has always sent this and the relay dropped it one line after arrival,
    // which left nothing on the server to judge with.
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ agentVersion: "9.9.9-test" }), AT);
    assert.equal(s.statuses["h-canary"]?.agentVersion, "9.9.9-test");
    assert.equal(fleetView(s, NOW).hosts.find((h) => h.host === "h-canary")?.agentVersion, "9.9.9-test");
  });
  
  it("records a change the agent did not make", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ events: [ev()] }), AT);
    assert.equal(s.statuses["h-canary"]?.intrusions?.length, 1);
  });

  it("says it on the fleet view with who and when, not just that it happened", () => {
    // The fleet view is where an operator looks first. "something changed" sends them to the journal;
    // the pid, the process and the raw line let them start from what actually happened.
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ events: [ev()] }), AT);
    const p = fleetView(s, NOW).problems.join("|");
    contains(p, "not made by the agent");
    contains(p, "4242");
    contains(p, "tcp dport 9999");
  });

  it("ignores the agent's own applies", () => {
    // Every generation produces one of these on every host. Reporting them would bury the interesting
    // events in a list that grows with normal operation.
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ events: [ev({ byAgent: true })] }), AT);
    assert.deepEqual(s.statuses["h-canary"]?.intrusions, []);
    excludes(fleetView(s, NOW).problems.join("|"), "not made by the agent");
  });

  it("ignores changes to somebody else's table", () => {
    // **The check I nearly dropped.** The agent tags non-heliopause changes as `"other"` and sends them
    // anyway — its own table filter is applied only to the log line, not to what it transmits. Without
    // this, a podman or firewalld change on the same host reads as tampering with our ruleset. I
    // asserted the agent pre-filtered, checked, and was wrong.
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ events: [ev({ table: "other" })] }), AT);
    assert.deepEqual(s.statuses["h-canary"]?.intrusions, []);
  });

  it("keeps 'did not report' distinct from 'watched and saw nothing'", () => {
    // An older agent omits the key; a current one sends `[]`. Folding the first into the second would
    // claim a clean table on a host that is not watching at all.
    const s = state();
    handleHeartbeat(s, "h-canary", hb(), AT);
    assert.equal(s.statuses["h-canary"]?.intrusions, null);
    handleHeartbeat(s, "h-canary", hb({ events: [] }), AT);
    assert.deepEqual(s.statuses["h-canary"]?.intrusions, []);
  });

  it("does not gate on it", () => {
    // A tampered host is the strongest argument for pushing a new generation to it, not for withholding
    // one — withholding would leave it running whatever the intruder left behind.
    const s = state();
    const out = handleHeartbeat(s, "h-canary", hb({ events: [ev()] }), AT);
    assert.equal(out.status, 200);
    assert.equal(reply(out).generation, GEN);
  });

  it("carries the events onto the host row as well as the problem list", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ events: [ev()] }), AT);
    const row = fleetView(s, NOW).hosts.find((h) => h.host === "h-canary");
    assert.equal(row?.intrusions?.length, 1);
    assert.equal(row?.intrusions?.[0]?.pid, 4242);
  });

  it("reports the count and the latest line rather than the whole buffer", () => {
    // A flood is itself the signal, and pasting fifty raw monitor lines into the fleet view would bury
    // every other problem on the page.
    const s = state();
    const many = Array.from({ length: 12 }, (_, i) => ev({ raw: `change-${i}`, at: `2026-07-30T00:00:${10 + i}Z` }));
    handleHeartbeat(s, "h-canary", hb({ events: many }), AT);
    const p = fleetView(s, NOW).problems.find((x) => x.includes("not made by the agent")) ?? "";
    contains(p, "12 change(s)");
    contains(p, "change-11");
    excludes(p, "change-0 ");
  });
});

// H16 — the workload half's claim checked against what the applier itself observed.
//
// The three existing workload checks ask what the applier *said* (nothing, not-confirmed, confirmed).
// These ask whether "confirmed" holds up against the object list it reported reading back. That is the
// distinction H16 is: intent versus observed state.
//
// Both were impossible until the relay stopped discarding `observed` and `policiesHash` — which is why
// `missingObjects()`, written for exactly this comparison, had **zero callers** in the repository.
describe("cross-layer consistency (H16)", () => {
  const NOW = new Date("2026-07-30T00:01:00Z");

  const wlManifest = (): Manifest => ({
    generation: GEN,
    issuedAt: AT,
    schemaVersion: SCHEMA_VERSION,
    hosts: {
      "h-canary": {
        stage: "canary",
        rulesetHash: "sha256:1",
        confirmTimeoutSec: 60,
        mustContain: [],
        workload: {
          policiesHash: "sha256:w1",
          cluster: "dev",
          mustExist: ["arc-runners/deny-a", "arc-runners/deny-b"],
          confirmTimeoutSec: 300,
          policyCount: 2,
          watchSelectors: { namespaces: [], labels: [] },
        },
      },
    },
  });

  const wlState = () => {
    const s = emptyState();
    s.manifest = wlManifest();
    return s;
  };

  /** A host confirmed on both halves. `observed` and `policiesHash` are what H16 reads. */
  const both = (over: { observed?: string[] | null; policiesHash?: string | null } = {}) =>
    hb({
      applied: { generation: GEN, state: "confirmed", observedHash: "dump:1", artifactHash: "sha256:1" },
      workload: {
        state: "confirmed",
        policiesHash: over.policiesHash === undefined ? "sha256:w1" : over.policiesHash,
        observed: over.observed === undefined ? ["arc-runners/deny-a", "arc-runners/deny-b"] : over.observed,
      },
    });

  it("stays quiet when every expected object is in the cluster", () => {
    const s = wlState();
    handleHeartbeat(s, "h-canary", both(), AT);
    excludes(fleetView(s, NOW).problems.join("|"), "not in cluster");
  });

  it("contradicts a confirmed applier that is missing an object", () => {
    // The failure this exists for: `kubectl apply` exits 0, the agent reports confirmed, and one of the
    // policies is not actually there. Every other field on the row reads as success.
    const s = wlState();
    handleHeartbeat(s, "h-canary", both({ observed: ["arc-runners/deny-a"] }), AT);
    const p = fleetView(s, NOW).problems.join("|");
    contains(p, "reports confirmed but 1 object(s) are not in");
    contains(p, "arc-runners/deny-b");
  });

  it("treats an unreadable cluster as nothing confirmed, and says so", () => {
    // `observed: null` is "I could not look". Treating unknown as satisfied is how a policy governing
    // zero pods passes as applied — so all of `mustExist` is reported missing, with the reason.
    const s = wlState();
    handleHeartbeat(s, "h-canary", both({ observed: null }), AT);
    const p = fleetView(s, NOW).problems.join("|");
    contains(p, "2 object(s) are not in");
    contains(p, "could not read the cluster back");
  });

  it("reports a workload document digest that is not the published one", () => {
    // The workload equivalent of `artifactMatches` — it applied something, and not what this generation
    // published. Same class as H30's `artifact-hash-wrong`, on the other layer.
    const s = wlState();
    handleHeartbeat(s, "h-canary", both({ policiesHash: "sha256:other" }), AT);
    const p = fleetView(s, NOW).problems.join("|");
    contains(p, "it applied something else");
    contains(p, "sha256:other");
  });

  it("does not fire on a host with no workload assignment", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ applied: { generation: GEN, state: "confirmed", observedHash: "dump:1", artifactHash: "sha256:1" } }), AT);
    excludes(fleetView(s, NOW).problems.join("|"), "not in cluster");
  });

  it("does not fire while the workload half is still short of confirmed", () => {
    // `pending` is already reported by the check above it. Adding "and also objects are missing" to a
    // half that has not finished applying would be noise on every rollout.
    const s = wlState();
    handleHeartbeat(s, "h-canary", hb({
      applied: { generation: GEN, state: "confirmed", observedHash: "dump:1", artifactHash: "sha256:1" },
      workload: { state: "pending", policiesHash: "sha256:w1", observed: [] },
    }), AT);
    const p = fleetView(s, NOW).problems.join("|");
    excludes(p, "not in cluster");
    contains(p, "workload half is pending");
  });

  it("keeps the observed list on the status so it can be compared at all", () => {
    // The regression that made `missingObjects` uncallable: the relay stored state and detail and threw
    // the rest away.
    const s = wlState();
    handleHeartbeat(s, "h-canary", both(), AT);
    assert.deepEqual(s.statuses["h-canary"]?.workloadObserved, ["arc-runners/deny-a", "arc-runners/deny-b"]);
    assert.equal(s.statuses["h-canary"]?.workloadPoliciesHash, "sha256:w1");
  });

  it("truncates a long missing list rather than pasting all of it", () => {
    const s = emptyState();
    const many = Array.from({ length: 9 }, (_, i) => `ns/p-${i}`);
    s.manifest = {
      ...wlManifest(),
      hosts: {
        "h-canary": {
          ...wlManifest().hosts["h-canary"]!,
          workload: { ...wlManifest().hosts["h-canary"]!.workload!, mustExist: many, policyCount: 9 },
        },
      },
    };
    handleHeartbeat(s, "h-canary", both({ observed: [] }), AT);
    const p = fleetView(s, NOW).problems.find((x) => x.includes("not in cluster")) ?? "";
    contains(p, "9 object(s)");
    contains(p, "+5 more");
  });
});

// H36 — ports this project's rules do not govern, said out loud.
//
// A published container port is DNAT'd on `prerouting`, before any `input` hook, so the packet never
// reaches our rules. A policy declaring that port closed is not wrong — it is not consulted. Saying
// nothing would imply coverage that does not exist, and "I blocked it and it is still open" is the
// worst thing a firewall can be.
describe("published ports (H36)", () => {
  const NOW = new Date("2026-07-30T00:01:00Z");

  it("reports a port another table redirects, and says why it matters", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ publishedPorts: ["inet netavark: tcp/8080 -> 10.88.0.5:80"] }), AT);
    const p = fleetView(s, NOW).problems.join("|");
    contains(p, "bypass this ruleset");
    contains(p, "tcp/8080");
    // The mechanism, not just the verdict: an operator who does not know why needs the sentence.
    contains(p, "prerouting");
  });

  it("stays quiet when the host reports none", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ publishedPorts: [] }), AT);
    excludes(fleetView(s, NOW).problems.join("|"), "bypass this ruleset");
  });

  it("keeps 'did not report' distinct from 'reported none'", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb(), AT);
    assert.equal(s.statuses["h-canary"]?.publishedPorts, null);
    handleHeartbeat(s, "h-canary", hb({ publishedPorts: [] }), AT);
    assert.deepEqual(s.statuses["h-canary"]?.publishedPorts, []);
  });

  it("does not gate on it", () => {
    // A published port is usually intentional. Holding a rollout over one would block the change most
    // likely to be the fix.
    const s = state();
    const out = handleHeartbeat(s, "h-canary", hb({ publishedPorts: ["inet netavark: tcp/8080"] }), AT);
    assert.equal(out.status, 200);
    assert.equal(reply(out).generation, GEN);
  });

  it("carries it onto the host row", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ publishedPorts: ["inet netavark: tcp/8080"] }), AT);
    const row = fleetView(s, NOW).hosts.find((h) => h.host === "h-canary");
    assert.deepEqual(row?.publishedPorts, ["inet netavark: tcp/8080"]);
  });

  it("truncates a long list", () => {
    const s = state();
    const many = Array.from({ length: 7 }, (_, i) => `inet netavark: tcp/${8000 + i}`);
    handleHeartbeat(s, "h-canary", hb({ publishedPorts: many }), AT);
    const p = fleetView(s, NOW).problems.find((x) => x.includes("bypass this ruleset")) ?? "";
    contains(p, "7 port(s)");
    contains(p, "+4 more");
  });
});

describe("a host outside this relay's generation", () => {
  // ## Answered, but not filed
  //
  // The CN check settles "is this host who it claims to be". Nothing settled "does it belong here":
  // measured 2026-08-12, a `gw-01.prod` certificate beating at the dev relay was answered `200` and
  // written into `statuses` and `lastSeen`. It appeared nowhere — `fleetView` and `computeGate` both
  // iterate the manifest — so the entry accumulated unread and unbounded.
  //
  // **The gate was never reachable from there.** A host cannot claim a peer's name, and the gate
  // reads only hosts the manifest names; both measured. What this closes is the relay's own
  // bookkeeping, and it is written here because what actually kept it from mattering is the PKI
  // shape — one CA per VPC — which lives in the deployment and not in this file.

  const hostOutside = () => handleHeartbeat(state(), "h-other", hb({ host: "h-other" }), AT);

  it("is still answered, because dropping out of a generation is legitimate", () => {
    // `rollout.ts` calls this "decommissioned, or simply not covered by any policy yet". Refusing
    // would cut a working host's relay connection mid-decommission over a bookkeeping decision.
    const out = hostOutside();
    assert.equal(out.status, 200);
    assert.equal(reply(out).generation, null);
    contains(reply(out).gate.reason, "not part of this generation");
  });

  it("leaves no trace in the relay's state", () => {
    // The regression. Every field written for a recorded host must stay absent for this one.
    const s = state();
    handleHeartbeat(s, "h-other", hb({ host: "h-other" }), AT);
    assert.equal(s.statuses["h-other"], undefined, "statuses must not grow");
    assert.equal(s.lastSeen["h-other"], undefined, "lastSeen must not grow");
  });

  it("still records the hosts the generation does name", () => {
    // The known positive. Without it the test above is satisfied by a relay that records nothing,
    // which would take the fleet view down entirely.
    const s = state();
    handleHeartbeat(s, "h-canary", hb(), AT);
    assert.ok(s.statuses["h-canary"], "a named host must still be recorded");
    assert.equal(s.lastSeen["h-canary"], AT);
  });

  it("records everything while no manifest is loaded", () => {
    // A relay restart. The state is memory-only and the manifest arrives from disk moments later;
    // "cannot say yet" is not "does not belong", and refusing to remember would blind the fleet view
    // for an interval at exactly the moment an operator is watching it.
    const s = emptyState();
    handleHeartbeat(s, "h-anyone", hb({ host: "h-anyone" }), AT);
    assert.ok(s.statuses["h-anyone"], "with no manifest there is nothing to exclude against");
  });
});

// ── A refusal is the host's answer, and it used to stay on the host ───────────
//
// Twice on 2026-09-02–03 a host sat on an old generation while the relay held a new one, and every
// field in the fleet view said fine: `state: confirmed`, `blockedBy: null`, `drifted: false`. The
// agent knew why both times — a schema skew, then a peer namespace its build did not support — and
// the sentence existed only in a journal on a machine the person diagnosing it could not read.
describe("a refused generation says so where an operator looks", () => {
  const refused = (generation: string, reason: string) =>
    hb({
      applied: { generation: "gen1", state: "confirmed", artifactHash: "a", observedHash: "h" },
      lastRefusal: { generation, reason, at: AT },
    });

  it("reports the refusal and names the generation it refused", () => {
    const s = state();
    s.manifest = { ...manifest, generation: "gen2" };
    handleHeartbeat(s, "h-canary", refused("gen2", "signed workload selector watch is invalid"), AT);
    const v = fleetView(s, new Date(AT), 300);
    contains(v.problems.join("|"), "refused generation gen2");
    contains(v.problems.join("|"), "selector watch is invalid");
    assert.equal(v.hosts[0]!.lastRefusal?.generation, "gen2");
  });

  it("is not `blockedBy` — a stage holding a host and a host declining are different facts", () => {
    // `blockedBy` answers "which earlier stage is holding this one". A refusal is the host turning
    // down something no stage was withholding, and folding it into that field would make a host
    // that refuses look like a host that is politely waiting its turn.
    const s = state();
    s.manifest = { ...manifest, generation: "gen2" };
    handleHeartbeat(s, "h-canary", refused("gen2", "whatever the reason"), AT);
    assert.equal(fleetView(s, new Date(AT), 300).hosts[0]!.blockedBy, null);
  });

  it("stops reporting once the host is on the generation it once refused", () => {
    // History in a status view reads as a live problem. A host that refused `gen2` and is now
    // running `gen2` has answered the question.
    const s = state();
    s.manifest = { ...manifest, generation: "gen2" };
    handleHeartbeat(s, "h-canary", hb({
      applied: { generation: "gen2", state: "confirmed", artifactHash: "a", observedHash: "h" },
      lastRefusal: { generation: "gen2", reason: "an earlier attempt", at: AT },
    }), AT);
    const v = fleetView(s, new Date(AT), 300);
    assert.equal(v.hosts[0]!.lastRefusal, null);
    assert.deepEqual(v.problems.filter((p) => p.includes("refused generation")), []);
  });

  it("carries the agent's source digest beside its version", () => {
    // The two answer different questions and on 2026-09-03 they disagreed: same `agentVersion`, same
    // `schemaVersion`, different code, and the difference decided whether a generation applied.
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ agentBuild: "d731497715ca" }), AT);
    assert.equal(fleetView(s, new Date(AT), 300).hosts[0]!.agentBuild, "d731497715ca");
    // An older agent does not send it, and that is "did not say" — never a match.
    const older = state();
    handleHeartbeat(older, "h-canary", hb(), AT);
    assert.equal(fleetView(older, new Date(AT), 300).hosts[0]!.agentBuild, null);
  });
});

// ── Two authorization expiries on the host row, as information (#138) ────────
//
// The one the agent enforces, and the one this relay serves. Shown, never acted on here: whether a host
// would accept what it is served depends on state only the host holds, and two review rounds found the
// gaps each time the relay tried to predict it. An actual refusal reaches the view as `lastRefusal`.
describe("authorization expiry on the host row", () => {
  const FUTURE = "2026-07-31T00:00:00Z";
  const PAST = "2026-07-29T00:00:00Z";
  const trust = (currentExpiresAt?: string | null) => ({
    managerKeyIds: ["mk-1"], breakGlassKeyIds: [], trustDigest: "sha256:aaaaaaaaaaaa",
    currentKeyId: "mk-1", currentPayloadHash: "sha256:pppp", currentAuthorizationMode: "two-person" as const,
    currentAuthorizedAt: "2026-07-28T00:00:00Z", currentPlanHash: "sha256:hhhh",
    ...(currentExpiresAt === undefined ? {} : { currentExpiresAt }),
  });
  /** An envelope served to the host, carrying only the field the row reads. */
  const serving = (s: RelayState, host: string, payload: string) => {
    s.artifacts = {
      ...s.artifacts,
      [host]: { version: "heliopause-ed25519-v1", algorithm: "Ed25519", keyId: "k", payload, signature: "s" } as RelayState["artifacts"][string],
    };
  };
  const encode = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const row = (s: RelayState) => fleetView(s, new Date(AT), 300).hosts[0]!;

  it("puts the enforced authorization's expiry on the row", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ artifactTrust: trust(FUTURE) }), AT);
    assert.equal(row(s).authorizationExpiresAt, FUTURE);
  });

  it("puts null — not knowing — for an agent too old to say, or one with nothing recorded", () => {
    for (const beat of [hb(), hb({ artifactTrust: trust() }), hb({ artifactTrust: trust(null) })]) {
      const s = state();
      handleHeartbeat(s, "h-canary", beat, AT);
      assert.equal(row(s).authorizationExpiresAt, null);
    }
  });

  it("puts the served envelope's expiry on the row, which can differ from the enforced one", () => {
    const s = state();
    serving(s, "h-canary", encode({ expiresAt: FUTURE }));
    handleHeartbeat(s, "h-canary", hb({ artifactTrust: trust(PAST) }), AT);
    assert.equal(row(s).servedAuthorizationExpiresAt, FUTURE);
    assert.equal(row(s).authorizationExpiresAt, PAST);
  });

  it("puts null for an envelope it does not serve or cannot read as a time", () => {
    for (const payload of [undefined, "not base64 json", encode({}), encode({ expiresAt: "tomorrow" })]) {
      const s = state();
      if (payload !== undefined) serving(s, "h-canary", payload);
      handleHeartbeat(s, "h-canary", hb(), AT);
      assert.equal(row(s).servedAuthorizationExpiresAt, null, String(payload));
    }
  });

  it("raises no problem about expiry, lapsed or not — a refusal is what reports it", () => {
    const s = state();
    serving(s, "h-canary", encode({ expiresAt: PAST }));
    handleHeartbeat(s, "h-canary", hb({ artifactTrust: trust(PAST), applied: { generation: GEN, state: "rolled-back", artifactHash: artifactFor("h-canary"), observedHash: null } }), AT);
    assert.deepEqual(fleetView(s, new Date(AT), 300).problems.filter((p) => /expir|lapse/i.test(p)), []);
  });
});

// ── A confirmed host with no table (#139) ─────────────────────────────────────
//
// After a reboot the table is gone until the agent puts it back. The agent now says which of three
// it saw — `present`, `absent`, or `unread` (not read yet, or `nft` failed) — and the relay reads that
// rather than guessing from a null `observedHash`. A held, unmerged attempt guessed by beat count and
// then by time, and two review rounds found three false alarms in it; the scenarios below are those three.
describe("a confirmed host that says its table is absent", () => {
  const beat = (table: "present" | "absent" | "unread" | undefined, over: HeartbeatOverride = {}) =>
    hb({
      ...over,
      applied: {
        generation: "gen1", state: "confirmed", artifactHash: "a",
        observedHash: table === "present" ? "h" : null,
        detail: table === "absent" ? "table inet heliopause is absent" : table === "unread" ? "host observation refresh pending" : undefined,
        ...(table === undefined ? {} : { table }),
        ...(over.applied ?? {}),
      },
    });
  const absentLines = (s: RelayState) =>
    fleetView(s, new Date(AT), 300).problems.filter((p) => p.includes("table is absent"));
  const refusals = (s: RelayState) =>
    fleetView(s, new Date(AT), 300).problems.filter((p) => p.includes("refused generation"));
  const stale = { lastRefusal: { generation: "gen1", reason: "an earlier attempt", at: AT } };

  it("is reported as soon as the agent says so, with its words", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", beat("absent"), AT);
    const lines = absentLines(s);
    assert.equal(lines.length, 1, JSON.stringify(lines));
    assert.match(lines[0]!, /h-canary/);
    assert.match(lines[0]!, /gen1/);
  });

  it("says nothing while a restarted agent has not read its table yet, however many beats", () => {
    // Review scenario 1 (held branch): a one-second interval and a 25-second first observation.
    const s = state();
    for (let i = 0; i < 25; i++) handleHeartbeat(s, "h-canary", beat("unread"), AT);
    assert.deepEqual(absentLines(s), []);
  });

  it("says nothing for an agent too old to say", () => {
    const s = state();
    for (let i = 0; i < 5; i++) handleHeartbeat(s, "h-canary", beat(undefined, { applied: { observedHash: null } }), AT);
    assert.deepEqual(absentLines(s), []);
  });

  it("says nothing for a first apply that is not confirmed yet", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", beat("absent", { applied: { state: "pending" } }), AT);
    assert.deepEqual(absentLines(s), []);
  });

  it("clears once the table is back", () => {
    // Review scenario 3 (held branch) was a run of beats bridging a silence. Nothing is carried
    // between beats now; each one is read as it is.
    const s = state();
    handleHeartbeat(s, "h-canary", beat("absent"), AT);
    handleHeartbeat(s, "h-canary", beat("present"), AT);
    assert.deepEqual(absentLines(s), []);
  });

  it("shows a refusal of the generation it is on, when the table is absent", () => {
    // 2026-09-28: the rebooted host fetched its own generation again and the apply was refused.
    const s = state();
    handleHeartbeat(s, "h-canary", beat("absent", stale), AT);
    assert.equal(refusals(s).length, 1);
    assert.equal(fleetView(s, new Date(AT), 300).hosts[0]!.lastRefusal?.generation, "gen1");
  });

  it("keeps an old same-generation refusal hidden while the table is unread", () => {
    // Review scenario 2 (held branch): a transient failure left a refusal in the agent's state, and a
    // restart begins with unread beats.
    const s = state();
    handleHeartbeat(s, "h-canary", beat("unread", stale), AT);
    assert.deepEqual(refusals(s), []);
    assert.equal(fleetView(s, new Date(AT), 300).hosts[0]!.lastRefusal, null);
  });

  it("shows a refusal of the generation it is on, when it is not confirmed", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", beat("present", { ...stale, applied: { state: "rolled-back" } }), AT);
    assert.equal(refusals(s).length, 1);
  });

  it("puts what the agent said on the host's row, and null for an agent too old to say", () => {
    // The rollout verdict for #147 is "every host reports `present`"; the row is where it is read.
    const s = state();
    handleHeartbeat(s, "h-canary", beat("present"), AT);
    assert.equal(fleetView(s, new Date(AT), 300).hosts[0]!.table, "present");
    const older = state();
    handleHeartbeat(older, "h-canary", beat(undefined), AT);
    assert.equal(fleetView(older, new Date(AT), 300).hosts[0]!.table, null);
  });
});

describe("the agent certificate each heartbeat presented", () => {
  const presented = {
    cn: "h-canary", serial: "0A", sha256: "ab".repeat(32),
    notBefore: "2026-07-01T00:00:00.000Z", notAfter: "2026-11-25T04:16:24.000Z",
  };

  it("is recorded with the heartbeat and carried on the host's fleet row", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb(), AT, presented);
    assert.deepEqual(s.agentCerts["h-canary"], { ...presented, observedAt: AT });
    const row = fleetView(s, new Date(AT)).hosts.find((h) => h.host === "h-canary")!;
    assert.deepEqual(row.agentCert, { ...presented, observedAt: AT });
    assert.equal(fleetView(s, new Date(AT)).hosts.find((h) => h.host === "h-app-01")!.agentCert, null);
  });

  it("is not recorded for a host the manifest does not list — the same rule as its status", () => {
    const s = state();
    handleHeartbeat(s, "h-stranger", hb({ host: "h-stranger" }), AT, { ...presented, cn: "h-stranger" });
    assert.equal(s.agentCerts["h-stranger"], undefined);
    assert.equal(s.statuses["h-stranger"], undefined);
  });

  it("is not recorded from a heartbeat the relay refuses", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb({ host: "h-app-01" }), AT, presented);
    assert.deepEqual(s.agentCerts, {});
  });

  it("keeps the previous reading when a heartbeat arrives without a readable certificate", () => {
    const s = state();
    handleHeartbeat(s, "h-canary", hb(), AT, presented);
    handleHeartbeat(s, "h-canary", hb(), "2026-07-30T00:01:00Z", null);
    assert.equal(s.agentCerts["h-canary"]!.observedAt, AT);
  });
});

// ── #148: a finding per problem, and whether each kind could be judged ───────
//
// The structured half of `problems`, for a consumer that alerts when a problem opens and again when
// it ends. The second half is the harder one: a finding disappearing is evidence only where the view
// could judge that kind, and `evaluated` says where.

describe("structured findings (#148)", () => {
  const NOW = new Date("2026-07-30T00:01:00Z");
  const LONG_AGO = new Date(NOW.getTime() - 3600_000);
  const FLOOR = [0, 6, 0] as const;
  const DIGEST_A = "sha256:aaaaaaaaaaaaaaaaaaaa";
  const DIGEST_B = "sha256:bbbbbbbbbbbbbbbbbbbb";

  // Written out here, once, and not derived from `ProblemKind` or from what `fleetView` returns: a
  // kind removed from the code must fail the catalog, and a kind removed from this list must too.
  const EXPECTED_HOST_KINDS = [
    "rolled-back", "refused-generation", "table-absent", "ruleset-changed", "published-ports",
    "cilium-nodeport-unrestricted", "contradiction-artifact-hash-changed",
    "contradiction-artifact-hash-wrong", "contradiction-unknown-generation",
    "contradiction-kernel-unchanged", "unexpected-filters", "workload-unreported",
    "workload-not-confirmed", "workload-objects-missing", "workload-document-mismatch",
    "agent-version-behind", "break-glass-authorization", "artifact-trust-unreadable",
    "authorization-unnamed", "never-reported", "silent",
  ];
  const EXPECTED_FLEET_KINDS = ["trust-ring-split"];

  const WORKLOAD = {
    policiesHash: "sha256:w1",
    cluster: "dev",
    mustExist: ["util/hp-dev-p700"],
    confirmTimeoutSec: 300,
    policyCount: 1,
    watchSelectors: { namespaces: ["arc-runners"], labels: ["app=idp"] },
  };
  const entry = (host: string, withWorkload = false): Manifest["hosts"][string] => ({
    stage: "general",
    rulesetHash: `sha256:${host}`,
    confirmTimeoutSec: 60,
    mustContain: [],
    ...(withWorkload ? { workload: WORKLOAD } : {}),
  });
  const trustOf = (over: Partial<NonNullable<Heartbeat["artifactTrust"]>> = {}) => ({
    managerKeyIds: ["mk-1"],
    breakGlassKeyIds: ["bg-1"],
    trustDigest: DIGEST_A,
    currentKeyId: "mk-1",
    currentPayloadHash: "sha256:pppp",
    currentAuthorizationMode: "two-person" as const,
    currentAuthorizedAt: "2026-07-29T00:00:00Z",
    currentPlanHash: "sha256:hhhh",
    ...over,
  });
  /** A healthy beat: confirmed on `gen`, the artifact the manifest publishes, a current agent. */
  const good = (host: string, over: HeartbeatOverride = {}, gen = GEN): Heartbeat =>
    hb({
      host,
      agentVersion: "0.6.0",
      artifactTrust: trustOf(),
      ...over,
      applied: {
        generation: gen, state: "confirmed", artifactHash: `sha256:${host}`, observedHash: "dump:1",
        ...(over.applied ?? {}),
      },
    });
  const withoutTrust = (b: Heartbeat): Heartbeat => {
    delete (b as { artifactTrust?: unknown }).artifactTrust;
    return b;
  };
  const view = (
    s: RelayState,
    now = NOW,
    startedAt: Date | undefined = LONG_AGO,
    floor: readonly [number, number, number] | undefined = FLOOR,
  ) => fleetView(s, now, 90, startedAt, floor);
  const stateWith = (hosts: Record<string, Manifest["hosts"][string]>): RelayState => {
    const s = emptyState();
    s.manifest = { generation: GEN, issuedAt: AT, schemaVersion: SCHEMA_VERSION, hosts };
    return s;
  };
  const one = (host: string, b: Heartbeat, withWorkload = false) => () => {
    const s = stateWith({ [host]: entry(host, withWorkload) });
    handleHeartbeat(s, host, b, AT);
    return s;
  };

  /** Every kind at once, one host per finding where it can be. */
  function catalog(): RelayState {
    const wl = ["c-wl-unrep", "c-wl-notconf", "c-wl-missing", "c-wl-doc"];
    const names = [
      "c-rolled", "c-refused", "c-table", "c-drift", "c-ports", "c-cilium", "c-intr", "c-contra",
      "c-contra2", "c-filters", ...wl, "c-old", "c-bg", "c-trusterr", "c-unnamed", "c-never",
      "c-silent", "c-ring",
    ];
    const s = stateWith(Object.fromEntries(names.map((n) => [n, entry(n, wl.includes(n))])));
    const beat = (b: Heartbeat, at = AT) => handleHeartbeat(s, b.host, b, at);
    beat(good("c-rolled", { applied: { state: "rolled-back", observedHash: null, detail: "baseline absent" } }));
    beat(good("c-refused", { lastRefusal: { generation: "g-next", reason: "schema too new", at: AT } }));
    beat(good("c-table", { applied: { observedHash: null, table: "absent", detail: "rebooted" } }));
    beat(good("c-drift"));
    beat(good("c-drift", { applied: { observedHash: "dump:2" } }));
    beat(good("c-ports", { publishedPorts: ["tcp 8080 -> 192.0.2.10:80"] }));
    beat(good("c-cilium", {
      ciliumExposure: { nodePortAddresses: [], services: ["HostPort 192.0.2.20:443/TCP web/web"] },
    }));
    beat(good("c-intr", {
      events: [{
        at: AT, table: "inet heliopause", raw: "add rule inet heliopause input accept", pid: 7, process: "nft",
        byAgent: false,
      }],
    }));
    beat(good("c-contra", { applied: { artifactHash: "sha256:a1" } }));
    beat(good("c-contra", { applied: { artifactHash: "sha256:a2" } }));
    beat(good("c-contra2", { applied: { artifactHash: "sha256:o" } }, "g-old"));
    beat(good("c-contra2", { applied: { artifactHash: "sha256:x" } }, "g-other"));
    beat(good("c-filters", { foreignFilters: ["inet firewalld"] }));
    beat(good("c-wl-unrep"));
    beat(good("c-wl-notconf", {
      workload: { state: "rolled-back", policiesHash: null, observed: [], detail: "absent after apply" },
    }));
    beat(good("c-wl-missing", { workload: { state: "confirmed", policiesHash: "sha256:w1", observed: [] } }));
    beat(good("c-wl-doc", {
      workload: { state: "confirmed", policiesHash: "sha256:other", observed: ["util/hp-dev-p700"] },
    }));
    beat(good("c-old", { agentVersion: "0.5.0" }));
    beat(good("c-bg", { artifactTrust: trustOf({ currentAuthorizationMode: "break-glass" }) }));
    beat(withoutTrust(good("c-trusterr", { artifactTrustError: "trust directory is not configured" })));
    beat(good("c-unnamed", { artifactTrust: trustOf({ currentAuthorizationMode: null, currentAuthorizedAt: null }) }));
    beat(good("c-silent"), "2026-07-29T23:50:00Z");
    beat(good("c-ring", { artifactTrust: trustOf({ trustDigest: DIGEST_B }) }));
    return s;
  }

  it("the catalog raises every kind, and only the kinds written down here", () => {
    assert.equal(EXPECTED_HOST_KINDS.length + EXPECTED_FLEET_KINDS.length, 22);
    const v = view(catalog());
    assert.deepEqual(
      [...new Set(v.findings.map((f) => f.kind))].sort(),
      [...EXPECTED_HOST_KINDS, ...EXPECTED_FLEET_KINDS].sort(),
    );
    for (const [host, ev] of Object.entries(v.evaluated)) {
      assert.deepEqual(Object.keys(ev).sort(), [...EXPECTED_HOST_KINDS].sort(), host);
    }
    assert.deepEqual(Object.keys(v.fleetEvaluated), EXPECTED_FLEET_KINDS);
  });

  it("problems strings are unchanged by structured findings", () => {
    // Captured from `fleetView` at 029831d — before findings existed — run on this same catalog. What
    // this pins is that the change reworded nothing.
    assert.deepEqual(view(catalog()).problems, CATALOG_PROBLEMS_BEFORE_148);
  });

  it("every finding has its problems line, and only the intrusion line has no finding", () => {
    // Independent of `fleetView`: which words each kind's line carries.
    const said: Record<string, string> = {
      "rolled-back": "rolled back", "refused-generation": "refused generation", "table-absent": "table is absent",
      "ruleset-changed": "no longer matches", "published-ports": "published by another table",
      "cilium-nodeport-unrestricted": "nodeport-addresses", "contradiction-artifact-hash-changed": "earlier reported the same",
      "contradiction-artifact-hash-wrong": "manifest publishes", "contradiction-unknown-generation": "never served",
      "contradiction-kernel-unchanged": "identical kernel dump", "unexpected-filters": "also filters here",
      "workload-unreported": "not reported the workload", "workload-not-confirmed": "workload half is",
      "workload-objects-missing": "are not in", "workload-document-mismatch": "applied something else",
      "agent-version-behind": "floor", "break-glass-authorization": "break-glass",
      "artifact-trust-unreadable": "signing trust", "authorization-unnamed": "cannot name",
      "never-reported": "never reported", silent: "silent for", "trust-ring-split": "may sign",
    };
    const v = view(catalog());
    for (const f of v.findings) {
      const line = v.problems.find((p) => p.includes(said[f.kind]!) && (f.host === null || p.startsWith(`${f.host}: `)));
      assert.ok(line, `no problems line for ${f.kind} on ${f.host}`);
    }
    assert.equal(v.problems.length, v.findings.length + 1);
  });

  it("intrusion events stay a problems line with no finding", () => {
    const s = one("c-intr", good("c-intr", {
      events: [{ at: AT, table: "inet heliopause", raw: "add rule", byAgent: false }],
    }))();
    const v = view(s);
    assert.equal(v.problems.length, 1);
    contains(v.problems[0]!, "not made by the agent");
    assert.deepEqual(v.findings, []);
  });

  it("carries counts as integers and no prose, detail, address or digest in a value", () => {
    const v = view(catalog());
    const byKind = Object.fromEntries(v.findings.map((f) => [f.kind, f]));
    assert.equal(byKind["published-ports"]!.count, 1);
    assert.equal(byKind["cilium-nodeport-unrestricted"]!.count, 1);
    assert.equal(byKind["unexpected-filters"]!.count, 1);
    assert.equal(byKind["workload-objects-missing"]!.count, 1);
    assert.equal(byKind["workload-objects-missing"]!.value, null);
    assert.equal(byKind["refused-generation"]!.value, "g-next");
    assert.equal(byKind["table-absent"]!.value, GEN);
    assert.equal(byKind["workload-not-confirmed"]!.value, "rolled-back");
    assert.equal(byKind["authorization-unnamed"]!.value, GEN);
    assert.deepEqual(byKind["trust-ring-split"], { kind: "trust-ring-split", host: null, value: "18,1", count: 2 });
    for (const f of v.findings) {
      assert.ok(Number.isInteger(f.count), `${f.kind} count ${f.count}`);
      for (const banned of ["192.0.2.", "sha256:", "rebooted", "schema too new", "firewalld", "util/", "dump:"]) {
        assert.ok(!(f.value ?? "").includes(banned), `${f.kind} value carries ${banned}`);
      }
    }
  });

  it("joins same-kind contradictions on one host into one finding with their count", () => {
    const s = one("c-a", good("c-a"))();
    s.contradictions["c-a"] = [
      { host: "c-a", kind: "unknown-generation", certainty: "certain", detail: "one" },
      { host: "c-a", kind: "unknown-generation", certainty: "certain", detail: "two" },
    ];
    const v = view(s);
    assert.equal(v.problems.length, 2);
    assert.deepEqual(v.findings, [{ kind: "contradiction-unknown-generation", host: "c-a", value: null, count: 2 }]);
  });

  it("silent finding carries no elapsed seconds", () => {
    const s = catalog();
    const a = view(s, NOW);
    const b = view(s, new Date(NOW.getTime() + 20_000));
    // Known positive: the prose does move between the two.
    assert.notEqual(a.problems.find((p) => p.startsWith("c-silent")), b.problems.find((p) => p.startsWith("c-silent")));
    assert.deepEqual(a.findings, b.findings);
  });

  it("a relay without a manifest reports manifest:false rather than an empty fleet", () => {
    const v = view(emptyState());
    assert.deepEqual(v.findings, []);
    assert.equal(v.observability.manifest, false);
    assert.equal(v.fleetEvaluated["trust-ring-split"], "no");
    // Known positive: the same relay with a manifest says so.
    assert.equal(view(state()).observability.manifest, true);
  });

  it("says the grace window is active while the relay is younger than the silence threshold", () => {
    assert.equal(view(state(), NOW, new Date(NOW.getTime() - 5_000)).observability.graceActive, true);
    assert.equal(view(state(), NOW, LONG_AGO).observability.graceActive, false);
  });

  // ## R8 — the evaluation table
  //
  // One case per input the plan's table names: the state, the value `evaluated` must hold for that
  // kind, and whether that kind's finding is present.
  type Case = {
    kind: ProblemKind; why: string; build: () => RelayState;
    floor?: readonly [number, number, number] | undefined; expect: string; finding: boolean;
  };
  const unheard = () => stateWith({ h: entry("h") });
  const exposed = { nodePortAddresses: [], services: ["HostPort 192.0.2.20:443/TCP web/web"] };
  const cases: Case[] = [
    { kind: "rolled-back", why: "never reported", build: unheard, expect: "no", finding: false },
    { kind: "refused-generation", why: "never reported", build: unheard, expect: "no", finding: false },
    { kind: "table-absent", why: "agent too old to report a table", build: one("h", good("h")), expect: "no", finding: false },
    { kind: "table-absent", why: "table unread", build: one("h", good("h", { applied: { table: "unread" } })), expect: "no", finding: false },
    {
      kind: "table-absent", why: "pending re-apply",
      build: one("h", good("h", { applied: { state: "pending", table: "present" } })), expect: "no-resolve", finding: false,
    },
    { kind: "ruleset-changed", why: "reference taken on first contact", build: one("h", good("h")), expect: "no-resolve", finding: false },
    { kind: "published-ports", why: "not reported", build: one("h", good("h")), expect: "no", finding: false },
    { kind: "cilium-nodeport-unrestricted", why: "not reported", build: one("h", good("h")), expect: "no", finding: false },
    {
      kind: "cilium-nodeport-unrestricted", why: "workload not confirmed on this generation",
      build: one("h", good("h", {
        ciliumExposure: exposed, workload: { state: "pending", policiesHash: "sha256:w1", observed: null },
      }), true),
      expect: "no", finding: true,
    },
    {
      kind: "contradiction-artifact-hash-wrong", why: "no artifact hash",
      build: one("h", good("h", { applied: { artifactHash: null } })), expect: "no", finding: false,
    },
    { kind: "contradiction-artifact-hash-wrong", why: "not on this generation", build: one("h", good("h", {}, "g-old")), expect: "no", finding: false },
    { kind: "contradiction-artifact-hash-changed", why: "an event, outside the open/resolve model", build: one("h", good("h")), expect: "no", finding: false },
    { kind: "contradiction-unknown-generation", why: "an event, outside the open/resolve model", build: one("h", good("h")), expect: "no", finding: false },
    { kind: "contradiction-kernel-unchanged", why: "an event, outside the open/resolve model", build: one("h", good("h")), expect: "no", finding: false },
    { kind: "unexpected-filters", why: "not reported", build: one("h", good("h")), expect: "no", finding: false },
    { kind: "workload-unreported", why: "older generation", build: one("h", good("h", {}, "g-old"), true), expect: "no", finding: false },
    {
      kind: "workload-not-confirmed", why: "older generation",
      build: one("h", good("h", { workload: { state: "rolled-back", policiesHash: null, observed: [] } }, "g-old"), true),
      expect: "no", finding: false,
    },
    {
      kind: "workload-objects-missing", why: "workload pending",
      build: one("h", good("h", { workload: { state: "pending", policiesHash: "sha256:w1", observed: [] } }), true),
      expect: "no", finding: false,
    },
    {
      kind: "workload-objects-missing", why: "cluster not read back",
      build: one("h", good("h", { workload: { state: "confirmed", policiesHash: "sha256:w1", observed: null } }), true),
      expect: "no-resolve", finding: true,
    },
    {
      kind: "workload-document-mismatch", why: "workload pending",
      build: one("h", good("h", { workload: { state: "pending", policiesHash: "sha256:other", observed: [] } }), true),
      expect: "no", finding: false,
    },
    {
      kind: "workload-document-mismatch", why: "no document hash",
      build: one("h", good("h", { workload: { state: "confirmed", policiesHash: null, observed: ["util/hp-dev-p700"] } }), true),
      expect: "no", finding: false,
    },
    { kind: "agent-version-behind", why: "no floor", build: one("h", good("h", { agentVersion: "0.1.0" })), floor: undefined, expect: "no", finding: false },
    { kind: "break-glass-authorization", why: "trust not sent", build: one("h", withoutTrust(good("h"))), expect: "no", finding: false },
    {
      kind: "break-glass-authorization", why: "trust unreadable",
      build: one("h", withoutTrust(good("h", { artifactTrustError: "unreadable" }))), expect: "no", finding: false,
    },
    { kind: "artifact-trust-unreadable", why: "never reported", build: unheard, expect: "no", finding: false },
    {
      kind: "authorization-unnamed", why: "not confirmed",
      build: one("h", good("h", { applied: { state: "pending" }, artifactTrust: trustOf({ currentAuthorizationMode: null }) })),
      expect: "no", finding: false,
    },
    {
      kind: "authorization-unnamed", why: "trust unreadable",
      build: one("h", withoutTrust(good("h", { artifactTrustError: "unreadable" }))), expect: "no", finding: false,
    },
    { kind: "silent", why: "not heard from since this process started", build: unheard, expect: "no", finding: false },
  ];

  it("every kind whose input is null or absent is not evaluated unless absence is itself the finding", () => {
    // Every host kind written down above has a case here; `never-reported` is judged by the grace
    // window and has its own test below.
    const covered = new Set<string>(cases.map((c) => c.kind));
    assert.deepEqual(EXPECTED_HOST_KINDS.filter((k) => !covered.has(k) && k !== "never-reported"), []);
    for (const c of cases) {
      const v = fleetView(c.build(), NOW, 90, LONG_AGO, "floor" in c ? c.floor : FLOOR);
      assert.equal(v.evaluated.h![c.kind], c.expect, `${c.kind}: ${c.why}`);
      assert.equal(v.findings.some((f) => f.kind === c.kind), c.finding, `${c.kind}: ${c.why} — finding`);
    }
  });

  it("never-reported is not evaluated inside the grace window, and is after it", () => {
    const s = unheard();
    assert.equal(view(s, NOW, new Date(NOW.getTime() - 5_000)).evaluated.h!["never-reported"], "no");
    const after = view(s, NOW, LONG_AGO);
    assert.equal(after.evaluated.h!["never-reported"], "yes");
    assert.ok(after.findings.some((f) => f.kind === "never-reported"));
  });

  it("agent-version: a missing version with a floor is a finding, judged", () => {
    // The exception to the rule above: here absence is the finding.
    const b = good("h");
    delete (b as { agentVersion?: unknown }).agentVersion;
    const v = view(one("h", b)());
    assert.equal(v.evaluated.h!["agent-version-behind"], "yes");
    assert.ok(v.findings.some((f) => f.kind === "agent-version-behind"));
  });

  it("break-glass: trust turning unreadable opens artifact-trust-unreadable and does not resolve break-glass", () => {
    const s = one("h", good("h", { artifactTrust: trustOf({ currentAuthorizationMode: "break-glass" }) }))();
    const before = view(s);
    assert.ok(before.findings.some((f) => f.kind === "break-glass-authorization"));
    assert.equal(before.evaluated.h!["break-glass-authorization"], "yes");
    handleHeartbeat(s, "h", withoutTrust(good("h", { artifactTrustError: "unreadable" })), AT);
    const after = view(s);
    assert.equal(after.findings.some((f) => f.kind === "break-glass-authorization"), false);
    assert.equal(after.evaluated.h!["break-glass-authorization"], "no");
    assert.ok(after.findings.some((f) => f.kind === "artifact-trust-unreadable"));
    assert.equal(after.evaluated.h!["artifact-trust-unreadable"], "yes");
  });

  it("a silent host judges nothing but its silence", () => {
    const s = unheard();
    handleHeartbeat(s, "h", good("h", { publishedPorts: [] }), "2026-07-29T23:50:00Z");
    const ev = view(s).evaluated.h!;
    for (const kind of EXPECTED_HOST_KINDS) {
      const want = kind === "silent" || kind === "never-reported" ? "yes" : "no";
      assert.equal(ev[kind as ProblemKind], want, kind);
    }
    // Known positive: the same beat, recent, judges published-ports.
    assert.equal(view(one("h", good("h", { publishedPorts: [] }))()).evaluated.h!["published-ports"], "yes");
  });

  it("a host unheard since restart judges nothing but never-reported, during and after the grace window", () => {
    const s = unheard();
    for (const startedAt of [new Date(NOW.getTime() - 5_000), LONG_AGO]) {
      const ev = view(s, NOW, startedAt).evaluated.h!;
      for (const kind of EXPECTED_HOST_KINDS) {
        if (kind === "never-reported") continue;
        assert.equal(ev[kind as ProblemKind], "no", `${kind} at relay start ${startedAt.toISOString()}`);
      }
    }
  });

  it("workload findings are held while the workload half is pending on this generation", () => {
    const ev = view(one("h", good("h", { workload: { state: "pending", policiesHash: "sha256:w1", observed: [] } }), true)())
      .evaluated.h!;
    assert.equal(ev["workload-objects-missing"], "no");
    assert.equal(ev["workload-document-mismatch"], "no");
    // Known positive: confirmed with everything present judges both.
    const ok = view(one("h", good("h", {
      workload: { state: "confirmed", policiesHash: "sha256:w1", observed: ["util/hp-dev-p700"] },
    }), true)()).evaluated.h!;
    assert.equal(ok["workload-objects-missing"], "yes");
    assert.equal(ok["workload-document-mismatch"], "yes");
  });

  it("trust-ring-split still opens with a host missing its digest, but is not resolvable", () => {
    const s = stateWith({ a: entry("a"), b: entry("b"), c: entry("c") });
    handleHeartbeat(s, "a", good("a"), AT);
    handleHeartbeat(s, "b", good("b", { artifactTrust: trustOf({ trustDigest: DIGEST_B }) }), AT);
    handleHeartbeat(s, "c", withoutTrust(good("c")), AT);
    const v = view(s);
    assert.ok(v.findings.some((f) => f.kind === "trust-ring-split"));
    assert.equal(v.fleetEvaluated["trust-ring-split"], "no-resolve");
    // Known positive: every host reporting a digest makes it judged.
    handleHeartbeat(s, "c", good("c"), AT);
    assert.equal(view(s).fleetEvaluated["trust-ring-split"], "yes");
    // A digest from a host that has since gone silent is as old as its last beat.
    handleHeartbeat(s, "c", good("c"), "2026-07-29T23:50:00Z");
    assert.equal(view(s).fleetEvaluated["trust-ring-split"], "no-resolve");
  });

  // ## R9 — whether the drift reference can be trusted

  it("R9: the first confirm after a restart re-baselines without trust", () => {
    // Before the restart: a drift. After it, the same tampered dump is the first thing this process
    // sees, so it becomes the reference — the finding disappears, and that must not read as resolved.
    const before = one("h", good("h"))();
    handleHeartbeat(before, "h", good("h", { applied: { observedHash: "dump:tampered" } }), AT);
    assert.ok(view(before).findings.some((f) => f.kind === "ruleset-changed"));

    const restarted = one("h", good("h", { applied: { observedHash: "dump:tampered" } }))();
    assert.equal(restarted.referenceTrusted?.h, false);
    const v = view(restarted);
    assert.equal(v.findings.some((f) => f.kind === "ruleset-changed"), false);
    assert.equal(v.evaluated.h!["ruleset-changed"], "no-resolve");
    // A new change on top of it still opens.
    handleHeartbeat(restarted, "h", good("h", { applied: { observedHash: "dump:3" } }), AT);
    assert.ok(view(restarted).findings.some((f) => f.kind === "ruleset-changed"));
  });

  it("R9: a new generation confirmed in this process re-baselines with trust, and drift then opens and resolves", () => {
    const s = one("h", good("h", {}, "g-old"))();
    handleHeartbeat(s, "h", good("h", { applied: { observedHash: "dump:2" } }), AT);
    assert.equal(s.referenceTrusted?.h, true);
    handleHeartbeat(s, "h", good("h", { applied: { observedHash: "dump:3" } }), AT);
    const open = view(s);
    assert.ok(open.findings.some((f) => f.kind === "ruleset-changed"));
    assert.equal(open.evaluated.h!["ruleset-changed"], "yes");
    handleHeartbeat(s, "h", good("h", { applied: { observedHash: "dump:2" } }), AT);
    const resolved = view(s);
    assert.equal(resolved.findings.some((f) => f.kind === "ruleset-changed"), false);
    assert.equal(resolved.evaluated.h!["ruleset-changed"], "yes");
  });

  it("R9: a reference with a null hash is not trusted — reached here only by writing the reference directly", () => {
    // `handleHeartbeat` never stores a null hash, so nothing in this file reaches this branch through
    // heartbeats alone.
    const s = unheard();
    s.references.h = { generation: "g-old", hash: null, artifactHash: null };
    handleHeartbeat(s, "h", good("h"), AT);
    assert.equal(s.referenceTrusted?.h, false);
  });

  it("a new-generation confirm with an unchanged kernel does not earn trust", () => {
    // Different artifact, same dump: `kernel-unchanged` on the beat that would otherwise rebind with trust.
    const s = one("h", good("h", { applied: { artifactHash: "sha256:o" } }, "g-old"))();
    handleHeartbeat(s, "h", good("h"), AT);
    assert.deepEqual(s.contradictions.h?.map((c) => c.kind), ["kernel-unchanged"]);
    assert.equal(s.referenceTrusted?.h, false);
    assert.equal(view(s).evaluated.h!["ruleset-changed"], "no-resolve");
    // Known positive: the same move with a changed dump contradicts nothing and earns trust.
    const ok = one("h", good("h", { applied: { artifactHash: "sha256:o" } }, "g-old"))();
    handleHeartbeat(ok, "h", good("h", { applied: { observedHash: "dump:2" } }), AT);
    assert.equal(ok.contradictions.h, undefined);
    assert.equal(ok.referenceTrusted?.h, true);
  });

  it("a confirm of a generation this relay never served does not earn trust", () => {
    const s = one("h", good("h", {}, "g-old"))();
    handleHeartbeat(s, "h", good("h", { applied: { observedHash: "dump:2" } }, "g-other"), AT);
    assert.deepEqual(s.contradictions.h?.map((c) => c.kind), ["unknown-generation"]);
    assert.equal(s.referenceTrusted?.h, false);
  });

  it("a healthy host with every input judges every state kind", () => {
    const s = one("h", good("h", {}, "g-old"), true)();
    handleHeartbeat(s, "h", good("h", {
      applied: { observedHash: "dump:2", table: "present" },
      foreignFilters: [],
      publishedPorts: [],
      ciliumExposure: { nodePortAddresses: ["192.0.2.1"], services: [] },
      workload: { state: "confirmed", policiesHash: "sha256:w1", observed: ["util/hp-dev-p700"] },
    }), AT);
    const v = view(s);
    assert.deepEqual(v.findings, []);
    // Written out here rather than derived from the code: every kind, and what a healthy host gives.
    assert.deepEqual(v.evaluated.h, {
      "rolled-back": "yes",
      "refused-generation": "yes",
      "table-absent": "yes",
      "ruleset-changed": "yes",
      "published-ports": "yes",
      "cilium-nodeport-unrestricted": "yes",
      "contradiction-artifact-hash-changed": "no",
      "contradiction-artifact-hash-wrong": "yes",
      "contradiction-unknown-generation": "no",
      "contradiction-kernel-unchanged": "no",
      "unexpected-filters": "yes",
      "workload-unreported": "yes",
      "workload-not-confirmed": "yes",
      "workload-objects-missing": "yes",
      "workload-document-mismatch": "yes",
      "agent-version-behind": "yes",
      "break-glass-authorization": "yes",
      "artifact-trust-unreadable": "yes",
      "authorization-unnamed": "yes",
      "never-reported": "yes",
      silent: "yes",
    });
    assert.equal(v.fleetEvaluated["trust-ring-split"], "yes");
  });

  it("refused-generation is not resolvable while the table is unread and the refusal is of its own generation", () => {
    // The `refusalAnswered` filter hides this refusal; its disappearing is not the host taking the generation.
    const refusal = { generation: GEN, reason: "schema too new", at: AT };
    const v = view(one("h", good("h", { applied: { table: "unread" }, lastRefusal: refusal }))());
    assert.equal(v.findings.some((f) => f.kind === "refused-generation"), false);
    assert.equal(v.evaluated.h!["refused-generation"], "no-resolve");
    // Known positive: the same refusal with the table present is judged.
    const ok = view(one("h", good("h", { applied: { table: "present" }, lastRefusal: refusal }))());
    assert.equal(ok.evaluated.h!["refused-generation"], "yes");
  });

  // ## PR 4 — event counts

  it("counts each beat that produced an event-shaped contradiction, and starts again at 0 in a new process", () => {
    const s = one("h", good("h"))();
    assert.deepEqual(view(s).events, []);
    handleHeartbeat(s, "h", good("h", { applied: { artifactHash: "sha256:other" } }), "2026-07-30T00:00:15Z");
    handleHeartbeat(s, "h", good("h", { applied: { artifactHash: "sha256:other" } }), "2026-07-30T00:00:30Z");
    assert.deepEqual(view(s).events, [
      { host: "h", kind: "contradiction-artifact-hash-changed", count: 2, lastAt: "2026-07-30T00:00:30Z" },
    ]);
    // A beat without one leaves the count as it was.
    s.manifest = { ...s.manifest!, generation: "g-next" };
    handleHeartbeat(s, "h", good("h", { applied: { observedHash: "dump:2" } }, "g-next"), "2026-07-30T00:00:45Z");
    assert.equal(s.contradictions.h, undefined);
    assert.equal(view(s).events[0]!.count, 2);
    // A new process: the same beats again count from 0.
    const restarted = one("h", good("h"))();
    handleHeartbeat(restarted, "h", good("h", { applied: { artifactHash: "sha256:other" } }), AT);
    assert.equal(view(restarted).events[0]!.count, 1);
  });

  it("counts the other two event kinds, and the catalog's problems are unchanged by the counts", () => {
    const v = view(catalog());
    assert.deepEqual(v.events.map((e) => `${e.host} ${e.kind} ${e.count}`).sort(), [
      "c-contra contradiction-artifact-hash-changed 1",
      "c-contra2 contradiction-kernel-unchanged 1",
      "c-contra2 contradiction-unknown-generation 1",
    ]);
    assert.deepEqual(v.problems, CATALOG_PROBLEMS_BEFORE_148);
  });

  it("names when the process whose counts these are started, or null when not told", () => {
    assert.equal(view(state()).processStartedAt, LONG_AGO.toISOString());
    assert.equal(fleetView(state(), NOW).processStartedAt, null);
  });

  it("a host is observable when heard from since this process started and not silent", () => {
    const v = view(catalog());
    assert.equal(v.hostObservable["c-never"], false);
    assert.equal(v.hostObservable["c-silent"], false);
    assert.equal(v.hostObservable["c-rolled"], true);
    // The same rule that makes every kind but silent and never-reported `no`.
    for (const [host, ev] of Object.entries(v.evaluated)) assert.equal(v.hostObservable[host], ev["rolled-back"] !== "no", host);
    assert.deepEqual(Object.keys(v.hostObservable).sort(), Object.keys(v.evaluated).sort());
  });
});

const CATALOG_PROBLEMS_BEFORE_148 = [
  "c-rolled: rolled back — baseline absent",
  "c-refused: refused generation g-next — schema too new",
  "c-table: confirmed generation 6f98e0c but its table is absent — rebooted",
  "c-drift: ruleset no longer matches the dump it confirmed",
  "c-ports: 1 port(s) are published by another table and bypass this ruleset (DNAT on prerouting, before any input hook): tcp 8080 -> 192.0.2.10:80",
  "c-cilium: Cilium nodeport-addresses is unrestricted; 1 eBPF HostPort/NodePort frontend(s) bypass this nftables ruleset: HostPort 192.0.2.20:443/TCP web/web",
  "c-intr: 1 change(s) to its ruleset were not made by the agent — latest 2026-07-30T00:00:00Z pid=7 (nft): add rule inet heliopause input accept",
  "c-contra: reporting contradicts itself — reported generation 6f98e0c with artifact sha256:a2 but earlier reported the same generation with sha256:a1 — a generation names one artifact per host, so one of those reports was false",
  "c-contra: reporting contradicts itself — confirmed generation 6f98e0c with artifact sha256:a2, but the manifest publishes sha256:c-contra for this host — the agent's own hash check should have refused this artifact and reverted",
  "c-contra2: reporting contradicts itself — confirmed generation g-other, which is neither the published 6f98e0c nor the g-old it last confirmed — this relay never served it that",
  "c-contra2: reporting is unexplained — moved from generation g-old to g-other with a different artifact (sha256:o → sha256:x) but an identical kernel dump dump:1 — either the new rules were not applied, or the difference is confined to parts of the artifact a stateless dump does not show",
  "c-filters: inet firewalld also filters here — this host's confirmed rules are not the only thing deciding",
  "c-wl-unrep: applied its ruleset but has not reported the workload half",
  "c-wl-notconf: workload half is rolled-back on cluster dev — absent after apply",
  "c-wl-missing: workload half reports confirmed but 1 object(s) are not in cluster dev: util/hp-dev-p700",
  "c-wl-doc: workload half confirmed document sha256:other but the manifest publishes sha256:w1 — it applied something else",
  "c-old: runs agent 0.5.0, below the 0.6.0 floor",
  "c-bg: enforcing a break-glass authorization from 2026-07-29T00:00:00Z — that mode skips the two-person rule, and nothing else in this system reports that it is still in force",
  "c-trusterr: cannot read its artifact signing trust — trust directory is not configured",
  "c-unnamed: enforcing generation 6f98e0c but cannot name the authorization for it — an expired authorization can never be re-applied on this host, and a break-glass one would not be reported",
  "c-never: has never reported",
  "c-silent: silent for 660s",
  "the fleet does not agree on which keys may sign a ruleset — sha256:aaaaaaaaaaaa: c-bg, c-cilium, c-contra, c-contra2, c-drift, c-filters, c-intr, c-old, c-ports, c-refused, c-rolled, c-silent, c-table, c-unnamed, c-wl-doc, c-wl-missing, c-wl-notconf, c-wl-unrep · sha256:bbbbbbbbbbbb: c-ring — expected during a key rotation and a finding after one",
];
