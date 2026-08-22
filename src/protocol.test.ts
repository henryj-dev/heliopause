// Protocol guard tests.
//
// The types carry most of the contract and the compiler checks those. What is left here are the
// two decisions a type cannot express: what counts as version skew, and what counts as drift.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { contains } from "./test-util.ts";
import {
  artifactMatches,
  hasDrifted,
  missingObjects,
  workloadStatus,
  ROLLOUT_ORDER,
  schemaSupported,
  SCHEMA_VERSION,
  type Artifact,
  type Heartbeat,
} from "./protocol.ts";

const artifact: Artifact = {
  generation: "6f98e0c",
  host: "h-dev-01",
  ruleset: "table inet heliopause {}\n",
  rulesetHash: "sha256:abc",
  confirmTimeoutSec: 120,
  mustContain: ["baseline: management SSH"],
};

function heartbeat(artifactHash: string | null): Heartbeat {
  return {
    host: "h-dev-01",
    agentVersion: "0.0.0",
    schemaVersion: SCHEMA_VERSION,
    applied: { generation: "6f98e0c", state: "confirmed", artifactHash, observedHash: "dump:1" },
  };
}

describe("schemaSupported", () => {
  it("accepts its own version", () => {
    assert.equal(schemaSupported(SCHEMA_VERSION), true);
  });

  // A newer manager must not be able to drive an older agent by accident. Refusing forward
  // versions is the point — an agent that "mostly understands" a newer artifact applies a
  // partial firewall, which is worse than applying none.
  it("refuses a newer artifact", () => {
    assert.equal(schemaSupported(SCHEMA_VERSION + 1), false);
  });

  it("refuses an older artifact", () => {
    assert.equal(schemaSupported(SCHEMA_VERSION - 1), false);
  });
});

describe("artifactMatches", () => {
  it("accepts a host reporting the digest we published", () => {
    assert.equal(artifactMatches(artifact, heartbeat("sha256:abc")), true);
  });

  it("rejects a host running something else", () => {
    assert.equal(artifactMatches(artifact, heartbeat("sha256:def")), false);
  });

  it("rejects a host that has applied nothing", () => {
    assert.equal(artifactMatches(artifact, heartbeat(null)), false);
  });
});

describe("hasDrifted", () => {
  it("is false while the dump is unchanged since apply", () => {
    assert.equal(hasDrifted("dump:1", "dump:1"), false);
  });

  it("is true once the dump differs from the post-apply reference", () => {
    assert.equal(hasDrifted("dump:1", "dump:2"), true);
  });

  // Fail safe. A null observation means the dump could not be read, so compliance is unknown —
  // and unknown has to surface rather than pass silently.
  it("treats an unreadable dump as drift", () => {
    assert.equal(hasDrifted("dump:1", null), true);
  });

  // Before the first apply there is no reference. That is reported by `state`, not as drift —
  // otherwise every unprovisioned host would sit permanently in an alarm state.
  it("is false when no reference has been captured yet", () => {
    assert.equal(hasDrifted(null, "dump:1"), false);
    assert.equal(hasDrifted(null, null), false);
  });
});

describe("ROLLOUT_ORDER", () => {
  // The gateway runs the relay. If it locks itself out, every other host in that VPC stops
  // receiving artifacts — including the one that would fix it. It goes last, always.
  it("puts the gateway last", () => {
    assert.equal(ROLLOUT_ORDER.at(-1), "gateway");
  });

  it("starts with the canary", () => {
    assert.equal(ROLLOUT_ORDER[0], "canary");
  });
});

// ── The workload half ─────────────────────────────────────────────────────────

const wlArtifact: Artifact = {
  ...artifact,
  workload: {
    policies: "[]",
    policiesHash: "sha256:w1",
    applier: "h-dev-01",
    cluster: "dev",
    mustExist: ["util/hp-dev-p700", "arc-runners/hp-dev-p701"],
    confirmTimeoutSec: 300,
  },
};

function wlHeartbeat(policiesHash: string | null): Heartbeat {
  return {
    ...heartbeat("sha256:abc"),
    workload: { state: "confirmed", policiesHash, observed: null },
  };
}

describe("workloadStatus", () => {
  it("says n/a when nothing was assigned and nothing reported", () => {
    // Not a success and not a failure. A boolean would have to fold this into one of them, and
    // either choice is wrong: true hides a dropped assignment, false breaks every non-cluster host.
    assert.equal(workloadStatus(artifact, heartbeat("sha256:abc")), "n/a");
  });

  it("says ok when the digests agree", () => {
    assert.equal(workloadStatus(wlArtifact, wlHeartbeat("sha256:w1")), "ok");
  });

  it("says missing when a half was published and the host said nothing", () => {
    // A schema-2 agent always reports the field when it has one, so silence means it never got there.
    assert.equal(workloadStatus(wlArtifact, heartbeat("sha256:abc")), "missing");
  });

  it("says mismatch when the host applied something else", () => {
    assert.equal(workloadStatus(wlArtifact, wlHeartbeat("sha256:other")), "mismatch");
  });

  it("flags a host reporting a half it was never assigned", () => {
    // Left over from an earlier generation, or a node that thinks it is the applier. Either way the
    // cluster may be holding objects nothing is publishing.
    assert.equal(workloadStatus(artifact, wlHeartbeat("sha256:w1")), "unassigned-but-reported");
  });
});

describe("missingObjects", () => {
  it("is empty when every expected object is present", () => {
    assert.deepEqual(missingObjects(wlArtifact.workload!.mustExist, [
      "util/hp-dev-p700",
      "arc-runners/hp-dev-p701",
    ]), []);
  });

  it("names the object that is absent", () => {
    assert.deepEqual(
      missingObjects(wlArtifact.workload!.mustExist, ["util/hp-dev-p700"]),
      ["arc-runners/hp-dev-p701"],
    );
  });

  it("ignores objects present beyond what was expected", () => {
    // Extra objects are someone else's business — flux, or an operator. This answers only "did what
    // we published land", and widening it here would make every unrelated CNP a false alarm.
    assert.deepEqual(
      missingObjects(["util/hp-dev-p700"], ["util/hp-dev-p700", "other/unrelated"]),
      [],
    );
  });

  // The inverse of `hasDrifted`'s treatment of a null dump, and for the same reason: unknown must
  // not read as satisfied. A cluster the agent could not query confirms nothing.
  it("treats an unreadable cluster as everything missing", () => {
    assert.deepEqual(
      missingObjects(wlArtifact.workload!.mustExist, null),
      wlArtifact.workload!.mustExist,
    );
  });

  it("is empty when nothing was expected, even with an unreadable cluster", () => {
    assert.deepEqual(missingObjects([], null), []);
  });
});
