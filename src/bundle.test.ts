// The content address, and the validation that stands between "JSON arrived" and "this is a generation".
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { BundleError, bundleHash, validateBundle, type PlanBundle } from "./bundle.ts";
import { SCHEMA_VERSION, type Manifest } from "./protocol.ts";

const sha = (s: string) => "sha256:" + createHash("sha256").update(s).digest("hex");

const RULES_A = 'table inet heliopause { chain input { type filter hook input priority 0; } }\n';
const RULES_B = 'table inet heliopause { chain input { type filter hook input priority 0; policy drop; } }\n';

function bundle(over: Partial<PlanBundle> = {}): PlanBundle {
  const manifest: Manifest = {
    generation: "abc1234",
    issuedAt: "2026-08-03T00:00:00.000Z",
    schemaVersion: SCHEMA_VERSION,
    hosts: {
      "gw-01.dev": {
        stage: "canary",
        rulesetHash: sha(RULES_A),
        confirmTimeoutSec: 120,
        mustContain: ["DEV-SSH"],
        expectFilters: [],
      },
    },
  };
  return { manifest, rulesets: { "gw-01.dev": RULES_A }, workload: {}, ...over };
}

function refusal(fn: () => unknown): BundleError {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof BundleError, `expected BundleError, got ${e}`);
    return e;
  }
  return assert.fail("expected a refusal");
}

describe("the content address", () => {
  it("is stable across key insertion order", () => {
    // The hash decides whether an approval applies, so it must be a function of content and not of
    // how the object happened to be built. `JSON.stringify` alone is not: it emits insertion order.
    const a = bundle();
    const reordered: PlanBundle = {
      rulesets: a.rulesets,
      workload: a.workload,
      manifest: {
        hosts: a.manifest.hosts,
        schemaVersion: a.manifest.schemaVersion,
        issuedAt: a.manifest.issuedAt,
        generation: a.manifest.generation,
      },
    };
    assert.equal(bundleHash(a), bundleHash(reordered));
  });

  it("changes when a single rule changes", () => {
    const a = bundle();
    const b = bundle({
      rulesets: { "gw-01.dev": RULES_B },
      manifest: {
        ...a.manifest,
        hosts: { "gw-01.dev": { ...a.manifest.hosts["gw-01.dev"]!, rulesetHash: sha(RULES_B) } },
      },
    });
    assert.notEqual(bundleHash(a), bundleHash(b));
  });

  it("changes when a host is added", () => {
    const a = bundle();
    const b = bundle({
      rulesets: { ...a.rulesets, "gw-02.dev": RULES_B },
      manifest: {
        ...a.manifest,
        hosts: {
          ...a.manifest.hosts,
          "gw-02.dev": { stage: "general", rulesetHash: sha(RULES_B), confirmTimeoutSec: 120, mustContain: [] },
        },
      },
    });
    assert.notEqual(bundleHash(a), bundleHash(b));
  });

  it("cannot be confused by moving bytes between a host name and its ruleset", () => {
    // Length-prefixing. Concatenating fields directly would make these two hash identically, and here
    // the ambiguity would be between two different firewalls.
    const one = bundleHash(bundle({ rulesets: { ab: "cd" }, manifest: { ...bundle().manifest, hosts: {} } }));
    const two = bundleHash(bundle({ rulesets: { a: "bcd" }, manifest: { ...bundle().manifest, hosts: {} } }));
    assert.notEqual(one, two);
  });

  it("distinguishes two renderings issued at different times", () => {
    const a = bundle();
    const b = bundle({ manifest: { ...a.manifest, issuedAt: "2026-08-03T01:00:00.000Z" } });
    assert.notEqual(bundleHash(a), bundleHash(b));
  });
});

describe("validating a bundle off the wire", () => {
  it("accepts a consistent one", () => {
    const b = validateBundle(JSON.parse(JSON.stringify(bundle())));
    assert.equal(b.manifest.generation, "abc1234");
  });

  it("refuses a manifest entry whose digest disagrees with the carried bytes", () => {
    // Every agent would refuse this artifact and revert, so accepting it means publishing a
    // generation guaranteed to fail everywhere.
    const b = bundle({ rulesets: { "gw-01.dev": RULES_B } });
    const e = refusal(() => validateBundle(b));
    assert.match(e.message, /hashes to/);
  });

  it("refuses a host named in the manifest with no ruleset carried", () => {
    const e = refusal(() => validateBundle(bundle({ rulesets: {} })));
    assert.match(e.message, /carries no ruleset/);
  });

  it("refuses a ruleset for a host the manifest does not name", () => {
    // Otherwise the submitter, not the manifest, chooses which files get written.
    const b = bundle();
    const e = refusal(() => validateBundle({ ...b, rulesets: { ...b.rulesets, "ghost.dev": RULES_B } }));
    assert.match(e.message, /does not name/);
  });

  it("refuses a host name that would escape the artifact directory", () => {
    const b = bundle();
    const bad = {
      ...b,
      manifest: { ...b.manifest, hosts: { "../../etc/nft": b.manifest.hosts["gw-01.dev"]! } },
      rulesets: { "../../etc/nft": RULES_A },
    };
    const e = refusal(() => validateBundle(bad));
    assert.match(e.message, /suspicious host/);
  });

  it("refuses a workload document for a host with no workload assignment", () => {
    const b = bundle();
    const e = refusal(() => validateBundle({ ...b, workload: { "gw-01.dev": "{}" } }));
    assert.match(e.message, /no workload assignment/);
  });

  it("refuses a workload assignment with no document carried", () => {
    const b = bundle();
    const entry = b.manifest.hosts["gw-01.dev"]!;
    const bad = {
      ...b,
      manifest: {
        ...b.manifest,
        hosts: {
          "gw-01.dev": {
            ...entry,
            workload: {
              policiesHash: sha("{}"),
              cluster: "dev",
              mustExist: [],
              confirmTimeoutSec: 120,
              policyCount: 0,
              watchSelectors: [],
            },
          },
        },
      },
    };
    const e = refusal(() => validateBundle(bad));
    assert.match(e.message, /carries no document/);
  });

  it("refuses an object that is not a bundle at all", () => {
    refusal(() => validateBundle(null));
    refusal(() => validateBundle({}));
    refusal(() => validateBundle({ manifest: { generation: "g" } }));
  });
});

// ## The protected-host opt-in travels in the bundle
//
// Not decoration: the opt-in is in the content address, which is what stops an approval given for a
// plan *without* the flag from being replayed onto the same generation *with* it. The manager cannot
// check the claim — it holds no policy — so being in the hash and being printed is the whole of what
// it buys. See `assertProtectedAllowed` in `publish.ts`.
describe("the protected-host opt-in", () => {
  it("changes the content address", () => {
    // 🔴 The property. Reverting `allowProtected` out of `PlanBundle` fails here, and so does
    // carrying it anywhere outside the hashed bytes.
    assert.notEqual(
      bundleHash(bundle()),
      bundleHash(bundle({ allowProtected: true })),
    );
  });

  it("is absent rather than false when nobody opted in", () => {
    // So a generation with no protected host hashes exactly as it did before this field existed —
    // adding it invalidated nothing already pending.
    assert.ok(!("allowProtected" in validateBundle(JSON.parse(JSON.stringify(bundle())))));
    assert.equal(
      validateBundle(JSON.parse(JSON.stringify(bundle({ allowProtected: true })))).allowProtected,
      true,
    );
  });

  // ⚠️ This one is about *rejection* only — it stays green on a reader that drops **every** opt-in.
  // What catches that is the preservation assertion in the test above, and an independent review
  // pointed out that the first version of this comment claimed both.
  it("drops anything looser than exactly true", () => {
    // The field is only ever read as "a person said yes", so `"yes"`, `1` and `false` must not
    // become that. Dropped rather than refused: a bundle is also how a pending plan is re-read, and
    // a reader stricter than the writer turns stored plans into errors.
    for (const loose of ["true", 1, "yes", false, null, {}]) {
      const tampered = { ...JSON.parse(JSON.stringify(bundle())), allowProtected: loose };
      assert.ok(
        !("allowProtected" in validateBundle(tampered)),
        `allowProtected: ${JSON.stringify(loose)} became an opt-in`,
      );
    }
  });
});
