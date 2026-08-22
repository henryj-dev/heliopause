// Endpoint normalisation — specifically the `geofeed` kind (H8a).
//
// The renderer never sees this kind. It receives CIDRs that a caller resolved, exactly as it does for
// `host`, so the value of the kind is entirely in what normalisation refuses to accept. Two of those
// refusals are the reason the kind is safe to have at all: it cannot be a destination, and its selector
// must be a real selector rather than a partial wildcard.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { contains } from "./test-util.ts";
import { normalizePolicy, policyFingerprint, PolicyError } from "./policy.ts";

const base = {
  name: "cf edge to mailer 443",
  src: { kind: "geofeed", value: "cloudflare:KR" },
  dst: { kind: "host", value: "mailer-01" },
  proto: "tcp",
  ports: "443",
  action: "allow",
};

const norm = (over: Record<string, unknown> = {}) => normalizePolicy({ ...base, ...over }, "p-1");

describe("geofeed endpoints", () => {
  it("accepts a geofeed source", () => {
    // The known positive. Without it, every refusal below could pass because the kind is rejected
    // outright.
    const p = norm();
    assert.deepEqual(p.src, { kind: "geofeed", value: "cloudflare:KR" });
  });

  it("accepts a subdivision and the whole-feed selector", () => {
    assert.equal(norm({ src: { kind: "geofeed", value: "vultr:KR-11" } }).src.value, "vultr:KR-11");
    assert.equal(norm({ src: { kind: "geofeed", value: "cloudflare:*" } }).src.value, "cloudflare:*");
  });

  it("refuses a geofeed destination", () => {
    // A geofeed names where traffic comes from. As a destination it would mean "to everything in that
    // country" — thousands of prefixes from one typo, in an egress rule.
    assert.throws(() => norm({ dst: { kind: "geofeed", value: "cloudflare:KR" } }), (e: unknown) => {
      assert.ok(e instanceof PolicyError);
      contains((e as Error).message, "dst.kind cannot be geofeed");
      return true;
    });
  });

  it("refuses a malformed selector at the edit, not at render time", () => {
    // The renderer receives resolved CIDRs and cannot tell a typo'd selector from a real one. If this
    // is not caught here it is caught nowhere.
    for (const v of ["cloudflare", "cloudflare:KOREA", "cloudflare:KR-*", "cloudflare:K*", ":KR"]) {
      assert.throws(() => norm({ src: { kind: "geofeed", value: v } }), PolicyError, `"${v}" must be refused`);
    }
  });

  it("requires a value", () => {
    assert.throws(() => norm({ src: { kind: "geofeed", value: "" } }), PolicyError);
  });

  it("normalises case so one selector is one policy", () => {
    // `Cloudflare:kr` and `cloudflare:KR` select the same prefixes. Leaving them distinct would make
    // `policyFingerprint` report an edit that did not happen — the same reason ports and label
    // selectors are sorted and deduplicated.
    const a = norm({ src: { kind: "geofeed", value: "  CloudFlare : kr " } });
    const b = norm();
    assert.equal(a.src.value, "cloudflare:KR");
    assert.equal(policyFingerprint(a), policyFingerprint(b));
  });

  it("keeps distinct selectors distinct in the fingerprint", () => {
    // The other half of the same property: normalisation must not collapse two different sources.
    const kr = policyFingerprint(norm());
    const jp = policyFingerprint(norm({ src: { kind: "geofeed", value: "cloudflare:JP" } }));
    assert.notEqual(kr, jp);
  });
});

describe("endpoint kinds that were already refused", () => {
  it("still refuses an unknown kind, and now lists geofeed as available", () => {
    // Pins that adding a kind widened the set rather than replacing the check.
    assert.throws(() => norm({ src: { kind: "geofeedd", value: "cloudflare:KR" } }), (e: unknown) => {
      contains((e as Error).message, "geofeed");
      return true;
    });
  });

  it("still refuses a k8s-service source", () => {
    assert.throws(() => norm({ src: { kind: "k8s-service", value: "ns/svc" } }), PolicyError);
  });
});
