import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { Policy } from "./policy.ts";
import { applyPolicyDocument, placementsFromSite, policiesFromSite, SitePolicyError } from "./site-policy.ts";

const policy = (id: string, name = id): Policy => ({
  id, name, src: { kind: "any", value: "" }, dst: { kind: "host", value: "a" },
  proto: "tcp", ports: "443", action: "allow", denyMode: "drop", priority: 100, enabled: true,
});

const site = () => ({
  hosts: [
    { id: "a", stage: "canary" as const, items: [{ policy: policy("P1"), srcCidrs: [], dstCidrs: ["10.0.0.1"] }] },
    { id: "b", stage: "general" as const, items: [{ policy: policy("P1"), srcCidrs: [], dstCidrs: ["10.0.0.1"] }] },
  ],
});

describe("site policy document overlay", () => {
  it("extracts shared policies once and replaces every placement", () => {
    assert.deepEqual(policiesFromSite(site()).map((p) => p.id), ["P1"]);
    const changed = applyPolicyDocument(site(), { schemaVersion: 1, policies: [policy("P1", "changed")] });
    assert.equal(changed.hosts[0]!.items[0]!.policy.name, "changed");
    assert.equal(changed.hosts[1]!.items[0]!.policy.name, "changed");
  });

  it("refuses missing and unplaced policy ids", () => {
    assert.throws(
      () => applyPolicyDocument(site(), { schemaVersion: 1, policies: [policy("P2")] }),
      (e) => e instanceof SitePolicyError && /missing site policies: P1/.test(e.message) && /no site placement: P2/.test(e.message),
    );
  });

  it("builds placements from a schema 2 document, including a new policy", () => {
    const base = site(); const placements = placementsFromSite(base);
    const next = applyPolicyDocument(base, { schemaVersion: 2, policies: [policy("P1"), policy("P2")], placements: [
      ...placements, { layer: "input", policyId: "P2", host: "b", srcCidrs: ["192.0.2.0/24"], dstCidrs: ["10.0.0.2"] },
    ] });
    assert.equal(next.hosts[1]!.items.some((item) => item.policy.id === "P2"), true);
  });
});
