import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  emptyPolicyDocument,
  loadPolicyDocument,
  PolicyStoreError,
  putPolicy,
  removePolicy,
  replacePolicyPlacements,
  savePolicyDocument,
} from "./policy-store.ts";
import type { Policy } from "./policy.ts";

const policy = (id = "P1"): Policy => ({
  id,
  name: "allow web",
  src: { kind: "internet", value: "" },
  dst: { kind: "host", value: "web-01" },
  proto: "tcp",
  ports: "443,80",
  action: "allow",
  denyMode: "drop",
  priority: 100,
  enabled: true,
  notes: "",
});

describe("policy document store", () => {
  it("round-trips a normalized document atomically", () => {
    const dir = mkdtempSync(join(tmpdir(), "heliopause-policy-"));
    const path = join(dir, "policy.json");
    const added = putPolicy(emptyPolicyDocument(), policy()).document;
    savePolicyDocument(path, added);
    const loaded = loadPolicyDocument(path);
    assert.equal(loaded.policies[0]!.ports, "80,443");
    assert.equal(readFileSync(path, "utf8").endsWith("\n"), true);
  });

  it("updates by id without changing its position", () => {
    let doc = putPolicy(emptyPolicyDocument(), policy("P1")).document;
    doc = putPolicy(doc, policy("P2")).document;
    const result = putPolicy(doc, { ...policy("P1"), name: "changed" });
    assert.equal(result.created, false);
    assert.deepEqual(result.document.policies.map((p) => p.id), ["P1", "P2"]);
    assert.equal(result.document.policies[0]!.name, "changed");
  });

  it("refuses duplicate ids and missing deletes", () => {
    const duplicate = { schemaVersion: 1 as const, policies: [policy(), policy()] };
    const dir = mkdtempSync(join(tmpdir(), "heliopause-policy-"));
    const path = join(dir, "policy.json");
    assert.throws(() => savePolicyDocument(path, duplicate), /duplicate policy id/);
    assert.throws(() => removePolicy(emptyPolicyDocument(), "missing"), PolicyStoreError);
  });

  it("replaces placements and removes them with their policy", () => {
    let doc = putPolicy(emptyPolicyDocument(), policy()).document;
    doc = replacePolicyPlacements(doc, "P1", [{ layer: "input", policyId: "P1", host: "web-01", srcCidrs: [], dstCidrs: ["10.0.0.1"] }]);
    assert.equal(doc.placements?.length, 1);
    doc = removePolicy(doc, "P1");
    assert.deepEqual(doc.placements, []);
  });
});
