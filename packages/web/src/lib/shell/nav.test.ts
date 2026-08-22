import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { activeKey, crumbsFor, navGroups } from "./nav.ts";

describe("app nav", () => {
  it("groups the seven screens the classic console also names", () => {
    const groups = navGroups();
    assert.deepEqual(groups.map((g) => g.label), ["fleet", "evidence", "policy"]);
    assert.deepEqual(groups.flatMap((g) => g.items.map((i) => i.key)), [
      "fleet", "changes", "enrollment", "lookup", "traffic", "routing", "policy",
    ]);
  });

  it("treats /app and /app/policy/files as named places, not queries", () => {
    assert.equal(activeKey("/app", "/app"), "fleet");
    assert.equal(activeKey("/app/", "/app"), "fleet");
    assert.equal(activeKey("/app/policy/files", "/app"), "policy");
    assert.deepEqual(crumbsFor("policy", "/app/policy/files", "/app"), ["policy", "files"]);
    assert.doesNotMatch(crumbsFor("policy", "/app/policy/files", "/app").join("/"), /[?&]s=/);
  });

  it("names a CSR status in the path so a colleague opens the same queue", () => {
    assert.equal(activeKey("/app/enrollment/pending", "/app"), "enrollment");
    assert.deepEqual(crumbsFor("enrollment", "/app/enrollment/pending", "/app"), ["enrollment", "pending"]);
    assert.deepEqual(crumbsFor("enrollment", "/app/enrollment", "/app"), ["enrollment"]);
    assert.doesNotMatch(crumbsFor("enrollment", "/app/enrollment/pending", "/app").join("/"), /[?&]status=/);
  });

  it("names a plan in the path so a colleague can open the same card", () => {
    const hash = "sha256:" + "9f31c0a4" + "0".repeat(52) + "7be2";
    assert.equal(activeKey(`/app/changes/${encodeURIComponent(hash)}`, "/app"), "changes");
    assert.deepEqual(crumbsFor("changes", `/app/changes/${encodeURIComponent(hash)}`, "/app"), [
      "changes",
      "sha256:9f31c0a4…7be2",
    ]);
    assert.deepEqual(crumbsFor("changes", "/app/changes", "/app"), ["changes"]);
  });
});
