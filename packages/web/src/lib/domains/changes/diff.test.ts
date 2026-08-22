import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { changesPath, readPlanDiff } from "./diff.ts";

describe("readPlanDiff", () => {
  it("keeps same apart from an empty change list", () => {
    const read = readPlanDiff({ base: "abc1234", head: "abc1234", same: true, commits: [], files: [] }, 200);
    assert.deepEqual(read, { kind: "same", base: "abc1234", head: "abc1234" });
  });

  it("reads authored files and generated files as two lists", () => {
    const read = readPlanDiff({
      base: "e30b8d1",
      head: "4a91c7f",
      same: false,
      commits: [{ sha: "7c2b91d", message: "allow postgres", author: "nari.kim" }],
      files: [{ filename: "prod.ts", status: "modified", additions: 14, deletions: 6, patch: "+x" }],
      generated: [{ filename: "rendered/prod/gw-01.nft", status: "modified", additions: 302, deletions: 77 }],
    }, 200);
    assert.equal(read.kind, "changed");
    if (read.kind !== "changed") return;
    assert.equal(read.files[0]?.patch, "+x");
    assert.equal(read.generated[0]?.patch, null);
    assert.equal(read.commits[0]?.sha, "7c2b91d");
  });

  it("treats unavailable as a reason, not as nothing changed", () => {
    const read = readPlanDiff({ unavailable: "this console has no repository credential to compare with" }, 200);
    assert.equal(read.kind, "unavailable");
    if (read.kind === "unavailable") {
      assert.match(read.reason, /repository credential/);
    }
  });

  it("does not turn a 404 into an empty diff", () => {
    const read = readPlanDiff({ error: "no pending plan with that hash" }, 404);
    assert.equal(read.kind, "unavailable");
  });
});

describe("changesPath", () => {
  it("encodes the hash the way the ruleset reader already does", () => {
    assert.equal(changesPath("sha256:ab"), "/api/plans/sha256%3Aab/changes");
  });
});
