// What the build id has to be true of, for the comparison it feeds to mean anything.
//
// The comparison is "is the renderer the same code as the manager". That makes two properties
// load-bearing and one exclusion load-bearing, and each is a way the field could look right and
// answer wrong:
//
//   · it must move when shipped code moves, or a stale renderer reads as current
//   · it must not move for anything the image does not carry, or a manager run from a checkout
//     never matches a renderer run from an image and the banner is permanently, uselessly on
//   · it must not depend on the order the filesystem lists files in
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildId, computeBuildId } from "./build-id.ts";

const dir = mkdtempSync(join(tmpdir(), "hp-build-"));
after(() => rmSync(dir, { recursive: true, force: true }));

const write = (name: string, text: string) => writeFileSync(join(dir, name), text, "utf8");

describe("the build id", () => {
  it("is the same for the same source", () => {
    write("a.ts", "export const a = 1;\n");
    write("b.ts", "export const b = 2;\n");
    assert.equal(computeBuildId(dir), computeBuildId(dir));
  });

  it("moves when a shipped module changes", () => {
    write("a.ts", "export const a = 1;\n");
    const before = computeBuildId(dir);
    write("a.ts", "export const a = 2;\n");
    assert.notEqual(computeBuildId(dir), before, "a change to shipped code did not move the build id");
  });

  it("moves when a module is added or removed", () => {
    write("a.ts", "export const a = 1;\n");
    const before = computeBuildId(dir);
    write("c.ts", "export const c = 3;\n");
    const added = computeBuildId(dir);
    assert.notEqual(added, before);
    rmSync(join(dir, "c.ts"));
    assert.equal(computeBuildId(dir), before, "removing the file did not restore the id");
  });

  it("moves when a module is renamed but its text is not", () => {
    // Cheap to close and it is the one case a content-only digest gets wrong: the same bytes under
    // a different name is a different program.
    write("a.ts", "export const a = 1;\n");
    const before = computeBuildId(dir);
    rmSync(join(dir, "a.ts"));
    write("z.ts", "export const a = 1;\n");
    assert.notEqual(computeBuildId(dir), before);
    rmSync(join(dir, "z.ts"));
    write("a.ts", "export const a = 1;\n");
  });

  it("ignores tests, which are not in the image", () => {
    // 🔑 Without this the manager running from a checkout can never equal a renderer running from an
    // image, and a banner that is always on is one that stops being read — which is how the thing it
    // reports goes unnoticed a second time.
    write("a.ts", "export const a = 1;\n");
    const before = computeBuildId(dir);
    write("a.test.ts", "// this file is not shipped\n");
    assert.equal(computeBuildId(dir), before, "a test file moved the build id");
    rmSync(join(dir, "a.test.ts"));
  });

  it("ignores files that are not TypeScript", () => {
    write("a.ts", "export const a = 1;\n");
    const before = computeBuildId(dir);
    write("notes.md", "# not code\n");
    assert.equal(computeBuildId(dir), before);
    rmSync(join(dir, "notes.md"));
  });

  it("answers for this repository's own source, and is short enough to read", () => {
    // The known positive for the real call. A digest over an empty or missing directory would still
    // be a hex string, so asserting the shape alone proves nothing about it having read anything.
    const id = buildId();
    assert.match(id, /^[0-9a-f]{12}$/);
    assert.notEqual(id, computeBuildId(dir), "the repository hashed to the same value as a fixture");
  });

  it("computes once and keeps the answer", () => {
    assert.equal(buildId(), buildId());
  });
});
