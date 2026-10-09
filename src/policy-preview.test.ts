import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { checkEdit, makePreviewCopy, PreviewRefused } from "./policy-preview.ts";

/** This repository's root — the `src` and `bin` the copy must import. */
const CODE_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

function checkout(): { root: string; site: string } {
  const root = mkdtempSync(join(tmpdir(), "hp-pvtest-src-"));
  const dir = join(root, "policy");
  mkdirSync(dir);
  writeFileSync(join(dir, "policies.json"), '{"groups":{"a":[{"id":"before"}]}}\n');
  writeFileSync(join(dir, ".secret"), "not copied\n");
  mkdirSync(join(dir, "k8s"));
  writeFileSync(join(dir, "k8s", "x.yaml"), "not copied\n");
  const site = join(dir, "alpha.ts");
  writeFileSync(
    site,
    'import P from "./policies.json" with { type: "json" };\n' +
      'export { buildId } from "../src/build-id.ts";\n' +
      "export const groups = P.groups;\n",
  );
  return { root, site };
}

describe("render-diff preview copy", () => {
  it("evaluates the edited file and imports the renderer's own src", async () => {
    const { root, site } = checkout();
    const copy = makePreviewCopy({
      sitePath: site, path: "policies.json", content: '{"groups":{"a":[{"id":"after"}]}}',
      allowPaths: ["policies.json"], codeRoot: CODE_ROOT,
    });
    try {
      assert.ok(copy.sitePath.startsWith(realpathSync(tmpdir())) || copy.sitePath.startsWith(tmpdir()));
      assert.ok(!copy.sitePath.startsWith(root + sep), "the copy is inside the checkout");
      const mod = (await import(pathToFileURL(copy.sitePath).href)) as { groups: { a: { id: string }[] }; buildId: unknown };
      assert.equal(mod.groups.a[0]!.id, "after", "the copy did not carry the edit");
      // Node resolves the `src` symlink to its target, so this is the module this test also imports.
      const canonical = (await import(pathToFileURL(join(CODE_ROOT, "src", "build-id.ts")).href)) as { buildId: unknown };
      assert.equal(mod.buildId, canonical.buildId, "../src in the copy is not the renderer's src");
      // The checkout itself is untouched.
      assert.match(readFileSync(join(root, "policy", "policies.json"), "utf8"), /before/);
    } finally {
      copy.remove();
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("copies files beside the module only, and removes the copy", () => {
    const { root, site } = checkout();
    const copy = makePreviewCopy({
      sitePath: site, path: "policies.json", content: "{}", allowPaths: ["policies.json"], codeRoot: CODE_ROOT,
    });
    const dir = resolve(copy.sitePath, "..");
    try {
      assert.equal(copy.files, 2, "expected alpha.ts and policies.json");
      assert.equal(existsSync(join(dir, ".secret")), false, "a dot file was copied");
      assert.equal(existsSync(join(dir, "k8s")), false, "a subdirectory was copied");
    } finally {
      copy.remove();
      rmSync(root, { recursive: true, force: true });
    }
    assert.equal(existsSync(dir), false, "the copy was left behind");
    copy.remove();
  });

  it("does not follow a symlink in the checkout into the copy", () => {
    const { root, site } = checkout();
    const outside = mkdtempSync(join(tmpdir(), "hp-pvtest-outside-"));
    writeFileSync(join(outside, "secret.json"), '{"secret":true}\n');
    symlinkSync(join(outside, "secret.json"), join(root, "policy", "linked.json"));
    symlinkSync(join(outside, "missing.json"), join(root, "policy", "dangling.json"));
    let copy: ReturnType<typeof makePreviewCopy> | undefined;
    try {
      copy = makePreviewCopy({
        sitePath: site, path: "policies.json", content: "{}", allowPaths: ["policies.json"], codeRoot: CODE_ROOT,
      });
      const dir = resolve(copy.sitePath, "..");
      assert.equal(existsSync(join(dir, "linked.json")), false, "a file from outside the checkout was copied");
      assert.equal(copy.files, 2);
    } finally {
      copy?.remove();
      rmSync(root, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("refuses when the temporary directory is inside the checkout", () => {
    const { root, site } = checkout();
    const inside = join(root, "policy", "tmp");
    mkdirSync(inside);
    const saved = process.env.TMPDIR;
    process.env.TMPDIR = inside;
    try {
      assert.throws(() => makePreviewCopy({
        sitePath: site, path: "policies.json", content: "{}", allowPaths: ["policies.json"], codeRoot: CODE_ROOT,
      }), /inside the policy checkout/);
      assert.deepEqual(readdirSync(inside), [], "a copy was made inside the checkout");
    } finally {
      if (saved === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = saved;
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("refuses anything but JSON data in an editable file", () => {
    const allow = ["policies.json", "alpha.ts"];
    assert.throws(() => checkEdit("other.json", "{}", allow), PreviewRefused);
    assert.throws(() => checkEdit("alpha.ts", "export {}", allow), /only JSON/);
    assert.throws(() => checkEdit("policies.json", "not json", allow), /not JSON/);
    assert.throws(() => checkEdit("policies.json", "1", allow), /object or array/);
    assert.throws(() => checkEdit("policies.json", "x".repeat(1_000_001), allow), /exceeds/);
    assert.throws(() => checkEdit("../policies.json", "{}", ["../policies.json"]), /beside the site module/);
    assert.throws(() => checkEdit("k8s/a.json", "{}", ["k8s/a.json"]), /beside the site module/);
    assert.doesNotThrow(() => checkEdit("policies.json", "[]", allow));
  });

  it("leaves nothing on disk when it refuses", () => {
    const { root, site } = checkout();
    const before = new Set(readdirTmp());
    try {
      assert.throws(() => makePreviewCopy({
        sitePath: site, path: "policies.json", content: "nope", allowPaths: ["policies.json"], codeRoot: CODE_ROOT,
      }), PreviewRefused);
      assert.deepEqual(readdirTmp().filter((n) => !before.has(n)), []);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

/** Preview copies currently in the temporary directory (the checkout fixtures use another prefix). */
const readdirTmp = (): string[] =>
  readdirSync(tmpdir()).filter((n) => n.startsWith("hp-preview-"));
