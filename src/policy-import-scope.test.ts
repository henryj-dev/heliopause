// The judgement `importsAreReusable` makes, driven against a real directory.
//
// Every case below builds the tree it names and asks the function. A case that passed by describing
// the tree in a string would stay green when the function stopped looking at the tree.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { importsAreReusable, stampRecords, type ImportReport, type ImportScope } from "./policy-import-scope.ts";

/** A tree under the system temp dir, removed when the test finishes. */
function fixture(): { root: string; file: (rel: string) => string; remove: () => void } {
  const root = mkdtempSync(join(tmpdir(), "hp-import-scope-"));
  return {
    root,
    file: (rel) => join(root, rel),
    remove: () => rmSync(root, { recursive: true, force: true }),
  };
}

const site = (root: string): ImportScope => ({ sitePath: join(root, "policy", "site.ts"), ownRoots: [] });

/** A complete report naming these paths as the resolved `file:` URLs. */
function report(...paths: string[]): ImportReport {
  return { complete: true, urls: paths.map((p) => pathToFileURL(p).href) };
}

describe("an import report is reusable only when the stamp can see every file", () => {
  it("accepts a file inside the site tree that the stamp records", () => {
    const f = fixture();
    try {
      mkdirSync(f.file("policy"));
      writeFileSync(f.file("policy/site.ts"), "");
      writeFileSync(f.file("policy/helper.ts"), "");
      assert.equal(importsAreReusable(report(f.file("policy/site.ts"), f.file("policy/helper.ts")), site(f.root)), true);
    } finally { f.remove(); }
  });

  it("refuses a file outside the site tree", () => {
    const f = fixture();
    try {
      mkdirSync(f.file("policy"));
      writeFileSync(f.file("policy/site.ts"), "");
      writeFileSync(f.file("elsewhere.ts"), "");
      assert.equal(importsAreReusable(report(f.file("elsewhere.ts")), site(f.root)), false);
    } finally { f.remove(); }
  });

  it("refuses a file under a dot-directory or node_modules, which the stamp does not descend into", () => {
    const f = fixture();
    try {
      mkdirSync(f.file("policy/.generated"), { recursive: true });
      mkdirSync(f.file("policy/node_modules/pkg"), { recursive: true });
      writeFileSync(f.file("policy/site.ts"), "");
      writeFileSync(f.file("policy/.generated/helper.ts"), "");
      writeFileSync(f.file("policy/node_modules/pkg/index.js"), "");
      assert.equal(importsAreReusable(report(f.file("policy/.generated/helper.ts")), site(f.root)), false);
      assert.equal(importsAreReusable(report(f.file("policy/node_modules/pkg/index.js")), site(f.root)), false);
    } finally { f.remove(); }
  });

  it("accepts a dot-file, because the stamp skips dot-directories and not dot-files", () => {
    const f = fixture();
    try {
      mkdirSync(f.file("policy"));
      writeFileSync(f.file("policy/site.ts"), "");
      writeFileSync(f.file("policy/.helper.ts"), "");
      assert.equal(importsAreReusable(report(f.file("policy/.helper.ts")), site(f.root)), true);
    } finally { f.remove(); }
  });

  it("accepts a file inside this renderer's own src or bin", () => {
    const f = fixture();
    try {
      mkdirSync(f.file("policy"));
      mkdirSync(f.file("src"));
      writeFileSync(f.file("policy/site.ts"), "");
      writeFileSync(f.file("src/model.ts"), "");
      const scope: ImportScope = { sitePath: f.file("policy/site.ts"), ownRoots: [f.file("src")] };
      assert.equal(importsAreReusable(report(f.file("src/model.ts")), scope), true);
    } finally { f.remove(); }
  });

  it("does not treat a directory whose name extends the root's name as inside it", () => {
    // `/x/site` and `/x/site2` share a prefix up to the separator. A check written as
    // `startsWith(root)` reads the second as inside the first.
    const f = fixture();
    try {
      mkdirSync(f.file("site"));
      mkdirSync(f.file("site2"));
      writeFileSync(f.file("site/site.ts"), "");
      writeFileSync(f.file("site2/helper.ts"), "");
      const scope: ImportScope = { sitePath: f.file("site/site.ts"), ownRoots: [] };
      assert.equal(importsAreReusable(report(f.file("site2/helper.ts")), scope), false);
    } finally { f.remove(); }
  });

  it("allows a node builtin and refuses a data URL, an http URL, a malformed report and an incomplete one", () => {
    const f = fixture();
    try {
      mkdirSync(f.file("policy"));
      writeFileSync(f.file("policy/site.ts"), "");
      const scope = site(f.root);
      assert.equal(importsAreReusable({ complete: true, urls: ["node:fs"] }, scope), true);
      assert.equal(importsAreReusable({ complete: true, urls: ["data:text/plain,hi"] }, scope), false);
      assert.equal(importsAreReusable({ complete: true, urls: ["http://example.test/x"] }, scope), false);
      assert.equal(importsAreReusable({ complete: true, urls: [1 as unknown as string] }, scope), false);
      assert.equal(importsAreReusable({ complete: false, urls: [] }, scope), false);
    } finally { f.remove(); }
  });

  it("refuses a file whose extension the stamp does not record", () => {
    const f = fixture();
    try {
      mkdirSync(f.file("policy"));
      writeFileSync(f.file("policy/site.ts"), "");
      writeFileSync(f.file("policy/notes.md"), "");
      assert.equal(importsAreReusable(report(f.file("policy/notes.md")), site(f.root)), false);
    } finally { f.remove(); }
  });

  it("follows a symlink to where it points and judges that", () => {
    const f = fixture();
    try {
      mkdirSync(f.file("policy"));
      mkdirSync(f.file("outside"));
      writeFileSync(f.file("policy/site.ts"), "");
      writeFileSync(f.file("outside/helper.ts"), "");
      symlinkSync(f.file("outside/helper.ts"), f.file("policy/linked.ts"));
      // The report names the link, which is inside the tree; the file it points at is not.
      assert.equal(importsAreReusable(report(f.file("policy/linked.ts")), site(f.root)), false);
    } finally { f.remove(); }
  });
  it("refuses a file: URL that names no local path, without throwing", () => {
    // `fileURLToPath` throws for both: an encoded separator, and a host on a platform that has none.
    // Thrown here, it would turn the response into a 503; the report is only unsafe to cache against.
    const f = fixture();
    try {
      mkdirSync(f.file("policy"));
      writeFileSync(f.file("policy/site.ts"), "");
      const scope = site(f.root);
      assert.equal(importsAreReusable({ complete: true, urls: ["file:///a%2Fb.ts"] }, scope), false);
      assert.equal(importsAreReusable({ complete: true, urls: ["file://host/x.ts"] }, scope), false);
    } finally { f.remove(); }
  });

  it("judges a symlinked site file against the link's directory, which is the one the stamp walks", () => {
    // `/x/site.ts → /y/real.ts`. The stamp walks `/x` and stats the entry through the link, so the entry
    // is seen and `/y/helper.ts` is not. Judging against `/y` would accept the helper and cache an
    // answer whose input the stamp cannot see move.
    const f = fixture();
    try {
      mkdirSync(f.file("x"));
      mkdirSync(f.file("y"));
      writeFileSync(f.file("y/real.ts"), "");
      writeFileSync(f.file("y/helper.ts"), "");
      symlinkSync(f.file("y/real.ts"), f.file("x/site.ts"));
      const scope: ImportScope = { sitePath: f.file("x/site.ts"), ownRoots: [] };
      assert.equal(importsAreReusable(report(f.file("y/real.ts")), scope), true);
      assert.equal(importsAreReusable(report(f.file("y/real.ts"), f.file("y/helper.ts")), scope), false);
    } finally { f.remove(); }
  });

  it("reads a root of / as one case with the rest", () => {
    // A prefix length of `root.length + 1` drops the first character below `/`, so `/.generated/` read
    // as `generated/` and was recorded. No temporary directory is `/`, so the judgement is asked directly.
    assert.equal(stampRecords("/.generated/helper.ts", "/"), false);
    assert.equal(stampRecords("/node_modules/helper.ts", "/"), false);
    assert.equal(stampRecords("/policy/helper.ts", "/"), true);
    assert.equal(stampRecords("/a/bc.ts", "/a/b"), false);
  });
});
