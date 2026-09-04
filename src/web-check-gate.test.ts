import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

describe("the web diagnostic gate", () => {
  it("runs Svelte diagnostics before unit tests in CI", () => {
    const root = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { scripts: Record<string, string> };
    const ci = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");

    assert.equal(root.scripts["check:web"], "npm run check -w @heliopause/web");
    assert.match(ci, /- run: npm run typecheck\n[\s\S]*- run: npm run check:web\n[\s\S]*- run: npm test/);
  });

  // ## The two halves of the console's CSP, and why the build hash must reach both
  //
  // Kit hashes its inline bootstrap and emits the directive as a `<meta http-equiv>`. The server
  // repeats the exact build hash because the browser intersects the two policies. `frame-ancestors`
  // can only be written by the server because it is **ignored** in a meta element.
  //
  // That intersection is what makes this worth a test. If the server omits the build hash, its
  // `default-src` blocks the inline bootstrap and the console goes blank. Unsafe sources must not
  // be copied from the build policy.
  //
  it("keeps the build hash in the HTTP policy and frame-ancestors in the server", () => {
    const svelteConfig = readFileSync(new URL("../packages/web/svelte.config.js", import.meta.url), "utf8");
    const server = readFileSync(new URL("./web-console.ts", import.meta.url), "utf8");

    // Kit's half: hashed, because the bootstrap is inline and no static string can name it.
    assert.match(svelteConfig, /csp:\s*\{[\s\S]*mode:\s*"hash"/);
    assert.match(svelteConfig, /"script-src"/);

    // The server's half must provide a fail-closed script fallback and allow only style attributes.
    const headerBlock = /SECURITY_HEADERS[\s\S]*?\n\};/.exec(server)?.[0] ?? "";
    assert.ok(headerBlock, "SECURITY_HEADERS not found in web-console.ts");
    assert.ok(
      headerBlock.includes('"script-src \'self\'"'),
      "the server must provide a fail-closed script-src fallback",
    );
    assert.match(headerBlock, /style-src 'self'/);
    assert.match(headerBlock, /style-src-attr 'unsafe-inline'/);
    // And the directive a meta tag cannot deliver has to be here.
    assert.match(headerBlock, /frame-ancestors 'none'/);
  });

  it("permits the explicit TypeScript import suffixes used by the Svelte package", () => {
    const tsconfig = JSON.parse(readFileSync(new URL("../packages/web/tsconfig.json", import.meta.url), "utf8")) as {
      compilerOptions: { allowImportingTsExtensions?: boolean };
    };
    assert.equal(tsconfig.compilerOptions.allowImportingTsExtensions, true);
  });

  // 🔴 `packages/web/tsconfig.json` carried `"exclude": ["src/**/*.test.ts"]`, and the root
  // tsconfig's `include` stops at `src/`, `bin/` and `examples/`. So this workspace's 24 test files
  // were type-checked by **no gate at all** — `node --test` strips types rather than checking them,
  // which is the same reason `examples/` was added to the root `include`.
  //
  // Turning it on found two real errors that had been sitting there: a `type SiteHost` imported
  // from a module that only imports it, and `unapproved: 0` where `UnapprovedDevice[]` belongs.
  //
  // Pinned here rather than trusted, because re-adding an `exclude` is a one-line change that looks
  // like tidying and silently removes a gate.
  it("type-checks the console's own tests — they are inside no other tsconfig", () => {
    const tsconfig = JSON.parse(readFileSync(new URL("../packages/web/tsconfig.json", import.meta.url), "utf8")) as {
      exclude?: string[];
    };
    const excluded = (tsconfig.exclude ?? []).filter((p) => p.includes("test"));
    assert.deepEqual(
      excluded,
      [],
      "packages/web tests are checked by nothing else — excluding them here removes the only gate",
    );

    // And the root tsconfig must not be the thing that covers them, because it does not reach
    // `packages/` at all. Said out loud so the sentence above cannot quietly stop being true.
    const root = JSON.parse(readFileSync(new URL("../tsconfig.json", import.meta.url), "utf8")) as {
      include: string[];
    };
    assert.ok(
      !root.include.some((p) => p.startsWith("packages/")),
      "if the root tsconfig ever covers packages/, rewrite this test rather than deleting it",
    );
  });
});
