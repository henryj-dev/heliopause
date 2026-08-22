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

  // ## The two halves of the console's CSP, and why they must stay apart
  //
  // `script-src` can only be written by the build — Kit hashes its inline bootstrap and emits the
  // directive as a `<meta http-equiv>`. `frame-ancestors` can only be written by the server — it is
  // **ignored** in a meta element. So the policy is split, and the browser enforces the intersection
  // of the two.
  //
  // That intersection is what makes this worth a test. If someone later adds `script-src 'self'` to
  // the header "for completeness", the intersection drops Kit's hash and the console goes blank —
  // with every unit test still green, because each half is individually valid. This asserts the
  // split rather than either half.
  //
  // Verified end to end once, against a real `npm run build:web`: the meta carried
  // `script-src 'self' 'sha256-3mqbss…'`, the page's single inline script hashed to exactly that,
  // and the header carried no `script-src`. That check needs a build, so it is not run here.
  it("keeps script-src in the build and frame-ancestors in the server", () => {
    const svelteConfig = readFileSync(new URL("../packages/web/svelte.config.js", import.meta.url), "utf8");
    const server = readFileSync(new URL("./web-console.ts", import.meta.url), "utf8");

    // Kit's half: hashed, because the bootstrap is inline and no static string can name it.
    assert.match(svelteConfig, /csp:\s*\{[\s\S]*mode:\s*"hash"/);
    assert.match(svelteConfig, /"script-src"/);

    // The server's half must not restate it — the intersection would drop the hash.
    const headerBlock = /SECURITY_HEADERS[\s\S]*?\n\};/.exec(server)?.[0] ?? "";
    assert.ok(headerBlock, "SECURITY_HEADERS not found in web-console.ts");
    assert.ok(
      !headerBlock.includes("script-src"),
      "script-src is in the response header as well as the build — the intersection blanks the console",
    );
    // And the directive a meta tag cannot deliver has to be here.
    assert.match(headerBlock, /frame-ancestors 'none'/);
  });

  it("permits the explicit TypeScript import suffixes used by the Svelte package", () => {
    const tsconfig = JSON.parse(readFileSync(new URL("../packages/web/tsconfig.json", import.meta.url), "utf8")) as {
      compilerOptions: { allowImportingTsExtensions?: boolean };
    };
    assert.equal(tsconfig.compilerOptions.allowImportingTsExtensions, true);
  });
});
