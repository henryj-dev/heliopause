// CLI-contract (drift) test for `packages/enroll-app`.
//
// The Tauri enrollment-approval app GUI-wraps the repo's Node CLIs
// (`bin/heliopause-enrollment.ts`, `bin/heliopause-pki.ts`) by shelling out to
// them with a fixed argument order and field names. Nothing here runs a cluster,
// a network, or the CLIs — it STATICALLY reads the CLI source and pins the exact
// interface the app depends on, so a CLI change that would break the app fails
// HERE (in CI) instead of silently at the operator's desk. We recently hit this:
// the enrollment CLI is command-first and the fingerprint field is `csrSha256`,
// and a version drift between checkouts caused failures.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel: string) => readFileSync(join(repoRoot, rel), "utf8");

describe("enroll-app CLI contract: bin/heliopause-enrollment.ts", () => {
  const source = read("bin/heliopause-enrollment.ts");

  it("parses positionals command-first (command, store, subject)", () => {
    assert.match(source, /const \[command, store, subject\] = positional/);
  });

  it("treats an https:// store as the remote manager", () => {
    assert.match(source, /store\.startsWith\("https:\/\/"\)/);
  });

  it("dispatches the three subcommands the app invokes", () => {
    for (const command of ["csr-list", "csr-export", "cert-upload"]) {
      assert.ok(
        source.includes(`command === "${command}"`),
        `enrollment CLI must handle ${command}`,
      );
    }
  });
});

describe("enroll-app CLI contract: src/enrollment-store.ts CSR record", () => {
  const source = read("src/enrollment-store.ts");

  it("declares NodeCsrRecord with id, hostname and csrSha256", () => {
    const match = source.match(/interface NodeCsrRecord\s*\{[\s\S]*?\}/);
    assert.ok(match, "NodeCsrRecord interface must exist");
    const body = match[0];
    for (const field of ["id", "hostname", "csrSha256"]) {
      assert.match(body, new RegExp(`\\b${field}\\b`), `NodeCsrRecord must declare ${field}`);
    }
  });
});

describe("enroll-app CLI contract: bin/heliopause-pki.ts sign-csr", () => {
  const source = read("bin/heliopause-pki.ts");

  it("has a sign-csr command", () => {
    assert.match(source, /"sign-csr"/);
  });

  it("parses positionals command-first ([cmd, dirArg, ...rest])", () => {
    assert.match(source, /const \[cmd, dirArg, \.\.\.rest\] = positional/);
  });

  it("reads --expect-sha256 and --name", () => {
    assert.match(source, /expect-sha256/);
    assert.match(source, /flags\.get\("name"\)/);
  });

  it("computes the fingerprint over the CSR in DER form (csrSha256, not the public-key sha)", () => {
    assert.match(source, /-outform/);
    assert.match(source, /"DER"/);
    // sha256 over that DER, matching the enrollment queue's csrSha256.
    assert.match(source, /createHash\("sha256"\)/);
  });
});
