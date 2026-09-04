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

// ── The other end of the contract ─────────────────────────────────────────────
//
// 🔴 **Everything above pins the CLI side only.** A contract needs two ends, and this file anchored
// one: change `bin/heliopause-enrollment.ts` and these tests fail; change
// `packages/enroll-app/src-tauri/src/lib.rs` — reorder the arguments, rename a flag, drop a step —
// and **nothing anywhere fails**. The app is not in the npm workspaces, has no Rust tests, and is
// named by no CI job, so this file was the only thing that could have noticed.
//
// It matters more than the line count suggests: this is the desktop tool an operator uses to
// **sign host certificates with the local CA**. Read statically, like the CLI half — nothing here
// runs a build, a toolchain, or the app.
describe("enroll-app app-side contract: src-tauri/src/lib.rs", () => {
  const rs = read("packages/enroll-app/src-tauri/src/lib.rs");

  // The order the CLIs actually parse. `bin/heliopause-enrollment.ts` is command-first and then
  // the store, which is what the tests above pin from the other side; if the app ever emits them
  // the other way round it fails at the operator's desk with a parse error, not here.
  it("calls the enrollment CLI command-first, then the manager URL", () => {
    for (const command of ["csr-list", "csr-export", "cert-upload"]) {
      const call = new RegExp(
        `"bin/heliopause-enrollment\\.ts"\\.to_string\\(\\),\\s*"${command}"\\.to_string\\(\\),\\s*cfg\\.manager_url`,
      );
      assert.match(rs, call, `${command} must be passed command-first, then the manager URL`);
    }
  });

  // `sign-csr <caDir> <csr> <crt>` — positional order, then the two flags the signer reads.
  it("calls sign-csr with the CA dir first and both verification flags", () => {
    const signCall = /\.arg\("bin\/heliopause-pki\.ts"\)[\s\S]{0,600}?\.output\(\)/.exec(rs)?.[0] ?? "";
    assert.ok(signCall, "the sign-csr invocation must be findable");
    assert.match(signCall, /\.arg\("sign-csr"\)/);
    assert.match(signCall, /\.arg\(&cfg\.pki_dir\)/);
    assert.match(signCall, /--name=\{hostname\}/);
    // Dropping this flag would sign whatever CSR the manager handed over, with no check that it is
    // the key the operator was shown. It is the whole reason the fingerprint travels.
    assert.match(signCall, /--expect-sha256=\{expect_sha256\}/);
  });

  it("uses the field name the enrollment store actually declares", () => {
    // `csrSha256`, not `sha256` or `fingerprint` — a drift between checkouts caused this once.
    assert.match(rs, /csr_sha256|csrSha256/);
  });

  // 🔴 The app spawns processes. It must never do so through a shell: every argument here is
  // operator-supplied or manager-supplied, and a shell would make the difference between an
  // argument and a command a matter of quoting.
  it("spawns with argument vectors and never through a shell", () => {
    assert.doesNotMatch(rs, /Command::new\("(?:sh|bash|zsh|cmd)"\)/);
    assert.doesNotMatch(rs, /\.arg\("-c"\)/);
    assert.doesNotMatch(rs, /std::process::Command::new\("\/bin\//);
  });

  // The CSR id reaches the filesystem as a temp-file name. `sanitize` is the only thing standing
  // between a manager-supplied id and a path that escapes the temp directory, and its guarantee
  // lived in a comment.
  it("sanitises the CSR id before it becomes a path", () => {
    assert.match(rs, /fn sanitize\(/);
    assert.match(rs, /is_ascii_alphanumeric\(\)/);
    assert.match(rs, /let safe_id = sanitize\(/);
    // …and the temp paths are built from the sanitised value, not the raw one.
    assert.match(rs, /format!\("\{safe_id\}\.csr"\)/);
    assert.match(rs, /format!\("\{safe_id\}\.crt"\)/);
  });
});

// The frontend is a plain page in a webview with `withGlobalTauri`, so its permission set is the
// boundary: whatever the page may invoke, an XSS in it may invoke too.
describe("enroll-app permission boundary: src-tauri/capabilities/default.json", () => {
  const caps = JSON.parse(read("packages/enroll-app/src-tauri/capabilities/default.json")) as {
    permissions: string[];
    windows: string[];
  };

  it("grants the core defaults and nothing else", () => {
    assert.deepEqual(caps.permissions, ["core:default"]);
  });

  // The app's own description says the shell plugin is "intentionally NOT enabled — process
  // spawning happens inside the Rust commands". That sentence is the security argument for the
  // whole design, and it was enforced by nobody.
  it("does not enable the shell plugin, which would move spawning into the page", () => {
    for (const p of caps.permissions) {
      assert.doesNotMatch(p, /^shell:/, "the shell plugin would let the webview spawn processes");
    }
  });

  it("scopes the capability to the one window that exists", () => {
    assert.deepEqual(caps.windows, ["main"]);
  });
});
