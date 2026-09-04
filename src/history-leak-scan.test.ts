import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";

describe("introduced-history site-data scanner", () => {
  it("detects a leak added in an intermediate commit without printing its value", () => {
    const repo = mkdtempSync(join(tmpdir(), "heliopause-history-scan-"));
    const git = (...args: string[]) => execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
    git("init", "-q", "-b", "main");
    git("config", "user.name", "security-test");
    git("config", "user.email", "security-test@example.invalid");
    writeFileSync(join(repo, "fixture.txt"), "documentation address: 192.0.2.1\n");
    git("add", "fixture.txt"); git("commit", "-qm", "base");
    const base = git("rev-parse", "HEAD");

    const leaked = ["8.8", "8.8"].join(".");
    writeFileSync(join(repo, "fixture.txt"), `accidental address: ${leaked}\n`);
    // The candidate also replaces its own scanner with a no-op. CI must execute the trusted base
    // copy (the absolute `scanner` below), not this attacker-controlled file.
    mkdirSync(join(repo, "scripts"));
    writeFileSync(join(repo, "scripts/scan-public-history.mjs"), "process.exit(0);\n");
    git("add", "fixture.txt", "scripts/scan-public-history.mjs");
    git("commit", "-qm", "introduce");
    const introduced = git("rev-parse", "HEAD");
    writeFileSync(join(repo, "fixture.txt"), "documentation address: 198.51.100.4\n");
    git("commit", "-qam", "remove");
    const head = git("rev-parse", "HEAD");

    const scanner = resolve(import.meta.dirname, "../scripts/scan-public-history.mjs");
    const bypassed = spawnSync(process.execPath, [join(repo, "scripts/scan-public-history.mjs")], { cwd: repo, encoding: "utf8" });
    assert.equal(bypassed.status, 0, "fixture must prove the candidate scanner is ineffective");
    const failed = spawnSync(process.execPath, [scanner, "--base", base, "--head", head], { cwd: repo, encoding: "utf8" });
    assert.equal(failed.status, 1);
    assert.match(failed.stderr, /source [0-9a-f]{12} contains a non-documentation IPv4 address/);
    assert.equal(failed.stderr.includes("fixture.txt"), false, "scanner output must redact candidate paths too");
    assert.equal(failed.stderr.includes(leaked), false, "scanner output must redact the matched value");

    const clean = spawnSync(process.execPath, [scanner, "--base", introduced, "--head", head], { cwd: repo, encoding: "utf8" });
    assert.equal(clean.status, 0, clean.stderr);
  });

  it("allows only the exact global-unicast prefix-floor fixture", () => {
    const repo = mkdtempSync(join(tmpdir(), "heliopause-history-prefix-floor-"));
    const git = (...args: string[]) => execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
    git("init", "-q", "-b", "main");
    git("config", "user.name", "security-test");
    git("config", "user.email", "security-test@example.invalid");
    const floor = ["2000", "::"].join("");
    const fixture = join(repo, "fixture.txt");
    const scanner = resolve(import.meta.dirname, "../scripts/scan-public-history.mjs");

    writeFileSync(fixture, `known prefix-floor network: ${floor}/12\n`);
    git("add", "fixture.txt");
    const allowed = spawnSync(process.execPath, [scanner, "--worktree"], { cwd: repo, encoding: "utf8" });
    assert.equal(allowed.status, 0, allowed.stderr);

    writeFileSync(fixture, `bare address must fail: ${floor}\n`);
    const refused = spawnSync(process.execPath, [scanner, "--worktree"], { cwd: repo, encoding: "utf8" });
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /source [0-9a-f]{12} contains a non-documentation IPv6 address/);
    assert.equal(refused.stderr.includes(floor), false, "scanner output must redact the matched value");
  });

  // ## Why these two cases exist
  //
  // Both allowances were added because the scanner refused text it should not have, and the way
  // that showed up is the reason they are pinned rather than trusted:
  //
  //   · `geofeed.ts` explains a bypass in which an IPv4 address is written as IPv6 in pure hex. The
  //     dotted spelling of the same address has always been skipped here and checked by the IPv4
  //     scanner; the hex spelling was refused outright. So the same value passed in one notation and
  //     failed in the other, and the comment describing the defect could not be committed. Three
  //     commits sat red on it while every local gate reported green.
  //   · `2001:db8::/32` is visibly not a real address, which makes it useless as the known positive
  //     in a test that has to accept a *global unicast* prefix. RFC 9637 reserved `3fff::/20` for
  //     exactly that, and it was refused here.
  //
  // Each case asserts the refusal too. An allowance with only the passing half is how a scanner
  // stops scanning: `::ffff:` plus a public address, and a second hextet outside `3fff::/20`, must
  // still fail. Both forbidden literals are assembled at runtime — written out, they would make
  // *this* file fail the scan, which is precisely what happened to the comment in the scanner.
  const scanFixture = (prefix: string, body: string) => {
    const repo = mkdtempSync(join(tmpdir(), `heliopause-history-${prefix}-`));
    const git = (...args: string[]) => execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
    git("init", "-q", "-b", "main");
    git("config", "user.name", "security-test");
    git("config", "user.email", "security-test@example.invalid");
    writeFileSync(join(repo, "fixture.txt"), body);
    git("add", "fixture.txt");
    const scanner = resolve(import.meta.dirname, "../scripts/scan-public-history.mjs");
    return spawnSync(process.execPath, [scanner, "--worktree"], { cwd: repo, encoding: "utf8" });
  };

  it("reads a hex-written embedded IPv4 as the address it is, in both directions", () => {
    // `::ffff:a00:1` is `10.0.0.1`; the dotted spelling of it already passes.
    const privatePayload = scanFixture("mapped-private", "mapped: ::ffff:a00:1/128\nnat64: 64:ff9b::/96\n");
    assert.equal(privatePayload.status, 0, privatePayload.stderr);

    // The same prefix carrying a public address — `4a7d:2b10` decodes into an ordinary routable
    // /8 that `allowedV4` does not list. The decode hands the octets over unchanged, so the mapped
    // spelling buys nothing. Spelled in dotted form here, this comment would fail the scan.
    const publicPayload = scanFixture("mapped-public", `mapped: ::ffff:${["4a7d", "2b10"].join(":")}/128\n`);
    assert.equal(publicPayload.status, 1, "a public address in mapped hex form must still fail");
    assert.match(publicPayload.stderr, /contains a non-documentation IPv6 address/);
  });

  it("allows RFC 9637 documentation space at /20 and not one bit wider", () => {
    const inside = scanFixture("doc-inside", "documentation: 3fff:1::/32 and 3fff::1\n");
    assert.equal(inside.status, 0, inside.stderr);

    // Second hextet above `0fff` is outside `3fff::/20` — unassigned global unicast, not documentation.
    const outside = scanFixture("doc-outside", `outside: 3fff:${["1", "234"].join("")}::/32\n`);
    assert.equal(outside.status, 1, "3fff::/16 must not be allowed — the reservation is /20");
    assert.match(outside.stderr, /contains a non-documentation IPv6 address/);
  });

  it("rejects binary credential containers instead of skipping their NUL bytes", () => {
    const repo = mkdtempSync(join(tmpdir(), "heliopause-history-binary-key-"));
    const git = (...args: string[]) => execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
    git("init", "-q", "-b", "main");
    git("config", "user.name", "security-test");
    git("config", "user.email", "security-test@example.invalid");
    writeFileSync(join(repo, "base.txt"), "clean\n");
    git("add", "base.txt"); git("commit", "-qm", "base");
    const base = git("rev-parse", "HEAD");
    writeFileSync(join(repo, "operator.p12"), Buffer.from([0, 1, 2, 3]));
    git("add", "operator.p12"); git("commit", "-qm", "binary credential");
    const head = git("rev-parse", "HEAD");

    const scanner = resolve(import.meta.dirname, "../scripts/scan-public-history.mjs");
    const refused = spawnSync(process.execPath, [scanner, "--base", base, "--head", head], { cwd: repo, encoding: "utf8" });
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /forbidden binary credential container/);
    assert.equal(refused.stderr.includes("operator.p12"), false);
  });

  it("rejects binary key extensions and never emits hostile candidate paths", () => {
    const repo = mkdtempSync(join(tmpdir(), "heliopause-history-path-"));
    const git = (...args: string[]) => execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
    git("init", "-q", "-b", "main");
    git("config", "user.name", "security-test");
    git("config", "user.email", "security-test@example.invalid");
    writeFileSync(join(repo, "base.txt"), "clean\n");
    git("add", "base.txt"); git("commit", "-qm", "base");
    const base = git("rev-parse", "HEAD");
    const workflowCommand = ["::", "error::"].join("");
    const hostile = `candidate\n${workflowCommand}injected\u001b[31m.der`;
    writeFileSync(join(repo, hostile), Buffer.from([0, 1, 2, 3]));
    git("add", hostile); git("commit", "-qm", "binary key");
    const head = git("rev-parse", "HEAD");

    const scanner = resolve(import.meta.dirname, "../scripts/scan-public-history.mjs");
    const refused = spawnSync(process.execPath, [scanner, "--base", base, "--head", head], { cwd: repo, encoding: "utf8" });
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /forbidden binary key material/);
    assert.equal(refused.stderr.includes(workflowCommand), false);
    assert.equal(refused.stderr.includes("\u001b"), false);
    assert.equal(refused.stderr.includes("candidate"), false);
  });

  it("does not let an unknown binary blob bypass content inspection", () => {
    const repo = mkdtempSync(join(tmpdir(), "heliopause-history-binary-"));
    const git = (...args: string[]) => execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
    git("init", "-q", "-b", "main");
    git("config", "user.name", "security-test");
    git("config", "user.email", "security-test@example.invalid");
    writeFileSync(join(repo, "base.txt"), "clean\n");
    git("add", "base.txt"); git("commit", "-qm", "base");
    const base = git("rev-parse", "HEAD");
    writeFileSync(join(repo, "opaque.bin"), Buffer.from([0, 1, 2, 3]));
    git("add", "opaque.bin"); git("commit", "-qm", "opaque binary");
    const head = git("rev-parse", "HEAD");

    const scanner = resolve(import.meta.dirname, "../scripts/scan-public-history.mjs");
    const refused = spawnSync(process.execPath, [scanner, "--base", base, "--head", head], { cwd: repo, encoding: "utf8" });
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /unreviewable binary blob/);
    assert.equal(refused.stderr.includes("opaque.bin"), false);
  });

  it("reads an object identifier as an OID and an address as an address", () => {
    // An ASN.1 OID is a dotted sequence of small integers, so it is a syntactically perfect IPv4
    // address. `OID 1.3.101.112` — Ed25519 — sat in a comment in `agent/heliopause-pull.py` and
    // failed this scan on every commit in range. **CI was red for two days on a constant**, while
    // the image built and shipped from the same workflow, which is how a check becomes something
    // people merge past.
    //
    // Both directions in one test on purpose. Skipping the OID is one line, and the same line
    // written slightly wider would let `OID` anywhere earlier in the file excuse a real address —
    // so the negative case is what makes the positive one worth having.
    const repo = mkdtempSync(join(tmpdir(), "heliopause-history-oid-"));
    const git = (...args: string[]) => execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
    git("init", "-q", "-b", "main");
    git("config", "user.name", "security-test");
    git("config", "user.email", "security-test@example.invalid");
    const fixture = join(repo, "fixture.txt");
    const scanner = resolve(import.meta.dirname, "../scripts/scan-public-history.mjs");
    const ed25519 = ["1.3", "101.112"].join(".");
    const address = ["8.8", "4.4"].join(".");

    writeFileSync(fixture, `Ed25519 SubjectPublicKeyInfo carries OID ${ed25519}.\n`);
    git("add", "fixture.txt");
    const allowed = spawnSync(process.execPath, [scanner, "--worktree"], { cwd: repo, encoding: "utf8" });
    assert.equal(allowed.status, 0, allowed.stderr);

    // The word has to be adjacent. A file that mentions OIDs somewhere must not thereby become a
    // place to keep addresses.
    writeFileSync(fixture, `OID ${ed25519} is Ed25519.\n\nThe resolver answers at ${address}.\n`);
    const refused = spawnSync(process.execPath, [scanner, "--worktree"], { cwd: repo, encoding: "utf8" });
    assert.equal(refused.status, 1, "an address later in a file that mentions an OID was excused");
    assert.match(refused.stderr, /contains a non-documentation IPv4 address/);
    assert.equal(refused.stderr.includes(address), false, "scanner output must redact the matched value");
  });

  it("reads a CSS pseudo-element as a name and a short IPv6 as an address", () => {
    // `dialog.modal::backdrop` matches as the IPv6 of its first three hex letters,
    // and Node's `isIP` reports 6 for that prefix. The same constant sat in
    // `RuleEditModal.svelte` and failed every commit in range — the IPv6 sibling
    // of the OID case above.
    const repo = mkdtempSync(join(tmpdir(), "heliopause-history-css-"));
    const git = (...args: string[]) => execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
    git("init", "-q", "-b", "main");
    git("config", "user.name", "security-test");
    git("config", "user.email", "security-test@example.invalid");
    const fixture = join(repo, "fixture.txt");
    const scanner = resolve(import.meta.dirname, "../scripts/scan-public-history.mjs");
    const address = [":", ":bac"].join("");

    writeFileSync(fixture, "dialog.modal::backdrop { background: transparent; }\n");
    git("add", "fixture.txt");
    const allowed = spawnSync(process.execPath, [scanner, "--worktree"], { cwd: repo, encoding: "utf8" });
    assert.equal(allowed.status, 0, allowed.stderr);

    writeFileSync(fixture, `The resolver answers at ${address}.\n`);
    const refused = spawnSync(process.execPath, [scanner, "--worktree"], { cwd: repo, encoding: "utf8" });
    assert.equal(refused.status, 1, "a short IPv6 that is also a CSS-ident prefix was excused");
    assert.match(refused.stderr, /contains a non-documentation IPv6 address/);
    assert.equal(refused.stderr.includes(address), false, "scanner output must redact the matched value");
  });

  it("keeps the authoritative PR scanner outside the candidate workflow", () => {
    const trusted = readFileSync(resolve(import.meta.dirname, "../.github/workflows/trusted-leaks.yml"), "utf8");
    const ordinary = readFileSync(resolve(import.meta.dirname, "../.github/workflows/ci.yml"), "utf8");
    assert.match(trusted, /^\s*pull_request_target:/m);
    assert.match(trusted, /working-directory: \.candidate/);
    assert.match(trusted, /node \"\$GITHUB_WORKSPACE\/\.trusted-scanner\/scripts\/scan-public-history\.mjs\"/);
    assert.match(trusted, /ref: \$\{\{ github\.event\.repository\.default_branch \}\}/);
    assert.match(trusted, /repository: \$\{\{ github\.repository \}\}[\s\S]*ref: refs\/pull\/\$\{\{ github\.event\.pull_request\.number \}\}\/head/);
    assert.match(trusted, /sparse-checkout: \.heliopause-no-candidate-files/);
    assert.doesNotMatch(trusted, /head\.repo\.full_name/);
    assert.match(trusted, /persist-credentials: false/g);
    assert.match(trusted, /^permissions:\n\s+contents: read$/m);
    assert.match(trusted, /HELIOPAUSE_SITE_HOSTNAME_PATTERN: \$\{\{ secrets\.HELIOPAUSE_SITE_HOSTNAME_PATTERN \}\}/);
    assert.doesNotMatch(ordinary, /secrets\.HELIOPAUSE_SITE_HOSTNAME_PATTERN/);
  });

  it("runs no job on a self-hosted runner", () => {
    // A public repository accepts pull requests from anyone, and `pull_request` runs the
    // candidate's code: `npm ci` executes its lifecycle scripts and `rollback-test.sh` starts a
    // container with `--pid=host --cap-add=NET_ADMIN`. On a hosted runner that is a capability over
    // an ephemeral VM thrown away when the job ends; on a machine of ours it is a container-escape
    // primitive next to the thing that builds the firewall control plane.
    //
    // This is asserted over the label rather than left to review because the two workflows drifted
    // apart once already: `ci.yml` routed forks away from the self-hosted runner while
    // `trusted-leaks.yml` — which fires on `pull_request_target`, so on **every** fork pull request
    // — still named it outright. One file's care did not cover the other, and nothing said so.
    const workflows = ["ci.yml", "trusted-leaks.yml"].map((name) =>
      [name, readFileSync(resolve(import.meta.dirname, "../.github/workflows", name), "utf8")] as const);
    for (const [name, text] of workflows) {
      const labels = [...text.matchAll(/^\s*runs-on:\s*(.+)$/gm)].map((match) => (match[1] ?? "").trim());
      assert.ok(labels.length > 0, `${name} declares no runs-on — the fixture stopped matching`);
      assert.deepEqual(labels.filter((label) => label !== "ubuntu-latest"), [],
        `${name} schedules a job somewhere other than a GitHub-hosted runner`);
    }
  });

  it("keeps every tracked file inspectable — no raw NUL in this repository", () => {
    // The scanner refuses any blob containing a NUL, because it cannot prove an uninspectable blob
    // carries no site data. That policy is right, and it means a single raw NUL in a source file
    // turns the publish gate red for a file with nothing wrong in it — which is what
    // `src/ruleset-diff.ts` did in `8fdae68`, using the byte itself as a string separator instead
    // of the `\u0000` escape.
    //
    // The scanner's own `--worktree` mode would catch this, but only where someone runs it; the
    // repository learned about it from a red CI job two commits later. This is the same check
    // stated over the tracked tree, so `npm test` says it on the machine where the mistake is made.
    const root = resolve(import.meta.dirname, "..");
    const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: root, maxBuffer: 64 * 1024 * 1024 })
      .toString("utf8").split("\0").filter(Boolean);
    assert.ok(tracked.length > 100, "fixture must actually enumerate the repository");
    const binary = tracked.filter((path) => readFileSync(join(root, path)).includes(0));
    assert.deepEqual(binary, [], "a tracked file holds a raw NUL and the leak scanner will refuse it");
  });
});

// ── Accepting a finding in history ────────────────────────────────────────────
//
// History is immutable, so a false positive in a merged commit made `--all` fail for ever — and
// every scheduled run of `trusted-leaks.yml` did exactly that, on three files whose literals had
// already been rewritten in the tree. The pull-request gate reads only introduced commits, so it
// stayed green and the permanent failure was invisible from where anyone was looking.
//
// The allowlist is the fix. These pin the three properties that keep it from becoming a way to ship
// the thing the scan exists to catch.
describe("the scanner's history allowlist", () => {
  /** A repo whose middle commit introduces a public address, then removes it. */
  const repoWithLeakInHistory = () => {
    const repo = mkdtempSync(join(tmpdir(), "heliopause-scanignore-"));
    const git = (...args: string[]) => execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
    git("init", "-q", "-b", "main");
    git("config", "user.name", "security-test");
    git("config", "user.email", "security-test@example.invalid");
    writeFileSync(join(repo, "fixture.txt"), "documentation address: 192.0.2.1\n");
    git("add", "fixture.txt"); git("commit", "-qm", "base");
    const base = git("rev-parse", "HEAD");
    // Assembled rather than written, for the reason the scanner's own comments give: a file that
    // names a forbidden address makes the scan refuse the file.
    writeFileSync(join(repo, "fixture.txt"), `accidental address: ${["8.8", "8.8"].join(".")}\n`);
    git("commit", "-qam", "introduce");
    const blob = git("rev-parse", "HEAD:fixture.txt");
    writeFileSync(join(repo, "fixture.txt"), "documentation address: 198.51.100.4\n");
    git("commit", "-qam", "remove");
    return { repo, base, head: git("rev-parse", "HEAD"), blob };
  };

  const scanner = () => resolve(import.meta.dirname, "../scripts/scan-public-history.mjs");
  const run = (repo: string, ...args: string[]) =>
    spawnSync(process.execPath, [scanner(), ...args], { cwd: repo, encoding: "utf8" });

  const IPV4 = "contains a non-documentation IPv4 address";

  it("accepts a finding by blob, and says how many it accepted", () => {
    const { repo, base, head, blob } = repoWithLeakInHistory();
    assert.equal(run(repo, "--base", base, "--head", head).status, 1, "fixture must fail without the allowlist");

    writeFileSync(join(repo, ".heliopause-scanignore"), `# a known-safe example\n${blob}:${IPV4}\n`);
    const accepted = run(repo, "--base", base, "--head", head);
    assert.equal(accepted.status, 0);
    assert.match(accepted.stdout, /1 accepted by \.heliopause-scanignore/);
  });

  // The entry names one blob and one class. Neither may be a wildcard by accident: an entry that
  // silenced a *different* finding would be the worst possible failure of this file.
  it("accepts only the blob and the class it names", () => {
    const { repo, base, head, blob } = repoWithLeakInHistory();

    writeFileSync(join(repo, ".heliopause-scanignore"), `${blob}:contains a non-documentation IPv6 address\n`);
    assert.equal(run(repo, "--base", base, "--head", head).status, 1, "a different finding class must still refuse");

    const otherBlob = "0".repeat(40);
    writeFileSync(join(repo, ".heliopause-scanignore"), `${otherBlob}:${IPV4}\n`);
    assert.equal(run(repo, "--base", base, "--head", head).status, 1, "a different blob must still refuse");
  });

  // 🔴 The worktree is the one place a finding must never be suppressible: the file is in front of
  // you and the fix is to change it. An allowlist entry there would be a way to commit the thing.
  it("does not suppress a worktree finding, even for the same content", () => {
    const { repo, blob } = repoWithLeakInHistory();
    writeFileSync(join(repo, "fixture.txt"), `accidental address: ${["8.8", "8.8"].join(".")}\n`);
    writeFileSync(join(repo, ".heliopause-scanignore"), `${blob}:${IPV4}\n`);
    const r = run(repo, "--worktree");
    assert.equal(r.status, 1, "worktree findings are not suppressible");
    assert.match(r.stderr, /contains a non-documentation IPv4 address/);
  });

  // An exception nobody can trace stops being an exception and becomes folklore. `--all` walks
  // every reachable object, so there an entry that matched nothing is provably dead.
  it("fails on a stale entry under --all, and stays quiet about it on a range scan", () => {
    const { repo, base, head } = repoWithLeakInHistory();
    const stale = `${"1".repeat(40)}:${IPV4}\n`;
    writeFileSync(join(repo, ".heliopause-scanignore"), stale);

    const all = run(repo, "--all");
    assert.equal(all.status, 1);
    assert.match(all.stderr, /matched nothing in full history — remove it/);

    // A range scan sees a slice and cannot tell stale from not-yet-reached, so it must not guess.
    const ranged = run(repo, "--base", base, "--head", head);
    assert.equal(ranged.stderr.includes("matched nothing"), false);
  });

  // 🔴 **The trust boundary.** `trusted-leaks.yml` runs the scanner with the *candidate's* checkout
  // as the working directory — that is the whole design: inert candidate objects, trusted code. If
  // the allowlist came from there, a pull request could ship a leak and accept it in the same
  // commit, and every other precaution in that workflow would still be intact and useless.
  //
  // So the workflow passes `--ignore-file` pointing into `.trusted-scanner`, and these pin both
  // halves: the flag is honoured, and it is honoured *instead of* the working directory's file.
  it("reads the allowlist from --ignore-file, not from the scanned tree", () => {
    const { repo, base, head, blob } = repoWithLeakInHistory();
    const elsewhere = mkdtempSync(join(tmpdir(), "heliopause-trusted-"));
    const trusted = join(elsewhere, ".heliopause-scanignore");

    writeFileSync(trusted, `${blob}:${IPV4}\n`);
    const withFlag = run(repo, "--base", base, "--head", head, "--ignore-file", trusted);
    assert.equal(withFlag.status, 0, "the named file must be read");

    // And the candidate's own file must not be. Written as an entry that *would* suppress the
    // finding if it were honoured — so this fails loudly if the precedence ever inverts.
    writeFileSync(join(repo, ".heliopause-scanignore"), `${blob}:${IPV4}\n`);
    writeFileSync(trusted, "# the trusted copy accepts nothing\n");
    const candidateTried = run(repo, "--base", base, "--head", head, "--ignore-file", trusted);
    assert.equal(candidateTried.status, 1, "a candidate must not be able to accept its own finding");
  });

  it("is wired into the trusted workflow, which does not run in the trusted tree", () => {
    // The scanner defaults to the working directory, and in `trusted-leaks.yml` that is the
    // candidate. A default is the wrong thing there, and the mistake would be silent — ENOENT is
    // indistinguishable from an empty allowlist. Read the workflow and require the flag.
    const workflow = readFileSync(
      resolve(import.meta.dirname, "../.github/workflows/trusted-leaks.yml"),
      "utf8",
    );
    const invocations = [...workflow.matchAll(/node "\$GITHUB_WORKSPACE\/\.trusted-scanner\S*scan-public-history\.mjs"/g)]
      // The arguments continue on the following lines of a `run: >-` block; a bounded window after
      // the invocation is enough to see them without parsing YAML.
      .map((m) => workflow.slice(m.index ?? 0, (m.index ?? 0) + 400));
    assert.equal(invocations.length, 2, "expected the pull-request scan and the scheduled scan");
    for (const call of invocations) {
      assert.match(call, /--ignore-file "\$GITHUB_WORKSPACE\/\.trusted-scanner\//);
    }
    // …and the trusted checkout has to actually contain it, or the flag names a missing file and
    // the scan silently accepts nothing.
    assert.match(workflow, /sparse-checkout: \|[\s\S]*?\.heliopause-scanignore/);
  });

  it("refuses a malformed allowlist rather than treating it as empty", () => {
    const { repo, base, head } = repoWithLeakInHistory();
    writeFileSync(join(repo, ".heliopause-scanignore"), "not-a-blob:some class\n");
    const r = run(repo, "--base", base, "--head", head);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /expected "<blob-sha>:<finding class>"/);
  });
});
