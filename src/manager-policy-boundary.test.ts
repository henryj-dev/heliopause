// C1: the manager renders the policy and never runs it.
//
// ## What the finding was
//
// The manager imported the site module — `await import(pathToFileURL(sitePath))` — to render the
// policy screen, and `GET /policy` was reachable by any read-tier operator. A TypeScript module's
// top level is code, so a commit to the policy repository was arbitrary execution inside the
// manager process: the process that holds the artifact signing key, the GitHub App key, the OIDC
// secret and the relay credentials, running inside the cluster whose firewall it governs. The
// git-sync sidecar meant no operator action was needed to land the commit either.
//
// ## Why this file was rewritten
//
// The first remediation deleted the screen, and this test pinned the deletion. It passed. The
// console was gone for two weeks and the operator found out by opening it and getting a 404.
//
// The old fourth case even stated the trap and then walked into it: "a test that only asserted the
// removal would pass just as well if the capability had been dropped entirely" — so it checked the
// capability still existed *somewhere*, on the operator's workstation. Existing somewhere is not the
// requirement. The requirement is that the console at the manager's own address can read, edit and
// propose policy, and no assertion here was about that.
//
// So this file now pins **both** halves, and the second half is the one that regressed:
//
//   - the manager holds no policy checkout and evaluates nothing (the finding), and
//   - the routes that make it a console are served (the requirement).
//
// A change that satisfies only the first is the outage this file exists to prevent. `/policy/edit`
// and `/policy/propose` never had the flaw in the first place — committing a file through the GitHub
// App and opening a pull request are data operations — and were removed as collateral.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const read = (relative: string) => readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf8");

/**
 * Comments describe this boundary at length; stripping them keeps the check about code.
 *
 * Not decoration. An earlier version of a source-level test in this repository passed after the call
 * it guarded was deleted, because the function's name survived in a comment two lines above.
 *
 * ⚠ **Line comments go first, and the order is load-bearing.** Block-stripping first lets a `*\/`
 * written inside a line comment close some earlier `/*`, and the non-greedy match then deletes
 * everything between them. That happened on 2026-08-16: a line comment mentioning the wildcard
 * `Accept` header ate **sixteen thousand characters of real source** — 56,619 down to 40,725 — and
 * five tests reported that the manager no longer served `/policy`, `/policy/edit` or
 * `/policy/propose`. Nothing was wrong with the manager. The check had destroyed its own input and
 * described the wreckage confidently.
 *
 * Stripping lines first makes that particular landmine harmless, because the offending text is gone
 * before the block pass runs. It does not make this a parser: a `*\/` inside a *string literal* would
 * still close an earlier block comment. If these assertions ever fail in a way that makes no sense,
 * compare `code(source).length` against `source.length` before believing them.
 */
const code = (source: string) =>
  source
    .split("\n")
    .filter((line) => !/^\s*\/\//.test(line))
    .join("\n")
    .replace(/\/\*[\s\S]*?\*\//g, "");

describe("the manager's policy boundary — it does not evaluate", () => {
  it("contains no dynamic import at all", () => {
    // Not "no import of the site module" — any dynamic import is a place a path could be threaded
    // back in, and the manager has no legitimate need for one. Static imports are unaffected: they
    // are resolved from this repository at load time and cannot be pointed at a policy checkout.
    const source = code(read("./manager-server.ts"));
    const found = [...source.matchAll(/(^|[^.\w])import\s*\(/g)].map((m) => m.index);
    assert.deepEqual(found, [], "manager-server.ts regained a dynamic import");
  });

  it("takes no path to a policy checkout in its options", () => {
    // The import needs somewhere to point. `policySource.url` is deliberately a URL: there is no
    // filename in this interface for a future author to reach for, which is the difference between
    // a rule and a habit.
    const source = code(read("./manager-server.ts"));
    const options = /export interface ManagerOptions \{[\s\S]*?\n\}/.exec(source);
    assert.ok(options, "could not find ManagerOptions");
    assert.ok(
      !/sitePath|policySite|policyDir|policyPath/.test(options[0]),
      "ManagerOptions names a policy path again — it may only be given a URL",
    );
  });

  it("does not import the half of the contract that touches the disk", () => {
    // `policy-source.ts` has both sides in it so they cannot drift apart, and only one belongs here.
    // `collectPolicySource` reads files and shells out to git; a manager that imported it would be
    // one line from having a checkout again.
    const source = code(read("./manager-server.ts"));
    assert.ok(
      !/collectPolicySource/.test(source),
      "manager-server.ts imports collectPolicySource — that side runs where the checkout is",
    );
  });

  it("never asks the renderer for anything but the rendered policy", () => {
    // The connection to `heliopause-policy-render` is the one place untrusted output enters this
    // process. It is one GET, and the response is parsed by `parsePolicySource` rather than used
    // directly — a `JSON.parse` whose result went straight into `buildScreen` would be the same
    // trust boundary with the check taken out.
    const source = code(read("./manager-server.ts"));
    assert.match(source, /parsePolicySource/, "the manager stopped validating the renderer's answer");
  });
});

describe("the manager's policy boundary — it is still the console", () => {
  // This half is the regression, not the finding. Every assertion here failed for two weeks while
  // every assertion above passed.
  const source = code(read("./manager-server.ts"));

  for (const route of ["/policy", "/policy/edit", "/policy/propose"]) {
    it(`serves ${route}`, () => {
      assert.ok(
        source.includes(`"${route}"`),
        `manager-server.ts no longer serves ${route} — the console cannot ${
          route === "/policy" ? "be read" : route.endsWith("edit") ? "save" : "open a review"
        }`,
      );
    });
  }

  it("renders the page rather than answering with data", () => {
    // `/policy` returning JSON would pass a route check and still be useless in a browser, which is
    // the failure mode this whole file keeps rediscovering: the assertion held and the thing the
    // operator needed did not. The manager used to call `policyPage(` here. The Svelte console is
    // the page now: GET `/policy` 302s through `policyAppPath` so a bookmark still opens a screen.
    assert.match(
      source,
      /pathname === "\/policy"[\s\S]*?policyAppPath\(/,
      "the manager no longer sends /policy to a rendered page",
    );
  });

  it("offers the editor only to a caller who may write", () => {
    assert.match(
      source,
      /opts\.policyWrite && mayWrite/,
      "the editor is no longer gated on write permission",
    );
  });

  it("still exists on the operator's own machine too", () => {
    // Unchanged, and still worth pinning — the workstation path is what works when the cluster does
    // not, which is the same reason every other path out of an incident bypasses the manager.
    const ui = code(read("../bin/heliopause-ui.ts"));
    assert.match(ui, /buildScreen/, "the local UI no longer builds the policy screen");
    assert.match(ui, /"\/api\/propose"/, "the local UI no longer offers the propose flow");
    assert.match(ui, /workstationAppPath/, "the local UI no longer sends a browser to /app when the console is built");
  });
});

describe("the evaluation happens somewhere, and only there", () => {
  // That the renderer refuses to start while holding a credential is checked by *starting it*, in
  // `policy-render-service.test.ts`. It was checked here first, as `assert.match(source,
  // /refuseIfArmed\(\)/)`, and deleting the call did not fail it: the regex matched the
  // `function refuseIfArmed(): void` declaration. A source-level test of a guard passes on a
  // program that never runs the guard.
  //
  // What is left here is the shape a grep can actually see.
  it("keeps the one import of untrusted code in an entry point", () => {
    // Visible in a file somebody opens on purpose, rather than in a library where a future caller
    // could reach it without noticing what they were doing.
    const renderer = code(read("../bin/heliopause-policy-render.ts"));
    assert.match(renderer, /await import\(/, "the renderer stopped evaluating the site module");
  });

  it("does not let the contract module import a policy path of its own", () => {
    // `policy-source.ts` is imported by both sides. If it grew its own `import()` the manager would
    // inherit the ability to evaluate a policy by calling a function that looks like a parser.
    const contract = code(read("./policy-source.ts"));
    const found = [...contract.matchAll(/(^|[^.\w])import\s*\(/g)].map((m) => m.index);
    assert.deepEqual(found, [], "policy-source.ts gained a dynamic import");
  });
});
