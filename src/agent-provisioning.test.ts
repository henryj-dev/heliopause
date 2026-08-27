// What an operator has to put in `agent.env` for the agent to start at all.
//
// ## The failure this is written against
//
// The signed-artifact path added three required settings — the target pin and the two trust rings —
// and for a while nothing outside the agent's own docstring said so. The startup guard did not check
// them and the packaging did not mention them, which combines badly in one specific way: unset, the
// agent authenticates, heartbeats, and reports healthy while refusing **every** generation, because
// the target comparison cannot match and the trust ring cannot load. It fails closed, and the error
// names the artifact — so a missing line in a unit file reads as a bad generation, during a rollout,
// on the host that was supposed to apply it.
//
// The guard now refuses to start instead. This test is the other half: it reads the list out of the
// agent and asserts the example file an operator copies actually contains every name on it. A guard
// nobody can satisfy from the documentation is a service that will not come up.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const read = (relative: string) => readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf8");

/**
 * The names `main()` refuses to start without, taken from the agent rather than restated here.
 *
 * Restating them would make this a test of its own fixture: someone adding a fourth required
 * setting would leave the packaging silent and this test green, which is the exact shape of the
 * problem it exists to catch.
 */
function requiredEnvNames(): string[] {
  const agent = read("../agent/heliopause-pull.py");
  // Anchored inside `main()`. An unanchored search for `missing = [` finds the rule-comparison list
  // in the apply path first — it parsed to zero names and the test failed for a reason that had
  // nothing to do with the guard.
  const main = agent.slice(agent.indexOf("\ndef main():"));
  assert.ok(main.length > 0, "could not find main() in heliopause-pull.py");
  const guard = /missing = \[[\s\S]*?\n    \]/.exec(main);
  assert.ok(guard, "could not find the required-environment guard in main()");
  const names = [...guard[0].matchAll(/\("(HELIOPAUSE_[A-Z0-9_]+)",/g)].map((m) => m[1]!);
  assert.ok(names.length >= 4, `the guard parsed to ${names.length} names, which cannot be right`);
  return names;
}

describe("the agent's required configuration is documented where it is copied from", () => {
  it("names every required setting in agent.env.example", () => {
    const example = read("../packaging/systemd/agent.env.example");
    const missing = requiredEnvNames().filter((name) => !new RegExp(`^${name}=`, "m").test(example));
    assert.deepEqual(missing, [], `agent.env.example does not set: ${missing.join(", ")}`);
  });

  it("still refuses to start without them — the list is not decoration", () => {
    // The known positive for the parse above. If the guard were deleted the regex would find
    // nothing and `requiredEnvNames` would throw, but a guard that had been reduced to a comment
    // would still parse; this pins the three the signing path needs.
    const names = requiredEnvNames();
    for (const name of ["HELIOPAUSE_TARGET", "HELIOPAUSE_MANAGER_SIGNING_KEYS_DIR", "HELIOPAUSE_BREAK_GLASS_KEYS_DIR"]) {
      assert.ok(names.includes(name), `${name} is no longer required at startup`);
    }
  });

  it("starts the agent from the certificate path the agent is configured to read", () => {
    // `heliopause-agent.path` watches one file and the agent reads one file, and nothing but this
    // test says they are the same file. If the example moved the certificate — or the unit did —
    // an enrolled host would sit with a valid certificate and an agent that never starts, which is
    // the exact silence the path unit exists to remove.
    const unit = read("../packaging/systemd/heliopause-agent.path");
    const watched = /^PathExists=(.+)$/m.exec(unit)?.[1];
    const example = read("../packaging/systemd/agent.env.example");
    const configured = /^HELIOPAUSE_CERT_FILE=(.+)$/m.exec(example)?.[1];
    assert.ok(watched && configured, "could not find the watched path or the configured certificate path");
    assert.equal(watched, configured);
    assert.match(unit, /^Unit=heliopause-agent\.service$/m);
    // The README is what an installer copies from; a unit nobody is told to install is not installed.
    assert.match(read("../packaging/systemd/README.md"), /enable --now heliopause-agent\.path/);
  });

  it("keeps the enrollment token where the enrollment unit is allowed to delete it", () => {
    // Three places name the token file — the script's default, the example the operator copies, and
    // the unit's ConditionPathExists — and the unit is ProtectSystem=strict, so a fourth thing has to
    // hold: the path must sit under one of the unit's ReadWritePaths, or the spent token can never be
    // removed and the timer never reaches its no-op end state. It sat outside for a month
    // (/etc/heliopause/enroll-token) and nothing here said so; stardust read it off the unit file.
    const script = read("../agent/heliopause-enroll.py");
    const scriptDefault = /HELIOPAUSE_ENROLL_TOKEN_FILE",\s*"([^"]+)"\)/.exec(script)?.[1];
    const example = read("../packaging/systemd/agent.env.example");
    const exampleValue = /^#?HELIOPAUSE_ENROLL_TOKEN_FILE=(.+)$/m.exec(example)?.[1];
    const unit = read("../packaging/systemd/heliopause-enroll.service");
    const condition = /^ConditionPathExists=(.+)$/m.exec(unit)?.[1];
    assert.ok(scriptDefault && exampleValue && condition, "could not find all three copies of the token path");
    assert.equal(exampleValue, scriptDefault);
    assert.equal(condition, scriptDefault);
    const writable = (/^ReadWritePaths=(.+)$/m.exec(unit)?.[1] ?? "").split(/\s+/).filter(Boolean);
    assert.ok(writable.length > 0, "the enrollment unit declares no ReadWritePaths");
    assert.ok(
      writable.some((dir) => scriptDefault.startsWith(dir.endsWith("/") ? dir : `${dir}/`)),
      `${scriptDefault} is outside the unit's ReadWritePaths (${writable.join(" ")}) — the spent token could not be unlinked`,
    );
    assert.match(unit, /^ProtectSystem=strict$/m, "the invariant above only matters under ProtectSystem=strict; if that changed, revisit this test");
  });

  it("documents every setting the manager cannot start without", () => {
    // The same gap, one process over. `env(name)` with no fallback exits 2 when unset, and the
    // signing path added one of those — a manager that would not come up after the image rolled
    // out, with nothing in the file an operator copies to say why.
    //
    // Only the unconditional calls count. Most of the manager's settings sit inside a spread that
    // is skipped unless that feature is configured (OIDC, OTP, cert-api), and requiring those to be
    // documented would be requiring every optional feature to be enabled. The heuristic is
    // indentation: a top-level statement is read on every start.
    const manager = read("../bin/heliopause-manager.ts");
    const required = manager
      .split("\n")
      .filter((line) => line.length - line.trimStart().length <= 2)
      .flatMap((line) => [...line.matchAll(/env\("(HELIOPAUSE_[A-Z0-9_]+)"\)/g)].map((m) => m[1]!));
    assert.ok(required.length >= 2, `parsed ${required.length} unconditional settings, which cannot be right`);
    const example = read("../packaging/manager.env.example");
    const missing = required.filter((name) => !new RegExp(`^${name}=`, "m").test(example));
    assert.deepEqual(missing, [], `manager.env.example does not set: ${missing.join(", ")}`);
  });

  it("exposes the trust directory to the unit read-only", () => {
    // `ProtectSystem=strict` already makes /etc read-only, so this is not the thing preventing a
    // write. It is the declaration that the agent depends on that path, in the file that would
    // otherwise be the only place not to mention it.
    assert.match(read("../packaging/systemd/heliopause-agent.service"), /^ReadOnlyPaths=\/etc\/heliopause\/trust$/m);
  });

  it("points both rings at that directory rather than somewhere the unit does not grant", () => {
    // Two files agreeing by coincidence is the normal state of a unit and its env file; this makes
    // the agreement checked. A ring configured outside the granted path would load in testing, where
    // the sandbox is absent, and fail only under systemd.
    const example = read("../packaging/systemd/agent.env.example");
    for (const name of ["HELIOPAUSE_MANAGER_SIGNING_KEYS_DIR", "HELIOPAUSE_BREAK_GLASS_KEYS_DIR"]) {
      const line = new RegExp(`^${name}=(.+)$`, "m").exec(example);
      assert.ok(line, `${name} is not set in agent.env.example`);
      assert.ok(
        line[1]!.startsWith("/etc/heliopause/trust/"),
        `${name} points at ${line[1]} which the unit does not expose`,
      );
    }
  });
});
