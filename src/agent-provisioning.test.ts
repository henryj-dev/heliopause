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

  it("documents every namespace list the agent reads, so a provisioner can set them", () => {
    // The failure this closes, measured 2026-09-03: `HELIOPAUSE_K8S_PEER_NAMESPACES` was added to
    // the agent and to the renderer and **not to this file**. stardust renders `agent.env` from
    // exactly this example, so a variable absent here is one their provisioning cannot set — and
    // the first policy naming a peer outside the writable list would have had the agent refuse the
    // *whole* workload document, taking the existing CNPs down with the new ones.
    //
    // Optional settings are commented out in the example, so the match allows the `#` — what is
    // being checked is that the name and a usable value are written down, not that they are active.
    const example = read("../packaging/systemd/agent.env.example");
    const agent = read("../agent/heliopause-pull.py");
    const read_by_agent = [...agent.matchAll(/os\.environ\.get\("(HELIOPAUSE_K8S_[A-Z_]*NAMESPACES)"/g)]
      .map((m) => m[1]!);
    assert.ok(read_by_agent.length >= 2, `expected both namespace lists, found ${read_by_agent.join(", ")}`);
    for (const name of new Set(read_by_agent)) {
      assert.match(example, new RegExp(`^#?${name}=.+$`, "m"), `${name} is not documented in agent.env.example`);
    }
  });

  it("gives a peer namespace a grant that cannot close its pods", () => {
    // The two lists are two privileges, and the example an operator copies has to keep them apart.
    // `kube-system` is the peer namespace that matters — binding the applier ClusterRole there would
    // let this agent create the CiliumNetworkPolicy that puts CoreDNS into ingress default-deny.
    const podreader = read("../packaging/kubernetes/heliopause-agent-podreader.example.yaml");
    // Comments stripped first. The header deliberately *names* `ciliumnetworkpolicies` — in the
    // `kubectl auth can-i … # no` line that proves the boundary — so a whole-file search would fail
    // on the very sentence that documents the property being checked.
    const manifest = podreader.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
    assert.match(manifest, /resources: \["pods"\]/);
    assert.equal(/ciliumnetworkpolicies/.test(manifest), false, "the pod-reader example grants CNP verbs");
    // A Role, not a ClusterRole, and bound by name to itself — not to the applier role next door.
    assert.match(manifest, /kind: Role\n\s+name: heliopause-agent-podreader/);
    assert.equal(/name: heliopause-workload-applier/.test(manifest), false);
    // And the README has to send the reader there, or the file is one nobody copies.
    assert.match(read("../packaging/systemd/README.md"), /heliopause-agent-podreader\.example\.yaml/);
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

  it("creates its own /etc/heliopause/pki so a never-touched host does not die 226/NAMESPACE", () => {
    // The script makedirs() the pki dir, but that is unreachable under ProtectSystem=strict: a
    // directory named in ReadWritePaths is bind-mounted at namespace setup and must already exist,
    // and a fresh host has no /etc/heliopause/pki — so the unit failed at step NAMESPACE before the
    // script ran (measured on the first saga onboarding, web-01, 2026-08-28). ConfigurationDirectory
    // creates it before the sandbox and makes it writable; a bare ReadWritePaths entry cannot.
    const unit = read("../packaging/systemd/heliopause-enroll.service");
    assert.match(
      unit,
      /^ConfigurationDirectory=heliopause\/pki$/m,
      "the unit must create /etc/heliopause/pki itself (ConfigurationDirectory), not require it to pre-exist",
    );
    assert.doesNotMatch(
      unit,
      /^ReadWritePaths=[^\n]*\/etc\/heliopause\/pki/m,
      "/etc/heliopause/pki as a bare ReadWritePaths requires it to pre-exist and 226s a never-touched host",
    );
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
