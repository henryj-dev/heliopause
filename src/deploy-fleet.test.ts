// The relay ships as source that `deploy-fleet.sh` rsyncs onto a gateway, not as a bundle. So the
// list of paths that script copies must cover everything the running relay imports — and the trap is
// the imports that leave the repo's own `src`/`bin` for a workspace package.
//
// ## Why this exists
//
// `src/i18n.ts` imports `../packages/i18n/src/index.ts` by relative path. `deploy-fleet.sh relay`
// used to ship `bin src` only, so on the host `/opt/heliopause/packages/i18n/src/index.ts` did not
// exist and the relay died with `ERR_MODULE_NOT_FOUND` before it could serve a single artifact.
// Measured 2026-08-27, on the first attempt to roll a schema-4 relay onto the live fleet — the code
// had gained the shared-package import after the previous relay deploy, and the ship list did not
// follow it. Nothing failed in CI because the script is not exercised there; the fleet was the test.
//
// This pins the invariant so the next such import is caught here instead of on a gateway: every
// `packages/<x>` a non-test `src` file imports must be in the relay's ship list.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const at = (relative: string) => fileURLToPath(new URL(relative, import.meta.url));
const read = (relative: string) => readFileSync(at(relative), "utf8");

/** The `packages/<name>` directories that non-test files under `src/` import, by relative path. */
function packagesImportedBySrc(): Set<string> {
  const out = new Set<string>();
  const dir = at("./");
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".ts") || name.endsWith(".test.ts")) continue;
    const source = readFileSync(`${dir}${name}`, "utf8");
    // `from "../packages/i18n/src/index.ts"` and any depth of `../` before it.
    for (const m of source.matchAll(/from\s+"(?:\.\.\/)+packages\/([a-z0-9-]+)\//g)) {
      out.add(`packages/${m[1]!}`);
    }
  }
  return out;
}

/** The whitespace-separated ship list for a `deploy-fleet.sh` target (`relay` or `agent`). */
function shipPaths(what: "relay" | "agent"): string[] {
  const script = read("../scripts/deploy-fleet.sh");
  const line = new RegExp(`${what}\\)\\s+unit=\\S+;\\s+paths="([^"]+)"`).exec(script);
  assert.ok(line, `could not find the ${what} ship list in deploy-fleet.sh`);
  return line[1]!.trim().split(/\s+/).filter(Boolean);
}

describe("deploy-fleet.sh ships every source the relay imports", () => {
  it("covers each packages/<x> that src imports by relative path", () => {
    const needed = packagesImportedBySrc();
    // The known positive: if this ever parses to nothing, the regex above has drifted and the test
    // is asserting against an empty set — which would pass while guarding nothing.
    assert.ok(needed.size >= 1, "expected src to import at least one workspace package (i18n)");
    assert.ok(needed.has("packages/i18n"), "src/i18n.ts's import of packages/i18n went missing");

    const relay = new Set(shipPaths("relay"));
    const missing = [...needed].filter((p) => !relay.has(p));
    assert.deepEqual(
      missing,
      [],
      `deploy-fleet.sh relay does not ship ${missing.join(", ")} — the relay imports it and will ` +
        `ERR_MODULE_NOT_FOUND on the host. Add it to the relay paths.`,
    );
  });

  it("handles a path shipped for the first time (backup skip, parent made)", () => {
    // The relay ship list now carries `packages/i18n`, a path that is not on a host until the first
    // schema-4 deploy. The deploy must not `cp` a backup source that is not there (`set -e` aborts),
    // and rsync into `.../packages/i18n/` needs the parent `packages/` made first — it creates the
    // leaf, not the tree. Both were measured on gw-01.util 2026-08-27; this pins the guards.
    // `[^"]*` rather than the exact `$p`: this test owns the filesystem guard; the separate heredoc
    // test below owns which shell expands that variable.
    const script = read("../scripts/deploy-fleet.sh");
    assert.match(script, /if \[ -e "\/opt\/heliopause\/[^"]*" \]; then sudo cp -a/,
      "the backup must skip a path that does not exist yet, or the first deploy of a new path aborts");
    assert.match(script, /sudo mkdir -p "\/opt\/heliopause\/[^"]*"; sudo rsync/,
      "rsync must have its parent directory made first, or a new nested path fails");
  });

  it("does not expand the remote script in the operator's shell", () => {
    const script = read("../scripts/deploy-fleet.sh");
    assert.match(
      script,
      /printf -v remote_env 'HELIOPAUSE_DEPLOY_PATHS=%q HELIOPAUSE_DEPLOY_STAMP=%q HELIOPAUSE_DEPLOY_UNIT=%q' \\\n\s+"\$paths" "\$stamp" "\$unit"\n\s+ssh [^\n]+ "\$remote_env bash -s" <<'EOS'\nset -euo pipefail\npaths="\$HELIOPAUSE_DEPLOY_PATHS"\nstamp="\$HELIOPAUSE_DEPLOY_STAMP"\nunit="\$HELIOPAUSE_DEPLOY_UNIT"/,
      "the active SSH heredoc must receive and consume all three explicitly quoted values",
    );
  });

  it("still ships the repo's own bin and src", () => {
    // Not decoration: the packages line is additive, and a careless edit that replaced rather than
    // extended the list would strip the relay's own code and pass the check above.
    const relay = new Set(shipPaths("relay"));
    assert.ok(relay.has("bin") && relay.has("src"), "the relay must ship its own bin and src");
  });
});

/** Host names from the `HOSTS` block, in file order. */
function fleetHosts(): string[] {
  const script = read("../scripts/deploy-fleet.sh");
  const block = /\nHOSTS="\n([\s\S]*?)\n"\n/.exec(script);
  assert.ok(block, "could not find the HOSTS block in deploy-fleet.sh");
  return block[1]!.split("\n").map((l) => l.split("=")[0]!.trim()).filter(Boolean);
}

/** The names listed in a `--all` order variable. */
function order(name: "RELAY_ORDER" | "AGENT_ORDER"): string[] {
  const script = read("../scripts/deploy-fleet.sh");
  const line = new RegExp(`\\n${name}="([^"]+)"`).exec(script);
  assert.ok(line, `could not find ${name} in deploy-fleet.sh`);
  return line[1]!.trim().split(/\s+/).filter(Boolean);
}

// ## Why these exist
//
// `--all` walks a list written by hand, and a host that is in the fleet but not in that list is
// skipped in silence — the deploy reports success having never touched it. That is the same shape as
// the defect this file already pins for ship paths: not a wrong answer, a missing one.
//
// It has happened. `web-01.dev` joined the fleet and `HOSTS` did not follow, so the script could not
// address it at all and its agent was rolled by hand instead — which is how it ended up on a build
// nothing else was running.
describe("deploy-fleet.sh --all reaches the whole fleet", () => {
  it("names every known host in the agent order", () => {
    const hosts = fleetHosts();
    assert.ok(hosts.length >= 8, `HOSTS parsed to ${hosts.length} entries — the block shape drifted`);
    const listed = new Set(order("AGENT_ORDER"));
    for (const host of hosts) {
      assert.ok(listed.has(host), `${host} is in HOSTS but not in AGENT_ORDER — --all would skip it`);
    }
  });

  it("names only known hosts, in both orders", () => {
    const hosts = new Set(fleetHosts());
    for (const name of [...order("AGENT_ORDER"), ...order("RELAY_ORDER")]) {
      assert.ok(hosts.has(name), `${name} is in a --all order but not in HOSTS`);
    }
  });

  it("names hosts by the id the fleet view prints, and every relay host has a relay", () => {
    // The relay's `/status` and the console name hosts `gw-01.dev-icn-vtr`; a script that says
    // `gw-01.dev` cannot be matched to a row without translating, and that drift stood for two months.
    for (const host of fleetHosts()) {
      assert.match(host, /^[a-z0-9-]+\.[a-z0-9]+-[a-z0-9]+-[a-z0-9]+$/, `${host} is not a fleet host id`);
    }
    const gateways = fleetHosts().filter((h) => h.startsWith("gw-01."));
    assert.deepEqual([...order("RELAY_ORDER")].sort(), [...gateways].sort(), "a gateway is missing from RELAY_ORDER");
  });

  it("refuses before touching a host that has no rsync", () => {
    // The install is `rsync --delete`. Checked first, so a host without it is left exactly as it was
    // rather than with backups taken and the tarball unpacked.
    const script = read("../scripts/deploy-fleet.sh");
    const check = script.indexOf("command -v rsync");
    assert.ok(check > 0, "the rsync preflight is gone");
    // On the host, not on the operator's machine: inside the remote heredoc, and before its first change.
    assert.ok(check > script.indexOf("<<'EOS'"), "the rsync check must run on the host, inside the remote script");
    assert.ok(check < script.indexOf("sudo cp -a"), "the rsync check must come before the first backup");
  });

  it("puts the canary first among agents", () => {
    // The rollout stages already name k3s-01 as the canary; the deploy order agreeing with them is
    // what makes a bad build stop at the same host a bad generation would.
    assert.equal(order("AGENT_ORDER")[0], "k3s-01.dev-icn-vtr");
  });
});

// ## Why this exists
//
// `systemctl is-active` answers "is a process running", not "is it running what I just shipped".
// Measured 2026-09-03: a relay deploy's restart line was lost in the tarball's xattr warnings, the
// file on disk had already been replaced, and the unit reported `active` while executing code from
// two days before. Every downstream check agreed, because every one of them read the file.
describe("deploy-fleet.sh proves the restart happened", () => {
  const script = read("../scripts/deploy-fleet.sh");

  it("compares the start timestamp across the restart", () => {
    assert.match(script, /before="\$\(systemctl show -p ExecMainStartTimestampMonotonic/);
    assert.match(script, /after="\$\(systemctl show -p ExecMainStartTimestampMonotonic/);
    assert.match(script, /\[ "\$after" = "\$before" \]/);
  });

  it("uses the monotonic timestamp, which a same-second restart cannot alias", () => {
    assert.doesNotMatch(
      script,
      /\$\(systemctl show -p ExecMainStartTimestamp --value "\$unit"/,
      "the wall-clock form has second granularity — a fast restart lands inside the same second",
    );
  });

  it("reports a source digest rather than the version string", () => {
    // A version string is not a build identity: eight hosts once reported one version while running
    // two builds. `AGENT_BUILD` is sha256(source)[:12], so the column can be read against the fleet
    // view directly.
    assert.match(script, /sha256sum "\$f"/, "status must digest the deployed file");
    assert.match(script, /f=\/opt\/heliopause\/agent\/heliopause-pull\.py/);
    assert.match(script, /f=\/opt\/heliopause\/src\/relay\.ts/);
    assert.doesNotMatch(script, /agent-schema=/);
  });
});

// ## The operator's umask travels with the files
//
// `tar` packs the checkout's modes and the host-side `rsync -a` keeps them. On 2026-10-10 the operator's
// shell had `umask 077`, the pull before the rollout rewrote eight tracked files as 0600, and the first
// relay deploy died with `EACCES … open '/opt/heliopause/src/relay.ts'` — the relay's service account
// could not read its own source. `heliopause-pull.py` was among the eight, and the agent ships through
// the same install loop.
//
// The script now runs `chmod` on what it installed. Not `rsync --chmod`: macOS's `openrsync` accepts
// that option, exits 0 and changes nothing (measured the same day), so a test of it on a Mac would pass
// while proving nothing, and the hosts' rsync was not measured. `chmod` behaves the same on both.
//
// This runs the script's own `chmod` argument against a staged tree, so the mode is tested by effect.
describe("deploy-fleet.sh installs files the service account can read", () => {
  /** The install loop's `chmod` mode, read from the script so the test runs what the host runs. */
  function installChmod(): string {
    const script = read("../scripts/deploy-fleet.sh");
    const m = /sudo rsync -a --delete "\$T\/\$p\/" "\/opt\/heliopause\/\$p\/"; sudo chmod -R (\S+) "\/opt\/heliopause\/\$p"; done/
      .exec(script);
    assert.ok(m, "the install loop no longer runs chmod on what it installed, right after rsync");
    return m[1]!;
  }

  it("makes a 0600 file go-readable and keeps an executable executable", () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-deploy-modes-"));
    try {
      const sub = join(dir, "sub");
      mkdirSync(sub);
      writeFileSync(join(sub, "relay.ts"), "x");
      writeFileSync(join(sub, "run"), "#!/bin/sh\n");
      chmodSync(join(sub, "relay.ts"), 0o600);
      chmodSync(join(sub, "run"), 0o700);
      chmodSync(sub, 0o700);
      execFileSync("chmod", ["-R", installChmod(), dir]);
      const mode = (p: string) => (statSync(p).mode & 0o777).toString(8);
      assert.equal(mode(join(sub, "relay.ts")), "644", "a 0600 source is still unreadable to the service account");
      assert.equal(mode(join(sub, "run")), "755", "an executable lost its execute bit, or did not gain read");
      assert.equal(mode(sub), "755", "a 0700 directory is still closed to the service account");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
