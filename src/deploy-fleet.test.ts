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
import { readdirSync, readFileSync } from "node:fs";
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
    // `[^"]*` rather than the exact `\$p`: the loop variable is written inside a heredoc, so on disk
    // it is the escaped `\$p`, and pinning that escaping would test the quoting more than the guard.
    const script = read("../scripts/deploy-fleet.sh");
    assert.match(script, /if \[ -e "\/opt\/heliopause\/[^"]*" \]; then sudo cp -a/,
      "the backup must skip a path that does not exist yet, or the first deploy of a new path aborts");
    assert.match(script, /sudo mkdir -p "\/opt\/heliopause\/[^"]*"; sudo rsync/,
      "rsync must have its parent directory made first, or a new nested path fails");
  });

  it("still ships the repo's own bin and src", () => {
    // Not decoration: the packages line is additive, and a careless edit that replaced rather than
    // extended the list would strip the relay's own code and pass the check above.
    const relay = new Set(shipPaths("relay"));
    assert.ok(relay.has("bin") && relay.has("src"), "the relay must ship its own bin and src");
  });
});
