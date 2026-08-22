/**
 * What build of this repository a process is running, computed from the code it is running.
 *
 * ## Why this exists
 *
 * The manager reads its policy from `heliopause-policy-render`, a separate Deployment. They are the
 * same image by convention and nothing checks it. Measured 2026-08-18: the manager was on
 * `3e1c248` and the renderer on `b32a7c6`, eleven commits behind, because the deploy pipeline
 * rewrites one manifest per component directory and the renderer's manifest is a second file inside
 * the manager's. The build succeeds, the tag commit lands, and the renderer is simply never named.
 *
 * `POLICY_SOURCE_SCHEMA` is the only thing that notices, and it notices by **refusing** — on the day
 * somebody bumps it, `/policy` starts answering 503 and nothing on the page says the reason is a
 * stale renderer. The agents solved the same problem years earlier and it is right there in the
 * fleet view: `agentVersion` travels on every heartbeat, and its comment calls it "the only
 * server-side evidence that a host-unit deployment took". The renderer had no such field.
 *
 * ## Why it is derived rather than injected
 *
 * A build argument would have to be passed by the pipeline, and the pipeline is in another
 * organisation's repository — the same one whose omission caused this. A stamp that depends on the
 * thing it is meant to catch is not a check.
 *
 * `Dockerfile.manager` states the property this relies on: Node runs the `.ts` directly, there is no
 * build stage, and "the image contents are exactly what is in git at the tagged commit". So the
 * source **is** the build, and hashing it needs nothing from anybody.
 *
 * ## What is hashed, and what is deliberately not
 *
 * Every `.ts` in this directory that is not a test. Tests are excluded because they are not in the
 * image: a manager running from a checkout would otherwise never match a renderer running from an
 * image, and a comparison that is always unequal is one nobody reads. `bin/` is excluded for the
 * same reason in reverse — the image carries three entry points and each process runs one, so
 * including them would make two processes of the same build disagree.
 *
 * Blunt on purpose. A change to any shipped module moves the value, including ones the policy
 * contract does not depend on. That over-reports rather than under-reports, and the answer it gives
 * — "these are different builds" — is true in every case where it differs. Naming a subset would be
 * a judgement about which modules matter that goes stale the first time somebody moves a function.
 */
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

/**
 * Hex digest of the shipped source in `dir`, truncated to something a person can compare by eye.
 *
 * Twelve characters, the length git logs use for a short sha, and for the same reason: this is read
 * off a screen next to another one of these, and a full sha256 is compared by nobody.
 *
 * The filename goes into the hash with its content. Without it, renaming a module to a name that
 * sorts elsewhere while moving its text produces the same digest — unlikely, and free to close.
 */
export function computeBuildId(dir: string): string {
  const h = createHash("sha256");
  const names = readdirSync(dir)
    .filter((n) => n.endsWith(".ts") && !n.endsWith(".test.ts"))
    .sort();
  for (const name of names) {
    h.update(name);
    h.update("\0");
    h.update(readFileSync(join(dir, name)));
  }
  return h.digest("hex").slice(0, 12);
}

/**
 * This process's build. Computed once — the files cannot change under a running process in the way
 * that matters here, and a digest recomputed per request would be a disk read per page view.
 */
let cached: string | null = null;
export function buildId(): string {
  if (cached === null) cached = computeBuildId(import.meta.dirname);
  return cached;
}
