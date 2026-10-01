/**
 * The two comma-separated environment specs the manager is configured with.
 *
 * ## Why these live here rather than in `bin/heliopause-manager.ts`
 *
 * They were in the entry point, and the entry point reads `process.env` and calls `process.exit` at
 * the top level — so nothing could import it, and nothing could test them. That was not a
 * theoretical gap: `parsePairs` printed a malformed entry verbatim, one of its callers is
 * `HELIOPAUSE_OTP_USERS` whose values are shared OTP secrets, and the fix for that shipped with no
 * regression test because there was nowhere to put one. A property worth stating in a comment is
 * worth a test that fails without it.
 *
 * ## They throw; they do not exit
 *
 * Exiting is the entry point's job. A parser that calls `process.exit` cannot be tested, cannot be
 * reused, and cannot be composed — and the exit is not even the interesting part. What is
 * interesting is *which* input is refused and *what the message discloses*, and both are visible
 * only if the failure is a value the caller can inspect.
 *
 * Messages are unchanged from when this was inline, deliberately: an operator reading a manager
 * that refuses to start should see the same sentence as before.
 */

import { resolve } from "node:path";

/** One relay the manager aggregates: a name, an https URL, and the PKI directory for that VPC. */
export interface RelaySpec {
  name: string;
  url: string;
  pkiDir: string;
}

/** Refusal of an environment spec. The entry point turns this into a message and an exit code. */
export class EnvSpecError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvSpecError";
  }
}

/**
 * A numeric setting, its range, and what it is when unset.
 *
 * `fallback` is part of the bound rather than applied beside it, so a default that would itself be
 * refused cannot be introduced by editing one of the two in isolation.
 */
export interface NumberBounds {
  min: number;
  max: number;
  fallback: number;
}

/**
 * Read a numeric environment value, or refuse it.
 *
 * ## Why `Number(x)` on its own is not good enough here
 *
 * It yields `NaN`, and **`NaN` fails open through every comparison it touches.** These are not
 * hypotheticals; each was measured against this repository's own code:
 *
 * | setting | with `NaN` |
 * |---|---|
 * | `HELIOPAUSE_RELOAD_SEC` | `Math.max(5, NaN)` is `NaN`, and `setInterval(fn, NaN)` fires **every millisecond** — a gateway re-reading a 16 MB bundle ~875 times a second |
 * | `HELIOPAUSE_PUBLIC_REFRESH_SEC` | the same loop, in the manager |
 * | `HELIOPAUSE_OIDC_SESSION_TTL_SEC` | `expiresAt` becomes `Invalid Date`, and `invalid <= now` is `false` — **sessions never expire** |
 * | `HELIOPAUSE_PLAN_TTL_SEC` | `elapsed > NaN` is `false` — **approved plans never expire** |
 * | `HELIOPAUSE_MAX_PENDING_PLANS` | `size >= NaN` is `false` — **the pending-plan cap is gone** |
 *
 * Three of those five are the safety property, switched off by a typo, with nothing anywhere saying
 * so. `Math.max(5, …)` in particular *looks* like it prevents the first one.
 *
 * So the rule is that an unreadable value stops the process where somebody is watching, rather than
 * becoming a number that silently means "no limit".
 *
 * ## The message quotes the value
 *
 * Unlike `parsePairs`, which refuses to echo anything it could not parse. The difference is what
 * these variables hold: a port, an interval, a count. There is no shape of secret that belongs in
 * one, and an operator who mistyped needs to see what they typed. Truncated anyway, because an
 * environment variable is whatever somebody put in it.
 */
export function boundedInteger(name: string, raw: string | undefined, bounds: NumberBounds): number {
  const value = readNumber(name, raw, bounds);
  if (!Number.isInteger(value)) {
    throw new EnvSpecError(
      `${name} must be a whole number between ${bounds.min} and ${bounds.max} — got ${quote(raw)}`,
    );
  }
  return value;
}

/**
 * The same, for a setting that is legitimately fractional.
 *
 * One caller today: `HELIOPAUSE_PUBLIC_RETRY_SEC`, whose own documentation says *"fractional values
 * are accepted so a test can drive the whole ladder without waiting"*. A separate function rather
 * than a flag on the one above, so the call site says which kind of number it is asking for.
 */
export function boundedNumber(name: string, raw: string | undefined, bounds: NumberBounds): number {
  return readNumber(name, raw, bounds);
}

function readNumber(name: string, raw: string | undefined, bounds: NumberBounds): number {
  const given = raw?.trim();
  if (given === undefined || given === "") return bounds.fallback;
  // `Number("")` is 0 and `Number(" ")` is 0, which is why the blank cases are handled above rather
  // than left to fall through — an empty variable means "unset", not "zero".
  const value = Number(given);
  if (!Number.isFinite(value)) {
    throw new EnvSpecError(`${name} must be a number between ${bounds.min} and ${bounds.max} — got ${quote(raw)}`);
  }
  if (value < bounds.min || value > bounds.max) {
    throw new EnvSpecError(`${name} must be between ${bounds.min} and ${bounds.max} — got ${quote(raw)}`);
  }
  return value;
}

function quote(raw: string | undefined): string {
  const text = String(raw ?? "");
  return JSON.stringify(text.length > 32 ? `${text.slice(0, 32)}…` : text);
}

/**
 * Every numeric setting an entry point reads, and the range it accepts.
 *
 * ## Why these are here and not at each `number(...)` call
 *
 * They were at the call sites, and CI caught what that costs. `bin/heliopause-relay.ts` had
 * `Math.max(5, reloadSec)` before this parser existed — a **clamp**, so `HELIOPAUSE_RELOAD_SEC=2`
 * was accepted and quietly became 5. Turning the clamp into a refusal with the same 5 in it turned
 * an accepted value into a startup failure, and `scripts/rollback-test.sh` sets exactly that 2. The
 * unit tests passed; the job that needs a real kernel did not.
 *
 * A number written in one file and depended on in another is the shape of that failure. With the
 * table here, `env-spec.test.ts` can read the values the scripts and the env examples actually use
 * and check them against the bound that will judge them — which is the test that was missing.
 *
 * `fallback` is inside the bound so a default that would itself be refused cannot be introduced by
 * editing one of the two.
 */
export const ENV_BOUNDS = {
  // `0` is `listen(0)` — let the kernel choose, which is what the service tests bind.
  HELIOPAUSE_MANAGER_PORT: { min: 0, max: 65_535, fallback: 8444 },
  HELIOPAUSE_RELAY_PORT: { min: 0, max: 65_535, fallback: 8443 },
  HELIOPAUSE_POLICY_RENDER_PORT: { min: 0, max: 65_535, fallback: 9099 },

  /**
   * How often the relay re-reads its artifact directory.
   *
   * **Floor of 1, not 5.** Five was carried over from the `Math.max(5, …)` this replaced, and that
   * was a clamp: a smaller value was honoured as 5 rather than refused. Refusing it broke
   * `rollback-test.sh`, which asks for 2 — and asking for 2 is a reasonable thing for a gateway
   * whose bundle is small. What this exists to refuse is `NaN`, `0` and negatives, all of which
   * `setInterval` turns into a one-millisecond loop.
   *
   * A value below the old clamp is now **honoured rather than silently raised**, so a deployment
   * that set one is getting what it asked for from this release.
   */
  HELIOPAUSE_RELOAD_SEC: { min: 1, max: 3600, fallback: 30 },

  HELIOPAUSE_ARTIFACT_AUTHORIZATION_TTL_SEC: { min: 15 * 60, max: 7 * 24 * 60 * 60, fallback: 86_400 },
  HELIOPAUSE_PUBLIC_REFRESH_SEC: { min: 60, max: 86_400, fallback: 3600 },
  /** Fractional on purpose — a test drives the retry ladder without waiting. */
  HELIOPAUSE_PUBLIC_RETRY_SEC: { min: 0.001, max: 3600, fallback: 5 },
  HELIOPAUSE_OIDC_SESSION_TTL_SEC: { min: 60, max: 30 * 86_400, fallback: 8 * 3600 },
  HELIOPAUSE_RELAY_TIMEOUT_MS: { min: 100, max: 120_000, fallback: 5_000 },
  HELIOPAUSE_PUBLISH_TIMEOUT_MS: { min: 1_000, max: 600_000, fallback: 30_000 },
  HELIOPAUSE_PLAN_TTL_SEC: { min: 60, max: 86_400, fallback: 600 },
  HELIOPAUSE_MAX_PENDING_PLANS: { min: 1, max: 1024, fallback: 32 },

  /**
   * How long one policy module gets to import before the renderer gives up on it at startup.
   *
   * It bounds a module that **never settles**, not a slow one: unbounded, the verification loop's
   * own `await` never returns, `server.listen` is never reached, and the process answers nothing at
   * all — not even `/healthz`.
   *
   * 🔴 **It lives here because its first version did not, and that was a hole.** Read as
   * `Number(raw)` with a `isFinite && > 0` guard, `2147483648` passed — and `setTimeout` clamps
   * anything past 2³¹−1 to **one millisecond**, so the largest-looking value became the smallest
   * possible budget while the error text still quoted the number the operator typed. Worse, it is
   * invisible in a smoke test: a healthy synchronous module blocks the loop, so the 1 ms timer
   * cannot fire and every site still verifies. It bites only on a module that does async work at
   * import, which is the module the bound is for.
   *
   * The `max` is what makes that unrepresentable, and it is the half that matters here.
   *
   * ⚠️ **The table's other benefit does not apply to this name, and saying so is the point.**
   * `env-spec.test.ts` cross-checks these names against five files — two scripts and three
   * `*.env.example` — and the renderer has none: it is a Deployment, and its environment lives in
   * manifests outside this repository. So the scan finds nothing for this variable and will keep
   * finding nothing. Putting it in `manager.env.example` to give the net something to catch would
   * be worse than the gap, because the manager does not read it. What this entry buys is the bound
   * and the shared refusal vocabulary, not coverage.
   *
   * ## Why 60s and not a round 120s
   *
   * The ceiling is a second outage budget, not just a sanity limit. While the renderer is still
   * verifying, `server.listen` has not run, so **nothing answers — `/healthz` included**, and the
   * probe watching it is 30s × 3 (cited from the deployment manifests, which this repository cannot
   * check). A single site allowed 120s is therefore 120s dark against a 90s deadline: the same
   * crashloop the parallel verification was introduced to remove, re-reachable by one site instead
   * of three. `120_000` was the first value here: it did make the 1 ms clamp unrepresentable, which is
   * all the sentence above claims, and it left the **dark window past the liveness deadline**
   * representable, which is a second thing a ceiling here has to rule out. Two jobs, one number; the
   * first value only did the first. 60s keeps headroom under the deadline and is still far longer than
   * any cold import measured.
   */
  HELIOPAUSE_POLICY_STARTUP_BUDGET_MS: { min: 100, max: 60_000, fallback: 30_000 },

  /**
   * How long one policy module gets on the **request** path before `/source` answers 503.
   *
   * 🔴 **It exists because the relationship it needs cannot be expressed as a constant.** `/source`'s
   * 503 carries the sentence the console shows in place of an empty page, and that sentence only
   * reaches anyone if this side gives up before its caller does. The caller is the manager, whose
   * clock is `HELIOPAUSE_RELAY_TIMEOUT_MS` — **in the manager's own environment**, which this process
   * cannot read. Deriving from that variable's `fallback` looked like a coupling and is not one: an
   * operator who sets the manager to 2000 gets a renderer still budgeting 4000, which is the defect
   * the derivation was written to remove, reachable again. Measured: client abort at 2007ms with the
   * renderer logging its own timeout at 4000ms, to a socket nobody was reading.
   *
   * So the honest shape is a knob with a default that matches the common case, and an operator who
   * moves one moves both. The real fix is for the caller to send its deadline and for this side to
   * budget against what it was told — a header, backward compatible the way `?site=` is — and that is
   * a change to two services, deliberately not smuggled in here.
   *
   * The default is 80% of `HELIOPAUSE_RELAY_TIMEOUT_MS`'s own default, which is where the margin
   * comes from: measured 4040ms against a 5000ms client, ~960ms of slack, with the synchronous `git`
   * calls inside the budget window rather than before it.
   */
  HELIOPAUSE_POLICY_SOURCE_BUDGET_MS: { min: 100, max: 60_000, fallback: 4_000 },
} as const satisfies Record<string, NumberBounds>;

export type BoundedEnvName = keyof typeof ENV_BOUNDS;

/**
 * `dev=https://192.0.2.1:8443=./pki,prod=https://192.0.2.2:8443=./pki-prod`
 *
 * Three fields because each VPC has its own CA (V39): the manager presents a different operator
 * certificate to each relay and verifies each against that VPC's own anchor. One shared PKI would
 * reach exactly one VPC and report the others as unreachable — measured while wiring this up.
 *
 * Named rather than positional so a site view can say which VPC is unreachable. "relay 2 is down" is
 * not something an operator can act on at three in the morning.
 */
export function parseRelays(spec: string): RelaySpec[] {
  const out: RelaySpec[] = [];
  for (const entry of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    const parts = entry.split("=");
    if (parts.length !== 3 || parts.some((p) => !p)) {
      throw new EnvSpecError(`malformed relay entry ${JSON.stringify(entry)} — expected name=url=pkiDir`);
    }
    const [name, url, pkiDir] = parts as [string, string, string];
    if (!url.startsWith("https://")) {
      // Refused rather than upgraded. The site view names every host in the fleet, and it travels
      // over this connection.
      throw new EnvSpecError(`relay ${name} must be https — got ${JSON.stringify(url)}`);
    }
    // The name is the zone's whole identity — it keys the CA (`pkiDir`), the agent's
    // `HELIOPAUSE_TARGET`, the site module, and the last label of every host id under it
    // (`k3s-01.dev`). Two entries sharing a name collapse all of that to ambiguity: a heartbeat from
    // `k3s-01.dev` could belong to either relay, `/site` shows two VPCs with one name, and an app
    // token scoped `*.dev` mints for both. The map that feeds `/site` would silently keep only the
    // last entry, so the earlier relay would vanish from the fleet view with nothing said. Unlike a
    // malformed entry, the name is not a secret and quoting it is how the operator finds the
    // duplicate — the two commas that look identical.
    if (out.some((r) => r.name === name)) {
      throw new EnvSpecError(`relay ${JSON.stringify(name)} is named twice — each zone name must be unique`);
    }
    out.push({ name, url, pkiDir });
  }
  if (out.length === 0) {
    throw new EnvSpecError("HELIOPAUSE_RELAYS is empty — there is nothing to aggregate");
  }
  return out;
}

/** One site module the renderer serves, and the zone name it serves it under. */
export interface PolicySiteSpec {
  name: string;
  path: string;
}

/**
 * `HELIOPAUSE_POLICY_SITES` — `dev-icn-vtr=./dev.ts,prod-icn-vtr=./prod.ts` — for the renderer.
 *
 * ## Why neither neighbour was reused
 *
 * Not `parsePairs`: its whole refusal design is "position only, never quote the entry", because one
 * of its callers holds shared OTP secrets. Site names and module paths are configuration, and
 * "entry 2 is malformed" is useless to an operator who has mistyped a filename — here the name is
 * the only thing that makes the message actionable.
 *
 * Not `parseRelays`: that is three positional fields split on `=`, and a path may legitimately
 * contain one. This splits on the *first* `=` only.
 *
 * ## The duplicate-path refusal is the point of this function
 *
 * Two names pointing at one module is the 2026-09-28 incident written as configuration — the
 * renderer would answer `prod-icn-vtr` with whatever that module holds, and everything downstream
 * would agree with it. It costs one line to catch here, before anything is served.
 *
 * The name is compared against a relay name and ends up in a signed artifact's `target`, so it is
 * held to the same shape `artifact-signature.ts` holds that field to. A name this parser accepts
 * and the signer later refuses would fail at publish time, which is several hours too late.
 */
export function parsePolicySites(spec: string): PolicySiteSpec[] {
  const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
  const out: PolicySiteSpec[] = [];
  for (const entry of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    const eq = entry.indexOf("=");
    if (eq <= 0 || eq === entry.length - 1) {
      throw new EnvSpecError(`malformed policy site entry ${JSON.stringify(entry)} — expected name=path`);
    }
    const name = entry.slice(0, eq).trim();
    const path = entry.slice(eq + 1).trim();
    if (!SAFE_NAME.test(name) || name.length > 128) {
      throw new EnvSpecError(
        `policy site name ${JSON.stringify(name)} is overlong or contains characters a signed target may not`,
      );
    }
    if (out.some((s) => s.name === name)) {
      throw new EnvSpecError(`policy site ${JSON.stringify(name)} is named twice — each zone name must be unique`);
    }
    // Normalised before comparing. `alpha=./site.ts,beta=subdir/../site.ts` are two strings and one
    // module, and the renderer resolves them to one path *after* this — so a raw-string comparison
    // lets exactly the configuration this check exists to refuse through, and the two names then
    // share a cache slot. `resolve` is pure path arithmetic, no filesystem, and the renderer runs it
    // in this same process so the two agree. Copilot found this on PR #55.
    const sharing = out.find((s) => resolve(s.path) === resolve(path));
    if (sharing) {
      throw new EnvSpecError(
        `policy sites ${JSON.stringify(sharing.name)} and ${JSON.stringify(name)} both name ${JSON.stringify(path)}` +
          ` — a zone is one module, and serving one VPC's policy under another's name is the failure this names`,
      );
    }
    out.push({ name, path });
  }
  if (out.length === 0) {
    throw new EnvSpecError("HELIOPAUSE_POLICY_SITES is empty — there is no policy to serve");
  }
  return out;
}

/**
 * `a=1,b=2` into a map, refusing anything malformed.
 *
 * Refusing rather than skipping. A dropped mapping here presents as "my approvals are refused and I
 * do not know why", with the operator looking at a configuration line that appears correct.
 *
 * 🔴 **No part of a refused entry appears in the message — position only.** One caller is
 * `HELIOPAUSE_OTP_USERS`, whose values are shared OTP secrets, and these two branches fire on
 * exactly the inputs whose shape we cannot reason about. A secret containing a comma splits into a
 * fragment with no `=`; a message quoting that fragment writes the secret to stderr and into
 * journald. **A misconfiguration must not be the thing that publishes the secret.**
 *
 * An earlier version of this fix named the key in the empty-value branch, arguing that a key half
 * is not a secret. It is not safe, and the reason is the sentence above: an entry we are refusing
 * is one whose halves we cannot vouch for. A transposed `<secret>=` has the secret sitting in the
 * key position, and that is precisely what this branch catches.
 *
 * The ordinal is enough to act on — the operator has the variable in front of them and can count
 * commas — and the two messages stay distinct so they still say *what* is wrong.
 *
 * The duplicate-key message does quote the key, and that is not the same case: reaching it means
 * the entry parsed, so the key is a key. It is also the only way to say which one repeats.
 */
export function parsePairs(spec: string, name: string): Map<string, string> {
  const out = new Map<string, string>();
  let ordinal = 0;
  for (const entry of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    ordinal += 1;
    const eq = entry.indexOf("=");
    if (eq <= 0) {
      throw new EnvSpecError(`${name}: entry ${ordinal} is malformed — expected <key>=<value>`);
    }
    if (eq === entry.length - 1) {
      throw new EnvSpecError(`${name}: entry ${ordinal} has an empty value — expected <key>=<value>`);
    }
    const k = entry.slice(0, eq).trim();
    const v = entry.slice(eq + 1).trim();
    if (out.has(k)) {
      throw new EnvSpecError(`${name}: ${JSON.stringify(k)} is declared twice`);
    }
    out.set(k, v);
  }
  return out;
}
