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
    out.push({ name, url, pkiDir });
  }
  if (out.length === 0) {
    throw new EnvSpecError("HELIOPAUSE_RELAYS is empty — there is nothing to aggregate");
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
