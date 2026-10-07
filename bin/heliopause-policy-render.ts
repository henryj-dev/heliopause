#!/usr/bin/env node
// The one process that runs the policy author's code.
//
// ## Why this exists
//
// The site module is TypeScript and its top level is code, so rendering the policy screen means
// executing whatever is in the policy repository. The manager used to do that inline, which made a
// commit to that repository arbitrary code execution next to the artifact signing key, the GitHub
// App key, the OIDC client secret and the relay client certificate — audit finding C1. The first fix
// deleted the screen, and deleting the screen deleted the console.
//
// So the execution moves to a process with nothing in it. This one holds a policy checkout and no
// credential, answers exactly one question, and answers it in JSON. A hostile commit still runs —
// there is no way to render a program without running it — but it runs where the blast radius is a
// rendered answer rather than a console, a credential and a fleet.
//
// ⚠️ **It is not confined to the policy it came from, and this file used to say it was.** A module is
// evaluated by `import()` in this process's own realm, so it shares every intrinsic and every
// prototype with the other sites served here. The tests below prove it: a module that poisons
// `Object.prototype` makes a *different*, correct site answer 503, and that is asserted as the
// expected result because it is what the code does. Per-site isolation would mean a separate realm —
// a `worker_thread` or a `vm` context — and that is not what this is.
//
// What the captures and guards below buy is that one module's mistake is a 503 rather than an exit:
// the process stays up and the sites that still evaluate keep serving. That is a smaller claim than
// the one this paragraph made, and it is the one the tests actually hold.
//
// ## What keeps that true
//
// Not a comment. Three things this process checks about itself before it listens, below in
// `refuseIfArmed()`: no credential-shaped environment, no Kubernetes service account token, no
// signing key. All three are deployment facts that a manifest can get wrong silently, and every one
// of them has been got wrong in this repository at least once. Failing to start is the correct
// outcome — a renderer that will not come up costs the console, and coming up armed costs the fleet.
//
// The fourth thing is not checkable from in here and lives in the manifest: a CiliumNetworkPolicy
// that allows ingress only from the manager and egress only to the git remote. Containers in one pod
// share a network namespace, which is why this is a separate Deployment rather than a sidecar —
// a sidecar cannot be given a different network identity from the process it is isolating.

import { createServer } from "node:http";
import { Worker } from "node:worker_threads";
import { evaluateWithLifecycle } from "../src/policy-eval-lifecycle.ts";
import { existsSync, opendirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { timingSafeEqual } from "node:crypto";
import { oneLine } from "../src/log-scrub.ts";
import { boundedInteger, ENV_BOUNDS, parsePolicySites } from "../src/env-spec.ts";
import { zoneMismatch, ZoneMismatchError } from "../src/site-zone.ts";
import { armedReasons } from "../src/policy-render-guard.ts";
import { assemblePolicySource, parsePolicySource, type PolicySource } from "../src/policy-source.ts";
import { policyHead, type ScreenSite } from "../src/policy-screen.ts";
import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();

/**
 * One line, always, with this service's prefix on it.
 *
 * `oneLine` is the shared control in `src/log-scrub.ts`; see its doc for what it covers and — more
 * importantly — for what it cannot: a policy module shares this process's stdout, so it can write a
 * byte-identical line without passing through here at all. This bounds the *interpolation* channel.
 */
const log = (m: string): void => console.log(`[policy-render] ${oneLine(m)}`);

/**
 * A failure that happened **after** the declared-name check ran and passed.
 *
 * Its whole job is to be **distinguishable**. The startup verification says "the declared-name check
 * did not run" on a failure, and that is true of an import that threw, a missing export or a
 * timeout — and false of anything `collectPolicySource` raises, which is reached only past the
 * check. Selecting on the message text got this wrong in both directions on successive commits;
 * carrying the fact with the error is what stops there being a third way to get it wrong.
 */
/**
 * A zone mismatch **this process** found, as opposed to one handed to it.
 *
 * ## Class identity is not provenance, and `instanceof` was treated as if it were
 *
 * A policy module can `import { ZoneMismatchError } from "../src/site-zone.ts"` -- the exact spelling
 * the mount check above demands of a site module -- and Node's resolver realpaths by default, so the
 * module's `../src/site-zone.ts` and this file's are the **same module instance** and the class object
 * is literally the same. A `ZoneMismatchError` thrown by a module therefore satisfies
 * `instanceof ZoneMismatchError` here, and the startup loop turned that into `process.exit(2)` with a
 * refusal sentence the module wrote. Reproduced: a `resolveService` that throws one takes the pod down
 * and prints `refusing to start: beta is declared for ..., but forged from resolveService via ../src`.
 *
 * The precondition is not exotic -- it is the layout this file insists on. With the checkout mounted at
 * `/opt/heliopause/policy` and the binary at `/opt/heliopause/bin`, both `../src` spellings resolve to
 * `/opt/heliopause/src`. So one line in a policy commit could take every co-served site's console down,
 * which is the outage the startup block spends a paragraph refusing to manufacture.
 *
 * 🔴 **A subclass does not brand it, and that was this file's first answer.** `class Own extends
 * ZoneMismatchError {}` inherits statics, so `Own[Symbol.hasInstance]` resolves up the chain to
 * `ZoneMismatchError[Symbol.hasInstance]` — which a module can define, because it holds the same class
 * object. Measured: after `Object.defineProperty(ZoneMismatchError, Symbol.hasInstance, {value: () =>
 * true})`, a plainly-constructed error satisfies `instanceof Own`. The brand has to be something a
 * module cannot name at all.
 *
 * A `WeakSet` this module closes over is that: membership is not a property of the error, not on any
 * prototype, and not reachable through the class. `Symbol.hasInstance`, `setPrototypeOf`, a forged
 * prototype chain and prototype pollution all move properties around and none of them can add an
 * entry here. Weak so a refused error is still collectable.
 *
 * A module-authored `ZoneMismatchError` is therefore an ordinary content fault: wrapped as
 * `ZoneCheckedError`, logged, that site answers 503, and the pod stays up.
 *
 * @see src/policy-render-service.test.ts "a module cannot force a refusal by throwing the renderer's
 *      own error class"
 */
const OUR_ZONE_MISMATCHES = new WeakSet<ZoneMismatchError>();
// ## Bound before any policy module is imported
//
// `foundHere` called `OUR_ZONE_MISMATCHES.has(...)`, which looks the method up on
// `WeakSet.prototype` **at call time** — and a policy module runs in this realm, so
// `WeakSet.prototype.has = () => true` in one makes every error look like ours. Measured: it turned an
// ordinary content fault into `exit 2` with a refusal nobody configured. The set is unreachable to a
// module, but the *lookup* was not; capturing it here, before the first `import()`, is what makes the
// unreachability of the set the only thing that matters.
const zoneMismatchIsOurs = WeakSet.prototype.has.bind(OUR_ZONE_MISMATCHES) as (e: object) => boolean;
const rememberOurZoneMismatch = WeakSet.prototype.add.bind(OUR_ZONE_MISMATCHES) as (e: object) => unknown;

// ## The value was guarded; the constructor used to describe it was not
//
// A policy module is evaluated by `import()` in **this process's own realm** — the same `globalThis` —
// so `globalThis.Error = function () { throw 1; };` is two tokens that replace the constructor every
// later `new Error(...)` resolves. The guards below all read the thrown value carefully and then build
// an `Error` to carry it, which called the module's function instead.
//
// Where that lands is the whole severity. `asError` runs inside `evaluateWithin`'s rejection handler,
// the single point every module failure funnels through, and a throw inside a rejection handler is an
// unhandled rejection: **exit 1 during the startup loop, before `server.listen`.** Measured — a module
// that replaces `Error` and then throws a string takes the process down at boot, so it restarts and
// does it again. At `replicas: 1` with `Recreate` that is every co-served site's console dark on a
// crashloop, the same outage `asError` was added to prevent, reached through `asError` itself. The
// handler's own comment describes this mechanism and did not close it, because the comment was about
// the *value* being unreadable and this is the *constructor* being replaced.
//
// Captured here, before the first dynamic import, for the reason the block above gives. `extends Error`
// needs no capture: the superclass is resolved when the class definition is evaluated, which is also
// before any import, so `ZoneCheckedError` and `ZoneMismatchError` already hold the real one.
//
// @see src/policy-render-service.test.ts "survives a module that replaces the globals it will be described with"
const RealError = Error;

// ## A module's callback outlives the handler that was watching its import
//
// `setTimeout(() => { throw new Error("late") }, 500)` at a policy module's top level resolves its
// import cleanly, passes startup verification, answers `/healthz` 200 — and then throws with nothing
// from this file on the stack. The default action for that is to exit, so the pod died **after** both
// probes had passed, which at `replicas: 1` with `Recreate` is every co-served console dark on a
// crashloop driven by a config commit. Measured against `origin/main` of this repository — not
// against the running image, whose tag is a sha from the other repository and does not resolve here.
//
// Staying up is the better trade: one module's delayed mistake should not be a fleet outage, and the
// sites that do evaluate keep serving. The cost is real and deliberate — a genuine fault in *this*
// file no longer crashes loudly either — so it is not swallowed: every one is logged and counted, and
// the count is on `/readyz`, where an operator polling readiness sees it without reading logs.
//
// Installed before the first dynamic import, like the captures above.
//
// @see src/policy-render-service.test.ts "keeps serving when a module's own callback throws later"
let faults = 0;
for (const signal of ["uncaughtException", "unhandledRejection"] as const) {
  process.on(signal, (thrown: unknown) => {
    faults += 1;
    // `oneLine` and `reasonOf`: the text can come from a policy module, so it carries the same
    // forgery and unreadability channels as any other module-supplied string.
    console.error(`[policy-render] ${oneLine(`${signal} #${faults} — the process is staying up: ${reasonOf(thrown)}`)}`);
    console.error(`[policy-render]   this cannot be attributed to one site; check /readyz and the policy commits`);
  });
}

// The same capture, for the same reason, on the coercion two shared paths use. `globalThis.String =
// function () { throw 1; };` in one module made **another site** answer 503: `sourceStamp` and
// `hostIds` run for every site, so a module that replaces `String` un-serves the modules it does not
// own, and the log says only that they failed to evaluate. Measured. That is quieter than the crash
// above and worse — a correct prod policy stops rendering because a dev commit is hostile or broken.
//
// Not substituted inside `reasonOf` and `asError`: those calls are already wrapped in the `try`/`catch`
// that exists for a value whose coercion throws, so a replaced `String` lands in the same fallback.
// `boundedInteger`'s runs before the first import, where nothing has been replaced yet.
const toText = String;

// And the rest of what a shared path resolves at call time. `evaluateWithin` arms a timer for **every**
// site, so `globalThis.setTimeout = function () { throw 1; };` in one module throws inside the
// `new Promise` executor of another site's evaluation — measured, alpha answered 503 because beta was
// hostile. `send` serialises every response including `/healthz`, and the readiness memo reads the
// clock, so a replaced `JSON` or `Date` is the same reach by a different name.
//
// Captured rather than each call being wrapped: a `try` around a timer that was replaced still has no
// timer, and the point is that the module never gets to participate in another site's request at all.
const arm = setTimeout;
const disarm = clearTimeout;
const readClock = Date.now;
const toJson = JSON.stringify;
// ## The wire pair, captured for the same reason and with the same limit
//
// `evaluated` serialises the outgoing `PolicySource` and its caller parses it back. Both functions
// are resolved here, before the first `import()`, because a policy module runs in this realm and a
// call-time lookup would be the module's function — and the value being serialised is the one thing
// a module fully controls.
//
// ⚠️ Capturing the function is not the same as the operation being safe. `JSON.stringify` calls a
// `toJSON` it finds **on the value**, inherited ones included, so a poisoned `Object.prototype` is
// not closed by this line — that is why the caller treats a throw here as this site's failure
// rather than assuming the conversion cannot throw.
const writeWire = JSON.stringify;
const parseWire = JSON.parse;

// ## ⚠️ What this does **not** do, stated because leaving it implied is the same silence
//
// The substitutions above are the call sites that were *measured* to reach another site or the
// process. Nothing stops the next edit from adding a bare `JSON.stringify(`, `String(` or
// `setTimeout(` on a shared path, and the tests will not catch it: they exercise the shapes known
// today, and a new unguarded call is only reachable by a shape nobody has written yet.
//
// A check over this file's source text would find it, and that is deliberately not here: `AGENTS.md`
// records three separate times that asserting on source text in this repo missed the thing it was
// written for, and the test file's own preamble says the same. So this is a gap held open on purpose,
// not an oversight — and it is a second reason the captures are a patch on measured paths rather than
// a boundary. Evaluating policy in its own realm removes the whole class, including this.
//
// Until then, the rule for anyone editing this file: an intrinsic resolved at call time on a path
// more than one site reaches must use the captured name. Ask what the operation looks up **on the
// value** as well — `JSON.stringify` calls an inherited `toJSON`, resolving a promise reads an
// inherited `then`, and capturing the global closes neither.

// ## "The zone check had already passed" is no longer a fact this file carries
//
// It used to be, as `ZoneCheckedError` plus a `WeakSet` — membership rather than `instanceof`,
// because an `Error` in a revoked `Proxy.revocable` made the prototype walk throw at startup before
// the listener existed (measured). That whole mechanism is gone: the zone check now runs **last**, on
// the parsed wire, so no failure can arrive past it and nothing is left to mark. Deleting it was not
// tidying — a classification that cannot be true is a line a reviewer reverts, sees green, and reads
// as protecting nothing.
//
// The sibling mechanism above it stays: `foundHere` still has to tell a zone mismatch **this** process
// raised from one a module threw, because the class is importable and `instanceof` is forgeable.

/** A zone mismatch this process found. Registered so `foundHere` can recognise it later. */
function ownZoneMismatch(message: string): ZoneMismatchError {
  const error = new ZoneMismatchError(message);
  rememberOurZoneMismatch(error);
  return error;
}

/** Whether this process constructed `error`. Unspoofable because the set is unreachable. */
function foundHere(error: unknown): error is ZoneMismatchError {
  // No `instanceof` here. It cannot help — membership already implies this process built the object —
  // and it can hurt: `instanceof` runs a Proxy's `getPrototypeOf` trap, so the check meant to
  // establish provenance could itself throw. `typeof` is enough to keep the bound `has` from being
  // handed a primitive.
  if (error === null || (typeof error !== "object" && typeof error !== "function")) return false;
  return zoneMismatchIsOurs(error);
}

/**
 * Whatever was thrown, as an `Error`.
 *
 * ## `throw null` in a policy commit was a crashloop
 *
 * `throw` takes any value, and a policy module is code this process runs on purpose without trusting
 * it. `(e as Error).message` on a nullish throw raises a `TypeError` **at the read**, so the startup
 * loop died before `server.listen` — exit 1, no listener, and at `replicas: 1` with `Recreate` that is
 * every co-served site's console down, which is precisely the outage the loop's own comment says must
 * never be manufactured. Two tokens in a policy repo. `throw 42` survived and printed the reason as
 * the literal word `undefined`.
 *
 * It also broke the fix directly above it: `new ZoneCheckedError((e as Error).message)` threw *inside
 * the catch*, so the wrapper was never constructed and a post-zone-check failure fell into the branch
 * that blames the declared name — the exact confusion `ZoneCheckedError` exists to end.
 *
 * Normalised once, where the value is caught, rather than at each read. There were four reads.
 *
 * @see src/policy-render-service.test.ts "survives a policy module that throws a nullish value"
 */
/**
 * An error's message, or a stand-in — never a throw.
 *
 * `.message` is an ordinary property and a configuration module can make it a getter that throws.
 * Measured: an `Error` with such a getter reached the log line and the 503 body, where the interpolation
 * threw outside every guard and the process exited. That is a getter away from an ordinary mistake — a
 * property that reads something undefined during construction.
 *
 * Used at every place a caught value's message is interpolated. There are four, which is why this is a
 * function rather than a `try` at each one.
 *
 * @see src/policy-render-service.test.ts "survives a module whose error resists being read"
 */
function reasonOf(error: unknown): string {
  try {
    const message = (error as { message?: unknown } | null)?.message;
    return typeof message === "string" ? message : String(message);
  } catch {
    return "an error whose message cannot be read";
  }
}

function asError(thrown: unknown): Error {
  // ## Even the classification can throw
  //
  // `thrown instanceof Error` walks the prototype chain, which runs a Proxy's `getPrototypeOf` trap
  // — so a thrown `new Proxy({}, { getPrototypeOf() { throw … } })` made **this line** throw, and a
  // revoked Proxy raised `TypeError: Cannot perform 'getPrototypeOf' on a proxy that has been
  // revoked`. Both landed in a rejection handler that had already cleared its timer, so the process
  // exited. The guard below covers the classification for that reason and not for tidiness.
  let isError: boolean;
  try {
    isError = thrown instanceof Error;
  } catch {
    isError = false;
  }
  // Returned as it is, deliberately. An earlier version rebuilt the error around a safely-read
  // message, and that breaks two things that key on the **object**: `foundHere`'s `WeakSet`, which is
  // how a zone mismatch this process built is told from one a module threw, and the
  // `ZoneCheckedError` membership set, which is how a content fault past the zone check is told
  // from one before it. A rebuilt error is in neither, so both silently reclassify. (That version also
  // compared `message === source.message` to skip the rebuild in the common case, which read the
  // getter a **second** time outside the guard and threw — the defect, inside its own fix.)
  //
  // Reading the message safely belongs at the point of reading. `reasonOf` below does that.
  if (isError) return thrown as Error;
  // ## The coercion is the part a module attacks next
  //
  // `String(thrown)` is not safe on a value a policy module chose. Measured, four of five hostile
  // shapes made **this function** throw: a `toString` that throws, a `Symbol.toPrimitive` that throws,
  // `Object.create(null)` (two tokens, no `toString` to find), and a Proxy whose `get` trap throws. Any
  // of them restored the exact crash `asError` exists to prevent, from inside it.
  //
  // `typeof` cannot throw — not even through a Proxy, which has no trap for it — so the fallback is
  // always available. `JSON.stringify` is not an alternative: `undefined` for a function, and it throws
  // on a cycle, which is where this started.
  let described: string;
  try {
    described = String(thrown);
  } catch {
    described = `a ${typeof thrown} that cannot be described`;
  }
  return new RealError(`policy module threw a non-error value: ${described}`);
}

const env = (name: string, fallback?: string): string => {
  const v = process.env[name] ?? fallback;
  if (v === undefined) {
    console.error(`[policy-render] missing required environment: ${name}`);
    process.exit(2);
  }
  return v;
};

/**
 * Refuse to start holding anything worth stealing.
 *
 * The whole design rests on this process being empty, and "empty" is a property of the deployment
 * rather than of the code. A manifest that mounts the signing key here by copy-paste, or forgets
 * `automountServiceAccountToken: false`, produces a renderer that looks identical from the outside
 * and has quietly moved C1 rather than fixed it. So the property is asserted where it can be
 * measured — at startup, in the process itself.
 */
function refuseIfArmed(): void {
  // The decision lives in `policy-render-guard.ts` so that it can be exercised with a service
  // account token file that exists — the real path cannot be created on a machine that is not a
  // kubelet's, and the check for it was therefore untestable and, as defect injection showed,
  // untested. This function is the wiring, and the spawn test in `policy-render-service.test.ts`
  // is what proves the wiring runs.
  const armed = armedReasons({ env: process.env });

  if (armed.length === 0) return;
  console.error(
    "[policy-render] refusing to start: this process runs untrusted policy code and must hold no " +
      `credential, but it holds ${armed.length}:`,
  );
  for (const a of armed) console.error(`[policy-render]   - ${a}`);
  console.error("[policy-render] fix the deployment, not this check.");
  process.exit(2);
}

refuseIfArmed();

const label = process.env.HELIOPAUSE_POLICY_LABEL ?? "policy";

/**
 * Which modules this process serves, and under which zone names.
 *
 * ## Two variables, and only one of them names the zones
 *
 * `HELIOPAUSE_POLICY_SITE` is one module with no name. That is how every renderer was deployed
 * before 2026-09-29 and it keeps working exactly as it did: a bare `GET /source` answers it, and the
 * payload carries no `siteName` because there is none to carry.
 *
 * `HELIOPAUSE_POLICY_SITES` is `name=path,name=path`. The names are zone names — the same strings as
 * `HELIOPAUSE_RELAYS` and the agents' `HELIOPAUSE_TARGET` — and they are what `?site=` selects.
 *
 * Both set is refused rather than merged. They are two answers to one question, and a process that
 * picks between them silently is a process whose behaviour is decided by whichever line of the
 * manifest was edited last.
 */
const sites: { name: string | null; path: string }[] = (() => {
  const many = process.env.HELIOPAUSE_POLICY_SITES;
  const one = process.env.HELIOPAUSE_POLICY_SITE;
  if (many && one) {
    console.error("[policy-render] refusing to start: HELIOPAUSE_POLICY_SITES and HELIOPAUSE_POLICY_SITE are both set.");
    console.error("[policy-render]   they are two answers to one question — keep the one this deployment means");
    process.exit(2);
  }
  if (many) {
    try {
      return parsePolicySites(many).map((s) => ({ name: s.name, path: resolve(s.path) }));
    } catch (e) {
      console.error(`[policy-render] ${oneLine(`refusing to start: ${reasonOf(e)}`)}`);
      process.exit(2);
    }
  }
  return [{ name: null, path: resolve(env("HELIOPAUSE_POLICY_SITE")) }];
})();

/**
 * The checkout has to be mounted where the site module's own imports resolve.
 *
 * A site module reaches the model with `../src`, and Node resolves that against the *module's*
 * location — not the process's. Mount the checkout at `/policy` and `dev.ts` asks for `/src`, which
 * is not in this image. Nothing fails until the first request, and then it fails as a module
 * resolution error naming a path that appears in no manifest.
 *
 * Measured 2026-08-16: that is exactly how the renderer's first deployment was wrong. The Dockerfile
 * comment that warned about it had been deleted along with the sidecar it was written for, so the
 * warning and the mistake missed each other by one commit.
 *
 * Checked here rather than at render time because it is a property of the *mount*, decided when the
 * pod is written, and knowable before anything has been cloned — `../src` is this image's own
 * directory, not the policy repository's.
 */
// Per module, not once: the answer is the same for three modules in one directory today, and it is
// a property of each module's own location rather than of the deployment.
for (const site of sites) {
  const modelDir = resolve(site.path, "..", "..", "src");
  if (!existsSync(modelDir)) {
    console.error(
      `[policy-render] refusing to start: ${site.path} is mounted where its own imports do not resolve.`,
    );
    console.error(`[policy-render]   a site module imports the model with ../src, which from there is ${modelDir}`);
    console.error(`[policy-render]   mount the checkout inside this image's directory — /opt/heliopause/policy`);
    process.exit(2);
  }
}
// ## The child-version loader hook is gone, and so is `?v=`
//
// Both existed to defeat the module registry. ES modules are keyed by URL and never evicted, so the
// renderer minted a moving query per evaluation, and #59 extended it to the children — without that,
// `dev.ts` re-evaluated while `./policies.json` stayed the copy read at pod start, so the stamp and
// the generation id moved and the rules did not.
//
// A worker starts with an **empty registry** and is terminated after one evaluation. There is nothing
// to evict, so there is nothing to defeat: the worker imports the module by its plain path and every
// file it pulls in is read fresh. @see src/policy-eval-worker.ts
//
// 🔑 Removed rather than left in place. The hook only fired for imports whose parent URL carried a
// `v`, and no import in this process has one any more — so it would be a guard that cannot be
// reached, which this repository has recorded three times as worse than no guard: a reviewer reverts
// it, sees green, and reads the line as protecting nothing.
//
// ⚠️ What it cost to find is worth keeping: the first version keyed on the importing module's
// directory and left two holes a review found the next day (`sub/a.ts` importing `../up.json` got the
// pod-start copy; `../class.ts` loaded twice, so `instanceof` went false), and the version before
// that compared against the configured path rather than the real one and did nothing, silently, on
// macOS. @see docs/policy-evaluation-realm-design.md §1-g, which measured the hook as an amplifier of
// the leak this change removes.

const allowPaths = (process.env.HELIOPAUSE_POLICY_ALLOW_PATHS ?? "policies.json")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
// Parsed, not coerced. `Number("nine-thousand")` is `NaN`, and `listen(NaN)` throws
// `ERR_SOCKET_BAD_PORT` — loud, but naming neither this variable nor this service. Same rule as
// every other numeric setting; see `boundedInteger`.
let port: number;
try {
  port = boundedInteger(
    "HELIOPAUSE_POLICY_RENDER_PORT",
    process.env.HELIOPAUSE_POLICY_RENDER_PORT,
    ENV_BOUNDS.HELIOPAUSE_POLICY_RENDER_PORT,
  );
} catch (error) {
  console.error(`[policy-render] ${(error as Error).message}`);
  process.exit(2);
}
const hostname = process.env.HELIOPAUSE_POLICY_RENDER_HOST ?? "::";
/**
 * The bearer this service requires. **Required**, not optional.
 *
 * ## Why the default was wrong
 *
 * `?? ""` combined with `bearerOk` returning `true` on an empty token meant the default deployment
 * served `GET /source` to anyone who could reach the port — over plain HTTP, bound to `::`. What it
 * serves is the whole policy: every allowed path into the site, plus the bodies of the editable
 * files. The startup line said so out loud (`bearer not set (relying on network policy alone)`) and
 * that sentence was the entire control.
 *
 * A network policy is a real control and it is not the only one this repository trusts elsewhere —
 * the same codebase records that there are two enforcement points and that eBPF bypasses one of
 * them. A default that rests on exactly one, silently, is not the shape the rest of this system
 * takes. `env()` exits when it is missing, so a deployment that forgot it fails at startup where
 * somebody is watching rather than serving the policy to the cluster.
 *
 * Read from a file when one is named, for the reason `heliopause-manager.ts` gives about its own
 * secrets: env survives in `/proc/<pid>/environ` and in crash dumps. `HELIOPAUSE_POLICY_RENDER_TOKEN`
 * stays accepted because it is the variable `policy-render-guard.ts` allowlists by exact name — see
 * the note there.
 */
const token = process.env.HELIOPAUSE_POLICY_RENDER_TOKEN_FILE
  ? readFileSync(env("HELIOPAUSE_POLICY_RENDER_TOKEN_FILE"), "utf8").trim()
  : env("HELIOPAUSE_POLICY_RENDER_TOKEN");
if (!token) {
  console.error("[policy-render] refusing to start: the configured bearer token is empty");
  process.exit(2);
}

/**
 * Evaluated once per commit, not once per request.
 *
 * ⚠ **This was keyed on the site module's mtime alone, and that was wrong for eleven hours on
 * 2026-08-16.** The comment here asserted that mtime "is what git-sync changes when it lands a new
 * commit". It is not: `git reset --hard` only rewrites files whose *content* changed. Two commits
 * that day touched `policies.json` and nothing else, so `dev.ts` kept the mtime it got when the pod
 * cloned the repo, the key never moved, and the console served the checkout as it stood at pod
 * start — `head.sha` included. The approver read pre-narrowing rules on the screen where they
 * approved the narrowing, and the screen was confident: it printed a generation id, just the wrong
 * one.
 *
 * The intent was always "once per commit", so key on the commit. `policyHead` is one `git rev-parse`
 * and answers exactly that. The file mtimes stay in the key underneath it for the two cases a sha
 * cannot see: a checkout with no git at all (`sha === null`), and an edit that has landed on disk
 * but not in a commit — which is what `dirty` means and what an operator sees mid-edit.
 *
 * The `?v=` on the import specifier is unchanged in purpose: ES modules are cached by URL, so
 * without a moving query a new checkout stays invisible until the process restarts. It reaches the
 * files the module imports only through the resolve hook above — a query on the module alone left
 * `policies.json` at its pod-start content for a month, under this key and this comment.
 *
 * A stale-on-error cache would be wrong here. If the module throws, the console must say so — a
 * screen that keeps drawing the last policy that worked is a screen that lies about what is
 * deployed, and it lies most convincingly right after somebody breaks the policy.
 */
// Keyed by site path, not by name — the single-site case has no name, and the path is what the
// stamp is computed from. One slot for all of them would make every request to a second site a
// miss, which is merely wasteful; a key that drops the site is what serves one VPC's payload under
// another's name, which is the failure this whole change exists to stop.
// ## The cache holds the wire bytes, not a parsed value
//
// It held the object `collectPolicySource` returned, and the first version of the evaluation seam
// kept that while adding a parse in front of it. That combination served **two different payloads
// for one evaluation**: `parsePolicySource` defaults an absent `site.cfg.protectedHosts` by writing
// it **into the value it was given** (`src/policy-source.ts:247`), so the first response — written
// from the bytes — omitted the field and the second — served from the parsed object — carried it.
//
// Bytes remove the question. There is one representation, it is the one that crossed the boundary,
// and a later change that evaluates in a worker returns exactly this type.
//
// @see src/policy-render-service.test.ts "answers the same payload on a cache miss and a cache hit"
const cached = new Map<string, { stamp: string; wire: string }>();

/**
 * The evaluation in progress for each site, keyed like `cached` and holding the stamp it started on.
 *
 * Concurrent cache misses on one stamp used to start one worker each — measured on `d8615ca`: 64
 * concurrent requests after a stamp move ran 64 workers, and a failing site, which is never cached,
 * ran one per request (#117). A miss now joins the evaluation already running for the same stamp.
 *
 * Only the **running** evaluation is shared. A failure is not remembered once it settles, so the next
 * request after it evaluates again, as before; what changes is that everyone waiting on that one
 * evaluation receives its answer, success or failure, instead of starting their own.
 *
 * @see src/policy-render-service.test.ts "concurrent requests share one evaluation"
 */
const inFlight = new Map<string, { stamp: string; answer: Promise<string> }>();

/**
 * What can change what `/source` should answer, in one string — as much of it as this can see.
 *
 * Not "everything", which is what this claimed. It reads the entry module, the allowlisted files, the
 * git sha and the entry module's neighbours; a file the module imports from **outside** its directory
 * is invisible, and breaking one leaves the cache answering 200 with the last good payload. The
 * neighbour scan was added because the narrower version had that failure for any `./helper.ts`.
 *
 * Read the mtimes of the allowed files too, not just the module: the whole defect above was a key
 * that could not see a change to `policies.json`. A path that does not exist contributes `-`, so
 * its appearance and disappearance both move the key.
 */
/**
 * Why a stamp could not be completed, for the refusal to quote.
 *
 * Two unrelated causes used to arrive as the same bare `null`, and the caller reported both as the cap
 * being exceeded — so a permissions fault on a four-file directory told the operator to go and look at
 * a limit that was nowhere near being reached, and the `errno` was discarded by the only code that had
 * it. This file already records two defects of that shape: a `faults` count that disappeared exactly
 * when something was wrong, and a log line that claimed an authorization was "already in force" about a
 * record the kernel had never seen.
 *
 * @see src/policy-render-service.test.ts "refuses a site whose tree is larger than the scan cap"
 * @see src/policy-render-service.test.ts "refuses a site whose tree it could not finish reading"
 */
type ScanFailure =
  | { kind: "overflow"; visited: number }
  | { kind: "unreadable"; at: string; code: string };

/** The reason a refusal quotes, in one sentence an operator can act on. */
function scanFailureReason(failure: ScanFailure): string {
  return failure.kind === "overflow"
    ? `more than ${STAMP_SCAN_CAP} entries beside it, so a change here cannot be noticed`
    : `${failure.at} could not be read (${failure.code}), so a change here cannot be noticed`;
}

/**
 * How many directory entries the stamp will visit before it gives up.
 *
 * Entries, not matching files. Counting matches let a tree of a thousand directories holding one
 * `.ts` file pass the cap untouched while still costing a full traversal on every request, which is
 * the cost the cap exists to bound.
 */
const STAMP_SCAN_CAP = 2_000;

/**
 * A `ScanFailure` instead of a stamp means **no complete stamp**, and carries which of the two reasons
 * it was: the tree has more entries than the scan cap, or a directory could not be enumerated. Either
 * way a change here cannot be noticed, so the caller refuses the site rather than serving it — see
 * `currentSource`. (This said `null`, which is what the function returned before the reason was added to
 * it in this same change.)
 * Returning a placeholder instead froze the key; evaluating without caching leaked the module
 * registry. Both were tried, in that order, and both are recorded there.
 */
function sourceStamp(sitePath: string): string | ScanFailure {
  const head = policyHead(sitePath);
  const dir = dirname(resolve(sitePath));
  const mtime = (p: string): string => {
    try {
      return toText(statSync(p).mtimeMs);
    } catch {
      return "-";
    }
  };
  // ## The entry module is not the only file that changes what it evaluates to
  //
  // This read the entry module, the allowlisted files and the git sha. A policy module's own
  // `import "./helper.ts"` was in none of them, so breaking only the helper left the cache answering
  // **200 with the last good payload** for a site that no longer evaluates — not an outage, a screen
  // that lies about what is deployed, which the comment above `cached` says must never happen.
  // Measured here, and confirmed in the running image by the cluster's operator, who read its
  // `heliopause-policy-render.ts` and found no `readdirSync` — the stamp there is the entry module,
  // the allowlisted files and the sha, and nothing else.
  //
  // The whole directory rather than a dependency graph: Node exposes no import graph for an evaluated
  // module, and policy modules keep their helpers beside them. A helper **outside** this directory is
  // still invisible to the stamp — the known remaining gap, not an oversight.
  //
  // ## Two things the first version of this got wrong, both found by an audit
  //
  // It called `readdirSync(dir, { recursive: true })` and `break`'d at the cap. That bounds the array
  // it builds and **not the walk**: the recursive form returns a materialised array, so the whole tree
  // is read before the loop sees its first entry. The walk below is explicit and stops.
  //
  // And above the cap it substituted the literal `over-400`, a constant — so a tree larger than the cap
  // had a stamp that could never move, and the cache served its first answer forever. That is exactly
  // the defect the neighbour scan exists to fix, reintroduced inside the fix. Above the cap this now
  // refuses to produce a stamp at all and the caller does not cache, which costs an evaluation per
  // request and cannot serve a stale one.
  //
  // @see src/policy-render-service.test.ts "refuses a site whose tree is larger than the scan cap"
  // ## 🔴 `.git` is why this skips dot-directories, and skipping them is why the cap means anything
  //
  // The policy directory is a git checkout. Measured in a real tree: **3,116 entries** with `.git`
  // included and **49** without — 24 of them source files. A cap counted over everything is therefore
  // exceeded on the first request of every ordinary deployment, and the version of this that refused
  // above the cap would have answered 503 for **every site at once**. That is a full console outage,
  // which is worse than the leak it replaced, which was worse than the frozen key before that. Three
  // attempts at this line, each worse than the last, and the thing that settled it was counting the
  // entries in an actual checkout instead of reasoning about a plausible one.
  //
  // What is skipped is **dot-directories and `node_modules`**, and a module importing out of one of
  // those is invisible to the stamp — the same class of gap as a helper outside the directory, stated in
  // the same breath. This did say the skipped paths are "not part of any module graph", which is not
  // true of `.generated/` or a vendored directory and was never true of a dot-**file**: the first
  // version of the predicate ran before the directory check and hid `./.helper.ts` too, which is a legal
  // import the resolve hook versions. Directories only, for that reason.
  //
  // `withFileTypes` reports a symlink as a symlink rather than as what it points at, so
  // `isDirectory()` is false for one and this walk never follows them. That is what makes a cycle
  // impossible here rather than merely unlikely — and it is why a helper reached through a symlink is
  // invisible too.
  const neighbours: string[] = [];
  let visited = 0;
  let overflowed = false;
  const stack = [dir];
  walk: while (stack.length > 0) {
    const here = stack.pop() as string;
    // ## `opendirSync`, not `readdirSync`, and the cap is why
    //
    // `readdirSync` materialises **every** entry of a directory before the loop sees the first one, so
    // the cap bounded the entries this loop processed and not the entries the process allocated. One
    // very wide directory therefore still cost its full enumeration synchronously, which is time
    // `/healthz` spends waiting on a request for a different site. A handle read one entry at a time
    // makes the cap mean what it says.
    let handle: ReturnType<typeof opendirSync>;
    try {
      handle = opendirSync(here);
    } catch (e) {
      // ## 🔴 A directory that cannot be read is not an empty one
      //
      // This used to `continue`, which treated a refused enumeration as "nothing here" and returned a
      // **complete** stamp. A directory can deny enumeration while still allowing a known filename to
      // be opened, so a helper stays importable and becomes unstampable at the same instant — and this
      // function's whole job is to notice when it changes. Fail-open, in the one place that must not.
      //
      // Refusing instead is consistent with the overflow below: no complete stamp, no answer. It does
      // mean a permissions fault anywhere under the policy directory refuses every site sharing it,
      // which is loud — and the alternative is a console that keeps drawing a policy nobody can
      // invalidate.
      //
      // The cause travels with the refusal. Reporting this as the cap being exceeded — which it was, for
      // one release — sends an operator to a limit that may be nowhere near reached. `code` is read
      // defensively because the value is whatever the runtime threw.
      let code: string;
      try {
        const given = (e as { code?: unknown } | null)?.code;
        code = typeof given === "string" ? given : "no errno on the error";
      } catch {
        code = "an error whose code cannot be read";
      }
      return { kind: "unreadable", at: here, code };
    }
    try {
      for (;;) {
        const entry = handle.readSync();
        if (entry === null) break;
        visited += 1;
        if (visited > STAMP_SCAN_CAP) { overflowed = true; break walk; }
        // Directories only. The first version of this line skipped **any** entry whose name began with
        // a dot, which hid `./.helper.ts` as well as `./.git/` — a legal import that the resolve hook
        // versions and this stamp could not see change. Inside the scanned directory, which made it a
        // new defect rather than the stated gap about helpers outside it.
        if (entry.isDirectory()) {
          if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
          stack.push(join(here, entry.name));
          continue;
        }
        if (!entry.isFile()) continue;
        if (!/\.(ts|mts|cts|js|mjs|cjs|json)$/.test(entry.name)) continue;
        neighbours.push(join(here, entry.name));
      }
    } finally {
      // `break walk` leaves through here too, which is the case that would otherwise leak the handle.
      try {
        handle.closeSync();
      } catch {
        // Already closed, or the directory went away mid-walk. Neither changes the stamp.
      }
    }
  }
  if (overflowed) return { kind: "overflow", visited };
  neighbours.sort();
  const scanned = neighbours.map(mtime).join(",");
  const files = [sitePath, ...allowPaths.map((p) => resolve(dir, p))].map(mtime).join(",");
  // The path is in the key, not only in the `Map` bucket it is stored under. Two modules in one
  // directory share a git sha and an allowlist, so the rest of this string is identical for both —
  // and two files written in the same millisecond have the same mtime too. Without this prefix the
  // stamp for `alpha.ts` and `beta.ts` can be byte-identical, and then a cache that keys on the
  // stamp alone answers one site's request with the other's policy. Belt and braces on purpose: the
  // bucket and the stamp each encode the site, so a mistake in either is caught by the other.
  return `${sitePath}:${head.sha ?? "nogit"}:${head.dirty ? "dirty" : "clean"}:${files}:${scanned}`;
}

/** The host ids a rendered site declares, for the zone check. */
function hostIdsOf(site: ScreenSite): string[] {
  const hosts = (site as { hosts?: readonly { id?: unknown }[] }).hosts ?? [];
  return hosts.map((h) => toText(h?.id ?? "")).filter(Boolean);
}

async function currentSource(site: { name: string | null; path: string }): Promise<string> {
  const { name, path: sitePath } = site;
  // ## 🔴 No complete stamp is a refusal, and the first version of this served instead
  //
  // A `ScanFailure` rather than a stamp means a change cannot be noticed — either the tree has more
  // entries than the scan cap, or a directory could not be enumerated, and the refusal below says which.
  // (This said `null`; the reason was added to that return in this same change and the sentence did not
  // follow.) An earlier
  // version of this evaluated anyway and skipped the cache, minting a fresh `?v=` per request so the
  // re-evaluation was a real one — that code is gone, and this paragraph is why it is not coming
  // back. It leaks: ES modules are keyed by URL and never evicted, and a
  // measured 7.32 KiB is retained per distinct URL (Node 26.4, after a forced GC; 4,000 imports of one
  // URL retain nothing). At one poll every few seconds that is hundreds of megabytes a day and then an
  // OOM kill, which at `replicas: 1` takes every co-served console with it.
  //
  // So the defect that fix introduced was worse than the one it closed — a stale policy against no
  // policy at all. Refusing is the third option and the right one: this site answers 503 and says why,
  // nothing new enters the module registry, and a tree this large is a configuration an operator can
  // fix or a cap they can raise.
  //
  // ⚠️ **Its neighbours are not unaffected, and this line used to say they were.** The scan is of the
  // directory, so every site whose module sits in it reaches the same verdict — and in the fleet all
  // three do. An overflow is therefore every console, not one. That is the price of refusing, and it is
  // why the cap sits far above a measured checkout rather than near it.
  const stamped = sourceStamp(sitePath);
  if (typeof stamped !== "string") {
    throw new RealError(
      `${sitePath}: ${scanFailureReason(stamped)} — so this site is refused rather than served from a ` +
        "key that cannot move",
    );
  }
  const stamp = stamped;
  const hit = cached.get(sitePath);
  if (hit && hit.stamp === stamp) return hit.wire;
  // ## The module is evaluated in a worker, and what comes back is text
  //
  // Everything the module can reach now lives in a thread that is terminated after one evaluation:
  // the globals it replaces, the prototypes it poisons, a top-level `while (true) {}`, and the module
  // graph itself, which is what #89 is about. `docs/policy-evaluation-realm-design.md` §4-a has the
  // measurement that chose a worker over `vm`.
  //
  // `src/policy-eval-worker.ts` holds the three lines §3-b measured — a dedicated port, taken before
  // the module is imported, and a captured `postMessage` — and the reasons they are not
  // interchangeable with the obvious alternatives.
  const running = inFlight.get(sitePath);
  // The stamp is part of the match: a request that sees a newer stamp than the running evaluation
  // started on must not be answered from the older one.
  if (running && running.stamp === stamp) return running.answer;
  const answer = (async () => {
    const moduleWire = await evaluateInWorker({ sitePath, label: name ?? label });
    return accepted({ moduleWire, name, sitePath, stamp });
  })();
  const entry = { stamp, answer };
  inFlight.set(sitePath, entry);
  // Removes only its own entry: a newer evaluation may have replaced it. Both handlers, so this chain
  // is never an unhandled rejection; each caller handles the rejection it receives.
  const forget = () => { if (inFlight.get(sitePath) === entry) inFlight.delete(sitePath); };
  answer.then(forget, forget);
  return answer;
}

/** The half of `currentSource` that runs in the parent on what the worker sent: read the module's
 *  half, add everything the renderer reads itself, validate, zone-check, cache. Separated because
 *  every one of those steps can refuse, and the caller turns a refusal into that site's 503. */
function accepted(
  input: { moduleWire: string; name: string | null; sitePath: string; stamp: string },
): string {
  const { moduleWire, name, sitePath, stamp } = input;
  // ## 🔑 Two keys are taken from the worker's message; this side reads the rest
  //
  // A module controls what its worker sends — measured twice: once by replacing
  // `Function.prototype.call` to intercept the send, once by an inherited `Object.prototype.toJSON` that
  // the worker's captured `JSON.stringify` still calls. So the only fields taken from the message are
  // the ones the module is entitled to choose anyway: `site` and the resolver table. `label`,
  // `siteName`, `build`, `repo`, `head` and `files` are taken here from the renderer's configuration and
  // the checkout, and any other key in the message is dropped, so a value placed in the message cannot
  // become one of them.
  //
  // ⚠️ That is about the message. The module runs with this process's filesystem permissions and can
  // write the checkout files read below — measured: a module that wrote into `policies.json` had its
  // text served in `files`. That predates the worker, and closing it is a separate change, #131.
  //
  // @see src/policy-render-service.test.ts "does not take anything but the module's own half from the worker"
  const half = parseWire(moduleWire) as { site?: unknown; services?: unknown } | null;
  if (typeof half !== "object" || half === null || Array.isArray(half)) {
    throw new RealError(`${sitePath}: the evaluation sent something that is not an object`);
  }
  const wire = writeWire(assemblePolicySource({
    module: { site: half.site as ScreenSite, services: half.services as Record<string, never> },
    sitePath,
    allowPaths,
    label: name ?? label,
    siteName: name ?? undefined,
  }));
  // ## Validated with the manager's own reader, and the result is thrown away
  //
  // `parsePolicySource` is what the far side runs on this payload, so running it here means the
  // renderer refuses the shapes its reader would — a function on `site`, a non-array `repo.probes` —
  // at the site that produced them rather than at the far end of a request.
  //
  // 🔴 **The parsed value is discarded on purpose.** It is not the same value: that function defaults
  // an absent `site.cfg.protectedHosts` by writing into what it was given
  // (`src/policy-source.ts:247`). Caching or serving it would ship a field the evaluated bytes do
  // not have — which is exactly the two-different-payloads defect the cache comment describes. The
  // call is a gate, not a conversion.
  //
  // ⚠️ That in-place default is a defect in its own right on the manager's side; it is filed rather
  // than fixed here (#123), because that function has callers this change does not survey.
  //
  // 🔴 **Calling it here is a behaviour change, and naming it took a review.** A payload that
  // serialises but fails validation — `cfg.protectedHosts: "bad"` is a string, so it writes fine and
  // `parsePolicySource` refuses it (`src/policy-source.ts:245`) — used to be served with a 200 and
  // rejected at the far end. Now this site fails here: `/source` answers 503, readiness counts it as
  // not serving, and startup verification reports it. That is the intended direction — "healthy and
  // unconsumable" is the state a validator exists to prevent — but it is a third change in behaviour,
  // not a refactor.
  //
  // ⚠️ The parsed value is no longer *only* discarded — the zone check below reads host ids off it.
  // The sentence above still holds for what gets cached and served: those are the bytes.
  //
  // @see src/policy-render-service.test.ts "no guard had named" — shape `serialisableButInvalid`
  const parsed = parsePolicySource(parseWire(wire));
  // ## The zone check reads the wire, because the worker's realm belongs to the module
  //
  // This check used to run in the parent on the module's own `site` object, before collection. Now
  // that the module is evaluated in a worker, running it *there* would put it in a realm the module
  // controls: `hostIdsOf` reads `site.hosts[].id`, and a getter — or a replaced `Array.prototype` —
  // makes it pass, after which the worker reports success and the parent has no reason to doubt it.
  //
  // So it runs here, on the parsed wire, where the values are data: serialisation leaves no getters
  // and no functions behind. @see src/policy-render-service.test.ts "a module that forges its host
  // ids through a getter is still refused"
  //
  // ⚠️ **The cost is that a wrong-zone module is now collected before it is refused**, where it used
  // to be refused first. A zone mismatch is a misconfiguration rather than a request-path cost, and
  // the wasted work is what buys a refusal the module cannot talk its way out of. It is a behaviour
  // change, not a refactor. @see docs/policy-eval-worker-notes.md
  const wrongZone = name === null
    ? null
    : zoneMismatch({ target: name, hostIds: hostIdsOf(parsed.site as ScreenSite) });
  if (wrongZone) throw ownZoneMismatch(wrongZone);
  cached.set(sitePath, { stamp, wire });
  log(`evaluated ${name ?? label} at ${parsed.head.sha ?? "unknown"}${parsed.head.dirty ? " (dirty)" : ""}`);
  // ## Serialised here, and the caller receives bytes
  //
  // `collectPolicySource` applies `toWire` to `site` and to the resolver results, and to nothing
  // else: `repo.probes` is carried in as `readCoverageProbes` returned it, past that conversion
  // (`src/policy-source.ts:437`). So "a `PolicySource` holds only JSON-representable values" is
  // false, and each attempt to say how far the conversion reaches was wrong one step further along.
  // Serialising the **whole** outgoing value here removes the question: there is no partial answer
  // left to give, so no later step has to re-derive which half already crossed.
  //
  // It is also where a serialisation failure now lands. Whatever cannot be written here fails **this
  // site, at evaluation**, instead of reaching the cache and throwing later in `send` on a request
  // unrelated to the commit that introduced it.
  //
  // ⚠️ That is **one of three** behaviour changes here; the others are the validator below and the
  // `.then` poisoning this seam closes on this path. All three are named in the commit message.
  //
  // ## Three **observed** triggers — the list is not closed, and saying it was is how this comment
  // has been wrong twice
  //
  // 1. **A poisoned `Object.prototype.toJSON`.** `JSON.stringify` calls a `toJSON` it finds on the
  //    value, inherited ones included, so capturing the function does not close this.
  // 2. **A replaced `JSON.parse`.** `readCoverageProbes` reads `coverage-*.json` with an
  //    **uncaptured** `JSON.parse` (`src/policy-screen.ts:146`), so a module that replaces the global
  //    chooses what a probe contains — a `BigInt` survives collection and throws here.
  // 3. **`Array.prototype.toJSON`**, replacing nothing in (1) or (2):
  //
  //        Array.prototype.toJSON = function (key) { return key === "probes" ? 1n : this; };
  //
  //    Measured through the renderer: collection succeeds, serialisation throws, **both** sites
  //    answer 503.
  //
  // 🔴 **Each version of this comment named the triggers it knew and read as a complete list.** First
  // "a probe file cannot be the trigger" — backed by a correct measurement (values from the original
  // parser all stringify) and a wrong conclusion, because **the parser is replaceable**. Then "two
  // things", which (3) refutes. Independent review produced both counterexamples.
  //
  // 🔑 So the thing to carry is the **shape**, not the list: `JSON.stringify` asks the value — and
  // everything the value inherits from — for a `toJSON`, and every prototype in that chain is
  // something a module in this realm can write. Any new entry here is another instance of that, not
  // a new kind of problem. **The list stays open on purpose.**
  //
  // ⚠️ **Only the first has a test here.** `poisonedToJSON` is a shape in the matrix below; the
  // replaced-parser case is measured (a global swap does reach `readCoverageProbes`, and the probe
  // comes back holding a `BigInt`) but **no test drives it through this renderer** — the fixture
  // that should have left `/source?site=beta` at 503 answered 200, and why is unresolved. Filed as
  // **#126** with the hypotheses rather than left as a claim with nothing holding it.
  //
  // @see src/policy-render-service.test.ts "no guard had named" — shape `poisonedToJSON`
  //
  // @see src/policy-render-service.test.ts "survives a module that replaces the globals it will be described with"
  return wire;
}

/**
 * How long a worker is kept alive after it has answered.
 *
 * ## Why it is not zero
 *
 * A module that returns a correct value and then throws from a timer is visible today: the
 * `uncaughtException`/`unhandledRejection` handlers above count it in `faults`, log it, and keep
 * serving. Terminating the moment the result arrives would **lose that**, which makes moving to a
 * worker a change that removes a signal the operator has now. This window carries it over: a late
 * failure inside it is counted and logged, and the answer already given does not change.
 *
 * ## Why this number, and what it does not claim
 *
 * 🔴 **It is a choice, not a measurement.** One observation exists — design §3-b ④: against a module
 * with a 200 ms timer, terminating at 50 ms saw no `error`, and staying up 600 ms saw it. **That is a
 * single data point**, and the distribution is unknown. "1,000 ms catches most of them" has not been
 * measured and is not claimed here.
 *
 * 🔴 **No value catches all of them** — a module can arm a timer for any delay. So read this as how
 * much is being spent, not as what is being caught.
 *
 * It does not add to response latency: the answer is sent as soon as a valid result arrives. What it
 * delays is reclaiming the thread, so the cost lands on concurrent worker count and memory — which is
 * why there is a counter below and why the cap itself is #117's to set.
 */
const WORKER_GRACE_MS = 1_000;

/**
 * The worker's entry file, resolved from this one.
 *
 * Not a bare `"../src/policy-eval-worker.ts"` string: `new Worker(path)` resolves a relative path
 * against the **process's** working directory, not this module's, so the renderer would find it only
 * when started from the repository root. The runtime image copies `src/` and `bin/` side by side
 * (`packaging/Dockerfile.manager`), and `import.meta.url` is the one value that holds in both.
 */
const WORKER_ENTRY = new URL("../src/policy-eval-worker.ts", import.meta.url);

/**
 * Workers alive right now, including ones inside their grace window.
 *
 * 🔑 **Counted rather than capped, on purpose.** A cap needs a number, and the number depends on the
 * deployment's memory limit — `resourceLimits` bounds one worker's heap while the container bounds the
 * whole process, and this repository cannot read that manifest (it is `stardust-deploy`'s, and the
 * cost of confusing "configured" with "running" is recorded in `AGENTS.md`). So the order is: count
 * first, read the maximum from operations, then choose. Capping first would put a number I invented
 * into production without a measurement.
 *
 * ⚠️ **Until then there is no cap.** Startup evaluates every site at once (four today). On the request
 * path, concurrent cache misses on one stamp share one evaluation (`inFlight`), so a burst no longer
 * spawns one worker per request — but a site that keeps failing still evaluates again on each request
 * after the shared one settles, and a moved stamp starts a new evaluation while the old one may still
 * be inside its grace. @see #117
 */
let workersAlive = 0;
/**
 * Evaluate one policy module in a worker and return the bytes it produced.
 *
 * The three lines §3-b measured live in `src/policy-eval-worker.ts`; the lifecycle — which signal is
 * the result, what happens when more than one arrives, when the thread is reclaimed — lives in
 * `src/policy-eval-lifecycle.ts`, where it takes the thread as an argument so a test can produce event
 * orders a real worker produces 1 time in 2,000.
 *
 * @see src/policy-render-service.test.ts "a module that spins forever fails only its own site"
 */
function evaluateInWorker(task: { sitePath: string; label: string }): Promise<string> {
  return evaluateWithLifecycle({
    // The port is **not** in `workerData` — a module reads `workerData` and posts on the port itself,
    // which §3-b ② measured arriving at the parent. The path and nothing else goes in it; the label,
    // name and allowlist were never the module's to see, and the parent fills them in (see `accepted`).
    spawn: () => new Worker(WORKER_ENTRY, { workerData: { sitePath: task.sitePath } }),
    budgetMs: SOURCE_SITE_BUDGET_MS,
    graceMs: WORKER_GRACE_MS,
    sitePath: task.sitePath,
    label: task.label,
    onLateFault: (thrown) => noteLateFault(task.label, thrown),
    log,
    onAlive: (delta) => { workersAlive += delta; },
    reasonOf,
  });
}

/** A fault that arrived after its site had already answered. Counted the same way the in-process
 *  handlers count one, so the signal the grace window exists to keep looks the same from outside. */
function noteLateFault(which: string, thrown: unknown): void {
  faults += 1;
  console.error(
    `[policy-render] ${oneLine(`${which}: a fault arrived after the answer (#${faults}) — the answer stands: ${reasonOf(thrown)}`)}`,
  );
}

/**
 * How long one readiness answer stands, and how long a single site gets to produce one.
 *
 * The memo window is what keeps `/readyz` O(1) under repetition: `currentSource` runs two
 * synchronous `git` calls per site before it ever reaches its own cache, so an ungated loop over
 * this route is a loop of `execFileSync` on the only event loop this process has. Two seconds is far
 * below the policy checkout's own sync interval, so nothing observable is lost.
 *
 * The per-site budget exists because a policy module is attacker-reachable code that runs at import.
 * `await new Promise(() => {})` at its top level never settles, and without a bound the whole route
 * never answers: the socket stays open, `/healthz` stays green, and the state this endpoint was
 * built to report arrives as **silence** — strictly worse than the 503 it exists to send. A site
 * that cannot answer inside the budget is not serving, which is not an approximation.
 */
const READY_MEMO_MS = 2_000;
// Larger than the two request-path budgets **at their defaults** — not by construction; `min: 100`
// lets an operator set this below either of them, and nothing here stops that because a small startup
// budget is a legitimate choice for a small tree. What the default expresses is that this is the
// first, cold import of each module, and being slow
// at boot is not the failure being bounded here — never settling is.
//
// Through `boundedInteger` like every other number this file reads, and **not** through a local
// `Number(...)` guard, which is what it was. That guard admitted `2147483648`, which `setTimeout`
// clamps to one millisecond: the largest-looking value became the smallest possible budget while
// the timeout text still quoted what the operator asked for. See the entry in `ENV_BOUNDS`.
//
// 🔴 **A bad value now refuses to start, and the comment this replaced promised it would not.** It
// said *"a typo in it must not become a second way to lose the renderer"*, and that was written
// against `NaN` and negatives — which the old guard did handle — not against the garbage that
// actually got through. Giving up the fallback is the deliberate half of the trade: a value outside
// the range is a value whose effect the operator cannot predict, and this file's answer to that
// everywhere else is to refuse rather than to substitute. What is **not** acceptable is refusing
// badly, which is what the first version of this did — an uncaught `EnvSpecError`, exit 1, and a V8
// stack naming `env-spec.ts` instead of the manifest line. Wrapped like `port` above, it refuses in
// this service's own vocabulary with the same exit code as every other refusal here.
let STARTUP_SITE_BUDGET_MS: number;
try {
  STARTUP_SITE_BUDGET_MS = boundedInteger(
    "HELIOPAUSE_POLICY_STARTUP_BUDGET_MS",
    process.env["HELIOPAUSE_POLICY_STARTUP_BUDGET_MS"],
    ENV_BOUNDS.HELIOPAUSE_POLICY_STARTUP_BUDGET_MS,
  );
} catch (error) {
  console.error(`[policy-render] ${(error as Error).message}`);
  process.exit(2);
}

/**
 * The request path's budget, which has to stay **below the manager's own client timeout**.
 *
 * `/source`'s 503 carries the sentence the console shows instead of an empty page, and that sentence
 * only reaches anyone if this side gives up first. At `READY_SITE_BUDGET_MS` it did not — that is
 * 5000, and so is the manager's `AbortSignal.timeout(HELIOPAUSE_RELAY_TIMEOUT_MS)` default, applied
 * before it connects, so the caller's clock always started first.
 *
 * ⚠️ **This was then `Math.floor(ENV_BOUNDS.HELIOPAUSE_RELAY_TIMEOUT_MS.fallback * 0.8)` with a
 * comment claiming "raising the relay timeout raises this with it". That coupling does not exist.**
 * The manager's timeout is a value in the *manager's* environment; what this read was a compile-time
 * default, so nothing an operator sets moves this number — including setting that very variable here,
 * measured. A reader would have gone looking for a lever that is wired to nothing.
 *
 * It is an env of its own now, so an operator who lowers one can lower the other. That is a knob, not
 * a guarantee: the only correct form is the caller sending its deadline and this side budgeting
 * against what it was told, which is a change to two services and is not in this one.
 */
let SOURCE_SITE_BUDGET_MS: number;
try {
  SOURCE_SITE_BUDGET_MS = boundedInteger(
    "HELIOPAUSE_POLICY_SOURCE_BUDGET_MS",
    process.env["HELIOPAUSE_POLICY_SOURCE_BUDGET_MS"],
    ENV_BOUNDS.HELIOPAUSE_POLICY_SOURCE_BUDGET_MS,
  );
} catch (error) {
  console.error(`[policy-render] ${oneLine((error as Error).message)}`);
  process.exit(2);
}

// ## Why these two are asserted and `port` is not
//
// `port` is read in straight-line code, so TypeScript's definite-assignment analysis covers it: soften
// `process.exit(2)` to `process.exitCode = 2` and the compiler says `TS2454: used before being
// assigned`. Both budgets are read **only inside closures**, and TS does not run that analysis into a
// closure — demonstrated on a minimal file, the `port` shape errors and the closure shape does not.
// The same softening would leave these `undefined`, and `setTimeout(fn, undefined)` fires at **1ms**
// with the message reading `did not finish within undefinedms`: round two's silent-1ms budget,
// restored, with no compiler signal and a message that names the bug. Cheap insurance for a failure
// whose only symptom is a number.
// Declared after the assertion below would be neater, but it has to follow `SOURCE_SITE_BUDGET_MS`
// and the compiler is emphatic about that — this line read above its source for one revision and
// `tsc` gave both `TS2448` and `TS2454` immediately. That is the straight-line protection the two
// budgets above do **not** get, since they are only read inside closures; the contrast is the reason
// the loop below exists at all.
//
// Same number as `/source`, and for the same reason rather than by coincidence. This was a literal
// `5_000` — the relay timeout's own default — which is precisely the collision `/source` was changed
// to avoid, left sitting on the neighbouring route. Nothing polls `/readyz` today, so there is no
// live victim; but `readiness()` waits on every site, so the first thing that polls it with the relay
// timeout inherits the identical race. Fixing one route and leaving its neighbour is how the same
// defect gets rediscovered.
const READY_SITE_BUDGET_MS = SOURCE_SITE_BUDGET_MS;

for (const [name, value] of [
  ["HELIOPAUSE_POLICY_STARTUP_BUDGET_MS", STARTUP_SITE_BUDGET_MS],
  ["HELIOPAUSE_POLICY_SOURCE_BUDGET_MS", SOURCE_SITE_BUDGET_MS],
] as const) {
  if (!Number.isInteger(value)) {
    console.error(`[policy-render] refusing to start: ${name} resolved to ${String(value)}, not an integer`);
    process.exit(2);
  }
}

let readyMemo: {
  /** `null` while in flight — an unsettled answer is shared regardless of age, never expired. */
  settledAt: number | null;
  answer: Promise<{ serving: number; total: number }>;
} | null = null;

/**
 * `currentSource`, or a rejection once the budget is spent.
 *
 * ⚠️ **Not "never hangs", which is what this said.** The budget is a timer, and a timer cannot
 * preempt synchronous code. `while (true) {}` at a policy module's top level blocks the event loop,
 * so the callback that would reject never runs: measured, the process stays alive and answers
 * nothing at all — no listener if it happens at startup, and no `/healthz` either way, so the
 * liveness probe kills the pod and the next one does the same. Measured against `origin/main` of
 * this repository; not separately checked in the running image.
 *
 * There is no fix for this in the same realm, which is why the sentence is a warning rather than a
 * TODO: interrupting the module means evaluating it somewhere with its own event loop — a
 * `worker_thread` or a `vm` context. That is also the boundary the intrinsic captures above are
 * explicitly *not*. The budget still does what it says for a module that hangs **asynchronously**,
 * which is the common case and the one the test covers.
 *
 * @see src/policy-render-service.test.ts "answers even when a site module never settles"
 *
 * Used by the readiness route *and* by the startup verification, because the unbounded wait is worse
 * at startup: a module that never settles there means `server.listen` is never reached, so the
 * process answers nothing at all — not even `/healthz` — and the only evidence is a pod that never
 * becomes ready. A test for the route found that by failing with "the renderer exited with 13 before
 * listening", which is the shape of the bug rather than a flaw in the test.
 */
function evaluateWithin(
  site: { name: string | null; path: string },
  budgetMs: number,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    // ## Deliberately **not** `unref`'d, and the first draft was
    //
    // At startup this is awaited at the module's top level. An `unref`'d timer does not hold the
    // event loop open, so with the only other pending work being an import that never settles, Node
    // finds nothing to do and exits **13** — "unsettled top-level await" — before the budget can
    // fire. The bound was there and could not reach: the process still answered nothing, which is
    // the exact failure it was added to prevent, arriving through the mechanism meant to prevent it.
    //
    // Holding the loop open costs at most one budget, and the timer is cleared on every normal path,
    // so a fast answer leaves nothing behind.
    const timer = arm(
      () => reject(new RealError(`evaluation did not finish within ${budgetMs}ms`)),
      budgetMs,
    );
    void currentSource(site).then(
      // No `try` around `resolve`. Resolving an object does read `.then` off it, and a module can
      // make that throw — but `currentSource` resolves its own object first, so its promise rejects
      // and this handler is never entered. Written, then deleted when no mutation could make it fire.
      (wire) => { disarm(timer); resolve(wire); },
      // `asError`, not a cast. `throw null` in a policy module rejected the import with `null`,
      // which `/source`'s handler then read `.message` off — a `TypeError` in a rejection handler,
      // so an unhandled rejection, so **exit 1 on the first request**. The startup loop had its own
      // `asError` and survived, which made it worse: the pod passed both probes and died when the
      // manager asked for policy, so the crashloop was driven by ordinary polling. Every consumer of
      // `currentSource` comes through here, which is why the normalisation belongs here and not at
      // the four places that read `.message` — the same "second path a per-call-site fix forgets"
      // this file noted about `console.error` one commit earlier, repeated.
      // A throw *in this handler* is an unhandled rejection, so the process would be gone — which is
      // exactly what a module that replaced `globalThis.Error` achieved through `asError`, measured as
      // exit 1 during the startup loop. The fix is that `asError` cannot throw: every inspection in it
      // is wrapped, `typeof` has no trap, and the constructor is captured before the first import. A
      // `try` here as well was written and then deleted — no mutation could make it fire, and a guard
      // no test can reach also hides the code it wraps from single-point mutation.
      (e: unknown) => { disarm(timer); reject(asError(e)); },
    );
  });
}

/**
 * Whether each site can be evaluated right now, bounded and memoised.
 *
 * This said "never rejects", which was true of the per-site failures it was written for — each one is
 * caught below — and false of the collection. Resolving the answer reads a `then` a policy module can
 * poison, so `/readyz` handles a rejection as well as an answer; without that it was exit 1 on the
 * readiness probe, i.e. on a schedule.
 *
 * ## The window runs from when the answer *settled*, not from when it started
 *
 * Stamped at the start, an evaluation slower than the window was stale the moment it finished and
 * was served to nobody: measured against one never-settling site, a caller arriving at +2.5s found
 * the memo already expired and began its own full five-second evaluation, so the process carried
 * two and then three concurrent evaluations — each opening with two synchronous `git` calls per
 * site — for an answer it already had in flight. The slow case is the only case this memo exists
 * for, and it was the one case it could not memoise.
 *
 * An in-flight answer is shared regardless of age (that half was always right and is kept): callers
 * queue behind it rather than starting rivals. The age test applies to a *settled* answer, which is
 * the only kind that can be stale.
 */
function readiness(): Promise<{ serving: number; total: number }> {
  if (readyMemo && (readyMemo.settledAt === null || readClock() - readyMemo.settledAt < READY_MEMO_MS)) {
    return readyMemo.answer;
  }
  // Not `Promise.all`: it resolves an array, and an array inherits a `then` a policy module can
  // poison — see the startup loop. The per-site promises resolve booleans, which are primitives and
  // run no thenable check at all, so only the collection had to change. Started before any is
  // awaited, as before.
  const started = sites.map((site) => evaluateWithin(site, READY_SITE_BUDGET_MS).then(() => true, () => false));
  const answer = (async () => {
    let serving = 0;
    for (const one of started) if (await one) serving += 1;
    // A plain object, deliberately. Resolving it reads `.then`, which a module can poison, and a
    // `__proto__: null` literal here would dodge that — but `/readyz` already answers the resulting
    // rejection, so both together meant reverting either one left every test green. One guard, the
    // general one, is worth more than two that hide each other from a mutation check.
    return { serving, total: started.length };
  })();
  const memo: { settledAt: number | null; answer: typeof answer } = { settledAt: null, answer };
  readyMemo = memo;
  // Both handlers, not just one. Every per-site promise is caught above, so `answer` rejects only if
  // the collection itself fails — which it can: resolving the answer reads a `then` a module may have
  // poisoned. With one handler that rejection was unhandled, and a `void`ed unhandled rejection is
  // exit 1. Stamping on either outcome is also correct: a settled failure is as stale as a settled
  // success and must not pin the memo open.
  //
  // The closure stamps **its own object**, not `readyMemo`, so a superseded memo can only mark itself
  // and nothing reads it again. (This said "guarded on identity", which named a `readyMemo === memo`
  // check that is not here and never was; the behaviour was right and the mechanism described was
  // fiction, which is the worse of the two ways to be wrong in a comment.)
  const stamp = (): void => {
    memo.settledAt = readClock();
  };
  void answer.then(stamp, stamp);
  return answer;
}

/**
 * Constant-time, and length-independent — a plain `===` on a bearer leaks its prefix by timing.
 *
 * There is no "no token configured" branch any more. It read `if (!token) return true;`, which is
 * the shape that made an unset variable into an open service; the token is required above, so the
 * only way to reach here is with one to compare against.
 */
function bearerOk(header: string | undefined): boolean {
  const given = (header ?? "").replace(/^Bearer /, "");
  const a = Buffer.from(given);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

// ## Serialising is not safe either, and capturing `JSON.stringify` did not make it safe
//
// `JSON.stringify` calls a **`toJSON` method it finds on the value**, inherited included. So
// `Object.defineProperty(Object.prototype, "toJSON", { value() { throw … } })` in a policy module
// made every response throw — inside the request handler, which is an uncaught exception, so
// **exit 1 on the first request**, `/healthz` included. Capturing the function closed nothing here:
// the hook is on the value, not on the global. Measured here, and confirmed in the running image by
// the cluster's operator: its `send` serialises unguarded and its `/healthz` goes through it.
//
// Two answers. `/healthz` gets a body that was serialised when this file was written, so the liveness
// probe never calls a serialiser at all. Everything else goes through a `send` that falls back to a
// literal: an error code is kept (a 503 stays a 503 and says why it has no body), and a success code
// becomes 500, because a 200 with a literal body would claim an empty policy is the policy.
//
// @see src/policy-render-service.test.ts "answers /healthz when the module poisoned serialisation"
const HEALTHZ_BODY = '{"ok":true}';
// ## The fallback carries `faults` too, because a field that vanishes is read as a zero
//
// This was a constant without it. So under a poisoned `toJSON` — the one condition that reaches this
// body — `/readyz` answered with no `faults` key at all, and an operator checking that field sees
// nothing and concludes there are none. The absence appeared precisely where something was wrong.
// Reported by the operator of the cluster this serves, who had just been bitten by reading a table's
// zero rows as "verified".
//
// Built by concatenation rather than `toJson`: interpolating a **number primitive** uses the spec's
// Number::toString, not `Number.prototype.toString`, so a module cannot hook it — which matters
// because the only way to get here is a module having hooked something.
const unserialisableBody = (): string =>
  '{"error":"the answer could not be serialised","faults":' + faults + "}";

const server = createServer((req, res) => {
  const raw = (code: number, text: string): void => {
    res.writeHead(code, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    });
    res.end(text);
  };
  const send = (code: number, body: unknown): void => {
    let text: unknown;
    try {
      text = toJson(body);
    } catch {
      log(`a response body could not be serialised — answering ${code >= 400 ? code : 500} without it`);
      raw(code >= 400 ? code : 500, unserialisableBody());
      return;
    }
    // ## Not throwing is not the same as producing a body
    //
    // `JSON.stringify` calls the `toJSON` it finds on the value, and an inherited one that **returns
    // `undefined`** makes it return `undefined` rather than raise — so the `catch` above never ran and
    // `res.end(undefined)` went out as a **200 with an empty body** under a JSON content type. The
    // manager then parses nothing and has no error to report. The guard above was written for a
    // throwing hook and the type annotation here said `string`, which was how it read as impossible.
    //
    // @see src/policy-render-service.test.ts "answers nothing rather than an empty body"
    if (typeof text !== "string") {
      log(`a response body serialised to ${typeof text} — answering ${code >= 400 ? code : 500} without it`);
      raw(code >= 400 ? code : 500, unserialisableBody());
      return;
    }
    raw(code, text);
  };

  // ## 🔴 A request target this cannot parse used to end the process
  //
  // `new URL("//[", "http://placeholder")` throws `ERR_INVALID_URL` — `//` makes it
  // protocol-relative, so `[` is read as the start of an IPv6 host and fails. This callback is
  // synchronous, so the throw left `createServer` uncaught: **exit 1**. Before authentication, so
  // `curl 'http://host:9099//['` from anything that could reach the port took the pod down, and at
  // `replicas: 1` with `Recreate` every zone's console went with it. Also `//[::1`, `//%` and
  // `http://[`. Measured on Node 26.4.0; the line is unchanged from `origin/main`, so this is live
  // today rather than something this branch introduced.
  //
  // A malformed target is a client error, so it gets 400 and the process keeps serving.
  let url: URL;
  try {
    url = new URL(req.url ?? "/", "http://placeholder");
  } catch {
    // No detail echoed back: the input is the caller's and there is nothing here worth quoting.
    return send(400, { error: "unparseable request target" });
  }

  // Unchanged on purpose. It answers "the listener is up" and nothing else, because it is wired to
  // this pod's **liveness** probe as well as its readiness one — liveness period 30s × 3, readiness
  // 10s × 3, `replicas: 1`, `strategy: Recreate`. Those five values are **not in this repository**:
  // they were read out of the deployment manifests in `stardust-deploy` by the session that owns
  // them and relayed here on 2026-09-29. Treat them as a citation, not as something this tree can
  // check — if the manifests move, nothing here goes red.
  //
  // Making this one strict would restart the pod for a policy problem, and a policy tree that cannot
  // be cloned does not become clonable by restarting — it becomes a crashloop. `/readyz` below is
  // the strict one, and it is deliberately not a probe.
  //
  // 🔴 **This endpoint's cheapness is load-bearing, and it is why `/readyz` is gated and memoised.**
  // Everything here shares one event loop. A route that does synchronous work holds this one up, and
  // holding it up past `timeoutSeconds` is a liveness failure — so any expensive route is a lever on
  // this pod's life. `/readyz` reached for `currentSource`, which calls `sourceStamp` → `policyHead`
  // → two synchronous `execFileSync("git", …)` per site **before** the cache is consulted, and a
  // review measured 42.7 ms each: thirty concurrent unauthenticated requests held `/healthz` over a
  // second and would have had kubelet kill the container on demand. The fix this comment is pointing
  // at is below; the rule it leaves behind is that nothing reachable without the bearer may call
  // `currentSource` on the request path.
  // Not `send`: the liveness probe must not depend on a serialiser a policy module can hook.
  if (req.method === "GET" && url.pathname === "/healthz") return raw(200, HEALTHZ_BODY);

  // ## Can this process serve any policy at all?
  //
  // `2/2 Running` with every site answering 503 was a real state on 2026-09-29, and nothing in the
  // cluster could say so: `/healthz` returns `{ok:true}` from a listener that has never successfully
  // evaluated anything. This is the sentence that tells "up" from "useful".
  //
  // 🔴 **Not wired to a probe, and that is the decision rather than an omission.** The renderer runs
  // at `replicas: 1` with `strategy: Recreate` (cited, not checkable here — see `/healthz` above), so
  // there is no surge pod: a readiness failure empties the endpoint list and the manager's
  // `GET /source` stops connecting at all. Compare the two failures — serving 503 puts "the policy
  // module could not be evaluated: …" on the console, and an empty endpoint list puts nothing
  // anywhere. **Both are broken; only one of them talks.** The common cause, the render/clone race,
  // was closed by an init container on the deployment side, so wiring this would trade information
  // away in the rare case and buy nothing in the common one.
  //
  // **Two replicas would not change that, and an earlier draft of this comment said they would.**
  // The pods share one policy remote, so a policy fault is *correlated*: both go unready together,
  // the endpoint list empties anyway, and the outage arrives by the route this paragraph refuses.
  // Readiness gating pays only for *uncorrelated* per-pod failure — which was the clone race, and
  // that is already closed. The sentence concluded the opposite of what it reasoned.
  //
  // 🔴 **Behind the bearer, and that is a correction.** It was unauthenticated, on the argument that
  // counts leak nothing. Counts do leak nothing — but *reaching* this route makes the process do
  // work, and `/healthz` above explains why work is the thing that must be gated here. `/sites` is
  // next door for the weaker reason (names); this one is gated for the stronger one. Both controls
  // are kept rather than one: the file already refuses, at the token check below, to rest on a single
  // control silently.
  //
  // **Counts, not names.** Site names are zone names; "2 of 3" says everything a health signal needs
  // and names nothing. Which site is failing is in this process's log and in `/source`'s own 503.
  // `ok` and the status code answer different questions on purpose — the code says "can this serve
  // anything", `degraded` says "is anything dark". A one-VPC outage is the 2026-09-28 shape, and it
  // must not read as plain green to whatever consumes the status line.
  //
  // Evaluated live rather than remembered from startup, within a window: a site that failed to
  // import at boot is fixed by the next git-sync two minutes later, and one that verified then can
  // break the same way, so an answer frozen at startup would be the past wearing the present's
  // clothes. `READY_MEMO_MS` is far shorter than that sync interval, so the answer is live at the
  // only granularity that exists — and it caps the work at one evaluation per window instead of one
  // per request. Not O(1): a sustained poll still costs `elapsed / READY_MEMO_MS` evaluations, which
  // is what an earlier version of this line overclaimed. What it removes is the *rate* lever, which
  // is the one that reached `/healthz`.
  if (req.method === "GET" && url.pathname === "/readyz") {
    if (!bearerOk(req.headers.authorization)) return send(401, { error: "bad or missing bearer" });
    void readiness().then(
      ({ serving, total }) => {
        // One site is enough to be *up*. Refusing while two of three work would let a bad `dev.ts`
        // take prod's and util's consoles down — the trade the startup verification below refused.
        // `workers` is the count `workersAlive` keeps — threads alive now, grace windows included. It
        // is here because the cap on it is #117's to choose and needs an operational maximum to be
        // chosen from (see `workersAlive`). It is also the only outside view of a budget that rejected
        // but did not terminate: the answer is identical either way and only this number differs.
        send(serving > 0 ? 200 : 503, {
          ok: serving > 0, degraded: serving < total, serving, total, faults, workers: workersAlive,
        });
      },
      // `readiness` is documented as not rejecting and that was true of the per-site failures it was
      // written for. It is not true of the collection: a module can poison the `then` that resolving
      // the answer reads. Without this handler that rejection is unhandled and the process exits 1 —
      // on `/readyz`, which is the readiness probe, so on a schedule.
      (e: unknown) => {
        log(`readiness could not be computed: ${reasonOf(e)}`);
        send(503, { ok: false, degraded: true, error: "readiness could not be computed", faults });
      },
    );
    return;
  }

  // Behind the bearer, beside `/source` rather than beside `/healthz`: the site names are the
  // fleet's zone names, which is the same class of information the payload carries.
  if (req.method === "GET" && url.pathname === "/sites") {
    if (!bearerOk(req.headers.authorization)) return send(401, { error: "bad or missing bearer" });
    return send(200, { sites: sites.map((s) => ({ name: s.name, label: s.name ?? label })) });
  }

  if (req.method === "GET" && url.pathname === "/source") {
    if (!bearerOk(req.headers.authorization)) return send(401, { error: "bad or missing bearer" });
    const asked = url.searchParams.get("site");
    const named = sites.filter((s) => s.name !== null).map((s) => s.name).join(", ");
    let site: { name: string | null; path: string } | undefined;
    if (asked !== null && sites.length === 1 && sites[0]!.name === null) {
      // ## One unnamed site: `?site=` is ignored, deliberately
      //
      // `HELIOPAUSE_POLICY_SITE` names nothing, so this process has no claim to contradict — and a
      // manager new enough to send `?site=` talking to a renderer still deployed the old way is the
      // ordinary state during a rollout. A 404 here would mean the manager must be rolled *after*
      // the renderer's env is flipped, which is the reverse of the order that keeps the console up.
      //
      // Nothing is lost: the payload carries no `siteName`, so the manager knows the name was never
      // confirmed, and its own zone rule reads the host ids either way.
      site = sites[0]!;
    } else if (asked !== null) {
      site = sites.find((s) => s.name === asked);
      // 404 and not a fallback. Answering a name this process does not serve with the site it
      // happens to hold is the whole of the 2026-09-28 incident, reproduced inside the renderer by a
      // typo instead of by a manifest.
      if (!site) return send(404, { error: `no site named ${toJson(asked)} here — this renderer serves ${named}` });
    } else if (sites.length === 1) {
      // The old manager's request, and the single-site deployment's. Unchanged.
      site = sites[0]!;
    } else {
      // 🔴 Deliberately dark rather than deliberately wrong. A caller that did not name a site is a
      // caller that cannot tell these apart, and serving the first one would be the incident again.
      // This is what makes the deployment order matter: flip the renderer to several sites before
      // the manager learns `?site=`, and the console goes down until it is rolled.
      return send(400, { error: `this renderer serves ${sites.length} sites — name one with ?site=: ${named}` });
    }
    // Bounded for the reason the paragraph below gives, and bounded **below the caller's own
    // timeout** — see `SOURCE_SITE_BUDGET_MS`. Unbounded, a module that never settles makes this
    // route answer nothing, and "nothing" is the empty page that comment calls the much worse claim;
    // bounded at the same number as the manager's abort, this side loses the race every time and the
    // sentence still never ships.
    void evaluateWithin(site, SOURCE_SITE_BUDGET_MS).then(
      // `raw`, not `send`. The body is already the wire text this evaluation produced; `send` takes a
      // **value** and writes it with the captured `JSON.stringify`, so passing the string there would
      // send a JSON string literal rather than the object. `raw` writes what it is given and sets
      // `content-length` from it — the same path `/healthz` uses for its literal body.
      (wire) => raw(200, wire),
      (e: Error) => {
        // The manager turns this into a 503 with this sentence in it. An empty page there would read
        // as "no policy", which is a different and much worse claim than "the policy will not load".
        const why = reasonOf(e);
        log(`evaluation failed: ${why}`);
        send(503, { error: `the policy module could not be evaluated: ${oneLine(why)}` });
      },
    );
    return;
  }

  return send(404, { error: "this service answers GET /source, GET /sites, GET /healthz and GET /readyz" });
});

// ## Is each module the site it is declared as? Checked before anything is served.
//
// Two failure modes live here and they must not be conflated.
//
// **A name that does not match its module** — `prod-icn-vtr=./dev.ts` — is a *configuration* fact.
// It cannot heal itself; somebody has to edit the Deployment. Refusing to start is right, and it
// matches the three refusals above: a renderer that will not come up costs the console, and coming
// up serving one VPC's firewall under another's name costs the fleet.
//
// **A module that throws when imported** is a *content* fact that changes commit to commit, and it
// is already handled — `/source` answers 503 and the console says so. Refusing to start on it would
// mean a git-sync landing a broken `dev.ts` takes prod's and util's consoles down at the next pod
// restart: a new outage manufactured by the fix. So it is logged and the process keeps listening,
// with that one site answering 503. `currentSource` re-checks the zone on every evaluation, so a
// module that could not be verified here is verified before it is ever served.
// ## Together, not one after another
//
// This was a `for … await`, which made the budget below **additive**: three sites that all hang cost
// three budgets before `server.listen` is reached, and until then nothing answers — `/healthz`
// included, because it does not exist yet. Measured at 2s × 3 = 6.1s, so the three-site deployment
// at the 30s default is ninety seconds dark. The liveness probe this file is careful about is
// 30s × 3, so the serial loop reached the very crashloop the `/healthz` comment argues must never
// be created, by way of the bound added to prevent a worse version of it.
//
// There is no ordering between sites — nothing here reads another site's result — and the same
// `evaluateWithin` is already used in parallel by `readiness()`. One helper with opposite
// concurrency in its two callers, and nothing said so.
//
// ⚠️ **What did change is what runs before a refusal.** Serially, a mismatch on the first site
// exited before the later ones were imported; now every declared module's top level executes and
// only then is the refusal considered. Measured: two misdeclared sites, both modules' side effects
// observed, then exit 2. That is accepted rather than fixed — running policy code is this process's
// whole job and `/source` would run all of them the moment it came up — but it is a widening during
// a boot already known to be misconfigured, and "no ordering between sites" is true of results and
// says nothing about side effects, which is the only thing that moved.
// ## Concurrent, but no array is ever resolved
//
// This was `await Promise.all(sites.map(...))` with the same per-site `try`, and the `try` did not
// help: `Promise.all` resolves its **result array**, an array inherits from `Object.prototype`, and
// a module that poisons `then` makes that resolution throw — outside every per-site handler, so an
// unhandled rejection at the top level and exit 1 before `server.listen`. Each site's promise is
// still started before any is awaited, so the imports still overlap; the results are collected by
// side effect into a plain array this code owns and never hands to a promise.
const failures: { site: (typeof sites)[number]; error: Error }[] = [];
const pending = sites.map(async (site) => {
  // Nothing was declared, so there is nothing to contradict.
  if (site.name === null) return;
  try {
    const wire = await evaluateWithin(site, STARTUP_SITE_BUDGET_MS);
    // Parsed only to count hosts for this line. `evaluateWithin` now carries the wire bytes, and the
    // one thing startup wants from them is a number to print — so the parse is local to the log
    // rather than something the evaluation path hands around.
    log(`verified ${site.name} — ${parsePolicySource(parseWire(wire)).site.hosts?.length ?? 0} hosts`);
  } catch (e) {
    failures.push({ site, error: asError(e) });
  }
});
for (const one of pending) await one;

for (const failure of failures) {
  const { site, error } = failure;
  const why = reasonOf(error);
  if (foundHere(error)) {
    // `oneLine` here too: `why` is built from host ids the policy module declares, so it carries the
    // same forgery channel as any other module-supplied text. `console.error` does not go through
    // `log`, which is exactly the kind of second path a per-call-site fix forgets.
    console.error(`[policy-render] ${oneLine(`refusing to start: ${site.name} is declared for ${site.path}, but ${why}`)}`);
    console.error(`[policy-render]   a zone's name is the last label of every host id under it — one of these is wrong`);
    process.exit(2);
  }
  // 🔴 **Whether the declared-name check ran is carried by the error's class, not guessed from it.**
  //
  // The paragraph above splits configuration faults from content faults, and anything that stops the
  // evaluation merges them: the check happens *after* the import, so a misdeclared site — the case
  // that block says "cannot heal itself" and must refuse — lands here instead of in `exit 2` whenever
  // its module fails first. That silence must not read as a pass, which is what the caveat is for.
  //
  // ⚠️ **This predicate has been wrong twice, once in each direction, and both times because it was
  // inferred instead of carried.** First it was `why.includes("did not finish within")`: that covered
  // only the timeout, so a module that *throws* — the commoner half — kept the plain line and the
  // hole stayed open, and the string was `evaluateWithin`'s own wording, so a module could choose
  // which sentence an operator read. Removing the condition fixed that and broke the other side:
  // `collectPolicySource` runs only *past* the check, so a correctly-declared site with an ordinary
  // `JSON.stringify` cycle was told its declared name might be wrong. `ZoneCheckedError` carries the
  // fact with the failure instead of inferring it from the message.
  //
  // Not fatal, because a slow-but-correct module must not take the pod down — that is the outage the
  // fix would manufacture. Containment is unchanged either way: `currentSource` re-checks the zone on
  // every evaluation, so an unverified site 503s rather than serving the wrong policy.
  // One line, and it says nothing about the declared name.
  //
  // 🔴 **This used to be two lines, and the split is no longer available.** The zone check ran before
  // collection, so a failure after it meant "the name is right, the content broke" — carried by
  // `ZoneCheckedError` — and the other branch said the check had not run. Now the check runs **last**,
  // on the parsed wire (see `accepted`), because a check inside the worker is a check in a realm the
  // module controls. Every content failure therefore happens before it.
  //
  // So the honest message is this one. Mentioning the check at all would re-open the defect an earlier
  // round closed: a module with an ordinary `JSON.stringify` cycle was told its declared name might be
  // wrong, and an operator went to edit a Deployment that was correct. The reason text already says
  // what broke — "Converting circular structure to JSON" does not read as a naming fault.
  //
  // ⚠️ **What is lost is the reassurance**, not the diagnosis: an operator no longer reads "your name
  // is right". The alternative was to have the worker report host ids alongside its failure so this
  // side could still check them, and those ids come from the module's realm — a forged set would
  // print "the name is right" over a name that is wrong, which is the same operator sent to the same
  // wrong place with the sign flipped. A genuine naming fault is still `exit 2` above, precisely.
  //
  // Not fatal, because a slow-but-correct module must not take the pod down — that is the outage the
  // fix would manufacture. Containment is unchanged: `currentSource` re-checks the zone on every
  // evaluation, so an unverified site answers 503 rather than serving the wrong policy.
  //
  // @see docs/policy-eval-worker-notes.md for the decision and what it cost
  log(`${site.name} did not evaluate at startup and will answer 503 until it does: ${why}`);
}

server.listen(port, hostname, () => {
  // The bound port rather than the requested one. They differ when the request was 0, which is how
  // a test gets a port without racing another process for a fixed one — and a line that reports the
  // number it asked for is a line that cannot be used to connect.
  const bound = server.address();
  const at = typeof bound === "object" && bound ? bound.port : port;
  // The `listening on host:port` prefix is parsed by `policy-render-service.test.ts` to learn the
  // port; what follows it is for a person reading `kubectl logs`. Naming every site is how that
  // person tells a three-site pod from a one-site pod without reading the manifest.
  const serving = sites.map((s) => (s.name === null ? s.path : `${s.name}=${s.path}`)).join(", ");
  log(`listening on ${hostname}:${at} — serving ${serving}, editable ${allowPaths.join(", ") || "(nothing)"}`);
  // `/readyz` joined this set in the commit that gated it, and this line did not follow. It is what
  // an operator reads in `kubectl logs` to learn what needs a token.
  log("bearer required on GET /source, GET /sites and GET /readyz");
  // Printed because a knob nobody can observe is a knob nobody can trust. `SOURCE_SITE_BUDGET_MS` has
  // to sit under the manager's own `HELIOPAUSE_RELAY_TIMEOUT_MS` and this process cannot read that
  // variable — it lives in another Deployment — so the operator is the one holding the relationship.
  // Without this line the only way to see which value took effect was to induce the timeout it exists
  // to prevent.
  log(`budgets: ${SOURCE_SITE_BUDGET_MS}ms per site on request, ${STARTUP_SITE_BUDGET_MS}ms at startup`);
});
