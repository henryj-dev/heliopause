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
// there is no way to render a program without running it — but it runs somewhere it can only reach
// the policy it came from.
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
import { registerHooks } from "node:module";
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { timingSafeEqual } from "node:crypto";
import { boundedInteger, ENV_BOUNDS, parsePolicySites } from "../src/env-spec.ts";
import { zoneMismatch, ZoneMismatchError } from "../src/site-zone.ts";
import { armedReasons } from "../src/policy-render-guard.ts";
import { collectPolicySource, type PolicySource } from "../src/policy-source.ts";
import { policyHead, type ScreenSite } from "../src/policy-screen.ts";
import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();

const log = (m: string): void => console.log(`[policy-render] ${m}`);

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
      console.error(`[policy-render] refusing to start: ${(e as Error).message}`);
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
/**
 * Carry the site module's version onto everything it imports from the policy checkout.
 *
 * ⚠ **`?v=` on the site module alone was not enough, and that was wrong for a month.** ES modules
 * are cached by URL. The moving query re-evaluated `dev.ts`, and `dev.ts` then imported
 * `./policies.json` — the same URL it had always been — and got the copy read at pod start. The
 * stamp moved, the generation id moved, `files` (read from disk) moved, and the rules did not.
 * Found 2026-09-30: three rules added from the console were published, confirmed on every host,
 * and absent from every ruleset. The console edits `policies.json` and nothing else, so every
 * console edit took this path.
 *
 * So a module that was loaded with a `v` passes it to what it imports from the policy tree. The
 * model under `../src` is this image's own code and is not versioned — it does not change between
 * commits, and re-evaluating it would give each commit its own copy of every class the
 * manager-facing code compares against.
 *
 * The tree is compared by **real path**. Node resolves to the real path, so a checkout behind a
 * symlink — macOS's `/var` → `/private/var`, or a sync tool's link — resolves to URLs that a prefix
 * built from the configured path never matches. The first version of this compared against the
 * configured path and did nothing, silently.
 */
//
// ## The boundary is the policy tree, not the importing module's directory
//
// The second version keyed on the parent's directory, and an independent review found two holes in
// it the day after: `sub/a.ts` importing `../up.json` got the pod-start copy, and `../class.ts`
// loaded twice — versioned from the root, bare from `sub/` — so `instanceof` went false on the
// first evaluation. One rule closes both: every file under a site module's own directory gets the
// same `v`, whichever policy module asked for it. `node_modules` is left alone even inside that
// tree; a package is not policy, and re-evaluating it per commit is a class-identity hazard with
// no stale-data benefit.
//
// The roots are real paths, refreshed each time a site is evaluated (`currentSource`), because the
// resolver answers in real paths and a checkout can sit behind a link that is re-pointed.
const policyRoots = new Set<string>();
registerHooks({
  resolve(specifier, context, nextResolve) {
    const result = nextResolve(specifier, context);
    if (!context.parentURL) return result;
    const v = new URL(context.parentURL).searchParams.get("v");
    if (v === null) return result;
    const url = new URL(result.url);
    if (url.protocol !== "file:" || url.searchParams.has("v")) return result;
    if (url.pathname.includes("/node_modules/")) return result;
    if (![...policyRoots].some((root) => url.pathname.startsWith(root))) return result;
    url.searchParams.set("v", v);
    return { ...result, url: url.href };
  },
});

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
const cached = new Map<string, { stamp: string; source: PolicySource }>();

/**
 * Everything that can change what `/source` should answer, in one string.
 *
 * Read the mtimes of the allowed files too, not just the module: the whole defect above was a key
 * that could not see a change to `policies.json`. A path that does not exist contributes `-`, so
 * its appearance and disappearance both move the key.
 */
function sourceStamp(sitePath: string): string {
  const head = policyHead(sitePath);
  const dir = dirname(resolve(sitePath));
  const mtime = (p: string): string => {
    try {
      return String(statSync(p).mtimeMs);
    } catch {
      return "-";
    }
  };
  const files = [sitePath, ...allowPaths.map((p) => resolve(dir, p))].map(mtime).join(",");
  // The path is in the key, not only in the `Map` bucket it is stored under. Two modules in one
  // directory share a git sha and an allowlist, so the rest of this string is identical for both —
  // and two files written in the same millisecond have the same mtime too. Without this prefix the
  // stamp for `alpha.ts` and `beta.ts` can be byte-identical, and then a cache that keys on the
  // stamp alone answers one site's request with the other's policy. Belt and braces on purpose: the
  // bucket and the stamp each encode the site, so a mistake in either is caught by the other.
  return `${sitePath}:${head.sha ?? "nogit"}:${head.dirty ? "dirty" : "clean"}:${files}`;
}

/** The host ids a rendered site declares, for the zone check. */
function hostIdsOf(site: ScreenSite): string[] {
  const hosts = (site as { hosts?: readonly { id?: unknown }[] }).hosts ?? [];
  return hosts.map((h) => String(h?.id ?? "")).filter(Boolean);
}

async function currentSource(site: { name: string | null; path: string }): Promise<PolicySource> {
  const { name, path: sitePath } = site;
  const stamp = sourceStamp(sitePath);
  const hit = cached.get(sitePath);
  if (hit && hit.stamp === stamp) return hit.source;
  // Before the import, so the hook above knows which tree this evaluation may version.
  policyRoots.add(`${pathToFileURL(realpathSync(dirname(resolve(sitePath)))).pathname}/`);
  // The import specifier still needs a value that moves, and `stamp` is not URL-safe.
  const mod = (await import(`${pathToFileURL(sitePath).href}?v=${encodeURIComponent(stamp)}`)) as {
    site?: ScreenSite;
  };
  if (!mod.site) throw new Error(`${sitePath} does not export \`site\``);
  // ## Checked on every evaluation, not only at startup
  //
  // Startup is where a wrong manifest is caught while somebody is watching, but a module that threw
  // at startup was never checked, and a commit can move a host id at any time. This is the gate that
  // holds; the startup one is the one that is loud. Throwing here surfaces as the 503 below, which
  // is the right shape — the module is present and this process will not vouch for it.
  const wrongZone = name === null ? null : zoneMismatch({ target: name, hostIds: hostIdsOf(mod.site) });
  if (wrongZone) throw new ZoneMismatchError(wrongZone);
  const source = collectPolicySource({
    site: mod.site, sitePath, allowPaths,
    // ## The label follows the site once there is more than one
    //
    // `HELIOPAUSE_POLICY_LABEL` is one value for the process, and the console prints it as "which
    // site this is". With several sites that makes every screen say the same thing — pick
    // `prod-icn-vtr` and the header still reads the label somebody wrote for dev, which is the
    // shape of the incident this whole change exists to stop: a page reporting the opposite of
    // what it drew. A named site knows its own name, so it uses it.
    label: name ?? label,
    ...(name === null ? {} : { siteName: name }),
  });
  cached.set(sitePath, { stamp, source });
  log(`evaluated ${name ?? label} at ${source.head.sha ?? "unknown"}${source.head.dirty ? " (dirty)" : ""}`);
  return source;
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
const READY_SITE_BUDGET_MS = 5_000;
// Larger than the request-path budget: this is the first, cold import of each module, and being slow
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
 * The request path's budget, and it must stay **below** the manager's own client timeout.
 *
 * `/source`'s 503 carries the sentence the console shows instead of an empty page, and that sentence
 * only reaches anyone if this side gives up first. At `READY_SITE_BUDGET_MS` it did not: the manager
 * applies `AbortSignal.timeout(HELIOPAUSE_RELAY_TIMEOUT_MS)` — default 5000, the same number — before
 * it connects, so its clock always starts first and always wins. Measured against a seven-second
 * module: the client threw at 5005ms and this process logged its timeout afterwards, to a socket
 * nobody was reading. The change bought a log line and nothing on the wire, and the comment claiming
 * otherwise was the third in this PR to conclude the opposite of its code.
 *
 * Derived rather than written down, so raising the relay timeout raises this with it and the
 * relationship cannot drift into equality again.
 */
const SOURCE_SITE_BUDGET_MS = Math.floor(ENV_BOUNDS.HELIOPAUSE_RELAY_TIMEOUT_MS.fallback * 0.8);

let readyMemo: {
  /** `null` while in flight — an unsettled answer is shared regardless of age, never expired. */
  settledAt: number | null;
  answer: Promise<{ serving: number; total: number }>;
} | null = null;

/**
 * `currentSource`, or a rejection once the budget is spent. Never hangs.
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
): Promise<PolicySource> {
  return new Promise<PolicySource>((resolve, reject) => {
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
    const timer = setTimeout(
      () => reject(new Error(`evaluation did not finish within ${budgetMs}ms`)),
      budgetMs,
    );
    void currentSource(site).then(
      (source) => { clearTimeout(timer); resolve(source); },
      (e: unknown) => { clearTimeout(timer); reject(e as Error); },
    );
  });
}

/**
 * Whether each site can be evaluated right now, bounded and memoised. Never rejects.
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
  if (readyMemo && (readyMemo.settledAt === null || Date.now() - readyMemo.settledAt < READY_MEMO_MS)) {
    return readyMemo.answer;
  }
  const answer = Promise.all(
    sites.map((site) => evaluateWithin(site, READY_SITE_BUDGET_MS).then(() => true, () => false)),
  ).then((results) => ({ serving: results.filter(Boolean).length, total: results.length }));
  const memo: { settledAt: number | null; answer: typeof answer } = { settledAt: null, answer };
  readyMemo = memo;
  // `void` because `answer` cannot reject — every per-site promise is already caught above — so this
  // only ever stamps. The closure stamps **its own object**, not `readyMemo`, so a superseded memo
  // can only mark itself and nothing reads it again. (This said "guarded on identity", which named a
  // `readyMemo === memo` check that is not here and never was; the behaviour was right and the
  // mechanism described was fiction, which is the worse of the two ways to be wrong in a comment.)
  void answer.then(() => {
    memo.settledAt = Date.now();
  });
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

const server = createServer((req, res) => {
  const send = (code: number, body: unknown): void => {
    const text = JSON.stringify(body);
    res.writeHead(code, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    });
    res.end(text);
  };

  const url = new URL(req.url ?? "/", "http://placeholder");

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
  if (req.method === "GET" && url.pathname === "/healthz") return send(200, { ok: true });

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
    void readiness().then(({ serving, total }) => {
      // One site is enough to be *up*. Refusing while two of three work would let a bad `dev.ts` take
      // prod's and util's consoles down — the trade the startup verification below already refused.
      send(serving > 0 ? 200 : 503, { ok: serving > 0, degraded: serving < total, serving, total });
    });
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
      if (!site) return send(404, { error: `no site named ${JSON.stringify(asked)} here — this renderer serves ${named}` });
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
      (source) => send(200, source),
      (e: Error) => {
        // The manager turns this into a 503 with this sentence in it. An empty page there would read
        // as "no policy", which is a different and much worse claim than "the policy will not load".
        log(`evaluation failed: ${e.message}`);
        send(503, { error: `the policy module could not be evaluated: ${e.message}` });
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
const verified = await Promise.all(
  sites.map(async (site) => {
    // Nothing was declared, so there is nothing to contradict.
    if (site.name === null) return null;
    try {
      const source = await evaluateWithin(site, STARTUP_SITE_BUDGET_MS);
      log(`verified ${site.name} — ${source.site.hosts?.length ?? 0} hosts`);
      return null;
    } catch (e) {
      return { site, error: e as Error };
    }
  }),
);

for (const failure of verified) {
  if (!failure) continue;
  const { site, error } = failure;
  const why = error.message;
  if (error instanceof ZoneMismatchError) {
    console.error(`[policy-render] refusing to start: ${site.name} is declared for ${site.path}, but ${why}`);
    console.error(`[policy-render]   a zone's name is the last label of every host id under it — one of these is wrong`);
    process.exit(2);
  }
  // 🔴 **Every failure that is not a zone mismatch means the zone check did not run**, and saying so
  // is the whole of this branch.
  //
  // The paragraph above splits configuration faults from content faults, and anything that stops the
  // evaluation quietly merges them: the check happens *after* the import, so a misdeclared site — the
  // case that block says "cannot heal itself" and must refuse — lands here instead of in `exit 2`
  // whenever its module fails first. Measured: a wrong-zone module that throws at import logged the
  // ordinary "did not evaluate" line and the pod came up, no caveat, zone never examined.
  //
  // ⚠️ **This was a string match on `"did not finish within"` and that was wrong twice over.** It
  // covered only the timeout, so a module that throws — the more common half — kept the plain line
  // and the hole stayed open on the other path. And the string is produced by `evaluateWithin`, so a
  // policy module could pick which sentence an operator reads by throwing that text itself: log
  // forgery in the one process whose premise is that it runs hostile code. There is no condition
  // here now, which is both the correct predicate and nothing for a module to spoof; the `instanceof`
  // above is the only distinction this catch needs, and it is the idiom the file already had.
  //
  // Not fatal, because a slow-but-correct module must not take the pod down — that is the outage the
  // fix would manufacture. Containment is unchanged either way: `currentSource` re-checks the zone on
  // every evaluation, so an unverified site 503s rather than serving the wrong policy.
  log(`${site.name} did not evaluate at startup — the declared-name check did not run for it, ` +
    `and it will answer 503 until it does: ${why}`);
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
});
