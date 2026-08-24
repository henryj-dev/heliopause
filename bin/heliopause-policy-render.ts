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
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { timingSafeEqual } from "node:crypto";
import { boundedInteger } from "../src/env-spec.ts";
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

const sitePath = resolve(env("HELIOPAUSE_POLICY_SITE"));

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
const modelDir = resolve(sitePath, "..", "..", "src");
if (!existsSync(modelDir)) {
  console.error(
    `[policy-render] refusing to start: ${sitePath} is mounted where its own imports do not resolve.`,
  );
  console.error(`[policy-render]   a site module imports the model with ../src, which from there is ${modelDir}`);
  console.error(`[policy-render]   mount the checkout inside this image's directory — /opt/heliopause/policy`);
  process.exit(2);
}
const label = process.env.HELIOPAUSE_POLICY_LABEL ?? "policy";
const allowPaths = (process.env.HELIOPAUSE_POLICY_ALLOW_PATHS ?? "policies.json")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
// Parsed, not coerced. `Number("nine-thousand")` is `NaN`, and `listen(NaN)` throws
// `ERR_SOCKET_BAD_PORT` — loud, but naming neither this variable nor this service. Same rule as
// every other numeric setting; see `boundedInteger`.
let port: number;
try {
  port = boundedInteger("HELIOPAUSE_POLICY_RENDER_PORT", process.env.HELIOPAUSE_POLICY_RENDER_PORT, {
    // `0` lets the kernel choose, which is what `policy-render-service.test.ts` binds.
    min: 0, max: 65_535, fallback: 9099,
  });
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
 * without a moving query a new checkout stays invisible until the process restarts.
 *
 * A stale-on-error cache would be wrong here. If the module throws, the console must say so — a
 * screen that keeps drawing the last policy that worked is a screen that lies about what is
 * deployed, and it lies most convincingly right after somebody breaks the policy.
 */
let cached: { stamp: string; source: PolicySource } | null = null;

/**
 * Everything that can change what `/source` should answer, in one string.
 *
 * Read the mtimes of the allowed files too, not just the module: the whole defect above was a key
 * that could not see a change to `policies.json`. A path that does not exist contributes `-`, so
 * its appearance and disappearance both move the key.
 */
function sourceStamp(): string {
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
  return `${head.sha ?? "nogit"}:${head.dirty ? "dirty" : "clean"}:${files}`;
}

async function currentSource(): Promise<PolicySource> {
  const stamp = sourceStamp();
  if (cached && cached.stamp === stamp) return cached.source;
  // The import specifier still needs a value that moves, and `stamp` is not URL-safe.
  const mod = (await import(`${pathToFileURL(sitePath).href}?v=${encodeURIComponent(stamp)}`)) as {
    site?: ScreenSite;
  };
  if (!mod.site) throw new Error(`${sitePath} does not export \`site\``);
  const source = collectPolicySource({ site: mod.site, sitePath, label, allowPaths });
  cached = { stamp, source };
  log(`evaluated ${label} at ${source.head.sha ?? "unknown"}${source.head.dirty ? " (dirty)" : ""}`);
  return source;
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

  if (req.method === "GET" && url.pathname === "/healthz") return send(200, { ok: true });

  if (req.method === "GET" && url.pathname === "/source") {
    if (!bearerOk(req.headers.authorization)) return send(401, { error: "bad or missing bearer" });
    void currentSource().then(
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

  return send(404, { error: "this service answers GET /source and GET /healthz" });
});

server.listen(port, hostname, () => {
  // The bound port rather than the requested one. They differ when the request was 0, which is how
  // a test gets a port without racing another process for a fixed one — and a line that reports the
  // number it asked for is a line that cannot be used to connect.
  const bound = server.address();
  const at = typeof bound === "object" && bound ? bound.port : port;
  log(`listening on ${hostname}:${at} — site ${sitePath}, editable ${allowPaths.join(", ") || "(nothing)"}`);
  log("bearer required on GET /source");
});
