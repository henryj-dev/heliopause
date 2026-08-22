/**
 * The line between the process that evaluates the policy and the process that renders it.
 *
 * ## Why there is a line at all
 *
 * The site module is TypeScript, and a TypeScript module's top level is code. The manager used to
 * render the policy screen by importing it:
 *
 *     const mod = await import(`${pathToFileURL(sitePath).href}?v=${stamp}`);
 *
 * which made **a commit to the policy repository arbitrary code execution inside the manager** — the
 * process holding the artifact signing key, the GitHub App key, the OIDC client secret and the relay
 * client certificate, with a git-sync sidecar landing commits without an operator touching anything.
 * That was audit finding C1, and the first fix was to delete the screen. Deleting the screen also
 * deleted the console, which is the thing the console exists to be.
 *
 * So the evaluation moves instead of disappearing. Somebody still has to run the module — but it can
 * be somebody with nothing worth stealing. `heliopause-policy-render` holds a policy checkout and no
 * credential, and hands the result across this file as **data**. The manager renders it with its own
 * code and never imports anything from the policy repository.
 *
 * ## What makes that safe rather than merely rearranged
 *
 * Everything in `PolicySource` is JSON. Measured before this file was written: `buildScreen` over the
 * live `dev.ts` produces a **byte-identical** `Screen` before and after `JSON.parse(JSON.stringify())`
 * of the site, and the site has exactly one function-valued field (`resolveService`), which is
 * carried here as a lookup table instead. There is no serialisation gap to paper over.
 *
 * The manager then treats this payload the way it treats any request body: untrusted input to
 * validate, not a module to trust. `parsePolicySource` is that check, and the escaping in
 * `policy-ui.ts` is what stops a hostile policy id from becoming a script tag — `policy-source.test.ts`
 * has the known positive.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import type { ServiceSelector } from "./cilium.ts";
import type { Commit } from "./history-view.ts";
import type { Probe } from "./coverage.ts";
import { buildId } from "./build-id.ts";
import { generationLabel, policyCommits, policyHead, readCoverageProbes } from "./policy-screen.ts";
import type { RepoFacts, ScreenSite } from "./policy-screen.ts";

/** Bumped when a field changes meaning. A mismatch is refused rather than guessed at. */
export const POLICY_SOURCE_SCHEMA = 1;

/**
 * A rendered-but-not-executed policy, as it travels.
 *
 * The name is what it is: this is the *source* the console reads from, not a copy of the repository.
 * Nothing here is a path — a path would be an invitation for the reader to go and look, and the
 * reader is the process that must not.
 */
export interface PolicySource {
  schemaVersion: number;
  /**
   * Which build of this repository produced the payload. See `build-id.ts`.
   *
   * **Optional, and its absence means something.** A renderer older than 2026-08-18 does not send it,
   * and that is itself the finding — it is at least that far behind. Same shape and same reasoning as
   * `ObservedRoute.origin`, which is absent from agents older than 2026-08-17: adding a required
   * field would have made every deployed renderer fail validation at once, which is a worse outage
   * than the one being reported.
   *
   * Not part of the schema version. `POLICY_SOURCE_SCHEMA` is bumped when a field changes *meaning*,
   * and this one adds a fact without altering any other. Bumping it here would refuse every renderer
   * in the fleet in order to tell somebody that one of them is old.
   */
  build?: string;
  /**
   * What the page calls the site.
   *
   * A label, not a location. The manager's own filesystem has no policy on it, so printing a
   * container path here would name a file that does not exist in the process displaying it.
   */
  label: string;
  /** The site, minus every function-valued field. Validated on arrival, never imported. */
  site: ScreenSite;
  /**
   * `resolveService` as a table.
   *
   * A missing key means `null`, and `null` is not `[]` — "nobody reported this selector" and
   * "queried, and it matches nothing" are different answers that `cilium.ts` renders differently.
   * Only non-null results travel, so the distinction survives the crossing.
   */
  services: Readonly<Record<string, ServiceSelector>>;
  /** What lives beside the site module: probes, history, the generation label. */
  repo: RepoFacts;
  /**
   * The commit a publish would carry, strictly.
   *
   * Separate from `repo.generation` because that one is a *label* and says "abc1234 (uncommitted
   * edits)" on purpose — a read-only page refusing to draw itself over a dirty tree would be useless
   * exactly when it is most useful. Publishing has the opposite rule and refuses a dirty tree
   * outright, so it needs the two facts apart rather than a sentence to parse.
   */
  head: { sha: string | null; dirty: boolean };
  /**
   * The editable files, verbatim, keyed by the path the console is allowed to write.
   *
   * The console's editor needs the current text to put in the textarea. It used to `readFileSync`
   * it beside the site module; the manager has no such file now, so the text travels with everything
   * else. The allowlist is applied where the file is read *and* again where the commit is made —
   * the same list, checked twice, because these two run in different processes and only one of them
   * has a credential.
   */
  files: Readonly<Record<string, string>>;
}

/** Thrown when a payload cannot be trusted to be what it claims. */
export class PolicySourceError extends Error {}

// The annotation is load-bearing, not decoration. TypeScript only lets a never-returning *function
// expression* narrow the code after it when the binding carries an explicit type, so without this
// every `if (!isObject(x)) bad(...)` below leaves `x` as `unknown` and the file stops compiling.
const bad: (why: string) => never = (why) => {
  throw new PolicySourceError(why);
};

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Keys that would write through an object literal into `Object.prototype`.
 *
 * `JSON.parse` itself is safe — it defines own properties rather than assigning — but the values
 * here get spread, indexed and copied downstream, and a lookup built with `obj[key] = value` from a
 * key named `__proto__` is the one place that stops being true. Refused at the door instead of
 * defended at every use.
 */
const POISON = new Set(["__proto__", "constructor", "prototype"]);

function safeRecord(v: unknown, what: string, valueCheck: (x: unknown) => boolean): Record<string, never> {
  if (!isObject(v)) bad(`${what} must be an object`);
  for (const [k, val] of Object.entries(v as object)) {
    if (POISON.has(k)) bad(`${what} may not contain the key ${k}`);
    if (!valueCheck(val)) bad(`${what}.${k} has the wrong shape`);
  }
  return v as Record<string, never>;
}

/**
 * Check a payload well enough to render it, and no further.
 *
 * ## What this does and does not promise
 *
 * It promises the shapes the renderer indexes into: the arrays it iterates are arrays, the strings
 * it prints are strings, the records it looks up cannot poison a prototype. It does **not** promise
 * the policy is sensible, because that is not a property a type check has — a syntactically perfect
 * rule can still open the wrong port, which is what the two-person approval on the bundle hash is
 * for.
 *
 * The reason to stop there rather than validate every field is that this is a **viewer**. A stricter
 * check that refuses to draw the page is a check that hides the policy at the moment somebody is
 * trying to find out what is wrong with it. Anything malformed further in surfaces as a render
 * failure with the renderer's own sentence, which names the field.
 */
export function parsePolicySource(raw: unknown): PolicySource {
  if (!isObject(raw)) bad("expected a JSON object");
  const v = raw as Record<string, unknown>;

  if (v.schemaVersion !== POLICY_SOURCE_SCHEMA) {
    // Named on both sides. A renderer and a manager that disagree here disagree about what a field
    // means, and rendering anyway is how a screen shows a confident wrong answer.
    bad(`policy source schema ${String(v.schemaVersion)} — this manager speaks ${POLICY_SOURCE_SCHEMA}`);
  }
  if (typeof v.label !== "string" || !v.label) bad("label must be a non-empty string");
  // Refused when present and wrong, accepted when absent. An older renderer omits it and must keep
  // working — the point of the field is to describe that renderer, not to lock it out.
  if (v.build !== undefined && (typeof v.build !== "string" || !v.build)) {
    bad("build must be a non-empty string when present");
  }

  const site = v.site;
  if (!isObject(site)) bad("site must be an object");
  const s = site as Record<string, unknown>;
  if (!isObject(s.cfg)) bad("site.cfg must be an object");
  if (!Array.isArray(s.hosts)) bad("site.hosts must be an array");
  for (const name of ["zones", "devices", "objects", "coverage", "workload"] as const) {
    if (s[name] !== undefined && !Array.isArray(s[name])) bad(`site.${name} must be an array when present`);
  }
  // A function cannot survive JSON, so one arriving here means the payload was built in-process by a
  // caller that skipped the wire. That is not an attack, it is a mistake — and it is the mistake
  // this whole file exists to prevent, so it is refused loudly rather than tolerated.
  for (const [k, val] of Object.entries(s)) {
    if (typeof val === "function") bad(`site.${k} is a function — this boundary carries data only`);
  }

  const services = safeRecord(v.services ?? {}, "services", isObject);
  const files = safeRecord(v.files ?? {}, "files", (x) => typeof x === "string");

  const repo = v.repo;
  if (!isObject(repo)) bad("repo must be an object");
  if (!Array.isArray(repo.probes)) bad("repo.probes must be an array");
  if (!Array.isArray(repo.commits)) bad("repo.commits must be an array");
  if (repo.generation !== null && typeof repo.generation !== "string") {
    bad("repo.generation must be a string or null");
  }

  const head = v.head;
  if (!isObject(head)) bad("head must be an object");
  if (head.sha !== null && typeof head.sha !== "string") bad("head.sha must be a string or null");
  if (typeof head.dirty !== "boolean") bad("head.dirty must be a boolean");

  return {
    schemaVersion: POLICY_SOURCE_SCHEMA,
    // Carried through rather than defaulted. `undefined` here is "the renderer did not say", which
    // the console prints as its own sentence; substituting anything would answer for it.
    ...(v.build === undefined ? {} : { build: v.build as string }),
    label: v.label,
    site: site as unknown as ScreenSite,
    services: services as Readonly<Record<string, ServiceSelector>>,
    repo: {
      probes: repo.probes as Probe[],
      commits: repo.commits as Commit[],
      generation: repo.generation as string | null,
    },
    head: { sha: head.sha as string | null, dirty: head.dirty },
    files: files as Readonly<Record<string, string>>,
  };
}

/**
 * The site as `buildScreen` and `planPublish` want it, with the one function put back.
 *
 * Rebuilt from the table rather than carried, which is the whole trick: the caller gets something
 * callable without anybody having evaluated the policy author's code to make it.
 */
export function screenSiteOf(source: PolicySource): ScreenSite {
  const table = new Map(Object.entries(source.services));
  return {
    ...source.site,
    resolveService: (ref: string): ServiceSelector | null => table.get(ref) ?? null,
  };
}

/**
 * Which allowlisted files the console can actually offer, and which one the rule table takes.
 *
 * **A function because it was a subscript.** The console picked `allowPaths[0]` and rendered that,
 * for as long as the editor has existed — so a deployment configured with two editable files offered
 * one, and the second was writable through the API and unreachable from the page. Nothing errored.
 * That is the shape this repository keeps finding: built, configured, and never called.
 *
 * `primary` is the JSON document, wherever it sits in the list, because the rule table is a parser
 * and JSON is what it parses. Order in `allowPaths` is a configuration detail and should not decide
 * which editor an operator gets.
 *
 * A path whose content the renderer could not read is dropped rather than offered empty: an editor
 * over an empty string has a save button that would commit nothing over the real file.
 */
export function editableFiles(
  allowPaths: readonly string[],
  files: Readonly<Record<string, string>>,
): { primary: { path: string; content: string } | null; more: { path: string; content: string }[] } {
  const readable = allowPaths
    .map((path) => ({ path, content: files[path] }))
    .filter((f): f is { path: string; content: string } => f.content !== undefined);
  const primary = readable.find((f) => f.path.endsWith(".json")) ?? readable[0] ?? null;
  return { primary, more: primary ? readable.filter((f) => f.path !== primary.path) : [] };
}

/** How much editable text one file may contribute. A textarea, not a repository. */
const MAX_FILE_BYTES = 1_000_000;

/**
 * Read the half of the policy that is not in the module, and pack it all for the wire.
 *
 * **This is the evaluator's side of the line, and only the evaluator's.** It touches the disk and
 * shells out to git, and the process that calls it is by definition the one holding a policy
 * checkout — which, after C1, is the process that holds nothing else. The manager imports
 * `parsePolicySource` and `screenSiteOf` from this file and must never reach this function; there is
 * a test that fails if it does.
 *
 * Takes an already-evaluated `site` rather than a path to import, so that the one `import()` of
 * untrusted code stays visible in the entry point instead of hiding in a library where a future
 * caller could reach it without noticing what they were doing.
 */
export function collectPolicySource(input: {
  site: ScreenSite;
  sitePath: string;
  label: string;
  allowPaths: readonly string[];
}): PolicySource {
  const { site, sitePath, label, allowPaths } = input;
  const dir = dirname(resolve(sitePath));

  const services: Record<string, ServiceSelector> = {};
  const resolver = site.resolveService as ((ref: string) => ServiceSelector | null) | undefined;
  if (resolver) {
    for (const ref of serviceRefs(site)) {
      const hit = resolver(ref);
      // Only non-null entries travel — see `PolicySource.services` for why the absence has to stay
      // an absence rather than becoming a `null` the far side reads as an answer.
      if (hit) services[ref] = hit;
    }
  }

  const files: Record<string, string> = {};
  for (const path of allowPaths) {
    // The allowlist is what may be edited, so it is also exactly what may be read out. A file that
    // will not read leaves its key out and the console renders read-only for it, rather than
    // offering an editor over an empty string whose save would overwrite the real file with nothing.
    try {
      const text = readFileSync(join(dir, path), "utf8");
      if (Buffer.byteLength(text) <= MAX_FILE_BYTES) files[path] = text;
    } catch {
      // Absent, unreadable, or the sync has not run yet.
    }
  }

  // `JSON.parse(JSON.stringify())` rather than a spread: it is the wire, applied here, so a field
  // that cannot survive the crossing fails in the process that owns the mistake instead of arriving
  // as a silently missing table three seconds later in the manager's log.
  const wire = JSON.parse(JSON.stringify({ ...site, resolveService: undefined })) as ScreenSite;

  const head = policyHead(sitePath);
  // A checkout with a `.git` and no answer from git is a different state from no checkout, and the
  // page cannot tell them apart: both render "no generation" and an empty history, with the other
  // ten sections intact, so nothing looks wrong. Measured 2026-08-16 — the renderer served a
  // complete policy with `generation: null` because the emptyDir's mount root is root-owned and git
  // refused it as `dubious ownership`. Finding that took a shell in the pod. Say it once, here.
  if (head.sha === null && existsSync(join(dir, ".git"))) {
    console.error(
      `[policy-source] ${dir} is a git checkout but git answered nothing — the generation and ` +
        "history columns will be empty. Usually the repository root is owned by another user " +
        "(a Kubernetes emptyDir mount root is root-owned): set safe.directory for this path.",
    );
  }

  return {
    schemaVersion: POLICY_SOURCE_SCHEMA,
    // The renderer naming itself. This is the whole of the fix on this side — the manager can now
    // hold it next to its own and say whether the two processes are the same code.
    build: buildId(),
    label,
    site: wire,
    services,
    repo: {
      probes: readCoverageProbes(sitePath),
      commits: policyCommits(sitePath),
      generation: generationLabel(sitePath),
    },
    head,
    files,
  };
}

/**
 * Everything in a site that could be a service reference.
 *
 * Walks the structure generically — every `{ kind, value }` pair anywhere under the workload set —
 * rather than reaching for the fields the schema has today. A resolver table that silently misses a
 * reference produces `null` at render time, which `cilium.ts` reads as "not known" and draws as a
 * gap in the policy; a table with a few extra keys costs nothing. Between the two failure modes,
 * only one is a wrong answer about a firewall.
 */
export function serviceRefs(site: ScreenSite): string[] {
  const found = new Set<string>();
  const walk = (node: unknown, depth: number): void => {
    if (depth > 24 || node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item, depth + 1);
      return;
    }
    const o = node as Record<string, unknown>;
    if (typeof o.kind === "string" && typeof o.value === "string") found.add(o.value);
    for (const val of Object.values(o)) walk(val, depth + 1);
  };
  walk(site.workload ?? [], 0);
  return [...found].sort();
}
