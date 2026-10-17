// # Whether an import report is safe to cache a render against
//
// `sourceStamp` (`bin/heliopause-policy-render.ts`) walks the site module's directory and skips
// dot-directories, `node_modules` and symlinks, so a file the module imports from **outside** that
// walk — a helper beside the checkout, a file under `.generated/`, a symlink out of the tree — can
// change without the stamp moving. The cache then answers 200 with the last render (#158).
//
// The worker records the URLs the module actually resolved (`src/policy-eval-worker.ts`) and this
// file says whether every one of them is somewhere that stamp can see, or is this renderer's own
// code. An unsafe report is still served — the answer is correct for that request — and the caller
// does not store it, so the next request evaluates again.
//
// ⚠️ **This is not a boundary.** The report is built in the worker, which is the module's realm, so a
// module can omit a URL or invent one. What this catches is an honest policy that imports something
// the stamp cannot see, not a policy written to hide an import.
//
// @see src/policy-import-scope.test.ts

import { realpathSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The directory `sourceStamp` walks for this site module, and the one the import check judges against.
 * One function so the two cannot start from different places.
 *
 * ## The link's directory, not the target's
 *
 * When the site file is itself a symlink (`/x/site.ts → /y/real.ts`), the walk could start from either.
 * It starts from `/x` because the rest of the stamp does: the allowlisted files are resolved against it
 * and the worker's read permission names it. Moving only the walk to `/y` would make a new pair that
 * disagrees. The import check then sees the target's neighbours in `/y` as outside, so an answer that
 * imports one is served and not cached — stricter than the stamp, which fails toward evaluating again.
 * The entry file itself is in the stamp through the link (`statSync` follows it), and the check accepts
 * it by its real path.
 *
 * @see src/policy-render-service.test.ts "does not cache an answer whose symlinked site file imports a neighbour of its target"
 */
export function stampRootOf(sitePath: string): string {
  return dirname(resolve(sitePath));
}

/**
 * The extensions the stamp records mtimes for. A file of any other extension inside the site tree is
 * imported without being in the stamp, so it is not safe to cache against.
 *
 * Kept here, beside `stampSkipsDirectory`, because the two together are the whole of "what the stamp
 * sees" and the renderer reads both from this module. A second copy of either drifts.
 */
export const STAMPED_EXTENSIONS = /\.(ts|mts|cts|js|mjs|cjs|json)$/;

/**
 * Whether `sourceStamp`'s walk descends into a directory of this name.
 *
 * Dot-directories and `node_modules` only. A dot-**file** is not a directory, so it is not skipped —
 * the first version of this predicate ran before the directory check and hid `./.helper.ts`, which is
 * a legal import the resolve hook versions. Symlinks are not a name question: the walk never follows
 * one because `withFileTypes` reports it as a symlink, so `isDirectory()` is false for it.
 *
 * @see bin/heliopause-policy-render.ts `sourceStamp`
 */
export function stampSkipsDirectory(name: string): boolean {
  return name.startsWith(".") || name === "node_modules";
}

/** What the worker reports about one evaluation's imports. `urls` are resolved `file:` URLs. */
export interface ImportReport {
  /** False when the record hit its cap, or a hook threw, or the report itself was unreadable. */
  complete: boolean;
  urls: readonly string[];
}

export interface ImportScope {
  /**
   * The site module's path as configured — a link stays a link. The stamp's root is `stampRootOf` of
   * it, and both it and the root are resolved when a report is judged, not before: a site file that
   * is gone must keep the reason the stamp or the evaluation gives, not a `realpath` error from here.
   */
  sitePath: string;
  /** This renderer's own `src` and `bin`, by real path. A module's `../src` imports land here. */
  ownRoots: readonly string[];
}

/**
 * True when every recorded import is somewhere the stamp can see, or is this renderer's own code.
 *
 * `complete: false`, a report that is not the shape above, any scheme other than `file:` and `node:`,
 * and a `file:` URL that resolves nowhere are all unsafe — the caller serves the answer and does not
 * cache it.
 *
 * `data:` is unsafe too. A data URL carries its bytes in the specifier, so it moves no file the stamp
 * reads, and nothing here shows that a changed data import changes the specifier the report records.
 * Refusing it costs one re-evaluation per request for a policy that uses one; allowing it would cache
 * an answer whose input this cannot see move.
 *
 * A `file:` URL that does not name a local path (`file://host/x.ts`, an encoded `/`) is unsafe as well,
 * not an error: a malformed report keeps the response and only loses the cache.
 *
 * @see src/policy-import-scope.test.ts "allows a node builtin and refuses a data URL, an http URL, a malformed report and an incomplete one"
 * @see src/policy-render-service.test.ts "does not cache an answer whose module imports a data: URL"
 */
export function importsAreReusable(report: ImportReport, scope: ImportScope): boolean {
  if (typeof report?.complete !== "boolean" || report.complete !== true) return false;
  if (!Array.isArray(report.urls)) return false;
  const siteRoot = realpathOf(stampRootOf(scope.sitePath));
  if (siteRoot === null) return false;
  const entry = realpathOf(scope.sitePath);
  const own = scope.ownRoots.map(realpathOf);
  for (const url of report.urls) {
    if (typeof url !== "string") return false;
    if (url.startsWith("node:")) continue;
    if (!url.startsWith("file:")) return false;
    const real = realpathOf(localPathOf(url));
    if (real === null) return false;
    if (real === entry) continue;
    if (own.some((root) => root !== null && below(real, root) !== null)) continue;
    if (!stampRecords(real, siteRoot)) return false;
  }
  return true;
}

/**
 * Whether the stamp's walk from `siteRoot` records the file at real path `real`: it is below the root,
 * no directory between them is one the walk skips, and its own name has a stamped extension.
 *
 * Exported for its test of a root of `/`, which no temporary directory can stand in for — a root that
 * ends in the separator is where a prefix length is off by one.
 */
export function stampRecords(real: string, siteRoot: string): boolean {
  const rest = below(real, siteRoot);
  if (rest === null || rest === "") return false;
  const parts = rest.split(sep);
  if (parts.slice(0, -1).some(stampSkipsDirectory)) return false;
  return STAMPED_EXTENSIONS.test(parts[parts.length - 1] ?? "");
}

/**
 * The path of `real` below `root`, `""` for the root itself, or null when it is not below it — so not
 * `/a/bc` for a root of `/a/b`. `relative` rather than a prefix length, so a root of `/` is one case
 * with the rest.
 */
function below(real: string, root: string): string | null {
  const rest = relative(root, real);
  if (rest === ".." || rest.startsWith(`..${sep}`) || isAbsolute(rest)) return null;
  return rest;
}

/** The local path a `file:` URL names, or `""` — which resolves nowhere — when it names none. */
function localPathOf(url: string): string {
  try {
    return fileURLToPath(url);
  } catch {
    return "";
  }
}

/** The real path, or null when it cannot be resolved — which is itself a reason not to cache. */
function realpathOf(p: string): string | null {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}
