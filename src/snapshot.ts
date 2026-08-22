// Geofeed snapshots — what was fetched, when, and what it hashed to.
//
// `geofeed.ts` decides what a feed's bytes may mean. This module decides *which bytes* a render sees,
// and the answer is never "whatever the URL returns right now".
//
// ## Why a snapshot and not a fetch
//
// A rendered ruleset is content-addressed, and everything downstream leans on that: drift compares a
// hash, H30 compares artifact hashes across generations, the two-person approval flow hashes the
// bundle an operator reviewed. If a render read a live URL, the same policy would produce a different
// ruleset every week — and the change would arrive with **nobody's approval on it**. A third party
// editing a CSV would be editing our firewall.
//
// So the sequence is explicit, per the design note: fetch → diff → approve → apply. This module holds
// the first step's output so the other three have something stable to talk about.
//
// ## Why the last good snapshot is kept
//
// A fetch failure must not become a render failure. "No ruleset" is worse than "a week-old ruleset" —
// the first leaves a host with nothing, the second leaves it with rules that were reviewed. So a
// failed refresh keeps serving the previous snapshot and raises a staleness warning instead.
//
// The one thing that is **not** allowed is a silent substitution: `resolve()` reports the age of what
// it used, and a caller that renders from a stale snapshot without saying so has turned a warning into
// a lie.
//
// ## Purity
//
// No network, no clock, no filesystem in the decision functions. Fetching is injected (`FetchFeed`),
// time is injected (`now`), and persistence is a separate pair of functions at the bottom. The same
// discipline `ResolveCidrs` follows, for the same reason: this must be testable without the internet.

import { createHash } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { FeedError, parseFeed, type FeedLimits, type ParsedFeed, FEED_LIMITS } from "./geofeed.ts";

/** A feed we are willing to fetch. Registered in config, not discovered. */
export interface FeedSource {
  /** Matches the `<feed>` half of a selector, e.g. `cloudflare`. */
  id: string;
  /**
   * One or more URLs, concatenated in order into a single feed document.
   *
   * Plural because the feed this project actually uses is published as two documents — Cloudflare's
   * ingress ranges are `/ips-v4` and `/ips-v6`, and a policy needs both or it silently covers only
   * half the address families. Splitting them into two registered feeds would make the v6 half a
   * separate object that a policy author has to remember to also reference, which is the same class
   * of mistake as validating IPv4 and leaving IPv6 unpoliced.
   *
   * Order is part of the identity: the snapshot hash covers the concatenation, so reordering the list
   * reads as a changed feed. That is correct — it is a different document.
   */
  urls: readonly string[];
  /** Per-feed overrides. Cloudflare's geo CSV needs a far larger cap than its ingress list. */
  limits?: Partial<FeedLimits>;
}

/**
 * One fetched feed, frozen.
 *
 * `hash` covers the **raw bytes**, not the parsed entries. That is deliberate: the point is to detect
 * that the upstream document changed, including in ways our parser ignores (a reordered file, a new
 * comment). A hash of the parse would call those identical and hide the fact that a third party edited
 * the source of our rules.
 */
export interface Snapshot {
  feedId: string;
  /**
   * Every URL that contributed, in the order they were concatenated.
   *
   * Recorded rather than derived from config, because config changes and a snapshot must stay
   * self-describing: a reviewer reading a six-week-old snapshot needs to know what it was fetched
   * from, not what the current config would fetch.
   */
  urls: readonly string[];
  /** ISO 8601, from the injected clock. */
  fetchedAt: string;
  /** `sha256:<hex>` over the raw response body. */
  hash: string;
  bytes: number;
  /** Raw body, kept so a render is reproducible from the snapshot alone. */
  text: string;
  /** Prefixes accepted, for review without re-parsing. */
  prefixCount: number;
  /** How many lines the parser refused. Non-zero is normal; a jump is not. */
  rejectCount: number;
}

/** Snapshot metadata without the body — what a plan or a console row shows. */
export interface SnapshotSummary {
  feedId: string;
  urls: readonly string[];
  fetchedAt: string;
  hash: string;
  bytes: number;
  prefixCount: number;
  rejectCount: number;
}

export function summarise(s: Snapshot): SnapshotSummary {
  const { text: _text, ...rest } = s;
  return rest;
}

/** Fetches a URL's body. Injected — this module does no I/O of its own. */
export type FetchFeed = (url: string) => Promise<string>;

export interface RefreshLimits {
  /**
   * Age at which a snapshot is reported stale.
   *
   * Feeds are registered as "weekly" in the design, so a week plus slack. Staleness is a **warning,
   * never a refusal**: refusing to render from an old snapshot would take the firewall down because a
   * CSV was old, which inverts the risk this whole module manages.
   */
  staleAfterSec: number;
  /**
   * Refuse a refresh whose prefix count moved by more than this fraction of the previous snapshot.
   *
   * The guard the design's rule 4 asks for, expressed relatively rather than absolutely: an absolute
   * cap catches a feed that became huge but not one that became **empty**, and a feed collapsing to
   * three prefixes is the more dangerous direction — it silently narrows a deny list, or empties an
   * allow source and takes a path down. Both directions are checked.
   */
  maxDriftFraction: number;
}

export const REFRESH_LIMITS: RefreshLimits = {
  staleAfterSec: 10 * 24 * 3600,
  maxDriftFraction: 0.5,
};

export type RefreshOutcome =
  /** Fetched and accepted. `changed` is false when the bytes hashed the same as before. */
  | { kind: "fetched"; snapshot: Snapshot; changed: boolean; prior: SnapshotSummary | null }
  /**
   * Fetch or validation failed and the previous snapshot stands.
   *
   * Carries both the reason and what is still being served, because "the refresh failed" and "what is
   * in force right now" are different questions and an operator needs the second one.
   */
  | { kind: "kept"; reason: string; snapshot: Snapshot; ageSec: number; stale: boolean }
  /** Fetch failed and there is nothing to fall back on. The only fatal case. */
  | { kind: "unavailable"; reason: string };

export function hashBytes(text: string): string {
  return "sha256:" + createHash("sha256").update(text, "utf8").digest("hex");
}

function ageSec(s: Snapshot, now: Date): number {
  const t = Date.parse(s.fetchedAt);
  if (Number.isNaN(t)) return Number.POSITIVE_INFINITY;
  return Math.max(0, Math.round((now.getTime() - t) / 1000));
}

/**
 * How far apart two prefix counts are, as a fraction of the first.
 *
 * No guard for `prior === 0`: `parseFeed` refuses a feed with no usable prefixes, so a stored snapshot
 * cannot have a count of zero — and if one somehow did, `n / 0` is already `Infinity`, which exceeds
 * any limit and forces the change through review. A guard was written here first and defect injection
 * showed removing it changed nothing, which is the definition of a check that is not one.
 */
function driftFraction(prior: number, next: number): number {
  return Math.abs(next - prior) / prior;
}

/**
 * Fetch a feed and decide whether the result may replace the current snapshot.
 *
 * `prior` is what is in force now, or null on first fetch. Returns what happened rather than throwing,
 * because every outcome except `unavailable` still leaves a usable snapshot and the caller needs to
 * report which one it used.
 */
export async function refreshFeed(input: {
  source: FeedSource;
  prior: Snapshot | null;
  fetch: FetchFeed;
  now: Date;
  limits?: RefreshLimits;
  feedLimits?: FeedLimits;
}): Promise<RefreshOutcome> {
  const { source, prior, fetch, now } = input;
  const lim = input.limits ?? REFRESH_LIMITS;
  const feedLim: FeedLimits = { ...(input.feedLimits ?? FEED_LIMITS), ...(source.limits ?? {}) };

  const keep = (reason: string): RefreshOutcome => {
    if (!prior) return { kind: "unavailable", reason };
    const age = ageSec(prior, now);
    return { kind: "kept", reason, snapshot: prior, ageSec: age, stale: age > lim.staleAfterSec };
  };

  if (source.urls.length === 0) {
    // A feed with no URLs would fetch nothing, concatenate to the empty string, and be refused by
    // `parseFeed` with a message about prefixes — which points at the feed's contents rather than at
    // the registration that is actually wrong.
    return keep(`feed "${source.id}" has no URLs registered`);
  }

  const parts: string[] = [];
  for (const url of source.urls) {
    try {
      parts.push(await fetch(url));
    } catch (e) {
      // **One failure abandons the whole refresh.** Concatenating the parts that succeeded would
      // produce a feed missing an address family — Cloudflare's list is `/ips-v4` plus `/ips-v6`, so a
      // failed v6 fetch would silently render a policy covering IPv4 only. That renders cleanly, hashes
      // cleanly, and is wrong in the direction this project's default failure mode already leans.
      return keep(`fetch failed for ${url}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  // A separator goes **between** documents, never after the last one. Appending a newline to every part
  // would make a single-URL feed's snapshot differ from the bytes that were served, and then `hash` no
  // longer covers what the upstream published — which is the one thing it exists to cover. Measured while
  // writing this: normalising every part broke two tests that assert the hash of the served body, and the
  // tests were right.
  const text = parts.reduce(
    (acc, p, i) => (i === 0 ? p : acc.endsWith("\n") ? acc + p : `${acc}\n${p}`),
    "",
  );

  let parsed: ParsedFeed;
  try {
    parsed = parseFeed(text, feedLim);
  } catch (e) {
    // A feed that no longer parses is the case the fallback exists for. Rendering nothing because a
    // third party shipped a broken file would be strictly worse than rendering last week's rules.
    return keep(e instanceof FeedError ? `feed rejected: ${e.message}` : `parse failed: ${String(e)}`);
  }

  if (prior) {
    const drift = driftFraction(prior.prefixCount, parsed.entries.length);
    if (drift > lim.maxDriftFraction) {
      return keep(
        `prefix count moved from ${prior.prefixCount} to ${parsed.entries.length} ` +
          `(${Math.round(drift * 100)}%, above the ${Math.round(lim.maxDriftFraction * 100)}% limit) — ` +
          `refusing to adopt it without review`,
      );
    }
  }

  const snapshot: Snapshot = {
    feedId: source.id,
    urls: [...source.urls],
    fetchedAt: now.toISOString(),
    hash: hashBytes(text),
    bytes: Buffer.byteLength(text, "utf8"),
    text,
    prefixCount: parsed.entries.length,
    rejectCount: parsed.rejects.length,
  };

  return {
    kind: "fetched",
    snapshot,
    // Compared on the raw hash, so an upstream reorder counts as a change even though the rendered
    // set is identical. That is the honest answer to "did the document we depend on change".
    changed: prior === null || prior.hash !== snapshot.hash,
    prior: prior ? summarise(prior) : null,
  };
}

/**
 * What a render was given, and how fresh it was.
 *
 * The staleness travels **with the prefixes**. A resolver that returned only the addresses would make
 * "rendered from a snapshot taken three weeks ago" unrepresentable, and that is exactly the fact a
 * reviewer needs when a rule looks wrong.
 */
export interface ResolvedFeed {
  prefixes: string[];
  snapshot: SnapshotSummary;
  ageSec: number;
  stale: boolean;
}

/**
 * The comment line recording which snapshot produced a rule.
 *
 * ## Why this is a comment and not a field
 *
 * The design's rule 7 asks for provenance in the ruleset. It goes in the **text** form only:
 * `rulesetHash` is computed over the JSON artifact (`publish.ts`), so a comment here cannot perturb
 * any host's hash. Adding provenance to the JSON would change every ruleset hash on the fleet the
 * moment this shipped — the same trap that kept `counter` out of the rendered rules (H27).
 *
 * So this is readable by an operator, and invisible to drift. Both are intended.
 */
// 🔴 **Nothing calls this, and that is the honest state of design rule 7 rather than an oversight.**
//
// The rule asks for provenance in the ruleset. This produces the lines and they have nowhere to go:
// the artifact the fleet applies is JSON (`renderHostRulesetJson`), the text form
// (`renderHostRuleset`) takes no provenance argument and no surface renders it, and putting these
// lines in the JSON would change every `rulesetHash` on the fleet the moment it shipped — the trap
// this file's header already names.
//
// Kept rather than deleted because it is correct and tested, and this deployment has no geofeed
// policy at all, so wiring it today would deliver an empty list to a renderer that does not exist.
// Whoever adds the first geofeed rule needs to decide **where an operator reads it**: a metadata
// field beside the ruleset (the plan view can already serve one, see `GET /plans/…/ruleset`) is the
// cheaper answer than reviving a second rendered form of the same rules.
//
// Recorded here so the next reader finds the reasoning instead of a function that looks like the
// rule is handled.
export function provenanceComment(feeds: readonly SnapshotSummary[]): string[] {
  // No early return for the empty case: mapping an empty list already yields `[]`. One was written
  // here first, and defect injection showed removing it broke nothing — the *behaviour* is
  // load-bearing (a host with no geofeed policy must emit no line, or every text ruleset on the fleet
  // changes the moment this ships), but the line was not.
  const sorted = [...feeds].sort((a, b) => a.feedId.localeCompare(b.feedId));
  return sorted.map(
    (s) => `# geofeed ${s.feedId}: ${s.prefixCount} prefixes from ${s.hash} fetched ${s.fetchedAt}`,
  );
}

// ── Persistence ───────────────────────────────────────────────────────────────
//
// Snapshots are **data, not policy**. They live outside `policy/` deliberately: policy is code under
// review with 35% comments carrying the reasons for rules (which is why there is no policy CRUD), and
// a 32MB CSV refreshed weekly is neither. Mixing them would put a machine-written blob in the file a
// human reviews.

/** Where a feed's snapshot is stored under `dir`. */
export function snapshotPath(dir: string, feedId: string): string {
  // The feed id reaches a path, so it is constrained to the same shape `parseSelector` enforces. A
  // feed called `../../etc` would otherwise write outside the store.
  if (!/^[a-z0-9][a-z0-9-]{0,30}$/.test(feedId)) {
    throw new FeedError(`feed id "${feedId}" is not a usable file name`);
  }
  return join(dir, `${feedId}.json`);
}

/** Read a stored snapshot, or null when there is none. */
export async function readSnapshot(dir: string, feedId: string): Promise<Snapshot | null> {
  let raw: string;
  try {
    raw = await readFile(snapshotPath(dir, feedId), "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw e;
  }
  const o = JSON.parse(raw) as Partial<Snapshot>;
  if (typeof o.text !== "string" || typeof o.hash !== "string") {
    throw new FeedError(`stored snapshot for "${feedId}" is missing its body or hash`);
  }
  // Verified on read, not trusted. A snapshot whose bytes no longer match its recorded hash is the
  // same class of finding as H30's artifact-hash contradiction: something edited what we were going to
  // render, and the record of what it was supposed to be is right there.
  const actual = hashBytes(o.text);
  if (actual !== o.hash) {
    throw new FeedError(
      `stored snapshot for "${feedId}" does not match its hash (recorded ${o.hash}, bytes hash ${actual}) — ` +
        `it was modified after it was taken`,
    );
  }
  return o as Snapshot;
}

/**
 * Write a snapshot atomically.
 *
 * Temp file then rename, the same shape `writeBundle` uses: a reader must never see a half-written
 * snapshot, and a crash mid-write must leave the previous one intact — that previous one is the
 * fallback the whole design leans on.
 */
export async function writeSnapshot(dir: string, s: Snapshot): Promise<string> {
  const path = snapshotPath(dir, s.feedId);
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  await writeFile(tmp, JSON.stringify(s, null, 2) + "\n", "utf8");
  await rename(tmp, path);
  return path;
}
