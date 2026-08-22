#!/usr/bin/env node
// Fetch a registered geofeed and store it as a snapshot.
//
//   heliopause-feed list                          what is registered, and how fresh each snapshot is
//   heliopause-feed refresh <feed-id>             fetch and store, refusing a suspicious change
//   heliopause-feed show <feed-id>                the stored snapshot's prefixes and refused lines
//
// ## Why this is a separate command from publishing
//
// The design's sequence is fetch → diff → approve → apply, and each arrow is a place a human can stop.
// Folding the fetch into `heliopause-publish` would collapse the first two: a render would silently
// adopt whatever the feed says today, and the approval at the end would be an approval of a diff nobody
// saw the inputs of. Keeping this separate means a feed change is its own reviewable event with its own
// timestamp, and the publish that follows renders from bytes that were already on disk.
//
// So this command changes no firewall. It writes a file. The ruleset moves when someone runs
// `heliopause-publish` afterwards, which is the point.

import { resolve } from "node:path";
import { readdir } from "node:fs/promises";
import { FEEDS, feedById } from "../src/feeds.ts";
import { makeFetchFeed } from "../src/feed-fetch.ts";
import { parseFeed, parseSelector, selectPrefixes } from "../src/geofeed.ts";
import {
  readSnapshot,
  refreshFeed,
  writeSnapshot,
  REFRESH_LIMITS,
  type Snapshot,
} from "../src/snapshot.ts";

import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();
const args = process.argv.slice(2);
const flags = new Map(
  args
    .filter((a) => a.startsWith("--"))
    .map((a) => {
      const [k, v] = a.replace(/^--/, "").split("=", 2);
      return [k!, v ?? "true"];
    }),
);
const [cmd, feedId] = args.filter((a) => !a.startsWith("--"));

if (!cmd || flags.has("help")) {
  console.error(
    "usage: heliopause-feed list\n" +
      "       heliopause-feed refresh <feed-id> [--dir=DIR] [--dry-run]\n" +
      "       heliopause-feed show <feed-id> [--dir=DIR] [--select=<feed>:<scope>]\n" +
      "\n" +
      "  list      registered feeds and the age of each stored snapshot\n" +
      "  refresh   fetch and store. Refuses a change large enough to need review.\n" +
      "  show      what the stored snapshot holds, and what it refused\n" +
      "\n" +
      "  --dir=DIR   where snapshots live (default ./snapshots, or HELIOPAUSE_SNAPSHOT_DIR)\n" +
      "  --dry-run   fetch and report, write nothing\n" +
      "\n" +
      "This command never changes a firewall. It writes a snapshot; `heliopause-publish` renders from it.\n",
  );
  process.exit(2);
}

const dir = resolve(flags.get("dir") ?? process.env["HELIOPAUSE_SNAPSHOT_DIR"] ?? "./snapshots");

function fail(msg: string): never {
  console.error(msg);
  process.exit(1);
}

function ageText(s: Snapshot): string {
  const sec = Math.max(0, Math.round((Date.now() - Date.parse(s.fetchedAt)) / 1000));
  const days = sec / 86400;
  const stale = sec > REFRESH_LIMITS.staleAfterSec ? "  STALE" : "";
  return `${days.toFixed(1)}d old${stale}`;
}

/** Read a stored snapshot, turning a tampered or unreadable one into a clear exit rather than a stack. */
async function load(id: string): Promise<Snapshot | null> {
  try {
    return await readSnapshot(dir, id);
  } catch (e) {
    return fail(`cannot read the stored snapshot for ${id}:\n  ${e instanceof Error ? e.message : String(e)}`);
  }
}

if (cmd === "list") {
  // Reported even when nothing is registered — an empty list is an answer, and "no feeds" is a
  // legitimate state for this project (the ingress list is the only feed it needs).
  let stored: string[] = [];
  try {
    stored = (await readdir(dir)).filter((f) => f.endsWith(".json")).map((f) => f.replace(/\.json$/, ""));
  } catch {
    // No directory yet. Not an error: it appears on the first refresh.
  }

  console.log(`snapshots in ${dir}\n`);
  for (const f of FEEDS) {
    const snap = stored.includes(f.id) ? await load(f.id) : null;
    console.log(`  ${f.id}`);
    console.log(`    ${f.urls.join("\n    ")}`);
    console.log(
      snap
        ? `    ${snap.prefixCount} prefixes, ${snap.rejectCount} refused — ${snap.hash.slice(0, 19)}… ${ageText(snap)}`
        : `    no snapshot yet — run: heliopause-feed refresh ${f.id}`,
    );
    console.log(`    ${f.notes}`);
    console.log();
  }

  // A snapshot with no registration is worth saying out loud: it is what a render would *not* use, and
  // the reason is a config change rather than anything visible in the file.
  const orphans = stored.filter((id) => !FEEDS.some((f) => f.id === id));
  if (orphans.length) {
    console.log(`  unregistered snapshots (nothing will render from these): ${orphans.join(", ")}`);
  }
  process.exit(0);
}

if (!feedId) fail(`${cmd} needs a feed id. Run "heliopause-feed list" to see them.`);
const source = feedById(feedId);
if (!source) {
  fail(`no feed registered as "${feedId}" — registered: ${FEEDS.map((f) => f.id).join(", ") || "(none)"}`);
}

if (cmd === "refresh") {
  const prior = await load(feedId);
  const outcome = await refreshFeed({
    source,
    prior,
    fetch: makeFetchFeed(),
    now: new Date(),
  });

  if (outcome.kind === "unavailable") {
    fail(
      `${feedId}: ${outcome.reason}\n` +
        `  Nothing is stored for this feed, so there is nothing to fall back on and no policy can\n` +
        `  render from it yet.`,
    );
  }

  if (outcome.kind === "kept") {
    // Exit 1, deliberately. The refresh did not do what was asked, and a scheduled run that reported
    // success here would let a feed silently stop updating.
    console.error(
      `${feedId}: refresh refused — ${outcome.reason}\n` +
        `  Still in force: ${outcome.snapshot.prefixCount} prefixes from ${outcome.snapshot.hash.slice(0, 19)}…, ` +
        `${(outcome.ageSec / 86400).toFixed(1)}d old${outcome.stale ? " (STALE)" : ""}\n` +
        `  Rules keep rendering from that snapshot. Nothing is broken; nothing was updated.`,
    );
    process.exit(1);
  }

  const s = outcome.snapshot;
  const parsed = parseFeed(s.text, source.limits ? { ...source.limits } as never : undefined);
  console.log(`${feedId}: fetched ${s.bytes} bytes, ${s.prefixCount} prefixes, ${s.rejectCount} refused`);
  console.log(`  ${s.hash}`);
  if (outcome.prior) {
    console.log(
      outcome.changed
        ? `  changed from ${outcome.prior.hash.slice(0, 19)}… (${outcome.prior.prefixCount} → ${s.prefixCount} prefixes)`
        : `  unchanged since ${outcome.prior.fetchedAt}`,
    );
  } else {
    console.log(`  first snapshot for this feed`);
  }
  for (const r of parsed.rejects.slice(0, 10)) console.log(`  refused line ${r.line}: ${r.reason}`);
  if (parsed.rejects.length > 10) console.log(`  … and ${parsed.rejects.length - 10} more`);

  if (flags.has("dry-run")) {
    console.log(`\n  --dry-run: nothing written`);
    process.exit(0);
  }
  if (!outcome.changed) {
    // Rewriting an identical snapshot would move `fetchedAt` forward and make a feed that has stopped
    // updating look freshly checked. The age of a snapshot is the age of its *contents*.
    console.log(`\n  not written: identical to the stored snapshot`);
    process.exit(0);
  }
  const path = await writeSnapshot(dir, s);
  console.log(`\n  written to ${path}`);
  console.log(`  Rules do not change until you run heliopause-publish.`);
  process.exit(0);
}

if (cmd === "show") {
  const s = await load(feedId);
  if (!s) fail(`no snapshot stored for ${feedId} — run: heliopause-feed refresh ${feedId}`);
  const parsed = parseFeed(s.text);
  console.log(`${feedId} — ${s.prefixCount} prefixes, ${ageText(s)}`);
  console.log(`  fetched ${s.fetchedAt} from`);
  for (const u of s.urls) console.log(`    ${u}`);
  console.log(`  ${s.hash}\n`);

  const sel = flags.get("select");
  if (sel) {
    // The selector is checked against the *stored* feed, which is what a render will see. Checking it
    // against a live fetch would answer a question nobody asked.
    try {
      const prefixes = selectPrefixes(parsed, parseSelector(sel));
      console.log(`  ${sel} → ${prefixes.length} prefixes`);
      for (const p of prefixes) console.log(`    ${p}`);
    } catch (e) {
      fail(`  ${sel}: ${e instanceof Error ? e.message : String(e)}`);
    }
  } else {
    const v4 = parsed.entries.filter((e) => e.family === "ip");
    const v6 = parsed.entries.filter((e) => e.family === "ip6");
    console.log(`  IPv4 (${v4.length}):`);
    for (const e of v4) console.log(`    ${e.prefix}${e.country ? `  ${e.country}` : ""}`);
    console.log(`  IPv6 (${v6.length}):`);
    for (const e of v6) console.log(`    ${e.prefix}${e.country ? `  ${e.country}` : ""}`);
  }

  if (parsed.rejects.length) {
    console.log(`\n  refused ${parsed.rejects.length} line(s):`);
    for (const r of parsed.rejects.slice(0, 20)) console.log(`    line ${r.line}: ${r.reason} — ${r.text}`);
  }
  process.exit(0);
}

fail(`unknown command "${cmd}" — expected list, refresh or show`);
