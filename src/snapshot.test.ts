// What a render is allowed to read, and what happens when the fetch does not cooperate.
//
// The successful path is one test. The rest are the cases that decide whether this module is worth
// having: a feed that failed, a feed that changed shape, and a snapshot that was edited after it was
// taken. Each of those, handled wrongly, either takes a host's ruleset away or changes it without
// anyone approving the change.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { contains } from "./test-util.ts";
import {
  refreshFeed,
  readSnapshot,
  writeSnapshot,
  snapshotPath,
  provenanceComment,
  hashBytes,
  summarise,
  REFRESH_LIMITS,
  type Snapshot,
  type FeedSource,
  type RefreshLimits,
} from "./snapshot.ts";
import { FeedError } from "./geofeed.ts";

const AT = new Date("2026-08-04T00:00:00Z");

/** Four public prefixes — RFC 5737 / RFC 3849, since this file is published. */
const BODY = [
  "192.0.2.0/24,KR,KR-11,Seoul",
  "198.51.100.0/24,KR,KR-26,Busan",
  "203.0.113.0/24,JP,JP-13,Tokyo",
  "2001:db8::/32,KR,KR-11,Seoul",
].join("\n");

const source: FeedSource = { id: "testfeed", urls: ["https://feed.invalid/geofeed.csv"] };

/**
 * A stored snapshot.
 *
 * The hash is derived from the body rather than defaulted, so a fixture cannot be internally
 * inconsistent — `readSnapshot` refuses a mismatch, and a helper that produced one would make every
 * test using it fail for a reason that has nothing to do with what it is testing. (V56 hit exactly
 * that: a fixture whose manifest and reports disagreed, where the check was right and the fixture
 * was wrong.) An override still wins, which is how the tamper test gets its mismatch on purpose.
 */
const snap = (over: Partial<Snapshot> = {}): Snapshot => {
  const text = over.text ?? BODY;
  return {
    feedId: "testfeed",
    urls: source.urls,
    fetchedAt: AT.toISOString(),
    bytes: Buffer.byteLength(text, "utf8"),
    prefixCount: 4,
    rejectCount: 0,
    hash: hashBytes(text),
    ...over,
    text,
  };
};

const limits = (over: Partial<RefreshLimits> = {}): RefreshLimits => ({ ...REFRESH_LIMITS, ...over });

const serve = (text: string) => async () => text;
const fail = (msg: string) => async () => {
  throw new Error(msg);
};

describe("refreshFeed — first fetch", () => {
  it("accepts a good feed and records what it saw", () => {
    return refreshFeed({ source, prior: null, fetch: serve(BODY), now: AT }).then((r) => {
      assert.equal(r.kind, "fetched");
      if (r.kind !== "fetched") return;
      assert.equal(r.snapshot.prefixCount, 4);
      assert.equal(r.snapshot.fetchedAt, AT.toISOString());
      assert.equal(r.snapshot.hash, hashBytes(BODY));
      assert.equal(r.changed, true, "the first fetch is always a change");
      assert.equal(r.prior, null);
    });
  });

  it("has nothing to fall back on, so a failed first fetch is fatal", async () => {
    // The one fatal case, and it must be distinguishable from `kept` — an operator seeing "kept" would
    // reasonably believe something is still being served.
    const r = await refreshFeed({ source, prior: null, fetch: fail("ETIMEDOUT"), now: AT });
    assert.equal(r.kind, "unavailable");
    if (r.kind !== "unavailable") return;
    contains(r.reason, "ETIMEDOUT");
  });

  it("is fatal on a first fetch that does not parse", async () => {
    const r = await refreshFeed({ source, prior: null, fetch: serve("garbage\nmore garbage"), now: AT });
    assert.equal(r.kind, "unavailable");
  });
});

describe("refreshFeed — a fetch failure must not become a render failure", () => {
  it("keeps the previous snapshot and says what it is serving", async () => {
    // Design rule 3. "No ruleset" is worse than "a week-old ruleset": the first leaves a host with
    // nothing, the second leaves it with rules that were reviewed.
    const prior = snap();
    const r = await refreshFeed({ source, prior, fetch: fail("ENOTFOUND"), now: AT });
    assert.equal(r.kind, "kept");
    if (r.kind !== "kept") return;
    contains(r.reason, "ENOTFOUND");
    assert.equal(r.snapshot.hash, prior.hash, "the prior snapshot is what is in force");
  });

  it("keeps the previous snapshot when the new feed no longer parses", async () => {
    const r = await refreshFeed({ source, prior: snap(), fetch: serve("# nothing usable"), now: AT });
    assert.equal(r.kind, "kept");
    if (r.kind !== "kept") return;
    contains(r.reason, "feed rejected");
  });

  it("reports the age of what it kept", async () => {
    // The staleness has to travel with the decision. A caller that rendered from this without saying
    // how old it was would have turned a warning into a lie.
    const prior = snap({ fetchedAt: "2026-07-28T00:00:00Z" });
    const r = await refreshFeed({ source, prior, fetch: fail("x"), now: AT });
    assert.equal(r.kind, "kept");
    if (r.kind !== "kept") return;
    assert.equal(r.ageSec, 7 * 24 * 3600);
    assert.equal(r.stale, false, "a week is within the weekly-feed window");
  });

  it("flags a snapshot past the staleness window", async () => {
    const prior = snap({ fetchedAt: "2026-06-01T00:00:00Z" });
    const r = await refreshFeed({ source, prior, fetch: fail("x"), now: AT });
    assert.equal(r.kind, "kept");
    if (r.kind !== "kept") return;
    assert.equal(r.stale, true);
  });

  it("treats an unparseable timestamp as infinitely old rather than as fresh", async () => {
    // Reading a broken date as "now" would mark the oldest possible snapshot fresh, which is the one
    // direction of error that hides a problem.
    const r = await refreshFeed({ source, prior: snap({ fetchedAt: "not a date" }), fetch: fail("x"), now: AT });
    assert.equal(r.kind, "kept");
    if (r.kind !== "kept") return;
    assert.equal(r.stale, true);
  });
});

describe("refreshFeed — a feed that changed shape needs review", () => {
  it("refuses a feed that grew past the drift limit", async () => {
    // Design rule 4. A URL now pointing somewhere else produces a plausible set of prefixes that
    // nobody reviewed.
    const grown = [BODY, "192.0.2.128/25,KR,,", "203.0.113.128/25,KR,,", "198.51.100.128/25,KR,,"].join("\n");
    const r = await refreshFeed({ source, prior: snap(), fetch: serve(grown), now: AT, limits: limits({ maxDriftFraction: 0.2 }) });
    assert.equal(r.kind, "kept");
    if (r.kind !== "kept") return;
    contains(r.reason, "prefix count moved from 4 to 7");
  });

  it("refuses a feed that collapsed, not only one that grew", async () => {
    // The more dangerous direction and the one an absolute cap misses entirely: a feed shrinking to
    // one prefix silently narrows a deny list, or empties an allow source and takes a path down.
    const r = await refreshFeed({ source, prior: snap(), fetch: serve("192.0.2.0/24,KR,,"), now: AT });
    assert.equal(r.kind, "kept");
    if (r.kind !== "kept") return;
    contains(r.reason, "4 to 1");
  });

  it("accepts movement inside the limit", async () => {
    // The known positive for the drift guard. Without this, a guard that rejected everything would
    // pass both tests above.
    const r = await refreshFeed({ source, prior: snap(), fetch: serve(`${BODY}\n192.0.2.128/25,KR,,`), now: AT });
    assert.equal(r.kind, "fetched");
  });

  it("does not apply the drift guard on a first fetch", async () => {
    // There is nothing to compare against, and refusing here would make a feed unregisterable.
    const r = await refreshFeed({ source, prior: null, fetch: serve("192.0.2.0/24,KR,,"), now: AT });
    assert.equal(r.kind, "fetched");
  });
});

describe("refreshFeed — change detection", () => {
  it("reports unchanged when the bytes hash the same", async () => {
    const r = await refreshFeed({ source, prior: snap(), fetch: serve(BODY), now: AT });
    assert.equal(r.kind, "fetched");
    if (r.kind !== "fetched") return;
    assert.equal(r.changed, false);
  });

  it("counts a reordered feed as changed even though the rendered set is identical", async () => {
    // The hash covers raw bytes on purpose. Hashing the parse would call this identical and hide that
    // a third party edited the document our rules come from.
    const reordered = BODY.split("\n").reverse().join("\n");
    const r = await refreshFeed({ source, prior: snap(), fetch: serve(reordered), now: AT });
    assert.equal(r.kind, "fetched");
    if (r.kind !== "fetched") return;
    assert.equal(r.changed, true);
    assert.equal(r.snapshot.prefixCount, 4, "same prefixes");
  });

  it("carries the prior summary so a diff has two sides", async () => {
    const r = await refreshFeed({ source, prior: snap(), fetch: serve(`${BODY}\n192.0.2.128/25,KR,,`), now: AT });
    assert.equal(r.kind, "fetched");
    if (r.kind !== "fetched") return;
    assert.equal(r.prior?.prefixCount, 4);
    assert.equal(r.snapshot.prefixCount, 5);
  });

  it("applies a per-feed limit override", async () => {
    // Cloudflare needs 200,000 and Vultr 5,000; one global cap would either reject the first or fail
    // to guard the second.
    const tight: FeedSource = { ...source, limits: { maxPrefixes: 2 } };
    const r = await refreshFeed({ source: tight, prior: null, fetch: serve(BODY), now: AT });
    assert.equal(r.kind, "unavailable");
  });

  it("counts refused lines without failing", async () => {
    const r = await refreshFeed({ source, prior: null, fetch: serve(`${BODY}\n10.0.0.0/8,KR,,`), now: AT });
    assert.equal(r.kind, "fetched");
    if (r.kind !== "fetched") return;
    assert.equal(r.snapshot.rejectCount, 1, "a private prefix in the feed is recorded, not fatal");
    assert.equal(r.snapshot.prefixCount, 4);
  });
});

describe("refreshFeed — a feed published as several documents", () => {
  // Cloudflare's ingress list is `/ips-v4` plus `/ips-v6`. A policy needs both families or it silently
  // covers half the address space, which is this environment's standing failure mode.
  const two = { id: "testfeed", urls: ["https://a.invalid/v4", "https://b.invalid/v6"] };
  const byUrl = (map: Record<string, string>) => async (url: string) => {
    const body = map[url];
    if (body === undefined) throw new Error(`unexpected url ${url}`);
    return body;
  };

  it("concatenates the documents into one feed", async () => {
    const r = await refreshFeed({
      source: two,
      prior: null,
      now: AT,
      fetch: byUrl({
        "https://a.invalid/v4": "192.0.2.0/24,KR,,\n198.51.100.0/24,KR,,",
        "https://b.invalid/v6": "2001:db8::/32,KR,,",
      }),
    });
    assert.equal(r.kind, "fetched");
    if (r.kind !== "fetched") return;
    assert.equal(r.snapshot.prefixCount, 3, "both families present");
    assert.deepEqual(r.snapshot.urls, two.urls, "the snapshot records what it was built from");
  });

  it("separates documents that do not end in a newline", async () => {
    // Without a separator the last line of one document splices onto the first line of the next,
    // producing one malformed prefix and losing two valid ones.
    const r = await refreshFeed({
      source: two,
      prior: null,
      now: AT,
      fetch: byUrl({ "https://a.invalid/v4": "192.0.2.0/24", "https://b.invalid/v6": "2001:db8::/32" }),
    });
    assert.equal(r.kind, "fetched");
    if (r.kind !== "fetched") return;
    assert.equal(r.snapshot.prefixCount, 2);
  });

  it("does not append a separator after the last document", async () => {
    // `hash` must cover the bytes upstream served. Normalising every part would make a single-URL feed's
    // snapshot differ from the served body, and then the hash no longer means what its doc says.
    const r = await refreshFeed({ source, prior: null, fetch: serve(BODY), now: AT });
    assert.equal(r.kind, "fetched");
    if (r.kind !== "fetched") return;
    assert.equal(r.snapshot.hash, hashBytes(BODY));
  });

  it("abandons the whole refresh when one document fails", async () => {
    // The case this design exists for. Keeping the half that succeeded would render a policy covering
    // IPv4 only — cleanly, with a valid hash, and wrong.
    const r = await refreshFeed({
      source: two,
      prior: snap(),
      now: AT,
      fetch: byUrl({ "https://a.invalid/v4": "192.0.2.0/24,KR,," }),
    });
    assert.equal(r.kind, "kept");
    if (r.kind !== "kept") return;
    contains(r.reason, "b.invalid/v6");
  });

  it("refuses a feed registered with no URLs", async () => {
    // Would otherwise fetch nothing, concatenate to "", and be refused by `parseFeed` with a message
    // about prefixes — pointing at the feed's contents rather than at the registration that is wrong.
    const r = await refreshFeed({ source: { id: "empty", urls: [] }, prior: null, fetch: serve(BODY), now: AT });
    assert.equal(r.kind, "unavailable");
    if (r.kind !== "unavailable") return;
    contains(r.reason, "no URLs registered");
  });

  it("fetches in the registered order", async () => {
    // Order is part of the feed's identity: the hash covers the concatenation, so reordering reads as a
    // changed document. That is correct, and it means the fetch must not race.
    const seen: string[] = [];
    await refreshFeed({
      source: two,
      prior: null,
      now: AT,
      fetch: async (url) => {
        seen.push(url);
        return url.endsWith("v4") ? "192.0.2.0/24,KR,," : "2001:db8::/32,KR,,";
      },
    });
    assert.deepEqual(seen, two.urls);
  });
});

describe("summarise", () => {
  it("drops the body so a plan can carry the metadata", () => {
    const s = summarise(snap());
    assert.equal("text" in s, false, "a 32MB CSV must not travel in a plan");
    assert.equal(s.hash, hashBytes(BODY));
  });
});

describe("provenanceComment", () => {
  it("records the hash and time that produced the rules", () => {
    // Design rule 7: what made this rule must be traceable.
    const lines = provenanceComment([summarise(snap())]);
    assert.equal(lines.length, 1);
    contains(lines[0]!, "geofeed testfeed");
    contains(lines[0]!, hashBytes(BODY));
    contains(lines[0]!, "2026-08-04T00:00:00.000Z");
  });

  it("emits nothing when no feed was used", () => {
    // Load-bearing. An unconditional line would change every host's text ruleset the moment this
    // shipped, and a host with no geofeed policy has no provenance to state.
    assert.deepEqual(provenanceComment([]), []);
  });

  it("sorts by feed id so the output is stable", () => {
    const a = summarise(snap({ feedId: "vultr" }));
    const b = summarise(snap({ feedId: "cloudflare" }));
    const lines = provenanceComment([a, b]);
    contains(lines[0]!, "cloudflare");
    contains(lines[1]!, "vultr");
  });

  it("starts every line with a comment marker", () => {
    // These are spliced into `nft -f` text. A line that is not a comment is a syntax error on the
    // host, which would be found at apply time rather than here.
    for (const l of provenanceComment([summarise(snap())])) assert.match(l, /^#/);
  });
});

describe("readSnapshot / writeSnapshot", () => {
  const dir = async () => mkdtemp(join(tmpdir(), "hp-snap-"));

  it("round-trips a snapshot", async () => {
    const d = await dir();
    await writeSnapshot(d, snap());
    const back = await readSnapshot(d, "testfeed");
    assert.equal(back?.hash, hashBytes(BODY));
    assert.equal(back?.text, BODY);
  });

  it("returns null when there is no snapshot yet", async () => {
    // Distinct from throwing: first run is normal, and `refreshFeed` needs `null` to mean "no prior".
    assert.equal(await readSnapshot(await dir(), "testfeed"), null);
  });

  it("refuses a snapshot whose bytes no longer match its hash", async () => {
    // The same class of finding as H30's artifact-hash contradiction: something edited what we were
    // about to render, and the record of what it should have been is sitting next to it.
    const d = await dir();
    const s = snap();
    await writeSnapshot(d, s);
    const path = snapshotPath(d, "testfeed");
    const stored = JSON.parse(await readFile(path, "utf8")) as Snapshot;
    stored.text = `${BODY}\n0.0.0.0/0,KR,,`;
    await writeFile(path, JSON.stringify(stored), "utf8");
    await assert.rejects(() => readSnapshot(d, "testfeed"), (e: unknown) => {
      contains((e as Error).message, "does not match its hash");
      contains((e as Error).message, "modified after it was taken");
      return true;
    });
  });

  it("refuses a stored snapshot missing its body", async () => {
    const d = await dir();
    await writeFile(snapshotPath(d, "testfeed"), JSON.stringify({ feedId: "testfeed" }), "utf8");
    await assert.rejects(() => readSnapshot(d, "testfeed"), FeedError);
  });

  it("leaves no temp file behind", async () => {
    // Temp-then-rename: a reader must never see a half-written snapshot, and a crash mid-write must
    // leave the previous one intact — that one is the fallback everything else leans on.
    const d = await dir();
    await writeSnapshot(d, snap());
    await assert.rejects(() => readFile(`${snapshotPath(d, "testfeed")}.tmp`, "utf8"));
  });

  it("refuses a feed id that would escape the store", async () => {
    // The id reaches a path. `../../etc` would write outside the directory it was given.
    for (const id of ["../../etc", "a/b", "", "Feed", "a".repeat(40)]) {
      assert.throws(() => snapshotPath("/tmp/x", id), FeedError, `"${id}" must be refused`);
    }
  });
});
