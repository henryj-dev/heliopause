// Every test here is a rejection, because acceptance is the uninteresting half: a feed of clean
// prefixes parses. What this module exists to get right is what happens when it does not — and each
// of those cases, if unhandled, produces a *wider* firewall rather than a crash.
//
// Addresses in fixtures are RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and RFC 3849
// (2001:db8::/32). This file is tracked and published; site addresses are not.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { contains } from "./test-util.ts";
import {
  parseFeed,
  parseSelector,
  selectPrefixes,
  FeedError,
  FEED_LIMITS,
  type FeedLimits,
} from "./geofeed.ts";

/** A feed that parses, so a test can add one bad line to it and still reach the line's check. */
const GOOD = [
  "192.0.2.0/24,KR,KR-11,Seoul",
  "198.51.100.0/24,KR,KR-26,Busan",
  "203.0.113.0/24,JP,JP-13,Tokyo",
  "2001:db8::/32,KR,KR-11,Seoul",
].join("\n");

const limits = (over: Partial<FeedLimits> = {}): FeedLimits => ({ ...FEED_LIMITS, ...over });

describe("parseFeed — the shapes real feeds have", () => {
  it("parses a well-formed feed", () => {
    // The known positive. Without it every rejection test below could pass because the parser
    // rejects everything.
    const f = parseFeed(GOOD);
    assert.equal(f.entries.length, 4);
    assert.deepEqual(f.rejects, []);
  });

  it("ignores comment lines", () => {
    // Vultr's feed has three (measured 2026-07-29). Reading them as data would produce a prefix of
    // `#` and a confusing rejection reason for a line that is not an error at all.
    const f = parseFeed(`# this feed is provided as-is\n#\n${GOOD}`);
    assert.equal(f.entries.length, 4);
    assert.deepEqual(f.rejects, [], "a comment is not a reject");
  });

  it("ignores blank lines and tolerates CRLF", () => {
    const f = parseFeed(`\r\n${GOOD.split("\n").join("\r\n")}\r\n\r\n`);
    assert.equal(f.entries.length, 4);
  });

  it("keeps country and region uppercased", () => {
    const f = parseFeed("192.0.2.0/24,kr,kr-11,Seoul");
    assert.equal(f.entries[0]!.country, "KR");
    assert.equal(f.entries[0]!.region, "KR-11");
  });

  it("accepts a feed line with no country at all", () => {
    // The fields after the prefix are optional in practice. A missing country means the entry can
    // only ever be selected by `*`, which is different from the line being malformed.
    const f = parseFeed("192.0.2.0/24");
    assert.equal(f.entries[0]!.country, "");
    assert.equal(f.entries[0]!.region, "");
  });

  it("drops a duplicate prefix instead of rendering it twice", () => {
    // A feed may list one prefix under several cities. Two identical set members are not an error,
    // they are noise — but they would also perturb the ruleset hash.
    const f = parseFeed("192.0.2.0/24,KR,KR-11,Seoul\n192.0.2.0/24,KR,KR-26,Busan");
    assert.equal(f.entries.length, 1);
    assert.deepEqual(f.rejects, [], "a duplicate is not a reject");
  });

  it("reports a bad line without discarding the good ones", () => {
    // The property that keeps a third party's typo from taking our data source offline. The inverse —
    // throwing on the first bad row — would mean any upstream mistake stops every render.
    const f = parseFeed(`${GOOD}\nnot-a-prefix,KR,KR-11,Seoul`);
    assert.equal(f.entries.length, 4, "good lines survive");
    assert.equal(f.rejects.length, 1);
    assert.equal(f.rejects[0]!.line, 5, "1-based, so the reason points at a findable line");
  });
});

describe("parseFeed — prefixes that would widen a rule", () => {
  it("refuses `0.0.0.0/0` outright", () => {
    // One of these in an allow source opens the rule to the internet, and nobody reads a 138,213-line
    // feed. Refused as reserved space rather than as an over-wide prefix — `0.0.0.0/8` is unspecified
    // space and the reserved check deliberately runs first (see `parseFeed`). The verdict is what
    // matters here; the next test pins the length floor on a prefix that is *only* too wide.
    const f = parseFeed(`${GOOD}\n0.0.0.0/0,KR,KR-11,Seoul`);
    assert.equal(f.entries.length, 4);
    assert.equal(f.rejects.length, 1);
    contains(f.rejects[0]!.reason, "reserved");
  });

  it("refuses a prefix that is over-wide but not reserved", () => {
    // The floor's own known positive. `192.0.0.0/4` is public space, so nothing else can refuse it —
    // if the length check were deleted this test is the one that fails.
    const f = parseFeed(`${GOOD}\n192.0.0.0/4,KR,KR-11,Seoul`);
    assert.equal(f.entries.length, 4);
    assert.equal(f.rejects.length, 1);
    contains(f.rejects[0]!.reason, "wider than the /8 limit");
  });

  it("refuses a /7 even though /8 is allowed", () => {
    // Pins the boundary. A floor that was off by one would accept twice the address space.
    const seven = parseFeed(`${GOOD}\n192.0.0.0/7,KR,KR-11,Seoul`);
    assert.equal(seven.rejects.length, 1);
    const eight = parseFeed("192.0.0.0/8,KR,KR-11,Seoul");
    assert.equal(eight.entries.length, 1, "/8 is the documented limit and must pass");
  });

  it("refuses RFC 1918 and CGNAT space", () => {
    // A geofeed describes public space. A private prefix in one would make a "from country X" rule
    // match internal traffic, and this project's address model rests on internalSupernet meaning
    // what it says.
    const bad = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"];
    for (const p of bad) {
      const f = parseFeed(`${GOOD}\n${p},KR,KR-11,Seoul`);
      assert.equal(f.rejects.length, 1, `${p} must be refused`);
      contains(f.rejects[0]!.reason, "reserved");
    }
  });

  it("refuses loopback, link-local and multicast", () => {
    for (const p of ["127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/8", "0.0.0.0/8"]) {
      const f = parseFeed(`${GOOD}\n${p},KR,KR-11,Seoul`);
      assert.equal(f.rejects.length, 1, `${p} must be refused`);
    }
  });

  it("refuses IPv6 ULA, link-local and multicast", () => {
    // The v6 half of the same rule. IPv4-only reserved checks are how this environment's default
    // failure mode looks: v4 validated, v6 left unpoliced.
    for (const p of ["fc00::/7", "fd00::/8", "fe80::/10", "ff00::/8"]) {
      const f = parseFeed(`${GOOD}\n${p},KR,KR-11,Seoul`);
      assert.equal(f.rejects.length, 1, `${p} must be refused`);
      contains(f.rejects[0]!.reason, "reserved");
    }
  });

  it("refuses an IPv6 prefix wider than the floor", () => {
    const f = parseFeed(`${GOOD}\n2000::/12,KR,KR-11,Seoul`);
    assert.equal(f.rejects.length, 1);
    contains(f.rejects[0]!.reason, "/12");
  });
});

describe("parseFeed — malformed addresses", () => {
  it("refuses an octet above 255", () => {
    const f = parseFeed(`${GOOD}\n192.0.2.300/24,KR,KR-11,Seoul`);
    assert.equal(f.rejects.length, 1);
    contains(f.rejects[0]!.reason, "255");
  });

  it("refuses a leading zero in an octet", () => {
    // `010.1.1.1` is octal to some parsers and decimal to others. Two readings of one address is how
    // a rule ends up matching a different network than the one reviewed.
    const f = parseFeed(`${GOOD}\n010.0.2.0/24,KR,KR-11,Seoul`);
    assert.equal(f.rejects.length, 1);
    contains(f.rejects[0]!.reason, "leading zero");
  });

  it("refuses host bits set rather than silently taking the network", () => {
    // nft would accept `192.0.2.5/24` and match all 256 addresses. That may not be what the feed's
    // author claimed, and resolving the disagreement silently hides it.
    const f = parseFeed(`${GOOD}\n192.0.2.5/24,KR,KR-11,Seoul`);
    assert.equal(f.rejects.length, 1);
    contains(f.rejects[0]!.reason, "host bits");
  });

  it("accepts a /32 — a single address is not host bits set", () => {
    // The boundary the earlier `expectAddrs` bug lived on (V50): a mask check written without care
    // discards /32. Here /32 must pass, since every mask bit is set.
    const f = parseFeed("192.0.2.7/32,KR,KR-11,Seoul");
    assert.equal(f.entries[0]!.prefix, "192.0.2.7/32");
  });

  it("refuses a prefix length above the family maximum", () => {
    assert.equal(parseFeed(`${GOOD}\n192.0.2.0/33,KR,,`).rejects.length, 1);
    assert.equal(parseFeed(`${GOOD}\n2001:db8::/129,KR,,`).rejects.length, 1);
  });

  it("refuses a prefix with no length", () => {
    assert.equal(parseFeed(`${GOOD}\n192.0.2.0,KR,,`).rejects.length, 1);
    assert.equal(parseFeed(`${GOOD}\n2001:db8::,KR,,`).rejects.length, 1);
  });

  it("refuses an empty prefix field", () => {
    const f = parseFeed(`${GOOD}\n,KR,KR-11,Seoul`);
    assert.equal(f.rejects.length, 1);
    contains(f.rejects[0]!.reason, "empty prefix");
  });

  it("canonicalises IPv6 so one prefix has one spelling", () => {
    // Two spellings would render as two set members and perturb every ruleset hash containing them.
    const f = parseFeed("2001:0DB8:0000:0000::/48,KR,KR-11,Seoul");
    assert.equal(f.entries[0]!.prefix, "2001:db8::/48");
  });

  it("tags family from the address, not from the field count", () => {
    const f = parseFeed(GOOD);
    assert.deepEqual(f.entries.map((e) => e.family), ["ip", "ip", "ip", "ip6"]);
  });
});

describe("parseFeed — whole-feed refusals", () => {
  it("refuses a feed above the byte limit", () => {
    // A URL that now points somewhere else looks exactly like this.
    assert.throws(() => parseFeed(GOOD, limits({ maxBytes: 10 })), (e: unknown) => {
      assert.ok(e instanceof FeedError);
      contains((e as Error).message, "bytes");
      return true;
    });
  });

  it("refuses a feed above the prefix limit", () => {
    assert.throws(() => parseFeed(GOOD, limits({ maxPrefixes: 2 })), FeedError);
  });

  it("refuses a feed that parsed to nothing, and says why", () => {
    // Rule 6 one level up. Returning `[]` would let every selector match nothing — which *is* caught
    // downstream, but by then the reason for the emptiness is gone.
    assert.throws(() => parseFeed("nope\nalso nope"), (e: unknown) => {
      contains((e as Error).message, "no usable prefixes");
      contains((e as Error).message, "line 1");
      return true;
    });
  });

  it("refuses an empty feed", () => {
    assert.throws(() => parseFeed(""), FeedError);
    assert.throws(() => parseFeed("# only a comment"), FeedError);
  });

  it("carries a 400 status, like PolicyError", () => {
    // A bad feed is bad input, not a server fault. The write API turns this into a refusal an
    // operator can act on rather than a 500.
    try {
      parseFeed("");
      assert.fail("expected a throw");
    } catch (e) {
      assert.equal((e as FeedError).statusCode, 400);
    }
  });
});

describe("parseSelector", () => {
  it("parses a country selector", () => {
    assert.deepEqual(parseSelector("cloudflare:KR"), { feed: "cloudflare", scope: "KR" });
  });

  it("parses a subdivision selector", () => {
    assert.deepEqual(parseSelector("vultr:KR-11"), { feed: "vultr", scope: "KR-11" });
  });

  it("parses the whole-feed selector", () => {
    // `cloudflare:*` is the registered `ao-cf-edge` object — "anything behind Cloudflare".
    assert.deepEqual(parseSelector("cloudflare:*"), { feed: "cloudflare", scope: "*" });
  });

  it("normalises case on both halves", () => {
    assert.deepEqual(parseSelector("  CloudFlare : kr  "), { feed: "cloudflare", scope: "KR" });
  });

  it("refuses a value with no colon", () => {
    assert.throws(() => parseSelector("cloudflare"), FeedError);
  });

  it("refuses a partial wildcard", () => {
    // `KR-*` invites `K*`, and there is no case for either. A wildcard that matches more than it
    // looks like is the failure this whole module guards.
    assert.throws(() => parseSelector("cloudflare:KR-*"), FeedError);
    assert.throws(() => parseSelector("cloudflare:K*"), FeedError);
  });

  it("refuses a scope that is not a country code shape", () => {
    for (const s of ["KOREA", "k", "", "KR-", "KR-11-3"]) {
      assert.throws(() => parseSelector(`cloudflare:${s}`), FeedError, `"${s}" must be refused`);
    }
  });

  it("refuses a feed name that is not a plain identifier", () => {
    for (const f of ["", "a b", "../etc", "feed_1"]) {
      assert.throws(() => parseSelector(`${f}:KR`), FeedError, `"${f}" must be refused`);
    }
  });
});

describe("selectPrefixes", () => {
  const feed = parseFeed(GOOD);

  it("selects by country across both families", () => {
    assert.deepEqual(selectPrefixes(feed, parseSelector("cloudflare:KR")), [
      "192.0.2.0/24",
      "198.51.100.0/24",
      "2001:db8::/32",
    ]);
  });

  it("selects by subdivision", () => {
    assert.deepEqual(selectPrefixes(feed, parseSelector("cloudflare:KR-26")), ["198.51.100.0/24"]);
  });

  it("selects the whole feed for `*`", () => {
    assert.equal(selectPrefixes(feed, parseSelector("cloudflare:*")).length, 4);
  });

  it("does not treat a subdivision selector as a country prefix match", () => {
    // `KR-11` must not also match plain `KR` entries, and `KR` must not be satisfied by region text.
    const only = parseFeed("192.0.2.0/24,KR,,Seoul");
    assert.throws(() => selectPrefixes(only, parseSelector("cloudflare:KR-11")), FeedError);
  });

  it("refuses a selector that matches nothing", () => {
    // The check with the widest consequence: no match renders a rule with no address condition,
    // which matches everything. A typo'd country code (`KP` for `KR`) is the likely way to get here.
    assert.throws(() => selectPrefixes(feed, parseSelector("cloudflare:KP")), (e: unknown) => {
      contains((e as Error).message, "matches no prefixes");
      contains((e as Error).message, "all traffic");
      return true;
    });
  });

  it("refuses a selection above the per-object limit", () => {
    // The feed cap defends the parse; this defends the render. `cloudflare:*` is 138,213 prefixes and
    // belongs in a named set, not inline.
    assert.throws(() => selectPrefixes(feed, parseSelector("cloudflare:*"), limits({ maxSelected: 2 })), FeedError);
  });

  it("returns prefixes sorted, so a render is byte-stable", () => {
    // Unsorted output would make ruleset hashes depend on feed line order. Every drift baseline and
    // every H30 check in the project rests on that hash meaning "the same rules".
    const shuffled = parseFeed(
      ["198.51.100.0/24,KR,,", "2001:db8::/32,KR,,", "192.0.2.0/24,KR,,"].join("\n"),
    );
    assert.deepEqual(
      selectPrefixes(shuffled, parseSelector("cloudflare:KR")),
      selectPrefixes(feed, parseSelector("cloudflare:KR")),
      "line order must not change the rendered set",
    );
  });
});
