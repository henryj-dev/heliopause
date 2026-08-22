// Parsing and validating an RFC 8805 geofeed. Pure — no I/O, no clock, no network.
//
// A geofeed is a third party's CSV saying which prefixes sit in which country. Fetching it is
// someone else's job (`snapshot.ts` holds what was fetched); this module decides what a feed's bytes
// are allowed to mean.
//
// ## Why the validation is the module
//
// Every rejection here is a rule that, if absent, silently widens a firewall:
//
//   · `0.0.0.0/0` in an allow source opens the rule to the internet. A feed is 138,213 lines
//     (measured, Cloudflare 2026-07-29) and nobody reads it, so one bad line is invisible.
//   · An empty match renders a rule with no address condition — which matches everything. Same
//     hazard as an empty address group, and `objects.ts` refuses that for the same reason.
//   · A feed that grew 10x, or a URL that now points somewhere else, produces a plausible-looking
//     set of prefixes that were never reviewed.
//
// So the failure mode this guards is not "the render crashes". It is "the render succeeds and means
// something wider than what was approved". A parser that returns a partial list on bad input is
// worse than one that refuses: half a deny list is not a deny list.
//
// ## Why private ranges are refused
//
// A geofeed describes public address space. A private prefix appearing in one is either a mistake in
// the feed or an attempt to make a rule match internal traffic — and this project's whole address
// model rests on `internalSupernet` meaning what it says.
//
// ## What this does NOT do
//
// It does not fetch, cache, schedule, or decide freshness. It does not know which selector a policy
// wants. Given bytes and a selector it answers "these prefixes, or here is why not".

// Deliberately imports nothing from `policy.ts`. The dependency runs the other way — `policy.ts` calls
// `parseSelector` to validate a `geofeed` endpoint's value — and importing back would make the cycle
// that Node's type stripping resolves at runtime in ways that depend on which module loads first.
// `FeedError` therefore carries its own `statusCode` rather than extending `PolicyError`.

/**
 * Limits applied to one feed.
 *
 * Defaults are deliberately not "whatever the feed happens to be today". `maxPrefixes` is set from
 * the largest feed measured (Cloudflare, 138,213 lines) with headroom, not from the largest selector
 * (`cloudflare:KR`, 1,368) — the cap defends against a feed changing shape, and a cap tuned to
 * today's selector would reject next month's normal growth.
 */
export interface FeedLimits {
  /** Reject the whole feed above this many bytes. */
  maxBytes: number;
  /** Reject the whole feed above this many accepted prefixes. */
  maxPrefixes: number;
  /** Reject a selector matching more than this. Guards the *rendered* set, not the feed. */
  maxSelected: number;
  /**
   * Shortest IPv4 prefix length accepted. `/8` per the design note — anything shorter is a /7 or
   * larger, i.e. tens of millions of addresses attributed to one country.
   */
  minIpv4Prefix: number;
  /** Shortest IPv6 prefix length accepted. */
  minIpv6Prefix: number;
}

export const FEED_LIMITS: FeedLimits = {
  maxBytes: 32 * 1024 * 1024,
  maxPrefixes: 200_000,
  maxSelected: 50_000,
  minIpv4Prefix: 8,
  minIpv6Prefix: 16,
};

/** One accepted feed entry. */
export interface FeedEntry {
  /** Normalised CIDR, exactly as it will be rendered. */
  prefix: string;
  family: "ip" | "ip6";
  /** ISO 3166-1 alpha-2, uppercased. Empty when the feed left it blank. */
  country: string;
  /** ISO 3166-2 subdivision, uppercased (e.g. `KR-11`). Empty when absent. */
  region: string;
}

/** A line that was not accepted, kept so a feed can be reviewed rather than guessed at. */
export interface FeedReject {
  /** 1-based line number in the source, so the reason points at something findable. */
  line: number;
  reason: string;
  /** The offending text, truncated — a feed line can be arbitrarily long. */
  text: string;
}

export interface ParsedFeed {
  entries: FeedEntry[];
  /**
   * Lines refused, with reasons.
   *
   * Reported rather than thrown because a real feed has junk in it — Vultr's has three comment lines
   * (measured) and feeds carry blank lines and occasional malformed rows. Refusing the whole feed for
   * one bad row would mean any third-party typo takes the firewall's data source offline. What must
   * never happen is a bad row being *accepted*, and that is what this list is evidence of.
   */
  rejects: FeedReject[];
}

export class FeedError extends Error {
  readonly statusCode: number;
  constructor(msg: string) {
    super(msg);
    // Assigned here, not as a parameter property: Node's type stripping rejects those
    // (`ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX`). Same reason as `ApprovalError`.
    this.statusCode = 400;
  }
}

const MAX_REJECT_TEXT = 120;

/** IPv4 dotted quad with a prefix length. Deliberately strict — no shorthand, no leading zeros. */
const V4_CIDR = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;

/**
 * Is this prefix inside space that must never come from a geofeed?
 *
 * Not an exhaustive special-registry list. It covers the ranges whose appearance would change what a
 * rule means in this environment: RFC 1918 and CGNAT (they would make a "from country X" rule match
 * internal traffic), loopback, link-local, multicast, and the IPv6 equivalents.
 */
function reservedReason(prefix: string, family: "ip" | "ip6"): string | null {
  if (family === "ip") {
    const m = V4_CIDR.exec(prefix)!;
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a === 10) return "RFC 1918 private space (10.0.0.0/8)";
    if (a === 172 && b >= 16 && b <= 31) return "RFC 1918 private space (172.16.0.0/12)";
    if (a === 192 && b === 168) return "RFC 1918 private space (192.168.0.0/16)";
    if (a === 100 && b >= 64 && b <= 127) return "RFC 6598 CGNAT space (100.64.0.0/10)";
    if (a === 127) return "loopback (127.0.0.0/8)";
    if (a === 169 && b === 254) return "link-local (169.254.0.0/16)";
    if (a === 0) return "unspecified (0.0.0.0/8)";
    if (a >= 224) return "multicast or reserved (224.0.0.0/3)";
    return null;
  }
  const head = prefix.toLowerCase();
  if (head.startsWith("::1/") || head === "::/0") return "loopback or unspecified";
  if (/^f[cd]/.test(head)) return "unique local address (fc00::/7)";
  if (/^fe[89ab]/.test(head)) return "link-local (fe80::/10)";
  if (/^ff/.test(head)) return "multicast (ff00::/8)";
  return null;
}

/**
 * Parse and normalise an IPv4 CIDR, or return why not.
 *
 * Requires the address to be the network address for its length. A feed line like `203.0.113.4/24` is
 * ambiguous — nft would take the network — and accepting it means the rendered rule covers 256
 * addresses that the feed's author may not have intended to claim. Refusing makes the disagreement
 * visible instead of resolving it silently.
 */
function parseV4(raw: string): { prefix: string; len: number } | { reason: string } {
  const m = V4_CIDR.exec(raw);
  if (!m) return { reason: "not an IPv4 CIDR" };
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (octets.some((o) => o > 255)) return { reason: "IPv4 octet above 255" };
  // Leading zeros are how `010.1.1.1` gets read as octal by some parsers and as decimal by others.
  for (const part of [m[1]!, m[2]!, m[3]!, m[4]!]) {
    if (part.length > 1 && part.startsWith("0")) return { reason: "IPv4 octet has a leading zero" };
  }
  const len = Number(m[5]);
  if (len > 32) return { reason: "IPv4 prefix length above 32" };
  const asInt = ((octets[0]! << 24) | (octets[1]! << 16) | (octets[2]! << 8) | octets[3]!) >>> 0;
  // `<<` with a shift of 32 is a no-op in JS, so /0 needs its own mask.
  const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
  if ((asInt & mask) >>> 0 !== asInt) {
    return { reason: `host bits set — not the network address for /${len}` };
  }
  return { prefix: `${octets.join(".")}/${len}`, len };
}

/**
 * Parse and normalise an IPv6 CIDR, or return why not.
 *
 * Uses `URL` to validate the address half rather than hand-rolling IPv6 text parsing. Node normalises
 * inside brackets (`[2001:DB8:0:0::1]` → `[2001:db8::1]`), which gives canonical lowercase compressed
 * form for free — and canonical form is required, not cosmetic: two spellings of one prefix would
 * render as two set members and perturb every ruleset hash that contains them.
 *
 * The network-address check is skipped here. Doing it properly needs 128-bit arithmetic, and unlike
 * IPv4 the feeds measured emit correct network addresses; the guard that matters for v6 is the
 * prefix-length floor, which is enforced.
 */
function parseV6(raw: string): { prefix: string; len: number } | { reason: string } {
  const slash = raw.lastIndexOf("/");
  if (slash < 0) return { reason: "not an IPv6 CIDR" };
  const addr = raw.slice(0, slash);
  const lenText = raw.slice(slash + 1);
  if (!/^\d{1,3}$/.test(lenText)) return { reason: "IPv6 prefix length is not a number" };
  const len = Number(lenText);
  if (len > 128) return { reason: "IPv6 prefix length above 128" };
  if (!addr.includes(":")) return { reason: "not an IPv6 CIDR" };
  let canon: string;
  try {
    const u = new URL(`http://[${addr}]/`);
    canon = u.hostname.replace(/^\[|\]$/g, "");
    if (!canon.includes(":")) return { reason: "not an IPv6 address" };
  } catch {
    return { reason: "not an IPv6 address" };
  }
  return { prefix: `${canon}/${len}`, len };
}

/** Split one CSV row. RFC 8805 fields carry no quoting or embedded commas. */
function fields(line: string): string[] {
  return line.split(",").map((f) => f.trim());
}

/**
 * Parse RFC 8805 bytes into entries plus a list of what was refused.
 *
 * Throws only for conditions that make the whole feed unusable — too large, or nothing valid in it.
 * Per-line problems are collected, because a third party's typo must not take our data source down.
 */
export function parseFeed(text: string, limits: FeedLimits = FEED_LIMITS): ParsedFeed {
  const bytes = Buffer.byteLength(text, "utf8");
  if (bytes > limits.maxBytes) {
    throw new FeedError(`feed is ${bytes} bytes, above the ${limits.maxBytes} limit`);
  }

  const entries: FeedEntry[] = [];
  const rejects: FeedReject[] = [];
  // Duplicate prefixes are dropped rather than refused: a feed may legitimately list one prefix under
  // several cities. Keeping both would render two identical set members.
  const seen = new Set<string>();

  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    const line = i + 1;
    const trimmed = raw.trim();
    if (trimmed === "") continue;
    // Vultr's feed has three of these (measured). A parser that read them as data would produce a
    // prefix of `#` and reject it with a confusing reason.
    if (trimmed.startsWith("#")) continue;

    const f = fields(trimmed);
    const prefixText = f[0] ?? "";
    if (prefixText === "") {
      rejects.push({ line, reason: "empty prefix field", text: trimmed.slice(0, MAX_REJECT_TEXT) });
      continue;
    }

    const family: "ip" | "ip6" = prefixText.includes(":") ? "ip6" : "ip";
    const parsed = family === "ip" ? parseV4(prefixText) : parseV6(prefixText);
    if ("reason" in parsed) {
      rejects.push({ line, reason: parsed.reason, text: trimmed.slice(0, MAX_REJECT_TEXT) });
      continue;
    }

    // ## Order is load-bearing
    //
    // The reserved check runs **before** the prefix-length floor, and the parsers deliberately do not
    // apply the floor themselves. Several reserved ranges are also shorter than the floor —
    // `fc00::/7`, `fe80::/10`, `0.0.0.0/8` at the boundary — so whichever check runs first is the one
    // that reports. With the floor first, every one of those lines was refused for its *length*, and
    // the reserved check could have been deleted with no test noticing. Measured while writing this:
    // the ULA test failed on the reason string, not on the verdict.
    //
    // Both orders reject; only this one makes the reserved check observable. A check whose absence
    // changes nothing visible is not a check ([[known-positive-required]]).
    const reserved = reservedReason(parsed.prefix, family);
    if (reserved) {
      rejects.push({ line, reason: `reserved address space: ${reserved}`, text: trimmed.slice(0, MAX_REJECT_TEXT) });
      continue;
    }

    const floor = family === "ip" ? limits.minIpv4Prefix : limits.minIpv6Prefix;
    if (parsed.len < floor) {
      rejects.push({
        line,
        reason: `${family === "ip" ? "IPv4" : "IPv6"} prefix /${parsed.len} is wider than the /${floor} limit`,
        text: trimmed.slice(0, MAX_REJECT_TEXT),
      });
      continue;
    }

    if (seen.has(parsed.prefix)) continue;
    seen.add(parsed.prefix);

    entries.push({
      prefix: parsed.prefix,
      family,
      country: (f[1] ?? "").toUpperCase(),
      region: (f[2] ?? "").toUpperCase(),
    });

    if (entries.length > limits.maxPrefixes) {
      throw new FeedError(
        `feed holds more than ${limits.maxPrefixes} prefixes — refusing rather than rendering a set ` +
          `nobody reviewed (a feed that grew this much, or a URL pointing somewhere else, looks exactly like this)`,
      );
    }
  }

  if (entries.length === 0) {
    // The design note's rule 6, one level up: a feed that parsed to nothing is not an empty feed, it
    // is a feed we failed to read. Returning `[]` here would let every selector match nothing, and a
    // selector matching nothing is caught downstream — but by then the reason is lost.
    throw new FeedError(
      `feed holds no usable prefixes (${rejects.length} line(s) refused` +
        (rejects[0] ? `; first: line ${rejects[0].line} — ${rejects[0].reason}` : "") +
        `)`,
    );
  }

  return { entries, rejects };
}

/**
 * A selector: `<feed>:<what>` where `<what>` is `*`, a country, or a subdivision.
 *
 * `*` is accepted for whole-feed objects (`cloudflare:*` — "anything behind Cloudflare"), which the
 * design registers as `ao-cf-edge`. It is not a wildcard match on arbitrary text: `KR-*` is refused,
 * because a partial wildcard invites `K*` and there is no case for it.
 */
export interface Selector {
  feed: string;
  /** Uppercased. `"*"` means the whole feed. */
  scope: string;
}

const FEED_NAME = /^[a-z0-9][a-z0-9-]{0,30}$/;
const SCOPE = /^([A-Z]{2}(-[A-Z0-9]{1,3})?|\*)$/;

/** Parse `cloudflare:KR` / `vultr:KR-11` / `cloudflare:*`. */
export function parseSelector(value: string): Selector {
  const raw = String(value ?? "").trim();
  const colon = raw.indexOf(":");
  if (colon < 0) {
    throw new FeedError(`geofeed value must be "<feed>:<selector>", e.g. cloudflare:KR — got "${raw}"`);
  }
  const feed = raw.slice(0, colon).trim().toLowerCase();
  const scope = raw.slice(colon + 1).trim().toUpperCase();
  if (!FEED_NAME.test(feed)) {
    throw new FeedError(`geofeed feed name "${feed}" must be 1-31 chars of lowercase letters, digits or hyphen`);
  }
  if (!SCOPE.test(scope)) {
    throw new FeedError(
      `geofeed selector "${scope}" must be a country ("KR"), a subdivision ("KR-11") or "*" — ` +
        `partial wildcards are not accepted`,
    );
  }
  return { feed, scope };
}

/**
 * Prefixes a selector matches, sorted.
 *
 * ## Why an empty match throws
 *
 * A selector matching nothing renders a rule with no address condition, and a rule with no address
 * condition matches **everything**. On an allow that is the whole internet; the mistake is silent
 * because the feed parsed fine and the policy looks correct. `objects.ts` refuses empty groups for
 * exactly this reason, and a typo'd country code (`KP` for `KR`) is a far more likely way to get here
 * than an empty group is.
 *
 * ## Why the cap is on the selection, not just the feed
 *
 * The feed cap defends the parse; this one defends the render. `cloudflare:*` is 138,213 prefixes and
 * belongs in a named set, not inline — a caller that has not arranged for that should be told before
 * it produces a ruleset no host can load.
 */
export function selectPrefixes(
  feed: ParsedFeed,
  selector: Selector,
  limits: FeedLimits = FEED_LIMITS,
): string[] {
  const want = selector.scope;
  const matched = feed.entries.filter((e) => {
    if (want === "*") return true;
    if (want.includes("-")) return e.region === want;
    return e.country === want;
  });

  if (matched.length === 0) {
    throw new FeedError(
      `geofeed selector "${selector.feed}:${selector.scope}" matches no prefixes — refusing, because a ` +
        `rule with no address condition matches all traffic. Check the code against the feed's contents.`,
    );
  }
  if (matched.length > limits.maxSelected) {
    throw new FeedError(
      `geofeed selector "${selector.feed}:${selector.scope}" matches ${matched.length} prefixes, above ` +
        `the ${limits.maxSelected} limit for a single object`,
    );
  }

  // Sorted so the same feed and selector always render byte-identical. Unsorted output would make
  // ruleset hashes depend on feed line order, and every drift baseline in the project rests on that
  // hash meaning "the same rules".
  return matched.map((e) => e.prefix).sort();
}

// No `isFeedError` helper here. One was written and had **zero callers** — the same shape as
// `missingObjects` before H16 — and it was the only reason this module imported `policy.ts`, which made
// the dependency circular once `policy.ts` needed `parseSelector`. Callers that must distinguish check
// `statusCode`, which both error types carry.
