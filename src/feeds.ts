// The feeds this project is willing to fetch.
//
// A registry, not a discovery mechanism: a URL that is not here cannot be fetched, so adding a source
// of firewall rules is a reviewed code change rather than a runtime argument.
//
// ## Why this file is tracked while `policy/` is not
//
// These URLs are public and identical for every deployment — they name Cloudflare's own published
// ranges, not anything about this site. `policy/` is the opposite: it is a map of one specific
// infrastructure, which is why it stays out of git.

import type { FeedSource } from "./snapshot.ts";

/** A registered feed, with the note explaining what it is for. */
export interface RegisteredFeed extends FeedSource {
  notes: string;
}

/**
 * ## Why Cloudflare's *ingress* list and not its geofeed
 *
 * The design document originally registered `api.cloudflare.com/local-ip-ranges.csv` (138,213 lines,
 * measured) and selected `cloudflare:KR` from it. That was the wrong dataset, and the reason is worth
 * keeping: the CSV is **geographic** — it answers "which country is this Cloudflare edge in". The
 * question a policy needs answered is "will a request reaching our origin come from here", and
 * Cloudflare publishes that separately as `/ips-v4` and `/ips-v6`.
 *
 * The difference is not academic:
 *
 * ```
 *                          prefixes   rendered JSON   named set needed?
 * ingress list (this)            22          6.7 KB   no
 * cloudflare:KR               1,368           249 KB  no, but one 21 KB rule line
 * cloudflare:*              138,213        24,987 KB  yes — 6x the agent's 4 MB ceiling
 * ```
 *
 * All three numbers are measured. The last one also exceeds the relay's 8 MB bundle limit, and
 * rendering a named set would require widening the agent's artifact allowlist (`ALLOWED_OBJECTS` holds
 * `table`, `chain`, `rule` — measured: an artifact carrying a `set` is refused) on all seven hosts. So
 * choosing the right dataset removed a gateway-resident code change, not just some bytes.
 *
 * ## What this narrows, and what it does not
 *
 * Restricting an origin's inbound to these prefixes removes internet-wide scanning and direct hits. It
 * is **not** authentication: any request that passed through Cloudflare arrives from here, including one
 * an attacker sent through their own Cloudflare zone pointed at our origin. Authenticated Origin Pulls
 * or a shared secret is what proves the request came through *our* configuration.
 *
 * ## Two URLs, one feed
 *
 * Registered together because a policy needs both families or it silently covers half the address
 * space — this environment's standing failure mode (public IPv6 is assigned on every host). One failed
 * fetch abandons the whole refresh for the same reason.
 */
const CLOUDFLARE_INGRESS: RegisteredFeed = {
  id: "cf-ingress",
  urls: ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"],
  limits: {
    // A few hundred bytes in practice. A ceiling this tight is a guard in its own right: if this list
    // ever returns something the size of a geofeed, the URL is not returning what it used to.
    maxBytes: 256 * 1024,
    maxPrefixes: 500,
    maxSelected: 500,
  },
  notes:
    "Cloudflare edge ranges — use as `cf-ingress:*`. Narrows an origin's inbound to Cloudflare; " +
    "does not authenticate it. No country field, so only `:*` selects.",
};

export const FEEDS: readonly RegisteredFeed[] = [CLOUDFLARE_INGRESS];

export function feedById(id: string): RegisteredFeed | null {
  return FEEDS.find((f) => f.id === id) ?? null;
}
