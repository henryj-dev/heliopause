// Named address ranges, and what a policy crossing between them means.
//
// ## Why this exists, and why it did not until now
//
// The GUI design has had a zone screen since 2026-07-29 and it could not be built: there is no zone
// in `EndpointKind`, and no trust level anywhere in the model. Projecting something zone-shaped from
// what existed would have put a table on screen that nothing else in the system agreed with.
//
// So the concept is defined here rather than inferred. A zone is a **name for a range that policies
// already reference** — `DEV.mgmt`, `DEV.podCidr`, the gateway backbone — plus one judgement the
// model did not carry: how much this deployment trusts what lives there.
//
// ## The trust level has to do something or it is decoration
//
// A number rendered in a column and read by nobody is worse than an absent column: it looks like a
// control. So `crossings` reports every policy that admits a **less trusted** zone into a more
// trusted one. That is not a refusal — plenty of them are correct and deliberate, starting with
// every rule that lets the internet reach a mail server — but it is the list an operator should be
// able to produce on demand, and until now producing it meant reading the policy set by eye.
//
// Trust is a property of the deployment, not of the address. `10.254.0.0/16` is trusted here because
// operators reach it through WARP with device posture behind them; the same range somewhere else
// would deserve nothing. That is why it is stated in the site module and not derived.
import type { Endpoint, Policy } from "./policy.ts";
import { cidrRange } from "./nft.ts";

/**
 * How far this deployment trusts what sits in a zone. Higher is more trusted.
 *
 * Deliberately coarse. A finer scale invites arguments about whether something is a 6 or a 7, and
 * the only question this answers is "is traffic moving toward more trust than it came from".
 */
export type Trust = 0 | 1 | 2 | 3;

export const TRUST_LABEL: Record<Trust, string> = {
  0: "untrusted",
  1: "low",
  2: "medium",
  3: "high",
};

export interface Zone {
  /** Stable id, used in policy notes and in the table. */
  id: string;
  name: string;
  /** IPv4 CIDRs. A zone may hold several — `dev` is one VPC but four ranges. */
  cidrs: string[];
  /** IPv6 CIDRs, when the zone has any. Empty is normal: most of this fleet is v4-only. */
  cidrs6?: string[];
  trust: Trust;
  /** What lives here, in one line. Shown in the table, so it is written for an operator. */
  notes?: string;
}

/** A policy that lets a less trusted zone reach a more trusted one. */
export interface Crossing {
  policyId: string;
  policyName: string;
  from: Zone;
  to: Zone;
  /** How many levels of trust this gains. Larger is more worth reading. */
  gain: number;
  action: Policy["action"];
}

// ── address arithmetic ────────────────────────────────────────────────────────
//
// `cidrRange` lives in `nft.ts` and is imported rather than reimplemented. It was written three
// times in three shapes before — one of them IPv4-only, which is how `Zone.cidrs6` came to be
// declared and read by nothing. One parser, so "what does this CIDR cover" cannot have two answers.
//
// It carries the family, and this file compares only within one. `::/0` spans a larger number than
// `0.0.0.0/0`, so without that check a single v6 zone swallows every v4 zone.

/**
 * The zone a CIDR belongs to, or null.
 *
 * **Most specific wins.** `10.17.128.0/18` sits inside `10.17.0.0/16`, and answering "dev" for a pod
 * range would lose exactly the distinction the pod range exists to make. Ties cannot happen: two
 * zones claiming the same prefix is a configuration error `zoneConflicts` reports.
 */
export function zoneOf(zones: readonly Zone[], cidr: string): Zone | null {
  const r = cidrRange(cidr);
  if (!r) return null;
  let best: Zone | null = null;
  let bestSize: bigint | null = null;
  for (const z of zones) {
    // Both lists. `cidrs6` was declared and read by nothing — see `range` — so an IPv6 endpoint
    // placed in no zone disappeared from the crossings table rather than being reported.
    for (const c of [...z.cidrs, ...(z.cidrs6 ?? [])]) {
      const zr = cidrRange(c);
      if (!zr) continue;
      // Compared only within a family. The two are different number spaces, and `::/0` contains
      // every v6 address rather than every address — without this an all-v6 zone would swallow the
      // v4 ones by being numerically wider.
      if (zr.family !== r.family) continue;
      if (r.first < zr.first || r.last > zr.last) continue;
      const size = zr.last - zr.first + 1n;
      if (bestSize === null || size < bestSize) {
        best = z;
        bestSize = size;
      }
    }
  }
  return best;
}

/**
 * Zone list problems worth refusing to render over.
 *
 * **Not "overlapping ranges".** The first version looked for two CIDRs that overlap without one
 * containing the other, and that cannot happen: prefixes are aligned, so any two ranges are either
 * nested or disjoint. It was a check for an impossible state, which is the same as no check — it
 * passed on every input including the ones that are genuinely wrong.
 *
 * What can actually go wrong:
 *
 *   · **the same CIDR in two zones** — `zoneOf` then answers whichever has the smaller range, and on
 *     a tie whichever was listed first, so one address carries two trust levels
 *   · **a malformed CIDR** — silently placed in no zone, so every policy touching it disappears from
 *     the crossings list rather than being reported
 */
export function zoneConflicts(zones: readonly Zone[]): Array<{ a: Zone; b: Zone; cidr: string }> {
  const out: Array<{ a: Zone; b: Zone; cidr: string }> = [];
  /** Both lists, so a malformed entry in either is reported rather than silently unzoned. */
  const all = (z: Zone): string[] => [...z.cidrs, ...(z.cidrs6 ?? [])];
  for (let i = 0; i < zones.length; i++) {
    for (const c of zones[i]!.cidrs) {
      if (!cidrRange(c)) out.push({ a: zones[i]!, b: zones[i]!, cidr: `${c} is not a CIDR` });
      // ## The wrong list is its own mistake, and it used to be invisible
      //
      // `cidrs` is the v4 list and `cidrs6` the v6 one. An entry in the wrong one parses fine and
      // then never matches anything, because `zoneOf` compares within a family — so the zone exists,
      // the CIDR is valid, and nothing is ever placed in it. That is indistinguishable from a zone
      // nobody uses, which is why it needs saying rather than inferring.
      else if (cidrRange(c)!.family === "ip6") {
        out.push({ a: zones[i]!, b: zones[i]!, cidr: `${c} is IPv6 but is listed in cidrs — move it to cidrs6` });
      }
    }
    for (const c of zones[i]!.cidrs6 ?? []) {
      if (!cidrRange(c)) out.push({ a: zones[i]!, b: zones[i]!, cidr: `${c} is not a CIDR` });
      else if (cidrRange(c)!.family === "ip") {
        out.push({ a: zones[i]!, b: zones[i]!, cidr: `${c} is IPv4 but is listed in cidrs6 — move it to cidrs` });
      }
    }
    for (let j = i + 1; j < zones.length; j++) {
      for (const ca of all(zones[i]!)) {
        for (const cb of all(zones[j]!)) {
          const ra = cidrRange(ca);
          const rb = cidrRange(cb);
          if (!ra || !rb) continue;
          // Family included: `::/0` and `0.0.0.0/0` both span their whole space and would otherwise
          // compare equal as numbers, reporting a conflict between two zones that cannot overlap.
          if (ra.family === rb.family && ra.first === rb.first && ra.last === rb.last) {
            out.push({ a: zones[i]!, b: zones[j]!, cidr: `${ca} claimed by both` });
          }
        }
      }
    }
  }
  return out;
}

/** Which zone an endpoint names, when it names one at all. */
function endpointZone(zones: readonly Zone[], e: Endpoint, resolved?: readonly string[]): Zone | null {
  if (e.kind === "cidr" && e.value) return zoneOf(zones, e.value);
  // A resolved source list is what the site module hands the renderer; using it means a policy
  // written against a host group is placed by the addresses it actually expands to.
  if (resolved?.length) {
    const found = resolved.map((c) => zoneOf(zones, c)).filter((z): z is Zone => z !== null);
    if (!found.length) return null;
    // ## A source spanning zones takes the least trusted of them
    //
    // The first version returned null unless every address agreed, on the reasoning that a rule with
    // no single origin has no honest crossing. **That silently dropped the rules most worth
    // reading**: a source list holding `203.0.113.9` and `10.17.0.5` disappeared entirely, and the table
    // showed nothing where an operator most needed a row.
    //
    // Least-trusted is the only answer that cannot understate. If any part of a source is untrusted,
    // the policy admits untrusted traffic — the trusted remainder does not make that less true. The
    // symmetric choice for a destination is the same value for the opposite reason: reaching the
    // least trusted thing in a set is the weakest claim the set supports.
    return found.reduce((a, b) => (b.trust < a.trust ? b : a));
  }
  return null;
}

/**
 * Policies that admit a less trusted zone into a more trusted one.
 *
 * **Not a list of faults.** `DEV-MX-PUBLIC` lets the whole internet reach a mail server on 25 and is
 * exactly right; so is every Cloudflare rule. What this produces is the set of places where the
 * deployment's trust ordering is deliberately crossed, which is the review an operator would
 * otherwise do by reading every rule.
 *
 * Denies are included and marked. A deny crossing inward is usually the opposite of a concern, and
 * omitting it would make the table read as "these are the allows" while calling itself crossings.
 */
export function crossings(
  zones: readonly Zone[],
  items: readonly { policy: Policy; srcCidrs?: readonly string[]; dstCidrs?: readonly string[] }[],
): Crossing[] {
  const out: Crossing[] = [];
  for (const it of items) {
    const from = endpointZone(zones, it.policy.src, it.srcCidrs);
    const to = endpointZone(zones, it.policy.dst, it.dstCidrs);
    if (!from || !to || from.id === to.id) continue;
    const gain = to.trust - from.trust;
    if (gain <= 0) continue;
    out.push({ policyId: it.policy.id, policyName: it.policy.name, from, to, gain, action: it.policy.action });
  }
  // Largest gain first: a rule letting untrusted reach high-trust is what a reviewer wants at the top.
  return out.sort((a, b) => b.gain - a.gain || a.policyId.localeCompare(b.policyId));
}

export interface ZoneRow {
  zone: Zone;
  /** Policies whose source resolves into this zone. */
  asSource: number;
  /** Policies whose destination resolves into this zone. */
  asDestination: number;
  /** Crossings that end here — traffic admitted from something less trusted. */
  admits: number;
}

/** The zone table: what each zone is, and how much policy points at it. */
export function zoneRows(
  zones: readonly Zone[],
  items: readonly { policy: Policy; srcCidrs?: readonly string[]; dstCidrs?: readonly string[] }[],
): ZoneRow[] {
  const cross = crossings(zones, items);
  return zones.map((zone) => ({
    zone,
    asSource: items.filter((it) => endpointZone(zones, it.policy.src, it.srcCidrs)?.id === zone.id).length,
    asDestination: items.filter((it) => endpointZone(zones, it.policy.dst, it.dstCidrs)?.id === zone.id).length,
    admits: cross.filter((c) => c.to.id === zone.id).length,
  }));
}
