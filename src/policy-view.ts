// Screen 10 of the design document — the policy table — as a pure projection of a site module.
//
// ## Why this cannot live in the manager
//
// The manager never sees a policy. It receives a `PlanBundle`, and a bundle carries the *rendered*
// output — nftables text and a Cilium document — with no zones, no service catalogue and no policy
// rows. That is deliberate: the manager pod runs inside the cluster it protects, so the policy
// repository is not in its image and must not be. See 인터페이스-설계.md 결정 10.
//
// So this projection runs where the policy is: the operator's workstation, which already holds the
// repository and already runs the renderer.
//
// ## What it computes that the source does not say
//
// A policy object is a rule. What an operator needs to know about it is what it *does to this site*,
// and that is a join between the rule and the hosts:
//
//   - **how many hosts it actually renders a rule on.** Zero is the finding worth having, and it
//     cannot be read off the source: a site module maps every authored policy onto every host in
//     its group, and the *renderer* is what decides the rule does not apply here. So this takes the
//     renderer's `skipped` list. Without it the flag can never fire — which is how the first draft
//     of this file shipped a check that was structurally dead, caught while writing its test.
//   - **how wide it is.** Any-source with no port restriction is not wrong, but it is the shape a
//     mistake takes, and it should be visible without reading CIDRs.
//
// Both are derived here rather than in the page, so they can be tested without a browser.

import type { Policy } from "./policy.ts";
import type { PublishHost } from "./publish.ts";

/** Everything that is any address, in both families. Rendered as "any source" by `nft.ts`. */
const ANY = new Set(["0.0.0.0/0", "::/0"]);

/** Why a row is flagged. Slugs rather than prose, so tests do not depend on wording. */
export type PolicyRisk =
  /** Renders to no host at all. The rule exists and does nothing. */
  | "renders-nowhere"
  /** Allows from any source. Not wrong; the shape a mistake takes. */
  | "any-source"
  /** No port restriction — the whole protocol. */
  | "all-ports"
  /** Present in the module but switched off. Shown, never hidden (규약 9: 삭제는 없다). */
  | "disabled";

export interface PolicyRow {
  id: string;
  name: string;
  action: Policy["action"];
  /** `"drop"` or `"reject"`. Only meaningful for a deny. */
  denyMode: Policy["denyMode"];
  proto: Policy["proto"];
  /** As authored — `"22"`, `"80,443"`, `"@service-object"`, or `""` for every port. */
  ports: string;
  priority: number;
  enabled: boolean;
  notes: string | null;
  /** Host ids this policy renders an input rule on, in site order. Skips are excluded. */
  hosts: string[];
  /** Host ids that list this policy but where the renderer produced nothing. */
  skippedOn: string[];
  /**
   * Whether the caller supplied render results.
   *
   * `false` means `hosts` is "listed on" rather than "renders on", and `renders-nowhere` was not
   * evaluated. A page that shows the count without showing this would be asserting something it was
   * never told.
   */
  placementKnown: boolean;
  /** Host ids where it renders an egress rule instead. */
  egressHosts: string[];
  /** Resolved source CIDRs, unioned across hosts and sorted. Empty means any. */
  srcCidrs: string[];
  risks: PolicyRisk[];
}

/** The site's shape, as far as this projection needs it. */
export interface PolicySource {
  hosts: readonly PublishHost[];
  /**
   * Policy ids the renderer skipped, per host id.
   *
   * Required for `renders-nowhere` to mean anything. A policy present in a host's `items` has not
   * necessarily produced a rule there — `nft.ts` skips one whose destination does not cover the
   * host, and that skip is the difference between "protecting this host" and "listed next to it".
   *
   * Omitted is honest but weaker: every placed policy then counts as placed, and the flag cannot
   * fire. `placementKnown` on the row says which of the two a reader is looking at.
   */
  skipped?: ReadonlyMap<string, ReadonlySet<string>>;
}

/**
 * Project a site into one row per policy.
 *
 * Ordered by `priority` then `id`, which is the order the renderer evaluates them in once a chain
 * defaults to deny. Showing them in module order instead would let a reader conclude the wrong thing
 * about which rule wins.
 *
 * A policy appearing on several hosts is **one row**, not one per host. The question this table
 * answers is "what does this rule do", and the hosts are its answer, not its identity.
 */
export function policyRows(site: PolicySource): PolicyRow[] {
  const byId = new Map<string, PolicyRow>();

  const touch = (p: Policy): PolicyRow => {
    let row = byId.get(p.id);
    if (!row) {
      row = {
        id: p.id,
        name: p.name,
        action: p.action,
        denyMode: p.denyMode,
        proto: p.proto,
        ports: p.ports,
        priority: p.priority,
        enabled: p.enabled,
        notes: p.notes ?? null,
        hosts: [],
        skippedOn: [],
        egressHosts: [],
        srcCidrs: [],
        placementKnown: site.skipped !== undefined,
        risks: [],
      };
      byId.set(p.id, row);
    }
    return row;
  };

  for (const h of site.hosts) {
    const skippedHere = site.skipped?.get(h.id);
    for (const item of h.items) {
      const row = touch(item.policy);
      if (skippedHere?.has(item.policy.id)) row.skippedOn.push(h.id);
      else row.hosts.push(h.id);
      // Collected even for a skipped host: the resolved source is a fact about the rule, and hiding
      // it on the row that says the rule does nothing removes the evidence for why.
      for (const c of item.srcCidrs) if (!row.srcCidrs.includes(c)) row.srcCidrs.push(c);
    }
    for (const e of h.egress ?? []) {
      const row = touch(e.policy);
      row.egressHosts.push(h.id);
    }
  }

  for (const row of byId.values()) {
    row.srcCidrs.sort();
    // Order matters only for reading: the first flag is the one that says the rule does nothing.
    if (row.placementKnown && !row.hosts.length && !row.egressHosts.length) {
      row.risks.push("renders-nowhere");
    }
    // An empty resolved source is what `nft.ts` renders as "any source", and so is an explicit
    // all-addresses CIDR. Treating only the explicit one as wide would miss the commoner spelling.
    const anySource = row.srcCidrs.length === 0 || row.srcCidrs.some((c) => ANY.has(c));
    if (anySource && row.action === "allow") row.risks.push("any-source");
    if (row.ports.trim() === "") row.risks.push("all-ports");
    if (!row.enabled) row.risks.push("disabled");
  }

  return [...byId.values()].sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id));
}

/** Counts for the screen's header. Derived here so the page cannot compute them differently. */
export function policySummary(rows: readonly PolicyRow[]): {
  total: number;
  allow: number;
  deny: number;
  disabled: number;
  nowhere: number;
} {
  return {
    total: rows.length,
    allow: rows.filter((r) => r.action === "allow").length,
    deny: rows.filter((r) => r.action === "deny").length,
    disabled: rows.filter((r) => !r.enabled).length,
    nowhere: rows.filter((r) => r.risks.includes("renders-nowhere")).length,
  };
}
