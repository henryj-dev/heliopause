// The catalogue screens — objects (5), services (6), feeds (7), dynamic membership (8) and the
// address space a site actually touches (2).
//
// ## Two of the designed screens are missing on purpose
//
// **3 존 and 5-b 신원 are not here, and not because they are next.** Measured 2026-08-07:
//
//   - `EndpointKind` is host / host-group / cidr / object / internet / any / k8s-service /
//     k8s-namespace / k8s-label / geofeed. **There is no zone**, and no trust level anywhere in the
//     model. A zone screen would have to invent the concept before it could show one.
//   - There is no device or user model either. Identity belongs to the identity provider; this
//     project authorises certificate subjects and OIDC roles and holds no inventory of people.
//
// Both would need a model change first. Projecting something that looks like them from what exists
// would put a table on screen that nothing else in the system agrees with.
//
// ## Why `2 네트워크` is derived and says so
//
// A network is not declared either. What a site does have is the address space its rules actually
// reference, and that is worth showing — it answers "what does this policy touch" without claiming
// to be an inventory. The page labels it as derived so nobody reads it as a declaration.

import type { Endpoint, Policy } from "./policy.ts";
import type { AddressObject, ServiceObject } from "./objects.ts";
import type { PublishHost } from "./publish.ts";

// ── Objects (5) and services (6) ──────────────────────────────────────────────

export interface ObjectRow {
  id: string;
  name: string;
  /** Member endpoints, already stringified. */
  members: string[];
  notes: string | null;
  /** Policy ids referencing this object. Empty is the finding — an object nothing uses. */
  usedBy: string[];
}

/**
 * Address objects, with who references them.
 *
 * `usedBy` empty is the reason this screen earns its place: an object nobody references is dead
 * configuration that still reads as protection when someone scans the catalogue.
 */
export function objectRows(
  objects: readonly AddressObject[],
  policies: readonly Policy[],
): ObjectRow[] {
  return objects.map((o) => ({
    id: o.id,
    name: o.name,
    members: o.members.map(endpointLabel),
    notes: o.notes ?? null,
    usedBy: policies
      .filter((p) => refersToObject(p.src, o) || refersToObject(p.dst, o))
      .map((p) => p.id),
  }));
}

/** Service objects. `members` are port specs; the protocol lives on the policy, not here. */
export function serviceRows(
  services: readonly ServiceObject[],
  policies: readonly Policy[],
): ObjectRow[] {
  return services.map((s) => ({
    id: s.id,
    name: s.name,
    members: [...s.members],
    notes: s.notes ?? null,
    // A service object is referenced from `ports`, not from an endpoint — `"@ssh-admin"`. By id or
    // by name, for the reason spelled out on `refersToObject`.
    usedBy: policies
      .filter((p) => p.ports.split(",").some((x) => {
        const ref = x.trim();
        return ref === `@${s.id}` || ref === `@${s.name}`;
      }))
      .map((p) => p.id),
  }));
}

/**
 * Does this endpoint name that object — by id **or** by name?
 *
 * ## Both, because the resolver accepts both
 *
 * `objectCidrs` in `device-policy.ts` is what actually expands an object endpoint into addresses,
 * and it matches `o.id === e.value || o.name === e.value`. `objects.ts` documents the reference as
 * the *name* (`ports` as `"@<name>"`, `src`/`dst` as `{ kind: "object", value: "<name>" }`), and
 * `normalizePorts` validates the thing after the `@` against the name character set.
 *
 * This asked only about the id. So every policy that referenced an object the documented way was
 * missing from `usedBy` — on the one screen whose stated reason for existing is that
 * "`usedBy` empty … is dead configuration that still reads as protection". An operator reading an
 * empty column and deleting the object gets a render failure rather than a silent hole
 * (`assertPorts` refuses an unresolved `@ref`), which is why this is a wrong answer and not an
 * outage. It is still the wrong answer, given by the column that exists to give the right one.
 *
 * Matching both here rather than picking one keeps this screen agreeing with the resolver. That an
 * id can collide with another object's name is a real ambiguity, and it is refused where it
 * matters — `objectCidrs` throws when a reference resolves to two objects.
 */
function refersToObject(e: Endpoint, o: { id: string; name: string }): boolean {
  return e.kind === "object" && (e.value === o.id || e.value === o.name);
}

// ── Feeds (7) ─────────────────────────────────────────────────────────────────

export interface FeedRow {
  /** The feed reference as written in the policy — a URL or a well-known name. */
  ref: string;
  /** Policy ids that resolve through this feed. */
  usedBy: string[];
}

/**
 * Feeds referenced by policy.
 *
 * There is no feed *registry* in the config — a feed is named at the point of use, by a `geofeed`
 * endpoint. So this is a projection of what the rules ask for, not a list of what is configured, and
 * a feed appears here exactly when something depends on it.
 *
 * Freshness is not here. It is a property of a fetch, and fetching belongs to `heliopause-feed`;
 * a screen that showed a stale timestamp it had computed itself would be reporting on its own
 * process rather than on the fleet's.
 */
export function feedRows(policies: readonly Policy[]): FeedRow[] {
  const byRef = new Map<string, string[]>();
  for (const p of policies) {
    for (const e of [p.src, p.dst]) {
      if (e.kind !== "geofeed" || !e.value) continue;
      const list = byRef.get(e.value) ?? [];
      list.push(p.id);
      byRef.set(e.value, list);
    }
  }
  return [...byRef.entries()].sort(([a], [b]) => a.localeCompare(b))
    .map(([ref, usedBy]) => ({ ref, usedBy }));
}

// ── Dynamic membership (8) ────────────────────────────────────────────────────

export interface MembershipRow {
  /** `namespace` or `selector`, and which one changes what the count means. */
  kind: "namespace" | "selector";
  name: string;
  members: string[];
  /** When the cluster was read. A count without this is one an operator reads as current. */
  at: string;
  /** Which applier reported it. */
  host: string;
  /**
   * Policy ids whose endpoints name this namespace or selector (M10).
   *
   * A count on its own does not say what depends on it. `arc-runners: 0 pods` is normal between CI
   * jobs and alarming if a rule was written to contain something that should be running — and the
   * row read the same either way. With this, an empty count names the rules that are currently
   * governing nothing.
   *
   * **This is a selection reading, not an enforcement one.** Cilium accepts a policy that selects no
   * endpoint, and nothing here proves eBPF is refusing a packet; that would need the privileged
   * Cilium telemetry this deployment deliberately does not grant. What it closes is the narrower and
   * more common case: a rule whose selector matches nothing at all.
   */
  usedBy: string[];
}

/**
 * Pod membership, as the applier last reported it.
 *
 * **A count of zero is not "safe".** For a CI runner namespace it means no job is running right now,
 * and the pods appear the moment one starts. That is why the timestamp travels with the number and
 * why this is a table of observations rather than a summary.
 */
export function membershipRows(
  hosts: readonly {
    host: string;
    workload?: { membership?: { at: string; namespaces: Record<string, string[]>; labelled: Record<string, string[]> } | null } | null;
  }[],
  policies: readonly Policy[] = [],
): MembershipRow[] {
  // Built once, from the same endpoints `selectorsToWatch` derives the questions from — so a row and
  // the query behind it cannot disagree about which policy asked.
  const byNamespace = new Map<string, string[]>();
  const byLabel = new Map<string, string[]>();
  for (const p of policies) {
    for (const e of [p.src, p.dst]) {
      const index = e.kind === "k8s-namespace" ? byNamespace : e.kind === "k8s-label" ? byLabel : null;
      if (!index || !e.value) continue;
      const list = index.get(e.value) ?? [];
      if (!list.includes(p.id)) list.push(p.id);
      index.set(e.value, list);
    }
  }
  const out: MembershipRow[] = [];
  for (const h of hosts) {
    const m = h.workload?.membership;
    if (!m) continue;
    // Only keys the applier actually answered are here: a namespace or selector it could not read is
    // omitted from the report rather than sent as empty, so every `[]` below is "queried, and none".
    for (const [name, members] of Object.entries(m.namespaces)) {
      out.push({ kind: "namespace", name, members: [...members], at: m.at, host: h.host, usedBy: [...(byNamespace.get(name) ?? [])].sort() });
    }
    for (const [name, members] of Object.entries(m.labelled)) {
      out.push({ kind: "selector", name, members: [...members], at: m.at, host: h.host, usedBy: [...(byLabel.get(name) ?? [])].sort() });
    }
  }
  return out.sort((a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name));
}

// ── Address space actually referenced (2) ─────────────────────────────────────

export interface AddressSpaceRow {
  cidr: string;
  /** How many policies resolve to this CIDR as a source. */
  asSource: number;
  /** Hosts whose destination addresses include it. */
  asHost: string[];
}

/**
 * The address space this site's rules touch.
 *
 * **Derived, not declared.** There is no network object in the model; this is the union of resolved
 * source CIDRs and host destination addresses, which is what the rules actually reference. It
 * answers "what does this policy touch" and deliberately does not claim to be an inventory of the
 * site's networks — the two differ exactly where a network exists and no rule mentions it, and that
 * gap is invisible from here.
 */
export function addressSpaceRows(hosts: readonly PublishHost[]): AddressSpaceRow[] {
  const src = new Map<string, number>();
  const dst = new Map<string, Set<string>>();
  for (const h of hosts) {
    for (const item of h.items) {
      for (const c of item.srcCidrs) src.set(c, (src.get(c) ?? 0) + 1);
      for (const c of item.dstCidrs) {
        const s = dst.get(c) ?? new Set<string>();
        s.add(h.id);
        dst.set(c, s);
      }
    }
  }
  const all = new Set([...src.keys(), ...dst.keys()]);
  return [...all].sort().map((cidr) => ({
    cidr,
    asSource: src.get(cidr) ?? 0,
    asHost: [...(dst.get(cidr) ?? [])].sort(),
  }));
}

/** `k8s-namespace:arc-runners`, `cidr:10.0.0.0/8`, `any`. Kind first — kind changes meaning. */
function endpointLabel(e: Endpoint): string {
  return e.value ? `${e.kind}:${e.value}` : e.kind;
}
