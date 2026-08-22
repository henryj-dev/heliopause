// Routes, declared and observed.
//
// ## Why a firewall declares routes at all
//
// A packet reaches a filter only if routing sent it there, so a ruleset and a route table are two
// halves of one answer. Until 2026-08-16 only one half was visible here, and the moment the other
// arrived it reported something nobody knew: two `proto static` routes on gw-01.dev carry every
// packet bound for the cluster's pod and service ranges, and they exist **only in that kernel**.
// Rebuild the host and they are gone; nothing in this system would notice until the gateway stopped
// reaching the cluster.
//
// Observation alone cannot close that. `proto static` says "a person or a script put this here",
// which names who probably knows — it cannot say whether anyone intended it. Only a declaration can,
// and the difference between the two questions is this file.
//
// ## What the observation got wrong, and what fixed it
//
// The first classifier called a route hand-added whenever its protocol was not one of the known
// automatic ones, and treated a **missing** protocol the same way. Four of gw-01.dev's six flagged
// routes were `wg0` routes with no protocol at all, and the test asserting that behaviour claimed
// they had "no other record".
//
// They do. Measured 2026-08-17: the peer's `AllowedIPs` is
// `10.255.0.0/16 10.254.0.0/16 10.16.0.0/16 10.253.0.0/16`, and the four routes are exactly those.
// `wg-quick` installs them from that config. So two thirds of the column was a false positive, and
// the comment justifying it was a claim wider than what had been measured — the failure this
// repository keeps finding in its own prose.
//
// The cure is not a cleverer guess. An origin can be *stated* — by whoever installs the route — and
// a declaration is where that statement lives. `owner` is the field, and it is also the safety
// boundary for applying routes: heliopause may only ever write the ones it owns. Fighting wg-quick
// or a DHCP lease over a route is a loop with a fleet on the other end of it.

/** Who installs a declared route. Not a guess — a statement, reviewed in the policy repository. */
export type RouteOwner =
  /** wg-quick, from the peer's `AllowedIPs`. Declared here so the fleet view stops calling it unowned. */
  | "wireguard"
  /**
   * An idempotent provisioning script installs it, and re-running that script is the repair.
   *
   * **This value exists because "operator" was wrong.** The two `proto static` routes on gw-01.dev were
   * declared with a note saying they were written down nowhere — no manifest, no policy, no
   * provisioning script. All three clauses were false, and the runbook says so plainly: stardust's
   * `scripts/vpc-bootstrap/gateway/add-node.sh` installs the pod and service routes on a gateway and
   * is idempotent, and `dnsmasq` serves the same destinations to every non-node client in the VPC
   * through `option-121`.
   *
   * The difference matters to whoever reads a drift report. `operator` says a human typed it and there
   * is nothing to re-run; `provisioning` names the thing to re-run. Recording the wrong one turns a
   * one-command repair into an investigation.
   */
  | "provisioning"
  /**
   * A person ran `ip route add` and there is no config behind it.
   *
   * Rare, and it should stay rare — this is the only owner whose repair is "ask somebody what they
   * meant". Reach for `provisioning` first and check whether a script already does it.
   */
  | "operator"
  /**
   * heliopause installs it. Reserved for the apply half; nothing writes routes yet, so a declaration
   * using this owner describes an intention rather than a mechanism — see `readyToApply`.
   */
  | "heliopause";

/**
 * One route this deployment says should exist.
 *
 * Deliberately not the kernel's full route model. `metric`, `scope`, `src` and the rest exist and are
 * not declared: a field this file accepts is a field the comparison has to match on, and matching on
 * something the kernel normalises differently produces drift that is not drift. The four here are
 * what identify a route to a reader.
 */
export interface RouteDecl {
  /** `10.17.128.0/18`, or `default`. Exactly as `ip route` prints it. */
  dst: string;
  /** Next hop, absent for a route that is on-link. */
  via?: string;
  /** Interface. Absent means any — a route matched by destination alone. */
  dev?: string;
  /** Routing table. Absent means `main`, which is what `ip route` shows by default. */
  table?: string;
  /** Who installs it. */
  owner: RouteOwner;
  /**
   * Why this route exists, in a sentence. Required, and required for the same reason the policy
   * rules' notes are: the two routes that started this were undiscoverable *because* the reason for
   * them lived in one operator's memory.
   */
  note: string;
}

/** How a route got there, as far as the kernel will say. Three values, because there are three answers. */
export type RouteOrigin =
  /** `kernel`, `dhcp`, `ra`, or a routing daemon. Something else owns it and can be asked. */
  | "automatic"
  /** `proto static` or `boot`: a person or a script. */
  | "static"
  /**
   * No protocol reported at all. **Not the same as static** — this is the case the first classifier
   * got wrong. `wg-quick` produces it, and so does anything using the kernel's default of `unspec`.
   */
  | "unstated";

/** A route as the agent observed it. `origin` is absent from agents older than 2026-08-17. */
export interface ObservedRoute {
  dst: string;
  via: string;
  dev: string;
  proto: string;
  table: string;
  origin?: RouteOrigin;
  /**
   * The old field, kept so an older agent's report still parses.
   *
   * **Not read when `origin` is present, and not trusted when it is absent.** It carried the false
   * positive above, so mixing the two eras would put a known-wrong verdict next to a correct one in
   * the same column — the same reason the exchange index keeps its two eras of read-marks apart.
   */
  handAdded?: boolean;
}

/**
 * What the comparison says about one route.
 *
 * `missing` and `undeclared` are the two findings. The rest exist so that every observed route lands
 * in a named bucket rather than being filtered out of the answer — a comparison that only lists
 * problems cannot be checked for having looked at everything.
 */
export type RouteVerdict =
  /** Declared and present. */
  | "ok"
  /** Declared and **not** on the host. A rebuild lost it, or it was never applied. */
  | "missing"
  /** On the host, put there by a person or a script, and declared nowhere. The finding that started this. */
  | "undeclared"
  /** On the host with no protocol and no declaration. Says so rather than guessing an owner. */
  | "unstated"
  /** On the host and owned by something that can be asked — the kernel, a lease, a daemon. */
  | "automatic";

export interface RouteRow {
  dst: string;
  via: string;
  dev: string;
  table: string;
  verdict: RouteVerdict;
  /** Present when a declaration matched, or when one was expected and nothing did. */
  owner?: RouteOwner;
  note?: string;
  /** What the kernel said, for a row that came from the host. Absent on a `missing` row. */
  origin?: RouteOrigin;
}

export interface RouteComparison {
  /**
   * `null` when this host has no route declaration at all.
   *
   * **A host with no model is not a host whose routes are undeclared.** The first is "we have not
   * described this host's routing"; the second is "we have, and this route is not in it". Rendering
   * them the same way would turn every host outside the model into a false finding, and the fleet has
   * three such hosts today (prod and util publish from their own site modules).
   */
  rows: RouteRow[] | null;
  missing: number;
  undeclared: number;
  unstated: number;
}

const table = (t: string | undefined): string => (t === undefined || t === "" ? "main" : t);

/**
 * True when the declaration and the observed route are the same route.
 *
 * `dev` and `via` are compared only when the declaration states them. A declaration that names a
 * destination and an owner and leaves the interface open is a legitimate thing to write — the mesh
 * routes are identified by where they go, not by an interface name that a rename would change.
 */
function same(d: RouteDecl, o: ObservedRoute): boolean {
  if (d.dst !== o.dst) return false;
  if (table(d.table) !== table(o.table)) return false;
  if (d.dev !== undefined && d.dev !== o.dev) return false;
  if (d.via !== undefined && d.via !== (o.via || undefined)) return false;
  return true;
}

/**
 * Classify what the kernel said. Kept here rather than in the agent so the rule is testable in one
 * place and an older agent's report gets the same treatment as a new one's.
 */
export function originOf(proto: string): RouteOrigin {
  if (proto === "") return "unstated";
  if (proto === "static" || proto === "boot") return "static";
  return "automatic";
}

/**
 * Compare what this deployment declared against what the host reports.
 *
 * Order of the result is the order a reader wants: the findings first, then everything else, so a
 * long table does not bury the two rows that need a decision.
 */
export function compareRoutes(
  declared: readonly RouteDecl[] | undefined,
  observed: readonly ObservedRoute[] | null | undefined,
): RouteComparison {
  if (declared === undefined || observed === null || observed === undefined) {
    return { rows: null, missing: 0, undeclared: 0, unstated: 0 };
  }
  const rows: RouteRow[] = [];
  const matched = new Set<ObservedRoute>();

  for (const d of declared) {
    const hit = observed.find((o) => !matched.has(o) && same(d, o));
    if (hit) matched.add(hit);
    rows.push({
      dst: d.dst,
      via: hit ? hit.via : (d.via ?? ""),
      dev: hit ? hit.dev : (d.dev ?? ""),
      table: table(d.table),
      verdict: hit ? "ok" : "missing",
      owner: d.owner,
      note: d.note,
      // The observed protocol travels on an `ok` row so a declaration claiming `owner: "wireguard"`
      // over a route the kernel calls `static` is visible rather than smoothed over.
      ...(hit ? { origin: originOf(hit.proto) } : {}),
    });
  }

  for (const o of observed) {
    if (matched.has(o)) continue;
    const origin = o.origin ?? originOf(o.proto);
    rows.push({
      dst: o.dst,
      via: o.via,
      dev: o.dev,
      table: table(o.table),
      verdict: origin === "static" ? "undeclared" : origin === "unstated" ? "unstated" : "automatic",
      origin,
    });
  }

  const rank: Record<RouteVerdict, number> = { missing: 0, undeclared: 1, unstated: 2, ok: 3, automatic: 4 };
  rows.sort((a, b) => rank[a.verdict] - rank[b.verdict] || a.table.localeCompare(b.table) || a.dst.localeCompare(b.dst));
  return {
    rows,
    missing: rows.filter((r) => r.verdict === "missing").length,
    undeclared: rows.filter((r) => r.verdict === "undeclared").length,
    unstated: rows.filter((r) => r.verdict === "unstated").length,
  };
}

/**
 * Whether heliopause could apply this declaration itself.
 *
 * **Nothing calls this to act yet, and that is stated rather than implied.** It answers one question
 * — which declared routes are heliopause's to write — and the fleet view uses the count to say how
 * much of the routing model is describing versus controlling. Writing routes is the next step and it
 * is the first thing this system would install that can strand a host from the channel it would use
 * to roll back, so it does not arrive as a side effect of a declaration format.
 */
export function readyToApply(declared: readonly RouteDecl[] | undefined): number {
  return (declared ?? []).filter((d) => d.owner === "heliopause").length;
}

/**
 * Ranges whose route must not be rewritten, derived from the management baseline.
 *
 * ## The gap this closes
 *
 * The applier's only verification is the heartbeat, and a successful heartbeat proves **the relay path
 * survived** — not the operator's. Those are different paths: the relay is one address on the VPC
 * gateway, and management arrives from somewhere else entirely. So a declared route that changes the
 * next hop for the management range cuts every operator out of the host and then **confirms cleanly**,
 * because the heartbeat never used that route. The deadline exists and would never fire.
 *
 * The nftables half solved the same problem with `mustContain`: a ruleset that renders without its
 * management rules is undone at once rather than waiting for a timer that has nothing to notice. This
 * is that check for routes, and it is a refusal rather than a post-check because a route is applied in
 * one syscall — by the time you could look, the path you would look through is gone.
 *
 * ## Why the baseline, and not a new field
 *
 * `cfg.baseline` already names where management comes from, it is already reviewed, and it is already
 * the thing the ruleset protects. A second list would be a second thing to keep in step, and the
 * failure of that is silent: the two agree today and disagree after the change nobody propagated.
 *
 * Entries with no sources are skipped. An empty `srcCidrs` means "every source", which names no
 * particular return path — treating it as every address would refuse every route, including the ones
 * that are safe, and a guard that refuses everything gets removed rather than obeyed.
 */
export function managementGuard(
  baseline: readonly { srcCidrs?: readonly string[] }[] | undefined,
): string[] {
  const out = new Set<string>();
  for (const rule of baseline ?? []) {
    for (const cidr of rule.srcCidrs ?? []) {
      // v4 only, matching what the applier can compare: the agent reads `ip -4 route`. A v6 entry here
      // would be carried to a check that cannot use it, which reads as protection and is not.
      if (cidr.includes(":")) continue;
      out.add(cidr);
    }
  }
  return [...out].sort();
}
