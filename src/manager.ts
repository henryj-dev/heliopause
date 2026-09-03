// The manager — one per site, and the only thing that renders.
//
// ## What it is for
//
// The relay serves one VPC and deliberately cannot interpret what it serves. The manager is the
// other half: it holds the policy, renders it, publishes generations, and is the only place that
// sees the whole fleet at once. That last property is what this file adds — a relay can answer
// "how is my VPC", and nothing until now could answer "how is the site".
//
// ## Why the aggregation is a pure function
//
// `fleetView` in the relay is pure for the same reason, and the reason is worth restating: the
// interesting cases are the failures. One VPC unreachable, two VPCs on different generations, a
// relay that restarted and has not heard from its hosts yet. Those are trivial to construct as data
// and painful to construct as live infrastructure, so the decision-making stays testable and the I/O
// stays in the caller.
//
// ## What "one VPC is down" must not do
//
// It must not take the answer with it. The relays are separate precisely so a gateway outage is
// contained, and an aggregator that fails the whole request because one relay timed out reports the
// opposite of what the design provides. A failed VPC is **recorded as a failed VPC** and the rest of
// the site is still described — the same rule `observe.sh` follows.

import type { FleetView, HostView } from "./relay.ts";
import type { Contradiction } from "./consistency.ts";
import type { RulesetEvent } from "./protocol.ts";

/** One VPC's relay, as the manager knows it. */
export interface RelaySource {
  /** Short name for display and for keying results — `dev`, `prod`, `util`. */
  name: string;
  /** `https://10.0.0.1:8443`. The manager dials this with an operator certificate. */
  url: string;
  /**
   * PKI directory for **this VPC**, because each VPC has its own CA (V39).
   *
   * That split is deliberate: a CA key that leaks cannot mint an identity another VPC will trust.
   * The consequence lands here — the manager cannot hold one certificate and one anchor for the
   * whole site. It presents a different operator certificate to each relay and verifies each
   * against that VPC's own CA.
   *
   * Measured while wiring this up: with a single CA the manager reached `dev` and got
   * "self-signed certificate in certificate chain" from the other two. The aggregation was right —
   * it reported the two failures and still described `dev` — but the cause was the manager assuming
   * a shared trust root that this site deliberately does not have.
   */
  pkiDir: string;
  /**
   * Which operator certificate in `pkiDir` to present, by name — `hp-manager` for
   * `operator-hp-manager.pem`.
   *
   * Named rather than inferred. A directory holding both a human's certificate and the manager's is
   * the normal state on an operator's workstation, and picking one by sort order would mean the
   * manager silently authenticates as a person. That is exactly the kind of thing an audit log
   * should never have to be consulted to discover.
   *
   * Omitted only when the directory holds exactly one, which is the case in a container that was
   * given just the credential it needs.
   */
  operatorName?: string;
}

/**
 * What one relay answered, or why it did not.
 *
 * A discriminated pair rather than `FleetView | null`: "unreachable" carries a reason, and losing
 * the reason turns a diagnosable outage into an absence.
 */
export type RelayResult =
  | { name: string; url: string; ok: true; view: FleetView }
  | { name: string; url: string; ok: false; error: string };

/** The whole site, assembled from every relay that answered. */
export interface SiteView {
  /**
   * Per VPC, in the order the sources were given. Both reachable and not.
   *
   * Ordered rather than keyed so the display is stable across polls — a map's iteration order is an
   * implementation detail and a fleet view that reorders itself is hard to read at a glance.
   */
  vpcs: RelayResult[];
  /** Hosts across every reachable VPC, each tagged with the VPC it came from. */
  hosts: Array<{
    vpc: string;
    host: string;
    state: string | null;
    generation: string | null;
    current: boolean;
    drifted: boolean;
    ageSec: number | null;
    /**
     * Which rollout stage this host is in, and what is holding it there.
     *
     * **Both were dropped here until 2026-08-11**, and the cost was that this view could show a
     * host stuck on an old generation with no way to say why. `gw-01.dev` sat on the previous
     * generation while every other row read `confirmed`; the site view rendered `blockedBy: null`
     * and the relay — asked directly — answered *"waiting on general: mailer-03.dev has not
     * reported this generation"*. The fleet was behaving exactly as designed and the aggregate view
     * could not express it.
     *
     * That is the failure this project keeps producing: a field that is correct at every layer
     * below and absent at the last one. The row is not wrong, it is mute, and a mute row about a
     * stalled rollout reads as an unexplained stall.
     */
    stage: string | null;
    /** Why this host has not moved, in the relay's words. `null` when nothing is holding it. */
    blockedBy: string | null;
    /**
     * Why this host is out of service, when a person declared it so in the policy. `null` normally.
     *
     * An excused host and a silent one are indistinguishable from the outside and mean opposite
     * things — one is accounted for, the other is what staged rollout stops on.
     */
    maintenance: string | null;
    /**
     * Other tables filtering on this host that its policy does not account for.
     *
     * `null` means the host did not report, which is not the same as none — see
     * `HostView.unexpectedFilters`. Carried here because a row reading `confirmed` while another
     * firewall decides is precisely the state this view exists to make visible, and the matching
     * entry in `problems` says what it means but not which row it belongs to.
     */
    unexpectedFilters: string[] | null;
    /**
     * Ways this host's own reporting does not hold together (H30).
     *
     * Carried for the same reason as `unexpectedFilters`: the matching `problems` entry says what it
     * means but not which row it belongs to, and an operator scanning the table needs the finding on
     * the row. **This was omitted when H30 landed** — the check ran, the relay recorded it, the fleet
     * view carried it, and the site view dropped it on the floor. Aggregation is where a signal gets
     * lost quietly, because every layer below it still looks right.
     */
    contradictions: Contradiction[];
    /**
     * Changes to this host's ruleset that its agent did not make (H27/H28).
     *
     * `null` = the host did not report (an older agent); `[]` = it watched and saw nothing.
     */
    intrusions: RulesetEvent[] | null;
    /**
     * The agent build that last reported.
     *
     * The only server-side evidence that a host-unit deployment took. stardust's runbook makes
     * the point about its own node-agent — fail-silent, `rc=0` even with a wrong URL, so judge
     * from the server, not from the machine that ran the installer. This is that field here.
     *
     * `null` on an agent too old to send one, which is what a half-finished rollout looks like.
     */
    agentVersion: string | null;
    agentBuild: string | null;
    lastRefusal: { generation: string; reason: string; at: string } | null;
    /** Ports another table redirects inbound, outside what this ruleset governs (H36). */
    publishedPorts: string[] | null;
    /**
     * The host's IPv4 routes as the kernel holds them.
     *
     * Projected because a packet reaches a filter only if routing sent it there, and this view is
     * the one place both halves can be read together. This projection has dropped a signal three
     * times — `blockedBy`, the intrusion set, the whole workload half — each time because a field
     * arrived correct at every layer beneath and stopped here.
     */
    routes: import("./rollout.ts").HostStatus["routes"];
    ciliumExposure: import("./protocol.ts").CiliumExposure | null;
    /**
     * The workload half, on the host assigned one — `null` on every other host (H14a).
     *
     * The third time this projection lost a signal, and the widest: **the site view carried no part
     * of the workload half at all.** A host with `state: confirmed` and `workload.state:
     * rolled-back` read as plain `confirmed` here, which is the one combination `HostView.workload`
     * exists to keep separable — the generation landed on the host and not in the cluster. The
     * cluster-scoped policies have no host-layer rule behind them, so every other field on the row
     * still reads as success.
     *
     * Carried whole rather than flattened to a word, and `membership` with its `at` verbatim,
     * because a pod count without the time it was true is one an operator reads as current. Pod
     * membership goes stale in seconds.
     */
    workload: HostView["workload"];
  }>;
  /**
   * Everything an operator has to look at, VPC-tagged.
   *
   * An unreachable relay is itself the first entry, because during a rollout it means the hosts
   * behind it are receiving nothing — which is more urgent than most of what the relays report.
   */
  problems: string[];
  /**
   * Generations in play across the site, most common first.
   *
   * More than one is normal mid-rollout and a problem afterwards, and the manager cannot tell which
   * without knowing when the publish happened — so it reports the fact rather than judging it.
   */
  generations: Array<{ generation: string | null; vpcs: string[] }>;
  /** VPCs that answered, out of how many were asked. `reachable < asked` is always a problem. */
  reachable: number;
  asked: number;
}

/**
 * Assemble a site view from per-relay results.
 *
 * Takes results rather than performing the requests, so the failure cases — one relay down, all of
 * them down, two VPCs disagreeing about the generation — are constructible in a test.
 */
export function siteView(results: RelayResult[]): SiteView {
  const hosts: SiteView["hosts"] = [];
  const problems: string[] = [];
  const byGeneration = new Map<string | null, string[]>();

  for (const r of results) {
    if (!r.ok) {
      // First, and phrased as consequence rather than symptom. "prod unreachable" is a fact about a
      // connection; "hosts behind it are receiving nothing" is what it means.
      problems.push(`${r.name}: relay unreachable — hosts behind it are receiving nothing (${r.error})`);
      continue;
    }

    const gen = r.view.generation;
    byGeneration.set(gen, [...(byGeneration.get(gen) ?? []), r.name]);

    for (const h of r.view.hosts) {
      hosts.push({
        vpc: r.name,
        host: h.host,
        state: h.state,
        generation: h.generation,
        current: h.current,
        drifted: h.drifted,
        ageSec: h.ageSec,
        stage: h.stage ?? null,
        blockedBy: h.blockedBy ?? null,
        maintenance: h.maintenance ?? null,
        // `?? null` rather than omitted: a relay too old to report this must read as "unknown" on
        // every row it serves, not as "clear".
        unexpectedFilters: h.unexpectedFilters ?? null,
        // `?? []` here and `?? null` above, and the difference is not an inconsistency: the relay does
        // the contradiction checking itself, so there is nothing it can fail to look at. Intrusions come
        // from the agent, which can be too old to report them.
        contradictions: h.contradictions ?? [],
        intrusions: h.intrusions ?? null,
        agentVersion: h.agentVersion ?? null,
        agentBuild: h.agentBuild ?? null,
        lastRefusal: h.lastRefusal ?? null,
        publishedPorts: h.publishedPorts ?? null,
        routes: h.routes ?? null,
        ciliumExposure: h.ciliumExposure ?? null,
        // `?? null` for the same reason as the rest: a relay too old to report the workload half is
        // not a host that has none, and the two render identically if this defaults to anything
        // else. Inside it, `membership: null` keeps meaning "did not report" as distinct from a
        // namespace queried and empty — `arc-runners` between CI jobs is genuinely `[]`.
        workload: h.workload ?? null,
      });
    }

    // Tagged with the VPC. Without that an operator reading "k3s-01: rolled back" has to know which
    // site's k3s-01 — and host names repeat across VPCs by design.
    for (const p of r.view.problems) problems.push(`${r.name}: ${p}`);
  }

  const generations = [...byGeneration.entries()]
    .map(([generation, vpcs]) => ({ generation, vpcs }))
    .sort((a, b) => b.vpcs.length - a.vpcs.length);

  return {
    vpcs: results,
    hosts,
    problems,
    generations,
    reachable: results.filter((r) => r.ok).length,
    asked: results.length,
  };
}

/**
 * Is the site in a state an operator should be told about?
 *
 * Separate from `problems` because the two questions differ: `problems` lists what to look at, this
 * answers whether to interrupt someone. A site mid-rollout has problems and is fine; a site with an
 * unreachable relay has the same count and is not.
 */
export function siteNeedsAttention(view: SiteView): boolean {
  // An unreachable relay always does — its hosts are receiving nothing and nobody can see them.
  if (view.reachable < view.asked) return true;
  return view.problems.length > 0;
}
