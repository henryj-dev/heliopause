// The rest of the workstation screens, as pure projections of a site module.
//
// ## Why these three and not the ones the design document lists first
//
// `GUI-테이블-설계.md` describes zones (3), address objects (5) and a service catalogue (6) before
// these. Measured 2026-08-07, all three were empty:
//
//   - **There was no zone.** `EndpointKind` is host / host-group / cidr / object / internet / any /
//     k8s-service. Zones were a concept in the design document and not in the model, so screen 3
//     could not be projected from a site — it would have had to be invented first.
//   - **The site used no objects.** Every endpoint across all three VPCs was a literal `cidr` or
//     `host` (15 and 15 in dev, 4 and 4 in prod and util; `object` appeared zero times). The object
//     model existed in `objects.ts` and nothing referenced it.
//
// Building those first would have produced three empty tables and the impression that the screens
// were done. What follows is what a site contained then, and still does.
//
// ⚠️ **Both were invented afterwards, and this paragraph outlived that.** Read as present tense on
// 2026-08-24 it says a screen cannot exist while `policy-screen.ts` is building it: `site.zones` is
// in the model, `zoneRows` and `crossings` project screens 3 and 4, `objectRows` projects screen 5,
// and `policy-ui.ts` renders all of them. `device-view.ts` places every device in a zone.
//
// Left as history rather than deleted, because the reasoning is the useful part and it was correct:
// a table that can only be empty is worse than no table. The tense is what went stale. Nothing here
// projects zones or objects — they are built where the policy is, from `site.zones`, and this file
// is still the three screens below.
//
// ## Why baseline is the one that matters most
//
// It is the layer **policy cannot override** — management SSH, ICMP, DHCP renewal. A reader of the
// policy screen sees every rule an operator wrote and none of these, so the two screens together are
// the first complete answer to "what is open on this host".

import type { BaselineRule, Config } from "./config.ts";
import type { PublishHost } from "./publish.ts";
import type { CiliumItem } from "./cilium.ts";

// ── Baseline (screen 9) ───────────────────────────────────────────────────────

export interface BaselineRow {
  desc: string;
  proto: string;
  /** As authored. Empty means every port on that protocol. */
  ports: string;
  /** Empty means any source — for ICMP and DHCP that is deliberate. */
  srcCidrs: readonly string[];
  /** Set when this rule is open to any source, which for a baseline is worth seeing. */
  anySource: boolean;
}

/**
 * Project the baseline.
 *
 * Deliberately does **not** sort. Baseline order is the order it renders in, and a table that
 * reorders it would mislead about precedence in the one layer where precedence is not negotiable.
 */
export function baselineRows(cfg: Pick<Config, "baseline">): BaselineRow[] {
  return cfg.baseline.map((b: BaselineRule) => ({
    desc: b.desc,
    proto: b.proto,
    ports: b.ports,
    srcCidrs: b.srcCidrs,
    // ICMP and NDP are unrestricted on purpose — a host that cannot be pinged is harder to debug —
    // so this is a fact to show, not a finding to grade. The page renders it as neutral.
    anySource: b.srcCidrs.length === 0,
  }));
}

// ── Hosts (screen 4, the policy half) ─────────────────────────────────────────

/**
 * What the manager knows about a host, folded onto the policy row.
 *
 * Every field is optional-by-absence rather than nullable: a row with no `fleet` was never asked
 * about, and a row with `fleet` and `state: null` was asked and the host has not reported. Those are
 * different sentences and the table renders them differently.
 */
export interface HostFleet {
  state: string | null;
  generation: string | null;
  /** False when the host is not on the generation the manager wants it on. */
  current: boolean;
  drifted: boolean;
  ageSec: number | null;
  /** Why it is not moving, when the rollout gate is shut against it. */
  blockedBy: string | null;
}

export interface HostRow {
  id: string;
  stage: string;
  /** Input policies listed against this host. */
  inputCount: number;
  /** Egress policies listed against it. */
  egressCount: number;
  /** Policy ids the renderer produced nothing for, when render results were supplied. */
  skipped: string[];
  /** False when no render results were given — the counts are then "listed", not "renders". */
  placementKnown: boolean;
  /** True when a rule matching `protectedHosts` shields this host from being locked out. */
  protected: boolean;
  /**
   * Fleet state, when a manager was reachable. Absent means nobody asked.
   *
   * The screen is split across two surfaces on purpose (결정 10) and this is the seam. Filling these
   * with placeholders when no manager was given would turn "we did not ask" into "this host has no
   * agent", which is the more alarming of the two and the wrong one.
   */
  fleet?: HostFleet;
}

/**
 * The half of screen 4 that a site module can answer.
 *
 * The other half — agent state, last applied, drift — belongs to the manager, and joining them needs
 * `GET /site`. Kept separate rather than half-filled: a table with empty columns reads as "this host
 * has no agent", which is the opposite of "we did not ask".
 */
export function hostRows(
  site: { cfg: Pick<Config, "protectedHosts">; hosts: readonly PublishHost[] },
  skipped?: ReadonlyMap<string, ReadonlySet<string>>,
): HostRow[] {
  const guards = (site.cfg.protectedHosts ?? []).map((p) => new RegExp(p));
  return site.hosts.map((h) => ({
    id: h.id,
    stage: h.stage,
    inputCount: h.items.length,
    egressCount: (h.egress ?? []).length,
    skipped: [...(skipped?.get(h.id) ?? [])].sort(),
    placementKnown: skipped !== undefined,
    protected: guards.some((re) => re.test(h.id)),
  }));
}

// ── Workload (screen 10-b) ────────────────────────────────────────────────────

export interface WorkloadRow {
  id: string;
  name: string;
  action: string;
  src: string;
  dst: string;
  proto: string;
  ports: string;
  enabled: boolean;
  notes: string | null;
}

/**
 * The Cilium half.
 *
 * Cluster-scoped rather than per-host: a CiliumNetworkPolicy is not addressed to a machine, so there
 * is no placement column here and no skip list. That asymmetry with the nftables screen is real and
 * the page should not hide it — the two layers protect different destinations (design document §2).
 */
export function workloadRows(items: readonly CiliumItem[]): WorkloadRow[] {
  return items.map((i) => {
    const p = i.policy;
    return {
      id: p.id,
      name: p.name,
      action: p.action,
      src: endpointLabel(p.src),
      dst: endpointLabel(p.dst),
      proto: p.proto,
      ports: p.ports,
      enabled: p.enabled,
      notes: p.notes ?? null,
    };
  });
}

/**
 * Fold the manager's site view onto policy host rows.
 *
 * Matched by host id, which is the same string in both places — it is the certificate subject CN, so
 * a mismatch is not a naming inconsistency but a host the relay would refuse anyway.
 *
 * **A host the manager does not know keeps no `fleet` field.** That happens when the policy lists a
 * host in a VPC this manager does not aggregate, and it must not read as "reported nothing".
 */
export function joinFleet(
  rows: readonly HostRow[],
  siteHosts: readonly {
    host: string; state: string | null; generation: string | null;
    current: boolean; drifted: boolean; ageSec: number | null; blockedBy: string | null;
  }[],
): HostRow[] {
  const byId = new Map(siteHosts.map((h) => [h.host, h] as const));
  return rows.map((r) => {
    const f = byId.get(r.id);
    if (!f) return r;
    return {
      ...r,
      fleet: {
        state: f.state, generation: f.generation, current: f.current,
        drifted: f.drifted, ageSec: f.ageSec, blockedBy: f.blockedBy,
      },
    };
  });
}

/** `k8s-namespace:arc-runners`, `cidr:10.0.0.0/8`, `any`. Kind first, because kind changes meaning. */
function endpointLabel(e: { kind: string; value?: string }): string {
  return e.value ? `${e.kind}:${e.value}` : e.kind;
}
