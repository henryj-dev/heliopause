import { certaintyWord, contradictionKind, hostStateWord, t, type Lang } from "../../i18n.ts";
import type { HostIntrusion, SiteHost, SiteView, WorkloadHalf, WorkloadMembership } from "./site";

export type ChipKind = "ok" | "warn" | "bad" | "info" | "mute" | "none";

export interface StateChip {
  kind: ChipKind;
  word: string;
  hatch?: boolean;
}

/**
 * Additive. 시안 A2 keeps ✓ confirmed next to ✕ drifted — folding them into
 * one word is how the honest host that also drifted disappeared.
 */
export function hostStateChips(host: SiteHost, lang: Lang = "en"): StateChip[] {
  if (host.maintenance) {
    return [{ kind: "mute", word: t(lang, "m.maintenance") }];
  }
  if (host.ageSec === null && host.state === null) {
    return [{ kind: "none", word: t(lang, "m.neverSeen"), hatch: true }];
  }
  const chips: StateChip[] = [];
  if (host.state === "confirmed") chips.push({ kind: "ok", word: t(lang, "m.confirmed") });
  else if (host.state) chips.push({ kind: "bad", word: hostStateWord(lang, host.state) });
  if (host.drifted) chips.push({ kind: "bad", word: t(lang, "m.drifted") });
  if (host.blockedBy) chips.push({ kind: "info", word: t(lang, "m.holding") });
  chips.push(...contradictionChips(host, lang));
  chips.push(...intrusionChips(host, lang));
  return chips.length > 0 ? chips : [{ kind: "none", word: t(lang, "m.neverSeen"), hatch: true }];
}

/** Ours are not findings. Counting the agent's own writes would make every publish look like a break-in. */
export function foreignIntrusions(host: SiteHost): HostIntrusion[] {
  return (host.intrusions ?? []).filter((row) => !row.byAgent);
}

export function intrusionChips(host: SiteHost, lang: Lang = "en"): StateChip[] {
  const n = foreignIntrusions(host).length;
  return n > 0 ? [{ kind: "warn", word: t(lang, "m.intrusion", { n }) }] : [];
}

/**
 * certain is filled danger; unexplained is hatched mute. Colour alone
 * would collapse the line consistency.ts drew on purpose.
 */
export function contradictionChips(host: SiteHost, lang: Lang = "en"): StateChip[] {
  const certain = host.contradictions.filter((row) => row.certainty === "certain");
  const soft = host.contradictions.filter((row) => row.certainty !== "certain");
  const chips: StateChip[] = [];
  if (certain.length) {
    chips.push({ kind: "bad", word: certain.map((row) => contradictionKind(lang, row.kind)).join(", ") });
  }
  if (soft.length) {
    chips.push({
      kind: "mute",
      word: soft.map((row) => contradictionKind(lang, row.kind)).join(", "),
      hatch: true,
    });
  }
  return chips;
}

export function hostHasProblem(host: SiteHost): boolean {
  if (host.maintenance || host.drifted || host.blockedBy) return true;
  if (host.state === null || host.ageSec === null) return true;
  if (host.contradictions.some((row) => row.certainty === "certain")) return true;
  if (host.workload && host.workload.state && host.workload.state !== "confirmed") return true;
  if (foreignIntrusions(host).length > 0) return true;
  if (host.unexpectedFilters && host.unexpectedFilters.length > 0) return true;
  return host.current === false;
}

export function generationSet(hosts: readonly SiteHost[]): string[] {
  const seen = new Set<string>();
  for (const host of hosts) {
    if (host.generation) seen.add(host.generation);
  }
  return [...seen];
}

export function hostsOnVpc(hosts: readonly SiteHost[], vpc: string): number {
  return hosts.filter((host) => host.vpc === vpc).length;
}

export function hostMatches(host: SiteHost, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  return `${host.host} ${host.vpc} ${host.state ?? ""} ${host.generation ?? ""}`.toLowerCase().includes(needle);
}

/**
 * Whether the table is empty because nobody is registered, or because no
 * relay answered. 시안 A3 is the first; an unread VPC card is the second.
 * A filter that matches nothing is neither — that stays on the screen.
 */
export function fleetListing(site: SiteView): "hosts" | "empty" | "unread" {
  if (site.hosts.length > 0) return "hosts";
  if (site.vpcs.some((vpc) => vpc.ok)) return "empty";
  return "unread";
}

export function answeredVpcNames(site: SiteView): string[] {
  return site.vpcs.filter((vpc) => vpc.ok).map((vpc) => vpc.name);
}

export function fleetSummary(site: SiteView): { problems: number; generations: string[] } {
  return {
    problems: site.problems.length > 0
      ? site.problems.length
      : site.hosts.filter(hostHasProblem).length,
    generations: generationSet(site.hosts),
  };
}

export type AuthorizationExpiry =
  | { kind: "left"; at: string; hours: number; minutes: number }
  | { kind: "lapsed"; at: string }
  | { kind: "unknown" };

/**
 * The enforced authorization's expiry, for the host row (#138). Information only: a confirmed host
 * keeps its rules past it, and the case where a lapse blocks anything is reported by the relay.
 * `null` is "not known" and stays that — it is never drawn as time left.
 */
/**
 * Which expiry lines a host row shows. The applied one needs something applied; the served one does
 * not — a host refusing its first envelope has no generation, and that is where the served expiry
 * matters most.
 */
export function authorizationLines(
  host: Pick<SiteHost, "generation" | "authorizationExpiresAt" | "servedAuthorizationExpiresAt">,
): Array<{ key: "m.authApplied" | "m.authServed"; at: string | null }> {
  return [
    ...(host.generation ? [{ key: "m.authApplied" as const, at: host.authorizationExpiresAt }] : []),
    { key: "m.authServed" as const, at: host.servedAuthorizationExpiresAt },
  ];
}

export function authorizationExpiry(at: string | null, nowMs: number): AuthorizationExpiry {
  if (at === null) return { kind: "unknown" };
  const leftMs = Date.parse(at) - nowMs;
  if (leftMs <= 0) return { kind: "lapsed", at };
  const totalMinutes = Math.floor(leftMs / 60_000);
  return { kind: "left", at, hours: Math.floor(totalMinutes / 60), minutes: totalMinutes % 60 };
}

/**
 * How many distinct agent builds the fleet is running, and how many hosts could not say.
 *
 * ## Why the split matters rather than the digest
 *
 * `agentBuild` is the agent's own source hashed by itself, added 2026-09-03 for a case a version
 * string cannot see: code changing without `AGENT_VERSION` moving, because nothing an agent and a
 * relay must agree on changed. It has travelled from the host through the relay to the manager ever
 * since. **Nothing drew it.**
 *
 * What that cost, measured 2026-09-29: a fix was merged, an image rolled, and eight hosts kept
 * running a three-week-old agent — the image carries `src/` and `bin/`, and the agent lives in
 * `agent/`. Every screen was green. The value that would have said so was one step away the whole
 * time.
 *
 * A digest in a column would not have helped either; nobody compares sixteen hex characters across
 * eight rows. **The finding is the disagreement**: one build across the fleet is a rollout that
 * landed, two is a rollout that is partway, and that is a sentence rather than a value.
 *
 * `unknown` counts hosts that reported nothing — either older than the field or not reporting at
 * all. Kept apart from the builds because "did not say" is not a third version.
 *
 * ## It is self-attested, so it is a rollout signal and not an integrity control
 *
 * The digest is computed by the agent over its own file and sent in its own heartbeat. Nothing else
 * measures it, so an agent that has been replaced can report whatever digest it likes, and a fleet
 * showing one build everywhere is evidence that every host *claims* the same source — not proof of
 * it. What the field is honest about is the case it was added for: an unmodified agent that a rollout
 * has not reached yet, which has no reason to lie and every reason to differ.
 *
 * Saying so here because the banner reads like verification and is not. Integrity of what a host
 * enforces rests on the signed artifact path — `currentAuthorization`, the trust digest, the key ids
 * — none of which this value touches.
 */
export function agentBuildSplit(hosts: readonly SiteHost[]): { builds: string[]; unknown: number } {
  const builds = [...new Set(hosts.map((h) => h.agentBuild).filter((b): b is string => Boolean(b)))];
  builds.sort();
  return { builds, unknown: hosts.filter((h) => !h.agentBuild).length };
}

/**
 * Which agent-build lines the fleet screen should draw.
 *
 * ## Why this is a function and not two `{#if}`s
 *
 * It was two, chained — `{#if split}{:else if unknown > 0 && builds.length > 0}`. That second
 * condition made the silent line dead in the one state it exists for: **no host reporting at all**
 * (`builds: []`, `unknown: 8`) rendered nothing, which on the page is indistinguishable from one
 * build everywhere. `agentBuildSplit` keeps those apart and a test asserts it does; the template
 * threw it away, and no test could see that because nothing here runs the template.
 *
 * So the decision moves out of the markup, where it can be asserted. The two lines are independent:
 * a fleet can be both split and partly silent, and that is two facts, not a choice between them.
 */
export function agentBuildLines(
  hosts: readonly SiteHost[],
): { split: { builds: string[]; answered: number } | null; silent: number | null } {
  const { builds, unknown } = agentBuildSplit(hosts);
  return {
    split: builds.length > 1 ? { builds, answered: hosts.length - unknown } : null,
    silent: unknown > 0 ? unknown : null,
  };
}

/** The hosts reporting one agent build, so a split can name them instead of only counting them. */
export function hostsOnBuild(hosts: readonly SiteHost[], build: string): string[] {
  return hosts.filter((h) => h.agentBuild === build).map((h) => h.host).sort();
}

export function vpcTone(vpc: SiteView["vpcs"][number], hosts: readonly SiteHost[]): "ok" | "warn" | "bad" {
  if (!vpc.ok) return "bad";
  return hosts.some((host) => host.vpc === vpc.name && hostHasProblem(host)) ? "warn" : "ok";
}

export function vpcLabel(vpc: SiteView["vpcs"][number], hosts: readonly SiteHost[], lang: Lang = "en"): string {
  if (!vpc.ok) return t(lang, "m.vpcUnread");
  const n = hosts.filter((host) => host.vpc === vpc.name && hostHasProblem(host)).length;
  return n > 0 ? t(lang, "m.vpcProblems", { n }) : t(lang, "m.vpcOk");
}

/** The generation hosts with `current` are on, when any have reported one. */
export function wantedGeneration(hosts: readonly SiteHost[]): string | null {
  for (const host of hosts) {
    if (host.current && host.generation) return host.generation;
  }
  return null;
}

export function whyBits(host: SiteHost, lang: Lang = "en"): string[] {
  const bits: string[] = [];
  for (const row of host.contradictions) {
    bits.push(t(lang, "m.whyContradiction", {
      kind: contradictionKind(lang, row.kind),
      certainty: certaintyWord(lang, row.certainty),
      detail: row.detail,
    }));
  }
  if (host.unexpectedFilters && host.unexpectedFilters.length > 0) {
    bits.push(t(lang, "m.whyFilters", { names: host.unexpectedFilters.join(", ") }));
  }
  const foreign = foreignIntrusions(host);
  if (foreign.length > 0) {
    const last = foreign[foreign.length - 1]!;
    const who = last.process ?? t(lang, "m.unknownProcess");
    const pid = last.pid === null ? "" : t(lang, "m.whyPid", { pid: last.pid });
    bits.push(t(lang, "m.whyIntrusions", { at: last.at, table: last.table, pid, who }));
  }
  if (host.publishedPorts && host.publishedPorts.length > 0) {
    bits.push(t(lang, "m.whyPorts", { ports: host.publishedPorts.join(", ") }));
  }
  if (host.blockedBy) bits.push(host.blockedBy);
  if (host.maintenance) bits.push(host.maintenance);
  return bits;
}

export function hostRowClass(host: SiteHost): string {
  if (host.contradictions.some((row) => row.certainty === "certain") || host.drifted) return "hit-bad";
  return "";
}

export function workloadChip(workload: WorkloadHalf, lang: Lang = "en"): StateChip {
  if (workload.state === "confirmed") return { kind: "ok", word: t(lang, "m.confirmed") };
  if (workload.state === null) return { kind: "none", word: t(lang, "m.notReported"), hatch: true };
  return { kind: "bad", word: hostStateWord(lang, workload.state) };
}

export function membershipPodCount(membership: WorkloadMembership): number {
  let n = 0;
  for (const pods of Object.values(membership.namespaces)) n += pods.length;
  for (const pods of Object.values(membership.labelled)) n += pods.length;
  return n;
}

export type RoutesView =
  | { kind: "unreported" }
  | { kind: "owned"; total: number }
  | { kind: "by-hand"; hand: number; total: number; title: string };

/**
 * Count, not the list. Eighteen routes in a cell is a cell nobody reads.
 * Unreported is never drawn as zero.
 */
export function routesView(host: SiteHost): RoutesView {
  if (host.routes === null) return { kind: "unreported" };
  const hand = host.routes.filter((row) => row.handAdded);
  if (hand.length === 0) return { kind: "owned", total: host.routes.length };
  return {
    kind: "by-hand",
    hand: hand.length,
    total: host.routes.length,
    title: hand.map((row) => `${row.dst}${row.via ? ` via ${row.via}` : ""} dev ${row.dev}`).join(" · "),
  };
}
