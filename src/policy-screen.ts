// The policy screen's view model, built once and used from both surfaces.
//
// ## Why this is a module and not part of the CLI
//
// It was part of the CLI, and that is how eleven screens ended up somewhere the operator could not
// reach them. The manager console is the address people actually open; serving the same screens
// there means the assembly has to live where both callers can reach it.
//
// **The caller imports the site module.** Node resolves a dynamic import against the importing
// file, and the two callers sit in different directories inside different processes — one on a
// workstation checkout, one in a container. Passing the already-imported `site` keeps that decision
// where the caller's layout is known.
//
// **Two things degrade rather than throw**: the generation label and the commit history both come
// from `git`, which is not in the manager image. Each returns its empty answer, the page renders
// without those two, and nothing pretends they are something else — `generation: null` is already
// rendered as "no generation".
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { policyRows, type PolicyRow } from "./policy-view.ts";
import { crossings, zoneRows } from "./zones.ts";
import { deviceRows, userScreenRows } from "./device-view.ts";
import { coverageRows, coverageSummary, type Probe } from "./coverage.ts";
import { baselineRows, hostRows, joinFleet, workloadRows } from "./site-view.ts";
import { addressSpaceRows, feedRows, membershipRows, objectRows, serviceRows } from "./catalog-view.ts";
import { historyRows, liveGenerations, type Commit } from "./history-view.ts";
import { planPublish } from "./publish.ts";
import type { AddressObject, FirewallObject, ServiceObject } from "./objects.ts";
import type { PolicyPageMeta, SiteSections } from "./policy-ui.ts";

/** The shape `heliopause-publish` exports. Structural, so this module does not import a bin. */
export interface ScreenSite {
  cfg: Parameters<typeof baselineRows>[0];
  hosts: Parameters<typeof hostRows>[0]["hosts"];
  workload?: unknown[];
  resolveService?: unknown;
  zones?: Parameters<typeof zoneRows>[0];
  devices?: Parameters<typeof deviceRows>[0];
  coverage?: Parameters<typeof coverageRows>[0];
  objects?: readonly FirewallObject[];
}

/** What the manager knows and the site module does not. Optional — offline renders skip it. */
export interface FleetAnswer {
  hosts: Parameters<typeof joinFleet>[1] & Parameters<typeof membershipRows>[0];
  generations: Parameters<typeof liveGenerations>[0];
}

export interface ScreenInput {
  /**
   * The clock, for the ages this screen computes. Defaults to now.
   *
   * Injectable because `buildScreen` read the clock itself, and a test comparing two screens built
   * from the same data failed roughly one run in three: a second boundary between the two builds
   * moved `ageSec` by one. A test that fails on the time of day gets re-run rather than read, and
   * this one is what says the wire format survived the crossing. Nothing in production passes it.
   */
  now?: string;
  /** Absolute path to the site module — used for git, for `coverage-*.json`, and to import from. */
  sitePath: string;
  /**
   * What the page calls it. Defaults to `sitePath`.
   *
   * The workstation passes what the operator typed; an absolute container path would be a location
   * nobody recognises. `PolicyPageMeta.site` has said "as the operator typed it" since it was
   * written, and moving this assembly into a module quietly broke that.
   */
  label?: string;
  site: ScreenSite;
  /**
   * Everything this function would otherwise read from beside the site module, supplied instead.
   *
   * **Present means the caller has no checkout**, and then nothing here touches the disk or shells
   * out to git. That is the whole point: the manager renders a policy it never had a copy of and
   * never executed, so a commit to the policy repository cannot run code in the process holding the
   * signing key. Whoever *does* have the checkout (`heliopause-policy-render`, or the workstation)
   * reads these three things and sends them as data.
   *
   * All three together, never some of them. A half-supplied set would read the missing ones from a
   * path that does not exist in that process, and every absent answer here renders as a truthful
   * "not measured" / "no generation" — which is the wrong sentence when the facts exist and merely
   * did not travel.
   */
  repo?: RepoFacts;
  /** Live fleet state, when a manager answered. */
  fleet?: FleetAnswer | null;
  /** Rendered into the footer as the other half of the console. */
  manager?: string;
  editable?: boolean;
  proposable?: boolean;
}

/**
 * The three facts that live beside the site module rather than inside it.
 *
 * Data, deliberately — this is what crosses the line from the process that has the policy checkout
 * to the process that renders it. Nothing here is a function, and nothing here is a path.
 */
export interface RepoFacts {
  /** `coverage-*.json`, as `readCoverageProbes` would have found them. */
  probes: readonly Probe[];
  /** `git log`, as `policyCommits` would have found it. */
  commits: readonly Commit[];
  /** `git rev-parse --short HEAD`, as `generationLabel` would have produced it. `null` is "unknown". */
  generation: string | null;
}

export interface Screen {
  rows: PolicyRow[];
  meta: PolicyPageMeta;
  extra: SiteSections;
}

/**
 * The probes the external verifiers last wrote, from beside the site module.
 *
 * **One file per vantage point.** Both writers rewriting one file produced a rebase conflict in a
 * file nobody edits by hand; separate files remove the collision rather than resolve it.
 *
 * Returns `[]` for anything unreadable, and that is the point — every cell then reads "not
 * measured", which is the true state. An absent file means nobody ran the verifier, not that
 * everything passed.
 */
export function readCoverageProbes(sitePath: string): Probe[] {
  const dir = resolve(sitePath, "..");
  let names: string[];
  try {
    names = readdirSync(dir).filter((n) => /^coverage-.*\.json$/.test(n)).sort();
  } catch {
    return [];
  }
  const out: Probe[] = [];
  for (const name of names) {
    try {
      const v = JSON.parse(readFileSync(resolve(dir, name), "utf8")) as { probes?: unknown };
      if (!Array.isArray(v.probes)) continue;
      // Only the fields the row builder matches on are required. A probe missing them cannot be
      // placed on a target, and placing it wrongly is worse than dropping it.
      for (const p of v.probes) {
        if (
          p && typeof p === "object" &&
          typeof (p as Probe).checkId === "string" &&
          typeof (p as Probe).addr === "string" &&
          typeof (p as Probe).at === "string"
        ) out.push(p as Probe);
      }
    } catch {
      // A vantage point whose file will not parse contributes nothing, and its cells stay unmeasured.
    }
  }
  return out;
}

function git(dir: string, args: string[]): string | null {
  try {
    return execFileSync("git", ["-C", dir, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    // No git binary (the manager image has none) or not a repository. Both mean the same thing to
    // the caller: this label cannot be produced, and the page says "no generation" rather than
    // inventing one.
    return null;
  }
}

/**
 * The commit the policy is at.
 *
 * Best effort, unlike `heliopause-publish` where the id is the generation's name and a dirty tree is
 * refused. Here it is a label on a read-only page: refusing to display the policy because the tree
 * has uncommitted edits would make this useless at exactly the moment it is most useful.
 */
export function generationLabel(sitePath: string): string | null {
  const { sha, dirty } = policyHead(sitePath);
  if (sha === null) return null;
  return dirty ? `${sha} (uncommitted edits)` : sha;
}

/**
 * The same two facts `generationLabel` renders, kept apart.
 *
 * Publishing and displaying want opposite things from a dirty tree — `heliopause-publish` refuses
 * one outright because the generation id *names* the commit, while the page draws it anyway with a
 * note. A caller that has to decide cannot do it from the sentence, so it gets the fields.
 */
export function policyHead(sitePath: string): { sha: string | null; dirty: boolean } {
  const dir = resolve(sitePath, "..");
  const sha = git(dir, ["rev-parse", "--short", "HEAD"]);
  if (sha === null) return { sha: null, dirty: false };
  return { sha, dirty: Boolean(git(dir, ["status", "--porcelain"])) };
}

const SEP = "";

/** The policy repository's commit log — the only history that exists. */
export function policyCommits(sitePath: string, limit = 40): Commit[] {
  const out = git(resolve(sitePath, ".."), ["log", `-${limit}`, `--format=%h${SEP}%s${SEP}%an${SEP}%aI`]);
  if (!out) return [];
  return out.split("\n").filter(Boolean).map((line) => {
    const [id, subject, author, at] = line.split(SEP);
    return { id: id ?? "", subject: subject ?? "", author: author ?? "", at: at ?? "" };
  });
}

/**
 * Which policies the renderer skipped, per host.
 *
 * A render failure is reported and then ignored. `RenderError` means the pipeline feeding the
 * renderer is broken, and that is worth knowing — but this is a viewer, and refusing to show the
 * policy because it does not currently render would hide the table at the moment somebody is trying
 * to find out why. The page falls back to "placement not computed", which is exactly true.
 */
export function skippedByHost(site: ScreenSite): ReadonlyMap<string, ReadonlySet<string>> | undefined {
  try {
    const plan = planPublish({
      cfg: site.cfg,
      generation: "ui",
      issuedAt: new Date().toISOString(),
      hosts: site.hosts,
      ...(site.workload ? { workload: site.workload } : {}),
      ...(site.resolveService ? { resolveService: site.resolveService } : {}),
    } as Parameters<typeof planPublish>[0]);
    return new Map(plan.artifacts.map((a) => [a.host, new Set(a.skipped.map((s) => s.policyId))] as const));
  } catch (e) {
    console.error(`[screen] the renderer failed, so placement is not shown: ${(e as Error).message}`);
    return undefined;
  }
}

/** Assemble everything the page needs. Pure with respect to the network — the caller supplies fleet. */
/**
 * Every distinct policy the site declares, host layer and workload layer together.
 *
 * Lifted out of `buildScreen`, which had the same expression inline, because the lookup needs the
 * identical list. Two copies of "what are all the policies" is how a screen and a search end up
 * disagreeing about which rules exist — and the one that disagrees quietly is the search, because
 * nobody cross-checks a result they asked for.
 */
export function allSitePolicies(site: {
  hosts: readonly { items?: readonly { policy: unknown }[]; egress?: readonly { policy: unknown }[] }[];
  workload?: readonly unknown[];
}): unknown[] {
  const seen = new Set<string>();
  return [
    ...site.hosts.flatMap((h) => [
      ...(h.items ?? []).map((i) => i.policy),
      ...((h.egress ?? []) as { policy: unknown }[]).map((e) => e.policy),
    ]),
    ...((site.workload ?? []) as { policy: unknown }[]).map((w) => w.policy),
  ].filter((p) => {
    const id = (p as { id?: string }).id;
    if (id === undefined) return true;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

export function buildScreen(input: ScreenInput): Screen {
  const { site, sitePath } = input;
  const skipped = skippedByHost(site);
  const rows = policyRows({ hosts: site.hosts, ...(skipped ? { skipped } : {}) });
  // Workload policies belong in this list, and leaving them out was not a small omission: the tables
  // built from it answer "who references this object / service / feed", and an object referenced only
  // by a CiliumNetworkPolicy came back with **no** references. `objectRows` documents an empty
  // `usedBy` as dead configuration that still reads as protection — so the screen was not merely
  // incomplete, it was asserting the opposite of the truth about a live source list.
  //
  // Deduplicated by id because a policy can be placed on a host and in the workload set, and one rule
  // counted twice reads as two callers.
  const seenPolicy = new Set<string>();
  const allPolicies = [
    ...site.hosts.flatMap((h) => [
      ...h.items.map((i) => i.policy),
      ...((h.egress ?? []) as { policy: unknown }[]).map((e) => e.policy),
    ]),
    ...((site.workload ?? []) as { policy: unknown }[]).map((w) => w.policy),
  ].filter((p) => {
    const id = (p as { id?: string }).id;
    if (id === undefined) return true;
    if (seenPolicy.has(id)) return false;
    seenPolicy.add(id);
    return true;
  }) as Parameters<typeof objectRows>[1];
  const catalogue: readonly FirewallObject[] = site.objects ?? [];
  const fleet = input.fleet ?? null;

  const extra: SiteSections = {
    baseline: baselineRows(site.cfg),
    hosts: fleet ? joinFleet(hostRows(site as never, skipped), fleet.hosts) : hostRows(site as never, skipped),
    workload: workloadRows((site.workload ?? []) as never),
    objects: objectRows(catalogue.filter((o): o is AddressObject => o.kind === "address"), allPolicies),
    services: serviceRows(catalogue.filter((o): o is ServiceObject => o.kind === "service"), allPolicies),
    feeds: feedRows(allPolicies),
    // `allPolicies` and not just the workload set: the endpoints that produce a membership query are
    // the same ones the host layer reads, and passing a narrower list would leave rows whose
    // `usedBy` is empty for no reason an operator could see.
    membership: fleet ? membershipRows(fleet.hosts, allPolicies) : [],
    addressSpace: addressSpaceRows(site.hosts),
    history: historyRows(
      input.repo ? input.repo.commits : policyCommits(sitePath),
      fleet ? liveGenerations(fleet.generations) : new Map(),
    ),
    // Zones describe the policy set rather than changing it, so both come from the same items the
    // renderer sees — a crossing computed from anything else would be about a different firewall.
    zones: zoneRows(site.zones ?? [], site.hosts.flatMap((h) => h.items)),
    crossings: crossings(site.zones ?? [], site.hosts.flatMap((h) => h.items)),
    // Read beside the site module. Absent means nothing was measured, and the table says exactly
    // that on every cell — the one thing it must not do is render an empty table, which reads as
    // "no checks failed".
    ...(site.coverage?.length
      ? (() => {
          // Injectable, and the reason is a test that failed roughly one run in three. Two screens
          // built from the same data must be identical, and they were not: `buildScreen` read the
          // clock itself, so a second boundary falling between the two builds moved `ageSec` by one
          // and the comparison failed. A test that fails on the time of day is a test that gets
          // re-run rather than read, and this suite is the thing that says the wire format is intact.
          const now = input.now ?? new Date().toISOString();
          const cov = coverageRows(site.coverage, input.repo ? input.repo.probes : readCoverageProbes(sitePath), {
            now,
          });
          return { coverage: { rows: cov, summary: coverageSummary(cov) } };
        })()
      : {}),
    // No live Cloudflare read. Reaching it here would make the screen's "matches" state depend on
    // whether a token happened to be present; `heliopause-devices` supplies the comparison.
    devices: deviceRows(site.devices ?? [], site.zones ?? []),
    users: userScreenRows(site.devices ?? [], site.zones ?? []),
  };

  const meta: PolicyPageMeta = {
    site: input.label ?? sitePath,
    generation: input.repo ? input.repo.generation : generationLabel(sitePath),
    hosts: site.hosts.map((h) => h.id),
    editable: Boolean(input.editable),
    proposable: Boolean(input.proposable),
    ...(input.manager ? { manager: input.manager } : {}),
  };

  return { rows, meta, extra };
}
