// Turns policy into a published generation: one artifact per host, plus the manifest that names
// them. This is the manager's job — the half of the control plane the relay is deliberately unable
// to do for itself.
//
// Split into a pure planner and a writer for the same reason as the renderer: everything that
// decides *what* gets published is testable without a filesystem, and the part that touches disk
// has no decisions left in it.

import { createHash } from "node:crypto";
import { bundleFromPlan, writeBundle } from "./bundle.ts";
import { defineConfig, type Config } from "./config.ts";
import type { EgressItem, InputItem, Skipped } from "./nft.ts";
import { managementGuard, type RouteDecl } from "./routes.ts";

/**
 * The routes a host's agent is given, which is the subset heliopause installs.
 *
 * Only `dst`, `via`, `dev` and `table` travel: the owner has already been used (it is the filter) and
 * the note is for a person reading the policy. Sending the note would put prose an operator wrote
 * into the input of a process that runs `ip route`, for no purpose.
 */
function routesFor(h: PublishHost): { dst: string; via?: string; dev?: string; table?: string }[] {
  return (h.routes ?? [])
    .filter((r) => r.owner === "heliopause")
    .map((r) => ({
      dst: r.dst,
      ...(r.via === undefined ? {} : { via: r.via }),
      ...(r.dev === undefined ? {} : { dev: r.dev }),
      ...(r.table === undefined ? {} : { table: r.table }),
    }));
}
import { renderHostRulesetJson } from "./nft-json.ts";
import {
  SCHEMA_VERSION,
  type Manifest,
  type ManifestEntry,
  type RolloutStage,
  type WorkloadEntry,
} from "./protocol.ts";
import {
  assignsToWorkloadLayer,
  renderCiliumPolicies,
  selectorsToWatch,
  type CiliumItem,
  type CiliumSkipped,
  type CiliumWarning,
  type ResolvePods,
  type ResolveService,
} from "./cilium.ts";

/** One host to render for. */
export interface PublishHost {
  /**
   * Identity, and it must equal the subject CN of that host's certificate.
   *
   * The relay refuses a heartbeat whose claimed host disagrees with its certificate, so a typo
   * here does not produce a subtly wrong policy — it produces a host that is refused outright.
   * That is the intended failure: loud, immediate, and impossible to mistake for working.
   */
  id: string;
  stage: RolloutStage;
  items: InputItem[];
  egress?: EgressItem[];
  /**
   * Why this host is out of service, if it is. Its policy still renders and still ships.
   *
   * **This exists because "not reporting" has two causes and they need opposite responses.** A host
   * that has locked itself out reports nothing, and so does a host whose provider moved it onto a
   * CPU its libc will not run on — the second happened on 2026-08-11 and held the `gateway` stage
   * shut for a day. Silence alone cannot tell them apart, and a rule that advanced past long
   * silences would be the same code that advances past a host that just bricked itself. That is the
   * one failure staged rollout exists to prevent, so the distinction is not inferred: a person
   * states it, in the policy, with a reason.
   *
   * The host keeps its ruleset. When it comes back it applies the current generation like any other
   * host — nothing has to be remembered or restored, because nothing was removed. Deleting it from
   * `hosts` would also unblock the rollout and would leave it with no policy at all on return.
   */
  maintenance?: string;
  /**
   * The routes this deployment says should exist on this host (`routes.ts`).
   *
   * **Does not ship, and does not change the ruleset.** It is compared against what the host reports
   * and the difference is shown; nothing writes a route. That split is deliberate — a route is the
   * first thing this system could install that can strand a host from the channel it would use to
   * roll back, and this repository has already lost a fleet's control path once by applying before
   * the way back was proved.
   *
   * Absent means this host has no route model. That is not the same as "its routes are undeclared",
   * and the comparison keeps them apart: three of the seven hosts publish from their own site
   * modules, so the dev model says nothing about them and must not invent findings for them.
   */
  routes?: readonly RouteDecl[];
}

export interface PublishInput {
  cfg: Config;
  /** Git commit that produced this. See `Generation.id`. */
  generation: string;
  issuedAt: string;
  hosts: PublishHost[];
  /**
   * Policies for the workload layer, with their address resolution. Empty when there are none.
   *
   * Kept apart from `PublishHost.items` because these are not per-host: a CiliumNetworkPolicy is
   * cluster-scoped, so the whole set renders once and lands on the designated applier. Splitting them
   * by host would mean deciding which node "owns" a cluster-wide object, which is the question
   * `workload.applier` already answers.
   */
  workload?: CiliumItem[];
  /** Service → selector resolution, injected the same way `ResolveCidrs` is. */
  resolveService?: ResolveService;
  /**
   * Selector → pods, as the applier last reported it (H14a).
   *
   * Absent means the render says "not known" rather than showing an empty pod list. That is the
   * honest answer and the safe one: an empty list reads as "this policy selects nothing", which for
   * a containment policy is the opposite of the truth.
   */
  resolvePods?: ResolvePods;
}

export interface PublishedArtifact {
  host: string;
  json: string;
  entry: ManifestEntry;
  skipped: Skipped[];
  ruleCount: number;
}

/** The workload half of a generation, rendered once and addressed to the applier. */
export interface PublishedWorkload {
  /** Host the document goes to — `cfg.workload.applier`. */
  applier: string;
  cluster: string;
  /** The CNP objects, serialised. Written next to the host rulesets. */
  json: string;
  entry: WorkloadEntry;
  skipped: CiliumSkipped[];
  /**
   * Surfaced rather than swallowed. Every one of these means the rendered rule is narrower or wider
   * than what was written, which an operator has to see before believing the generation.
   */
  warnings: CiliumWarning[];
  /**
   * Pods each policy actually selects. `null` means not known — see `CiliumPlan.affectedPods`.
   *
   * The distinction survives all the way out to the publisher's output because it is what an
   * operator reads: "selects nothing" and "nobody told us" justify different decisions.
   */
  affectedPods: Record<string, string[] | null>;
}

export interface PublishPlan {
  manifest: Manifest;
  artifacts: PublishedArtifact[];
  /** Absent when no policy needed this layer. */
  workload?: PublishedWorkload;
}

export class PublishError extends Error {}

/**
 * Render every host and build the manifest. Pure — no clock, no filesystem, no git.
 *
 * Any host failing to render aborts the whole publish. Publishing the rest would hand out a
 * generation that is *partly* what was intended, and the hosts that did receive it would report
 * success — leaving the operator to notice the gap from a rule count. A generation is all or
 * nothing so that "published" keeps meaning one thing.
 */
/**
 * The tables this host is allowed to have besides ours.
 *
 * Every matching allowance contributes, rather than the first match winning. A host can be covered
 * by a broad pattern and a specific one at once — "every gateway runs podman" plus "this one also
 * runs something else" — and first-match-wins would silently discard the second.
 */
function allowedFilters(cfg: PublishInput["cfg"], host: string): string[] {
  const out = new Set<string>();
  for (const a of cfg.expectedFilters) {
    if (a.hosts.some((re) => new RegExp(re).test(host))) for (const t of a.tables) out.add(t);
  }
  return [...out].sort();
}

export function planPublish(input: PublishInput): PublishPlan {
  if (!input.generation) throw new PublishError("generation id is empty");
  if (input.hosts.length === 0) throw new PublishError("nothing to publish — no hosts given");

  // ## The config is re-validated here, at the render boundary
  //
  // `defineConfig` holds the safety invariants — chiefly that a dropping input hook with an empty
  // baseline is refused, which its own comment calls "the one configuration that is certainly
  // wrong". A site module in the policy repository calls it, and until now that was the only place
  // it ran.
  //
  // That is not enough, because this function is also reached from `POST /policy/plan`, where `cfg`
  // arrives as **JSON from the policy renderer** — the process this manager's own header calls "the
  // untrusted side of that connection". `parsePolicySource` checks that `site.cfg` is an object and
  // nothing more. So the guard was running inside the trust boundary and not at it.
  //
  // Measured before writing this: a `cfg` with `hookPolicy.input: "drop"` and an empty baseline
  // rendered cleanly, and its only assertion was `baseline: loopback`. The agent's `mustContain`
  // check would pass, the heartbeat would leave through the output chain and return on the input
  // chain's conntrack rule, and the host would confirm — with SSH gone and the rollback timer never
  // firing, because the relay path survived.
  //
  // Idempotent for every config already built with `defineConfig`: verified against all five site
  // modules (dev, prod, util, probe, dev-observe), which re-validate to byte-identical values. So
  // nothing that publishes today stops publishing.
  let cfg: Config;
  try {
    cfg = defineConfig(input.cfg);
  } catch (e) {
    throw new PublishError(`config is unsafe to render from: ${(e as Error).message}`);
  }

  const seen = new Set<string>();
  const artifacts: PublishedArtifact[] = [];
  const hosts: Record<string, ManifestEntry> = {};

  for (const h of input.hosts) {
    if (seen.has(h.id)) throw new PublishError(`host ${JSON.stringify(h.id)} appears twice`);
    seen.add(h.id);

    let rendered;
    try {
      rendered = renderHostRulesetJson(cfg, h.id, h.items, h.egress ?? []);
    } catch (e) {
      throw new PublishError(`cannot render ${h.id}: ${(e as Error).message}`);
    }

    const entry: ManifestEntry = {
      stage: h.stage,
      // Travels in the manifest because the relay computes the gate and never reads the policy.
      // Omitted when absent so an in-service host's entry is byte-identical to what it was before
      // this field existed — a manifest diff should show a host going out of service, not every
      // host gaining a key.
      ...(h.maintenance ? { maintenance: h.maintenance } : {}),
      rulesetHash: "sha256:" + createHash("sha256").update(rendered.json).digest("hex"),
      confirmTimeoutSec: cfg.confirmTimeoutSec,
      mustContain: rendered.assertions,
      // Empty stays empty rather than becoming `[]` in the manifest: a host whose policy targets no
      // single address (broadcast-only rules) has nothing to check, and that is different from
      // "checked and found nothing".
      ...(rendered.expectAddrs.length ? { expectAddrs: rendered.expectAddrs } : {}),
      // Always present, including when empty — unlike `expectAddrs` above. An empty list here is a
      // real statement ("nothing else should be filtering on this host") and it is the statement
      // that makes a returning firewalld visible. Omitting it would read to the agent as "no
      // expectation was expressed", which is the one answer that cannot produce a warning.
      expectFilters: allowedFilters(cfg, h.id),
      // **Filtered to what heliopause owns, and omitted when that is nothing.** The declaration also
      // names routes belonging to wg-quick and to an operator; those are for the comparison on the
      // console, and handing them to an applier would make its input wider than its authority.
      //
      // Omitted rather than `[]` for the same reason `maintenance` is: today every host would gain an
      // empty key, and a manifest diff should show a host being given routes rather than every host
      // growing a field. `[]` and absent mean the same thing to the agent — apply nothing.
      // The guard travels with the routes and only with them: it is consulted by the applier, and the
      // applier does not run when there is nothing to apply. Sending it alone would put a field on
      // every host's entry that nothing reads.
      ...(routesFor(h).length
        ? { routes: routesFor(h), routeGuard: managementGuard(cfg.baseline) }
        : {}),
    };
    hosts[h.id] = entry;
    artifacts.push({
      host: h.id,
      json: rendered.json,
      entry,
      skipped: rendered.skipped,
      ruleCount: rendered.ruleCount,
    });
  }

  // A generation with no canary cannot be staged: the first stage to open would be `general`, and
  // every host in it would apply at once. That is the failure mode staging exists to prevent, so
  // it is refused rather than allowed to look like a rollout.
  if (!input.hosts.some((h) => h.stage === "canary")) {
    throw new PublishError(
      "no host is assigned the canary stage — every other host would apply simultaneously",
    );
  }

  const workload = planWorkload(input, cfg, hosts);

  return {
    manifest: {
      generation: input.generation,
      issuedAt: input.issuedAt,
      schemaVersion: SCHEMA_VERSION,
      hosts,
    },
    artifacts,
    ...(workload ? { workload } : {}),
  };
}

/**
 * Render the workload half and attach it to the applier's manifest entry.
 *
 * Mutates `hosts` rather than returning an entry for the caller to merge, so the manifest cannot end
 * up describing a workload artifact that is not addressed to anyone.
 */
function planWorkload(
  input: PublishInput,
  /**
   * The validated config, passed rather than re-read from `input.cfg`.
   *
   * ## This is a guard against drift, and it is unfalsifiable today — measured, not assumed
   *
   * `planPublish` validates with `defineConfig` before calling this, so an invalid workload config
   * is refused there and never reaches here. And `defineConfig` does not *transform* `workload` — it
   * validates or throws — so `cfg.workload` and `input.cfg.workload` are the same object on every
   * path that gets this far. Defect injection confirms it: changing this back to `input.cfg.workload`
   * leaves `tsc --noEmit` clean and all 42 tests in `publish.test.ts` passing.
   *
   * A test claiming to cover it was written and then deleted, because it passed either way — it was
   * proving the top-level guard, not this parameter. A check that cannot fail is worth less than
   * nothing when a test asserts that it can.
   *
   * It stays for the reason the relay's "artifact unavailable" branch stays: the cost is one
   * parameter, and the failure it forecloses is a future field on `Config` that `defineConfig`
   * normalises — at which point one half of the render would silently read the raw value while the
   * other read the normalised one, and type checking would have nothing to say about it.
   */
  cfg: Config,
  hosts: Record<string, ManifestEntry>,
): PublishedWorkload | undefined {
  const items = input.workload ?? [];
  const needing = items.filter((i) => assignsToWorkloadLayer(i.policy).workload);

  const w = cfg.workload;
  if (!w) {
    // Refused, not skipped. A policy naming a pod destination has no host-layer rule behind it
    // (evaluation rule 8), so publishing the host half alone would hand out a generation that
    // confirms cleanly over traffic nobody is governing.
    if (needing.length) {
      throw new PublishError(
        `${needing.length} policy/policies need the workload layer ` +
          `(${needing.map((i) => i.policy.id).join(", ")}) but cfg.workload is null. A pod or ` +
          `service destination cannot be enforced by nftables — the packet is resolved in eBPF and ` +
          `never reaches a netfilter hook. Configure workload, or remove those policies.`,
      );
    }
    return undefined;
  }

  if (!hosts[w.applier]) {
    // The applier has to be a host in this generation, or the manifest names an assignment that
    // nothing will ever fetch — and the workload half would silently never be applied.
    throw new PublishError(
      `workload.applier ${JSON.stringify(w.applier)} is not among the hosts being published ` +
        `(${Object.keys(hosts).join(", ")}) — it would never fetch the artifact addressed to it`,
    );
  }

  if (needing.length === 0) return undefined;

  let rendered;
  try {
    rendered = renderCiliumPolicies(
      {
        k8sApplier: w.applier,
        cluster: w.cluster,
        generation: input.generation,
        ciliumVersion: w.ciliumVersion,
        ...(input.resolveService ? { resolveService: input.resolveService } : {}),
        ...(input.resolvePods ? { resolvePods: input.resolvePods } : {}),
      },
      needing,
    );
  } catch (e) {
    // Same all-or-nothing rule as the host half: a generation is one thing or it is not published.
    throw new PublishError(`cannot render the workload layer: ${(e as Error).message}`);
  }

  const entry: WorkloadEntry = {
    policiesHash: "sha256:" + createHash("sha256").update(rendered.json).digest("hex"),
    cluster: w.cluster,
    // `namespace/name` — what the agent will look for after applying. Derived from the objects
    // themselves rather than restated, so the check cannot drift from what was published.
    mustExist: rendered.plan.policies.map((p) => `${p.metadata.namespace}/${p.metadata.name}`),
    confirmTimeoutSec: w.confirmTimeoutSec,
    policyCount: rendered.plan.policies.length,
    ingressProtectedSelectors: rendered.plan.policies
      .filter((p) => p.spec.ingress?.length)
      .map((p) => p.spec.endpointSelector.matchLabels),
    // Derived from the policies being published, not restated — so what the applier is asked about
    // cannot drift from what was actually rendered. `needing` rather than every item: a policy the
    // workload layer does not own has no selector this cluster should be queried for.
    watchSelectors: selectorsToWatch(needing),
  };
  hosts[w.applier] = { ...hosts[w.applier]!, workload: entry };

  return {
    applier: w.applier,
    cluster: w.cluster,
    json: rendered.json,
    entry,
    skipped: rendered.plan.skipped,
    warnings: rendered.plan.warnings,
    affectedPods: rendered.plan.affectedPods,
  };
}

/**
 * Write a plan to the artifact directory.
 *
 * The write ordering — artifacts first, manifest renamed over atomically — lives in `writeBundle`,
 * which is also what the relay's `POST /publish` uses. One implementation on purpose: the ordering is
 * what stops a polling relay reading a half-finished generation, and two copies of it would be two
 * things to keep right with a failure that only appears when an agent fetches at the wrong instant.
 */
export async function writePublish(dir: string, plan: PublishPlan): Promise<void> {
  await writeBundle(dir, bundleFromPlan(plan));
}
