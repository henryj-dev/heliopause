// Staged rollout gating. Pure — no I/O, no clock.
//
// A generation does not reach every host at once. Hosts are assigned a stage, and a stage only
// opens once every host in the stages before it is confirmed at that same generation. The value
// of this is entirely in the failure case: a policy that locks hosts out locks out the canary,
// the canary never confirms, and the rest of the fleet never receives it.
//
// The relay evaluates this on every heartbeat, which is why it lives here as a function of
// recorded state rather than as a process the manager drives. A rollout that needed the manager
// online to advance would stall the moment the manager restarted mid-deploy.

import {
  ROLLOUT_ORDER,
  type ApplyState,
  type Manifest,
  type RolloutGate,
  type RulesetEvent,
} from "./protocol.ts";

/** The last thing a host told us about itself. */
export interface HostStatus {
  generation: string | null;
  state: ApplyState;
  /**
   * The host's own explanation, when it has one. Not used for gating — only reported.
   *
   * This is where a rollback says *why* it rolled back ("required rules absent after apply: …",
   * "confirmation timed out"). The relay was discarding it, which meant the fleet view could say a
   * host reverted but never which rule was missing, and that answer was only in the host's own
   * journal — reachable by ssh, which is the thing the status endpoint exists to avoid needing.
   */
  detail?: string | null;

  /**
   * The agent build that sent this heartbeat.
   *
   * Recorded because it is the **only server-side evidence that a host-unit deployment worked**.
   * stardust's own runbook makes the point about its node-agent — *"fail-silent, so `rc=0` even with
   * a wrong URL; do not judge installation success from the client"* — and the answer there is to
   * read `node_reports` on the server. This field is that answer here.
   *
   * The agent has always sent it (`agentVersion` in the heartbeat) and the relay discarded it one
   * line after arrival. Measured 2026-08-07: it reached `protocol.ts` as a type and nothing else.
   *
   * `undefined` on an agent too old to send one, which is itself the thing worth seeing.
   */
  agentVersion?: string | null;

  /**
   * The workload half's state, on a host that was assigned one. Absent otherwise.
   *
   * Tracked separately because the two halves genuinely disagree: a host can confirm its nftables
   * ruleset while the CiliumNetworkPolicy apply failed. Folding them into `state` would force a
   * choice between reporting the good half (a half-enforced generation reads as confirmed) and the
   * bad one (a host with no workload assignment looks broken).
   */
  workloadState?: ApplyState | null;
  workloadDetail?: string | null;

  /**
   * The objects the applier read back out of the cluster, and the digest of the document it applied
   * (H16).
   *
   * ## Why these had to be kept
   *
   * The relay was storing `workloadState` and `workloadDetail` and discarding the rest of the workload
   * report. That left nothing to compare the manifest's `mustExist` against, which is why
   * `missingObjects()` — written for exactly this — had **zero callers** in the repository.
   *
   * The consequence is the failure H16 exists to catch: an applier reports `confirmed` because
   * `kubectl apply` exited 0, and one of the policies is not actually in the cluster. Nothing
   * contradicts it, because the only thing that could was thrown away one line after arriving.
   *
   * `null` means the applier could not read the cluster back — not that the cluster is empty. Treating
   * unknown as satisfied is how a policy governing zero pods passes as applied.
   */
  workloadObserved?: string[] | null;
  workloadPoliciesHash?: string | null;

  /**
   * Other nftables tables the host reported filtering on `input` or `forward`.
   *
   * `null` means the host did not report — an older agent, or one whose `nft` call failed — and it
   * must not be read as "none". Deliberately **not** used for gating: another firewall being present
   * does not mean this generation is bad, and holding a rollout on it would stop the one change most
   * likely to be the fix.
   */
  foreignFilters?: string[] | null;
  /**
   * The host's IPv4 routes as reported (`Heartbeat.routes`).
   *
   * Carried through rather than summarised. A packet reaches a filter only if routing sent it there,
   * and the fleet view is where the two halves can finally be read side by side. `null` keeps its
   * meaning all the way up: not reported, which is not the same as none.
   */
  routes?: {
    dst: string;
    via: string;
    dev: string;
    proto: string;
    table: string;
    origin?: "automatic" | "static" | "unstated";
    handAdded: boolean;
  }[] | null;

  /**
   * Ports another table redirects inbound (H36). See `Heartbeat.publishedPorts`.
   *
   * Reported, never gated on. A published port is usually intentional; what makes it worth surfacing is
   * that this project's rules are **not consulted** for it — the packet is DNAT'd on `prerouting`,
   * before any `input` hook. Saying nothing would imply coverage that does not exist, and "I blocked it
   * and it is still open" is the worst thing a firewall can be.
   */
  publishedPorts?: string[] | null;

  /** Cilium eBPF frontends observed by the workload applier. */
  ciliumExposure?: import("./protocol.ts").CiliumExposure | null;

  /**
   * Changes to **our** table that this agent did not make (H27/H28).
   *
   * ## Why this had to travel
   *
   * The agent already subscribes to `nft monitor`, already decides which events are its own, and
   * already logs `UNAUTHORISED: n change(s) … not made by us`. It also already puts the events in its
   * heartbeat. **Nothing on this side read them** — measured 2026-08-03: zero mentions in `relay.ts`
   * and `manager.ts`.
   *
   * So intrusion detection worked and was invisible. Finding out required `ssh` to each host and
   * reading its journal, which is exactly what the status endpoint exists to remove the need for. The
   * detection was built in V-series work; this is the half that makes it observable.
   *
   * ## Why only the unauthorised ones
   *
   * The agent's own applies produce events too, and on a healthy fleet those are the overwhelming
   * majority — one per generation per host. Carrying them would bury the interesting ones in a list
   * that grows with normal operation, and a signal that arrives inside noise is not a signal.
   *
   * `null` means the host did not report (an older agent). `[]` means it watched and saw nothing —
   * the same distinction `foreignFilters` keeps, for the same reason.
   *
   * **Not used for gating.** A tampered host is the strongest possible argument for pushing a new
   * generation to it, not for withholding one.
   */
  intrusions?: RulesetEvent[] | null;
}

/**
 * States that block the stages behind them.
 *
 * `rolled-back` is in here for a reason worth stating: a host that reverted did so because
 * applying this generation cost it the path to its relay. That is the single strongest signal
 * available that the generation is bad, so it must stop the rollout rather than be retried past.
 */
const BLOCKING: Partial<Record<ApplyState, string>> = {
  none: "has not applied it",
  pending: "has not confirmed it yet",
  "rolled-back": "rolled back — the generation is suspect",
  unsupported: "cannot read this schema",
};

/**
 * May `host` apply `manifest.generation` yet?
 *
 * `statuses` is what each host last reported. A host missing from it is treated as having
 * reported nothing, which blocks — silence and success must never be the same answer, or a host
 * that has stopped heartbeating would let the rollout advance past it.
 */
export function computeGate(
  manifest: Manifest,
  host: string,
  statuses: Readonly<Record<string, HostStatus>>,
): RolloutGate {
  const entry = manifest.hosts[host];
  if (!entry) {
    // Not an error. Hosts drop out of a generation legitimately — decommissioned, or simply not
    // covered by any policy yet — and that should read as "nothing for you", not as a fault.
    return { stage: "canary", open: false, reason: `${host} is not part of this generation` };
  }

  const stageIndex = ROLLOUT_ORDER.indexOf(entry.stage);
  const earlier = ROLLOUT_ORDER.slice(0, stageIndex);

  for (const stage of earlier) {
    for (const [peer, peerEntry] of Object.entries(manifest.hosts)) {
      if (peerEntry.stage !== stage) continue;
      // ## A host declared out of service does not hold the stage shut
      //
      // The rest of this loop treats silence as a reason to stop, and that is deliberate: a host
      // that has just locked itself out reports exactly nothing, and advancing past it would spread
      // the generation that did it. **The one thing silence cannot tell you is why.**
      //
      // On 2026-08-11 `mailer-03` was migrated by its provider onto a CPU whose instruction set its
      // libc requires and does not have. It never booted, so it never reported, and the `gateway`
      // stage stayed shut for a day behind a host that was not coming back on its own. The fleet
      // was correct and stuck.
      //
      // The fix is not "skip hosts that have been quiet a long time" — that rule cannot distinguish
      // the dead host from the bricked one, and it would be the same code path for both. A person
      // states it instead, in the policy, with a reason that travels in the manifest and shows on
      // the console. `maintenance` is a claim someone made, not an inference this function drew.
      if (peerEntry.maintenance) continue;
      const status = statuses[peer];
      if (!status || status.generation !== manifest.generation) {
        return {
          stage: entry.stage,
          open: false,
          reason: `waiting on ${stage}: ${peer} has not reported this generation`,
        };
      }
      const blocker = BLOCKING[status.state];
      if (blocker) {
        return { stage: entry.stage, open: false, reason: `waiting on ${stage}: ${peer} ${blocker}` };
      }
      // A peer that confirmed its nftables half but not its workload half has not finished this
      // generation, and letting the next stage open would spread a policy set whose workload half is
      // known broken. This is checked only where the manifest assigned one, so a host without the
      // assignment cannot be blocked by a field it never reports.
      const wBlocker = peerEntry.workload ? workloadBlocker(status) : null;
      if (wBlocker) {
        return {
          stage: entry.stage,
          open: false,
          reason: `waiting on ${stage}: ${peer} ${wBlocker}`,
        };
      }
    }
  }

  return { stage: entry.stage, open: true };
}

/**
 * Why a host's workload half is not finished, or null if it is.
 *
 * A missing `workloadState` on an assigned host is a blocker, not a pass: a schema-2 agent always
 * reports the field when it has an assignment, so absence means it never applied. Treating unknown as
 * satisfied is how a cluster-scoped policy that was never written passes as rolled out.
 */
function workloadBlocker(status: HostStatus): string | null {
  const st = status.workloadState;
  if (st === undefined || st === null) return "has not reported its workload half";
  if (st === "confirmed") return null;
  const blocker = BLOCKING[st];
  return blocker ? `workload half ${blocker}` : null;
}

/**
 * Hosts whose reported state should stop an operator from walking away.
 *
 * Kept separate from gating because the two questions differ: gating asks whether to proceed,
 * this asks whether someone needs to look. A generation can be fully rolled out and still have a
 * host sitting in `rolled-back` from the attempt before it.
 */
export function rolloutBlockers(
  manifest: Manifest,
  statuses: Readonly<Record<string, HostStatus>>,
): Array<{ host: string; reason: string }> {
  const out: Array<{ host: string; reason: string }> = [];
  for (const host of Object.keys(manifest.hosts)) {
    const status = statuses[host];
    if (!status || status.generation !== manifest.generation) {
      out.push({ host, reason: "has not reported this generation" });
      continue;
    }
    const blocker = BLOCKING[status.state];
    if (blocker) {
      out.push({ host, reason: blocker });
      continue;
    }
    // Reported even when the host half is clean — that combination is the one worth showing, because
    // every other field says the generation landed.
    const wBlocker = manifest.hosts[host]!.workload ? workloadBlocker(status) : null;
    if (wBlocker) out.push({ host, reason: `${wBlocker}${status.workloadDetail ? ` — ${status.workloadDetail}` : ""}` });
  }
  return out;
}

/**
 * Seconds of silence after which a host's last report stops describing the present.
 *
 * The relay's `staleAfterSec` default, named here so the two callers that decide *how to display*
 * silence share one number with the one that decides whether to *report* it as a problem.
 */
export const STALE_SEC = 90;

/** What a status view should say about one host, before any colour is applied. */
export type HostVerdict =
  | { kind: "drift" }
  | { kind: "rolled-back" }
  | { kind: "never-seen" }
  | { kind: "silent"; ageSec: number }
  /** A person declared this host out of service. Not a fault, and not waited on. */
  | { kind: "maintenance"; reason: string }
  /** Reporting fine, but on an older generation. `blockedBy` says why when the gate is holding it. */
  | { kind: "behind"; blockedBy: string | null; state: string | null }
  | { kind: "confirmed" }
  | { kind: "other"; state: string };

/**
 * Judge one host from what the fleet view says about it.
 *
 * ## Silence outranks the stored state, and that ordering is the whole point
 *
 * `state` is the last thing a host said, not a statement about now. On 2026-08-11 `mailer-03` had
 * been dead for nine hours — Vultr migrated it onto a CPU whose instruction set its glibc requires
 * and does not have, so init never ran — and the site view printed a green `confirmed`, because
 * that genuinely was its last word. The relay view refused to do that; the site view had a second
 * copy of the decision and the copy was missing the age check.
 *
 * **A firewall console that calls a host confirmed while the host does not exist is worse than one
 * that says nothing.** It answers the question an operator actually asked — "is the fleet applying
 * my policy" — with a confident yes that stopped being true hours ago.
 *
 * So this is one function with one ordering, and both views call it. Two renderers agreeing by
 * inspection is what produced the bug.
 *
 * `drift` still outranks silence: a host that drifted and then went quiet has a specific problem,
 * and reporting only the silence would lose it.
 */
export function hostVerdict(h: {
  drifted?: boolean;
  ageSec: number | null;
  state: string | null;
  /** False when the host is applying an older generation than the one being rolled out. */
  current?: boolean;
  blockedBy?: string | null;
  maintenance?: string | null;
}): HostVerdict {
  if (h.drifted) return { kind: "drift" };
  if (h.state === "rolled-back") return { kind: "rolled-back" };
  // `null` is "never reported", which is not the same as "reported long ago" — see relay.ts. Both
  // are refusals to say the host is fine, but only one of them has an age to print.
  // ## `maintenance` outranks every form of silence, including "never heard from"
  //
  // This sat *below* `never-seen`, on the reasoning that a host nobody has ever heard from is
  // unaccounted for rather than out of service. That reasoning ignored how `ageSec` becomes null:
  // the relay's state is memory-only, so **every host reads as never-seen for a minute after a
  // relay restart** — and a host that is genuinely gone never beats again, so it stays there
  // permanently. Measured 2026-08-11: `mailer-03` was declared out of service, the flag reached the
  // view intact, and the console still drew `never seen`.
  //
  // The ordering question is really "which is the stronger statement". `never-seen` is the absence
  // of an observation; `maintenance` is a sentence a person wrote about this host on purpose. A
  // declaration should not be overridden by the absence of a measurement it already explains.
  // Above every form of silence — both `never-seen` and `silent`. This host is quiet *and somebody
  // wrote down why*, which is a stronger statement than either measurement.
  //
  // Still below drift and rollback. Those are statements the host itself made about the generation,
  // and an exemption from being waited on must not erase evidence the host already produced.
  //
  // ⚠️ There was a second, identical `if (h.maintenance)` below the `never-seen` line, left behind
  // when this one moved up. It was unreachable, and the comment that travelled with it argued for
  // the *old* order ("Below `never-seen` for the opposite reason") — so the function that says
  // ordering is the whole point carried a paragraph describing an order it no longer had. Deleting
  // either copy broke no test, which is the other reason it survived.
  if (h.maintenance) return { kind: "maintenance", reason: h.maintenance };
  if (h.ageSec === null) return { kind: "never-seen" };
  if (h.ageSec > STALE_SEC) return { kind: "silent", ageSec: h.ageSec };
  // Being behind outranks `state`, for the same reason silence does: `confirmed` describes the
  // generation this host is running, not the one being rolled out. A host mid-rollout is reporting
  // healthily *about the wrong thing*, and a green row next to a `wanted elsewhere` generation is
  // the table contradicting itself in two columns.
  if (h.current === false) return { kind: "behind", blockedBy: h.blockedBy ?? null, state: h.state };
  if (h.state === "confirmed") return { kind: "confirmed" };
  if (h.state === null) return { kind: "never-seen" };
  return { kind: "other", state: h.state };
}

// ── Agent versions ───────────────────────────────────────────────────────────

/**
 * The leading `major.minor.patch` of an agent version, or `null` when there is none to read.
 *
 * `AGENT_VERSION` is `0.6.0-pull-signed-routes` — a semver core plus a label naming what the build
 * carries. Only the core is compared; the label is for a human reading a journal, and ordering it
 * would mean deciding whether `pull-signed` precedes `pull-signed-routes`, which is a question with
 * no answer.
 *
 * `null` for anything unparseable, and the caller treats that as "cannot tell" rather than "old" —
 * a version string this code does not understand is not evidence about the host.
 */
export function agentVersionCore(value: string | null | undefined): [number, number, number] | null {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(String(value ?? ""));
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

/** Is `have` at least `want`? Both are `major.minor.patch` tuples. */
export function atLeastVersion(have: readonly [number, number, number], want: readonly [number, number, number]): boolean {
  for (let i = 0; i < 3; i++) {
    if (have[i]! !== want[i]!) return have[i]! > want[i]!;
  }
  return true;
}

/**
 * Why a host's agent build is worth an operator's attention, or `null`.
 *
 * ## Why this exists
 *
 * `agentVersion` has travelled from the heartbeat to `HostStatus` to the fleet view since 2026-08-07,
 * and **nothing has ever read it**. It is a column. `MIN_AGENT_SCHEMA` gates the schema and stops a
 * rollout loudly; a fleet where half the hosts run last month's agent produces no such sentence,
 * because every one of them speaks the current schema and confirms normally.
 *
 * That gap is the case this closes. A build older than the floor is not wrong — it applies policy
 * correctly — but it is missing whatever the floor was raised for, and the only place that fact
 * exists today is a column nobody diffs.
 *
 * ## Reported, never gated
 *
 * Same rule as `foreignFilters` and `intrusions`. Withholding a generation from an out-of-date agent
 * would stop the rollout that is most likely to be carrying the fix, and an old agent that applies
 * policy correctly is not a reason to leave it on older policy.
 */
export function agentVersionConcern(
  status: Pick<HostStatus, "agentVersion"> | undefined,
  floor: readonly [number, number, number] | undefined,
): string | null {
  if (!floor) return null;
  const want = floor.join(".");
  if (!status) return null; // Silence is its own finding and `fleetView` already reports it.
  const raw = status.agentVersion;
  // `null` is an agent too old to send the field at all — which is strictly older than any floor.
  if (raw === null || raw === undefined) return `reports no agent version, so it predates ${want}`;
  const have = agentVersionCore(raw);
  if (!have) return `reports an agent version this manager cannot read (${raw})`;
  return atLeastVersion(have, floor) ? null : `runs agent ${raw}, below the ${want} floor`;
}
