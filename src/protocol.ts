// The contract between manager, relay and agent. Pure types — no I/O.
//
// ── Why the agent pulls ───────────────────────────────────────────────────────
// The previous design had the control plane POST a ruleset to an HTTP server on every host.
// That server is an inbound attack surface on a firewall host, and it makes the control plane
// responsible for confirming reachability — which it cannot do reliably, because the thing it
// is testing is the path to itself.
//
// Here the agent opens every connection. It heartbeats out to a relay, and the reply carries
// the trigger. Three consequences follow, and they are the reason for the shape of these types:
//
//   1. **No listening port on the agent.** Nothing to reach, nothing to authenticate inbound.
//   2. **The heartbeat is the confirm signal.** If a freshly applied ruleset severs the path to
//      the relay, the next heartbeat fails and the agent rolls itself back. No external actor
//      has to notice, so rollback survives the control plane being down.
//   3. **Rollback is armed only for the generation just applied.** Once confirmed, a later
//      heartbeat failure means "updates have stopped", not "undo". Without that distinction a
//      gateway outage would make every host in the VPC revert a change that was fine.
//
// ── Why a schema version ──────────────────────────────────────────────────────
// Manager, relay and agent are updated at different times, so version skew is the normal state
// rather than an error. An agent that meets an artifact it does not understand must refuse it
// and say so. Guessing, or silently applying a partial interpretation, is worse than stalling.

/**
 * Bumped when the shape of anything in this file changes incompatibly.
 *
 * 4 adds `ManifestEntry.routes` and `routeGuard` to the signed entry. That is a **breaking** change
 * rather than an additive one, and the reason is the receiver: the agent validates a signed entry
 * with an exact key set and refuses anything it does not know, so a schema-3 agent meeting a routed
 * entry rejects the whole artifact and the rollout stalls at it — with the reason only in that
 * host's journal. Bumping instead makes the relay say it: "agent speaks schema 3, relay speaks 4",
 * on the fleet view, which is where somebody is looking.
 *
 * 3 requires manager-signed host envelopes and removes unsigned relay selector instructions. A
 * schema-2 agent would trust a compromised relay's replacement ruleset, so version skew cannot be
 * tolerated here. 2 added the workload half (`Artifact.workload`, `WorkloadEntry`, `Heartbeat.workload`). A schema-1
 * agent would ignore the field and apply only the nftables ruleset — which is exactly why this is a
 * bump rather than an additive change it could tolerate. Silently enforcing half a generation while
 * reporting a clean confirm is the failure this version number exists to make loud: a schema-1 agent
 * now reports `unsupported` and the rollout stops at it.
 */
export const SCHEMA_VERSION = 5;

/**
 * Lowest schema an agent may report and still be given work.
 *
 * The manager stops the rollout at a host below this rather than sending it something it will
 * mis-read.
 *
 * Raised to 4 with the signed route half, for the reason on `SCHEMA_VERSION`: a schema-3 agent
 * refuses a routed entry outright, and stopping the rollout here says so where it can be read.
 *
 * Raised to 2 with the workload half. Keeping it at 1 would let an older agent accept a generation
 * whose workload artifact it cannot apply, and the pod-destination policies in it have no fallback
 * layer behind them (evaluation rule 8) — so the traffic would be ungoverned while the host
 * confirmed.
 */
export const MIN_AGENT_SCHEMA = 5;

export type ArtifactAuthorizationMode = "two-person" | "solo-otp" | "break-glass";

// ── Generations ───────────────────────────────────────────────────────────────

/**
 * One publishable state of the whole policy set.
 *
 * `id` is the git commit that produced it. Using the commit rather than a counter means the
 * audit trail is the repository — "what did generation X contain" is answered by checking it
 * out, and nothing has to be stored twice.
 */
export interface Generation {
  id: string;
  /** ISO 8601. Stamped by the manager at publish time, not by the agent. */
  issuedAt: string;
  schemaVersion: number;
}

/** What a single host is expected to enforce at a given generation. */
export interface Artifact {
  generation: string;
  host: string;
  /**
   * The complete ruleset as an **nft JSON document** (`nft -j -f` input), serialised.
   *
   * JSON rather than nft text because the agent has to decide whether this is safe to apply, and
   * on text that means out-guessing nft's tokeniser — an approach that was measured to let
   * cross-table writes and `;`-separated `flush ruleset` straight through. In JSON every element
   * names its own family and table, so the check is a field comparison.
   *
   * Rendering already happened in the manager; the agent never renders.
   */
  ruleset: string;
  /**
   * Digest of `ruleset`, as text.
   *
   * Both sides compute this over the same bytes, so it answers exactly one question: did this
   * host receive the artifact we published? It deliberately says nothing about what the kernel
   * ended up holding — see `Heartbeat.applied.observedHash` for that.
   *
   * Sending the full text on every heartbeat would be wasteful (rulesets reach tens of kilobytes
   * once geofeed sets are attached), so the digest travels and the text is fetched only on
   * disagreement.
   */
  rulesetHash: string;
  /** Seconds to wait for a successful heartbeat before rolling back. */
  confirmTimeoutSec: number;

  /**
   * Rule comments that must be present in the table after applying.
   *
   * Checked by the agent before it arms anything. The heartbeat that confirms an apply proves the
   * path to the relay survived and nothing else — a ruleset that keeps the relay reachable while
   * dropping the management baseline would confirm cleanly and still take the host away.
   */
  mustContain: string[];

  /**
   * Addresses this host's inbound policy was written against. Empty means "do not check".
   *
   * The agent refuses the artifact if it holds **none** of these. That is a different question from
   * `mustContain`, which asks whether the rules landed in the kernel; this asks whether they name
   * the right machine.
   *
   * ## Why this is needed
   *
   * A site module resolves each host to an address and renders `ip daddr <addr>` matches from it.
   * Nothing downstream checks that the host still answers on that address, so if it changes, the
   * publish succeeds, the rules render cleanly, `mustContain` passes — the baseline comments are
   * all present — and every service rule silently matches traffic that will never arrive.
   *
   * Measured: mailer-01.dev rebooted, a profile conflict left it on `10.17.0.5` instead of the
   * `10.17.101.12` in `policy/dev.ts`, and nothing anywhere reported a problem. Under `accept` that
   * cost nothing. Under `drop` it is every mail port refused while the control plane says confirmed.
   *
   * The agent is the only party that can answer this — the publisher is pure and the relay
   * deliberately cannot interpret what it serves. `null` for a host whose policy targets no address
   * (broadcast-only rules, say), so "nothing to check" stays distinct from "checked and failed".
   */
  expectAddrs?: string[];

  /**
   * Other nftables tables this host is *expected* to have filtering on `input` or `forward`.
   *
   * The counterpart to `Heartbeat.foreignFilters`. The agent reports what it sees; this says which
   * of those are known and accounted for, and the difference is what becomes a problem.
   *
   * ## Why an allowlist rather than "any foreign table is a problem"
   *
   * Because two hosts in this fleet legitimately have one, permanently:
   *
   *     gw-01.dev   inet netavark   podman's network backend
   *     k3s-01      ip filter       kube-proxy
   *
   * Neither can be removed — the services on them need it. A check that fires on two of seven hosts
   * every single poll is a check operators learn to scroll past, and then it is worth less than
   * nothing: it is a warning that trains people to ignore warnings. Naming the expected ones is what
   * keeps the remaining signal meaningful.
   *
   * Empty means "nothing else should be filtering here", which is the correct expectation for a host
   * where heliopause is meant to be the only firewall — and stating it is what makes a returning
   * firewalld visible rather than silently authoritative.
   */
  expectFilters?: string[];

  /**
   * The workload half of this host's policy, when this host is the designated applier.
   *
   * Absent on every other host, and absent entirely on a host outside a cluster. Absent is not
   * "nothing to enforce" — it is "not your job", which is why the field is optional rather than an
   * empty document. A host that finds it missing applies its nftables half and stops.
   */
  workload?: WorkloadArtifact;
}

/**
 * CiliumNetworkPolicy objects for one cluster, carried alongside the nftables ruleset.
 *
 * ## Why this rides in the same artifact
 *
 * The two layers enforce one policy set (evaluation rule 8: a pod destination is the workload
 * layer's sole responsibility, a pod source is both layers'). Publishing them as separate
 * generations would let a host confirm the nftables half while the workload half was never applied,
 * and the control plane would report a clean generation over a policy that is half enforced. One
 * artifact, one generation, one confirm.
 *
 * ## Why only one host gets it
 *
 * CiliumNetworkPolicy is cluster-scoped. Three agents on three nodes writing the same object is
 * declarative convergence in theory and API contention with flapping in practice, so the manager
 * names one applier (H17) and the other nodes receive nothing. `applier` is echoed here so the
 * agent can refuse an artifact addressed to someone else rather than trusting that it was only
 * ever sent the right one.
 */
export interface WorkloadArtifact {
  /**
   * The CiliumNetworkPolicy objects, serialised as a JSON array.
   *
   * A document rather than a per-object list for the same reason the nftables half is one document:
   * the agent applies it as a unit, so a partial apply is not a state it can reach.
   */
  policies: string;
  /** Digest of `policies`. Same contract as `rulesetHash` — did this host get what we published? */
  policiesHash: string;
  /**
   * Host id this document is addressed to. The agent refuses it if this is not itself.
   *
   * The relay serves per-host artifacts and the certificate CN decides which one, so a mismatch
   * here should be impossible. It is checked anyway: the cost is one comparison, and the failure it
   * catches is two nodes fighting over one cluster-scoped object.
   */
  applier: string;
  /** Cluster this belongs to, for operator display and to keep two clusters' objects distinct. */
  cluster: string;
  /**
   * Object names the agent must find after applying, as `namespace/name`.
   *
   * The workload-layer equivalent of `mustContain`, and needed for the same reason: a successful
   * `kubectl apply` proves the API server accepted the documents, not that the objects are present
   * and governing pods. Cilium accepting a policy that selects nothing is the failure mode this
   * layer exists to remove.
   */
  mustExist: string[];
  /**
   * Seconds to wait before rolling the workload half back. Separate from `confirmTimeoutSec` (H20).
   *
   * The two layers fail differently, so one number cannot serve both. A bad nftables ruleset severs
   * SSH and the relay connection, so its timer has to be short. A bad CiliumNetworkPolicy breaks
   * app traffic while leaving node access intact, and needs to allow for Cilium's own convergence —
   * the agent identity cache and the eBPF maps do not update the instant the API server returns.
   * A timer as short as the nftables one would roll back healthy policy mid-convergence.
   */
  confirmTimeoutSec: number;
}

/**
 * What the manager publishes alongside a generation's rendered rulesets.
 *
 * The relay is deliberately not able to derive this. It serves what it is given and gates on
 * recorded state; deciding *what* each host should run stays in one place, so a compromised or
 * merely buggy gateway cannot invent a ruleset for the hosts behind it.
 */
export interface Manifest {
  generation: string;
  issuedAt: string;
  schemaVersion: number;
  /** Keyed by host id. A host absent from this map gets nothing at this generation. */
  hosts: Record<string, ManifestEntry>;
}

export interface ManifestEntry {
  stage: RolloutStage;
  /**
   * Why this host is out of service, if it is. Set by a person in the policy; see `PublishHost`.
   *
   * The relay uses it to stop waiting on this host, and only for that. The ruleset still ships and
   * the host still applies it when it returns.
   */
  maintenance?: string;
  /** Digest of that host's rendered artifact text. */
  rulesetHash: string;
  confirmTimeoutSec: number;
  /**
   * Rule comments the agent must find after applying, or it reverts.
   *
   * Travels in the manifest rather than inside the ruleset so the relay can hand it over without
   * parsing the artifact — the relay is deliberately unable to interpret what it serves.
   */
  mustContain: string[];

  /** Addresses the policy targets. See `Artifact.expectAddrs` — travels the same way. */
  expectAddrs?: string[];

  /** Other tables permitted to filter here. See `Artifact.expectFilters` — travels the same way. */
  expectFilters?: string[];

  /**
   * Routes this host must hold, and **only the ones heliopause owns**.
   *
   * ## Why the agent is not shown the rest
   *
   * The declaration also names routes owned by `wireguard` and by an operator. Those are compared on
   * the console and they are not this agent's business: an applier whose input is wider than its
   * authority is one refactor away from acting on the difference. What arrives here is exactly what
   * may be written, so "which of these am I allowed to touch" is not a question this code can get
   * wrong.
   *
   * ## Why it is in the manifest rather than a fetched artifact
   *
   * The same reason `mustContain` and `expectAddrs` are: the relay hands it over without reading it,
   * and a handful of small objects does not need a second fetch-and-verify path. The manifest is
   * hashed whole (`canonicalManifest` sorts every key of the object), so these are covered by the
   * bundle digest an approval is granted against — a bundle cannot carry different routes under the
   * same hash.
   *
   * Absent means this host applies no routes, which is every host today.
   */
  routes?: {
    dst: string;
    via?: string;
    dev?: string;
    table?: string;
  }[];

  /**
   * Ranges the agent must refuse to route over. Travels only when `routes` does.
   *
   * The heartbeat proves the relay path survived and says nothing about the operator's, so a route
   * that redirects the management range confirms cleanly while locking everybody out. This is the
   * `mustContain` of the routing half — see `managementGuard`, which derives it from `cfg.baseline`
   * rather than from a second list somebody has to keep in step.
   */
  routeGuard?: string[];

  /**
   * Present when this host is the workload-layer applier. Absent otherwise.
   *
   * Travels in the manifest for the same reason `mustContain` does: the relay hands it over without
   * reading the artifact, because the relay is deliberately unable to interpret what it serves.
   */
  workload?: WorkloadEntry;
}

/** The manifest's view of a host's workload assignment — digests and checks, never the document. */
export interface WorkloadEntry {
  policiesHash: string;
  cluster: string;
  mustExist: string[];
  confirmTimeoutSec: number;
  /** How many objects the document holds. Shown to operators; not a check. */
  policyCount: number;
  /**
   * Endpoint selectors governed by at least one rendered ingress allow.
   *
   * The relay combines these signed selectors with a confirmed workload hash before deciding that
   * an observed Cilium HostPort/NodePort is protected rather than merely bypassing nftables.
   */
  ingressProtectedSelectors?: Array<Record<string, string>>;
  /** Namespaces protected by an owned ingress-default-deny baseline. */
  ingressDefaultDenyNamespaces?: string[];
  /**
   * Selectors the applier should report membership for (H14a).
   *
   * Travels in the manifest for the same reason `mustContain` does: the relay hands it over without
   * reading the artifact, because the relay is deliberately unable to interpret what it serves. The
   * manager decides what to ask about — it is the only party that knows which selectors its policies
   * use — and the relay is a courier.
   */
  watchSelectors?: WatchSelectors;
}

// ── Rollout ───────────────────────────────────────────────────────────────────

/**
 * Applying a generation everywhere at once means a bad policy locks every host at once.
 *
 * Hosts advance in stages inside their own VPC, and each stage waits for the previous one to
 * confirm. The gateway is deliberately last: it runs the relay, so locking it out stops the
 * rest of that VPC from receiving anything — including the fix.
 */
export type RolloutStage = "canary" | "general" | "gateway";

export const ROLLOUT_ORDER: readonly RolloutStage[] = ["canary", "general", "gateway"] as const;

// ── Heartbeat ─────────────────────────────────────────────────────────────────

export type ApplyState =
  /** Nothing from us is on this host yet. */
  | "none"
  /** Applied, rollback timer running, waiting for a heartbeat to succeed. */
  | "pending"
  /** A heartbeat succeeded while pending. The timer is disarmed. */
  | "confirmed"
  /** The timer fired, or apply failed. The previous state was restored. */
  | "rolled-back"
  /** The artifact's schema is outside what this agent understands. Nothing was applied. */
  | "unsupported";

/**
 * A ruleset change observed on the host, from `nft monitor`.
 *
 * The agent watches continuously and buffers events with their own timestamps; the manager
 * collects them later. Separating detection from collection is what keeps a slow polling
 * interval from blurring *when* something happened — only *when we found out* moves.
 *
 * `pid`/`process` are the point of this: a change to our table made by anything other than the
 * agent is unauthorised, and that is decidable without trusting the agent's own accounting.
 */
export interface RulesetEvent {
  at: string;
  /** e.g. `inet heliopause`. Changes to other tables are recorded but not treated as ours. */
  table: string;
  /** Raw `nft monitor` line. Kept verbatim — normalising it would lose evidence. */
  raw: string;
  pid?: number;
  process?: string;
  /** True when this agent caused it. Anything else against our table is a finding. */
  byAgent: boolean;
}

/**
 * Which pods the cluster's selectors currently match (H14a).
 *
 * Reported by the applier so the manager can render `affectedPods` for selector-based policies and
 * compare pod counts across generations. Everything here is an observation with a timestamp, never a
 * decision — the agent reports what it saw and the manager decides what that means.
 */
export interface SelectorMembership {
  /**
   * ISO 8601, when the cluster was queried. **Not** when the heartbeat was sent.
   *
   * Pod membership goes stale in seconds — a CI runner exists for the length of one job. A count
   * without a time it was true is a number an operator will read as current and act on, so the two
   * always travel together and the manager refuses to use a reading older than it is willing to
   * trust.
   */
  at: string;
  /**
   * Pods per namespace, as bare pod names, for namespaces any policy selects.
   *
   * Keyed by namespace because that is the coarsest selector kind (`k8s-namespace`) and the finer
   * one (`k8s-label`) is resolved from `labelled` below. Empty array means "queried, and there are
   * none" — which is why the whole field being absent has to mean something different.
   */
  namespaces: Record<string, string[]>;
  /**
   * Pods matching each label selector the manager asked about, keyed by the selector string.
   *
   * The agent does not invent these keys: they arrive only inside the verified signed
   * `ManifestEntry.workload.watchSelectors`, so the manager asks about exactly the selectors its
   * policies use and an untrusted relay cannot expand what the agent queries.
   * Anything else would either be a cluster-wide pod dump on every beat or a guess about what
   * matters.
   */
  labelled: Record<string, string[]>;
  /** Set when the query failed. The other fields are then whatever was readable, possibly nothing. */
  detail?: string;
}

/** Cilium's host-facing eBPF service state, observed by the cluster applier. */
export interface CiliumExposure {
  /** Empty means Cilium accepts NodePort/HostPort frontends on every node address. */
  nodePortAddresses: string[];
  /** Canonical host-facing frontends, e.g. `HostPort 0.0.0.0:443/TCP dispatcher/pod`. */
  services: string[];
}

/** Agent → relay. Sent on an interval; this is the only connection either one makes. */
export interface Heartbeat {
  host: string;
  agentVersion: string;
  /**
   * Digest of the agent's own source, as `agent/heliopause-pull.py` computes it.
   *
   * Optional because an older agent does not send it, and `null` there means "did not say" — never
   * "matches". See `_agent_build` in the agent for why a version string was not enough: a change can
   * be load-bearing for what an agent accepts and still move neither `agentVersion` nor
   * `schemaVersion`, and one did.
   */
  agentBuild?: string | null;
  /**
   * Why this host refused the last artifact it was offered, when it refused one.
   *
   * Absent means "nothing to say". Present, it is the sentence that used to exist only in the host's
   * journal: `verify_artifact_envelope` raises, the agent logs one line and returns, and the next
   * heartbeat reported the *previous* generation with no reason at all.
   *
   * That silence cost two round trips on 2026-09-02–03 — a schema skew on one host, a peer namespace
   * on the applier — and in both the relay was holding a generation while the agent knew exactly why
   * it would not take it. The fleet view showed `blockedBy: null`.
   */
  lastRefusal?: { generation: string; reason: string; at: string } | null;
  schemaVersion: number;

  /**
   * Public-key trust configuration and the signed authorization currently enforced by this host.
   *
   * Only the host knows which keys it will accept a ruleset from, which makes this the only source
   * for two questions the rest of the system cannot answer:
   *
   *   · `managerKeyIds` / `breakGlassKeyIds` / `trustDigest` — **did a key rotation reach every
   *     host?** The published procedure is add-then-remove across N machines, and without this
   *     "the new signing key is deployed" is an assumption about a file. `fleetView` compares the
   *     digests across the generation and reports a fleet that does not agree.
   *   · `currentAuthorizationMode` / `currentAuthorizedAt` — **is a `break-glass` authorization
   *     still in force?** The manager keeps no record of what it authorized (`approval.ts` deletes a
   *     plan the moment it is published, because an approval that outlives its publish is a standing
   *     permission), so the host enforcing it is the only place its duration is visible. `fleetView`
   *     reports it.
   *
   * ⚠️ **`currentKeyId`, `currentPayloadHash` and `currentPlanHash` are carried and not compared.**
   * They would answer "is a host enforcing an authorization we did not issue", and the comparison
   * needs the manifest to name the authorization it published. The manifest is hashed into the
   * approval bundle, so extending it is a wire change with an approval-path consequence — a decision
   * to take deliberately, not as a side effect of adding a diagnostic. Stated here rather than left
   * for someone to rediscover that the data is present and unused.
   *
   * This whole object reached nothing until 2026-08-24: the agent built and sent it every interval
   * and `handleHeartbeat` copied the heartbeat into `HostStatus` field by field without it.
   */
  artifactTrust?: {
    managerKeyIds: string[];
    breakGlassKeyIds: string[];
    trustDigest: string;
    currentKeyId: string | null;
    currentPayloadHash: string | null;
    currentAuthorizationMode: ArtifactAuthorizationMode | null;
    currentAuthorizedAt: string | null;
    currentPlanHash: string | null;
  };

  applied: {
    generation: string | null;
    state: ApplyState;

    /**
     * Digest of the artifact **text** this host applied. Compared to `Artifact.rulesetHash`.
     *
     * Answers "did it get what we sent", and nothing more.
     */
    artifactHash: string | null;

    /**
     * Digest of the table **as read back from the kernel**, from a stateless dump.
     *
     * This is never equal to `artifactHash` and is not meant to be: the artifact is input text,
     * the dump is nft's own normalised rendering of the parsed result. The only sound comparison
     * is dump-to-dump on the same host — the value captured immediately after a successful apply
     * versus the value now. A difference means something changed the table behind us: a manual
     * edit, another tool, or an intruder.
     *
     * The dump is taken with nft's stateless flag so counter values are excluded. Otherwise the
     * digest would change with every packet and drift detection would be pure noise.
     */
    observedHash: string | null;

    /** Set when `state` is `unsupported` or `rolled-back`, so the manager can show a reason. */
    detail?: string;
  };

  /**
   * The workload half's own state. Absent on a host that was never given one.
   *
   * Reported separately rather than folded into `applied`, because the two halves can genuinely
   * disagree: the nftables ruleset confirms while the CiliumNetworkPolicy apply fails, or the
   * reverse. A single state field would have to pick one to report, and either choice hides a
   * half-enforced generation behind a clean status — the thing this whole layer exists to prevent.
   */
  workload?: {
    state: ApplyState;
    /** Digest of the document this host applied. Compared to `WorkloadArtifact.policiesHash`. */
    policiesHash: string | null;
    /**
     * Objects found in the cluster after applying, as `namespace/name`.
     *
     * The workload equivalent of reading the table back. Compared against `mustExist`, and reported
     * rather than reduced to a boolean so an operator can see *which* object went missing.
     */
    observed: string[] | null;
    detail?: string;
  };

  /**
   * What the cluster's selectors currently match, reported by the designated applier (H14a).
   *
   * ## Why this travels rather than being looked up
   *
   * The renderer is a pure function and cannot query a cluster — that is the property that makes a
   * plan reproducible and testable. So the facts it needs are injected, exactly as `ResolveCidrs`
   * injects address resolution. This is that injection for pod membership.
   *
   * ## What it is for
   *
   * A rendered policy names a selector; an operator needs to know **which pods that selector hits**.
   * Without it, `affectedPods` is empty for the `k8s-namespace` and `k8s-label` kinds, and an empty
   * list is indistinguishable from "no pods" when it actually means "not known". `arc-runners` is
   * precisely that case: genuinely zero between CI jobs, filled the moment work arrives.
   *
   * It is also what makes the selector-change guardrail possible. A Service selector that widens
   * silently widens the policy built on it, and the only way to notice is to compare the pod count
   * this reports against the last one.
   *
   * Absent on every host that is not the applier, and absent on an applier that could not query the
   * cluster — the second is why `SelectorMembership.at` exists.
   */
  membership?: SelectorMembership;

  /**
   * Other nftables tables filtering on this host, as `family name` (`"inet firewalld"`).
   *
   * ## Why this is reported at all
   *
   * Because the failure it catches is silent and this project already hit it. On 2026-08-02 a
   * generation was published, five hosts confirmed it, the kernel held exactly the rendered rules,
   * and **not one of the newly declared ports was reachable** — firewalld was hooked on the same
   * chain and rejecting them. A packet must pass every table hooked on its path, so a ruleset can be
   * perfectly applied and completely overridden, and the fleet view says `no problems` throughout.
   *
   * `confirmed` means "the rules I was given are in the kernel". It has never meant "these rules
   * decide". This field is the difference between those two sentences.
   *
   * ## Only the hooks that can override us
   *
   * `input` and `forward`. A table hooking `output`, `prerouting` or `postrouting` is doing NAT or
   * egress work that does not contradict an inbound decision, and listing it would bury the case
   * that matters in the ones that never do.
   *
   * ## null is not an empty list
   *
   * `null` means the agent did not report — an older agent, or one whose `nft` call failed. `[]`
   * means it looked and found nothing. Folding the first into the second would turn "we cannot see
   * whether another firewall is running" into "there is no other firewall", which is the exact
   * inversion this field exists to prevent.
   */
  foreignFilters?: string[] | null;

  /**
   * The host's IPv4 routes, as the kernel holds them (`ip -4 route show table all`).
   *
   * ## Why a firewall protocol carries routing
   *
   * A packet reaches a filter only if routing sent it there, so a ruleset and a route are two halves
   * of one answer and this protocol carried only one of them. Measured on gw-01.dev on 2026-08-16:
   * two `proto static` routes carry every packet bound for the cluster's pod and service ranges, and
   * **neither is written down anywhere** — not in the policy repository, not in a manifest, nowhere
   * but that kernel. Rebuild the host and they are gone, and nothing in this system would notice
   * until the gateway stopped reaching the cluster.
   *
   * ## What `origin` claims, and what it does not
   *
   * Three values, and the third one is a correction. `static` means proto `static` or `boot` — a
   * person or a script ran `ip route add`. `automatic` means the kernel, a DHCP lease or a routing
   * daemon owns it and can be asked. `unstated` means the kernel reported **no protocol at all**,
   * which names nobody and is not a synonym for either.
   *
   * The first version had two values and folded `unstated` into hand-added. Four of the six routes it
   * flagged on gw-01.dev were `wg0` routes with no protocol, and they are `wg-quick`'s, installed from
   * the peer's `AllowedIPs` — measured 2026-08-17 to match that list exactly. Two thirds of the column
   * was a false positive.
   *
   * **None of these values says "undeclared."** That question needs something to compare against, and
   * it now exists in the site model — `src/routes.ts` holds the declaration and the comparison.
   *
   * `handAdded` is the old field. It stays on the wire for a manager older than the agent, it now
   * carries the narrow meaning only, and a current manager reads `origin` instead: mixing the two eras
   * would put a known-wrong verdict beside a correct one in the same column.
   *
   * `null` means the agent did not report — an older agent, or one whose `ip` call failed. Same
   * contract as `foreignFilters`, for the same reason.
   */
  routes?:
    | {
        dst: string;
        via: string;
        dev: string;
        proto: string;
        table: string;
        /** Absent from agents older than 2026-08-17; the manager classifies from `proto` in that case. */
        origin?: "automatic" | "static" | "unstated";
        handAdded: boolean;
      }[]
    | null;

  /**
   * Ports another table redirects inbound, as `family table: proto/port -> dest` (H36).
   *
   * ## Why a firewall reports what it cannot control
   *
   * A published container port is DNAT'd on `prerouting`, before any `input` hook. The packet never
   * reaches this project's rules, so a policy declaring that port closed is not wrong — it is simply
   * not consulted. **"I blocked it and it is still open" is the worst thing a firewall can be**, and
   * this is the one shape of it that is structurally outside our reach.
   *
   * So the fleet view says so instead of implying coverage it does not have. Not gated on: a published
   * port is usually intentional, and holding a rollout over one would block the change most likely to
   * be the fix.
   *
   * `null` = the agent could not read the kernel; `[]` = it looked and found none.
   */
  publishedPorts?: string[] | null;

  /**
   * HostPort/NodePort frontends implemented in eBPF, where nftables cannot observe or govern them.
   * Absent on non-cluster hosts; null means the designated applier tried and could not read Cilium.
   */
  ciliumExposure?: CiliumExposure | null;

  /** Per-rule hit counts, keyed by the rule comment. Absent when counters are unavailable. */
  counters?: Record<string, number>;

  /** Buffered since the last successful heartbeat. Cleared once accepted. */
  events?: RulesetEvent[];
}

/**
 * Relay → agent. The trigger rides here.
 *
 * The relay never opens a connection to the agent — doing so would require the agent to listen,
 * which is the thing this design removes. Anything the agent needs to be told has to fit in a
 * reply to a request it made itself.
 */
export interface HeartbeatReply {
  /**
   * Generation the agent should be running.
   *
   * `null` means "nothing new" — either it is already current, or its stage has not opened yet.
   * The two are distinguished by `gate`, because "wait" and "you are done" need different
   * displays and only one of them is worth alerting on.
   */
  generation: string | null;
  gate: RolloutGate;
  /** Echoed so a misconfigured or stale relay is visible rather than silently tolerated. */
  schemaVersion: number;

}

/** What the applier should look up, carried only inside its signed manifest entry. */
export interface WatchSelectors {
  /** Namespaces to list pods in, for `k8s-namespace` policies. */
  namespaces: string[];
  /**
   * Label selectors to match, in the same `a=1,b=2` form the policy model uses.
   *
   * Echoed back as the keys of `SelectorMembership.labelled`, so the manager can line answers up
   * with questions without the agent having to normalise anything.
   */
  labels: string[];
}

export interface RolloutGate {
  stage: RolloutStage;
  /** False while an earlier stage is still unconfirmed. Not an error — a queue position. */
  open: boolean;
  /** Shown to operators, e.g. "canary h-pg not yet confirmed". */
  reason?: string;
}

// ── Guards ────────────────────────────────────────────────────────────────────

/**
 * Can this agent act on an artifact of the given schema?
 *
 * Deliberately a plain predicate rather than a range check spread across call sites: the
 * decision to refuse unknown work should be made in one place and be easy to find.
 */
export function schemaSupported(artifactSchema: number, agentSchema = SCHEMA_VERSION): boolean {
  return artifactSchema === agentSchema;
}

/** Did this host receive and apply the artifact we published? */
export function artifactMatches(artifact: Artifact, hb: Heartbeat): boolean {
  return hb.applied.artifactHash === artifact.rulesetHash;
}

/**
 * Did the workload half land as published?
 *
 * Three outcomes, and the middle one is the reason this is not a `&&` at the call site:
 *
 * - `"n/a"` — nothing was assigned and nothing reported. Not a success and not a failure.
 * - `"missing"` — a workload artifact was published and the host said nothing about it. A schema-2
 *   agent always reports the field when it has one, so silence means it never got there.
 * - `"mismatch"` — it applied something, but not what we sent.
 *
 * A boolean would have to fold `"n/a"` into either true or false. True hides a host that dropped its
 * assignment; false makes every non-cluster host look broken.
 */
export function workloadStatus(
  artifact: Artifact,
  hb: Heartbeat,
): "n/a" | "ok" | "missing" | "mismatch" | "unassigned-but-reported" {
  const want = artifact.workload;
  const got = hb.workload;
  if (!want) return got ? "unassigned-but-reported" : "n/a";
  if (!got) return "missing";
  return got.policiesHash === want.policiesHash ? "ok" : "mismatch";
}

/**
 * Which of `mustExist` is not in what the agent observed.
 *
 * Empty means every expected object is present. A null `observed` returns the whole expected list:
 * the agent could not read the cluster back, so nothing is confirmed present, and treating unknown
 * as satisfied is how a policy that governs zero pods passes as applied.
 */
export function missingObjects(want: readonly string[], observed: readonly string[] | null): string[] {
  if (observed === null) return [...want];
  const have = new Set(observed);
  return want.filter((o) => !have.has(o));
}

/**
 * Has the table changed since this host applied?
 *
 * `reference` is the stateless-dump digest the agent reported immediately after its last
 * successful apply; `observed` is the digest now. A null reference means there is nothing to
 * compare against yet, which is not drift — `Heartbeat.applied.state` is what reports that.
 *
 * A null `observed` **is** treated as drift: it means the dump could not be read, so the host's
 * compliance is unknown, and unknown has to surface rather than pass quietly.
 */
export function hasDrifted(reference: string | null, observed: string | null): boolean {
  if (reference === null) return false;
  return observed !== reference;
}
