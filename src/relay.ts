// The relay — one per gateway. Serves artifacts to the agents behind it and collects their state.
//
// It is deliberately not a decision-maker. It does not render policy and it cannot invent a
// ruleset: it serves what the manager published and gates on what agents reported. A gateway is
// the most exposed machine in each VPC, so the blast radius of it being wrong, or owned, is kept
// to "the hosts behind it stop receiving updates" rather than "the hosts behind it get told
// anything an attacker likes".
//
// `POST /publish` does not change that. It accepts a generation rather than producing one: the bundle
// is checked against the digests its own manifest carries, and those are what the agents check too. A
// relay that wanted to serve different rules would have to produce a manifest naming them, which is
// the thing an agent reverts on. What a compromised relay can do — refuse pushes and serve a stale
// generation — it could already do by being unreachable, which is why the fleet view reports
// generations per VPC.
//
// ## Why the project runs on Node
//
// This file is the reason. **Bun cannot read the client certificate.** Bun.serve enforces
// `requestCert`/`rejectUnauthorized` — an agent without a valid certificate is refused — but
// neither Bun.serve nor Bun's `node:https` shim exposes the peer certificate to the handler, so
// there is no way to learn *which* agent is calling. Node's `req.socket.getPeerCertificate()`
// returns it.
//
// That distinction decides the security model. Without it, every heartbeat's `host` field is an
// unverified self-assertion, and any host holding a valid agent certificate could report as any
// other. The concrete attack is on the staged rollout: a compromised low-value host reports
// `{host: "h-canary", state: "confirmed"}`, the canary gate opens on a generation that was never
// actually tested, and a locking policy proceeds to the whole fleet. Binding the claimed host to
// the certificate subject is what makes staging mean anything.

import { createServer, type Server } from "node:https";
import { certificateIsRevoked } from "./certificate-revocation.ts";
import type { IncomingMessage, ServerResponse } from "node:http";
import { lstat, readFile, stat } from "node:fs/promises";
import {
  schemaSupported,
  SCHEMA_VERSION,
  type Heartbeat,
  type HeartbeatReply,
  type Manifest,
  type RulesetEvent,
  type SelectorMembership,
  type CiliumExposure,
} from "./protocol.ts";
import { agentVersionConcern, agentVersionCore, computeGate, type HostStatus } from "./rollout.ts";
import { missingObjects } from "./protocol.ts";
import {
  MAX_AUTHORIZED_ARTIFACT_BUNDLE_BYTES,
  loadAuthorizedArtifactBundle,
  validateAuthorizedArtifactBundle,
  writeAuthorizedArtifactBundle,
  type HostArtifactEnvelope,
} from "./artifact-signature.ts";
import { MAX_REVOCATION_SNAPSHOT_BYTES, parseRevocationSnapshot } from "./revocation-snapshot.ts";
import { installRevocationSnapshot, RevocationWriterUnavailable } from "./revocation-writer.ts";
import { formatOperatorEvent, formatOperatorLog } from "./operator-i18n.ts";
import type { Lang } from "./i18n.ts";
import {
  reportContradictions,
  type Contradiction,
  type Reference,
} from "./consistency.ts";

/**
 * Body limits, per route rather than one global bound.
 *
 * A heartbeat is a few kilobytes of state; a generation bundle is every host's rendered ruleset in one
 * request. Measured on dev: 6 hosts, 71 KB. One limit for both would either let an agent send
 * megabytes or refuse a legitimate publish to a larger VPC — and the second failure would arrive as
 * "the publish stopped working" on the day a VPC grew.
 */
const MAX_BODY_BYTES = 256 * 1024;
const MAX_BUNDLE_BYTES = MAX_AUTHORIZED_ARTIFACT_BUNDLE_BYTES;

/** Everything the relay knows. Held in memory — all of it is re-derivable. */
export interface RelayState {
  /** Null until the first successful load. Agents are told to wait rather than given nothing. */
  manifest: Manifest | null;
  /** Signed per-host envelopes from the same atomic snapshot as `manifest`. Never interpreted here. */
  artifacts: Record<string, HostArtifactEnvelope>;
  statuses: Record<string, HostStatus>;
  /**
   * Per host, the stateless-dump digest seen when it first confirmed its current generation.
   *
   * This is the drift reference. It is held here rather than re-read from the agent on every beat,
   * so an agent that later starts lying about its dump contradicts a value it committed to earlier
   * instead of quietly redefining what "unchanged" means.
   *
   * It is keyed by generation because a new generation legitimately changes the dump. Without
   * that, the first correct rollout after a host is enrolled would look like tampering forever.
   */
  references: Record<string, Reference>;
  lastSeen: Record<string, string>;
  /** Hosts whose current dump no longer matches their reference. */
  drifted: Set<string>;
  /**
   * Self-contradictions each host's own reporting produced (H30), keyed by host.
   *
   * Separate from `drifted` because the two answer different questions and one does not imply the
   * other. Drift is "the kernel moved while the story stayed the same"; this is "the story moved in a
   * way no honest host's story can" — a host claiming a generation it never applied alters no kernel
   * and would pass drift detection cleanly.
   *
   * Replaced per beat rather than accumulated. A contradiction is a statement about the report that
   * just arrived, and keeping old ones would mean a host that has been reinstalled and is now honest
   * carries an accusation it can never clear.
   */
  contradictions: Record<string, Contradiction[]>;
  /**
   * Latest selector membership each applier reported (H14a), keyed by host.
   *
   * Memory-only like everything else here, and re-supplied on the next beat. The manager reads it
   * when rendering, so a relay restart costs one interval of "not known" rather than a wrong answer
   * — which is the right way round: the reading carries its own `at`, and a stale one presented as
   * current is worse than an absent one.
   */
  membership: Record<string, SelectorMembership>;
}

export function emptyState(): RelayState {
  return {
    manifest: null,
    artifacts: {},
    statuses: {},
    references: {},
    lastSeen: {},
    drifted: new Set(),
    contradictions: {},
    membership: {},
  };
}

export interface HeartbeatOutcome {
  status: number;
  body: HeartbeatReply | { error: string };
}

// ── fleet status ──────────────────────────────────────────────────────────────
//
// Everything below is read-only and derived from state the relay already holds. It exists because
// the alternative was `ssh` to each host in turn and read its journal — which does not scale past a
// handful of hosts, and worse, gives no single moment at which the fleet is described consistently.
// During a staged rollout that moment is exactly what you need: which stage is open, what is still
// pending, and whether anything drifted.

/**
 * What the host reported, minus what its policy said to expect.
 *
 * Returns `null` when the host has not reported, which is different from an empty list and is kept
 * different all the way to the display. A host whose agent cannot read the kernel is a host we
 * cannot make this claim about, and rendering that as "clear" would be the same inversion the
 * field exists to prevent.
 */
function unexpectedFilters(
  st: { foreignFilters?: string[] | null } | undefined,
  entry: { expectFilters?: string[] },
): string[] | null {
  const seen = st?.foreignFilters;
  if (!seen) return null;
  const expected = new Set(entry.expectFilters ?? []);
  return seen.filter((t) => !expected.has(t));
}

export interface HostView {
  host: string;
  stage: string | null;
  /** What the host last reported. `null` when it has never been heard from. */
  state: string | null;
  generation: string | null;
  /** Whether the host is on the generation the manifest names. */
  current: boolean;
  drifted: boolean;
  lastSeen: string | null;
  /** Seconds since the last heartbeat, or null if never seen. */
  ageSec: number | null;
  /** Why this host is not applying yet, when it is being held by an earlier stage. */
  blockedBy: string | null;
  /**
   * Why this host is out of service, when a person has declared it so. Null is the normal state.
   *
   * Carried to the views because an excused host and a merely silent one look identical from the
   * outside and mean opposite things: one is accounted for, the other is the thing staged rollout
   * exists to stop on. A row that cannot say which turns a deliberate exemption into an unexplained
   * gap — and unexplained gaps are what get investigated instead of the real problem.
   */
  maintenance: string | null;
  detail: string | null;

  /**
   * Other tables filtering on this host that its policy does not account for.
   *
   * `null` means the host did not report — not "none". `[]` means it looked and everything it found
   * was expected. Anything else is a table that can override this host's rules without appearing
   * anywhere in its ruleset.
   */
  unexpectedFilters: string[] | null;

  /**
   * Ways this host's own reporting does not hold together (H30).
   *
   * Empty is the normal answer and means "checked, nothing wrong" — unlike `unexpectedFilters`, where
   * `null` had to mean "the host did not look". Here the relay does the looking, so there is nothing
   * it can fail to report.
   */
  contradictions: Contradiction[];

  /**
   * Changes to this host's table that its agent did not make (H27/H28).
   *
   * `null` means the host did not report — an older agent. `[]` means it watched and saw nothing. The
   * distinction is kept for the same reason as `unexpectedFilters`: an agent that cannot watch is not
   * an agent reporting a clean table.
   */
  intrusions: RulesetEvent[] | null;
  /** The agent build that last reported. `null` on an agent too old to send one. */
  agentVersion: string | null;

  /**
   * Ports another table redirects inbound, which this project's rules do not govern (H36).
   *
   * `null` = the host did not report; `[]` = it looked and found none.
   */
  publishedPorts: string[] | null;
  routes: import("./rollout.ts").HostStatus["routes"];

  /** eBPF service exposure, absent/null when this host cannot report it. */
  ciliumExposure: CiliumExposure | null;

  /**
   * The workload half, on the host assigned one. `null` on every other host.
   *
   * A separate field rather than a merged status, because the pair `state: confirmed` with
   * `workload.state: rolled-back` is a real and important combination — the generation landed on the
   * host and not in the cluster.
   */
  workload: {
    cluster: string;
    state: string | null;
    /** Objects the agent was told to find after applying. */
    expected: number;
    detail: string | null;
    /**
     * What this host last reported its selectors match (H14a), or `null` if it has not reported.
     *
     * Carried verbatim, `at` included, because the manager renders the next generation from it and a
     * reading without the time it was taken is one an operator will read as current. Pod membership
     * goes stale in seconds.
     */
    membership: SelectorMembership | null;
  } | null;
}

export interface FleetView {
  generation: string | null;
  issuedAt: string | null;
  hosts: HostView[];
  /** Hosts that must be looked at: rolled back, drifted, or silent. */
  problems: string[];
  /**
   * Seconds since this relay process started, or null if it was not told.
   *
   * Reported so a caller can tell "this host is gone" from "the relay was just restarted and has
   * not heard from anyone yet" — relay state is memory-only, so those look identical otherwise.
   */
  relayAgeSec: number | null;
}

/**
 * Describe the fleet as of `now`. Pure — takes the clock rather than reading it.
 *
 * A host in the manifest that has never reported is included with `state: null` rather than omitted.
 * Omitting it would make a host that never enrolled indistinguishable from one that does not exist,
 * and the first is a problem while the second is not.
 */
export function fleetView(
  state: RelayState,
  now: Date,
  staleAfterSec = 90,
  /**
   * When this relay process started. Hosts unheard-of are reported as `unknown` rather than
   * `never reported` until this much time has passed.
   *
   * Relay state is memory-only and re-derived from heartbeats, so a restart empties it. Measured:
   * immediately after `systemctl restart heliopause-relay`, two of three healthy hosts showed
   * "has never reported" — they had each reported seconds earlier and were still active. For a tool
   * whose whole job is to say what is wrong, being unable to distinguish "this host is gone" from
   * "I just restarted" is the worst available failure: the alarm fires on a non-event, and an alarm
   * that does that gets ignored on the day it is real.
   */
  startedAt?: Date,
  /**
   * The oldest agent build this deployment wants to be running, as `[major, minor, patch]`.
   *
   * Unset means the question is not asked, which is what it was until 2026-08-22 — `agentVersion`
   * arrived in every heartbeat, was stored, was rendered as a column, and nothing ever compared it.
   * A half-upgraded fleet produced no sentence anywhere, because every host still speaks the current
   * schema and confirms normally.
   *
   * Reported, never gated: see `agentVersionConcern`.
   */
  minAgentVersion?: readonly [number, number, number],
): FleetView {
  const m = state.manifest;
  const hosts: HostView[] = [];
  const problems: string[] = [];

  for (const [host, entry] of Object.entries(m?.hosts ?? {})) {
    const st = state.statuses[host];
    const seen = state.lastSeen[host] ?? null;
    const ageSec = seen ? Math.round((now.getTime() - new Date(seen).getTime()) / 1000) : null;
    const gate = m ? computeGate(m, host, state.statuses) : { open: false, reason: "no manifest", stage: null };
    const drifted = state.drifted.has(host);
    const current = st?.generation === m?.generation;

    hosts.push({
      host,
      stage: entry.stage,
      state: st?.state ?? null,
      generation: st?.generation ?? null,
      current,
      drifted,
      lastSeen: seen,
      ageSec,
      // Only meaningful while the host has not yet applied; a confirmed host is not "blocked".
      blockedBy: !current && !gate.open ? (gate.reason ?? null) : null,
      maintenance: entry.maintenance ?? null,
      detail: st?.detail ?? null,
      unexpectedFilters: unexpectedFilters(st, entry),
      contradictions: state.contradictions[host] ?? [],
      intrusions: st?.intrusions ?? null,
      agentVersion: st?.agentVersion ?? null,
      publishedPorts: st?.publishedPorts ?? null,
      routes: st?.routes ?? null,
      ciliumExposure: st?.ciliumExposure ?? null,
      workload: entry.workload
        ? {
            cluster: entry.workload.cluster,
            state: st?.workloadState ?? null,
            expected: entry.workload.mustExist.length,
            detail: st?.workloadDetail ?? null,
            membership: state.membership[host] ?? null,
          }
        : null,
    });

    if (st?.state === "rolled-back") problems.push(`${host}: rolled back — ${st.detail ?? "see its journal"}`);
    if (drifted) problems.push(`${host}: ruleset no longer matches the dump it confirmed`);
    // Next to drift on purpose: drift is the consequence (the dump changed), this is the cause (who
    // changed it, when, from which process). A host showing both is one story, and reading them
    // together is what turns "something moved" into "this moved it".
    //
    // The count and the most recent line, not the whole buffer. A flood is itself the signal and
    // pasting fifty raw `nft monitor` lines into a fleet view would bury every other problem on the
    // page — the detail is in the host's journal and in the JSON view.
    // Stated as the limit it is, not as a fault. The rules are correct and simply not consulted — an
    // operator reading "confirmed" needs to know that this port is outside what that word covers.
    const pub = st?.publishedPorts;
    if (pub && pub.length) {
      problems.push(
        `${host}: ${pub.length} port(s) are published by another table and bypass this ruleset ` +
          `(DNAT on prerouting, before any input hook): ${pub.slice(0, 3).join("; ")}` +
          `${pub.length > 3 ? ` (+${pub.length - 3} more)` : ""}`,
      );
    }
    const cilium = st?.ciliumExposure;
    const protectedSelectors =
      current && st?.workloadState === "confirmed" &&
      st.workloadPoliciesHash === entry.workload?.policiesHash
        ? (entry.workload?.ingressProtectedSelectors ?? [])
        : [];
    const unprotectedCilium = cilium?.services.filter((service) => {
      const peer = /\s([a-z0-9-]+)\/([a-z0-9-]+)$/.exec(service);
      if (!peer) return true;
      const namespace = peer[1]!;
      const name = peer[2]!;
      return !protectedSelectors.some((selector) => {
        if (selector["k8s:io.kubernetes.pod.namespace"] !== namespace) return false;
        const app = selector.app;
        return typeof app === "string" && (name === app || name.startsWith(`${app}-`));
      });
    }) ?? [];
    if (cilium && cilium.nodePortAddresses.length === 0 && unprotectedCilium.length) {
      problems.push(
        `${host}: Cilium nodeport-addresses is unrestricted; ${unprotectedCilium.length} eBPF ` +
          `HostPort/NodePort frontend(s) bypass this nftables ruleset: ` +
          `${unprotectedCilium.slice(0, 3).join("; ")}` +
          `${unprotectedCilium.length > 3 ? ` (+${unprotectedCilium.length - 3} more)` : ""}`,
      );
    }
    const intr = st?.intrusions;
    if (intr && intr.length) {
      const last = intr[intr.length - 1]!;
      problems.push(
        `${host}: ${intr.length} change(s) to its ruleset were not made by the agent — ` +
          `latest ${last.at} pid=${last.pid ?? "?"} (${last.process ?? "unknown"}): ${last.raw.slice(0, 120)}`,
      );
    }
    // Graded, because a console that calls everything an emergency gets read as noise — and then the
    // certain ones are missed too. `certain` means no honest host produces this.
    for (const c of state.contradictions[host] ?? []) {
      problems.push(
        c.certainty === "certain"
          ? `${host}: reporting contradicts itself — ${c.detail}`
          : `${host}: reporting is unexplained — ${c.detail}`,
      );
    }
    // Phrased as the consequence, not the observation. "inet firewalld is present" is a fact about a
    // table; what an operator has to act on is that this host's confirmed ruleset is not the thing
    // deciding. Measured 2026-08-02: five hosts confirmed, the kernel matched, and every newly
    // declared port was still refused by a table nothing reported.
    const unexpected = unexpectedFilters(st, entry);
    if (unexpected?.length) {
      problems.push(
        `${host}: ${unexpected.join(", ")} also filters here — this host's confirmed rules are ` +
          `not the only thing deciding`,
      );
    }
    // The workload half is called out separately, and specifically for the case where the host half is
    // fine. That combination leaves every other field on this row reading as success while the
    // cluster-scoped policies — the ones with no host-layer rule behind them — are not in place.
    if (entry.workload && st && st.generation === m?.generation) {
      const ws = st.workloadState;
      if (ws === undefined || ws === null) {
        problems.push(`${host}: applied its ruleset but has not reported the workload half`);
      } else if (ws !== "confirmed") {
        problems.push(
          `${host}: workload half is ${ws} on cluster ${entry.workload.cluster}` +
            `${st.workloadDetail ? ` — ${st.workloadDetail}` : ""}`,
        );
      } else {
        // ## H16 — confirmed is a claim, and here it can be checked against the cluster
        //
        // The three checks above ask what the applier *said*. These ask whether what it said holds up
        // against what it also reported observing. That distinction is the whole of H16: intent versus
        // the state an agent read back.
        //
        // Both were impossible until now, because the relay stored `workloadState` and threw away the
        // rest of the workload report. `missingObjects()` was written for exactly this comparison and
        // had **zero callers** — the data it needed was discarded one line after arriving.
        // `?? null` converts `undefined` (no field) to `null` (could not read). Note that
        // `missingObjects` returns the whole expected list for **both** `null` and `[]` — measured, and
        // it means the distinction is not carried by this call. What carries it is the sentence below:
        // "could not read the cluster back" versus a plain missing-object list. Those send an operator
        // to different places — one is a broken applier, the other is a policy that did not land.
        const missing = missingObjects(entry.workload.mustExist, st.workloadObserved ?? null);
        if (missing.length) {
          problems.push(
            `${host}: workload half reports confirmed but ${missing.length} object(s) are not in ` +
              `cluster ${entry.workload.cluster}: ${missing.slice(0, 4).join(", ")}` +
              `${missing.length > 4 ? ` (+${missing.length - 4} more)` : ""}` +
              `${st.workloadObserved === null ? " — the applier could not read the cluster back" : ""}`,
          );
        }
        // The workload equivalent of `artifactMatches`. A digest mismatch means it applied *something*,
        // and not the document this generation published — the same class of finding as H30's
        // `artifact-hash-wrong`, on the other layer.
        if (
          st.workloadPoliciesHash != null &&
          st.workloadPoliciesHash !== entry.workload.policiesHash
        ) {
          problems.push(
            `${host}: workload half confirmed document ${st.workloadPoliciesHash.slice(0, 20)} but the ` +
              `manifest publishes ${entry.workload.policiesHash.slice(0, 20)} — it applied something else`,
          );
        }
      }
    }
    // The agent build, finally read. It has been carried to this view since 2026-08-07 and compared
    // against nothing — `MIN_AGENT_SCHEMA` stops a rollout at a host that speaks the wrong schema,
    // and there was no equivalent sentence for a host that speaks the right one from an old build.
    const behind = agentVersionConcern(st, minAgentVersion);
    if (behind) problems.push(`${host}: ${behind}`);

    // ## A break-glass authorization nobody wound back
    //
    // `break-glass` is the mode that skips the two-person rule. It is meant to be a moment, and the
    // only place its duration is visible is the host enforcing it — the manager does not keep a
    // record of authorizations it issued, by design (`approval.ts` deletes a plan the moment it is
    // published, because an approval that outlives its publish is a standing permission).
    //
    // So this is the one sentence in the system that can say a break-glass is *still on*. Reported
    // rather than gated: the host is enforcing a validly signed ruleset and cutting it off would be
    // the relay acting on a policy judgement.
    if (st?.artifactTrust?.currentAuthorizationMode === "break-glass") {
      const at = st.artifactTrust.currentAuthorizedAt;
      problems.push(
        `${host}: enforcing a break-glass authorization${at ? ` from ${at}` : ""} — that mode skips ` +
          `the two-person rule, and nothing else in this system reports that it is still in force`,
      );
    }

    // Silence is its own failure. A host that stopped heartbeating is not applying policy and is
    // not reporting drift either, so it looks healthy in every other field.
    //
    // But silence has two causes, and only one is the host's. Within `staleAfterSec` of this relay
    // starting, "no heartbeat yet" is the expected state for every host — they beat on their own
    // schedule and this process has no memory of the ones before it. Reporting that as a problem
    // makes every relay restart look like a fleet-wide outage.
    if (ageSec === null) {
      const relayAgeSec = startedAt ? (now.getTime() - startedAt.getTime()) / 1000 : Infinity;
      if (relayAgeSec > staleAfterSec) problems.push(`${host}: has never reported`);
    } else if (ageSec > staleAfterSec) {
      problems.push(`${host}: silent for ${ageSec}s`);
    }
  }

  // ## Do these hosts agree about which keys may sign a ruleset?
  //
  // A cross-host question, so it is here and not in the loop above. Each host reports a digest of the
  // manager and break-glass keys it will accept; every host in one generation should hold the same
  // ring, and only the hosts know whether they do.
  //
  // **What this catches is a rotation that did not land everywhere.** The published procedure is
  // add-then-remove — the new public key reaches every agent's ring, then the manager switches, then
  // the old one is dropped — and each step is a file on N machines. Nothing else in this system can
  // say whether step one actually finished, so "the new signing key is deployed" was an assumption
  // about a file rather than an observation of the fleet.
  //
  // Reported, never gated, and phrased as a state rather than a fault: **mid-rotation this is the
  // expected reading**, and it is supposed to be visible while it lasts. A relay that refused to
  // serve a disagreeing host would turn the safe half of the procedure into an outage.
  //
  // Hosts that have not reported one are left out rather than counted as a third answer — an agent
  // too old to send it is not a host that disagrees.
  const digests = new Map<string, string[]>();
  for (const [host, entry] of Object.entries(m?.hosts ?? {})) {
    void entry;
    const digest = state.statuses[host]?.artifactTrust?.trustDigest;
    if (!digest) continue;
    const at = digests.get(digest) ?? [];
    at.push(host);
    digests.set(digest, at);
  }
  if (digests.size > 1) {
    // Largest group first, so the sentence reads as "these are the odd ones out" rather than as an
    // arbitrary listing. Ties are broken by digest so the same fleet always produces the same line.
    const groups = [...digests.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
    problems.push(
      `the fleet does not agree on which keys may sign a ruleset — ` +
        groups.map(([digest, hs]) => `${digest.slice(0, 19)}: ${hs.sort().join(", ")}`).join(" · ") +
        ` — expected during a key rotation and a finding after one`,
    );
  }

  return {
    generation: m?.generation ?? null,
    issuedAt: m?.issuedAt ?? null,
    hosts,
    problems,
    relayAgeSec: startedAt ? Math.round((now.getTime() - startedAt.getTime()) / 1000) : null,
  };
}

/**
 * Handle one heartbeat. Pure apart from mutating `state` — no I/O, no clock.
 *
 * `certCN` is the subject common name from the verified client certificate. TLS has already
 * established that the peer holds the matching key and that our anchor vouches for it; what is
 * left is checking that the name it claims in the payload is the name it authenticated as.
 */
export function handleHeartbeat(
  state: RelayState,
  certCN: string | null,
  hb: Heartbeat,
  at: string,
): HeartbeatOutcome {
  if (!certCN) {
    return { status: 401, body: { error: "client certificate carries no subject CN" } };
  }
  if (hb.host !== certCN) {
    // Refuse rather than silently rewriting `host` to the CN. An agent whose identity and payload
    // disagree is either misconfigured or lying, and both are worth surfacing loudly — quietly
    // correcting it would hide the only evidence that someone tried.
    return {
      status: 403,
      body: { error: `heartbeat claims host "${hb.host}" but certificate is "${certCN}"` },
    };
  }

  // ## A host outside this generation is answered, but not remembered
  //
  // The CN check above settles "is this host who it claims to be". It does not settle "does this
  // host belong here", and nothing else did: measured 2026-08-12, a `gw-01.prod` certificate beating
  // at the dev relay was answered `200` and written into `statuses` and `lastSeen`. It never showed
  // up anywhere — `fleetView` and `computeGate` both iterate the manifest — so the entry
  // accumulated, unread and unbounded.
  //
  // **Gating was never reachable from here**, and that is worth stating rather than assuming: a host
  // cannot claim a *peer's* name, because the CN check refuses it, and the gate reads only hosts the
  // manifest names. Measured both. What this closes is the relay's own bookkeeping.
  //
  // What has kept it from mattering is the PKI shape, not this file: each VPC has its own CA, so a
  // prod certificate never completes the dev relay's handshake. That is a real defence living in the
  // deployment rather than in the program — consolidating the CAs, which is under discussion, would
  // remove it without changing a line here.
  //
  // **Answered, not refused.** `rollout.ts` treats a host outside the generation as a legitimate
  // state — "decommissioned, or simply not covered by any policy yet" — and returns "nothing for
  // you". Refusing the heartbeat would cut off a host mid-decommission, which is a working host
  // losing its relay connection over a bookkeeping decision. It gets the same reply it always did;
  // the relay simply does not file it.
  //
  // Before the first manifest loads there is nothing to compare against, so everything is recorded.
  // That window is a relay restart, when refusing to remember would blind the fleet view for one
  // interval — "cannot say yet" is not "does not belong".
  if (state.manifest && !state.manifest.hosts[certCN]) {
    // The same answer `computeGate` gives for this case, so the two cannot drift into disagreeing
    // about what a host outside the generation is told.
    return {
      status: 200,
      body: {
        generation: null,
        gate: computeGate(state.manifest, certCN, state.statuses),
        schemaVersion: SCHEMA_VERSION,
      },
    };
  }

  state.lastSeen[certCN] = at;
  state.statuses[certCN] = {
    generation: hb.applied.generation,
    // Kept so a host-unit deployment can be verified from the server rather than from the
    // machine that ran the installer. See `HostStatus.agentVersion`.
    agentVersion: hb.agentVersion ?? null,
    state: hb.applied.state,
    // Carried, not acted on. Gating reads `state` only; this is the host's explanation, and without
    // it a rolled-back host shows up in the fleet view with no reason attached.
    detail: hb.applied.detail ?? null,
    // The workload half is recorded whenever the host reports it, and gating decides on its own
    // whether this host was assigned one — the relay stores what it was told rather than judging it.
    workloadState: hb.workload?.state ?? null,
    workloadDetail: hb.workload?.detail ?? null,
    // Kept rather than discarded (H16). These two are what make it possible to contradict an applier
    // that reports `confirmed` while an object is missing from the cluster — see
    // `HostStatus.workloadObserved`. `?? null` on both: a host that reported no workload half at all and
    // one that could not read the cluster back are the same to this field, and both differ from `[]`.
    workloadObserved: hb.workload?.observed ?? null,
    workloadPoliciesHash: hb.workload?.policiesHash ?? null,
    // `?? null` and not `?? []`. An agent that omits the key has not looked; an agent that sends an
    // empty array has looked and found nothing. See `Heartbeat.foreignFilters`.
    foreignFilters: hb.foreignFilters ?? null,
    // Same `?? null` contract, and for the same reason: an agent that omits the key has not
    // looked, and a host whose routes could not be read must not read as a host with none.
    routes: hb.routes ?? null,
    publishedPorts: hb.publishedPorts ?? null,
    ciliumExposure: hb.ciliumExposure ?? null,
    // Which keys this host will accept a ruleset from, and what it is enforcing. Same `?? null`
    // contract as its neighbours — an agent too old to send it and one that sent it empty are
    // different things. `fleetView` reads two of its fields; see `HostStatus.artifactTrust` for
    // which, and for why the other two are carried and not compared.
    artifactTrust: hb.artifactTrust ?? null,
    // Changes to **our** table that the agent does not claim as its own.
    //
    // ## Both halves of the filter are needed, and I checked rather than assumed
    //
    // The first version dropped the table check on the reasoning that the agent must already have
    // applied it. **It does not.** `_record_event` tags every monitored change as either the agent's own
    // table or the literal string `"other"` (`heliopause-pull.py`), and sends both — the agent's
    // `unauthorised_events()` filter is applied only for its *log line*, not for what it transmits.
    // Without the table check here, a `podman` or `firewalld` change on the same host would be reported
    // as tampering with this ruleset.
    //
    // The relay still does not learn which table is ours. It compares against the tag the agent
    // assigned, which is a name the agent chose — so this stays a statement about what the host said,
    // not an interpretation of an artifact the relay is deliberately unable to read.
    //
    // ## What `byAgent` is worth
    //
    // A claim, not a fact. A compromised agent can set it true on its own tampering, or send no events
    // at all, and nothing on this side can tell. That is not what this catches. It catches the case the
    // agent is honest about: another tool, a person at a shell, a package's post-install hook — which is
    // why `nft monitor` was added. Catching a *lying* agent is the dump digest's job (drift, and H30).
    intrusions: hb.events ? hb.events.filter((e) => e.table !== "other" && !e.byAgent) : null,
  };

  // Kept so the manager can read it back when rendering the next generation (H14a). Held rather than
  // merged: a host that reports nothing this beat must not silently keep an older reading alive
  // under a fresh timestamp, because the timestamp is what tells an operator whether to trust it.
  if (hb.membership) state.membership[certCN] = hb.membership;

  // H30, and it must run **before** the reference below is rebound. Every check in it compares this
  // beat against what the host said last time, so overwriting the baseline first would leave it
  // comparing the new report to itself — a contradiction detector that can never find one.
  //
  // Stored, never gated on. A finding is a claim about a host's honesty, and refusing to serve a host
  // on suspicion is how a false positive becomes an outage. The relay's whole intervention is saying
  // so: the fleet view carries it, and the route handler logs it (this function stays pure, so it does
  // not log — same reason `handleHeartbeat` takes `at` instead of reading a clock).
  //
  // Replaced rather than accumulated, including the empty case: a host that was reinstalled and is now
  // reporting honestly must be able to clear the accusation.
  const found = reportContradictions(hb, state.references[certCN], state.manifest);
  if (found.length) state.contradictions[certCN] = found;
  else delete state.contradictions[certCN];

  // Record the drift reference the first time a host confirms a generation, and compare against it
  // on every beat after. Rebinding it on each confirm is what makes a legitimate apply reset the
  // baseline without also letting an unconfirmed host redefine it.
  if (hb.applied.state === "confirmed") {
    const observed = hb.applied.observedHash;
    const reference = state.references[certCN];
    if (observed === null) {
      // "I cannot dump my own table" is not a baseline, and it is not drift either — it is a host
      // that has lost its ruleset, which the generation reply above handles by telling it to
      // re-apply. Recording null here poisoned the reference permanently: measured on mailer-01
      // after a reboot, the absent-table beats set `hash: null`, and once the table was correctly
      // restored every later beat read as drift against that null forever. A drift alarm that stays
      // on after the problem is fixed is one that gets ignored.
      //
      // Neither set nor cleared: whatever was known before this outage stands until the host
      // confirms an actual dump again.
    } else if (!reference || reference.generation !== hb.applied.generation || reference.hash === null) {
      // First confirmation of this generation on this host — or the first real dump after an
      // outage left no usable reference. Whatever the kernel holds now becomes the baseline.
      // `artifactHash` is recorded alongside the dump digest, and it is what H30 needs: without it
      // "new generation, same rules" (normal, measured eight times on 2026-08-03) and "new rules,
      // unchanged kernel" (not normal) are indistinguishable. Omitting it left
      // `artifact-hash-changed` unable to fire at all — the relay's own integration test caught that,
      // and the pure unit tests could not, because they are handed a reference rather than building one.
      state.references[certCN] = {
        generation: hb.applied.generation,
        hash: observed,
        artifactHash: hb.applied.artifactHash,
      };
      state.drifted.delete(certCN);
    } else if (observed !== reference.hash) {
      state.drifted.add(certCN);
    } else {
      state.drifted.delete(certCN);
    }
  }

  if (!schemaSupported(hb.schemaVersion)) {
    // Tell it nothing to do, but answer with our version so the mismatch is visible on both sides
    // instead of looking like an idle fleet.
    return {
      status: 200,
      body: {
        generation: null,
        gate: {
          stage: "canary",
          open: false,
          reason: `agent speaks schema ${hb.schemaVersion}, relay speaks ${SCHEMA_VERSION}`,
        },
        schemaVersion: SCHEMA_VERSION,
      },
    };
  }

  const manifest = state.manifest;
  if (!manifest) {
    return {
      status: 200,
      body: {
        generation: null,
        gate: { stage: "canary", open: false, reason: "relay has no manifest loaded" },
        schemaVersion: SCHEMA_VERSION,
      },
    };
  }

  const gate = computeGate(manifest, certCN, state.statuses);

  // "Up to date" means confirmed **and** still holding the ruleset. Those are two facts, and this
  // used to check only the first.
  //
  // A confirmed host is told `generation: null` — nothing to do — which is right in the normal case
  // and stops the fleet re-applying on every beat. But an nftables table lives in kernel memory:
  // a reboot destroys it while the agent's state file still says `confirmed`. The agent then has
  // the information needed to notice (its own dump is empty) and no instruction to act on, because
  // the relay withheld the generation. Measured on mailer-01 after a reboot: the host held only
  // `table inet firewalld`, reported `confirmed`, and got `generation: null` back — so the
  // agent-side re-apply fix could not even be reached.
  //
  // `observedHash` is null exactly when the agent could not dump its own table. Treating that as
  // "not up to date" hands back the generation, and the agent re-applies the artifact it already
  // confirmed — restoring the state it is supposed to be in rather than changing anything.
  const holdsRuleset = hb.applied.observedHash !== null;
  const upToDate =
    hb.applied.generation === manifest.generation &&
    hb.applied.state === "confirmed" &&
    holdsRuleset;

  return {
    status: 200,
    body: {
      generation: upToDate || !manifest.hosts[certCN] ? null : manifest.generation,
      gate,
      schemaVersion: SCHEMA_VERSION,
    },
  };
}

// ── Artifact store ────────────────────────────────────────────────────────────

/**
 * Load the published manifest.
 *
 * A single current manifest is enough — an agent only ever applies the current generation, and
 * rollback restores that host's own previous kernel state rather than an older artifact. Keeping
 * a history here would imply the relay could serve an old generation, which is a capability
 * nothing needs and an attacker would enjoy.
 */
export async function loadManifest(artifactDir: string): Promise<Manifest> {
  const manifest = (await loadAuthorizedArtifactBundle(artifactDir)).manifest;
  if (!schemaSupported(manifest.schemaVersion)) {
    throw new Error(
      `manifest schema ${manifest.schemaVersion} is not ${SCHEMA_VERSION} — refusing to serve it`,
    );
  }
  if (!manifest.generation || typeof manifest.hosts !== "object" || manifest.hosts === null) {
    throw new Error("manifest is missing generation or hosts");
  }
  return manifest;
}

// ── Server ────────────────────────────────────────────────────────────────────

export interface RelayOptions {
  artifactDir: string;
  port: number;
  hostname?: string;
  tls: { certFile: string; keyFile: string; caFile: string };
  /** JSON enrollment/denylist file, reloaded for every request so revocation is immediate. */
  revocationFile?: string;
  /** Privilege-separated monotonic writer socket. Required whenever revocationFile is configured. */
  revocationWriterSocket?: string;
  /**
   * Certificate CNs allowed to read `/status`, matched exactly.
   *
   * Empty by default, which disables the endpoint entirely rather than opening it. A read-only view
   * of the whole fleet is not harmless: it names every host, its generation, and whether its
   * ruleset has drifted. Defaulting to "any valid certificate" would mean one compromised agent
   * yields a target list, so this has to be named deliberately.
   */
  operatorCNs?: readonly string[];
  /**
   * CNs allowed to push a generation to this relay via `POST /publish`, matched exactly.
   *
   * ## Why this is not `operatorCNs`
   *
   * Reading the fleet and changing the firewall are different powers, and the second is strictly
   * larger. Every operator certificate that exists today can read `/status`; if that same list could
   * write, then issuing a read-only credential — for a dashboard, for a colleague who needs to see
   * without touching — would silently hand out publish rights. So the write list is its own, and
   * empty by default, which disables the endpoint rather than opening it.
   *
   * ## Why the relay accepts a push at all
   *
   * It did not before: artifacts arrived by writing to `artifactDir` on the gateway, which means
   * publishing required shell access to every gateway in the site. That is a reasonable place to
   * start and a bad place to stay — it makes the approval rule from
   * docs/인터페이스-설계.md 결정 4 unenforceable, because anyone who can write the directory has
   * bypassed it entirely.
   *
   * **The filesystem path stays.** It is 결정 5's second escape hatch: if the manager is broken and
   * fixing it requires a firewall change, an operator with shell access on the gateway can still
   * publish. This endpoint is the ordinary path, not the only one.
   */
  publisherCNs?: readonly string[];
  /** Overridable for tests. */
  now?: () => Date;
  log?: (msg: string) => void;
  /** Deployment-wide journal language; never derived from an individual request. */
  logLang?: Lang;
  /**
   * Oldest agent build this VPC wants to be running, as `"0.6.0"`. Unset asks nothing.
   *
   * A string here rather than a tuple because it comes from the environment, and `"0.6.0"` is what an
   * operator writes. Parsed once at startup so a malformed value fails where somebody is watching
   * rather than being silently ignored on every poll.
   */
  minAgentVersion?: string;
}

/**
 * The client certificate's subject CN, or null if the peer is not authenticated.
 *
 * Exported so the manager uses the same identity logic rather than a second copy. Two
 * implementations of "who is calling" is two things to keep in agreement, and the consequence of
 * them disagreeing is an authorisation check that passes in one server and fails in the other.
 */
export function peerCN(req: IncomingMessage): string | null {
  const socket = req.socket as unknown as {
    authorized?: boolean;
    getPeerCertificate?: () => { subject?: { CN?: string } } | null;
  };
  if (!socket.authorized) return null;
  const cert = socket.getPeerCertificate?.();
  return cert?.subject?.CN ?? null;
}

async function readBody(req: IncomingMessage, limit = MAX_BODY_BYTES): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    // Bounded before buffering, not after. An unbounded read here is a gateway with under a
    // gigabyte of RAM being OOM-killed by one oversized POST, taking its whole VPC's updates down.
    if (size > limit) throw new Error("request body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function startRelay(
  opts: RelayOptions,
): Promise<{ server: Server; state: RelayState; reload: () => Promise<void> }> {
  const writeLog = opts.log ?? ((m: string) => console.error(`[relay] ${m}`));
  const logEvent = (key: Parameters<typeof formatOperatorLog>[1], params: Record<string, string | number> = {}) =>
    writeLog(`[relay] ${formatOperatorLog(opts.logLang ?? "en", key, params)}`);
  const log = (en: string, ko: string) => writeLog(`[relay] ${formatOperatorEvent(opts.logLang ?? "en", { en, ko })}`);
  const now = opts.now ?? (() => new Date());
  const state = emptyState();
  const operators = new Set(opts.operatorCNs ?? []);
  const publishers = new Set(opts.publisherCNs ?? []);
  let publishTail: Promise<void> = Promise.resolve();
  const serializePublish = async <T>(operation: () => Promise<T>): Promise<T> => {
    const before = publishTail;
    let release!: () => void;
    publishTail = new Promise<void>((resolve) => { release = resolve; });
    await before;
    try { return await operation(); } finally { release(); }
  };
  // Captured before anything is served. Relay state is memory-only, so within the first stale
  // window every host legitimately has no heartbeat on record — see fleetView's `startedAt`.
  const startedAt = now();
  // Parsed once, at startup. A floor nobody can read is a check that silently never runs, so a bad
  // value stops the relay here instead of being discarded on every `/status`.
  let minAgentVersion: [number, number, number] | undefined;
  if (opts.minAgentVersion) {
    const parsed = agentVersionCore(opts.minAgentVersion);
    if (!parsed) throw new Error(`minAgentVersion ${JSON.stringify(opts.minAgentVersion)} is not major.minor.patch`);
    minAgentVersion = parsed;
  }

  const reload = async () => {
    try {
      const loaded = await loadAuthorizedArtifactBundle(opts.artifactDir);
      // Only announce an actual change. The poll runs every few seconds, and logging each pass
      // buries the lines that matter — a rejected heartbeat, a drifted host — under a repeating
      // message that says nothing happened.
      if (loaded.manifest.generation !== state.manifest?.generation) {
        logEvent("server.manifestLoaded", { generation: loaded.manifest.generation });
      }
      // One assignment boundary for the pair: an agent can never receive an envelope from a
      // different on-disk snapshot than the manifest the rollout gate is using.
      state.manifest = loaded.manifest;
      state.artifacts = loaded.artifacts;
    } catch (e) {
      // Keep serving the manifest already in memory. A bad publish should stall the rollout, not
      // strand every agent behind this gateway with no answer at all.
      logEvent("server.manifestReloadFailed", { error: (e as Error).message });
    }
  };
  await reload();

  // Missing is not equivalent to "no revoked certificates". In particular, recreating an empty
  // file here would turn deletion + restart into an un-revoke. Provision a new relay explicitly
  // with `initializeRevocationSnapshot`; after that, absence or malformed state prevents startup.
  if (opts.revocationFile) {
    try {
      if ((await stat(opts.revocationFile)).size > MAX_REVOCATION_SNAPSHOT_BYTES) throw new Error("snapshot is oversized");
      const encoded = await readFile(opts.revocationFile);
      if (encoded.length > MAX_REVOCATION_SNAPSHOT_BYTES) throw new Error("snapshot is oversized");
      parseRevocationSnapshot(JSON.parse(encoded.toString("utf8")));
    } catch (error) {
      throw new Error(`configured revocation denylist is unavailable or invalid: ${(error as Error).message}`);
    }
    if (!opts.revocationWriterSocket) throw new Error("configured revocation denylist requires a writer socket");
    try {
      if (!(await lstat(opts.revocationWriterSocket)).isSocket()) throw new Error("not a Unix socket");
    } catch (error) {
      throw new Error(`configured revocation writer is unavailable: ${(error as Error).message}`);
    }
  }

  const [cert, key, ca] = await Promise.all([
    readFile(opts.tls.certFile),
    readFile(opts.tls.keyFile),
    readFile(opts.tls.caFile),
  ]);

  const server = createServer(
    { cert, key, ca, requestCert: true, rejectUnauthorized: true },
    (req: IncomingMessage, res: ServerResponse) => {
      void handle(req, res).catch((e) => {
        logEvent("server.unhandled", { error: (e as Error).message });
        if (!res.headersSent) res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "internal error" }));
      });
    },
  );

  async function handle(req: IncomingMessage, res: ServerResponse) {
    const cn = peerCN(req);
    const url = new URL(req.url ?? "/", "https://relay.invalid");

    if (url.pathname !== "/healthz" && certificateIsRevoked(opts.revocationFile, req, "snapshot")) {
      log(`request REFUSED for ${cn ?? "unknown"}: certificate fingerprint is revoked`, `요청 거부: ${cn ?? "알 수 없음"}의 인증서 지문이 폐기됨`);
      return send(res, 401, { error: "client certificate has been revoked" });
    }

    if (req.method === "POST" && url.pathname === "/heartbeat") {
      let hb: Heartbeat;
      try {
        hb = JSON.parse(await readBody(req)) as Heartbeat;
      } catch (e) {
        return send(res, 400, { error: `bad request body: ${(e as Error).message}` });
      }
      const outcome = handleHeartbeat(state, cn, hb, now().toISOString());
      if (outcome.status !== 200) {
        log(`heartbeat rejected from ${cn}: ${JSON.stringify(outcome.body)}`, `${cn}의 하트비트를 거부함: ${JSON.stringify(outcome.body)}`);
      }
      if (cn && state.drifted.has(cn)) {
        log(`DRIFT: ${cn} no longer matches the dump it confirmed`, `드리프트: ${cn}이(가) 확인한 덤프와 더 이상 일치하지 않음`);
      }
      return send(res, outcome.status, outcome.body);
    }

    if (req.method === "GET" && url.pathname === "/artifact") {
      if (!cn) return send(res, 401, { error: "client certificate carries no subject CN" });
      const entry = state.manifest?.hosts[cn];
      if (!entry) return send(res, 404, { error: `no artifact for ${cn} at this generation` });
      const envelope = state.artifacts[cn];
      if (!envelope) {
        log(`authorized artifact missing for manifest host ${cn}`, `매니페스트 호스트 ${cn}의 승인된 아티팩트가 없음`);
        return send(res, 500, { error: "artifact unavailable" });
      }
      // Opaque courier: no field is rebuilt from the relay's manifest and no relay-supplied digest
      // can become applyable. The agent verifies and decodes these exact manager-signed bytes.
      return send(res, 200, envelope);
    }

    // Receive a generation. **The only route that changes what this relay serves.**
    //
    // ## Why the relay still cannot interpret what it is given
    //
    // The whole design rests on the relay being unable to invent a ruleset, and that property has to
    // survive this endpoint. It does, because nothing here renders: the bundle is checked for internal
    // consistency and written, and the digests it is checked against are the manifest's own. A relay
    // that wanted to serve different rules would have to produce a bundle whose manifest names them —
    // which is exactly the thing an agent then checks against `rulesetHash` and, one level up, the
    // thing the manager holds an approval for.
    //
    // What this does add is that a compromised gateway can serve a *stale* generation by refusing
    // pushes. It could already do that by not being reachable, so no new capability arrives here — and
    // the fleet view reports generations per VPC precisely so a relay left behind is visible.
    //
    // ## Why the write is not gated on the manifest being newer
    //
    // Deliberately absent. Publishing an older generation is how a rollback of policy works: the
    // operator renders the previous commit and pushes it. A monotonicity check would make the relay
    // refuse the way back, which is the one thing 결정 5 says must never be gated.
    if (req.method === "POST" && url.pathname === "/publish") {
      if (!cn) return send(res, 401, { error: "client certificate carries no subject CN" });
      if (!publishers.has(cn)) {
        // Logged at the relay, because this is an attempt to change a firewall by an identity that is
        // authenticated but not authorised — the single most interesting line in this journal.
        log(`publish REFUSED for ${cn}: not a publisher`, `발행 거부: ${cn}은(는) 발행자가 아님`);
        return send(res, 403, { error: "this certificate is not authorised to publish generations" });
      }
      let bundle;
      try {
        bundle = validateAuthorizedArtifactBundle(JSON.parse(await readBody(req, MAX_BUNDLE_BYTES)));
      } catch (e) {
        // The message is the validator's own and is written for whoever is publishing: it names the
        // host and the digest that disagreed, which is what distinguishes a bad render from a
        // truncated upload.
        log(`publish from ${cn} rejected: ${(e as Error).message}`, `${cn}의 발행을 거부함: ${(e as Error).message}`);
        return send(res, 400, { error: (e as Error).message });
      }
      return serializePublish(async () => {
        try {
          await writeAuthorizedArtifactBundle(opts.artifactDir, bundle);
          // Reloaded while the publish lock is held. Each response therefore describes its own
          // activation rather than whichever concurrent request happened to win the last rename.
          await reload();
        } catch (e) {
          log(`publish from ${cn} could not be written: ${(e as Error).message}`, `${cn}의 발행을 쓸 수 없음: ${(e as Error).message}`);
          return send(res, 500, { error: "could not write the generation" });
        }
        log(`published generation ${bundle.manifest.generation} by ${cn} (${Object.keys(bundle.manifest.hosts).length} hosts)`, `${cn}이(가) 세대 ${bundle.manifest.generation}을(를) 발행함 (${Object.keys(bundle.manifest.hosts).length}개 호스트)`);
        return send(res, 200, {
          generation: bundle.manifest.generation,
          hosts: Object.keys(bundle.manifest.hosts).sort(),
          serving: state.manifest?.generation ?? null,
        });
      });
    }

    // Manager가 배포하는 최소 denylist. enrollment token·CSR·감사 원문은 gateway로
    // 복제하지 않는다. publisher CN만 쓸 수 있고 파일은 원자 교체되어 요청 중간에
    // certificateIsRevoked가 깨진 JSON을 읽지 않는다. Updates are monotonic: a publisher may
    // add a fingerprint but cannot roll the relay back to a snapshot that omits an existing one.
    if (req.method === "POST" && url.pathname === "/revocations") {
      if (!cn) return send(res, 401, { error: "client certificate carries no subject CN" });
      if (!publishers.has(cn)) {
        log(`revocation sync REFUSED for ${cn}: not a publisher`, `폐기 동기화 거부: ${cn}은(는) 발행자가 아님`);
        return send(res, 403, { error: "this certificate is not authorised to sync revocations" });
      }
      if (!opts.revocationFile) return send(res, 503, { error: "relay revocation file is not configured" });
      if (!opts.revocationWriterSocket) return send(res, 503, { error: "relay revocation writer is not configured" });
      try {
        const snapshot = parseRevocationSnapshot(JSON.parse(await readBody(req, MAX_REVOCATION_SNAPSHOT_BYTES)));
        const installed = await installRevocationSnapshot(opts.revocationWriterSocket, snapshot);
        const observed = parseRevocationSnapshot(JSON.parse(await readFile(opts.revocationFile, "utf8")));
        if (JSON.stringify(observed) !== JSON.stringify(snapshot) || installed.count !== snapshot.revocations.length) {
          throw new RevocationWriterUnavailable("revocation writer did not install the requested snapshot");
        }
        logEvent("server.revocationInstalled", { count: installed.count });
        return send(res, 200, { ok: true, count: installed.count });
      } catch (e) {
        if (e instanceof RevocationWriterUnavailable) {
          return send(res, 503, { error: "revocation writer is unavailable" });
        }
        return send(res, 400, { error: `invalid revocation snapshot: ${(e as Error).message}` });
      }
    }

    // Read-only fleet view, for operators. **Not reachable with an agent certificate.**
    //
    // An agent gets its own ruleset and reports its own state. This returns every host's identity,
    // generation, and whether its ruleset has drifted — which for an attacker who has taken one
    // host is a map for choosing the next one, and a list of which hosts are currently unprotected.
    // So the role is checked, not just the certificate's validity: mutual TLS proves *who* is
    // calling, and this decides whether that identity may ask.
    //
    // The allowlist is `operatorCNs`, matched exactly. There is no wildcard and no prefix rule —
    // "any CN starting with operator-" would hand the whole fleet's state to anyone who can get a
    // certificate issued with a chosen name.
    if (req.method === "GET" && url.pathname === "/status") {
      if (!cn) return send(res, 401, { error: "client certificate carries no subject CN" });
      if (!operators.has(cn)) {
        log(`status refused for ${cn}: not an operator`, `상태 조회 거부: ${cn}은(는) 운영자가 아님`);
        return send(res, 403, { error: "this certificate is not authorised to read fleet status" });
      }
      // `startedAt` is what lets the view distinguish "this host is gone" from "this relay was just
      // restarted and its state is memory-only".
      return send(res, 200, fleetView(state, now(), 90, startedAt, minAgentVersion));
    }

    // Deliberately unauthenticated and deliberately empty: it proves the listener is up without
    // telling an unauthenticated caller anything about generations, hosts or rollout state.
    if (req.method === "GET" && url.pathname === "/healthz") return send(res, 200, { ok: true });

    return send(res, 404, { error: "not found" });
  }

  await new Promise<void>((resolve) => server.listen(opts.port, opts.hostname ?? "::", resolve));
  logEvent("server.listening", { address: `${opts.hostname ?? "::"}:${opts.port}, artifacts from ${opts.artifactDir}` });
  return { server, state, reload };
}

function send(res: ServerResponse, status: number, body: unknown) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
    // Same as the manager's. Nothing here is a document, and several answers carry a host name or an
    // agent's own error text back to the caller.
    "x-content-type-options": "nosniff",
  });
  res.end(payload);
}
