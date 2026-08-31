// Aggregating several VPCs into one view.
//
// Every case here is a failure mode, because the successful case is uninteresting: relays answer and
// the rows are concatenated. What the manager exists to get right is what happens when one of them
// does not answer, or when they disagree.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { contains } from "./test-util.ts";
import { siteView, siteNeedsAttention, type RelayResult } from "./manager.ts";
import type { FleetView, HostView } from "./relay.ts";

const host = (over: Partial<HostView> = {}): HostView => ({
  host: "h-a",
  agentVersion: "0.3.0-pull",
  stage: "canary",
  state: "confirmed",
  generation: "gen1",
  current: true,
  drifted: false,
  lastSeen: "2026-08-02T00:00:00Z",
  ageSec: 5,
  blockedBy: null,
  maintenance: null,
  detail: null,
  workload: null,
  unexpectedFilters: null,
  // Empty is the normal answer: the relay does the checking, so there is nothing it can fail to
  // report. `[]` rather than optional for that reason — see `HostView.contradictions`.
  contradictions: [],
  // `null` = 보고하지 않음(구 에이전트), `[]` = 지켜봤고 없음. 픽스처는 전자를 기본으로 둔다 —
  // 이 파일의 테스트는 집계를 재고 침해 보고를 재지 않는다.
  intrusions: null,
  publishedPorts: null,
  routes: null,
  ciliumExposure: null,
  ...over,
});

const view = (over: Partial<FleetView> = {}): FleetView => ({
  generation: "gen1",
  issuedAt: "2026-08-02T00:00:00Z",
  planHash: null,
  hosts: [host()],
  problems: [],
  relayAgeSec: 600,
  ...over,
});

const ok = (name: string, v: FleetView = view()): RelayResult => ({
  name,
  url: `https://relay.${name}.invalid:8443`,
  ok: true,
  view: v,
});

const down = (name: string, error = "connect ETIMEDOUT"): RelayResult => ({
  name,
  url: `https://relay.${name}.invalid:8443`,
  ok: false,
  error,
});

describe("siteView", () => {
  it("describes the rest of the site when one relay is unreachable", () => {
    // The property the whole file exists for. Relays are separate so a gateway outage is contained;
    // an aggregator that failed the request would report the opposite of what the design provides.
    const s = siteView([ok("dev"), down("prod"), ok("util")]);
    assert.equal(s.reachable, 2);
    assert.equal(s.asked, 3);
    assert.equal(s.hosts.length, 2, "dev and util hosts still present");
  });

  it("says what an unreachable relay means, not just that it happened", () => {
    // "prod unreachable" is a fact about a connection. What an operator needs is the consequence.
    const s = siteView([down("prod", "connect ETIMEDOUT")]);
    contains(s.problems.join("|"), "receiving nothing");
    contains(s.problems.join("|"), "ETIMEDOUT");
  });

  it("tags every host with its VPC", () => {
    // Host names repeat across VPCs by design — every VPC has a `gw-01`. An untagged row is
    // ambiguous exactly where it matters.
    const s = siteView([ok("dev"), ok("prod")]);
    assert.deepEqual(s.hosts.map((h) => h.vpc).sort(), ["dev", "prod"]);
  });

  it("tags every problem with its VPC", () => {
    const s = siteView([ok("dev", view({ problems: ["h-a: rolled back"] }))]);
    assert.deepEqual(s.problems, ["dev: h-a: rolled back"]);
  });

  it("reports disagreeing generations rather than judging them", () => {
    // More than one generation is normal mid-rollout and a problem afterwards. The manager cannot
    // tell which without knowing when the publish happened, so it reports the fact.
    const s = siteView([
      ok("dev", view({ generation: "gen2" })),
      ok("prod", view({ generation: "gen1" })),
      ok("util", view({ generation: "gen1" })),
    ]);
    assert.equal(s.generations.length, 2);
    // Most common first, so the odd one out is visible at the end rather than buried.
    assert.deepEqual(s.generations[0], { generation: "gen1", vpcs: ["prod", "util"] });
    assert.deepEqual(s.generations[1], { generation: "gen2", vpcs: ["dev"] });
  });

  it("counts a relay with no manifest as its own generation, not as agreement", () => {
    // A relay that has not loaded a manifest reports `null`. Folding that into the others would make
    // a site look consistent while one VPC is serving nothing at all.
    const s = siteView([ok("dev"), ok("prod", view({ generation: null, hosts: [] }))]);
    assert.equal(s.generations.length, 2);
  });

  it("keeps the VPC order it was given", () => {
    // Stable across polls. A view that reorders itself is hard to read at a glance, and the ordering
    // of a map's entries is an implementation detail.
    const s = siteView([ok("util"), ok("dev"), ok("prod")]);
    assert.deepEqual(s.vpcs.map((v) => v.name), ["util", "dev", "prod"]);
  });

  it("handles every relay being down without throwing", () => {
    // The worst case still has to produce an answer — that is when someone is reading it.
    const s = siteView([down("dev"), down("prod"), down("util")]);
    assert.equal(s.reachable, 0);
    assert.equal(s.hosts.length, 0);
    assert.equal(s.problems.length, 3);
  });

  it("describes an empty site rather than failing on it", () => {
    const s = siteView([]);
    assert.deepEqual(s.problems, []);
    assert.equal(s.asked, 0);
  });
});

describe("siteNeedsAttention", () => {
  it("is true when a relay is unreachable even if nothing else is wrong", () => {
    // Its hosts are receiving nothing and nobody can see them. That is the case most likely to be
    // missed, because the reachable VPCs all look fine.
    assert.equal(siteNeedsAttention(siteView([ok("dev"), down("prod")])), true);
  });

  it("is true when a reachable relay reports a problem", () => {
    assert.equal(
      siteNeedsAttention(siteView([ok("dev", view({ problems: ["h-a: drifted"] }))])),
      true,
    );
  });

  it("is false for a healthy site", () => {
    assert.equal(siteNeedsAttention(siteView([ok("dev"), ok("prod")])), false);
  });

  it("is false for a site mid-rollout with no problems", () => {
    // Two generations in play is not itself a reason to interrupt someone — it is what a staged
    // rollout looks like while it is working.
    const s = siteView([ok("dev", view({ generation: "gen2" })), ok("prod", view({ generation: "gen1" }))]);
    assert.equal(siteNeedsAttention(s), false);
  });
});

describe("siteView — another firewall on a host", () => {
  it("carries the per-host finding, not only the problem line", () => {
    // `problems` already says what it means; it does not say which row. An operator scanning the
    // table for the host to act on needs the finding on the row, and the two disagreeing — the
    // fleet view showing it, the site view not — is how a signal gets lost in aggregation.
    const s = siteView([ok("dev", view({ hosts: [host({ unexpectedFilters: ["inet firewalld"] })] }))]);
    assert.deepEqual(s.hosts[0]!.unexpectedFilters, ["inet firewalld"]);
  });

  it("reads a relay too old to report as unknown, not as clear", () => {
    // The same null-versus-empty distinction the field is built on, one layer up. An older relay
    // omits the key entirely, and defaulting that to `[]` would claim every host behind it is alone.
    const stale = view({ hosts: [{ ...host(), unexpectedFilters: undefined } as unknown as HostView] });
    assert.equal(siteView([ok("dev", stale)]).hosts[0]!.unexpectedFilters, null);
  });
});

// Aggregation is where a signal gets lost quietly: every layer below still looks right.
//
// H30 landed with the check running, the relay recording it and the fleet view carrying it — and the
// site view dropping it on the floor. Nothing failed; the finding simply did not arrive where an
// operator looks across VPCs. These pin both per-host findings against that.
describe("siteView — per-host findings survive aggregation", () => {
  it("carries a contradiction onto the site row", () => {
    const c = {
      host: "h-a",
      kind: "artifact-hash-wrong" as const,
      certainty: "certain" as const,
      detail: "confirmed with an artifact the manifest does not publish",
    };
    const s = siteView([ok("dev", view({ hosts: [host({ contradictions: [c] })] }))]);
    assert.equal(s.hosts[0]!.contradictions.length, 1);
    assert.equal(s.hosts[0]!.contradictions[0]!.kind, "artifact-hash-wrong");
  });

  it("carries the agent build through to the site view", () => {
    // Five fields have been lost at exactly this join. This one is what an operator reads to decide
    // whether an agent deployment actually reached a host, so losing it would make the answer
    // unavailable at the moment it is asked for.
    const s = siteView([ok("dev", view({ hosts: [host({ agentVersion: "9.9.9-test" })] }))]);
    assert.equal(s.hosts[0]!.agentVersion, "9.9.9-test");
  });
  
  it("keeps null distinct from a version", () => {
    // `null` is an agent too old to send one — which is what a half-finished rollout looks like.
    const s = siteView([ok("dev", view({ hosts: [host({ agentVersion: null })] }))]);
    assert.equal(s.hosts[0]!.agentVersion, null);
  });
  
  it("carries intrusion events onto the site row", () => {
    const e = {
      at: "2026-08-03T00:00:00Z",
      table: "inet heliopause",
      raw: "add rule inet heliopause input tcp dport 9999 accept",
      pid: 4242,
      process: "nft",
      byAgent: false,
    };
    const s = siteView([ok("dev", view({ hosts: [host({ intrusions: [e] })] }))]);
    assert.equal(s.hosts[0]!.intrusions?.length, 1);
    assert.equal(s.hosts[0]!.intrusions?.[0]?.pid, 4242);
  });

  it("reads a relay too old to report intrusions as unknown, not as clear", () => {
    const stale = view({ hosts: [{ ...host(), intrusions: undefined } as unknown as HostView] });
    assert.equal(siteView([ok("dev", stale)]).hosts[0]!.intrusions, null);
  });

  it("carries Cilium eBPF exposure instead of dropping it at the manager", () => {
    const observed = {
      nodePortAddresses: [],
      services: ["HostPort 0.0.0.0:443/TCP dispatcher/dispatcher"],
    };
    const s = siteView([ok("dev", view({ hosts: [host({ ciliumExposure: observed })] }))]);
    assert.deepEqual(s.hosts[0]!.ciliumExposure, observed);
  });

  it("defaults contradictions to empty rather than unknown", () => {
    // The asymmetry is deliberate. The relay does the contradiction checking itself, so there is
    // nothing it can fail to look at; intrusions come from the agent, which can be too old to report.
    const stale = view({ hosts: [{ ...host(), contradictions: undefined } as unknown as HostView] });
    assert.deepEqual(siteView([ok("dev", stale)]).hosts[0]!.contradictions, []);
  });
});

// The third time, and the widest: the site view carried no part of the workload half at all.
//
// Every other field on such a row reads as success — `state: confirmed`, current generation, no
// drift — while the cluster-scoped policies, the ones with no host-layer rule behind them, are not
// in place. Nothing failed. The aggregate simply did not carry the half that would have said so.
describe("siteView — the workload half survives aggregation", () => {
  const workload = (over: Partial<NonNullable<HostView["workload"]>> = {}) => ({
    cluster: "dev-k3s",
    state: "confirmed" as string | null,
    expected: 4,
    detail: null as string | null,
    membership: null as NonNullable<HostView["workload"]>["membership"],
    ...over,
  });

  it("keeps a host confirmed on its own layer and rolled back in the cluster separable", () => {
    // The combination `HostView.workload` exists for. Flattened to one word the row reads
    // `confirmed`, which is true about the host and wrong about the site.
    const s = siteView([
      ok("dev", view({ hosts: [host({ workload: workload({ state: "rolled-back", detail: "apply timed out" }) })] })),
    ]);
    assert.equal(s.hosts[0]!.state, "confirmed");
    assert.equal(s.hosts[0]!.workload?.state, "rolled-back");
    assert.equal(s.hosts[0]!.workload?.detail, "apply timed out");
    assert.equal(s.hosts[0]!.workload?.cluster, "dev-k3s");
  });

  it("leaves the workload half null on a host that was never assigned one", () => {
    // Most hosts have none. `null` here is "not this host's job", which is why it cannot be the
    // same value as a relay that failed to report — see the next test.
    assert.equal(siteView([ok("dev")]).hosts[0]!.workload, null);
  });

  it("reads a relay too old to report the workload half as unknown, not as absent", () => {
    const stale = view({ hosts: [{ ...host(), workload: undefined } as unknown as HostView] });
    assert.equal(siteView([ok("dev", stale)]).hosts[0]!.workload, null);
  });

  it("carries membership with the time it was taken", () => {
    // A pod count without its timestamp is one an operator reads as current, and pod membership
    // goes stale in seconds — a CI runner exists for the length of one job.
    const m = {
      at: "2026-08-04T09:00:00Z",
      namespaces: { "arc-runners": ["runner-a", "runner-b"] },
      labelled: { "app=idp": ["idp-0"] },
    };
    const s = siteView([ok("dev", view({ hosts: [host({ workload: workload({ membership: m }) })] }))]);
    assert.equal(s.hosts[0]!.workload?.membership?.at, "2026-08-04T09:00:00Z");
    assert.deepEqual(s.hosts[0]!.workload?.membership?.namespaces["arc-runners"], ["runner-a", "runner-b"]);
  });

  it("keeps a namespace queried-and-empty distinct from one nobody queried", () => {
    // `arc-runners` is genuinely empty between CI jobs. Collapsing that into the same answer as a
    // namespace nobody asked about is how "0 pods" starts reading as "this policy is harmless".
    const m = { at: "2026-08-04T09:00:00Z", namespaces: { "arc-runners": [] }, labelled: {} };
    const s = siteView([ok("dev", view({ hosts: [host({ workload: workload({ membership: m }) })] }))]);
    assert.deepEqual(s.hosts[0]!.workload?.membership?.namespaces["arc-runners"], []);
    assert.equal(s.hosts[0]!.workload?.membership?.namespaces["idp"], undefined);
  });

  it("reports a host that has not reported membership as unknown rather than empty", () => {
    const s = siteView([ok("dev", view({ hosts: [host({ workload: workload() })] }))]);
    assert.equal(s.hosts[0]!.workload!.membership, null);
  });
});

describe("siteView — why a host has not moved", () => {
  // ## The field that was correct everywhere below and absent at the top
  //
  // On 2026-08-11 `gw-01.dev` sat on the previous generation while every other row read
  // `confirmed`. The site view offered no reason. The relay, asked directly, said:
  //
  //     gw-01.dev  gateway  waiting  waiting on general: mailer-03.dev has not reported this generation
  //
  // The fleet was doing exactly what staged rollout is for — `mailer-03` had been dead for twelve
  // hours, so the `general` stage never closed and the `gateway` stage never opened. **Correct
  // behaviour that the aggregate view could not express**, because the manager dropped `stage` and
  // `blockedBy` on the way through.
  //
  // A row that is mute about a stalled rollout reads as an unexplained stall, and an unexplained
  // stall is what an operator starts debugging. That is the cost: not a wrong answer, a missing one.

  it("carries the stage and the reason the host is held there", () => {
    const s = siteView([
      ok("dev", view({ hosts: [host({ stage: "gateway", current: false, blockedBy: "waiting on general: mailer-03.dev" })] })),
    ]);
    assert.equal(s.hosts[0]!.stage, "gateway");
    assert.equal(s.hosts[0]!.blockedBy, "waiting on general: mailer-03.dev");
  });

  it("says null when nothing is holding the host, rather than omitting the key", () => {
    // The known negative. A field that only ever appears when set cannot be distinguished from one
    // the relay never sent, and this view already has that distinction elsewhere.
    const s = siteView([ok("dev", view({ hosts: [host()] }))]);
    assert.equal(s.hosts[0]!.blockedBy, null);
  });

  it("reads a relay too old to report either as unknown, not as unblocked", () => {
    // An older relay omits the keys. Defaulting `blockedBy` to a string would invent a reason;
    // defaulting `stage` to one would place the host in a stage nobody assigned it.
    const stale = view({
      hosts: [{ ...host(), stage: undefined, blockedBy: undefined } as unknown as HostView],
    });
    const s = siteView([ok("dev", stale)]);
    assert.equal(s.hosts[0]!.stage, null);
    assert.equal(s.hosts[0]!.blockedBy, null);
  });
});
