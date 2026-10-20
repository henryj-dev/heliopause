# Phase 5: unified dry-run planning and isolated forwarding validation

## Audit

Baseline: PR #198, main `28b0f4e2116ec126ecca3e43f1257e1b8ff71c69`.
The supplied handoff incorrectly described interface MTU as absent: the baseline
already has `InventoryInterface.mtu` and 68–65535 validation. The matcher still
used a redundant cast. The real issues were incomplete route comparisons,
unclassified residual telemetry, unknown inventory properties, and independent
WG/FRR compiler inputs without cross-compiler review commitments.

## Model and compatibility

Optional desired route fields: `nextHop` (null means direct), `metric`,
`preferredSource`, `routeType: unicast`, `protocol: static|boot`. Legacy documents
remain readable when they use known fields. Unknown fields now fail validation;
correct misspellings explicitly rather than silently persisting inert settings.
An observed gateway/metric/source/protocol that has no desired equivalent produces
`unknown`, not a claim of full equality. Dynamic protocols are external evidence.
ECMP/encapsulation remain unsupported by the existing discovery/ingress contract;
no new multipath writer is introduced.

Inventory retains its bounded supported MTU range, not a claim about every Linux
netdevice. Networks with an IPv6 subnet require at least 1280 when MTU is declared.
WG's existing minimum 1280 is a backend constraint; omitted desired MTU remains
unmanaged. Registry's existing mutation path increments resource generations.

Residual rows keep the backward-compatible `unexpected` status plus a classification:
`external-observation`, `unclaimed-observation`, or `unexpected-managed`.
Matched owned resources use `managed-observation`, not a drift label. Explicit
exact-name `managedScopes` are supplied by a trusted caller, never inferred from
interface prefixes. None of these rows generates a repair or delete proposal.

## Unified composition

`buildNetworkChangeSet()` reuses `buildNetworkPlan()`, `compileWireGuard()` and
`compileFrr()`. The existing planning CLI accepts `--unified`; the legacy path
retains its output kind. New public types are exported from `src/index.ts`.
Every artifact is freshly compiled against one registry snapshot. Retained review
assertions check target, revision, desired digest and artifact hash; arbitrary
external artifacts cannot be injected. Expected generations can be supplied.

Operations carry target source/host identity, domain, writer/backend, artifact hash,
resource generations, preconditions, verification and recovery requirements.
The DAG orders underlay verification → WG configuration → pair tunnel verification
→ FRR configuration → end-to-end forwarding verification. Existing Cloudflare
interfaces get verification operations only. All plans remain `dry-run`,
`executable: false`, even when every declarative check succeeds.

BGP primary addresses and update sources must equal the remote/local WG host
addresses. Imported prefixes must fit that peer's AllowedIPs. Per-node ASNs,
static/BGP writers, observed non-BGP FIB shadowing, peer host routes, artifact review commitments, identities,
collector availability, graph cycles and missing dependencies are checked.

Binary string ordering avoids process-locale dependence.
A standalone `prefixPolicyDigest` binds shared export permissions even when no
compiler artifact is requested or produced.
Content hashes exclude request IDs and output-only `generatedAt`. The evaluation
clock still controls freshness decisions. Exact evidence digests deliberately bind
collector payload bytes/array order; top-level registry, binding, compiler, policy
and observation ordering is canonicalized. Observation order is not a freshness
or authorization signal.

## Shared prefix policy

Both compilers accept the same `NetworkPrefixPolicy`. Without one, conservative
legacy infrastructure-only behavior remains. Management overlap always fails.
Infrastructure aggregates cannot include reserved pod/service pools. Pod prefixes
must be contained in explicit pod pools and carry fresh reachability references.
Service exports require an exact /32 or /128 VIP, stable cluster/namespace/name/UID,
readiness, exposure reference and one advertisement owner. Whole service CIDRs
are refused. CNI-origin relay is explicitly unsupported, preventing FRR from
silently originating the same VIP. Backbone advertisements are exact hosts only.

Attestation references are offline input, not authenticated approval. The unified
planner binds references to source/host/collection/digest evidence, and still blocks
on unverified packet forwarding and exposure authorization. No authenticated Pod
or Service watcher, readiness verifier, live CNI discovery or WARP path verifier
is implemented. AllowedIPs select peers; they are not firewall access policy.

The NetworkManager backend remains unsupported. WG artifacts identify `wg-quick`
explicitly; the inventory driver identity remains distinct from that backend.

## Isolated lab and reproducibility

Run on a Linux Docker host or the `isolated network lab` hosted-runner workflow:

```sh
scripts/network-lab/run.sh 8.5.6 /tmp/hp-lab-8
scripts/network-lab/run.sh 10.2.1 /tmp/hp-lab-10
```

The host only compiles synthetic inputs and runs Docker. The container has no
external network, no host network/PID namespace, credentials or Docker socket.
NET_ADMIN/NET_RAW/SYS_ADMIN allow namespaces and kernel WG inside the disposable
container. Do not run `run.py` directly on a production host; it requires a Docker
container. The only writable host mount is the chosen result directory.

Four gateway namespaces and four workload namespaces use documentation address
ranges. Fresh private keys exist only in ephemeral memory/private temp files and
are not printed or saved in results. The compiler's templates are used unchanged
for FRR syntax checks, including separate IPv6 templates with optional BFD enabled.
IPv6 packet forwarding and BFD liveness/failover are not exercised by those parser checks. Lab-specific BGP timers are added to a separate runtime configuration BEFORE
session negotiation (per-peer keepalive 1s, hold 3s, connect retry 1s); parser checks
continue to consume the exact unmodified compiler templates. The secondary backbone uses a separate WG interface/port, not Cloudflare.

Checks require six Established peers per gateway, all twelve ordered workload
paths, the chosen BGP next hop, the actual kernel FIB interface, WG transmitted
byte deltas, and ping success. Primary outage and recovery measure convergence and
sampled probe losses. Recovery starts only after primary BGP sessions/valid paths
actually withdraw; two post-recovery samples check short-term stability. A deliberate static route shadow must be detected even when
BGP selected primary. Management addresses, local workload-to-management pings, default routes and export leakage
are checked. These tests do not establish actual Cloudflare/WARP behavior, CNI
routing, Kubernetes VIP translation, BFD, asymmetric-policy behavior or production
RHEL compatibility. No operational addresses from the handoff enter the fixture.

`input.json` and `report.json` are written to the chosen result directory. The
report distinguishes syntax, packet forwarding, outage and recovery. A missing
kernel capability or daemon is a failure, never a successful skip.

The lab exposed a real lifecycle requirement: administrative interface-down deletes
non-persistent peer host routes. Plain link-up left the primary BGP sessions Active
and forwarding on secondary. Recovery now explicitly brings the link up AND restores
the compiler-declared peer host routes before waiting for unforced BGP convergence.
The ChangeSet carries this as a recovery requirement. This is lab setup/recovery,
not an implementation or authorization of a production apply driver.

Upstream references: [FRR daemon common options](https://github.com/FRRouting/frr/blob/master/doc/manpages/common-options.rst),
[FRR 10.2.1 release](https://frrouting.org/release/10.2.1/).

## Validation status

Local root/manager type checks, workspace suite coverage, icon checks and 205 focused
network/CLI/packaging tests passed. Local full regression did not pass: Unix
socket/terminal restrictions prevented several existing integration suites from
running successfully. Those failures are not counted as successful verification.
Linux CI passed complete regression, mTLS and real-kernel rollback. The PR body
records final-head counts and links after the last validation run.

Recorded isolated lab run:
[39349509294](https://github.com/henryj-dev/heliopause/actions/runs/39349509294),
source revision `948aea5`. Both daemon versions passed all twelve checks, including
exact compiled IPv4/IPv6+BFD syntax, actual IPv4 workload/synthetic Pod-prefix/VIP
packets, primary session withdrawal, recovery and two post-recovery samples.

| FRR | Full validation convergence after primary failure | After explicit interface/host-route recovery | Lost dedicated samples (failure / recovery) |
| --- | --- | --- | --- |
| 8.5.6 | 710.372 ms | 2307.729 ms | 1 of 1 / 0 of 6 |
| 10.2.1 | 1618.950 ms | 1918.485 ms | 1 of 2 / 0 of 7 |

These are single-run lab measurements with short explicit BGP timers. They include
sequential FIB, BGP and all-pairs forwarding verification overhead. They are not
production outage guarantees or total packet-loss measurements. Dedicated sample
counts exclude packets sent by the all-pairs validator. The failure convergence
measurement ends at verified secondary forwarding; full BGP-session/path withdrawal
is a separate check performed before recovery.

Earlier 8.5.6 runs intermittently retained invalid primary next hops after sessions
returned. Waiting for all interfaces to be observed Up by zebra before restoring
dependent host routes eliminated that failure in the recorded run. That is a lab
recovery ordering finding, not proof of an upstream FRR defect or long-term
production stability. Only two post-recovery samples are checked.

The final report binds registry revision, ChangeSet hash and source artifact hashes,
and identifies the lab-specific key, secondary-tunnel and timer transformations.
These references make reports traceable, not signed or authorized execution evidence.

## Delivered scope and review

[PR #199](https://github.com/henryj-dev/heliopause/pull/199) is submitted for review.
Main comparison uses [PR #198](https://github.com/henryj-dev/heliopause/pull/198).

- `src/network-inventory.ts`, `src/network-matching.ts`: static route schema,
  explicit MTU semantics, strict fields, zone-identifier safety and observation classes.
- `src/network-prefix-policy.ts`, `src/network-change-set.ts`: shared export rules,
  evidence/ownership consistency, compiler composition and blocked operation graph.
- `src/network-canonical.ts`, `src/network-planner.ts`, `src/network-wireguard.ts`,
  `src/network-frr.ts`: binary ordering and reuse of existing compiler/plan modules.
- Existing `bin/heliopause-network-plan.ts` and `bin/heliopause-network-compile.ts`:
  offline unified planning and policy input; no new apply path.
- `examples/network-lab.ts`, `scripts/network-lab/`, `.github/workflows/network-lab.yml`:
  synthetic four-site model and isolated real-kernel verification matrix.
- Inventory, network CLI and Phase 5 regression tests plus public exports were updated.

No Manager/Relay/Agent transport, signature, approval, heartbeat, policy application
or rollback implementation is replaced. Existing security/compatibility regressions
remain in the complete CI run. No production VPC, Cloudflare Mesh, WARP, K3s or RHEL
gateway was accessed or modified. Network Overview UI and a real K3s/Cilium lab are
not implemented. ECMP, non-global FRR writer domains, NetworkManager execution,
IPv6 forwarding and BFD liveness remain outside verified scope.

## Next phase

Keep execution separate. Before Phase 6, design signed ChangeSets, authenticated
prefix/exposure evidence, trusted capability negotiation, secret resolution,
NetworkManager/WG/FRR drivers, durable per-driver undo, independent reachability,
restart recovery and per-site saga rollout with existing approvals/commit-confirm.
No production network modification is authorized by this phase or its lab results.
