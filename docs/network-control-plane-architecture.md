# Network Control Plane architecture and delivery plan

Status: target architecture with implementation boundaries recorded by delivery stage. Initial audit reviewed base `08d428b`; v2 builds on foundation PR #195 (`43921c9`), and registry/observability integration builds on PR #196 (`8a4ac86`). Inventory and telemetry do not authorize network configuration changes. This document contains no operational inventory. User-provided site addresses, identifiers, endpoints and proposed ASNs belong in private inventory, not this public repository.

## Existing system and reusable boundaries

Heliopause is currently a declarative host firewall control plane with selected route and Kubernetes workload controls, rather than a general network orchestrator. `src/config.ts` describes firewall baselines and hook policy; `src/routes.ts` describes declared/observed routes and ownership. `src/protocol.ts` carries per-host routes and management-route guards in the manifest. `src/publish.ts`, `src/bundle.ts` and `src/approval.ts` form the planning/publishing boundary.

Keep these security properties:

- `src/artifact-signature.ts` binds canonical per-host payload bytes, exact plan/bundle hashes, host identity and expiry to a manager Ed25519 key. The relay receives no signing authority.
- `src/manager.ts` aggregates relays using separate VPC trust roots. Keep trust scopes separate from the new inventory hierarchy; a topology edge must never imply authorization.
- `agent/heliopause-pull.py` pulls outbound, checks artifacts locally, confines nftables writes, applies owned static routes, persists recovery state and executes local confirmation deadlines. Existing network forwarding does not require the manager to stay alive.
- `src/rollout.ts` stages delivery. Retain canary gates, protected-host handling and explicit approval.
- `decisions/2026-10-01-coverage-trigger-independence.md` keeps external coverage measurement independent of the manager. Agent observations remain claims by the observed host; they cannot replace independent reachability probes.

Code is the authority where comments have aged: `src/routes.ts` says route writing is future work, but `apply_routes`, `rollback`, `recover_commitment` and durable `pendingRoutes` in the Python agent implement it. Current routes are intentionally narrow: the agent refuses default routes and non-main tables, observes IPv4 routes, and does not provide a policy-routing or dynamic-routing driver. Route protocol is evidence of origin, not proof of ownership.

The tracked policy-worker design documents record why executable policy evaluation crosses a worker boundary using captured messaging capabilities. Preserve that boundary. Add declarative network data through validated serialization rather than granting imported policy modules access to drivers or credentials. The host-retirement design documents also require policy/lifecycle changes to be explicit; deleting inventory must not silently delete live network resources.

Local history shows recent work on signed authorization expiry, durable rollback debt/restart recovery, independent observation and member-based approvals. These are reusable foundations. A later GitHub issue-list check found open issues #157, #155, #148 and #89, with no open network-control-plane transition issue in that returned list. Running infrastructure was not verified.

## Changes required

The current artifact is centered on one host ruleset plus optional routes/workload policy. A distributed topology needs resource identity, references, explicit address-allocation authority, resource-specific ownership, observation freshness and cross-host dependencies before broadening that artifact.

Introduce a pure resource graph beside the existing policy model. Do not replace the stable manifest with an unversioned generic payload. Implement validated adapters from the new graph to existing firewall/route declarations first. A future driver payload must have a version, bounded size, canonical content digest, target host, capability requirements and approval binding before the relay may distribute it.

The Python agent is a substantial single module. Extract collectors and then drivers behind narrow boundaries; keep current safety tests and protocol behavior intact. A generic driver abstraction does not prove complete rollback. Each write driver needs explicit external-boundary tests, persistent undo records and real-system verification.

## Target responsibilities and resource model

Use one logical control plane with an inventory/IPAM registry, pure validator/compiler/planner, reconciler and existing API/approval system. Keep relays as authenticated distribution and reporting components. Agents collect host state and execute only authorized driver operations. Begin with modules in the current repository; a package split is unnecessary until dependencies justify it.

| Resource group | Desired facts | Allocation or execution authority |
| --- | --- | --- |
| Site, region, VPC, cluster, host, gateway | Stable IDs, relationships, capabilities | Inventory operator; existing enrollment remains identity authority |
| Interface, VLAN, bridge, bond, address | Host scope, link relationships, MTU, address intent | One selected host network driver |
| Prefix, pool, allocation, reservation | Address family, routing domain, parent, purpose, consumer | Explicit allocator: Heliopause, Kubernetes or external |
| Overlay, peer, endpoint, key reference | Topology, public identity, transport association | WireGuard driver or external provider |
| Routing instance, static route, BGP neighbor, advertisement | Table/VRF, prefix class, allowed origin, dependency | Static driver or FRR/Cilium owner, never both for the same claim |
| Firewall policy, NAT, zone | Existing policy plus future explicit translation rules | Existing nftables/Cilium compiler, with scoped ownership |
| Service exposure | Selected service, VIP, readiness and advertisement policy | Kubernetes service owner plus one advertised-route owner |

Resource identity must be independent of a mutable address or interface display name. References must resolve in the correct host/site/routing domain. Parent prefix containment is permitted; independent sibling allocations must not overlap. Duplicate address use must be checked within its routing domain, with intentional isolation represented explicitly. A reserved pool is not an allocated interface address. Kubernetes owns Pod/Service allocation; IPAM records/reserves their pools without allocating individual Pod addresses.

The target model separates management mode (managed, external, imported) from driver identity and allocation authority. Here imported means recorded external configuration awaiting an explicit adoption decision. The initial implementation instead names its modes `external`, `managed` and `adopted`; it has no `imported` mode. Its `adopted` record requires nonempty `approvedBy` and `source` strings, which are structural metadata checks, not authentication, authorization or verification of a real approval. External/imported resources in the target lifecycle remain observation-only until an explicit adoption plan proves compatibility and records approval. Admission must reject two desired writers claiming one interface, route identity or configuration file. Matching an observed object does not grant permission to adopt it. The registry integration below adds persistent claims and atomic local conflict checks; the pure validator alone still cannot arbitrate concurrent managers.

Observations carry collector identity, timestamp, schema version and success/error status. Unavailable, unsupported, stale and successfully empty are different states. Drift is computed only for comparable successful observations. Linux discovery must cover both address families and report routes/rules/interfaces separately. WireGuard collection must avoid private keys and preshared keys; do not forward raw dump output. FRR collection should use explicitly allowed bounded JSON commands, with missing binaries and malformed output visible as collection errors.

## Routing design and unresolved environment gates

The requested deployment has four site gateways, a proposed native WireGuard primary backbone and an existing externally managed secondary overlay. Represent both transports independently. Their actual addresses, provider constraints, reachability and route ownership remain unknown until read-only discovery is authorized and completed. Four gateways imply six undirected full-mesh links; this is topology intent, not evidence of established tunnels.

FRR is the proposed inter-site routing owner. NetworkManager/nmstate is a candidate interface persistence owner on the target Linux family. These are proposed integrations, not implemented or certified choices. Pin versions and validate official APIs and packaging before implementation. Official references reviewed for the proposed boundaries: [WireGuard cryptokey routing](https://www.wireguard.com/), [FRR BFD](https://docs.frrouting.org/en/latest/bfd.html), [Cilium selective BGP advertisements](https://docs.cilium.io/en/stable/network/bgp-control-plane/bgp-control-plane-configuration/) and [Cilium LB IPAM](https://docs.cilium.io/en/stable/network/lb-ipam/). The latter separates address allocation from advertisement; these references do not establish behavior in the current deployment.

Transport peer selection (`AllowedIPs`), Linux routes, policy rules and FRR-selected paths are separate objects. Avoid automatic route installation competing with FRR. Changing wg-quick/NetworkManager ownership requires an explicit migration; never disable existing automatic routes as an incidental compiler effect. Test endpoint underlay reachability, tunnel next-hop reachability, MTU, reverse-path filtering, return traffic, existing static-route preference and recovery behavior in a lab. BGP/BFD adjacency alone does not establish end-to-end reachability.

Keep management space separate from transit and application prefixes. Never export it by default. Infrastructure prefixes, Pod prefixes, internal Service pools and approved service VIPs are distinct advertisement classes. A ClusterIP is not an ordinary routable host address; external exposure requires a verified service-translation path and return route. Default Service exposure is internal. Selective host VIP advertisements require readiness and explicit approval. If Cilium advertises a VIP or Pod prefix, FRR must not independently originate the same claim without a documented handoff.

Private ASNs, actual CNI, Pod/Service subdivision outside confirmed inventory, public endpoints/NAT, secondary-overlay BGP support, WARP source translation and return paths, gateway redundancy and installed networking managers remain discovery gates. Do not synthesize those values from a site naming convention.

## Change and recovery contract

A future ChangeSet binds graph revision and observations used to plan, exact compiled bytes, target capabilities, dependency order, impact, verification evidence and recovery limits. Approval expires if any bound input changes. Reconciliation proposes changes; it cannot silently bypass approval or adopt external resources.

For each host: validate capability/ownership → prepare durable backup and undo intent → apply dependency-ordered steps → verify local state and independent paths → confirm → commit. Persist phase transitions before the corresponding dangerous operation. Retry and restart must recover the same operation identity. Existing host rollback is reusable for its current scope, not proof that interface, key, daemon and multi-host changes are transactional.

Cross-host delivery is a staged saga with compensating actions, not a global atomic transaction. Keep old transport and management paths until the new path is independently verified. Stop rollout on an unconfirmed host or rollback debt. A failed or irreversible step leaves explicit operator recovery instructions. Key rotation needs overlap, peer coordination and secure secret storage; central inventory stores key references/public keys, never tunnel private keys in public policy or telemetry.

## Delivery roadmap

| Phase | Modules/resources | Dependencies and migration | Verification and completion gate |
| --- | --- | --- | --- |
| 1. Core foundation | New pure network model, ownership and IPAM modules; public exports | Additive; no existing manifest/store migration; no operational fixtures | Runtime rejection of bad IDs/references, conflicting writers, invalid CIDRs and overlapping sibling subnet/pool prefixes; IPv4/IPv6 boundary tests; existing API remains compatible |
| 2. Read-only discovery | Standalone Linux/WireGuard/FRR collectors and typed observations | Phase 1; no heartbeat change until version/size/freshness contract is reviewed | Fixture parsers plus mocked subprocess boundaries; time/output bounds; no write commands; key redaction; unavailable differs from empty; integration on disposable Linux |
| 3. Registry and API | Persistent inventory revision, atomic ownership claims, read/write API and audit | Phases 1–2; versioned storage/import, existing identity/authorization | Concurrent-write conflict tests; scoped access; restart durability; explicit external adoption; private inventory import with dry-run |
| 4. Planner/reconciler | Deterministic driver plans, revision preconditions, dependency DAG, drift classification | Registry and successful fresh observations; adapters to existing routes/firewall | Byte-identical compilation; changed observations invalidate plan; missing capability blocks apply; dry-run contains no mutations |
| 5. Native overlay | WireGuard and interface persistence drivers, secret references | Reviewed driver wire format, durable recovery and lab underlay; external overlay remains observation-only | Namespace/VM packet tests; reboot persistence; endpoint route/MTU/NAT; failure during every persisted phase; no operational rollout before approval |
| 6. Dynamic routing | FRR neighbors/filter/advertisement driver, route ownership checks | Verified overlay paths; official version-specific FRR contract; explicit static route handoff | RIB/FIB and packet forwarding; primary loss/fallback/recovery; stale route withdrawal; no management/Service-pool leakage |
| 7. Kubernetes exposure | Cluster discovery, CNI adapters, approved service VIP resources | Confirmed CNI, allocation and advertisement authority | Actual Service translation and return path; healthy/unhealthy advertisement behavior; policy denies; no blanket Service-CIDR exports |
| 8. Operations/UI | Topology, ChangeSet evidence, drift/freshness, recovery runbooks | Stable API and observed resource identities | Show unknowns and ownership conflicts; independent probes; canary drill; measured failover and restore times |

PR #195 shipped the first slice in `src/network-inventory.ts` with eight resource kinds (`site`, `node`, `gateway`, `network`, `subnet`, `address-pool`, `interface`, `route`), a pure runtime inventory validator, management/driver ownership metadata and a pool-prefix foundation for IPAM. It does not allocate or reserve individual addresses, execute drivers, persist a resource registry or deliver network changes. Read-only discovery is a separate follow-up boundary described below. The validator reuses the existing `cidrRange` parser: ordinary IPv4 and IPv6 prefixes are supported, but IPv4-mapped IPv6 prefixes written with a dotted-decimal IPv4 tail are unsupported. The `route` resource describes inventory intent; accepting its shape does not authorize an existing agent to apply it. Rows above describe the broader delivery sequence; remaining acceptance criteria are future work, not claims of functionality. No driver mutation, agent deployment, Cloudflare change or live network migration is authorized by this document.

Before any operational migration: collect current link/address/route/rule/WireGuard/FRR/CNI state through an approved read-only path; resolve owners and unknowns; back up configurations and secrets privately; verify console/out-of-band recovery; review generated change and undo plans; rehearse in disposable infrastructure; obtain separate approval; roll out one canary and independently verify packet paths before proceeding. Manager failure must leave committed data-plane configuration running; it must not disable local recovery for an unconfirmed change.


## Inventory v2: decisions and implementation boundary

The v1 `network.siteId` relationship could express a local network but could not attach gateways in several sites to one overlay. Its collision scope was `networkId`, so independent network records in the same intended address space could claim overlapping prefixes. The correction retains the resource records and pure `validateNetworkInventory(unknown)` API rather than introducing a generic graph engine. The implemented v2 model adds `routing-domain`, `domain-connection` and `learned-route` to the original eight resource kinds. Its exported types and validator are inventory-only; no execution or authorization path consumes them.

### Site and Network alternatives

| Alternative | Type/reference implications | Decision |
| --- | --- | --- |
| Optional `network.siteId` | Keeps old syntax, but absence does not distinguish shared transit, overlay or missing data; domain and membership rules still needed | Rejected as the complete model |
| Separate SiteNetwork and TransitNetwork kinds | Strong local/shared distinction, but duplicates shared prefix/interface relationships and needs another overlay choice | Valid alternative, unnecessary resource-kind split now |
| Network belongs to a routing domain, with explicit site scope | Discriminated local/shared forms, one common prefix model and bounded reference checks; preserves legacy local form | Selected |
| Generic Network plus relationship resources for everything | Extensible, but makes required membership/domain cardinality harder to see and expands validation machinery | Deferred; only the concrete domain-connection relationship is needed now |

The selected v2 form uses `scope: "site-local"`, `siteId`, `routingDomainId` and `purpose`, or `scope: "transit" | "overlay"`, `siteIds`, `routingDomainId` and `purpose`. Membership is explicit, nonempty and unique. An interface's node must belong to the local site or one of the shared network's member sites. Gateways reference nodes, so multiple gateways per site need no singleton exception. A transit is a shared logical network; an overlay records transport intent, not an established tunnel or a BGP session. Tunnel, peer, endpoint and key lifecycle remain future resources.

A `routing-domain` names an independent address/routing context. `isolation` distinguishes global, VRF and external contexts; optional VRF data describes a proposed Linux binding, not a requirement that every domain be a Linux VRF. Membership confers no access, routing reachability or apply authority. A `domain-connection` explicitly names two domains and represents bidirectional connectivity for conservative validation. All domains in a transitive connected component share the collision check. Selective prefix import/export and directional leaking are not modeled: the checker can reject configurations that a future precise filtering model could permit. Anycast/shared-prefix exceptions are unsupported and fail closed. Management-domain connections require explicit `allowManagement`; this flag is an inventory declaration, not an advertisement policy or operational authorization.

### Prefix hierarchy and allocation

V2 subnet overlap checks span the routing domain/connected component, including subnets belonging to different networks. Isolated domains may reuse prefixes. Explicit `parentSubnetId` permits strict containment only within the same network; references must be acyclic. Ancestor/descendant containment is intentional, whereas overlapping siblings or independent subnet claims are errors. Pools belong to subnets and must fit their parent. Pool reservations are not individual address allocations. Overlapping independently allocatable pool ranges must remain conflicts even when a containing subnet is only a hierarchy container.

Pool `purpose` separates infrastructure, Kubernetes Pod, Kubernetes Service, tunnel and management ranges. Kubernetes Pod/Service pools retain `allocationAuthority: "kubernetes"`; an administrative owner or managed inventory record does not transfer allocation authority. Allocation and reservation records, free-address selection, atomic leases and real address assignment remain unimplemented. Native tunnel host addresses and peer reachability routes will be distinct future resources.

### Route intent and ownership

The existing `src/routes.ts` owner vocabulary and static apply protocol remain unchanged. V2 inventory routes reference an interface and explicit logical routing domain, with any VRF table binding checked against their table. Write-conflict identity is the node, table and canonical destination prefix: changing the interface or logical domain label cannot evade a conflict over the same kernel table entry. Protocol/interface naming is not trusted ownership evidence. Static and FRR drivers must not claim the same route-installation identity. Next hops distinguish dynamic candidate paths, not independent permission for competing writers to replace one FIB destination.

The separate `learned-route` kind represents external observation, with `stage` naming learned, selected or installed evidence and protocol/source information. Multiple BGP candidates for one destination are valid observations, not duplicate write claims. These records do not create FRR sessions, inspect the kernel or demonstrate that learned, selected and installed state agree. Routing daemon policy ownership remains separate from direct static FIB writes. Inventory validity never broadens the existing agent's main-table/default-route safety refusals.

### Legacy and adoption migration

Legacy siteId-only networks remain accepted by the existing API in legacy-only documents. They retain v1 network-scoped comparison semantics; this compatibility path does not establish cross-network routing safety. Introducing a routing-domain resource or explicit v2 network fields requires converting every network in that document to v2. This prevents silently downgrading unconverted networks into separate implicit address spaces.

Migration is data-only: identify actual independent routing contexts privately; create explicit domains; convert local network scope and purpose; add shared-network site membership and parent subnet references; declare intended domain connections; validate the entire result. A validator cannot infer isolation from old IDs or live route protocol. No migration modifies the existing firewall policy, signed manifest, relay API or deployed agent.

Management modes remain `external`, `managed` and `adopted`. The target concept of imported configuration is represented as external inventory awaiting adoption, not a fourth mode. `approvedBy` and `source` strings record metadata only. They neither authenticate an approver nor establish approval, ownership transfer or execution rights. Actual adoption requires a future ChangeSet bound to resource revision, observed source configuration, exact target bytes, approval and host authorization. Existing signing/approval components are candidates for reuse, not an implemented adoption workflow.

## Read-only discovery boundary

Discovery is a separate Python collector boundary, with explicit calls and no network mutation or automatic adoption. Intended inputs are fixed `ip -j` link/address/route/rule queries, with separate IPv4 and IPv6 route/rule observations. Table identifiers inferred from these results describe observed tables; they do not enumerate every configured but empty table. Unknown JSON fields must not automatically become trusted inventory or raw report data. See [ip JSON output](https://man7.org/linux/man-pages/man8/ip.8.html).

WireGuard collection must request only public-key, listen-port, peers, endpoints, allowed-ips, latest-handshakes, transfer and persistent-keepalive fields. Script-friendly field queries use tab/newline framing; `all` adds an interface column. Never invoke `dump`, `showconf`, private-key or preshared-keys queries: dump includes both private and preshared key material. See the [WireGuard command contract](https://man7.org/linux/man-pages/man8/wg.8.html). Observation of an externally managed tunnel does not authorize writing it.

Command execution requires an exact allowlist, argument arrays with no shell, bounded run time and output, deterministic error categories, per-observation timestamps and capability evidence. Bound output during collection rather than after an unlimited capture; Python documents that `communicate()` buffers captured data in memory. Terminate and reap timed-out or over-limit children, and avoid forwarding raw stdout/stderr in errors. A successful empty response, missing tool, unsupported platform, denied permission, timeout and malformed response must remain distinguishable. See [Python subprocess behavior](https://docs.python.org/3/library/subprocess.html).

The collector introduced in PR #196 is an opt-in Python library (`collect_network_state`) and standalone JSON CLI; import performs no collection. Its original Linux/WireGuard scope consists of fourteen fixed queries: `ip -j link show`, `ip -j address show`, IPv4/IPv6 `route show table all`, IPv4/IPv6 `rule show`, and eight `wg show all` public-field queries listed above. Executables are resolved only in fixed system binary directories; stdin is closed and no shell is used. Each command defaults to a three-second deadline and one MiB cumulative stdout/stderr limit, enforced while both pipes are drained; failed or over-limit children are killed/reaped and raw diagnostics are omitted. A nonzero exit or any stderr makes that query unavailable, including a command that exits zero with warnings. This is deliberately conservative and can reject otherwise usable partial output.

The report has `schemaVersion`, `startedAt`, `completedAt`, `observations` and `capabilities`. Each named observation has `status`, `startedAt`, `completedAt` and success-only `data`; each matching capability has `available` and `status`. Statuses are `success`, `not-installed`, `unsupported`, `unavailable`, `timeout`, `output-limit` and parser `error`. Missing tool differs from unsupported platform; permission failures are grouped into unavailable rather than diagnosed separately. A successful query can contain an empty list. `available` means that particular query succeeded, not that a driver is authorized or a daemon's complete capability was proven.

Normalized Linux link/address records retain interface identity, selected MTU/link/master/state/flag fields and address family/local/prefix/scope data. Route/rule records retain selected destination/source, gateway, device, protocol, metric, table, type, preferred source, scope, priority, interface selector and action fields as applicable. Unknown fields are omitted, so this is a bounded observation schema rather than a lossless kernel snapshot. Recognized multipath/nexthop, alternate via, nexthop-ID and encapsulation structures return `unsupported` without partial data; malformed recognized fields return `error`. Recognized rule selectors whose meaning this schema cannot preserve (including marks/masks, TOS, IP protocol, port ranges, UID ranges, suppression selectors, l3mdev, inversion, goto and tunnel ID) also return `unsupported` without partial data. Other unknown fields are omitted; this remains a projection, not a complete routing-policy representation. Route address-family mismatches and numeric IP values return `error`; the route destination permits the `default` sentinel while rule source/destination permit `all`. WireGuard AllowedIPs require actual CIDR prefixes rather than either sentinel.

WireGuard data retains interface/public key/listen port and peer public keys, normalized endpoint address/port, allowed prefixes, handshake epoch, RX/TX counters and keepalive interval, by query. Separate queries are not atomic and may observe different generations of a changing interface. No merged peer snapshot or ownership inference is provided. `is_fresh` checks a report/observation completion timestamp against a caller-supplied maximum age and rejects future timestamps; it does not prove kernel state is unchanged, periodically refresh data or enforce a production freshness policy. A failed observation can still be recent: consumers must separately require `status == "success"` before using its data.

Tests cover fixture normalization and benign local child-process execution for bounded capture. They do not establish real RHEL/iproute2/WireGuard compatibility or live tunnel correctness. At PR #196, the module was standalone and was not packaged or invoked by the policy agent. The next section describes the subsequent opt-in agent integration, registry and FRR observations. No discovery data is automatically imported into desired inventory. No driver execution, reconciler, advertisement compiler, Cloudflare action or operational deployment is introduced.

## Registry and observability integration

### Durable desired state

`src/network-registry.ts` uses the existing `withFileLock` and `atomicWriteFile` primitives. One transaction loads the current document under an adjacent exclusive lock, compares `expectedRevision`, validates the complete candidate inventory, and atomically commits resources and audit metadata together. Revision conflicts return 409. The registry revision changes for a document mutation; resource generations change only when that resource changes. No-op writes preserve both. Missing storage starts as revision zero; corrupt or unknown storage schemas fail closed instead of being silently reset.

The registry is bounded to 512 resources and 512 KiB of input, with a four MiB persisted-document ceiling. The most recent 256 revision records retain authenticated actor, server time, action and exact before/after resource digests. This is bounded recent history, not a full historical snapshot archive or a complete external audit retention service. Deleted IDs are retired rather than silently reused. The registry retains up to 4,096 retired IDs and 4,096 persistent interface/route ownership claims, failing closed at those ceilings. Claims bind declared node/interface-name and node/table/canonical-prefix identities independently of mutable resource IDs, so rekeying a declaration cannot transfer its existing claim to a different management provider or driver. Deleting a referenced resource fails whole-inventory validation; deleting a declaration never deletes an interface, route or daemon configuration.

Management-mode/provider/driver changes and new adoption claims are refused because the actual adoption workflow is not implemented. Body-supplied approval strings cannot authorize transfer. `learned-route` and `observedGeneration` are rejected in desired registry writes; learned routes belong in telemetry. Legacy-only inventory can be submitted as a batch, retaining the v2 validator's all-at-once migration requirement when explicit routing domains are introduced.

This local store assumes a single Manager with a durable filesystem. Locks serialize cooperating local processes, not multi-host distributed writers; stale locks require an operator to stop writers and investigate before removal. A database or distributed transaction mechanism is not introduced.

### API and access

The Manager enables the registry with `HELIOPAUSE_NETWORK_REGISTRY_FILE` and observation persistence with `HELIOPAUSE_NETWORK_OBSERVATIONS_DIR`. Paths belong on private durable storage. Existing operator/member/session authentication is reused. Authorized readers can inspect state; mutations require the existing write permission and cookie-session CSRF checks. Actor identity comes from the authenticated principal, not request JSON. Disabled stores return a configured-unavailable response.

| Manager API | Contract |
| --- | --- |
| `GET /api/network/inventory` | Desired registry document and revision |
| `GET /api/network/inventory/:id` | One desired resource and current revision |
| `POST /api/network/inventory` | Create with `{expectedRevision, resource}` |
| `PUT /api/network/inventory/:id` | Update with `{expectedRevision, resource}` |
| `PUT /api/network/inventory` | Validated batch import/replace with `{expectedRevision, resources}` |
| `DELETE /api/network/inventory/:id` | Declaration deletion with `{expectedRevision}` |
| `GET /api/network/revisions` | Current revision and bounded recent change metadata |
| `GET /api/network/observations` | Fetch configured relay observations, persist latest accepted claims and expose cached state with relay availability |
| `GET /api/network/observations/:source/:host` | Source-scoped host observation and freshness |

Registry validation/ownership conflicts do not expand apply authority. No registry endpoint compiles or publishes artifacts, confirms policy, or executes a network driver.

### Independent agent telemetry

Option A (full heartbeat expansion) would consume the existing 256 KiB heartbeat budget and couple observation failures to confirmation traffic. A hybrid summary is possible later, but adds a cross-channel consistency contract without a current consumer. The chosen first integration therefore uses option B: independent bounded uploads to the relay, leaving schema 5 heartbeats and signed manifests unchanged.

`HELIOPAUSE_NETWORK_DISCOVERY=1` enables the independent scheduler after startup recovery. Its default attempt interval is 300 seconds and its whole-process budget is 45 seconds; `HELIOPAUSE_NETWORK_DISCOVERY_INTERVAL` and `HELIOPAUSE_NETWORK_DISCOVERY_BUDGET` configure them within bounded ranges. A separate process runs collectors and uploads, and a daemon scheduler thread monitors its process group. Neither collector nor upload holds policy-state locks or calls apply/confirm/recovery. While the agent is alive, timeout or shutdown terminates the telemetry process group; failed attempts wait for the next interval. The worker also has a 40-second self-deadline so an abruptly terminated parent cannot leave its uploader running indefinitely; restart does not guarantee immediate cleanup of an old attempt. Restart starts a new collection rather than restoring a policy commitment from telemetry.

The worker uses the agent's mTLS credentials and configured relay certificate pins. Its separate report schema is version 1 and includes a collection ID, timestamps, named per-query results and matching capabilities. Uploads are limited to 128 KiB, independent of the heartbeat limit. Oversized successful data becomes explicit output-limit evidence rather than silently truncated routes or peers. There is no raw command output, stderr, token, FRR password, WireGuard private key or preshared key field.

The relay binds the request host to the authenticated certificate CN and current manifest membership, and excludes configured operator/publisher identities from upload. Existing certificates do not carry a distinct cryptographic agent-role extension: manifest membership is the enrollment boundary here, not an invented new certificate claim. Operators can retrieve observations; an agent cannot use that read endpoint to inspect peers. Existing revocation checks still apply.

### Observed state and freshness

`src/network-observation.ts` validates a bounded allowlist of normalized collector fields before persisting an observation. Agent identity is bound at the relay and preserved as `(configured relay source, host)` at the Manager, allowing the same host name under separate trust roots. Paths use digests rather than untrusted host paths. Server receive times are separate from host collection times. Repeated collection IDs and older collections do not refresh a cached record's receive time.

Manager ingestion is request-driven, using the configured per-relay mTLS credentials. Successful snapshots are persisted locally; a failed relay fetch is recorded alongside cached observations instead of erasing them or fabricating empty success. The observation store retains the latest accepted report per scoped host, not an event archive. Freshness considers host report time, local receipt and relay receipt; it is separate from collector success. Recent errors remain errors, stale success remains stale, and a missing observation is never-observed. Query success or a recent WireGuard handshake never becomes a network-health or end-to-end reachability assertion.

Authenticated telemetry remains a host claim conveyed by its relay, not independent verification. It does not become an existing deployment confirmation, observed generation, desired resource, or approval. Actual reachability and comparison of FRR RIB with kernel FIB require separate evidence.

### FRRouting visibility and remaining work

The FRR collector uses fixed read-only `vtysh` queries and the existing bounded execution primitive. Version and connected-daemon list use narrow text parsing because the reviewed FRR command implementations do not offer JSON for those two commands. BGP summary, IPv4/IPv6 unicast RIB and BFD use structured JSON. Normalized records retain version, connected daemon names, local/remote ASNs, peer session state, optional reported prefix counts, route validity/best-path flags, next hops and BFD state. Missing counts stay unknown rather than becoming zero. Connected daemon names are not a process-health guarantee. BGP best-path selection does not assert Linux FIB installation or connectivity.

The supported fixture/source versions and any disposable-runtime measurements must be reported with test evidence; broad RHEL or arbitrary FRR-version compatibility is not implied. Real target-host verification requires separate environment approval. A read-only Network Overview UI is not part of this integration. No WireGuard/FRR writer, IP allocator, automatic failover, independent connectivity probe, or reconciliation execution is added.

The next delivery sequence is: bind fresh observations and registry revisions into deterministic, capability-checked plans; add WireGuard configuration compilation and explicit key references; add NetworkManager/nmstate persistence plans; add FRR configuration/filter/preference compilation; rehearse dual-backbone failure and recovery; then implement dependency-ordered multi-site ChangeSets with signed approval, durable per-driver undo, local rollback and independent connectivity checks. Each compiler remains dry-run until its real-system and recovery gates pass.

FRR compatibility evidence for this change: parsers were checked against official 8.5.6 and 10.2.1 fixture/source shapes and exercised against image `quay.io/frrouting/frr@sha256:e47e67bd612030cb1bedee2bde85b73913f2ea021573b749deb21d94940f03c1` (10.2.1). The disposable container used no network, a read-only root filesystem and no capabilities; bgpd ran without kernel installation, zebra connection or BGP/VTY listening sockets. Actual replies normalized version `10.2.1_git`, connected bgpd, an Active neighbor with zero reported prefixes, and locally originated IPv4/IPv6 RIB best paths. Missing bfdd returned a command failure. This did not establish live peer connectivity, kernel FIB installation, BFD operation or target RHEL compatibility. The fixture tests additionally cover all six BGP session states, count presence/absence, path selection and BFD down. No operational VPC was queried or modified.

The agent's existing build identifier continues to hash the policy-agent script itself; it does not attest the contents of auxiliary collector modules. Collector report schema and strict receiver validation identify supported telemetry shapes, not installed-source integrity. Fleet deployment already copies the whole agent directory, while npm packaging and manual installation include the new auxiliary modules. A future signed release/version attestation should bind the complete installed module set.

A local Node 26 synthetic measurement of the 512-resource ceiling (one site, one network, 510 mutually overlapping subnets) generated 129,795 validation issues in approximately 36 ms. The registry returns at most 128 issues to the client. This exercises one deliberately dense conflict case, not every graph shape or a production latency guarantee; input and persisted-data bounds remain necessary.

The integrated worker deliberately tightens the library defaults: each command gets two seconds, the collection gets 30 seconds total, and each command's capture is capped at 128 KiB before the final 128 KiB transport-envelope bound. This differs from the standalone library's three-second/one-MiB defaults. Scheduler tests hold a benign child while the actual policy main loop reaches its mocked heartbeat transport and a separate timer callback fires. They demonstrate isolation; they are not a real kernel rollback with a stalled collector. The existing real-kernel CI rollback suite separately verifies the preserved policy behavior.

Legacy migration is explicit: the existing pure `validateNetworkInventory()` API still accepts its earlier shapes, but a desired registry is a narrower destination. Import only desired resources; retain learned routes and observed-generation evidence outside that document, and keep historical adoption evidence separately until a real adoption workflow exists. New `adopted` claims are refused rather than upgraded from strings. This is not a migration of running host ownership. Stop and resolve validation/ownership conflicts before committing a batch; never treat inventory import as configuration deployment.

Relay telemetry storage fails immediately with a generic 503 when its local store lock is occupied; it does not wait synchronously for a competing writer. A stale-lock probe measured the original one-second wait delaying a 20 ms Node timer to roughly 1,025 ms; the fail-fast path returned in roughly one millisecond and the timer fired at 20 ms. This removes the intentional lock wait, not all shared-process latency: bounded validation and synchronous filesystem reads/fsync still use the relay process. Separate agent collection prevents command/upload stalls from blocking its policy loop; it is not a hard real-time guarantee for every resource shared with the relay.

Transport validation allows at most 2,048 rows per successful query and 2,048 elements in a normalized nested array. The integrated sender applies the same ceilings before upload. A query exceeding either limit becomes output-limit without data, while unrelated query results remain intact; the sender does not label a truncated table successful. The combined envelope still has its independent 128 KiB ceiling.

Optional relay telemetry storage is initialized lazily at its own endpoint. An obstructed or unavailable observation directory returns a generic telemetry 503 without preventing Relay startup, health checks or legacy heartbeats. Persistent registry and observation reads open a regular file without following a final symlink, use the same descriptor for size validation and bounded reads, and close it in all cases. A file replacement or growth between validation and reading cannot turn the read into an unbounded path-based load. The size cap remains enforced during the read, not only by an earlier stat.

## Phase 4: offline orchestration foundation

### Implemented boundary

This delivery adds offline comparison, planning and configuration compilation. It does not introduce a network execution driver, extend an agent command, grant adoption authority or connect these results to the existing firewall publisher. Every new artifact has its own schema version and kind; plans and templates are `dry-run` and `executable: false`. A generated template is not a valid deployment authorization.

### Observation clocks and recovery

The store admits at most 30 seconds of future skew for collection completion and relay receipt. This is a deliberately conservative acceptance policy, not a measured synchronization guarantee: it is much shorter than the default 300-second collection interval and 600-second freshness window. Larger offsets fail closed and need clock investigation. Old reports may be retained for diagnostics, but collection time, relay receipt and manager receipt each constrain freshness. Updating local receipt never rejuvenates an old collection. Matching additionally requires valid local receipt and, for source-scoped manager evidence, relay receipt.

Normal writes do not replace a future-poisoned record. A trusted local operator can call `NetworkObservationStore.recover(host, report, {expectedCollectionId, actor, reason}, metadata)` after fixing the clock. It compares the current collection identity, requires a recent replacement, and archives the previous record before replacing it. This method is not exposed as an unauthenticated HTTP endpoint. Recovery preserves evidence; it is not automatic adoption or policy confirmation. Per-source/host recovery archives are capped at 32; further recovery fails closed until an operator explicitly retains and manages those files offline. Recent collection IDs are persisted to reject retransmission across restarts; this bounded history is not an all-time replay ledger. Authenticated observations remain host claims, not independent health proofs.

### Identity and drift

`matchNetworkInventory` accepts a registry snapshot, observations, an explicit evaluation clock, and trusted bindings `{source, host, siteId, nodeId}`. The source is the configured relay trust scope. These bindings belong to the trusted caller; an offline JSON file cannot authenticate a host merely by naming one. Site/node references and ambiguous identities are rejected or classified unknown. Interface names are used only after this identity binding. Explicit VRF domains additionally require interface master evidence; external domains cannot be inferred from host links.

Supported comparisons are interface presence and optional desired MTU, and route destination/table/interface. IPv4/IPv6 prefixes and standard table aliases are normalized. The current registry has no desired WireGuard peer or BGP session settings, so those telemetry queries are not represented as declarative drift. Counters, handshake times, link operational state and BGP session/prefix counts never become configuration differences.

| Classification | Meaning |
| --- | --- |
| matched | Supported declarative fields agree; no connectivity claim |
| missing | A fresh successful relevant collector, with verified identity/domain prerequisites, lacks the desired identity |
| different | Supported declarative fields differ |
| unknown | Identity, required receipt, relevant field, or successful collection evidence is absent/ambiguous |
| stale | Retained evidence exceeded its validity window or has invalid future clock evidence |
| unsupported | Resource/domain or collector cannot support the comparison |
| unexpected | A successful collector observed an unclaimed object; it remains external |

External ownership is retained in results and never produces a repair proposal. Adopted metadata cannot authorize a writer.

### Deterministic planning

`buildNetworkPlan` recomputes matching; callers cannot submit a preclassified match as authority. It binds the registry revision, resource generations and digests, trusted identity bindings, exact observation digests, collector capabilities, explicit evaluation time and dependency graph. Caller-selected `id` is a review label outside `contentHash`. Object keys and set-like resource/binding/dependency collections are canonicalized; the observation report's arrays remain exact evidence, so changing their order changes its digest. There is no generated UUID or implicit current clock in the plan.

Dependencies come from inventory references and optional explicit `{resourceId, dependsOn}` edges. Missing references and cycles block an ordered plan. Proposals are limited to modeled managed interface/route creation or updates. A failed/unsupported collector, stale evidence, ambiguous identity, revision mismatch, invalid inventory or ownership conflict prevents an execution-ready result. Independent management/gateway connectivity, write capabilities, approval and durable undo are not yet implemented and remain explicit blockers/preconditions. This analysis neither auto-repairs drift nor schedules reconciliation.

The canonical helper shares the sorted JSON approach used by the registry while deliberately remaining separate from the signed policy bundle byte format. It rejects non-JSON numbers, sparse arrays, exotic objects, accessors and cycles rather than producing ambiguous hashes.

### Offline CLI

```
node bin/heliopause-network-plan.ts INPUT.json
node bin/heliopause-network-compile.ts wireguard INPUT.json
node bin/heliopause-network-compile.ts frr INPUT.json
```

Planner input contains `id`, `registry: {revision, resources}`, `expectedRegistryRevision`, `observations`, `bindings`, explicit epoch-millisecond `now`, and optional `maxAgeMs`/`additionalDependencies`. Compiler input contains `registry`, `expectedRegistryRevision` and a closed versioned `spec`. WireGuard also accepts a prior artifact for a hash-only interface diff. Exit 2 means a blocked plan or invalid compilation; exit 1 means malformed input/usage. No CLI has an apply option or network transport. Inputs must be trusted local exports; copying JSON is not an authentication mechanism.

### WireGuard compilation

`compileWireGuard` supports an explicit `wg-quick` full-mesh specification referencing an overlay network, gateways, managed WireGuard interfaces and independent underlay interfaces. Gateway entries declare tunnel host addresses, public keys, literal public endpoint/port, listen port, allowed local prefixes, opaque private-key references and optional MTU/keepalive. Tunnel addresses must fit declared tunnel pools; allocation is not performed. Duplicate addresses/keys/peers and overlapping peer cryptokey ranges are refused. Management and Kubernetes ranges are not implicitly exported.

Templates intentionally omit `PrivateKey`; references are separate metadata and no secret provider is invoked. `Table = off` belongs only to this `wg-quick` backend, not a generic interface option or `wg setconf`. Peer tunnel host routes are separately listed, so a `/32` or `/128` address is never assumed to create peer reachability. Underlay endpoint reachability and policy routing still require independent verification. The template hash binds the normalized intent and desired snapshot. The optional previous-artifact diff exposes only interface hashes and added/changed/removed labels, not prior raw template contents.

### FRRouting compilation

`compileFrr` generates narrow eBGP templates for explicit FRR `8.5.6` and `10.2.1` targets, with IPv4/IPv6 address families and a primary managed native/WireGuard plus secondary external Cloudflare backbone for each remote node/family. It requires explicit private ASNs, router ID, peer/source addresses, inventory interface/network references and declared peer reachability routes. External interfaces are referenced, never reconfigured. Only global routing domains/main-table reachability are currently supported; other domain semantics are refused.

Each peer receives exact inbound and outbound prefix allowlists and default-deny route maps. Inbound local preference 200/100 expresses backbone preference. Outbound filtering also requires an empty AS path, preventing learned eBGP routes from becoming transit exports. `network import-check` remains enabled; no `redistribute` or automatic service/default advertisement is generated. Only explicit site-local infrastructure subnet references are supported. Any overlap with management, Pod or Service reservations is refused, including an infrastructure aggregate covering such a pool. Service VIP approval and independently verified Pod summaries are future work and fail closed today. BFD is optional syntax, never a failover claim.

The reviewed syntax follows the official FRR stable-8.5 and stable-10.2 BGP/route-map manuals. Unit tests verify generation and filters, not daemon acceptance on every build. A container syntax check, real BGP/BFD sessions, FIB installation and packet forwarding were not established in this sandbox; exact runtime compatibility is a deployment gate, not a consequence of selecting a version string.

### Remaining execution work

The compilers are separate offline previews; they are not yet bound into one signed, approved executable ChangeSet. A future planner must bind exact compiler artifacts, independent reachability evidence, secret versions and per-driver recovery requirements before any execution protocol can accept them. Next gates are: WireGuard driver with local secret resolution and explicit host routes; NetworkManager/nmstate persistence; FRR driver with config validation and durable undo; dependency-ordered multi-site changes; independent management checks; dual-backbone withdrawal/failover rehearsals; restart recovery; and staged operational migration. Rollback must remain local when manager/relay connectivity is lost. Network Overview UI is deferred until these analysis contracts are stable.

## Dynamic routing fabric (BGP-driven)

### Why the direction changed

The Phase 4 previews put routing decisions into configuration that every gateway carries. `compileWireGuard` uses one interface per gateway with per-peer `allowedPrefixes` and refuses overlapping peer ranges, so WireGuard itself decides which remote prefixes reach which peer. `compileFrr` gives each peer exact `importSubnetIds`/`exportSubnetIds` lists. In that shape a new subnet, Service VIP or site requires regenerating and redeploying every gateway, and BGP cannot move traffic between backbones because the tunnel refuses destinations outside its AllowedIPs.

The fabric model moves path selection to BGP and leaves configuration to describe identity and limits:

| Concern | Phase 4 preview | Fabric model |
| --- | --- | --- |
| WireGuard | One interface, peer AllowedIPs = remote prefixes | One interface per peer, `AllowedIPs = 0.0.0.0/0, ::/0`, `Table = off`; the tunnel binds a key to a path only |
| Which prefixes use which tunnel | WireGuard AllowedIPs | FRR-installed kernel routes |
| Peer filters | Exact per-peer subnet lists | Derived from each site's **origin blocks**: management and tunnel pools denied, Service and load-balancer pools host routes only, block `le 32` permitted, AS path limited to the peer ASN optionally followed by its own cluster ASNs |
| New subnet or VIP inside a block | Every gateway changes | Only the owning gateway changes (if it originates it), or nothing (if a cluster speaker announces it) |
| New site | Every gateway changes | Every existing gateway gains one peer (full mesh), one gateway is added; existing tunnel names and ports do not change |
| Secondary backbone | eBGP over it | eBGP at local-pref 100, or `static-fallback`: remote blocks at kernel metric 200 so FRR's eBGP routes (metric 20) win while they exist |
| Firewall | Not coupled | Still not coupled. A learned route is never an access grant; firewall policy keeps referencing declared zones |

### Implemented in this change

`src/network-inventory.ts` adds four resource kinds and one pool purpose, all inventory only:

- `address-allocation`: one address in a pool, `reserved` or `allocated`, optional consumer. A managed allocation requires a pool whose `allocationAuthority` is `heliopause`; an external one records another allocator's choice. Kubernetes Pod/Service pools reject both. Duplicate addresses are refused within connected routing domains. Free-address selection and leases are still not implemented.
- `bgp-router`: `gateway` (FRR-managed or external) or `cluster` (always external, e.g. Cilium). Private ASNs only. One ASN per site, distinct across sites, and cluster ASNs distinct from every gateway ASN. Gateways declare `originSubnetIds` (site-local, non-management) and `advertiseSubnetIds` inside them, plus a stable `fabricIndex`.
- `bgp-fabric`: `full-mesh` topology, one primary and optional secondary transports over backbone overlay networks, `bgp` or `static-fallback`, `listenPortBase` for native transports, optional BFD.
- `fabric-attachment`: one gateway router on one transport, with a tunnel address allocation from a `tunnel` pool of that network. Native attachments carry endpoint, public key and an opaque private-key reference; external attachments reference the existing externally managed interface and carry no keys.
- Pool purpose `kubernetes-loadbalancer` for in-cluster VIP allocators. Such a pool must not overlap the Service pool: the API server does not know it and may allocate the same address as a ClusterIP. The existing pool-overlap check enforces this.

`src/network-fabric.ts` adds `planBgpFabric` and `diffBgpFabricPlans`, exposed through `node bin/heliopause-network-compile.ts fabric INPUT.json` (`INPUT`: `registry`, `expectedRegistryRevision`, `fabricId`, optional `previous` plan). The plan is `dry-run`/`executable: false` and contains, per gateway, the per-peer WireGuard interfaces (template without `PrivateKey`), listen ports, FRR configuration text, fallback routes and a content hash. Listen port on gateway A toward B is `listenPortBase + B.fabricIndex`; B's endpoint port for A is therefore `listenPortBase + A.fabricIndex`, so adding a site never renumbers existing tunnels. Interface names are `hpf` plus twelve hex digits derived from fabric, transport and the two routers.

In-site cluster speakers peer only with their own site's gateways: inbound they may announce Pod pool prefixes and host routes from Service/load-balancer pools; outbound they receive nothing (`RM-DENY-ALL`). Gateways re-export cluster-originated paths, and peers accept them through the AS-path filter.

`src/network-fabric.test.ts` covers the shapes above, including the site-addition and subnet-addition change scopes. The single-point mutations used to check those assertions, and the test each one turned red, are listed in the pull request that introduced the module.

### Not established

- **Namespace lab, not hosts.** `scripts/network-fabric-lab/` runs `planBgpFabric` output for a synthetic four-site fabric in a disposable `--network none` container (FRR 8.5.6 and 10.2.1, pinned images; CI job `BGP fabric FRR …`). It checks, separately: FRR parses every planned config; every per-peer native tunnel and the external backbone carry packets; every gateway establishes its native, external and cluster sessions; all twelve site pairs use their own native tunnel (BGP best path, kernel FIB, WireGuard byte delta, packets); the cluster VIP and Pod prefix propagate while the cluster's infrastructure subnet and Service aggregate are refused; one native link down moves only that pair to the external backbone; silent loss on one link with interfaces up (AllowedIPs emptied) is detected by the BGP hold timer and fails over; all-native-down and recovery; management, Service aggregate and tunnel pool cannot leak; a metric-0 kernel route shadows the BGP selection. Measured convergence on a developer Mac (Docker Desktop, lab timers keepalive 1 s / hold 3 s): single link 2.6–3.0 s, silent loss 3.1–3.5 s, all down 0.15–0.28 s, recoveries 1.7–2.3 s. These are lab measurements under lab timers, not expected production failover times.
- **Found by the lab.** The first planner revision omitted `disable-connected-check`; FRR refused every fabric session (`No path to specified Neighbor`) because tunnel peers sit behind /32 host routes. Fixed; the unit test now asserts it. A single-point mutation removing the Service-pool deny line was caught by the leak check (`('leaked', '10.40.192.0/18', 1)`).
- **Still not exercised.** The external backbone is a simulation (one WireGuard interface with per-peer block AllowedIPs), not Cloudflare Mesh; whether BGP runs over the real mesh is unknown. The cluster speaker is FRR, not Cilium. `static-fallback` mode, BFD sessions, IPv6 forwarding, RHEL/Rocky hosts and reboot persistence are not covered.
- **The existing WireGuard execution drivers cannot run this shape.** `agent/network_executor.py` (`validate_operation`) accepts only `/32` AllowedIPs equal to its installed routes, and the persistent NM driver derives interface names from its profile UUID. Executing a fabric needs a new driver operation (AllowedIPs `0.0.0.0/0, ::/0`, peer host route only, routes owned by FRR), with its own recovery tests.
- Intra-site iBGP between two gateways of one site is not generated (a warning is emitted). Dual gateways per site need that, or an equivalent, before they can carry traffic for each other.
- Whether BGP can run over the external secondary overlay, and how that overlay currently installs its routes (table and metric), remain discovery gates. A metric-0 route to a remote block beats every BGP route.
- Cluster-side BGP objects (for example Cilium BGP peer and advertisement resources) stay owned by the cluster. The plan states the peer address and ASN they must match; nothing compares them yet.
- `compileWireGuard`/`compileFrr` and the unified ChangeSet still use the Phase 4 shape. They are unchanged by this work and should be retired or rebased onto the fabric plan once a fabric driver exists.

### Revised next steps

1. Syntax-check generated FRR text in a disposable FRR container; then two-to-four namespace/VM gateways with real sessions, kernel route installation and packet tests, including primary loss, fallback and recovery.
2. Fabric WireGuard driver operation and recovery (new driver identity, AllowedIPs `0/0`, peer host routes, FRR-owned destinations), reusing the existing signed execution, journal and confirmation path.
3. FRR driver: write `frr.conf` fragments with validation (`vtysh --dryrun` or equivalent), durable undo and confirmation.
4. Bind the fabric plan into the signed ChangeSet in place of the Phase 4 WireGuard/FRR previews; stage rollout gateway by gateway, keeping the existing backbone until the new path is independently verified.
5. Cluster integration: compare declared cluster routers with observed BGP peers, then optionally generate the cluster-side manifests for the cluster owner to apply.
6. Free-address selection on `heliopause`-authority pools (tunnel addresses, fabric indices) and firewall zone references derived from inventory.
