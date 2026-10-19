# Network Control Plane architecture and delivery plan

Status: proposed target architecture; implementation status must be checked against the accompanying source changes. Reviewed against base `08d428b` on 2026-10-19. This document contains no operational inventory. User-provided site addresses, identifiers, endpoints and proposed ASNs belong in private inventory, not this public repository.

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

The target model separates management mode (managed, external, imported) from driver identity and allocation authority. Here imported means recorded external configuration awaiting an explicit adoption decision. The initial implementation instead names its modes `external`, `managed` and `adopted`; it has no `imported` mode. Its `adopted` record requires nonempty `approvedBy` and `source` strings, which are structural metadata checks, not authentication, authorization or verification of a real approval. External/imported resources in the target lifecycle remain observation-only until an explicit adoption plan proves compatibility and records approval. Admission must reject two desired writers claiming one interface, route identity or configuration file. Matching an observed object does not grant permission to adopt it. A future ownership registry also needs persistence and atomic conflict checks; a pure validator alone cannot arbitrate concurrent managers.

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

The shipped first slice in `src/network-inventory.ts` contains eight resource kinds (`site`, `node`, `gateway`, `network`, `subnet`, `address-pool`, `interface`, `route`), a pure runtime inventory validator, management/driver ownership metadata and a pool-prefix foundation for IPAM. It does not allocate or reserve individual addresses, execute drivers, persist a resource registry, collect live state or deliver network changes. The validator reuses the existing `cidrRange` parser: ordinary IPv4 and IPv6 prefixes are supported, but IPv4-mapped IPv6 prefixes written with a dotted-decimal IPv4 tail are unsupported. The `route` resource describes inventory intent; accepting its shape does not authorize an existing agent to apply it. Rows above describe the broader delivery sequence; remaining acceptance criteria are future work, not claims of functionality. No driver mutation, agent deployment, Cloudflare change or live network migration is authorized by this document.

Before any operational migration: collect current link/address/route/rule/WireGuard/FRR/CNI state through an approved read-only path; resolve owners and unknowns; back up configurations and secrets privately; verify console/out-of-band recovery; review generated change and undo plans; rehearse in disposable infrastructure; obtain separate approval; roll out one canary and independently verify packet paths before proceeding. Manager failure must leave committed data-plane configuration running; it must not disable local recovery for an unconfirmed change.
