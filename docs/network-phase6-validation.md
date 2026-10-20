# Phase 6: bounded single-gateway execution and recovery

Base: `e623b1e344fda264eabb86307b7fbbf3e1028b53` (#199). Implementation under final validation; kernel results are recorded separately below.

## A. Existing paths and reuse

`src/artifact-signature.ts` signs firewall host envelopes; `src/approval.ts` implements propose → approve → claim → settle with authenticated principals and aliases/OTP identities from `src/manager-server.ts`. `src/relay.ts` is an untrusted courier. `src/protocol.ts` describes firewall heartbeat confirmation. `agent/heliopause-pull.py` persists nft/workload commitments before apply, recovers them before heartbeat, and uses an absolute deadline plus a local watchdog. Its heartbeat confirms the firewall generation; that is not an independent data-path verification. `src/json-store.ts` provides protected atomic writes and an exclusive Registry mutation lock. Discovery capabilities confer no writer permission. Existing firewall kernel rollback tests do not test the new driver.

Reuse: existing Ed25519 length-framed signing format/SPKI key IDs; Python bounded trust-directory loader, strict canonical signed JSON and OpenSSL verifier; existing approval state machine and Manager mTLS/session principals, OTP requirement and identity alias checks; Registry mutation locking. Python uses the same temp-file → fsync → rename → directory-fsync durability sequence as the existing Agent, with a process lock that the kernel releases after a crash. The TypeScript O_EXCL lock is retained for Registry writes, not used as an Agent restart lock.

Separate boundaries: firewall payload schemas cannot carry the new driver operations; heartbeat confirmation cannot prove independent forwarding. New signature domains are `heliopause-network-execution-v1`, `heliopause-network-verification-v1` and `heliopause-network-confirm-v1`. Existing firewall protocol/schema and `NetworkChangeSet.executable:false` remain unchanged. No FRR driver is introduced.

## B. Contract and authority

`src/network-execution.ts` binds a unique transaction (also deriving its approved `hp` interface name from the first12 transaction hex digits), exact source/host/node identity, Registry revision/generations, desired/review/observation digests, structured artifact, local snapshot precondition, explicit linux-wireguard-v1 capability, issue/expiry/rollback times, two-person approval identity and approved plan hash. Signature validity and approval validity are checked separately. First-writer policy supports two-person only, not firewall solo-OTP/break-glass modes. Approval evidence is the existing trusted Manager’s attestation of its authenticated approval state, not signatures by two operator private keys. No arbitrary command/path appears in an operation.

Manager endpoints `/api/network/execution/{propose,approve,authorize,confirm}` and read-only `GET /api/network/execution/review?hash=...` are disabled unless explicit `networkExecutionTargets`, signing key, distinct verifier public keys, Registry and observation store are configured in ManagerOptions. Default deployment does not enable this experimental API. Proposal bytes are retained in Manager memory; approval uses authenticated principal aliases/OTP identity and no self-approval. Authorization rebuilds the review from the current Registry and source-scoped cached authenticated observation and verifies both commitments. Manager restart loses unissued approvals and requires re-proposal. The protected Agent spool is only delivery; signatures authorize it, not filesystem presence.

Agent has no online Registry reader. Therefore issuance and all Registry mutations share the Registry lock; issuance installs a durable `.execution-fence` before returning the signed envelope. Any fence blocks every Registry mutation and subsequent issuance, even after its nominal authorization expired or Manager restarted. This deliberately trades availability for freshness. **There is no automatic fence release endpoint.** An authenticated operator must first reconcile the exact Agent terminal transaction and any residual rollback debt, stop outstanding deliveries, verify the authorization can no longer be accepted (expiry/replay state and clock), and only then remove that exact fence under exclusive administrative maintenance. No production procedure or automatic multi-host rollout is claimed. Never remove a fence merely because a timer elapsed.

Agent verifies exact identity, trusted signature, separate approval, expiry, replay ledger, artifact hash, observation age, declared writer version, absent interface, absent host routes, local precondition, secret/public key correspondence, and protected underlay/management paths. Registry revision freshness is provided by the persistent fence, not an invented local comparison.

## C. Durable lifecycle

| Crash point | Persisted state before effect | New-process action |
| --- | --- | --- |
| Before prepared is durable | No network write allowed | No operation to resume |
| Before create | prepared/applying with absent-object undo and unique ownership alias | Remove only owned objects if present |
| After atomic create+ownership group, before alias/configuration | applying, same undo/owner | Require the exact atomic group and transaction-derived name; clean only the empty interrupted create |
| During address/peer/route writes | applying, full approved object set | Validate partial ownership; remove owned interface/routes |
| After configure | applying plus configured fingerprint | Refuse deleting objects altered by another writer |
| Verification/confirm wait | awaiting-verification/awaiting-confirm, original absolute deadline | Roll back immediately, do not extend deadline |
| Before rollback/delete | rolling-back | Repeat ownership-aware delete |
| After delete before settled write | rolling-back, interface absent | Idempotent removal and rolled-back |
| Delete/ownership failure | rollback-failed + bounded diagnostic history | Retry locally; keep debt until removal is verified |
| Confirmed | confirmed + approval/replay commitment | Keep configuration; no boot reapply |

Prepared state records exact prior snapshot/protected paths, operation and rollback intent, owner alias, original absolute deadline and accepted wall/monotonic times. Every state transition is durable before its corresponding effect. Same transaction/same bytes returns existing state; different bytes under the same identity are rejected. Completed IDs remain in a bounded ledger; reaching capacity refuses new execution rather than pruning replay evidence. Histories are bounded and prospective prepared-journal size checked with recovery-growth reserve before acceptance. Linux driver command failures and ownership conflicts retain bounded secret-safe diagnostics; command stderr and rejected secret bytes are not stored. Recovery always runs even when `enabled:false`.

During a live process, wall-clock expiry, backward-clock detection and monotonic elapsed budget trigger rollback. Confirmation rechecks deadlines after cryptographic and local verification. Restart is an uncertainty boundary: all unconfirmed states roll back immediately, independent of clock correctness. No waiting window is reset.

## D. Driver and secrets

`agent/network_executor.py` uses a bounded exclusive RTM_NEWLINK create request plus `ip`/`wg` structured argv, not wg-quick; no hooks, shell, FRR, NetworkManager/nmstate profile or existing adoption. Registry's earlier `wg-quick` ownership metadata is checked at issuance, but the signed driver explicitly names `linux-wireguard-v1` and this kernel-only backend difference is intentional. Supports one new transaction-derived `hp...` WireGuard interface, one IPv4 /32 address, MTU1280..1500, bounded literal IPv4 peers, exact AllowedIPs /32 list and matching explicit main-table static host routes (metric42760). No default, connected-prefix shadow, management/endpoint recursion, existing-interface or existing-destination overwrite.

Local `secretRef` is a slug resolved only inside the configured local secret directory. Private keys are owned0600 regular files opened O_NOFOLLOW and passed through inherited `/proc/self/fd` descriptors; no temporary configuration containing a key, no key in Registry/authorization/journal/API/log. Restart undo does not require reading a private key. Confirmed reboot restoration and key rotation are not implemented.

Ownership uses a transaction-derived interface name plus an opaque high uint32 kernel group derived from the locally random journal owner. The group and approved MTU are installed by one exclusive bounded RTM_NEWLINK request (the iproute2 name-form create rejects group assignment); alias is set in a separate following command. A crash before alias is accepted for cleanup only with that atomic group, exact name and empty down WG shape. A foreign same-name create with the default group is preserved. The fully configured fingerprint additionally binds ifindex, group, alias, MTU, public configuration and addresses. Linux v6.14 [`rtnl_create_link`](https://github.com/torvalds/linux/blob/v6.14/net/core/rtnetlink.c) handles IFLA_GROUP and IFLA_MTU before registration; it does not install IFLA_IFALIAS there. Actual kernel output caught the earlier mistaken alias assumption. Foreign attached addresses/peers/routes/configuration produce rollback-failed; no destination-only route deletion is used. A root actor can forge ownership metadata; this is not a security boundary against a compromised root.

## E. Independent verification and execution mode

The executor is an alternative `heliopause-pull.py --network-executor` mode. Both entry modes hold one cross-process writer flock. Starting another service fails without stopping the existing owner/watchdog. A durable locator beside that lock records custom network config/state paths; the next mode recovers that journal before accepting work. Existing firewall recovery and coupled rollback settle pending nft/workload debt before network mode, while graceful firewall stop settles its watchdog debt. Graceful network stop rolls back unconfirmed work; SIGKILL relies on durable recovery in the next process. Both installed units read the same Agent environment and must use the same writer lock; changing that trusted deployment configuration to use different locks is unsupported. The lab verifies two real production entry processes contend for one fixture lock; direct mode-guard unit tests stub the legacy recovery entry points and reject escaped subprocess calls. This does not claim a new combined firewall/WG transaction. Normal heartbeat and discovery never confirm this transaction. Protected-spool delivery permits a separate authenticated courier without creating a new network listener.

A verifier uses a distinct trusted Ed25519 ring. Overlap with Manager trust is rejected before new acceptance and confirm, while rollback never depends on keyring availability. Its bounded receipt binds transaction, authorization hash, artifact hash, timestamp/expiry, nonce and every named check. The authenticated Manager confirm endpoint checks the separate verifier signature and every bound result before issuing an explicit manager-signed confirm; the Agent additionally verifies its live local configuration/FIB/protected paths and fresh WG handshake before final confirmation. Neither a manager signature without verifier evidence nor verifier evidence alone confirms anything.

The isolated lab places gateway, fixed peer, gateway workload, peer workload and verifier in separate namespaces. Management veth links gateway to verifier and differs from the WG underlay and workload links. A separate verifier process checks interface/address/route/FIB, both workload directions, remote management connectivity, protected address/route and handshake. Lab probe tooling has namespace privileges; it is not a claim of OS privilege isolation against root. The Agent never receives verifier signing material through its configuration.

## F. Verification

Pending final CI. New unit tests and the isolated kernel workflow are separate from the existing firewall real-kernel rollback workflow. Kernel tests use the actual Executor/LinuxWireGuard apply and rollback paths; crash fault observers do not implement alternate network writes. Normal apply uses the production Agent entry point. SIGKILL/new-process tests leave durable state and real kernel objects in place. No host reboot test is claimed. Peer host-route loss after down/up (explicitly injected if retained by a kernel) must fail forwarding/FIB verification and trigger rollback; no test helper restores routes to manufacture confirmation. Fixed peer/workload/veth/sysctl setup is lab provisioning; only the target interface and its approved host routes are Agent writes.

## G. Limits

No operational network is touched. This is not production readiness. FRR execution, actual Cloudflare/WARP, Kubernetes CNI/Service translation, NetworkManager persistence, host reboot restoration, IPv6 forwarding/BFD and multi-site rollout are excluded. Long-term stability is not established. Fence reconciliation needs a future authenticated terminal-receipt protocol before general operations; this first path deliberately cannot silently unlock Registry mutation after an uncertain delivery.

## H. PR/evidence

Draft implementation PR: [#200](https://github.com/henryj-dev/heliopause/pull/200). Final head, CI counts/links and merge are recorded after verification.
