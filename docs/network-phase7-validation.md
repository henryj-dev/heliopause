# Consecutive network executions and authenticated terminal settlement

Base: PR200, `6a5b57d3417d916791137268821439ad53aed72a`. Scope: repeated bounded execution and authenticated settlement on one isolated gateway. No operational network changes.

## Audit and trust boundary

Existing Agent/enrollment keys are P-256, critical clientAuth/digitalSignature, CA:false (`src/pki.ts`, `agent/heliopause-enroll.py`). Relay authentication proves Agent-to-Relay identity, not an end-to-end terminal assertion to Manager. This implementation therefore uses **direct Agent-to-Manager mTLS**, not a new generic certificate signing use or a Relay claim. Every configured execution target pins source/host/node, a fresh journal identity and leaf SHA256. TLS authorization, clientAuth EKU, CN and exact leaf pin are required. Configured per-request revocation applies before machine routing. Retiring an Agent key requires updating the configured revocation file and/or removing its target pin; do not keep an old pin as an implicit key-rotation policy. Browser/session/bearer callers cannot use the terminal endpoint.

`heliopause-network-terminal-mtls-v1` is an authenticated transport contract/domain, **not a portable signed envelope**. It may not be accepted through Relay. New execution authorization is schema2 under `heliopause-network-execution-v2`, with an approved journalId; dry-run ChangeSet remains executable:false. Manager/verifier private keys never reach Agent.

Explicit Agent journal provisioning generates a fresh random identity; callers cannot choose an old identity for an empty replay ledger. Runtime missing/corrupt journal refuses new execution/reporting instead of initializing. Reprovisioning requires new Manager identity binding and reapproval; old authorizations mismatch. Legacy schema1 journals retain local recovery only and are not automatically settled. A legacy `.execution-fence` blocks migration until offline administrative reconciliation.

## Durable issuance and settlement

Registry schema2 requires an execution ledger containing exact envelopes, plan/authorization/artifact hashes, identity, journalId, revision, audit entries, cached confirm and terminal result. Explicit migration occurs before enabling issuance. Unissued proposals/approvals remain memory-only and need re-proposal after restart. Issued execution does not reuse their approval state: an authenticated retry retrieves the stored exact authorization.

The issued record and fence share **one Registry JSON document**. A successful atomic fsync/rename/directory-fsync commits them together. Confirmation issuance similarly stores its exact signed response before returning it; confirm-issued is not Agent-confirmed. A retry returns the same original window without extending it.

Terminal success is generated only in the same durable Agent terminal transition. The outbox is derived by reading that journal afterward. Confirmed proof commits the exact manager confirmation and independent verification; rolled-back proof requires the production removal path to verify absence. rollback-failed emits no successful terminal result and blocks subsequent execution. Terminal sequence and accepted-record count detect missing ledger entries. The bounded ledger is never pruned.

Manager verifies all terminal commitments and exact current fence. Settlement records the result/hash/audit and clears only that fence in the same Registry write. Identical old results are idempotent even when a newer fence exists; they never clear it. Conflicting results are rejected and audited. Execution expiry does not invalidate historical terminal authenticity. Current client credentials must still be valid, trusted and unrevoked; uncertainty retains the fence.

| Crash point | Durable state | Restart behavior |
| --- | --- | --- |
| Before issuance replace | Previous ledger, no new deliverable authority | Re-propose if needed |
| After issuance replace, before response | Exact issued envelope and fence | Authenticated retry retrieves it |
| After confirm replace, before response | confirm-issued with exact response | Retry returns original confirm, never a new deadline |
| After Agent terminal replace, before outbox | Durable terminal proof and replay record | Network restart or common mode guard regenerates outbox |
| Before settlement replace | Old issued/confirm-issued record and fence | Result retry settles |
| After settlement replace, before response | Settled result/audit and no old fence | Result retry returns idempotent success |
| Failed/ambiguous file write | Old or new complete document | Read/validate disk and fsync file+directory before cached authority/status/result export; never infer rollback from silence |

Registry operations use a narrow kernel flock on a stable inode. A Python helper acquires the flock on the **parent-opened descriptor inherited as fd3**, so helper death cannot release a live Node callback's lock. Parent death closes its descriptor; helper detects parent/pipe EOF and releases its copy. Lock path is never unlinked. Every Registry mutation, issuance, confirm and settlement shares this protocol. Legacy O_EXCL lock files are not guessed stale or deleted. Manager runtime now requires Python3; container packaging installs it. This is a local-filesystem, single-host locking contract, not distributed locking.

## Deadline and mode coexistence

Successful durable confirm releases the process-local driver deadline. New acceptance clears any stale deadline only after a validated disk ledger proves all previous work terminal; it never hides active rollback debt. This also handles a terminal rename followed by a directory-fsync exception. Existing rollback and restart deadline behavior remains fail-closed.

Network mode still replaces the firewall main loop: regular firewall heartbeat, discovery and monitoring are not continuously maintained by that mode. Both writer modes retain one shared writer lock; switching runs existing debt recovery first. Confirmed WG objects remain when switching back. The common guard regenerates the local terminal outbox before firewall mode, including a crash after terminal storage. The separate courier only reads the outbox and writes delivery acknowledgments; it never applies/rolls back and cannot block local deadline recovery. Its retry/timeout failures do not settle a fence by inference.

Normal provisioning:

1. Initialize inventory, then run `node --experimental-strip-types bin/heliopause-network-init.ts --registry <registry.json>` once. This cannot unlock old fences.
2. Run `python3 agent/network_executor.py --initialize-journal --state-dir <empty-owned-0700-directory>` once. Pin returned journalId and Agent certificate fingerprint in ManagerOptions and Agent configuration.
3. Configure protected local manager/verifier public-key rings, WG secret references and `terminalDelivery` with direct HTTPS URL, CA/client cert/key paths. Private key file must be owned0600.
4. Start the opt-in network writer and separate terminal courier. Operator GET `/api/network/execution/status` distinguishes issued (delivery unknown), confirm-issued and settled. Agent POST `/api/network/execution/terminal` is machine-only. No force-unlock endpoint exists.
5. Stop the current writer gracefully before switching services; keep the same Agent environment/writer lock. Existing unresolved debt blocks switching. Courier may remain running because it is not a network writer.

## Verification evidence

[PR201](https://github.com/henryj-dev/heliopause/pull/201) carries the final-head check links. The kernel workflow checks out the exact PR head (not a synthetic merge commit), reports `sourceCommit`, and requires all **38** scenarios; there is no partial-success or capability-skip mode. Final verification compares that report commitment with the PR head before merge.

First complete 38-case report: [run39369758067](https://github.com/henryj-dev/heliopause/actions/runs/39369758067), source `1a444e66aae288c004efc9c20dd6c8c2a56b952a`: **38 passed, 0 failed, 0 skipped**. Actual report environment: kernel `6.17.0-1022-azure`, wireguard-tools `v1.0.20210914`, iproute2 `6.1.0`, libbpf `1.1.2`. These values were read from this report, not copied from PR200. Host reboot was not verified. The final-head rerun is linked by the PR's “WireGuard durable transaction kernel lab” check and must report its own matching sourceCommit.

The 32 existing scenarios remain mandatory. Six new scenarios exercise confirmed→settlement→second execution, rolled-back→settlement→second execution, rollback-failed→fence retained→recovery→settlement, Manager restart and lost settlement response, Agent restart, and delayed/duplicate results. Five cases retain the same production Agent PID; only the explicitly named Agent-restart case changes it. Every second acceptance occurs after the first rollback deadline. Each case ends with two durable terminal/replay entries, two settled issuance records and no active fence. Separate second-interface address, secret, listen port, host routes and bidirectional workload addresses are asserted before independent confirmation. Confirmed first interfaces remain; rolled-back first interfaces are absent.

The lab starts the production Manager in the separate verifier namespace and uses real direct mTLS across the management veth. The production Agent applies/removes interfaces and routes; lab helpers prepare only peers, workload/management transport, credentials and signed approvals. A response-drop hook kills Manager after production settlement commits and before acknowledgment. Courier retries the identical result after restart. No ledger is pruned and no fence file is deleted to make a case pass.

Local network Executor tests: **60 passed, 0 failed, 0 skipped**, including real Linux preflight deadline regressions, disk terminal export barriers, real fresh-process recovery, and six courier tests. Original deadline failure was reproduced at the second real Linux preflight before the fix. Focused Node coverage includes 12 issuance, 24 settlement, 7 actual-mTLS Manager API and 14 Registry tests. Settlement tests include real SIGKILL before/after the atomic replace, simultaneous real-process Registry mutation, corrupt/missing storage and post-rename directory-fsync failure. Transactions tests guard subprocess.run and socket.socket, use a fake apply driver and replaced signature/trust boundaries, and allow Popen only for the fixed fresh-process journal reader. Deadline regressions use real Linux preflight/run with command, snapshot and secret-read boundaries replaced. Ownership tests fake ip/run reads and guard subprocess.run; NetlinkCreate supplies a fake socket channel. WriterMode replaces legacy recovery helpers and guards both subprocess entry points. Courier tests replace SSL/opener, guard run/Popen/socket, and retain production protected-file validation. Temporary file writes are real. These are class-specific boundaries, not a claim that one stub isolates every test. No mutation testing was performed.

Intermediate failures were investigated rather than accepted as skips: the first expanded lab passed the existing32 then failed because source-only staging lacked tracked `packages/i18n`; the allowlist now includes that source. Full CI caught missing shared CLI language setup and explicit image classification for the offline migration tool. CodeQL flagged the negative permission test's temporary chmod; it now injects insecure fstat metadata without weakening any real file permission or the production rejection check.

The first full green public CI is [run39370216828](https://github.com/henryj-dev/heliopause/actions/runs/39370216828) at `55e89a8caf175f3317a178053a61c4ada8bf9e74`. Actual collected counts:

| Suite | Executed | Failed / skipped |
| --- | ---: | --- |
| Root src + examples | 3003 | 0 / 0 |
| Manager workspace | 8 | 0 / 0 |
| Web workspace | 321 | 0 / 0 |
| Firewall Agent validation | 369 | 0 / 0 |
| Enrollment | 16 | 0 / 0 |
| Discovery | 39 | 0 / 0 |
| Discovery worker | 22 | 0 / 0 |
| Network Executor + courier | 60 | 0 / 0 |

Thus public unit suites execute **3838 tests**, with kernel scenarios reported separately. Local whole-suite execution is not reported green: root collected3003, passed2931, failed4 and canceled68 due to sandbox-denied Unix sockets and `/dev/tty`; Manager8 and Web321 passed. Local default LibreSSL skipped12 of369 firewall validation cases; CI ran all369 without skips. Network Executor's explicit OpenSSL3 run passed all60. No test or sandbox policy was relaxed to hide these differences.

Full CI separately runs firewall real-kernel rollback, mTLS round trip, and FRR 8.5.6/10.2.1 packet-forwarding regressions. They are not substitutes for these38 transaction scenarios. A clean checkout contains no private policy test checkout; public tests do not claim that separate site's coverage.

## Limits and next steps

Completion means safe terminal settlement and repeated bounded transactions in an isolated single gateway. No FRR writer, existing confirmed interface update/delete, NetworkManager persistence, host reboot restore, production network control, Cloudflare/WARP, Kubernetes or multi-site saga.

Emergency reconciliation remains offline: stop all Registry writers and the Agent writer, preserve the complete Registry/journal/outbox/ack evidence and backups, authenticate the target, inspect actual ownership/address/route state, repair rollback debt with its original recovery path, and obtain an authenticated terminal result. Do not delete an unknown fence or reinitialize a lost replay ledger. A lost/corrupt issued record or journal requires evidence-based operator recovery and new identity/reapproval; the normal API cannot guess success. This PR adds no general force-unlock mechanism.

Priority: one long-lived writer lifecycle retaining existing firewall watchdog/heartbeat/discovery while serializing bounded network jobs; then separately approved FRR apply/undo; then explicit NetworkManager/host-boot persistence; multi-site rollout only after per-host lifecycle is proven. Do not split or remove the shared writer lock to simulate coexistence.

The follow-up lifecycle should start by recovering both firewall and network debt under the existing writer lock, then run one scheduler with durable job admission, local rollback deadlines independent of transport, and read-only heartbeat/discovery/status workers. Mode transitions must finish or safely roll back the current job before admitting a different writer; the separate terminal courier remains outside that critical path. Add service-level restart/status and watchdog continuity tests before enabling this always-on mode.
