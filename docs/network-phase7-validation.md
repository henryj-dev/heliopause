# Consecutive network executions and authenticated terminal settlement

Base: PR200, `6a5b57d3417d916791137268821439ad53aed72a`. Implementation and final kernel validation in progress. No operational network changes.

## Audit and trust boundary

Existing Agent/enrollment keys are P-256, critical clientAuth/digitalSignature, CA:false (`src/pki.ts`, `agent/heliopause-enroll.py`). Relay authentication proves Agent-to-Relay identity, not an end-to-end terminal assertion to Manager. This implementation therefore uses **direct Agent-to-Manager mTLS**, not a new generic certificate signing use or a Relay claim. Every configured execution target pins source/host/node, a fresh journal identity and leaf SHA256. TLS authorization, clientAuth EKU, CN and exact leaf pin are required. Existing per-request revocation applies before machine routing. Browser/session/bearer callers cannot use the terminal endpoint.

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
| Failed/ambiguous file write | Old or new complete document | Read/validate disk; never infer successful rollback from silence |

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

Pending final exact-source kernel report and CI. Local named deadline regression reproduced the original `apply deadline elapsed` at second real Linux preflight before correction. Focused tests cover direct mTLS, Manager restart, response retry, tampering, historical results, result conflicts, missing storage and real SIGKILL around atomic settlement. Final counts and links will be recorded after actual execution.

## Limits and next steps

Completion means safe terminal settlement and repeated bounded transactions in an isolated single gateway. No FRR writer, existing confirmed interface update/delete, NetworkManager persistence, host reboot restore, production network control, Cloudflare/WARP, Kubernetes or multi-site saga.

Priority: one long-lived writer lifecycle retaining existing firewall watchdog/heartbeat/discovery while serializing bounded network jobs; then separately approved FRR apply/undo; then explicit NetworkManager/host-boot persistence; multi-site rollout only after per-host lifecycle is proven. Do not split or remove the shared writer lock to simulate coexistence.
