# Pre-accept cancellation and Rocky10 boot preparation

Base: PR202, `125225cd6315935d6cf810ed6d3282401162c42d`. Phase A implementation and isolated validation; Phase B target discovery/preparation; Phase C blocked. No operational host/network was accessed or changed. Final exact-head evidence is recorded below and in PR203.

## Audit and retained boundaries

The current production paths are `agent/heliopause-pull.py` (common writer owner/main heartbeat/monitor/watchdogs), `network_lifecycle.py` (bounded mailbox and admission), `network_executor.py` (mutation flock, protected replay/undo journal, kernel WG driver), `network_terminal_delivery.py` (independent direct-mTLS courier), and `network_discovery_lifecycle.py` (bounded child). The Registry, issued records, current fence, requests, receipts and audit share `src/network-registry.ts`'s single durable document, guarded by `network-registry-lock.ts`; settlement remains in `network-execution-settlement.ts`. New request issuance is `network-execution-cancellation.ts`. `manager-server.ts` authenticates operator and machine endpoints separately. Existing phase6/7/8 validation documents and systemd services remain in place.

NetworkChangeSet remains dry-run/executable:false. WG execution remains kernel-only `linux-wireguard-v1`, new dedicated interfaces and explicit IPv4 host routes only. Execution still needs two different approving principals and independent verification/confirm. Heartbeat/discovery cannot confirm network work. No writer lock is split, watchdog stopped, queue added or replay/fence record pruned. Feature disablement restricts new execution, not local recovery/cancellation/reporting.

## Exact cancellation contract and authority

`POST /api/network/execution/cancel` (also normalized without `/api`) takes an exact `transactionId` and `authorizationHash`. It requires the existing authenticated writable operator principal, existing cross-site/CSRF rejection and existing OTP policy when configured. A read-only principal cannot cancel. This intentionally permits one writer to reduce one already issued authority: it cannot authorize new configuration, delete a confirmed object or unlock a fence. The denial-of-service power is scoped to that exact issued record and audited as `cancel-requested`; execution itself retains two-person approval. Supported principal names use the same bounded name grammar as Agent execution approval; unsupported names are refused before signing/caching.

The request uses existing Ed25519/SPKI identities and framing, with separate domain `heliopause-network-cancel-v1`, schema1. Payload binds transaction/fence, source/host/node, journalId, authorizationHash, artifactHash, Registry revision, requestedAt/requestedBy and the exact original signed authorization. No shell/path operation, wildcard cancellation, Manager private key or verifier private key is sent to Agent. Manager persists the exact signed cancellation with its record/fence before returning it. Retries/restarts return identical bytes and original actor/time. Requesting cancellation does not prove Agent receipt or release the fence; no expiry-only or offline auto-settlement exists.

Cancellation has no execution validity extension and no cancellation expiry: it only reduces this exact authority, so an authentic old cancellation can still prevent acceptance or report historical disposition. Agent verifies both Manager-domain signatures and all identity/hash bindings, but deliberately does not require the original execution/observation to remain fresh. Clock uncertainty does not grant permission to apply; the existing durable execution clock watermark is neither cleared nor reset.

## Agent serialization, states and reporting

The same nonblocking `executor.lock` and existing protected replay journal serialize accept/cancel. The persistent Agent still owns the common host writer lock. The mailbox checks `cancel.json` before `request.json`/`confirm.json`. Cancel is ledger-only and may proceed while firewall admission is busy or new execution is disabled. It never bypasses writer admission to run a kernel command.

| Durable winner/state | Cancellation behavior | Report and subsequent behavior |
| --- | --- | --- |
| No accepted row; cancellation persists first | reserve the exact replay identity as `cancelled-before-accept`, without preflight/secret/kernel calls or undo inputs | permanent tombstone; original live or delayed authority cannot create a link, even after restart |
| Accept persisted prepared/applying/verification/confirm wait first | persist `cancelRequested` plus `cancellation-rejected` diagnostic receipt | no never-accepted proof; pre-issued confirm is refused; original tick performs ownership-checked rollback |
| rolling-back / rollback-failed | retain real debt, request existing retry | diagnostic only; no fence release until actual rolled-back proof |
| confirmed | preserve object and confirmed history, no cancellation-driven deletion | original independently confirmed terminal result may settle normally |
| rolled-back | preserve verified undo history | original rolled-back terminal proof may settle normally |
| Unreadable/missing/mismatched journal | refuse | never initialize or export successful cancellation; retain fence/evidence |

The historical field `acceptedSequence` counts reserved replay identities (including tombstones); it is not evidence of acceptance. Actual acceptance has `acceptedAt`/undo/owner material; these are forbidden on a never-accepted tombstone. Existing schema2 journalId is retained; no tombstones are copied to a newly provisioned empty journal. Successful cancellation increments the existing bounded terminal sequence once; duplicate cancellation does not add a row/sequence. Missing cancellation material, orphan acceptance flags/diagnostic receipts, unsupported identity and damaged terminal commitments fail closed.

Normal confirmed/rolled-back results remain schema1/domain `heliopause-network-terminal-mtls-v1`. New cancellation reports use schema2/domain `heliopause-network-cancellation-mtls-v1` with the same exact target/fence/authorization/artifact/revision/journal/stateHash bindings. A never-accepted terminal proof contains `cancellationHash` and exact `acceptancePrevented:true`. An accepted diagnostic contains `cancellationHash` and the durable acceptedState; its sequence is the stable replay-row index, not a terminal success sequence. Both are persisted and fsynced before the read-only outbox can export them. New Manager/Agent support is required for the new contract; an older Agent ignoring the mailbox or older Manager rejecting schema2 leaves the fence, never silently falls back to rolled-back.

Manager authenticates the existing direct Agent clientAuth mTLS leaf, loaded CA trust and live revocation decision, CN, pinned DER fingerprint and configured journal/target binding. Relay claims and operator sessions cannot submit machine receipts. A successful terminal response says settled:true. Accepted diagnostics say recorded:true/settled:false; courier never consumes a terminal-ack slot for them, and retries until actual terminal proof supersedes them. Manager deduplicates them without unbounded audit growth. Outbox/transport errors remain separate from local rollback failure and do not gate undo. As in Phase8, this assumes a responsive filesystem/process scheduler; a synchronous disk hang is not a hard real-time guarantee.

## Manager state, atomic settlement and crash boundaries

Issued/confirm-issued/settled remains separate from cancelStatus requested/accepted-recovery-required/settled. Existing GET execution/status exposes the signed request, diagnostic/terminal evidence, audit, current fence and reason. A requested cancellation waits for Agent; an authenticated acceptance diagnostic says verified rollback is required. Unknown/offline state retains the fence. Exact never-accepted proof alone may release its exact current fence under the same Registry lock/replace as the result and audit. Original confirm issuance is not proof of Agent confirmation. Cancel issuance blocks further confirm issuance/replay; Agent also refuses a previously issued confirm after its cancelRequested is durable.

Duplicate historical receipts are idempotent and cannot release a later fence. Conflicting never-accepted/accepted proofs in either order are rejected, as are conflicting terminal results; refusal audit is preserved. An accepted diagnostic cannot settle rollback-failed. Legitimate cancellation can settle after the original authorization expires. No force-unlock endpoint exists.

| Crash boundary | Disk state | Recovery/retry |
| --- | --- | --- |
| Manager before cancellation Registry replace | original issued record/fence | retry exact request; no acknowledgment assumed |
| Manager after request replace, before HTTP response | cached signed cancellation + same fence | new Manager returns identical request; Agent acknowledgment still required |
| Agent before tombstone atomic save | no accepted/cancelled row | no success outbox; fence retained, original authority still requires normal validation |
| Agent after tombstone replace, before response/outbox | durable tombstone/terminal commitment | restart exports same proof and permanently blocks original authority |
| Accepted cancelRequested persisted | actual accepted undo debt + diagnostic | confirm blocked; tick/restart uses original rollback, including execution disabled |
| Manager before settlement Registry rename | old fence and record | no partial unlock; retry same authenticated result |
| Manager after settlement rename, before directory fsync/response | result/audit/fence update in one document | durable read/fsync barrier and replay return same settlement; no second-file atomicity claim |
| Corruption/lost journal or issued record | preserved error/unknown evidence | fail closed, stop new changes; repair/reconcile with independent evidence, never empty initialization |

The new Manager crash tests call the real settlement function, interpose only the Registry file's rename and SIGKILL immediately before or after it in a real child process. Agent races use separate real processes and actual production Executor flocks; signatures/driver are explicitly isolated fixture boundaries there. Real signature and kernel behavior run through the shipping persistent Agent entry in the kernel lab.

## Record/byte limits and operational lifetime

Manager still has256 records and4MiB total Registry limit. New issuance permits at most64KiB decoded authority and3MiB prospective Registry size, reserving1MiB for the active record's bounded cancellation/result/audit updates. Cancellation cannot be cached if its decoded payload would exceed Agent's128KiB decoder limit. Agent still has1024 replay identities,6MiB admission/reserved-journal threshold and8MiB hard storage ceiling. Capacity status now reports actual byte usage, byte ceilings and record usage/remaining; Manager reads its file size under the existing lock/durable barrier, Agent reports canonical journal bytes. These are storage visibility, not archival tools.

Full256/1024 fixtures validate refusal of new identities while existing work can cancel/undo/export/settle. They construct validated archival rows, not256/1024 actual applies. Legacy files beyond3MiB refuse new issuance but may still accept cancellation/settlement updates that fit within4MiB. If a legacy authority exceeds the cancellation decoder limit or the required bounded update cannot fit the total storage ceiling, retain the fence/evidence and reconcile offline. This PR does not promise unlimited reporting at a physically full/damaged disk or solve legacy byte exhaustion by pruning.

Certificate procedure: finish existing local debt/settlement with the currently trusted identity when possible; stop issuance during rotation; preserve journalId/replay/outbox and hashes. Independently inspect the new clientAuth leaf's CN/CA/EKU/DER fingerprint and validity (`openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 -ext extendedKeyUsage`, `openssl verify -purpose sslclient` on lab/public certificate files). Explicitly update Manager pin and courier credentials and restart/reload those services through their supported configuration path; CA/pin changes are not automatically reloaded and certificate issuance does not update pins. Test retired-leaf refusal, valid current leaf, journal binding and legitimate historical receipt separately. Keep historical Manager public signing keys available for pending requests; never deploy Manager/verifier private keys to Agent.

If revocation/pin replacement happened before debt settled, direct reporting must fail authentication: retain protected state/outbox/fence, independently establish original host/journal and actual kernel/undo state, then perform an audited credential rebinding/offline recovery. Do not convert network absence or a new certificate into never-accepted proof. Actual API revocation/pin rejection is tested; end-to-end operational certificate rotation was not performed.

Archival/replacement procedure remains manual and constrained: quiesce issuance and writers/courier, resolve all debt/fences, preserve complete protected Registry+journal+identity+locator+outbox+ack evidence with SHA256 and restrictive backups, independently verify archive integrity, and require explicit new identity/journal/pin binding before reuse. Never erase/reuse old replay identity. Fresh journal refusal of old authority is tested; a safe automated archival/replacement tool is not implemented. A missing journal with unresolved work is not an eligible replacement procedure. Record/byte warnings must be monitored before limits; no automatic pruning/rotation is added.

## Rocky10 / backend / VM status

User confirmed Rocky Linux10; NetworkManager remains unknown; no disposable VM is available. The repository's earlier Rocky10/systemd257 firewall deployment notes do not establish this target's minor, architecture, kernel or active manager. Local qemu-system-x86_64/Lima/libvirt commands are absent. No operational host was contacted to fill this gap.

[VM preparation inputs](../scripts/network-vm-lab/README.md) and its environment example define exact-image/checksum pinning, CPU/architecture checks, isolated role/network layout, bounded read-only information to collect and all13 actual boot cases with required boot IDs/PIDs/timestamps/packet evidence. The official [Rocky10 release notes](https://docs.rockylinux.org/10/releases/release_notes/10_0/) and NetworkManager [keyfile](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-keyfile.html)/[settings](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-nmcli.html) references inform preparation only. NetworkManager is a candidate, not an installed/selected working backend. No image checksum, VM creation, profile, service ordering or actual boot result is invented.

Phase C begins only after a disposable reboot-capable VM/hypervisor with console access, exact Rocky10 image/minor/architecture and actual network-manager/version inventory exist. Then select one backend, implement separate writer capability/approval/owned profile+undo, and prove unconfirmed profiles cannot auto-activate before Agent recovery. Actual VM boot ID change and independent management/bidirectional traffic are required; container/process restart cannot substitute. Existing kernel backend remains unchanged; hostRebootVerified=false. No FRR, NetworkManager persistence, confirmed-resource adoption/delete or multi-site execution is implemented here.

## Validation evidence

Exact final-head CI/kernel report and independent integration verdict are indexed in [PR203](https://github.com/henryj-dev/heliopause/pull/203) before merge; the implementation checkpoint below is deliberately labelled with its own source. Local focused: issuer12, settlement46, mTLS API7, Registry14 collected/passed79,0 fail/cancel/skip. Agent executor64, lifecycle25 and cancellation16 actually ran and passed,0 fail/skip. Existing firewall369, enrollment16, discovery39 and discovery-worker22 also passed in the fresh local runner. Existing source tests, mTLS and firewall kernel tests are retained. The kernel runner requires all original52 plus10 cancellation cases (62 total), with no silent capability skip. New cases use production persistent Agent, real signed Manager cancel API, direct pinned mTLS courier, actual links/routes and separate verifier/management paths.

New coverage: before-accept and busy-refusal cancellation, historical expiry, live late delivery, accepted rollback and rollback-failed/retry, confirmed object preservation, bad signature, SIGKILL before/after tombstone save, Manager request/result response loss/restart, and cancellation settlement followed by a next approved transaction while old delivery competes. Unit coverage additionally checks actual accept/cancel lock races in both orders, identity/hash/journal tamper, duplicate/conflicting receipts, damaged/missing journal, capacity/byte refusal, old result/new fence and real Registry rename crash boundaries. No mutation testing was performed.

One initial capacity test performed1023 individual fsync writes; it was deliberately interrupted, not counted as pass/fail evidence, then replaced by one explicitly labelled archival-fixture write. The optimized cancellation suite actually ran16 with0 skip. An initial new API test found the normalized route allowlist lacked cancel (404); fixed and the real API suite rerun successfully. Local signature/driver substitutions do not claim whole-kernel coverage. Private operational policy/PKI/site data is not connected or claimed tested. Final report must use its own kernel/tool versions and sourceCommit, not Phase8/checkpoint numbers.


### Measured implementation checkpoint (not the final-document source hash)

[Kernel run39382325859](https://github.com/henryj-dev/heliopause/actions/runs/39382325859) emitted sourceCommit `99a4bcff5c33dc98c9b2be79129d2b107d54b71c`:62 unique PASS,0 fail,0 skip, original52 retained,10 cancellation cases. Actual environment: kernel `6.17.0-1022-azure`, wireguard-tools `v1.0.20210914`, iproute2 `6.1.0`/libbpf `1.1.2`, backend `linux-wireguard-v1`, hostRebootVerified=false. This is Linux container kernel evidence, not a Rocky10 VM boot result.

| Cancellation checkpoint | Actual Agent PID/evidence |
| --- | --- |
| before acceptance |158→158; never-accepted result, one replay record, no interface |
| firewall busy → cancel → settle → next approved work |382→382; two distinct transaction IDs, two journal records, no remaining fence |
| expired authority, execution disabled |706→706; historical cancellation settles, no apply |
| accepted work |930→930; real rolled-back proof, not never-accepted |
| confirmed work |1186→1186; confirmed object retained |
| rollback-failed/retry |1479→1479; diagnostic cannot settle while debt exists; owned undo retry then rolled-back |
| wrong cancellation signature |1753→1753; no replay/kernel mutation until authentic cancellation arrives |
| SIGKILL before save |1960→1997; empty journal/no success before save; disabled new process persists cancellation |
| SIGKILL after save |2192→2229; durable tombstone survives, same proof regenerated |
| Manager response losses/restarts |2422→2422; cached request and result recovered by new Manager processes; fence settled |

[Hosted CI39382326749](https://github.com/henryj-dev/heliopause/actions/runs/39382326749) on that checkpoint actually collected/passed root3025, Manager8, Web321 (0 failure/cancel/skip), Agent369/16/39/22/64/24/16 (0 fail/skip). Current source adds the separately measured25th lifecycle test; final-head CI must confirm it. Separate firewall real-kernel23 and mTLS18 passed. FRR8.5.6 and10.2.1 forwarding passed [run39382325856](https://github.com/henryj-dev/heliopause/actions/runs/39382325856); these are not FRR execution-driver tests.

The complete local public run on the current implementation collected root3025:2953 pass,4 fail,68 cancelled,0 skip, due to the existing sandbox Unix-socket/TTY restrictions; Manager8 and Web321 passed and all seven Agent suites passed with the actual counts above. Type checks, web diagnostics (0 errors/warnings), web build, icon20 check, workspace-suite coverage and worktree leak scan passed. Hosted results are distinct from local failures. Independent reviewer executed Node79 and Agent64/25/16 focused suites,0fail/skip, and reviewed race/replay/settlement/storage/crash/boot-preparation boundaries. Final exact-head report/source/PID checks and all CI remain required before the PR merge.
