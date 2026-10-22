# Network authority lifecycle policy and trial gates

Runtime scope remains [Phase10](network-phase10-validation.md). Historical evidence/custody is
[Phase11](network-phase11-evidence.md). The following is policy and tool behavior, not a record
that certificate/key rotation, journal replacement or a24-hour run has passed.

## Trust paths in current code

| Material | Stored/loaded | New execution / in-flight confirm / cancel | Delivery/settlement | Confirmed next-boot restore |
|---|---|---|---|---|
| Agent mTLS leaf/private key/CA | Agent env and terminalDelivery files; Manager `networkExecutionTargets` exact certificate SHA256+source/host/node/journal | Transport identity; never substitutes for signed execution/confirmation | Direct authorized CA+clientAuth+CN+exact pin; configured revocation per request | No signature authority; journal identity must remain unchanged |
| Manager Ed25519 execution/confirm/cancel signer | Manager process private key; Agent `managerKeys` public ring, read for each verification | Exact envelope keyId (SPKI SHA256), domain and canonical payload; old authorization remains required inside cancellation | Already issued durable record/result hashes, authenticated mTLS; cached confirm retains its original signature/validity | Original execution AND original confirmation keys reverified, historical timing/approval/artifact/journal binding checked |
| Independent verifier Ed25519 signer | Separate verifier process private key; Manager verifier keys and Agent `verifierKeys` ring | Fresh receipt; distinct ring from Manager. Key ID collision across classes refused | Confirmation proof hashes retained; no fresh verifier required merely to deliver a terminal result | Original receipt signature reverified; past proof never proves current packets |
| Boot restoration authority | Confirmed Agent journal `restorationAuthority` and exact owned profile/artifact | Never replayed as a new execution | Existing terminal sequence/result unchanged | Agent only, autoconnect=false; current trust/configuration/secret required |

Agent `network_executor.verify`, `independent_trust` and `validate_restore_authority` perform these
checks. mTLS terminal authentication is in `manager-server.ts`; the courier rereads TLS files each
iteration. Manager signer/pin configuration is process configuration, so stage files and restart
that process explicitly. The Agent's unrelated firewall artifact trust cache may require its own
process restart; do not infer all subsystem key changes from one network signature check.

## Normal rotation versus emergency removal

Normal leaf rotation preserves source/host/node/journal, every ledger entry and pending outbox.
Stage protected key/cert pairs, verify CA+CN+clientAuth+fingerprint, deliberately update exact
Manager pin, restart affected processes, and retry the **same** result until its exact hash is
acknowledged. Old pin/leaf must be refused. A replacement certificate never authorizes a new
journal or resets a replay sequence. Keep evidence of interrupted/revoked deliveries and reconcile
with the same Manager issued record/fence; do not synthesize a settlement or unlock it.

Normal signing-key overlap is an explicit finite maintenance window. Add distinct public keys,
verify exact SPKI IDs and separate trust classes, switch the signer, and check in-flight work's
original authority requirements. Cached confirms/cancellations retain original key IDs. Removal
of any required historical Manager/verifier key **denies boot restoration** in current code.
Do not silently keep a retired key forever or relabel old authority as signed by a new key.

The selected lifecycle policy prioritizes revocation: restoration refusal and stopping the trial
are permitted when a required historical key is removed. This is not permission to erase
evidence or to bypass revocation for availability.

Emergency removal uses that same fail-closed verification: no new activation under a removed
key. Preserve the exact profile, original authority, journal, fence/outbox and degraded diagnostic.
An already active kernel configuration is not automatically deleted by removing a trust file;
there is no general reconciliation or confirmed-resource deletion. Use the independent console,
stop new work, and assess isolation/recovery explicitly. Availability is not permission to ignore
revocation. Missing/corrupt/duplicate-ID trust must fail closed. Agent network verification refuses repeated
SPKI IDs within either ring as well as overlap across rings. Manager startup and confirm issuance
refuse duplicate verifier IDs; copying one public key to another filename is not key overlap.

**Unsupported:** a new-key restoration reauthorization contract for an existing confirmed resource.
If key retirement must preserve that resource's next-boot availability, this is a trial blocker until
a separately reviewed signed reauthorization bound to target/journal/configuration/lineage exists.
Restoring an urgently revoked key to make a reboot pass is not an approved recovery method.

## Record replacement scope

Scope A (no confirmed resources, all work terminal, exact Manager settlement/outbox ack,
no recovery debt/fence, complete verified archive, single writer) has an explicit
[maintenance contract](network-journal-maintenance.md). Its implementation and isolated
checks are separate from actual VM/storage-pressure qualification and independent archive custody.
Scope B (confirmed ownership/restoration carried across identity) remains unsupported. Never
empty the journal because terminal delivery is done: confirmed ownership still depends on it.
Manager256/Agent1024 and byte limits are finite; reserve workload budget before admission.
Normal Agent admission stops at 1023 primary records; one bounded, resource-free
never-accepted cancellation can use the last replay identity and persist a Manager
issuance hold. See [the paired-rollout capacity-stop contract](network-journal-maintenance.md#capacity-stop-reservation-paired-rollout-required).
Confirmed resources or recovery debt forbid that emergency reservation and scope-A retirement.
No pruning, force-unlock or blind identity reuse is allowed.

## 24-hour baseline procedure

`lifecycle_snapshot.py` is a read-only marked-guest collector: current on-disk module hashes,
service PID/start identity/CPU/RSS/FD/children, trust IDs, semantically committed journal excluding
only its ticking lastClock, exact journal identity/outbox/ack commitments, lifecycle and production
read-only profile/cache/kernel/secret checks. It emits no private key, whole profile, environment
or unrestricted process command line. Historical restoration authority is reverified without apply.

`soak_peer.py` independently samples fixed management/forward/reverse packets every5seconds.
`soak.py --root PRIVATE_LAB --transaction CONFIRMED_TX --output NEW_PRIVATE_DIRECTORY`
requires clean committed source and exact deployed collector/module hashes. It observes on a
fixed60second monotonic schedule for at least24hours and1440samples, plus at least24hours of
packet timestamps. It preserves every sample in a hash chain and stops on any packet loss/gap,
boot/PID change, target/trust/semantic journal drift, fence/debt, stale heartbeat/discovery, observed
failure, journal reserve or process budget violation. The final monitor tail is checked before pass.
A crash/incomplete archive cannot produce a successful final result. Resource budgets are in the
created plan; peak process bounds and average CPU checks are limited by the collection interval.
Transient peaks between samples are not disproved.

Both roles' installed runtime source commitments are compared with the clean source checkout,
including the Manager/relay source and observation tools, package metadata and i18n dependencies.
Configuration/public certificate and public trust commitments must remain equal to the initial
sample. The collector refuses declared private-key inode aliases before opening a public input;
it does not export private key material or establish that arbitrary source/config bytes are safe
for publication. Reads require stable file identity/size/metadata before and after collection.
Manager and Agent target/journal bindings must agree, and lifecycle status must belong to the
current Agent PID. These disk measurements do not attest the running process memory or
untracked dependency bytes. Repeated sampling cannot disprove changes between samples.

Initial settlement is checked before the baseline is accepted, then again on every sample.
A read-only production `Executor.load()` validates the Agent replay state without constructing
an executor, taking a writer lock, saving, repairing or running recovery. Legacy recovery-only
journals remain recoverable by the Agent, but cannot enter this baseline. The observer requires
identical transaction sets, target/journal/authority/artifact/revision bindings, closed Agent states,
settled Manager records, contiguous sequences, exact terminal result and outbox hashes, and
literal-true acknowledgments. An unchanged initial file hash alone does not establish settlement.
A retained acknowledgment for an intermediate cancellation response is permitted only when the
Manager retains that exact cached response. An intermediate response replaced by the final outbox
result need not have been delivered; it cannot carry an unexplained acknowledgment. These checks
establish cross-store agreement, not external PKI provenance or whole-schema equivalence.

The default console SSH ports remain22220/22221. For an explicitly identified pair on other
ports, pass `--gateway-ssh-port PORT --peer-ssh-port PORT` to the production runner; the two
ports must be distinct valid integers. Guest nonce checks still apply. Do not monkeypatch the
transport or accidentally observe a different retained lab. These checks are prerequisites for a
new final-source baseline; synthetic tests do not qualify a real24-hour run.


This is a **zero-issuance baseline**, consuming0new ledger slots. Certificate rotation/fault injection
must run separately, before/after this baseline, and retain their own identities and failure history.
Do not perform them concurrently and then label a reset/restarted baseline continuous. A shorter
preflight or synthetic clock test is never long-duration evidence. Longer field stability is unknown.

`lifecycle_pki.py prepare` creates a **new isolated3-day CA and leaves** on a marked peer for the
new lifecycle run, refusing an existing fixture. This prevents the previous1-day test PKI from
expiring inside the chosen24-hour window. It is initial test provisioning, not CA continuity,
operational CA rotation, or a signature-key promotion. Activation, leaf pin changes/revocation and
Manager/Agent restarts are separate measured fixture steps. The production Manager lab wrapper
can opt into a fixed revocation-file path; once configured, missing/corrupt files deny requests.

## Trial decision: not ready

No operational gateway/owner/window was supplied. A trial plan cannot name an invented host or
claim target OS/NM/service/console equivalence. Require exact target+owner+versions, dedicated
resource budget, independent console/management, change window, maximum unconfirmed deadline,
stop criteria, automatic undo/manual recovery owners, secret/certificate custody, evidence retention
and capacity budget. Require actual lifecycle/fault/24-hour results and vendor support review.

There is no general confirmed-object withdrawal tool. A trial requiring withdrawal on an existing
host is blocked until a separate contract exists. A disposable-gateway trial may instead explicitly
retire the **entire approved disposable guest** after evidence export, if its owner approves that
exit before entry; this does not authorize deleting any existing VM or operational host here.

## Distribution support review

On2026-10-21 the official [Rocky10.2 release notes](https://docs.rockylinux.org/releases/release_notes/10_2/)
and [Rocky WireGuard guide](https://docs.rockylinux.org/guides/security/wireguard_vpn/) were consulted.
Neither establishes a vendor WireGuard SLA for this target. The measured kernel marks WireGuard
Technology Preview. The upstream [Red Hat Technology Preview support policy](https://access.redhat.com/support/offerings/techpreview)
explicitly does not guarantee stability or a supported/GA future and warns that a migration path may
not exist. This is upstream policy context, **not a Rocky commercial support contract**. A linked
RHEL10.2 technology-preview page returned404 during review; no unseen content is asserted.
Obtain the actual target owner's support acceptance before trial entry. Experimental success
does not establish distribution/vendor production support.
