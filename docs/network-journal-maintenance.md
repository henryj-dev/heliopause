# Quiescent network journal maintenance (scope A)

This implementation supports only a single-target journal with **no confirmed resources**.
It does not transfer ownership/restoration authority, delete confirmed resources, prune records,
or unlock a fence. VM/capacity qualification is separate from the isolated tests below.

## Admission and archive

Stop the Agent and terminal courier through the independent console. Preserve their service
state and verify every work item is terminal, every Manager record is settled, every exact
terminal result is acknowledged, the fence is absent, and no rollback/restore debt remains.
A read-only production inventory must find no old interface, host route, NM profile or keyfile.
An unrelated object in one of those identities is a refusal, never an adoption/deletion.

Stage exactly eight protected core files in a new owned0700 directory, with owned0600 single-link
regular files and no symlink ancestors: `manager.json` (exact current Registry bytes),
`transactions.json`, `journal-identity.json`, `terminal-results.json`, `terminal-acks.json`,
`audit-public-keys.json`, `network-executor-config.json`, and `execution-evidence.json`, plus an owned0700 `evidence/` directory. The configuration contains only supported
configuration/path references, never TLS/private-key bytes. Audit keys have distinct Manager/
verifier public SPKI IDs; they verify old evidence and are never installed as execution trust.
Preserve any existing sidecars in the old directory as well; the eight core files and explicitly indexed attachments are the signed
archive contract, not a recursive export or an assertion that other files contain no secrets.

`node bin/heliopause-network-journal-archive.ts --snapshot STAGED --output NEW_ARCHIVE`
is read-only and reports an exact-byte commitment. Repeat with `--apply --expected-hash HASH`
to create a new private fsynced archive. Existing destinations are refused. Duplicate JSON keys and explicit credential fields are refused; the scan is defense in depth,
not permission to publish arbitrary lab data. Incomplete copies
remain evidence and fail verification; they do not permit replacement. Store a verified copy
under an independently chosen custody policy before operational maintenance. A copy on the
same development disk is not independent backup, and this tool supplies no remote custody.

The execution evidence index has `schemaVersion:1`, a `runs` array and a `files` map. Each exact
transaction ID/authorization hash has a40hex source commit, image SHA256, module-manifest
SHA256, and nonempty file lists for `report`, `inventory`, `packets`, `modules` and `history`.
Explicit empty history is represented by an actual hashed history JSON; it is not omitted.
An unused journal explicitly has empty runs/files and an empty evidence directory. Run IDs must
exactly cover the archived Agent transactions. Module commitment binds the first modules file.
The manifest SHA256 is included in approval, Manager receipt and permanent epoch tombstone.

Evidence identities and commitments must be JSON strings; a single-element array that
looks like a hash is invalid. Replay counters must be integers from 0 through 1,024,
and the saved clock must be a nonnegative safe integer. Both languages use the shared
`scripts/network-transaction-lab/fixtures/journal-validation-v1.json` contract cases.
A finite future clock watermark remains valid for clock-rollback detection. Malformed
values are refused without rounding, clearing history or repairing an identity in place.
Retain the original bytes and fence/transition evidence for inspection. A Manager commit
does not make an Agent-side refusal safe to bypass; resume only the same valid authority
after the exact refusal has been understood. Deploy compatible validators on both sides
before journal maintenance.

The stored top-level `acceptedSequence`, `terminalSequence` and `lastClock` use integer
JSON tokens (optional minus sign, decimal digits only). Although `1.0` and `1e0` are valid
JSON numbers with the same mathematical value, they are unsupported encodings for these
three fields. The same integer-token rule applies inside the explicitly committed execution
authorization, cancellation, terminal result and cancellation response objects, including
their reserved-identity and Manager/outbox copies. Otherwise a decoded `registryRevision:1.0`
or `sequence:1e0` can match JavaScript's digest but fail Python's. Manager record sequence
tokens are checked too. Python rejects the floating-point parse result; Manager checks the
original tokens before JavaScript loses that distinction. Escaped property names receive
the same check. Execution-evidence schema version and attachment byte counters use the
same integer-token rule. Other stored values, including monotonic floating-point history, retain
their existing representation. This is not a whole-document canonicalization rule.
Archive creation/loading and Manager plan/commit validation refuse unsupported counter
encoding; Agent load and offline transition refuse it without rewriting the source.
Preserve any pre-upgrade archive that uses it and the exact refusal. Do not normalize it
to obtain a new authority or clear a partial transition. This narrow encoding contract
does not prove equivalence of every TypeScript/Python schema or integer field.

Manager archive parsing also refuses unpaired Unicode surrogates in decoded keys and values,
including ASCII JSON escapes such as `\ud800`. Valid surrogate pairs, Unicode scalars and
U+FFFD remain supported. This prevents later Python UTF-8 serialization failures; it does not
normalize or replace historical bytes. The shared exact-byte fixtures state separate Manager
archive-parser and Agent decoder outcomes: Python's wider BOM/UTF-16/UTF-32 and surrogate
acceptance remains unchanged for existing recovery. Base64-encoded signed payload decoders
are a separate boundary; these tests do not establish whole-schema/decoder equivalence.

An emergency `capacityCancellation` archive must contain the history actually produced by the
Agent: one object with exactly `state:"cancelled-before-accept"` and a nonnegative safe integer
`at`, stored as an integer JSON token. Decimal/exponent tokens, extra entries or fields are
refused by the Manager even if unsigned history otherwise matches the terminal result. This
prevents Python/JavaScript canonical byte-length differences at the 512 KiB sidecar limit.
Primary transaction history and monotonic measurements retain their floating-point support.
The Agent's existing journal/recovery decoder is unchanged. Preserve unsupported old archives
and refusal evidence; do not rewrite history, reset a journal or bypass approval to transition.
The fix requires current Manager archive validation before new approvals/commits; deploying it
does not qualify a guest, establish evidence custody or repair an already partial transition.

Attachments are flat, fixed relative lowercase JSON names, with exact kind/byte/SHA256 metadata:
no recursion, absolute paths, traversal, duplicate runs/references, extra/missing files, symlink or
hardlink adoption. Limits are4096files,4MiB each,128MiB total, and64files per role/run. Both the
Manager and Agent independently re-open, hash, permission-check and fsync the indexed files.
A mismatch refuses transition and preserves the old records. These are private evidence limits,
not a claim that fitting within them makes an archive public-safe or operationally complete.

Include original report/packet/inventory/module/failure/retry/interruption evidence, not a new
success summary. A JSON wrapper for raw UTF8 diagnostics must distinguish original bytes/hash
from wrapper bytes/hash and preserve the complete original text; redaction must retain separate
original/derived commitments. Review source/deployed module commitments and independent
packet provenance before approval. Integrity and required-role coverage do not authenticate an
unsigned measurement, attest a loaded process, or prove that an author truthfully labeled a file.
Historical public audit keys alone likewise do not establish an external origin of evidence.

Configure the Manager's `networkJournalArchiveDirectory` explicitly. Each child archive name
is exactly32lowercase hex characters. API callers cannot supply paths, shell, hooks or keys.
The existing authenticated operator/writer/OTP/cross-site controls apply; this is not a separate
certificate-only authentication system.

Use `/api/network/journal-transition/propose` with `{archiveName}`, review the returned exact
archive/target/old/new identity hashes through `review?hash=...`, have a different authenticated
writer `approve` `{archiveName,hash}`, then `authorize` the same plan. Proposal maps are finite
and volatile: a restart before authorization requires fresh review/approval. Commit the resulting
envelope through `commit` `{archiveName,envelope}`. That operation reopens/verifies/fsyncs the
archive and compares current Registry bytes under the existing Registry kernel-writer lock.
It atomically replaces only that Manager store with a bounded retirement chain and fresh empty
execution epoch. Registry resources and their generations are retained. An exact receipt retry
returns its existing receipt; it cannot empty later successor records. The permanent tombstone
also retains the exact signed authorization, allowing recovery after a lost response and Manager
restart without reconstructing authority from local metadata. Current signer must match
the approved signing identity. There is no local metadata promotion of old authority.

Before Manager commit, transport the exact archive to protected Agent maintenance storage.
`python3 agent/network_journal_transition.py --archive ARCHIVE` performs read-only inspection
under existing host writer/executor locks: exact configuration and sidecars, quiescence, resource
absence, and a replaceable journal directory. A journal that is itself a mount point or lies on a
different filesystem from its parent is refused; storage migration is a separate operation.
Inspection does not create missing lock files or write transition state.

After Manager commit, transport the signed authorization and receipt to protected Agent storage.
Use `--archive ARCHIVE --authorization ENVELOPE --manager-receipt RECEIPT --apply` only for
the default integrated root-owned layout with Agent/courier stopped. Apply repeats the checks,
requires exact approved configuration bytes (or the exact successor bytes during recovery), and
executes the durable phases below. No network mutation is performed by this tool. A Manager
receipt is mandatory; Agent cannot transition first. Signature verification uses temporary files
in the existing protected Agent writer directory, never in the replaceable journal. A crash in
verification must not recreate an unpublished successor or alter the immutable archive.

After both commits, explicitly update the Manager target's journal binding, preserving the
same target and exact authorized leaf pin. Restart Manager and Agent/courier; verify both ledgers,
new journal, health and absence of a fence before allowing new work. The default network state parent `/var/lib/heliopause` must already
be owned0700; maintenance refuses an unsafe parent and never silently chmods a shared directory. Manager restart with a
retired/ambiguous configured binding fails. Old authorities/results cannot create a record in the
new epoch. They do not justify replay reset, copying old records back, or certificate rebinding.

## Crash boundaries

| Durable boundary | State and next attempt |
|---|---|
| Before Manager commit | Old records remain; no Agent receipt exists. Revalidate/reapprove if expired. |
| Manager committed, Agent untouched | New Manager epoch refuses old issuance; old Agent remains preserved. Stop admission and finish the exact approved transition. |
| Agent intent saved | New network admission and courier writes refuse the pending transition; mandatory firewall/local recovery remains independent. |
| Old retirement marker saved | Old journal cannot accept new work; exact original four replay/identity/outbox/ack files must match archive. |
| Old directory renamed | Every original file remains at `.retired-OLD_JOURNAL`; it is rechecked on resume. |
| Unique creating directory made, owner not yet saved | Preserve the unowned orphan; resume creates a distinct owned staging directory. It never fills/adopts the orphan. |
| Owned stage published/partly written | Exact transition owner marker required; only expected empty successor bytes/prefixes can be completed, retaining partial hashes. Completion appends only the remaining approved bytes and fsyncs the file; it does not create an untracked replacement temporary file. Foreign stage is preserved/refused. |
| Successor published, config still old | Pending marker prevents use; resume verifies pristine successor and rebinds only `journalId`. |
| Config bound, completion not recorded | Exact old/new configuration permitted only for this receipt; finish same transition without resetting successor records. |
| Complete | Exact retry is a no-op even after new work. A later approved transition preserves the prior completion marker inside its old directory. |

These are separate stores and renames, not a single atomic distributed operation. Partial or
foreign state requires stopping maintenance, preserving all files/hashes and inspecting through
the console. Do not remove a lock, marker, retired directory, receipt or tombstone to force progress.
The retirement chain itself is bounded256; exhaustion requires a separately designed policy.

## Qualification limits

Isolated tests exercise both real Node Ed25519/Registry transitions and Agent crash/file behavior
with live network/subprocess/socket boundaries replaced. A regression retains the production
signature helper's real directory/temp-file/fsync/cleanup behavior while replacing only its
OpenSSL subprocess; replacing the entire helper would hide that filesystem boundary. A loopback mTLS test exercises actual
operator authentication and two-person approval, receipt retry and retired-binding startup refusal.
Those tests do not establish Rocky VM crash recovery, storage-pressure survival or remote custody.
Confirmed-resource scope B remains unsupported and blocks a trial that requires that migration.

## Capacity-stop reservation (paired rollout required)

Normal Agent admission stops at 1,023 primary records and the existing 6 MiB admission
budget. The 1,024th replay identity is reserved for one Manager-signed cancellation of
an authority that was never accepted. If its complete terminal record would exceed
the admission budget, the Agent atomically preserves that record in
`journal-identity.json` (`capacityCancellation`, whole identity at most 512 KiB).
The primary journal bytes and counters remain unchanged. The effective record set and
terminal sequence include the reservation. All primary operations must already be
rolled back or cancelled before acceptance, with no confirmed resource or recovery debt; existing undo, reporting and acknowledgments continue. This is bounded
logical capacity protection, not a guarantee against physical storage failure.

The reservation produces terminal schema 3, domain
`heliopause-network-capacity-stop-mtls-v1`, with the original cancellation hash and
`acceptancePrevented=true, maintenanceRequired=true`. Direct pinned Agent mTLS still
authenticates delivery. The Manager atomically settles the exact fence and persists
an issuance hold. Execution-ledger schema 2 makes older Managers refuse this state;
older Agents refuse the extended identity. Deploy both versions before enabling new
work. A mixed-version rejection retains debt and requires the compatible binaries;
never downgrade the terminal result or remove the hold/identity field by hand.

Retries export the identical result/hash/sequence, including a restart between identity
persistence and outbox publication. A duplicate result cannot release the hold. New
Agent acceptance and Manager issuance remain stopped until the normal two-person,
full-archive scope-A transition retires the complete primary-plus-reserved history.
Its archive commits the raw identity and primary journal separately and preserves both
original files. No partial pruning or timeout clears this condition.

A pre-existing legacy primary ledger with 1,024 rows has no free emergency slot and
fails closed; existing accepted undo/report/settlement remain available. A confirmed
resource, including one in an otherwise terminal ledger, forbids the emergency reservation
and scope A. Capacity refusal then retains the Manager fence; existing recovery and
settlement remain available. The capacity stop does not transfer its ownership or restore authority. Such
a target needs a separately specified scope-B transition or an approved exit procedure
before its lifetime budget is exhausted. Do not present this reservation as that feature.

Implementation validation and real VM capacity-pressure results must be reported
separately. Synthetic padding and synthetic full-ledger fixtures do not establish the
size of legitimate operational history or the completion of 1,024 real operations.


## Completed epoch durability and recovery

A visible `complete` marker is not proof that its rename reached durable storage if
parent-directory fsync failed. Before admitting a new execution or a new preaccept
cancellation identity, the Agent checks the protected completion marker, successor
owner, identity, authority payload and receipt commitments, then fsyncs the same open
files and directories through the marker parent. A repeated completed transition also
performs this barrier without resetting any successor records. Confirmed boot activation
uses the barrier; interrupted restore undo remains independent.

Missing or inconsistent completion evidence refuses new admission and confirmed
activation. For missing complete markers or inconsistent complete-marker ownership/payload binding,
startup attempts existing owned unconfirmed undo and publishes terminal results before
recording the completion-evidence error. The existing known pending/retired
startup guard remains in place so startup cannot recreate an absent successor during an
offline transition. Keep the original archive, receipt, marker, sidecars and partial paths;
resume only the same approved transition. No timeout, pruning or local ownership rewrite
repairs missing evidence.

This local check binds previously verified protected payloads; it does not revalidate
historical signatures or establish independent custody. It does not require reinstalling
revoked keys. Same-length signature corruption cannot be detected by payload commitments
alone; the full archive/signature verifier and offline transition retry remain separate.
Boot restoration continues to verify its Manager/verifier authority against current trust.
The fsync barrier reserves no physical storage. If it fails, existing owned undo, terminal
export and identical-result retries remain available; new identities stay refused.


### Archive byte encoding

Manager archive creation, loading, evidence attachment validation and signed transition validation reject malformed UTF-8 before JSON decoding. Invalid bytes are not replaced with Unicode replacement characters or rewritten. Valid UTF-8, including an actual U+FFFD character, remains accepted where its field permits it. The existing Manager refusal of a UTF-8 BOM is retained; this does not add other JSON encodings or establish whole-schema equivalence with the Agent.

If encoding validation fails, preserve the original archive and reconcile its provenance. Do not repair the bytes in place, approve a normalized copy as the original, or clear the old journal. A paired compatible rollout and the existing full-archive/two-person transition checks remain required.

The shared byte fixtures record decoder-specific outcomes. Python's existing byte JSON decoder also accepts UTF-16/32 with a BOM and UTF-8 encoded surrogate bytes; Manager archive parsing refuses them. This stricter Manager behavior prevents approval of bytes the Agent would later reject without changing the Agent's common config/mailbox/journal decoder. It does not claim that every byte representation accepted by either decoder is a supported archive. Any Agent-wide encoding restriction requires separate compatibility qualification.
