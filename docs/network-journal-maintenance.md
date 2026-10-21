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

Stage exactly seven protected files in a new owned0700 directory, with owned0600 single-link
regular files and no symlink ancestors: `manager.json` (exact current Registry bytes),
`transactions.json`, `journal-identity.json`, `terminal-results.json`, `terminal-acks.json`,
`audit-public-keys.json`, and `network-executor-config.json`. The last contains only supported
configuration/path references, never TLS/private-key bytes. Audit keys have distinct Manager/
verifier public SPKI IDs; they verify old evidence and are never installed as execution trust.
Preserve any existing sidecars in the old directory as well; the seven files are the signed
archive contract, not a recursive export or an assertion that other files contain no secrets.

`node bin/heliopause-network-journal-archive.ts --snapshot STAGED --output NEW_ARCHIVE`
is read-only and reports an exact-byte commitment. Repeat with `--apply --expected-hash HASH`
to create a new private fsynced archive. Existing destinations are refused. Incomplete copies
remain evidence and fail verification; they do not permit replacement. Store a verified copy
under an independently chosen custody policy before operational maintenance. A copy on the
same development disk is not independent backup, and this tool supplies no remote custody.

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
returns its existing receipt; it cannot empty later successor records. Current signer must match
the approved signing identity. There is no local metadata promotion of old authority.

Transport the exact archive, signed authorization and Manager commit receipt to protected
Agent maintenance storage. `python3 agent/network_journal_transition.py --archive ARCHIVE
--authorization ENVELOPE --manager-receipt RECEIPT` checks authority without applying. Add
`--apply` only for the default integrated root-owned layout with Agent/courier stopped. It holds
the existing host writer and executor locks, rechecks configuration/archive/current sidecars and
production resource absence, then executes the durable phases below. No network mutation is
performed by this tool. A Manager receipt is mandatory; Agent cannot transition first.

After both commits, explicitly update the Manager target's journal binding, preserving the
same target and exact authorized leaf pin. Restart Manager and Agent/courier; verify both ledgers,
new journal, health and absence of a fence before allowing new work. Manager restart with a
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
| Owned stage published/partly written | Exact transition owner marker required; only expected empty successor bytes/prefixes can be completed, retaining partial hashes. Foreign stage is preserved/refused. |
| Successor published, config still old | Pending marker prevents use; resume verifies pristine successor and rebinds only `journalId`. |
| Config bound, completion not recorded | Exact old/new configuration permitted only for this receipt; finish same transition without resetting successor records. |
| Complete | Exact retry is a no-op even after new work. A later approved transition preserves the prior completion marker inside its old directory. |

These are separate stores and renames, not a single atomic distributed operation. Partial or
foreign state requires stopping maintenance, preserving all files/hashes and inspecting through
the console. Do not remove a lock, marker, retired directory, receipt or tombstone to force progress.
The retirement chain itself is bounded256; exhaustion requires a separately designed policy.

## Qualification limits

Isolated tests exercise both real Node Ed25519/Registry transitions and Agent crash/file behavior
with live network/subprocess/socket boundaries replaced. A loopback mTLS test exercises actual
operator authentication and two-person approval, receipt retry and retired-binding startup refusal.
Those tests do not establish Rocky VM crash recovery, storage-pressure survival or remote custody.
Confirmed-resource scope B remains unsupported and blocks a trial that requires that migration.
