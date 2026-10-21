# Phase11: evidence custody and lifecycle work

This record supersedes no historical measurements. Current runtime support remains
[Phase10](network-phase10-validation.md): measured Rocky10.2/NM+libnm1.56.0 only, dedicated
IPv4 WireGuard/host routes, persistent driver `networkmanager-wireguard-1.56-v1` with all profiles
`autoconnect=false` and Agent-only confirmed boot restoration. The old driver is kernel-only.

## Phase A: original evidence recheck

The original `/workspace/rocky10-lab/acceptance/final-report.json` was actually accessible in the
retained development environment on2026-10-21. Its SHA256 was independently re-read as
`81e0650a1fe7ffc2e76245b5271f72e3a7f81ee08895186012f4be85a00912cd`.
The run source is `2620023577ea554e863edf86bce6e7365d9c9d5f`; its Git tree matches main's
PR206 squash commit `2bd33b14143428e25e17126c5490e032dca974ed`.

The recheck read84 references (82 unique paths,68 JSON), all matching their recorded hashes.
It checked thirteen groups, twenty-five actual boot transitions (13graceful/12virtual power cuts),
two journal boot chains, surviving independent peer, replay/terminal sequence invariants, current
packet evidence, and ten exact settled results/Agent acknowledgments. One host coordinator
interruption and one production transient rollback retry remain in the original report.
This recheck is not a new run of twenty-five reboots and does not upgrade virtual guest power
loss to physical host/controller durability or a general recovery-time guarantee.

The new private archive retains the exact original JSON/Python bytes and hashes separately from
its portable manifest; it excludes credential tar/private keys/profile exports/guest disks.
Its tool and synthetic tests are [documented here](../scripts/network-evidence/README.md).
Real source and evidence stay outside the public repository. A future worker must actually obtain
and verify the archive; the path in this document is not evidence of future access.

## Provenance and retained measurement limits

The retained lab's public Manager/verifier keys verify ten execution authorizations and two
historical confirmed restoration authorities using production framing/domains and canonical
payload checks. Public leaf CA signature, CN gateway, clientAuth and endpoint fingerprints were
also rechecked independently during the audit. These keys are internally consistent with the
retained provisioning artifacts. They are not authenticated by a separate external operator PKI.
Neither a matching bundled key nor the archive tool's success establishes that missing provenance.

Historical deployed module comparison is a preboot assertion in the retained source262 runner.
There is no per-file deployed hash list or loaded-process attestation in those old boot reports.
The archive reconstructs expected module hashes from Git and labels this harness dependency.
It must not be described as a new historical module measurement. Current VM/disk inventory and
all subsequent lifecycle runs require separately recorded source/deployment commitments.

The final tool inventory's systemd executable probe used a wrong lookup path; installed RPM257
and actual service/boot evidence establish systemd operation. `nftables.service` was inactive:
firewall coexistence exercised the Agent's firewall boot restore. WG profile export failed exit2;
only failure-output nonleakage, default inspection and authorized root secret reads were checked.

## Remaining lifecycle/trial gates

This evidence PR does not rotate certificates/signing keys, archive/reset a replay ledger, transfer
identity, retire confirmed resources or prove long duration stability. Original journals, fences,
keys and guest disks remain preserved. A private same-host copy is not remote disaster recovery.
An owner-selected second custody location, access/retention owner and independent key provenance
remain trial-entry decisions.

The selected stability target is24hours continuous observation. Short preflight or fault exercises
must be reported separately. Certificate rotation/revocation, Manager/verifier key retirement,
quiescent identity replacement, capacity failure recovery and final-source VM exercises are still
separate work. Trial status remains **not ready**; no production network change is authorized.
