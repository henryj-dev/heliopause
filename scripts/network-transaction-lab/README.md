# Authenticated execution observation fixture

The default TLS relay remains the heartbeat/firewall fault fixture used by the
kernel transaction tests. Its POST success is not production observation validation.

An explicitly provisioned disposable pair can opt into `lifecycleObservationTransport: true`
in the peer's existing `config.json`. The identity must be exactly source `lab`, host
`gateway`, node `gateway`. This enables only the lab observation transport and the
Manager's configured `lab` RelaySource. It does not create keys, change firewall
artifacts, initialize journals, issue authority or apply a network change.

Before enabling it, provision a separate service identity inside the disposable
peer at `relay-operator-pki/{ca.pem,operator-hp-manager.pem,operator-hp-manager.key}`.
Use the current lab CA, a distinct service key and clientAuth leaf with CN
`hp-manager`; do not copy or impersonate Alice/Bob's keys. The private key must be
a regular single-link 0600 file in a protected directory. The Manager explicitly
selects `operatorName: hp-manager` and never infers a human credential by sorting.
Certificate source, SPKI, purpose, CA binding and remaining lifetime require
separate actual provisioning verification. No existing key is revoked or replaced
by this option.

The observation endpoint accepts an authenticated Gateway upload with exactly
`host: gateway` and a report object, a single bounded Content-Length, strict UTF-8
JSON and no duplicate/unknown envelope keys. The 128 KiB original request is kept
unchanged in a private durable spool with the receiver's actual receipt time.
An identical retry returns its original receipt. Partial writes are preserved
and refused rather than repaired. A full spool returns failure; nothing is pruned.
Complete files left visible after an fsync error require both held-file and
directory fsync barriers before their original receipt can be returned again.
The fixed service CN alone may read that spool. Human credentials and Gateway
credentials cannot read it, and the service credential cannot upload reports.

This fixture deliberately treats report content as opaque. A 200 response is a
**transport receipt**, not schema approval or proof of a completed production
Relay upload. The real Manager's `fetchNetworkObservations` validates the report
before its `NetworkObservationStore` writes the source-bound cache. Malformed
reports leave an existing valid Manager cache unchanged and report relay
unavailability. There is no direct cache injection or fabricated collection time.
GET adds only the receiver receipt; original report tokens and timestamps are not
rewritten. Neither production Relay enrollment nor its replay store is qualified
by these fixture endpoints.

Use the actual Gateway collector/worker, then the Manager observation GET, Alice's
propose, Bob's approve and Alice's authorize APIs for a separately identified NM
trial. The observation API adds display-only `freshness` and `collectors` fields;
exclude those two fields when committing the stored record's digest. Do not alter
its report, collection/receipt times or source binding. A new observation cannot
replace evidence inside an already signed authority. The normal 30-second age,
signature, two-person approval, expiry, fence and Agent precondition checks remain.

The HOST TLS tests use temporary certificates and a synthetic report to verify
this complete API route. They do not execute NM, prove packets, restore a boot,
verify the real VM's PKI, or start a 24-hour baseline. Actual deployment requires
new source/module/config/public-certificate commitments, private-key stat-only
commitments, no pending operation, and preservation of all original stores and
failed experiments. The observation spool is changing measurement data, not a
frozen baseline input. Its configuration and service identity are frozen inputs.
