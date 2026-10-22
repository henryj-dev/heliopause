# Private Phase10 VM evidence preservation

`bundle.py` preserves and rechecks the **existing Phase10 run**, not a new VM run, a
certificate authority, or a journal/ledger replacement. It never runs SSH, ip, wg,
NetworkManager or a gateway apply/undo path. Verification executes bounded Git reads and
the production OpenSSL Ed25519 verifier locally. Test fixtures are synthetic.

The current supported input is the exact Phase10 report schema: thirteen groups, twenty-five
changed gateway boots (thirteen graceful/twelve virtual power cuts), surviving peer, boot chains,
current packet observations, ten exact terminal settlements/Agent acknowledgments, and retained
interruption/transient retry history. Kernel/container reports remain separate and do not prove
host reboot. Unsupported/missing input fails; it is not a skipped success.

## Trust and deployment limitations

Supply the expected report digest, exact source commit/image digest and **separately pinned**
Manager/verifier public keys. Reusing an arbitrary key from inside an evidence bundle proves no
origin. The keys used to recheck the original development lab came from selected public members
of its retained provisioning tar, not an external operator PKI. The archive verifies that internal
signature binding and the report digest previously recorded in the development handoff; it does
not independently authenticate the human approvers or a real service's key provenance.

`sourceModules` contains expected SHA256 values reconstructed from the exact Git commit.
The original boot runner checked deployed bytes over SSH before every reboot, but its report did
not retain those per-file measurements. The archive explicitly records this harness dependency.
These values are **not** a new attestation of the historical guest or its loaded process.

## Preserve then independently verify

Keep the reviewed source report and referenced JSON/Python files in their original lab root.
Create an existing private 0700 archive parent outside the repository. Choose a new destination;
existing destinations are never overwritten. All path components must be non-symlinks. Files
must be bounded single-link regular files. Each archive file is 0600, flushed and fsynced; the
manifest is written last and both directories are fsynced. Partial failure leaves an incomplete
archive for diagnosis and leaves the originals intact. A manifest's presence alone is not proof
of successful signature verification: run `verify` and require exit 0.

```sh
python3 scripts/network-evidence/bundle.py preserve \
  --report "$REVIEWED_LAB/acceptance/final-report.json" --lab-root "$REVIEWED_LAB" \
  --bundle "$PRIVATE_ARCHIVE/new-run" --source-repo "$SOURCE_REPO" \
  --expected-report-sha256 "$REPORT_SHA256" --source "$EXACT_SOURCE_COMMIT" \
  --image-sha256 "$IMAGE_SHA256" \
  --manager-key "$EXTERNAL_MANAGER_PUBLIC_KEY" --manager-key-id "$MANAGER_SPKI_ID" \
  --verifier-key "$EXTERNAL_VERIFIER_PUBLIC_KEY" --verifier-key-id "$VERIFIER_SPKI_ID"
```

For `verify`, use the same arguments except `--report` and `--lab-root`, and change
`preserve` to `verify`. An existing source Git object database for the tested commit remains
required. Cross-check the source commit with the reviewed PR/merge tree separately.

Only explicitly referenced `.json`/`.py` files are copied. No root directory recursion, credential
tar, guest disk, profile export or private key is included. The manifest maps each original path
and original SHA256 to a portable filename and archive SHA256. Transformation is `none`; the
bytes and hashes must match exactly. This format does **not** support redacted derivations.
If redaction is needed, preserve a separately identified derivative with its own hash and review
rather than changing these originals or pretending its digest is unchanged.

Secret PEM/keyfile/JSON-field screening is defense in depth, **not declassification**. Reports
contain machine metadata, topology, journal identities, signed artifacts and audit details.
Keep real archives access restricted until a human has approved their exact public contents.
Never commit real evidence/private provisioning material to this public repository.

This archive has no authenticated remote custody or retention backend. Keep an access-controlled
second copy in an owner-selected durable location and record the custody/retention owner before
trial approval. A second directory on the same development host is not independent disaster
recovery. Source tools and synthetic fixtures can be public; the original evidence remains private.

Run `python3 scripts/network-evidence/test_bundle.py` or `npm test` for the isolated suite.
Tests deny escaped subprocess/socket operations and cover partial archive writes, missing files,
byte/hash mismatch, unsafe paths, duplicate cases, absent boot evidence and settlement mismatches.
