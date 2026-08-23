# Contributing

## Running it

```bash
npm ci
npm run typecheck          # tsc --noEmit
npm test                   # renderers, protocol, gating, relay, publisher, PKI
npm run check:web          # Svelte template and component diagnostics — outside the root tsconfig
npm run build:web          # the console the manager serves. Type-checking it does not build it
npm run icons:check        # every icon name still exists in lucide-static
python3 agent/test_validate.py    # the agent's validator and rollback state machine
python3 agent/test_enroll.py      # host-generated key, durable CSR enrollment
```

Two suites need more than a checkout:

```bash
./scripts/e2e-roundtrip.sh   # python agent → mTLS → node relay. Needs openssl, python3, curl
./scripts/rollback-test.sh   # auto-rollback against a real kernel. Needs docker
```

There is no build step. Node 22 strips types and runs `.ts` directly, which is why the runtime
version is part of the contract rather than an implementation detail.

## What this project is careful about

heliopause decides what a host accepts on the network, and the failure that matters is not a crash.
It is a firewall that reports success while enforcing something other than what was written. Almost
every convention below follows from that.

**A rule is never quietly wider than its text.** Where a policy cannot be rendered faithfully, the
renderer refuses; where it must be narrowed, it warns. Neither is optional — a skipped rule on the
workload layer has no second layer behind it, because pod traffic never reaches netfilter at all.

**"Not known" and "none" are different answers.** They appear as `null` versus `[]` throughout, and
collapsing them is the most common way a defect gets in here. An unqueried selector reported as an
empty pod list reads as "this policy is inert"; an unreadable cluster reported as "no objects" reads
as a successful apply. Several fixed defects were exactly this.

**A check that cannot fail is not a check.** If a validation can never reject anything, or always
rejects, say so rather than leaving it as decoration.

**Measurements beat assumptions.** Where a comment explains why something is the way it is, it
should name what was measured. Several decisions in this codebase reversed after a reading.

## Comments

Comments explain *why*, not *what*. The code says what it does; a comment earns its place by saying
what would go wrong otherwise, or what was tried and rejected.

This matters more than usual here because much of the logic is about failure modes that are invisible
in normal operation. A future reader deciding whether a check is load-bearing needs to know which
measured failure it came from.

## Tests

**Test the property, not the implementation.** The test name should say what would break.

**Verify a new test can fail.** Introduce the defect deliberately, confirm the test catches it, then
revert. A regression test that passes against the broken code is worse than none: it certifies
something it never checked. This has caught real gaps — 275 tests once passed while a required field
was missing entirely, because every test read the structured half and nothing exercised the
serialised one.

**Site-specific tests stay untracked.** Tests importing `policy/` belong with the policy they test —
see the split below.

## The repository split

This repository is published; the network it manages is not.

```
upstream (library, public)      ←   org clone (operational, private)
  src/ · agent/ · bin/               + policy/ · docs/ · artifacts/
```

`docs/` and `policy/` are deliberately untracked. They hold measured public addresses, per-host open
port inventories and operator egress addresses — individually each is a fact worth recording, and
published together they are a target list with addresses attached.

So: **nothing site-specific in a tracked file.** Use RFC 5737 documentation ranges (`192.0.2.0/24`)
and RFC 2606 names (`example.com`) in tests and examples. CI enforces the address half of this; the
rest is review.

## Commits

Explain what was wrong and why the fix is what it is, not what changed — the diff already says that.
Where a defect was measured, include the measurement. Conventional-commit prefixes (`feat`, `fix`,
`docs`, `chore`) with a scope.

## Before opening a pull request

- `npm run typecheck && npm test && python3 agent/test_validate.py && python3 agent/test_enroll.py`
- New tests verified to fail against the defect they cover
- No site-specific data in tracked files
- Comments say why

## What CI runs, and what it cannot tell you

`ci.yml` runs everything above plus `e2e-roundtrip.sh` and `rollback-test.sh` — the two suites that
need more than a checkout — on every pull request, including one from a fork. Every job is on an
ephemeral GitHub-hosted VM, so there is no machine of ours a candidate's code could reach and
nothing to skip for an outside contribution.

Two more things run there and are worth knowing about before a red check surprises you:

- **`trusted site-data leak gate`** is the required one. It scans every commit a pull request
  introduces — including blobs added and later deleted — for addresses, key material and
  credentials. It is loaded from the default branch and never executes anything from the branch
  under review, so changing it in your pull request changes nothing about how you are scanned.
- **`workflow audit`** lints `.github/workflows` with actionlint and zizmor. A pull request that
  touches CI is the only one this normally has anything to say about.

CodeQL runs alongside and does **not** gate a merge; its findings land in the Security tab and as
annotations on the diff.

What none of this covers: the policy suite. `policy/` is untracked (see the split above), and
`node --test` passes a glob that matches nothing rather than failing on it — so a public checkout
runs a smaller suite and says so nowhere. If a change touches rendering, expect the site-side tests
to run somewhere this repository cannot see.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Anything that would let someone bypass or disable a deployed ruleset
goes to a private advisory rather than a public issue.
