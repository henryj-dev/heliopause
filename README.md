# heliopause

[![ci](https://github.com/henryj-dev/heliopause/actions/workflows/ci.yml/badge.svg)](https://github.com/henryj-dev/heliopause/actions/workflows/ci.yml)

**A host firewall you can't lock yourself out of.**

Declarative nftables management with a commit–confirm–auto-rollback control plane.

> The *heliopause* is the boundary where the Sun's protective bubble meets interstellar
> space — the edge of the region it shields. That is what this manages: the edge of your hosts.

---

## Why

Managing host firewalls at scale usually means one of:

- hand-written `nftables` rulesets, applied over SSH, with no way back if you get it wrong
- `firewalld` / `ufw`, which are fine locally but have no central policy, no audit trail,
  and no notion of "apply this everywhere, then verify"
- a config-management tool that happily pushes a rule that severs your own access

All of them share the same failure mode: **the change that locks you out is applied the
same way as any other change.**

heliopause makes that failure mode structurally hard:

1. The control plane renders a complete ruleset and validates its syntax **before** sending it.
2. The agent applies it and **arms a rollback timer**.
3. The control plane re-verifies it can still reach the agent, and only then confirms.
4. If anything fails — bad rule, severed route, crashed controller — the timer fires and the
   host restores its previous state, including "there was no table here before".

This is `commit confirmed` from network gear, applied to Linux hosts.

## Design constraints

These are not incidental; they come from operating this in production.

- **It only touches its own nftables table.** Your existing `firewalld` / `iptables` rules are
  never modified. The agent *rejects* a submitted ruleset that names any other table.
- **`flush ruleset` is refused**, always. It is one line away from wiping a host's firewall.
- **Baseline allow rules are non-removable.** Management paths (SSH, control-plane ports) are
  rendered ahead of policy rules, and a policy that would overlap them is rejected with a
  reason rather than silently neutralised.
- **`ct state established,related accept` comes first**, always. Without it a broad deny drops
  the replies to connections the host itself opened, and SSH dies mid-session.
- **Nothing is silently skipped.** A policy that can't be rendered comes back with a reason.
  Silent no-ops are how you end up believing in controls that don't exist.

## Status

Early. The core (policy model, renderer, agent, orchestration) is extracted from a system
running on production hosts; the packaging, configuration surface, and public API are new and
will change. Pin exact versions.

## How it fits together

```
  ┌────────────────┐   ruleset (nft -f text)    ┌──────────────┐
  │ control plane  │ ─────────────────────────► │    agent     │  one per host
  │  (this lib)    │ ◄───────────────────────── │  (python3)   │  stdlib only, no deps
  └────────────────┘   apply / confirm / roll   └──────────────┘
         │                                              │
         │ policies, address & service objects          │ owns exactly one nft table
         │ rendered → validated → planned               │ arms rollback on every apply
```

The control plane is a library, not a service: you embed it in whatever already knows your
inventory (which host has which address, which zone it is in). heliopause does not discover
your infrastructure — you inject a resolver.

A manager process sits on top for sites with more than one VPC: it aggregates every relay into one
view (`GET /site`), serves the console, and is the ordinary route for publishing a
generation — `POST /plan` → `POST /approve` → `POST /publish`, where the approval must come from a
different certificate than the proposal. It is optional in the strongest sense: relays keep serving
without it, and `heliopause-publish` writes straight to a gateway's artifact directory, so the way
out of an incident never depends on the manager being healthy.

The core stays as it is — zero runtime dependencies, no build step — and the console is optional on
top: `npm install heliopause` must not pull a frontend toolchain for the majority who use it as a
library. Everything the console can do has the same core/API and a CLI caller.

The manager console serves every screen: the policy, zone, device and coverage tables as well as
plans, node tokens, CSRs, signed certificates and fingerprint revocations. It renders the policy
without holding it — `heliopause-policy-render` is a separate deployment carrying a checkout and no
credential, and the console reads JSON from it. The policy repository stays out of the manager image
deliberately: a site module's top level is code, and this process holds the signing key.

`heliopause-ui` serves the same tables from a workstation checkout. It is not the other half of the
product; it is what reads your *uncommitted* working tree, and what still works when the cluster does
not. It binds loopback only and has no authentication, because the person who can run it can already
read the file — on `0.0.0.0` it would become an unauthenticated map of every allowed path into the
site.

### Managed policy document

```bash
node bin/heliopause-policy.ts export-site policy/dev.ts ./policies.json
node bin/heliopause-ui.ts policy/dev.ts --policies=./policies.json
node bin/heliopause-publish.ts policy/dev.ts dev --policies=./policies.json \
  --propose=https://manager.example:8444 --pki=./pki --operator=ops-alice
```

Schema 2 stores policy definitions and their host ingress, host egress or workload placements.
Publishing refuses an unplaced policy or an unknown host. Exporting an existing site preserves CIDR
order and therefore produces byte-identical nftables and Cilium artifacts.

### Standalone enrollment

Set `HELIOPAUSE_ENROLLMENT_STORE` on the manager. No Dispatcher, database or identity provider is
required; OIDC and OTP remain optional. Operate the same store locally or over the manager API:

```bash
node bin/heliopause-enrollment.ts init ./enrollment.json
node bin/heliopause-enrollment.ts token-create ./enrollment.json host-01.example --actor=ops-alice
node bin/heliopause-enrollment.ts csr-list https://manager.example:8444 --pki=./pki
node bin/heliopause-enrollment.ts cert-upload https://manager.example:8444 REQUEST_ID \
  --cert=./host.pem --ca-name=site --pki=./pki
node bin/heliopause-enrollment.ts cert-revoke https://manager.example:8444 \
  --cert=./host.pem --reason=retired --pki=./pki
```

Initialization is an explicit, one-time deployment step and refuses to overwrite an existing file.
The manager and every write command refuse a missing or malformed store; they never guess that a
deleted revocation ledger is a harmless first boot. Back up this file and restore it rather than
running `init` again after it has held any certificate revocations.

Point the manager at its enrollment store with `HELIOPAUSE_REVOCATION_FILE`. It sends a minimal
snapshot containing only `revocations` to every relay over the existing publisher mTLS identity at
startup, after each revocation, and once per minute. Provision each relay's empty denylist exactly
once with `bin/heliopause-revocations.ts init`; normal relay startup never creates or repairs that
file. A separate socket-activated, locked `heliopause-revocation-writer` service account owns the denylist and
accepts only bounded, strict, monotonic snapshots—an existing fingerprint cannot be omitted or
rewritten. The network-facing relay has only read access plus permission to connect to that one Unix
socket; it never opens the file for writing. Relays reload the file on every request. A missing or
malformed configured file prevents startup, and deletion or corruption while running fails closed
instead of restoring a revoked credential. See `packaging/systemd/README.md` for the required
sysusers, initialization, socket, and relay enable order.

When one publicly trusted certificate covers more than one entry name, set the exact SNI allowlist
with `HELIOPAUSE_PUBLIC_SERVER_NAMES=manager.example,node-ingest.example`. The legacy singular
`HELIOPAUSE_PUBLIC_SERVER_NAME` remains accepted for one-name deployments.

### Signing a host-generated CSR offline

The host keeps its private key. After comparing the CSR SHA-256 shown by the host with the value in
the enrollment queue over a separate channel, an operator can issue the fixed agent profile:

```bash
node bin/heliopause-pki.ts sign-csr ./offline-ca ./host.csr ./host.pem \
  --name=host-01.example \
  --expect-sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The fingerprint is mandatory. The command verifies the CSR signature, exact single-CN subject and
ECDSA P-256 key, refuses to overwrite an output, and applies the same 90-day `clientAuth`-only
profile as `heliopause-pki issue`. CSR-requested extensions are never copied. The CA private key
stays in `./offline-ca`; the host private key never reaches it.

## Development

```bash
npm ci
npm run typecheck
npm test                          # renderers, protocol, gating, relay, publisher, PKI
python3 agent/test_validate.py    # the agent's validator and rollback state machine
python3 agent/test_enroll.py      # host-generated key, durable CSR enrollment

./scripts/e2e-roundtrip.sh        # python agent → mTLS → node relay (needs openssl, python3, curl)
./scripts/rollback-test.sh        # auto-rollback against a real kernel (needs docker)
```

No build step — Node 22 strips types and runs `.ts` directly.

The last two suites are separate because of what they need, not how long they take: identity binding
cannot be unit-tested without a real TLS handshake, and whether a locking ruleset is actually
reverted cannot be tested without a real kernel.

[CONTRIBUTING.md](CONTRIBUTING.md) covers conventions and why they are what they are.
[SECURITY.md](SECURITY.md) says what this tool promises, what it does not, and where to send a
vulnerability.

## License

Apache-2.0
