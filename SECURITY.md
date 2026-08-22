# Security

heliopause decides what a host accepts on the network. A defect here is not a crash — it is a
firewall that reports success while enforcing something other than what was written. Reports about
that class of behaviour are welcome, and this document says where to send them and what the project
already promises.

## Reporting a vulnerability

Open a [security advisory](https://github.com/henryj-dev/heliopause/security/advisories/new) on the
repository. That keeps the report private until there is something to publish.

Please do not open a public issue for anything that would let someone bypass or disable a deployed
ruleset. Everything else — a crash, a bad error message, a rendering bug that fails loudly — is
fine as an ordinary issue.

**What to expect.** This is a small project without a staffed security team, so the honest answer is
that reports are read when someone is at the keyboard, usually within a week. There is no bounty.

**What helps.** The generation id and the rendered artifact, if you have them — the artifact is the
exact input the agent acted on, and it makes the difference between reproducing a report and
guessing at it. Do not include private keys or certificates; the CA key in particular is the trust
root for a whole fleet.

## What is in scope

The properties below are the ones the design commits to. A way to violate any of them is a
vulnerability even if nothing crashes.

**An agent applies only what its manager published.** The artifact is validated structurally against
an allowlist before it reaches the kernel, and anything naming a table, chain type or hook outside
the agent's own is refused. Talking that validator past its allowlist is in scope.

**A host cannot report as another host.** The relay binds the claimed host in a heartbeat to the
subject CN of the client certificate and refuses a mismatch. Without that, staged rollout is
decorative: a compromised low-value host reports as the canary, the gate opens on a generation
nobody tested, and a locking policy proceeds to the fleet. Any way to report under another identity
is in scope.

**A ruleset that severs the management path is reverted without help.** The agent arms a rollback
timer at apply and cancels it only on a later successful heartbeat, and the commitment is persisted
so it survives the agent's own death. Anything that leaves a host applied-but-unrecoverable — a
timer that does not fire, a commitment that is lost across a restart — is in scope.

**A rendered rule is never wider than what was written.** Where the renderer cannot express a policy
faithfully it refuses rather than emitting an approximation, and where it must narrow one it warns.
A policy that renders to something broader than its text, silently, is in scope. (Several such
defects have been found and fixed; they are recorded in the deployment notes.)

**The relay cannot invent policy.** It serves what the manager published and gates on what agents
reported. A way to make a relay hand an agent a ruleset the manager did not publish is in scope.

**Revocation state is fail-closed and monotonic.** The relay validates the denylist at startup and
on every authenticated request. A separate locked service account owns the file and accepts updates only over
a group-restricted Unix socket; the relay cannot truncate, rename, chmod, unlink, or directly replace
it. Missing or malformed state refuses authenticated traffic, and an update may add rows but never
omit or rewrite one already installed. When the manager uses its enrollment store as the revocation
source, that store likewise requires an explicit one-time `heliopause-enrollment init`; manager
startup and later transactions never recreate missing state.

## What is out of scope

These are limits of the design rather than defects, and they are stated so a report is not spent on
them.

**Root on the host.** heliopause runs in the same kernel it manages. Root can `nft flush ruleset`
and there is no defence against that from inside — the agent will report the drift, which is the
guarantee, not prevention.

**Traffic that never reaches netfilter.** On a node running Cilium, pod and ClusterIP traffic is
resolved in eBPF and does not traverse netfilter at all. No nftables rule can govern it. That is why
there is a second renderer for CiliumNetworkPolicy; a report that "the host ruleset does not block a
pod destination" is describing the design.

**Published container ports.** Docker and Podman DNAT in `prerouting`, so a published port reaches
the container through `forward` — a hook heliopause deliberately does not manage. Inbound to a
published port does not pass through its rules.

**Whoever holds the CA key.** Certificate issuance is the trust root. Someone who can mint an agent
certificate can enrol a host, and someone who can mint a relay certificate can tell agents what to
apply. Protecting that key is the operator's, not the tool's.

**Policy that is wrong.** The tool renders what it is given. A policy that opens a port it should not
is a policy bug; the tool's job is to make what it will do visible before it does it.

**Arbitrary code already executing inside the relay.** Privilege separation protects the durable
denylist from that process, including across restart, but the relay is still the TLS request handler.
Arbitrary code in it can refuse all traffic or skip its own live certificate check until systemd
restarts it. Preventing that requires moving mTLS termination/revocation enforcement into a separate
proxy, not only separating the snapshot writer. The writer deliberately accepts additions from the
relay group, so a compromised relay can also add revocations (availability loss) but cannot remove or
rewrite an existing one.

## Repository history and site inventory

Deleting a file or adding it to `.gitignore` does not remove an older Git blob. Site-specific
deployment documents and policy inventory were pushed to reachable remote history before those
directories became untracked. The current tree no longer carries them, and CI now examines every
new commit—including intermediate blobs later deleted—for non-documentation addresses, private-key
material, general credentials, and an out-of-tree private-hostname pattern. Configure the repository
Actions secret `HELIOPAUSE_SITE_HOSTNAME_PATTERN` with an escaped alternation covering every private
site domain; the values must not be committed to this repository.

Require the **`trusted site-data leak gate`** check in repository rules. Its
`pull_request_target` workflow is loaded from the protected default branch, fetches the candidate
only as inert Git objects, and executes only the scanner from that protected default branch. It grants only
`contents: read`, persists no checkout credential, and never runs a candidate Action, script, hook,
package command, or scanner. Candidate paths and matched values are reduced to an opaque source hash
before output, so a newline, ANSI sequence, or workflow-command-shaped filename cannot inject a log
annotation. The ordinary `pull_request`/push job receives no private-hostname pattern and is only a
detection backstop: a candidate can change that workflow, and a post-push check cannot undo a direct
push that already landed.

There is one bootstrap boundary: GitHub cannot run a newly added `pull_request_target` workflow until
that workflow and scanner exist on the default branch. Introduce them in an owner-reviewed,
manually-scanned bootstrap change (preferably by themselves), then configure
`HELIOPAUSE_SITE_HOSTNAME_PATTERN` and make `trusted site-data leak gate` required **before** accepting
later feature changes. For the bootstrap itself, run the trusted local scanner against every
introduced commit and inspect the workflow diff; do not treat the candidate-controlled ordinary CI
job as approval. The scheduled trusted job scans `--all`, so it is expected to stay red until the
old reachable history described below has been sanitized.

That prevention does not sanitize the already distributed history. Before making the repository
public or adding a new mirror, coordinate one of these destructive, repository-wide operations:

1. Create a fresh repository from a scanned clean tree, preserving no old objects; or
2. use `git filter-repo` to remove the affected paths and blobs from every branch and tag, delete
   stale remote refs, force-push the rewritten refs, and require every collaborator and deployment
   checkout to reclone.

After either route, run `node scripts/scan-public-history.mjs --all --require-hostname-pattern` with
the hostname pattern supplied only through the environment, and run a full-history credential scan.
Treat the old inventory as disclosed to everyone who could read or mirror the former remote; history
rewriting cannot recall clones, forks, caches, or backups. These steps require repository-owner
coordination and intentionally are not performed by an ordinary remediation branch.

## Supported versions

Pre-1.0, so only the current `main` receives fixes. There are no maintained release branches yet.
