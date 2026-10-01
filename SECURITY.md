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

Require the **`trusted site-data leak gate`** check in repository rules — it is required here, and
the paragraph stays in the imperative because a fork inherits the workflow and not the setting. Its
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
job as approval.

### The sanitization: done, and what it does not undo

**This section is a record, not a task.** It used to read as pending work — it said the scheduled
`--all` job "is expected to stay red until the old reachable history has been sanitized", and told
the reader to coordinate a destructive rewrite "before making the repository public". Both are now
false, and leaving them standing is worse than saying nothing: a public repository should not tell
its readers that a disclosure remediation is still outstanding when it is not.

Measured 2026-08-23:

- Reachable history begins at this repository's initial import — 37 commits when this was last
  measured, and the count grows with ordinary work. The load-bearing half is the *beginning*, not
  the number: that is the shape route 1 below produces — a fresh repository from a scanned tree —
  rather than a rewrite of an older one. Recorded here as the observed state; this file did not
  perform it.
- `scripts/scan-public-history.mjs --all --require-hostname-pattern` **passes** over all of it. Run
  through the `trusted site-data leak gate` workflow, because that is the only place the hostname
  pattern exists. The address, key-material and credential classes also pass when the scanner is
  run locally without the pattern.
- `gitleaks` examines every commit on every push (`ci.yml`, the `leaks` job, full-depth checkout)
  and passes.
- `HELIOPAUSE_SITE_HOSTNAME_PATTERN` is configured, and `trusted site-data leak gate` is a required
  check.

**What none of that undoes.** Site-specific deployment documents and policy inventory were pushed to
a reachable remote before those directories became untracked. Treat that inventory as disclosed to
everyone who could read or mirror the former remote: a fresh repository does not recall clones,
forks, caches, or backups, and neither would a rewrite. The addresses in it are addresses of real
hosts, and that is a fact about the past which no future scan changes. It is the reason `docs/` and
`policy/` are untracked rather than sanitized — see the split in CONTRIBUTING.

### 2026-09-30 — 두 결정, 그리고 게이트가 보지 않는 곳

이 두 항목은 과제가 아니라 **기록**이다. 아래 둘은 검토되었고 수용되었다.

#### 커밋 메시지는 스캔되지 않는다 — 한 건 수용

`c8f1713` 의 커밋 메시지에 실제 mgmt 주소 하나(IPv6)와 그 기기의 v4·이름이 있다. 파일에서 그
값들을 **지우는** 커밋이었고, 무엇을 지웠는지 설명하려고 메시지에 인용했다.

`scripts/scan-public-history.mjs` 는 **blob 만 읽는다.** `git cat-file blob` 으로 트리의 내용을
보고, 커밋 메시지는 대상이 아니다. 그래서 이 경로는 게이트가 통과시킨 것이 아니라 **보지 않은**
것이고, 게이트를 고쳐서 막을 수 있는 종류가 아니다 — 메시지를 스캔하려면 그 자체가 다른 도구다.

같은 실수의 앞 판(`ab4ee35`)은 force push 로 브랜치에서 떨어졌지만 **GitHub API 로는 여전히
조회된다.** dangling object 는 서버 쪽 GC 전까지 URL 로 남고, 이력 재작성으로는 지워지지 않는다.

**이번 건은 수용한다(2026-09-30).** 재등록도, GC 요청도, 이력 재작성도 하지 않는다. 근거는
비용과 값의 비교다 — 재작성은 `main` ruleset 의 `non_fast_forward` 해제와 열린 브랜치들의
rebase 를 요구하는데, 그러고도 더 접근하기 쉬운 쪽(`ab4ee35` 의 URL)은 남는다. 노출된 값은
인증 수단이 아니고 WARP 인증 없이는 도달성을 주지 않으며, 재등록되면 바뀐다.

**다음에 같은 일이 생기면 그때 고친다.** 이 문단은 그 판단이 한 번 내려졌다는 기록이지,
앞으로도 같은 답이라는 뜻이 아니다. 특히 값이 인증 수단이거나 재등록으로 무효화되지 않는
종류라면 위 두 경로가 다시 후보다.

**그래서 남는 규칙 하나.** 사이트 값을 지우는 커밋은 **그 값을 메시지에 적지 않는다.** 무엇이
바뀌었는지는 diff 가 말한다.

#### `dispatch`·`heliopause`·`node-enroll` 은 공개 가능한 이름이다

이 세 호스트네임이 `src/manager-server.ts`·`src/manager-server.test.ts`·
`packaging/systemd/README.md` 에 있다. 누출 패턴(`HELIOPAUSE_SITE_HOSTNAME_PATTERN`)에 넣으면
그 게이트가 **영구히 빨개진다** — 트리에 이미 있기 때문이다.

**공개 가능한 이름으로 둔다(2026-09-30).** 셋 다 이 소프트웨어가 무엇을 하는지 설명하는 데
쓰이는 이름이고, 그 이름을 아는 것으로 도달할 수 있는 것은 없다. 패턴은 트리에 없는 이름을
위한 것이고, 트리에 있는 이름을 넣으면 보호는 0이면서 검사만 죽는다 — 그 조합은 「항상 빨간
검사」를 만들고, 항상 빨간 검사는 읽히지 않는다.

이것이 위 문단의 「disclosed to everyone who could read the former remote」와 다른 점은 **의도**다.
저쪽은 사고였고 이것은 결정이다.

### If a mirror is ever created, or this is ever re-bootstrapped

The same two routes apply, in the same order, and both require repository-owner coordination —
they are intentionally not something an ordinary remediation branch performs:

1. Create a fresh repository from a scanned clean tree, preserving no old objects; or
2. use `git filter-repo` to remove the affected paths and blobs from every branch and tag, delete
   stale remote refs, force-push the rewritten refs, and require every collaborator and deployment
   checkout to reclone.

After either route, run `node scripts/scan-public-history.mjs --all --require-hostname-pattern` with
the hostname pattern supplied only through the environment, and run a full-history credential scan.

## Supported versions

Pre-1.0, so only the current `main` receives fixes. There are no maintained release branches yet.
