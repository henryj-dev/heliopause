// The merge gate, and the four ways a gate like this passes something it should not have.
//
// Every test here is a "green" that is not one: a pull request nobody has checked yet, a check that
// is still running, a conclusion that is not a pass, and a proposer merging their own change because
// the console could not tell who proposed it. Each of those looks like success from the outside —
// no exception, no failing status — which is why they are pinned rather than reasoned about.
import { beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  checksAreGreen,
  checksUnreadable,
  forgetInstallationTokens,
  mergePullRequest,
  mergeRefusal,
  proposalBody,
  ProposalError,
  proposerFromBody,
  pullRequestChecks,
  pullRequestStatus,
  wouldMergeSolo,
  type AppCredentials,
  type CommitCheck,
  type Fetcher,
  type PullRequestStatus,
} from "./policy-proposal.ts";

beforeEach(() => forgetInstallationTokens());

const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "pkcs1", format: "pem" },
});

const creds: AppCredentials = { appId: "1", installationId: "2", privateKey };
const target = { owner: "o", repo: "r", base: "main" };
const HEAD = "a".repeat(40);

const fetcherFor = (
  routes: Array<{ match: RegExp; method?: string; status?: number; body?: unknown }>,
  seen: Array<{ url: string; method: string; body?: unknown }> = [],
): { fetch: Fetcher; seen: typeof seen } => ({
  seen,
  fetch: async (url, init) => {
    const method = init?.method ?? "GET";
    seen.push({ url, method, ...(init?.body ? { body: JSON.parse(init.body) } : {}) });
    const hit = routes.find((r) => r.match.test(url) && (r.method ?? "GET") === method);
    if (!hit) throw new Error(`no route for ${method} ${url}`);
    const status = hit.status ?? 200;
    return { ok: status < 400, status, text: async () => JSON.stringify(hit.body ?? {}) };
  },
});

const tokenRoute = { match: /access_tokens$/, method: "POST", body: { token: "t" } };

const statusOf = (over: Partial<PullRequestStatus> = {}): PullRequestStatus => ({
  number: 7,
  url: "https://example.invalid/pull/7",
  state: "open",
  merged: false,
  mergeCommitSha: null,
  headSha: HEAD,
  headRef: "policy/ops-alice/20260920-000000",
  baseSha: "b".repeat(40),
  baseRef: "main",
  mergeable: true,
  mergeableState: "clean",
  body: `heliopause-proposed-by: \`ops-alice\``,
  ...over,
});

const green: CommitCheck[] = [{ name: "check", state: "success", detail: "success" }];

describe("the proposer trailer", () => {
  // The round trip is the point. These two functions are written and read by different routes, in
  // different requests, possibly on different days — a body format changed on one side alone turns
  // every merge into "was not proposed from this console", which reads like a configuration problem.
  it("survives the body the console actually writes", () => {
    const body = proposalBody({ who: "ops-alice", site: "https://render.invalid", policies: 3, rendersNowhere: 0 });
    assert.equal(proposerFromBody(body), "ops-alice");
  });

  it("keeps saying it when the body also carries a plan", () => {
    const body = proposalBody({
      who: "ops-henry-review",
      site: "https://render.invalid",
      planHash: "sha256:abc",
      policies: 9,
      rendersNowhere: 1,
    });
    assert.equal(proposerFromBody(body), "ops-henry-review");
  });

  // The name renders as code in the pull request. An operator comparing it by eye sees `ops-alice`;
  // a comparison done on strings would see "`ops-alice`" and never match the certificate CN.
  it("strips the backticks the body renders the name in", () => {
    assert.equal(proposerFromBody("heliopause-proposed-by: `ops-alice`"), "ops-alice");
  });

  // Fail closed. A pull request opened by hand, or by another tool, has no trailer — and the absence
  // must not read as "nobody proposed it, so anybody may merge it".
  it("is null for a body that never named a proposer", () => {
    assert.equal(proposerFromBody("Looks good to me"), null);
    assert.equal(proposerFromBody(null), null);
    assert.equal(proposerFromBody(""), null);
  });

  it("is null when the line is there but empty", () => {
    assert.equal(proposerFromBody("heliopause-proposed-by:"), null);
    assert.equal(proposerFromBody("heliopause-proposed-by: ``"), null);
  });
});

describe("mergeRefusal", () => {
  it("lets a second operator merge a green pull request", () => {
    assert.equal(mergeRefusal({ status: statusOf(), checks: green, who: "ops-henry", proposer: "ops-alice" }), null);
  });

  // The rule the whole route exists for.
  it("refuses the operator who proposed it", () => {
    const why = mergeRefusal({ status: statusOf(), checks: green, who: "ops-alice", proposer: "ops-alice" });
    assert.match(String(why), /proposed by ops-alice/);
  });

  // The defect this pins is an absence: with no trailer to compare, a gate that only checked
  // `proposer === who` would compare `null === "ops-alice"`, find them different, and merge.
  it("refuses a pull request it cannot attribute", () => {
    const why = mergeRefusal({ status: statusOf({ body: null }), checks: green, who: "ops-henry", proposer: null });
    assert.match(String(why), /cannot say who proposed/);
  });

  // "No failures" and "nothing ran" are the same list. For the first seconds of a pull request's
  // life the second is true, which is exactly when a console button gets pressed.
  it("refuses a commit nothing has checked", () => {
    const why = mergeRefusal({ status: statusOf(), checks: [], who: "ops-henry", proposer: "ops-alice" });
    assert.match(String(why), /nothing has checked/);
    assert.equal(checksAreGreen([]), false);
  });

  it("names the check that failed, and the one still running", () => {
    const failed = mergeRefusal({
      status: statusOf(),
      checks: [{ name: "leak scan", state: "failure", detail: "failure" }, ...green],
      who: "ops-henry",
      proposer: "ops-alice",
    });
    assert.match(String(failed), /leak scan/);
    const pending = mergeRefusal({
      status: statusOf(),
      checks: [{ name: "auto-rollback against a real kernel", state: "pending", detail: "in_progress" }, ...green],
      who: "ops-henry",
      proposer: "ops-alice",
    });
    assert.match(String(pending), /still running.*auto-rollback/s);
  });

  // A failing check and a running one at once is not "still running" — an operator told to wait will
  // wait for something that has already decided against them.
  it("reports a failure ahead of a pending check", () => {
    const why = mergeRefusal({
      status: statusOf(),
      checks: [
        { name: "slow", state: "pending", detail: "queued" },
        { name: "typecheck", state: "failure", detail: "failure" },
      ],
      who: "ops-henry",
      proposer: "ops-alice",
    });
    assert.match(String(why), /failed/);
    assert.match(String(why), /typecheck/);
  });

  // null is GitHub still computing. Reading it as a permission would merge across a state that is
  // neither yes nor no, and it lasts a second or two after every push.
  it("waits while GitHub has not decided whether it merges", () => {
    const why = mergeRefusal({
      status: statusOf({ mergeable: null, mergeableState: "unknown" }),
      checks: green,
      who: "ops-henry",
      proposer: "ops-alice",
    });
    assert.match(String(why), /has not finished/);
  });

  it("refuses a branch that does not combine", () => {
    const why = mergeRefusal({
      status: statusOf({ mergeable: false, mergeableState: "dirty" }),
      checks: green,
      who: "ops-henry",
      proposer: "ops-alice",
    });
    assert.match(String(why), /dirty/);
  });

  // The order is the message: a merged pull request is not missing a check, and saying so sends an
  // operator to look at CI for something that already happened.
  it("says merged and closed before it says anything about checks", () => {
    assert.match(
      String(mergeRefusal({ status: statusOf({ merged: true }), checks: [], who: "ops-henry", proposer: "ops-alice" })),
      /already merged/,
    );
    assert.match(
      String(mergeRefusal({ status: statusOf({ state: "closed" }), checks: [], who: "ops-henry", proposer: "ops-alice" })),
      /is closed/,
    );
  });
});

describe("pullRequestChecks", () => {
  const checkRuns = (runs: unknown[], total = runs.length) => ({
    match: /check-runs/,
    body: { total_count: total, check_runs: runs },
  });
  const statuses = (rows: unknown[]) => ({ match: /commits\/[0-9a-f]+\/status/, body: { statuses: rows } });

  it("reads check runs and commit statuses as one list", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      checkRuns([{ name: "build", status: "completed", conclusion: "success" }]),
      statuses([{ context: "legacy/ci", state: "success" }]),
    ]);
    const out = await pullRequestChecks(creds, target, fetch, 1, HEAD);
    assert.deepEqual(out.map((c) => [c.name, c.state]), [["build", "success"], ["legacy/ci", "success"]]);
    assert.equal(checksAreGreen(out), true);
  });

  // A repository that reports only statuses would give an empty check-run list, and a gate reading
  // one API would call that green. This is the case where reading half is worse than reading none.
  it("does not call a status-only commit unchecked", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      checkRuns([]),
      statuses([{ context: "legacy/ci", state: "failure" }]),
    ]);
    assert.equal(checksAreGreen(await pullRequestChecks(creds, target, fetch, 1, HEAD)), false);
  });

  // Branch protection treats both as satisfied. A conditional job that correctly did not run must
  // not hold the merge forever.
  it("counts skipped and neutral as passes", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      checkRuns([
        { name: "docs only", status: "completed", conclusion: "skipped" },
        { name: "advisory", status: "completed", conclusion: "neutral" },
      ]),
      statuses([]),
    ]);
    assert.equal(checksAreGreen(await pullRequestChecks(creds, target, fetch, 1, HEAD)), true);
  });

  // `stale` means the result belongs to a commit that is no longer this one — the closest thing to a
  // pass that is not one.
  it("does not count stale, cancelled or timed out", async () => {
    for (const conclusion of ["stale", "cancelled", "timed_out", "action_required", "failure"]) {
      const { fetch } = fetcherFor([
        tokenRoute,
        checkRuns([{ name: conclusion, status: "completed", conclusion }]),
        statuses([]),
      ]);
      forgetInstallationTokens();
      const out = await pullRequestChecks(creds, target, fetch, 1, HEAD);
      assert.equal(out[0]?.state, "failure", conclusion);
    }
  });

  it("calls a run that has not completed pending, whatever it concluded before", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      checkRuns([{ name: "rollback", status: "in_progress", conclusion: null }]),
      statuses([]),
    ]);
    const out = await pullRequestChecks(creds, target, fetch, 1, HEAD);
    assert.deepEqual(out, [{ name: "rollback", state: "pending", detail: "in_progress" }]);
  });

  // Closed world, like `pullRequestChangedFiles`. A failing run on page two is a merge that passed a
  // gate which never saw it.
  it("refuses to answer when it cannot see every check", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      checkRuns([{ name: "one", status: "completed", conclusion: "success" }], 42),
      statuses([]),
    ]);
    await assert.rejects(() => pullRequestChecks(creds, target, fetch, 1, HEAD), /too many check runs/);
  });

  it("refuses a head that is not a sha", async () => {
    const { fetch } = fetcherFor([tokenRoute]);
    await assert.rejects(() => pullRequestChecks(creds, target, fetch, 1, "main"), /not a sha/);
  });
});

describe("pullRequestStatus", () => {
  // These three fields are what the gate reads. They were not parsed before the merge route existed,
  // and an unparsed `mergeable` defaults to `undefined` — which is neither `true` nor `null`, and so
  // would have fallen through a check written as `!== false`.
  it("carries mergeability and the body the trailer lives in", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      {
        match: /pulls\/7$/,
        body: {
          number: 7, html_url: "u", state: "open", merged: false,
          head: { sha: HEAD, ref: "policy/x" }, base: { sha: "b", ref: "main" },
          mergeable: true, mergeable_state: "clean", body: "heliopause-proposed-by: `ops-alice`",
        },
      },
    ]);
    const status = await pullRequestStatus(creds, target, fetch, 1, 7);
    assert.equal(status.mergeable, true);
    assert.equal(status.mergeableState, "clean");
    assert.equal(proposerFromBody(status.body), "ops-alice");
  });

  it("reports an absent mergeable as undecided rather than as false", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      {
        match: /pulls\/7$/,
        body: {
          number: 7, html_url: "u", state: "open", merged: false,
          head: { sha: HEAD, ref: "policy/x" }, base: { sha: "b", ref: "main" },
        },
      },
    ]);
    const status = await pullRequestStatus(creds, target, fetch, 1, 7);
    assert.equal(status.mergeable, null);
    assert.equal(status.mergeableState, "unknown");
    assert.equal(status.body, null);
  });
});

describe("mergePullRequest", () => {
  // The compare-and-set. Without `sha`, a commit pushed between the gate's read and this call is
  // merged carrying the *previous* commit's green checks — the race the gate exists to prevent.
  it("pins the merge to the head the gate decided about", async () => {
    const { fetch, seen } = fetcherFor([
      tokenRoute,
      { match: /pulls\/7\/merge$/, method: "PUT", body: { merged: true, sha: "c".repeat(40) } },
    ]);
    const out = await mergePullRequest(creds, target, fetch, 1, 7, HEAD);
    assert.equal(out.sha, "c".repeat(40));
    const put = seen.find((s) => s.method === "PUT");
    assert.deepEqual(put?.body, { merge_method: "squash", sha: HEAD });
  });

  // No invented title: the squash lands under the pull request's own, which is the sentence a
  // reviewer actually read.
  it("does not write a commit title nobody reviewed", async () => {
    const { fetch, seen } = fetcherFor([
      tokenRoute,
      { match: /pulls\/7\/merge$/, method: "PUT", body: { merged: true, sha: "c".repeat(40) } },
    ]);
    await mergePullRequest(creds, target, fetch, 1, 7, HEAD);
    const put = seen.find((s) => s.method === "PUT");
    assert.equal(Object.hasOwn(put?.body as object, "commit_title"), false);
  });

  // A 200 that says `merged: false` is GitHub declining without an error status. Returning its sha
  // to a caller would report a merge that did not happen.
  it("refuses to report a merge GitHub did not make", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      { match: /pulls\/7\/merge$/, method: "PUT", body: { merged: false } },
    ]);
    await assert.rejects(() => mergePullRequest(creds, target, fetch, 1, 7, HEAD), /did not merge/);
  });

  it("passes the 409 through when the head moved", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      { match: /pulls\/7\/merge$/, method: "PUT", status: 409, body: { message: "Head branch was modified" } },
    ]);
    await assert.rejects(
      () => mergePullRequest(creds, target, fetch, 1, 7, HEAD),
      (e: unknown) => e instanceof ProposalError && e.status === 409,
    );
  });
});

describe("checks the console is not allowed to read", () => {
  // The failure measured on 2026-09-20, on the first merge anybody tried: the installation had
  // `contents` and `pull_requests` — enough to commit and to open the pull request — and no
  // `checks`. Every merge would have answered 502 forever.
  it("names the permission for the refusal GitHub actually sends", () => {
    const why = checksUnreadable(
      new ProposalError("GET /repos/o/r/commits/aaa/check-runs → 403: Resource not accessible by integration", 403),
      creds,
      target,
    );
    assert.match(String(why), /may not read checks on o\/r/);
    assert.match(String(why), /Checks: read/);
    // The app id, because an organisation has several and the operator has to open the right one.
    assert.match(String(why), /id 1/);
  });

  // GitHub hides some resources from an unpermitted installation rather than refusing them. A gate
  // that recognised only 403 would fall back to the unreadable 502 for the other half.
  it("treats a 404 the same way", () => {
    assert.ok(checksUnreadable(new ProposalError("not found", 404), creds, target));
  });

  // A 500 is not a fact about this console's credential. Reporting it as one sends the operator to
  // edit an App that was never the problem.
  it("does not blame the permissions for anything else", () => {
    assert.equal(checksUnreadable(new ProposalError("boom", 500), creds, target), null);
    assert.equal(checksUnreadable(new ProposalError("rate limited", 429), creds, target), null);
    assert.equal(checksUnreadable(new Error("socket hang up"), creds, target), null);
    assert.equal(checksUnreadable("not an error", creds, target), null);
  });

  // The distinction the whole thing exists for. Both refuse; only one of them is worth waiting on.
  it("refuses with the permission sentence rather than with 'nothing has checked'", () => {
    const why = mergeRefusal({
      status: statusOf(),
      checks: [],
      who: "ops-henry",
      proposer: "ops-alice",
      checksUnavailable: "this console's app may not read checks",
    });
    assert.equal(why, "this console's app may not read checks");
    assert.doesNotMatch(String(why), /nothing has checked/);
  });

  // An unreadable check must never be softer than an unread one.
  it("never lets an unreadable check become a pass", () => {
    assert.equal(
      mergeRefusal({
        status: statusOf(),
        checks: green,
        who: "ops-henry",
        proposer: "ops-alice",
        checksUnavailable: "cannot read",
      }),
      "cannot read",
      "a stale green list must not outvote the fact that checks could not be read",
    );
  });

  // Order: the pull request's own facts first. Telling somebody to fix an App permission on a pull
  // request that is already merged is true and useless.
  it("still says merged, closed and self-proposed first", () => {
    const args = { checks: [], who: "ops-alice", proposer: "ops-alice", checksUnavailable: "cannot read" };
    assert.match(String(mergeRefusal({ ...args, status: statusOf({ merged: true }) })), /already merged/);
    assert.match(String(mergeRefusal({ ...args, status: statusOf({ state: "closed" }) })), /is closed/);
    assert.match(String(mergeRefusal({ ...args, status: statusOf() })), /proposed by ops-alice/);
  });
});

describe("one person, two names", () => {
  // `ops-henry` and `ops-henry-review` are two certificate CNs and one human — the manager knows
  // because both map to the same identity-provider account. Comparing the proposer to the caller's
  // name alone let that human propose as one and merge as the other.
  //
  // **The harm is not that one person merged alone.** It is that the record says two people did.
  // `approval.ts` argues exactly this for the plan; this is the same argument for the source.
  it("refuses the other certificate of the same human", () => {
    const why = mergeRefusal({
      status: statusOf(),
      checks: green,
      who: "ops-henry-review",
      proposer: "ops-henry",
      alsoKnownAs: ["ops-henry"],
    });
    assert.match(String(why), /is the same person/);
    assert.match(String(why), /proposed by ops-henry/);
  });

  // The known negative. Without it the rule passes against an implementation that refuses every
  // merge whose proposer differs from the caller — which is no rule at all, it is a stuck gate.
  it("still lets a genuinely different operator merge", () => {
    assert.equal(
      mergeRefusal({
        status: statusOf(),
        checks: green,
        who: "ops-henry",
        proposer: "ops-alice",
        alsoKnownAs: ["ops-henry-review"],
      }),
      null,
      "ops-alice is not one of this caller's names",
    );
  });

  it("knows when a merge would be solo, whichever name proposed it", () => {
    assert.equal(wouldMergeSolo({ who: "ops-henry", proposer: "ops-henry" }), true);
    assert.equal(wouldMergeSolo({ who: "ops-henry", proposer: "ops-henry-review", alsoKnownAs: ["ops-henry-review"] }), true);
    assert.equal(wouldMergeSolo({ who: "ops-henry", proposer: "ops-alice" }), false);
    // Unattributed is not solo — it is unattributed, and `mergeRefusal` refuses it on its own line.
    assert.equal(wouldMergeSolo({ who: "ops-henry", proposer: null }), false);
  });
});

describe("the solo hatch", () => {
  // The same escape the publish path opens one step later, and for the same stated reason: this site
  // has one operator, and without it nothing authored in the console could ever be merged from it.
  it("lets a solo-capable operator merge what they proposed", () => {
    assert.equal(
      mergeRefusal({ status: statusOf(), checks: green, who: "ops-alice", proposer: "ops-alice", maySolo: true }),
      null,
    );
  });

  it("still refuses them without the role", () => {
    assert.match(
      String(mergeRefusal({ status: statusOf(), checks: green, who: "ops-alice", proposer: "ops-alice" })),
      /does not merge it/,
    );
  });

  // The hatch is about *who*, not about *what*. Opening it must not also wave through a red check,
  // an unreadable one, or a branch that does not combine — each of those is a separate refusal and
  // each would be a different kind of accident.
  it("opens nothing else", () => {
    const solo = { who: "ops-alice", proposer: "ops-alice", maySolo: true } as const;
    assert.match(
      String(mergeRefusal({ ...solo, status: statusOf(), checks: [{ name: "ci", state: "failure", detail: "failure" }] })),
      /checks failed/,
    );
    assert.match(String(mergeRefusal({ ...solo, status: statusOf(), checks: [] })), /nothing has checked/);
    assert.match(
      String(mergeRefusal({ ...solo, status: statusOf(), checks: green, checksUnavailable: "cannot read" })),
      /cannot read/,
    );
    assert.match(
      String(mergeRefusal({ ...solo, status: statusOf({ mergeable: false, mergeableState: "dirty" }), checks: green })),
      /dirty/,
    );
    assert.match(String(mergeRefusal({ ...solo, status: statusOf({ merged: true }), checks: green })), /already merged/);
  });

  // Attribution comes first, and the hatch does not substitute for it: a pull request this console
  // did not open has no proposer to be the same as.
  it("does not rescue a pull request it cannot attribute", () => {
    assert.match(
      String(mergeRefusal({ status: statusOf({ body: null }), checks: green, who: "ops-alice", proposer: null, maySolo: true })),
      /cannot say who proposed/,
    );
  });
});
