// The write path, and the failure it must never have: overwriting somebody else's edit quietly.
//
// Everything here is about a request that *succeeded* while meaning something other than what the
// caller assumed — a branch that already existed, a file that moved under the editor, a 422 that is
// not a duplicate. None of those throw on their own.
import { beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  appJwt,
  branchName,
  commitToBranch,
  ensureRepositoryFileOnBranch,
  findPullRequestByBranch,
  forgetInstallationTokens,
  installationToken,
  isUsableBranchName,
  openPullRequest,
  pullRequestHumanApprovals,
  pullRequestChangedFiles,
  proposalBody,
  sameCommit,
  ProposalError,
  type AppCredentials,
  type Fetcher,
} from "./policy-proposal.ts";

// The installation token is cached per process, so one test warming it would change what the next
// one observes on its route table — a test that stopped exercising the exchange and did not say so.
beforeEach(() => forgetInstallationTokens());

const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "pkcs1", format: "pem" },
});

const creds: AppCredentials = { appId: "1", installationId: "2", privateKey };
const target = { owner: "o", repo: "r", base: "main" };

/** A fetcher driven by a route table. Unlisted routes fail loudly rather than returning a default. */
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
const baseRefRoute = { match: /git\/ref\/heads\/main$/, body: { object: { sha: "basesha" } } };

describe("appJwt", () => {
  // A container clock a few seconds ahead of GitHub's produces an `iat` in the future, which they
  // reject — and the rejection reads like a bad key.
  it("backdates iat so a fast clock does not invalidate the token", () => {
    const [, body] = appJwt(creds, 1_000_000).split(".");
    const claims = JSON.parse(Buffer.from(body!, "base64url").toString("utf8"));
    assert.ok(claims.iat < 1_000_000, "iat must be in the past");
    assert.ok(claims.exp > 1_000_000);
    assert.equal(claims.iss, "1");
  });
});

describe("branchName", () => {
  it("says who and when", () => {
    assert.equal(branchName("ops-alice", "2026-08-13T04:05:06Z"), "policy/ops-alice/20260813-040506");
  });

  // The name arrives from a certificate CN or an OIDC claim. A `/` would create a nested ref
  // namespace that a later ref collides with, and git reports that as a checkout failure somewhere
  // else entirely.
  it("slugs a name that would otherwise nest a ref", () => {
    const b = branchName("evil/../main", "2026-08-13T04:05:06Z");
    const [prefix, who, stamp, ...rest] = b.split("/");
    assert.equal(prefix, "policy");
    assert.equal(rest.length, 0, b);
    assert.ok(who && stamp);
    // git refuses a ref containing `..`. The slug survives the slash but must not survive this.
    assert.doesNotMatch(b, /\.\./, b);
  });

  it("keeps a single dot, which names legitimately carry", () => {
    assert.match(branchName("ops@example.com", "2026-08-13T04:05:06Z"), /^policy\/ops-example\.com\//);
  });

  it("falls back rather than producing an empty segment", () => {
    assert.match(branchName("!!!", "2026-08-13T04:05:06Z"), /^policy\/operator\//);
  });
});

describe("commitToBranch", () => {
  const edit = { target, path: "dev.ts", content: "x", message: "m", branch: "policy/a/b" };

  // The whole reason this module reads before it writes. Without the sha GitHub accepts the write
  // and the other operator's edit is gone, with nothing anywhere saying so.
  it("sends the current file sha so a concurrent edit is rejected, not overwritten", async () => {
    const { fetch, seen } = fetcherFor([
      tokenRoute, baseRefRoute,
      { match: /git\/refs$/, method: "POST", body: {} },
      { match: /contents\/dev\.ts\?ref=/, body: { sha: "filesha" } },
      { match: /contents\/dev\.ts$/, method: "PUT", body: { commit: { sha: "new" } } },
    ]);
    const out = await commitToBranch(creds, fetch, 0, edit);
    assert.equal(out.commit, "new");
    const put = seen.find((s) => s.method === "PUT")!;
    assert.equal((put.body as { sha?: string }).sha, "filesha");
  });

  it("omits the sha for a file that does not exist yet", async () => {
    const { fetch, seen } = fetcherFor([
      tokenRoute, baseRefRoute,
      { match: /git\/refs$/, method: "POST", body: {} },
      { match: /contents\/dev\.ts\?ref=/, status: 404, body: { message: "Not Found" } },
      { match: /contents\/dev\.ts$/, method: "PUT", body: { commit: { sha: "new" } } },
    ]);
    await commitToBranch(creds, fetch, 0, edit);
    const put = seen.find((s) => s.method === "PUT")!;
    assert.equal((put.body as { sha?: string }).sha, undefined);
  });

  // 404 means "new file". Anything else means something is wrong with the request or the
  // installation, and treating it as "new file" would write over whatever is actually there.
  it("does not treat a non-404 read failure as a new file", async () => {
    const { fetch } = fetcherFor([
      tokenRoute, baseRefRoute,
      { match: /git\/refs$/, method: "POST", body: {} },
      { match: /contents\/dev\.ts\?ref=/, status: 403, body: { message: "Resource not accessible" } },
    ]);
    await assert.rejects(() => commitToBranch(creds, fetch, 0, edit), /403/);
  });

  it("tolerates a branch that already exists", async () => {
    const { fetch } = fetcherFor([
      tokenRoute, baseRefRoute,
      { match: /git\/refs$/, method: "POST", status: 422, body: { message: "Reference already exists" } },
      { match: /contents\/dev\.ts\?ref=/, body: { sha: "filesha" } },
      { match: /contents\/dev\.ts$/, method: "PUT", body: { commit: { sha: "new" } } },
    ]);
    const out = await commitToBranch(creds, fetch, 0, edit);
    assert.equal(out.commit, "new");
  });

  it("does not tolerate any other ref failure", async () => {
    const { fetch } = fetcherFor([
      tokenRoute, baseRefRoute,
      { match: /git\/refs$/, method: "POST", status: 403, body: { message: "nope" } },
    ]);
    await assert.rejects(() => commitToBranch(creds, fetch, 0, edit), /403/);
  });

  it("refuses when the base branch has no commit", async () => {
    const { fetch } = fetcherFor([tokenRoute, { match: /git\/ref\/heads\/main$/, body: {} }]);
    await assert.rejects(() => commitToBranch(creds, fetch, 0, edit), /no commit to branch from/);
  });

  // The status alone sends the reader to the wrong layer; GitHub's sentence says which input was wrong.
  it("keeps GitHub's reason in the error", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      { match: /git\/ref\/heads\/main$/, status: 404, body: { message: "Branch not found" } },
    ]);
    await assert.rejects(() => commitToBranch(creds, fetch, 0, edit), /Branch not found/);
  });
});

describe("idempotent machine-owned branch updates", () => {
  it("derives desired bytes from the branch after creation, not from a stale base read", async () => {
    const current = '{"schemaVersion":1,"retiredHosts":[{"hostname":"already.dev"}]}\n';
    const { fetch, seen } = fetcherFor([
      tokenRoute, baseRefRoute,
      { match: /git\/refs$/, method: "POST", body: {} },
      { match: /git\/ref\/heads\/policy%2Fa%2Fb$/, body: { object: { sha: "branch-head" } } },
      { match: /contents\/retired-hosts\.json\?ref=/, body: {
        encoding: "base64", content: Buffer.from(current).toString("base64"), sha: "blob-sha",
      } },
      { match: /contents\/retired-hosts\.json$/, method: "PUT", body: { commit: { sha: "new-head" } } },
    ]);
    const out = await ensureRepositoryFileOnBranch(creds, fetch, 0, {
      target, path: "retired-hosts.json", message: "m", branch: "policy/a/b",
      transform: (content) => content.replace("]}", ',{"hostname":"next.dev"}]}'),
    });
    assert.equal(out.commit, "new-head");
    const put = seen.find((call) => call.method === "PUT")!;
    const written = Buffer.from(String((put.body as { content: string }).content), "base64").toString("utf8");
    assert.match(written, /already\.dev/);
    assert.match(written, /next\.dev/);
  });

  it("recovers a pull request that merged before its number was durably recorded", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      { match: /\/pulls\?head=.*state=all/, body: [{
        number: 9, html_url: "https://example.test/pull/9", state: "closed",
        merged_at: "2026-08-31T00:00:00Z", merge_commit_sha: "c".repeat(40),
        head: { sha: "b".repeat(40), ref: "policy/a/b" }, base: { ref: "main" },
      }] },
    ]);
    const found = await findPullRequestByBranch(creds, target, fetch, 0, "policy/a/b");
    assert.equal(found?.number, 9);
    assert.equal(found?.merged, true);
  });

  it("accepts only each human reviewer's latest approval of the exact durable head", async () => {
    const head = "b".repeat(40);
    const { fetch } = fetcherFor([
      tokenRoute,
      { match: /\/pulls\/9\/reviews\?per_page=100$/, body: [
        { id: 1, state: "APPROVED", commit_id: head, submitted_at: "2026-08-31T00:00:00Z", user: { login: "alice", type: "User" } },
        { id: 2, state: "CHANGES_REQUESTED", commit_id: head, submitted_at: "2026-08-31T00:01:00Z", user: { login: "alice", type: "User" } },
        { id: 3, state: "APPROVED", commit_id: "a".repeat(40), submitted_at: "2026-08-31T00:02:00Z", user: { login: "bob", type: "User" } },
        { id: 4, state: "APPROVED", commit_id: head, submitted_at: "2026-08-31T00:03:00Z", user: { login: "policy-bot", type: "Bot" } },
        { id: 5, state: "APPROVED", commit_id: head, submitted_at: "2026-08-31T00:04:00Z", user: { login: "carol", type: "User" } },
      ] },
    ]);
    assert.deepEqual(await pullRequestHumanApprovals(creds, target, fetch, 0, 9, head), ["carol"]);
  });

  it("fails closed when one review page cannot prove there is no later decision", async () => {
    const head = "b".repeat(40);
    const reviews = Array.from({ length: 100 }, (_, id) => ({
      id: id + 1, state: "APPROVED", commit_id: head,
      submitted_at: `2026-08-31T00:${String(id % 60).padStart(2, "0")}:00Z`,
      user: { login: `reviewer-${id}`, type: "User" },
    }));
    const { fetch } = fetcherFor([
      tokenRoute,
      { match: /\/pulls\/9\/reviews\?per_page=100$/, body: reviews },
    ]);
    await assert.rejects(
      () => pullRequestHumanApprovals(creds, target, fetch, 0, 9, head),
      /too many reviews/,
    );
  });

  it("lists the exact changed-file scope and refuses an ambiguous full page", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      { match: /\/pulls\/9\/files\?per_page=100$/, body: [{ filename: "retired-hosts.json" }] },
    ]);
    assert.deepEqual(await pullRequestChangedFiles(creds, target, fetch, 0, 9), ["retired-hosts.json"]);

    const { fetch: crowded } = fetcherFor([
      tokenRoute,
      { match: /\/pulls\/9\/files\?per_page=100$/, body: Array.from({ length: 100 }, (_, i) => ({ filename: `f-${i}` })) },
    ]);
    await assert.rejects(
      () => pullRequestChangedFiles(creds, target, crowded, 0, 9),
      /too many changed files/,
    );
  });
});

describe("openPullRequest", () => {
  const input = { target, branch: "policy/a/b", title: "t", body: "b" };

  it("opens one", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      { match: /\/pulls$/, method: "POST", body: { number: 7, html_url: "u" } },
    ]);
    assert.deepEqual(await openPullRequest(creds, fetch, 0, input), { number: 7, url: "u" });
  });

  it("returns the existing one when the branch already has a pull request", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      { match: /\/pulls$/, method: "POST", status: 422, body: { message: "A pull request already exists" } },
      { match: /\/pulls\?head=/, body: [{ number: 3, html_url: "old" }] },
    ]);
    assert.deepEqual(await openPullRequest(creds, fetch, 0, input), { number: 3, url: "old" });
  });

  // 422 also covers "No commits between main and this branch" — an edit that changed nothing. That
  // is not a duplicate, and reporting it as one would hand back a pull request number for a change
  // that was never made.
  it("rethrows a 422 that is not a duplicate", async () => {
    const { fetch } = fetcherFor([
      tokenRoute,
      { match: /\/pulls$/, method: "POST", status: 422, body: { message: "No commits between main and policy/a/b" } },
      { match: /\/pulls\?head=/, body: [] },
    ]);
    await assert.rejects(() => openPullRequest(creds, fetch, 0, input), /No commits between/);
  });
});

// ── One encoding rule, applied in every function ────────────────────────────
//
// `repoHead` and `compareGenerations` encoded the target; `commitToBranch` and `openPullRequest`
// interpolated it raw. Nothing was exploitable — owner, repo and base are deployment configuration —
// but a file where the same value is handled two ways is one where a reader has to work out which
// way is intended, and the answer is the one the other two functions already gave.
//
// Tested because encoding is the kind of thing that regresses invisibly: an unencoded path works for
// every value anyone has tried.

describe("the GitHub target is encoded the same way everywhere", () => {
  const odd = { owner: "o o", repo: "r/r", base: "release/2.0" };
  const edit = { target: odd, path: "dev.ts", content: "x", message: "m", branch: "policy/a/b" };

  it("encodes owner, repo and base when committing", async () => {
    const { fetch, seen } = fetcherFor([
      tokenRoute,
      { match: /git\/ref\/heads\/release%2F2\.0$/, body: { object: { sha: "basesha" } } },
      { match: /git\/refs$/, method: "POST", body: {} },
      { match: /contents\/dev\.ts\?ref=/, status: 404, body: { message: "Not Found" } },
      { match: /contents\/dev\.ts$/, method: "PUT", body: { commit: { sha: "new" } } },
    ]);
    await commitToBranch(creds, fetch, 0, edit);
    for (const call of seen.filter((s) => s.url.includes("/repos/"))) {
      assert.ok(call.url.includes("/repos/o%20o/r%2Fr"), `raw target in ${call.url}`);
    }
  });

  it("encodes them when opening a pull request", async () => {
    const { fetch, seen } = fetcherFor([
      tokenRoute,
      { match: /\/pulls$/, method: "POST", body: { number: 1, html_url: "u" } },
    ]);
    await openPullRequest(creds, fetch, 0, { target: odd, branch: "b", title: "t", body: "b" });
    const pulls = seen.find((s) => s.url.endsWith("/pulls"))!;
    assert.ok(pulls.url.includes("/repos/o%20o/r%2Fr"), `raw target in ${pulls.url}`);
  });
});

describe("proposalBody", () => {
  // A reviewer who thinks the pull request is the whole gate will merge and expect the fleet to
  // move. It will not, and nothing else on the page says so.
  it("says merging does not publish", () => {
    const b = proposalBody({ who: "w", site: "dev.ts", planHash: "sha256:x", policies: 3, rendersNowhere: 0 });
    assert.match(b, /does \*\*not\*\* publish/);
    assert.match(b, /sha256:x/);
  });

  it("marks policies that render nothing", () => {
    const b = proposalBody({ who: "w", site: "dev.ts", policies: 3, rendersNowhere: 2 });
    assert.match(b, /2 render nowhere/);
  });

  it("says so when no plan was rendered", () => {
    const b = proposalBody({ who: "w", site: "dev.ts", policies: 3, rendersNowhere: 0 });
    assert.match(b, /nothing has been proposed to the fleet/);
    assert.doesNotMatch(b, /does \*\*not\*\* publish/);
  });
});

describe("sameCommit — the comparison a staleness banner rests on", () => {
  it("matches an abbreviated sha against the full one", () => {
    // The renderer reports `git rev-parse --short`; GitHub returns forty characters. `===` between
    // them is always false, which is a banner that always fires — and one that always fires is
    // switched off within the week, taking the real warning with it.
    assert.equal(sameCommit("6e17455", "6e17455bd0d2c0a4c2f9e8f0a1b2c3d4e5f60718"), true);
    assert.equal(sameCommit("6e17455bd0d2c0a4c2f9e8f0a1b2c3d4e5f60718", "6e17455"), true);
  });

  it("says no when they are different commits", () => {
    assert.equal(sameCommit("6e17455", "0aaaaaabd0d2c0a4c2f9e8f0a1b2c3d4e5f60718"), false);
  });

  it("refuses a prefix too short to mean anything", () => {
    // Four hex characters match one commit in sixty-five thousand by chance. A banner that stays
    // quiet because of a coincidence is worse than no banner.
    assert.equal(sameCommit("6e17", "6e17455bd0d2c0a4c2f9e8f0a1b2c3d4e5f60718"), false);
  });

  it("says no rather than yes when it was given nothing", () => {
    // A checkout with no git answers `null`. Treating unknown as equal is how "we could not check"
    // becomes "it is fine" — the failure this whole banner exists to stop.
    assert.equal(sameCommit(null, "6e17455bd0d2c0a4c2f9e8f0a1b2c3d4e5f60718"), false);
    assert.equal(sameCommit("6e17455", null), false);
    assert.equal(sameCommit(null, null), false);
  });
});

describe("the installation token is not re-minted per call", () => {
  // Four functions in this file each began with `installationToken`, so a single `/policy/propose`
  // spent three exchanges and every policy-screen poll spent another — against a rate limit shared
  // with the thing that actually needs it. The manager's own `repoHeadCache` comment names that cost
  // one layer up.
  it("mints once and reuses it inside the window", async () => {
    const { fetch, seen } = fetcherFor([tokenRoute]);
    assert.equal(await installationToken(creds, fetch, 1_000), "t");
    assert.equal(await installationToken(creds, fetch, 1_000 + 60), "t");
    assert.equal(seen.filter((s) => s.url.endsWith("access_tokens")).length, 1);
  });

  it("mints again before the hour GitHub gives is actually up", async () => {
    // Retired ten minutes early, so a request that starts just before expiry cannot arrive after it.
    const { fetch, seen } = fetcherFor([tokenRoute]);
    await installationToken(creds, fetch, 1_000);
    await installationToken(creds, fetch, 1_000 + 50 * 60);
    assert.equal(seen.filter((s) => s.url.endsWith("access_tokens")).length, 2);
  });

  it("does not hand one installation's token to another", async () => {
    const { fetch, seen } = fetcherFor([tokenRoute]);
    await installationToken(creds, fetch, 1_000);
    await installationToken({ ...creds, installationId: "99" }, fetch, 1_000);
    assert.equal(seen.filter((s) => s.url.endsWith("access_tokens")).length, 2);
  });
});

describe("isUsableBranchName", () => {
  // `branchName` slugs the operator's name and says why a `/` in it would be a problem — and
  // `POST /policy/edit` accepts a `branch` from the body, which skipped that argument entirely.
  it("accepts what this console emits and what a person would type", () => {
    assert.equal(isUsableBranchName(branchName("ops@example.com", "2026-08-24T09:00:00.000Z")), true);
    assert.equal(isUsableBranchName("policy/narrow-idp"), true);
    assert.equal(isUsableBranchName("fix_1.2-rc"), true);
  });

  it("refuses what git refuses, and what would climb out of the namespace", () => {
    for (const bad of [
      "", "   ", "policy/../main", "/policy/x", "policy/x/", "policy//x",
      ".hidden", "policy/.hidden", "policy/x.", "policy/x.lock",
      "policy/a b", "policy/a~b", "policy/a^b", "policy/a:b", "policy/a?b", "policy/a*b",
      "policy/a\\b", "policy/a\nb", `policy/${"x".repeat(300)}`,
    ]) {
      assert.equal(isUsableBranchName(bad), false, `${JSON.stringify(bad)} should be refused`);
    }
  });
});
