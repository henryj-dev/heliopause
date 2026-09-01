// The console's write path: a policy edit becomes a branch, and a proposal becomes a pull request.
//
// ## Why a branch and not a commit to main
//
// Editing policy in a browser is editing a firewall. `main` is what the publisher renders from and
// what the generation id names, so a console that wrote straight to it would make "I clicked save"
// and "the fleet's next generation" the same event, with review happening — if at all — afterwards.
//
// ## What this deliberately does not do
//
// **It does not merge, and it does not publish.** Those are different questions and this module
// answers neither:
//
//   merge     adopts the source. A human reviews the diff in the pull request.
//   publish   hangs a generation on the fleet. That path already exists and keeps its own gate —
//             a two-person approval on the **bundle hash**, an OTP, a staged rollout and a rollback
//             on silence. A pull request approves *source*; those approve what agents will apply,
//             and the two are not the same artefact. A policy can review perfectly and render
//             nothing — `renders-nowhere` is a column on the policy screen for that reason.
//
// ## Why a GitHub App and not a deploy key
//
// A deploy key speaks git and nothing else, so it can push a branch and cannot open a pull request.
// The App's installation is scoped to the policy repository alone, with `contents:write` and
// `pull_requests:write` — measured after installation, because the first install landed on the code
// repository instead and would have given the console write access to the thing it never edits.
//
// The read-only sync key stays separate. It is mounted continuously in a sidecar; this credential is
// used only inside a request an operator authenticated. A credential that sits mounted forever
// should be the weaker of the two.
import { createSign } from "node:crypto";
import { readBoundedText } from "./bounded-body.ts";

/**
 * How much of GitHub's answer this will hold.
 *
 * A `compare` between two generations carries a unified diff per changed file, and the first real
 * one this console produced was 176 changed lines across nine commits — kilobytes. The ceiling is
 * generous because the failure it would cause is an approval screen that stops working on a large
 * change, and bounded because this runs in the process that holds the signing key.
 */
const MAX_GITHUB_RESPONSE_BYTES = 16 * 1024 * 1024;

export interface AppCredentials {
  appId: string;
  installationId: string;
  /** PEM. Never logged, never rendered. */
  privateKey: string;
}

export interface ProposalTarget {
  owner: string;
  repo: string;
  /** The branch pull requests target. */
  base: string;
}

/**
 * Minimal fetch shape, so tests do not reach the network.
 *
 * `body` and `headers` on the *response* are optional because the real `fetch` has them and a
 * substituted reader need not. `readBoundedText` treats that as a contract rather than a
 * coincidence: with a stream it bounds before allocating, without one it bounds after. See its
 * comment for why the two are not the same guarantee.
 */
export type Fetcher = (url: string, init?: {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}) => Promise<{
  ok: boolean;
  status: number;
  text: () => Promise<string>;
  headers?: { get(name: string): string | null };
  body?: ReadableStream<Uint8Array> | null;
}>;

export class ProposalError extends Error {
  // Declared, not a constructor parameter property. Node runs this repository's TypeScript in
  // strip-only mode, which cannot rewrite `constructor(readonly x)` into a field assignment — it
  // refuses the whole module. Measured; the tests would not load.
  readonly status: number | undefined;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "ProposalError";
    this.status = status;
  }
}

/**
 * A JWT signed with the App's key, good for ten minutes.
 *
 * `iat` is backdated a minute. GitHub rejects a token whose `iat` is in the future, and a container
 * clock a few seconds ahead of theirs is enough to produce one — a failure that looks like a bad key.
 */
export function appJwt(creds: AppCredentials, nowSec: number): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const head = enc({ alg: "RS256", typ: "JWT" });
  const body = enc({ iat: nowSec - 60, exp: nowSec + 540, iss: creds.appId });
  const signer = createSign("RSA-SHA256");
  signer.update(`${head}.${body}`);
  return `${head}.${body}.${signer.sign(creds.privateKey, "base64url")}`;
}

const API = "https://api.github.com";

async function gh(
  fetcher: Fetcher,
  token: string,
  path: string,
  method = "GET",
  body?: unknown,
  scheme = "Bearer",
): Promise<unknown> {
  const res = await fetcher(`${API}${path}`, {
    method,
    headers: {
      authorization: `${scheme} ${token}`,
      accept: "application/vnd.github+json",
      "content-type": "application/json",
      "user-agent": "heliopause-console",
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await readBoundedText(res, MAX_GITHUB_RESPONSE_BYTES, `${method} ${path}`);
  if (!res.ok) {
    // The body carries GitHub's reason — "Reference already exists", "No commits between …". Losing
    // it leaves the operator with a status code and no idea which of their inputs was wrong.
    throw new ProposalError(`${method} ${path} → ${res.status}: ${text.slice(0, 300)}`, res.status);
  }
  return text ? JSON.parse(text) : {};
}

/**
 * Exchange the App JWT for an installation token. Short-lived by construction — GitHub gives an hour.
 *
 * ## Cached, because four functions here each minted their own
 *
 * `repoHead`, `compareGenerations`, `commitToBranch` and `openPullRequest` all began with this call,
 * so one `POST /policy/propose` spent at least three and every `/policy/screen` poll spent one more
 * on top of the `repoHead` cache that already exists. `manager-server.ts` names the cost where it
 * caches the head sha: *"every poll would otherwise spend an installation rate limit shared with the
 * thing that actually needs it — proposing."* The same argument applies one layer down.
 *
 * Keyed by installation, so a deployment with more than one credential does not hand the wrong token
 * to the wrong repository. Retired **ten minutes early**: the token is good for an hour, and a
 * request that starts just before expiry must not arrive just after it.
 *
 * In memory and per process, like everything else here. Losing it costs one extra exchange.
 */
const installationTokens = new Map<string, { token: string; goodUntilSec: number }>();
const INSTALLATION_TOKEN_TTL_SEC = 50 * 60;

export async function installationToken(
  creds: AppCredentials,
  fetcher: Fetcher,
  nowSec: number,
): Promise<string> {
  const key = `${creds.appId}/${creds.installationId}`;
  const cached = installationTokens.get(key);
  if (cached && cached.goodUntilSec > nowSec) return cached.token;

  const jwt = appJwt(creds, nowSec);
  const out = (await gh(
    fetcher,
    jwt,
    `/app/installations/${encodeURIComponent(creds.installationId)}/access_tokens`,
    "POST",
  )) as { token?: string };
  if (!out.token) throw new ProposalError("the installation did not return a token");
  installationTokens.set(key, { token: out.token, goodUntilSec: nowSec + INSTALLATION_TOKEN_TTL_SEC });
  return out.token;
}

/** Drop every cached installation token. For a test, and for a credential rotation. */
export function forgetInstallationTokens(): void {
  installationTokens.clear();
}

/**
 * The sha the policy repository's base branch is actually on.
 *
 * ## Why the console needs to ask
 *
 * The policy screen prints a generation, and until 2026-08-16 nothing checked that it was current.
 * The renderer had served a checkout frozen at pod start for eleven hours — `head.sha` included —
 * and the screen stated it confidently: an approver read pre-narrowing rules on the page where they
 * approved the narrowing. The cache bug is fixed, but "the screen believes something about the
 * repository and nobody asks the repository" is the shape that produced it, and that shape survives
 * its instances.
 *
 * So this is the second opinion. It comes from GitHub rather than from the renderer, which is the
 * point: a stale renderer cannot report its own staleness, exactly as a stopped clock cannot report
 * the time.
 *
 * `/git/ref/heads/<base>` rather than `/commits/<base>`: a ref read is one object and cannot be
 * confused by a branch name that also matches a tag or a path, which the commits endpoint accepts.
 */
export async function repoHead(
  creds: AppCredentials,
  target: ProposalTarget,
  fetcher: Fetcher,
  nowSec: number,
): Promise<string> {
  const token = await installationToken(creds, fetcher, nowSec);
  const out = (await gh(
    fetcher,
    token,
    `/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}` +
      `/git/ref/heads/${encodeURIComponent(target.base)}`,
  )) as { object?: { sha?: string } };
  const sha = out.object?.sha;
  if (typeof sha !== "string" || sha.length < 7) {
    throw new ProposalError("the repository did not return a head sha for its base branch");
  }
  return sha;
}

/**
 * Is this file written by a machine rather than by a person?
 *
 * `coverage-*.json` is the coverage probes' output, committed by CI on every run. The same pattern
 * is what `readCoverageProbes` looks for, so this is the repository's own convention rather than a
 * guess made here.
 *
 * ## Why an approval screen needs to know
 *
 * Measured on the first real diff this console produced: eight of nine commits and 174 of 176 changed
 * lines were coverage output, and the one line a person wrote — the change actually being approved —
 * sat underneath them. A diff nobody scrolls to the end of is a diff nobody read, and the whole point
 * of showing it is that the second person sees what they are agreeing to.
 *
 * Generated files are still listed, with their counts. Hiding them would be a different lie: the
 * generation being approved does contain them, and an approver who later found unlisted changes in it
 * would be right to distrust the screen.
 */
export function isGeneratedPolicyFile(path: string): boolean {
  const name = path.slice(path.lastIndexOf("/") + 1);
  return /^coverage-.*\.json$/.test(name);
}

/** One file's change between two commits, as GitHub reports it. */
export interface ChangedFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  /** The unified diff, when GitHub sent one. Absent for binary or very large files. */
  patch?: string;
}

/**
 * What changed in the policy between two generations.
 *
 * ## Why the approver needs this and not a ruleset diff
 *
 * A plan already shows the rendered ruleset per host, and an approver can read it. What they cannot
 * read from it is **what is different** — the screen shows sixteen rules where fifteen were there
 * before, and finding the one that moved is a job for a machine. Today an approver either takes the
 * proposer's word for the change or re-derives it by hand, and the two-person rule is worth exactly
 * as much as the second person's ability to see what they are agreeing to.
 *
 * A ruleset-level diff would need the bytes each host is currently running, and the relay serves
 * those only to the host that owns them (`/artifact` is keyed on the client CN). The policy diff is
 * both cheaper and closer to the decision: rules are authored here, and this is the text a person
 * wrote.
 *
 * `base` is the generation the fleet is on, `head` is the generation being approved. Both are the
 * short shas this system calls generations; GitHub resolves them.
 */
export async function compareGenerations(
  creds: AppCredentials,
  target: ProposalTarget,
  base: string,
  head: string,
  fetcher: Fetcher,
  nowSec: number,
): Promise<{ commits: { sha: string; message: string; author: string }[]; files: ChangedFile[] }> {
  const token = await installationToken(creds, fetcher, nowSec);
  const out = (await gh(
    fetcher,
    token,
    `/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}` +
      `/compare/${encodeURIComponent(base)}...${encodeURIComponent(head)}`,
  )) as {
    commits?: { sha?: string; commit?: { message?: string; author?: { name?: string } } }[];
    files?: { filename?: string; status?: string; additions?: number; deletions?: number; patch?: string }[];
  };
  return {
    commits: (out.commits ?? []).map((c) => ({
      sha: String(c.sha ?? "").slice(0, 7),
      // First line only. A commit body in this repository runs to paragraphs, and a list of
      // paragraphs is not a list.
      message: String(c.commit?.message ?? "").split("\n")[0] ?? "",
      author: String(c.commit?.author?.name ?? ""),
    })),
    files: (out.files ?? []).map((f) => ({
      filename: String(f.filename ?? ""),
      status: String(f.status ?? ""),
      additions: Number(f.additions ?? 0),
      deletions: Number(f.deletions ?? 0),
      ...(typeof f.patch === "string" ? { patch: f.patch } : {}),
    })),
  };
}

/**
 * Do two shas name the same commit, one of them possibly abbreviated?
 *
 * The renderer reports `git rev-parse --short`, which is seven characters or more depending on what
 * the repository needs to stay unambiguous; GitHub returns forty. Comparing them with `===` is a
 * check that is always false, which is a banner that always cries — and a banner that always cries
 * is removed within the week, taking the real warning with it.
 */
export function sameCommit(a: string | null, b: string | null): boolean {
  if (!a || !b) return false;
  const [short, long] = a.length <= b.length ? [a, b] : [b, a];
  return short.length >= 7 && long.startsWith(short);
}

/**
 * A branch name that says who and when without needing a lookup.
 *
 * The operator name is slugged rather than trusted: it arrives from a certificate CN or an OIDC
 * claim, and a `/` in it would silently create a nested ref namespace that later refs collide with.
 */
export function branchName(who: string, at: string): string {
  const slug =
    who
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      // git refuses a ref containing `..`, and an operator name is not a place to find that out.
      // A dot survives on its own because names legitimately carry them — `ops@example.com`
      // becomes `ops-example.com` and stays readable.
      .replace(/\.{2,}/g, ".")
      .replace(/^[.-]+|[.-]+$/g, "") || "operator";
  const stamp = at.replace(/[-:]/g, "").replace(/\.\d+/, "").replace("T", "-").replace("Z", "");
  return `policy/${slug}/${stamp}`;
}

/**
 * Is this a branch name this console is willing to create?
 *
 * ## Why `branchName` alone was not the gate it reads as
 *
 * That function slugs the operator's name and says why — a `/` in it "would silently create a nested
 * ref namespace that later refs collide with". But `POST /policy/edit` accepts a `branch` in the
 * request body and only falls back to `branchName` when it is absent, so a caller supplying one
 * skipped the whole argument. Every writer is authenticated and GitHub refuses a malformed ref, so
 * nothing escaped — what was wrong is that the invariant had a documented reason and an open door.
 *
 * The shape is what this console itself emits plus room for a person naming a branch by hand:
 * segments of letters, digits, dot, dash, underscore, separated by `/`. Everything git objects to is
 * outside that — `..`, a leading or trailing dot, a trailing `.lock`, a control character, a space —
 * and so is anything that would climb out of the `policy/` namespace.
 */
export function isUsableBranchName(branch: string): boolean {
  if (!branch || branch.length > 255) return false;
  if (branch.includes("..") || branch.includes("//")) return false;
  if (branch.startsWith("/") || branch.endsWith("/")) return false;
  return branch
    .split("/")
    .every((segment) =>
      segment.length > 0 &&
      /^[A-Za-z0-9._-]+$/.test(segment) &&
      !segment.startsWith(".") &&
      !segment.endsWith(".") &&
      !segment.endsWith(".lock"));
}

export interface EditInput {
  target: ProposalTarget;
  /** Path inside the repository, e.g. `dev.ts`. */
  path: string;
  /** The whole file. Policy files are edited as a unit; a patch would need a merge this cannot do. */
  content: string;
  message: string;
  branch: string;
}

/**
 * Commit a file onto a branch, creating the branch from `base` when it does not exist.
 *
 * The blob is sent with the file's current sha when one exists — GitHub rejects the write otherwise,
 * and that rejection is the point: it means somebody changed the file since this editor read it, and
 * silently overwriting them is the failure a firewall repository can least afford.
 */
export async function commitToBranch(
  creds: AppCredentials,
  fetcher: Fetcher,
  nowSec: number,
  input: EditInput,
): Promise<{ branch: string; commit: string }> {
  const token = await installationToken(creds, fetcher, nowSec);
  const { owner, repo, base } = input.target;
  // Encoded, like `repoHead` and `compareGenerations`. These two were the only functions in this
  // file interpolating the target raw, which is a difference a reader has to notice rather than a
  // decision anyone made.
  const at = (p: string) => `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}${p}`;

  const baseRef = (await gh(fetcher, token, at(`/git/ref/heads/${encodeURIComponent(base)}`))) as { object?: { sha?: string } };
  const baseSha = baseRef.object?.sha;
  if (!baseSha) throw new ProposalError(`${base} has no commit to branch from`);

  try {
    await gh(fetcher, token, at("/git/refs"), "POST", { ref: `refs/heads/${input.branch}`, sha: baseSha });
  } catch (e) {
    // Already there — a second edit on the same branch is ordinary, and re-creating a ref is not.
    if (!(e instanceof ProposalError) || e.status !== 422) throw e;
  }

  let sha: string | undefined;
  try {
    const existing = (await gh(
      fetcher, token, at(`/contents/${encodeURIComponent(input.path)}?ref=${encodeURIComponent(input.branch)}`),
    )) as { sha?: string };
    sha = existing.sha;
  } catch (e) {
    // A new file. Anything other than "not there" is a real failure and should not be swallowed.
    if (!(e instanceof ProposalError) || e.status !== 404) throw e;
  }

  const put = (await gh(fetcher, token, at(`/contents/${encodeURIComponent(input.path)}`), "PUT", {
    message: input.message,
    content: Buffer.from(input.content, "utf8").toString("base64"),
    branch: input.branch,
    ...(sha ? { sha } : {}),
  })) as { commit?: { sha?: string } };

  return { branch: input.branch, commit: put.commit?.sha ?? "" };
}

export interface PullRequestInput {
  target: ProposalTarget;
  branch: string;
  title: string;
  body: string;
}

export interface RepositoryFile {
  content: string;
  /** Git blob sha, used for compare-and-swap updates through the contents API. */
  sha: string;
}

/** Read one repository file at an exact ref. Executable policy is never evaluated here. */
export async function readRepositoryFile(
  creds: AppCredentials,
  target: ProposalTarget,
  fetcher: Fetcher,
  nowSec: number,
  path: string,
  ref: string,
): Promise<RepositoryFile> {
  const token = await installationToken(creds, fetcher, nowSec);
  const out = (await gh(
    fetcher,
    token,
    `/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}` +
      `/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(ref)}`,
  )) as { content?: string; encoding?: string; sha?: string };
  if (out.encoding !== "base64" || typeof out.content !== "string" || typeof out.sha !== "string") {
    throw new ProposalError(`repository file ${JSON.stringify(path)} did not arrive as base64 content`);
  }
  return { content: Buffer.from(out.content.replaceAll("\n", ""), "base64").toString("utf8"), sha: out.sha };
}

/**
 * Put one exact file on a deterministic branch, idempotently.
 *
 * A retry after GitHub accepted the PUT but before the enrollment transaction committed sees the
 * desired bytes and returns the branch head instead of manufacturing another commit. The file must
 * already exist: the host-retirement document is an explicit policy-repository migration, and a
 * typo in its configured path must not create a second, unused document that looks successful.
 */
export async function ensureRepositoryFileOnBranch(
  creds: AppCredentials,
  fetcher: Fetcher,
  nowSec: number,
  input: Omit<EditInput, "content"> & { content?: string; transform?: (current: string) => string },
): Promise<{ branch: string; commit: string; changed: boolean }> {
  const token = await installationToken(creds, fetcher, nowSec);
  const { owner, repo, base } = input.target;
  const at = (p: string) => `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}${p}`;
  const baseRef = (await gh(fetcher, token, at(`/git/ref/heads/${encodeURIComponent(base)}`))) as {
    object?: { sha?: string };
  };
  const baseSha = baseRef.object?.sha;
  if (!baseSha) throw new ProposalError(`${base} has no commit to branch from`);
  try {
    await gh(fetcher, token, at("/git/refs"), "POST", { ref: `refs/heads/${input.branch}`, sha: baseSha });
  } catch (e) {
    if (!(e instanceof ProposalError) || e.status !== 422) throw e;
  }
  const branchRef = (await gh(
    fetcher, token, at(`/git/ref/heads/${encodeURIComponent(input.branch)}`),
  )) as { object?: { sha?: string } };
  const currentHead = branchRef.object?.sha;
  if (!currentHead) throw new ProposalError(`branch ${input.branch} has no head commit`);
  const current = await readRepositoryFile(creds, input.target, fetcher, nowSec, input.path, input.branch);
  if ((input.content === undefined) === (input.transform === undefined)) {
    throw new ProposalError("file update requires exactly one of content or transform");
  }
  // Computed from the branch after it was created. Building desired bytes from an earlier base read
  // can erase a retirement merged in between the read and branch creation.
  const desired = input.transform ? input.transform(current.content) : input.content!;
  if (current.content === desired) {
    return { branch: input.branch, commit: currentHead, changed: false };
  }
  const put = (await gh(fetcher, token, at(`/contents/${encodeURIComponent(input.path)}`), "PUT", {
    message: input.message,
    content: Buffer.from(desired, "utf8").toString("base64"),
    branch: input.branch,
    sha: current.sha,
  })) as { commit?: { sha?: string } };
  const commit = put.commit?.sha;
  if (!commit) throw new ProposalError("repository did not return the policy commit sha");
  return { branch: input.branch, commit, changed: true };
}

/** Find the PR for a deterministic head branch, including one merged before a crash was recorded. */
export async function findPullRequestByBranch(
  creds: AppCredentials,
  target: ProposalTarget,
  fetcher: Fetcher,
  nowSec: number,
  branch: string,
): Promise<PullRequestStatus | null> {
  const token = await installationToken(creds, fetcher, nowSec);
  const rows = (await gh(
    fetcher,
    token,
    `/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}/pulls` +
      `?head=${encodeURIComponent(`${target.owner}:${branch}`)}&state=all&per_page=10`,
  )) as Array<{
    number?: number; html_url?: string; state?: string; merged_at?: string | null;
    merge_commit_sha?: string | null; head?: { sha?: string; ref?: string };
    base?: { sha?: string; ref?: string };
  }>;
  const row = rows.find((candidate) => candidate.state === "open") ?? rows[0];
  if (!row) return null;
  if (!Number.isSafeInteger(row.number) || typeof row.html_url !== "string"
    || !["open", "closed"].includes(String(row.state)) || typeof row.head?.sha !== "string"
    || typeof row.head.ref !== "string" || typeof row.base?.ref !== "string") {
    throw new ProposalError(`pull request lookup for ${branch} returned an invalid status`);
  }
  return {
    number: row.number!,
    url: row.html_url,
    state: row.state as "open" | "closed",
    merged: typeof row.merged_at === "string",
    mergeCommitSha: typeof row.merge_commit_sha === "string" ? row.merge_commit_sha : null,
    headSha: row.head.sha,
    headRef: row.head.ref,
    baseSha: typeof row.base.sha === "string" ? row.base.sha : null,
    baseRef: row.base.ref,
  };
}

export interface PullRequestStatus {
  number: number;
  url: string;
  state: "open" | "closed";
  merged: boolean;
  mergeCommitSha: string | null;
  headSha: string;
  headRef: string;
  /** Exact base commit GitHub records for the PR; required by crash recovery before local CAS. */
  baseSha: string | null;
  baseRef: string;
}

/** Poll review/merge outcome without attempting to review or merge. */
export async function pullRequestStatus(
  creds: AppCredentials,
  target: ProposalTarget,
  fetcher: Fetcher,
  nowSec: number,
  number: number,
): Promise<PullRequestStatus> {
  if (!Number.isSafeInteger(number) || number < 1) throw new ProposalError("pull request number is invalid");
  const token = await installationToken(creds, fetcher, nowSec);
  const out = (await gh(
    fetcher,
    token,
    `/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}/pulls/${number}`,
  )) as {
    number?: number; html_url?: string; state?: string; merged?: boolean;
    merge_commit_sha?: string | null; head?: { sha?: string; ref?: string };
    base?: { sha?: string; ref?: string };
  };
  if (out.number !== number || typeof out.html_url !== "string" || !["open", "closed"].includes(String(out.state))
    || typeof out.merged !== "boolean" || typeof out.head?.sha !== "string"
    || typeof out.head.ref !== "string" || typeof out.base?.ref !== "string") {
    throw new ProposalError(`pull request #${number} returned an invalid status`);
  }
  return {
    number,
    url: out.html_url,
    state: out.state as "open" | "closed",
    merged: out.merged,
    mergeCommitSha: typeof out.merge_commit_sha === "string" ? out.merge_commit_sha : null,
    headSha: out.head.sha,
    headRef: out.head.ref,
    baseSha: typeof out.base.sha === "string" ? out.base.sha : null,
    baseRef: out.base.ref,
  };
}

/**
 * Files GitHub attributes to one pull request, with a closed-world page bound.
 *
 * The host-retirement recovery path uses this as a scope proof. Silently accepting the first page
 * would let an additional policy edit hide on page two, so a full page is ambiguous and refused.
 */
export async function pullRequestChangedFiles(
  creds: AppCredentials,
  target: ProposalTarget,
  fetcher: Fetcher,
  nowSec: number,
  number: number,
): Promise<string[]> {
  if (!Number.isSafeInteger(number) || number < 1) throw new ProposalError("pull request number is invalid");
  const token = await installationToken(creds, fetcher, nowSec);
  const rows = (await gh(
    fetcher,
    token,
    `/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}` +
      `/pulls/${number}/files?per_page=100`,
  )) as Array<{ filename?: string }>;
  if (rows.length >= 100) {
    throw new ProposalError(`pull request #${number} has too many changed files to prove its exact scope`);
  }
  if (rows.some((row) => typeof row.filename !== "string" || row.filename.length === 0)) {
    throw new ProposalError(`pull request #${number} returned an invalid changed file`);
  }
  return rows.map((row) => row.filename!);
}

/**
 * Human approvals of the exact durable head. The latest submitted review per GitHub user wins;
 * an older approval followed by CHANGES_REQUESTED is not approval, and bot reviews are not human.
 */
export async function pullRequestHumanApprovals(
  creds: AppCredentials,
  target: ProposalTarget,
  fetcher: Fetcher,
  nowSec: number,
  number: number,
  headSha: string,
): Promise<string[]> {
  if (!Number.isSafeInteger(number) || number < 1) throw new ProposalError("pull request number is invalid");
  const token = await installationToken(creds, fetcher, nowSec);
  const rows = (await gh(
    fetcher,
    token,
    `/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}/pulls/${number}/reviews?per_page=100`,
  )) as Array<{
    id?: number; state?: string; commit_id?: string; submitted_at?: string;
    user?: { login?: string; type?: string };
  }>;
  if (rows.length >= 100) {
    throw new ProposalError(`pull request #${number} has too many reviews to prove the latest human decision`);
  }
  const latest = new Map<string, { id: number; state: string; commit: string; submittedAt: string; type: string }>();
  for (const row of rows) {
    if (!Number.isSafeInteger(row.id) || typeof row.state !== "string" || typeof row.commit_id !== "string"
      || typeof row.submitted_at !== "string" || !Number.isFinite(Date.parse(row.submitted_at))
      || typeof row.user?.login !== "string" || typeof row.user.type !== "string") {
      throw new ProposalError(`pull request #${number} returned an invalid review`);
    }
    const previous = latest.get(row.user.login);
    if (!previous || row.submitted_at > previous.submittedAt
      || (row.submitted_at === previous.submittedAt && row.id! > previous.id)) {
      latest.set(row.user.login, {
        id: row.id!, state: row.state, commit: row.commit_id,
        submittedAt: row.submitted_at, type: row.user.type,
      });
    }
  }
  return [...latest.entries()]
    .filter(([, review]) => review.type === "User" && review.state === "APPROVED" && review.commit === headSha)
    .map(([login]) => login)
    .sort();
}

/** Open the pull request. Returns the existing one when the branch already has an open PR. */
export async function openPullRequest(
  creds: AppCredentials,
  fetcher: Fetcher,
  nowSec: number,
  input: PullRequestInput,
): Promise<{ number: number; url: string }> {
  const token = await installationToken(creds, fetcher, nowSec);
  const { owner, repo, base } = input.target;
  try {
    const pr = (await gh(fetcher, token, `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls`, "POST", {
      title: input.title,
      head: input.branch,
      base,
      body: input.body,
    })) as { number: number; html_url: string };
    return { number: pr.number, url: pr.html_url };
  } catch (e) {
    if (!(e instanceof ProposalError) || e.status !== 422) throw e;
    // 422 covers both "already exists" and "no commits between" — the second is not a duplicate and
    // must not be reported as one, so the open PR is looked up rather than assumed.
    const open = (await gh(
      fetcher, token,
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls` +
        `?head=${encodeURIComponent(`${owner}:${input.branch}`)}&state=open`,
    )) as Array<{ number: number; html_url: string }>;
    const first = open[0];
    if (!first) throw e;
    return { number: first.number, url: first.html_url };
  }
}

/**
 * What the pull request says.
 *
 * It names the rendered plan rather than describing the diff. GitHub shows the diff perfectly well;
 * what a reviewer cannot see there is whether the change renders into anything, which is the
 * question the console's own approval answers. Linking the two keeps a reviewer from believing the
 * pull request is the whole gate.
 */
export function proposalBody(input: {
  who: string;
  site: string;
  planHash?: string;
  policies: number;
  rendersNowhere: number;
}): string {
  const lines = [
    `Proposed from the heliopause console by \`${input.who}\`.`,
    "",
    `- site: \`${input.site}\``,
    `- policies: ${input.policies}${input.rendersNowhere ? ` — **${input.rendersNowhere} render nowhere**` : ""}`,
  ];
  if (input.planHash) {
    lines.push(`- plan: \`${input.planHash}\``);
    lines.push("");
    lines.push(
      "Merging adopts the source. It does **not** publish — the fleet moves when this plan is " +
        "approved and published in the console, which is where the two-person approval on the " +
        "rendered bundle, the staged rollout and the rollback on silence live.",
    );
  } else {
    lines.push("");
    lines.push("No plan was rendered for this branch, so nothing has been proposed to the fleet yet.");
  }
  return lines.join("\n");
}
