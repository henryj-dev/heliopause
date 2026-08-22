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

/** Minimal fetch shape, so tests do not reach the network. */
export type Fetcher = (url: string, init?: {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>;

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
  const text = await res.text();
  if (!res.ok) {
    // The body carries GitHub's reason — "Reference already exists", "No commits between …". Losing
    // it leaves the operator with a status code and no idea which of their inputs was wrong.
    throw new ProposalError(`${method} ${path} → ${res.status}: ${text.slice(0, 300)}`, res.status);
  }
  return text ? JSON.parse(text) : {};
}

/** Exchange the App JWT for an installation token. Short-lived by construction — GitHub gives an hour. */
export async function installationToken(
  creds: AppCredentials,
  fetcher: Fetcher,
  nowSec: number,
): Promise<string> {
  const jwt = appJwt(creds, nowSec);
  const out = (await gh(
    fetcher,
    jwt,
    `/app/installations/${encodeURIComponent(creds.installationId)}/access_tokens`,
    "POST",
  )) as { token?: string };
  if (!out.token) throw new ProposalError("the installation did not return a token");
  return out.token;
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
