// GET /api/plans/:hash/changes, as this package is allowed to see it.
//
// 시안 B1/B3: the second person cannot approve what they cannot see. An empty
// box is the wrong answer — it reads as "nothing changed". `unavailable` is a
// reason, not a zero.

export interface DiffCommit {
  sha: string;
  message: string;
  author: string;
}

export interface DiffFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  patch: string | null;
}

export type PlanDiff =
  | { kind: "same"; base: string; head: string }
  | { kind: "changed"; base: string; head: string; commits: DiffCommit[]; files: DiffFile[]; generated: DiffFile[] }
  | { kind: "unavailable"; reason: string }
  | { kind: "error"; reason: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function readCommit(value: unknown): DiffCommit | null {
  if (!isRecord(value) || typeof value.sha !== "string") return null;
  return {
    sha: value.sha,
    message: typeof value.message === "string" ? value.message : "",
    author: typeof value.author === "string" ? value.author : "",
  };
}

function readFile(value: unknown): DiffFile | null {
  if (!isRecord(value) || typeof value.filename !== "string") return null;
  return {
    filename: value.filename,
    status: typeof value.status === "string" ? value.status : "",
    additions: typeof value.additions === "number" ? value.additions : 0,
    deletions: typeof value.deletions === "number" ? value.deletions : 0,
    patch: typeof value.patch === "string" ? value.patch : null,
  };
}

function readFiles(value: unknown): DiffFile[] | null {
  if (!Array.isArray(value)) return null;
  const out: DiffFile[] = [];
  for (const row of value) {
    const file = readFile(row);
    if (!file) return null;
    out.push(file);
  }
  return out;
}

export function readPlanDiff(data: unknown, status: number): PlanDiff {
  if (status === 401) return { kind: "error", reason: "unauthorized" };
  if (status === 404) return { kind: "unavailable", reason: "no pending plan with that hash" };
  if (status !== 200) return { kind: "error", reason: `GET /api/plans/*/changes returned ${status}` };
  if (!isRecord(data)) return { kind: "error", reason: "plan diff is not an object" };
  if (typeof data.unavailable === "string" && data.unavailable !== "") {
    return { kind: "unavailable", reason: data.unavailable };
  }
  if (typeof data.base !== "string" || typeof data.head !== "string") {
    return { kind: "error", reason: "plan diff is missing base or head" };
  }
  if (data.same === true) return { kind: "same", base: data.base, head: data.head };
  const commits: DiffCommit[] = [];
  if (!Array.isArray(data.commits)) return { kind: "error", reason: "plan diff is missing commits" };
  for (const row of data.commits) {
    const commit = readCommit(row);
    if (!commit) return { kind: "error", reason: "a commit row is malformed" };
    commits.push(commit);
  }
  const files = readFiles(data.files);
  if (!files) return { kind: "error", reason: "plan diff is missing files" };
  const generated = data.generated === undefined ? [] : readFiles(data.generated);
  if (!generated) return { kind: "error", reason: "generated files are malformed" };
  return { kind: "changed", base: data.base, head: data.head, commits, files, generated };
}

export function changesPath(hash: string): string {
  return `/api/plans/${encodeURIComponent(hash)}/changes`;
}
