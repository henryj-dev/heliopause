// Headers and bodies for POST /api/policy/edit and /api/policy/propose.
//
// Duplicated rather than imported from changes: that package's proposeBody
// names a fleet plan target, and this one names a git branch. Sharing the
// name would make a caller send the wrong JSON.

export const CSRF_HEADER = "x-heliopause-csrf";

export function writeHeaders(csrf: string | null): Record<string, string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (csrf) headers[CSRF_HEADER] = csrf;
  return headers;
}

export function editBody(path: string, content: string, branch: string): string {
  const body: { path: string; content: string; branch?: string } = { path, content };
  if (branch) body.branch = branch;
  return JSON.stringify(body);
}

export function proposePolicyBody(branch: string, title = ""): string {
  const body: { branch: string; title?: string } = { branch };
  if (title) body.title = title;
  return JSON.stringify(body);
}

export type WriteOk<T> = { ok: true } & T;
export type WriteReplyKey =
  | "write.noCommit"
  | "write.noBranch"
  | "write.noCommitId"
  | "write.noPr"
  | "write.noPrNumber"
  | "write.noPrUrl"
  | "write.noPrStatus"
  | "write.noMerge";
export type WriteFail = { ok: false; reason: string } | { ok: false; key: WriteReplyKey };

export function writeFailMessage(fail: WriteFail, speak: (key: WriteReplyKey) => string): string {
  return "key" in fail ? speak(fail.key) : fail.reason;
}

export function readEditReply(data: unknown): WriteOk<{ branch: string; commit: string }> | WriteFail {
  if (typeof data !== "object" || data === null) return { ok: false, key: "write.noCommit" };
  const rec = data as { error?: unknown; branch?: unknown; commit?: unknown };
  if (typeof rec.error === "string") return { ok: false, reason: rec.error };
  if (typeof rec.branch !== "string" || rec.branch === "") return { ok: false, key: "write.noBranch" };
  if (typeof rec.commit !== "string" || rec.commit === "") return { ok: false, key: "write.noCommitId" };
  return { ok: true, branch: rec.branch, commit: rec.commit };
}

export function readProposeReply(data: unknown): WriteOk<{ number: number; url: string }> | WriteFail {
  if (typeof data !== "object" || data === null) return { ok: false, key: "write.noPr" };
  const rec = data as { error?: unknown; number?: unknown; url?: unknown };
  if (typeof rec.error === "string") return { ok: false, reason: rec.error };
  if (typeof rec.number !== "number") return { ok: false, key: "write.noPrNumber" };
  if (typeof rec.url !== "string" || rec.url === "") return { ok: false, key: "write.noPrUrl" };
  return { ok: true, number: rec.number, url: rec.url };
}

export type ProposeBlock =
  | { ok: true }
  | { ok: false; kind: "need-branch" }
  | { ok: false; kind: "dirty"; paths: readonly string[] };

/** The same three refusals the classic editor speaks before it POSTs. */
export function proposeBlock(branch: string, dirtyPaths: readonly string[]): ProposeBlock {
  if (!branch) return { ok: false, kind: "need-branch" };
  if (dirtyPaths.length === 0) return { ok: true };
  return { ok: false, kind: "dirty", paths: dirtyPaths };
}

export function proposeRefusal(
  block: Exclude<ProposeBlock, { ok: true }>,
): { key: "rule.saveFirst" | "rule.saveBeforePropose" | "rule.saveBeforeProposeIn"; paths?: string } {
  if (block.kind === "need-branch") return { key: "rule.saveFirst" };
  if (block.paths.length === 1) return { key: "rule.saveBeforePropose" };
  return { key: "rule.saveBeforeProposeIn", paths: block.paths.join(", ") };
}

/** `POST /api/policy/merge` — the number and nothing else; the gate is the manager's. */
export function mergeBody(number: number): string {
  return JSON.stringify({ number });
}

export interface PrCheck {
  name: string;
  state: "success" | "pending" | "failure";
  detail: string;
}

export interface PrStatus {
  number: number;
  url: string;
  state: string;
  merged: boolean;
  headSha: string;
  proposedBy: string | null;
  checks: PrCheck[];
  mayMerge: boolean;
  /** The manager's sentence for why not. Absent exactly when `mayMerge` is true. */
  why: string;
}

/**
 * Read the pull request's state.
 *
 * `mayMerge` is taken from the manager rather than recomputed here, and that is the point: the
 * button and the route must not be able to disagree. A browser that decided for itself would be a
 * second copy of a rule that lives in `mergeRefusal`, and the copy would be the one that goes stale.
 */
export function readPrReply(data: unknown): WriteOk<{ status: PrStatus }> | WriteFail {
  if (typeof data !== "object" || data === null) return { ok: false, key: "write.noPrStatus" };
  const rec = data as Record<string, unknown>;
  if (typeof rec.error === "string") return { ok: false, reason: rec.error };
  if (typeof rec.number !== "number") return { ok: false, key: "write.noPrNumber" };
  if (typeof rec.mayMerge !== "boolean") return { ok: false, key: "write.noPrStatus" };
  const checks = Array.isArray(rec.checks) ? rec.checks : [];
  return {
    ok: true,
    status: {
      number: rec.number,
      url: typeof rec.url === "string" ? rec.url : "",
      state: typeof rec.state === "string" ? rec.state : "",
      merged: rec.merged === true,
      headSha: typeof rec.headSha === "string" ? rec.headSha : "",
      proposedBy: typeof rec.proposedBy === "string" ? rec.proposedBy : null,
      checks: checks
        .map((raw) => (raw ?? {}) as Record<string, unknown>)
        .filter((c) => typeof c.name === "string")
        .map((c) => ({
          name: c.name as string,
          // Anything that is not one of the three known words is shown as pending rather than as a
          // pass. A state this browser does not recognise is not a state it may treat as green.
          state: c.state === "success" || c.state === "failure" ? c.state : "pending",
          detail: typeof c.detail === "string" ? c.detail : "",
        })),
      mayMerge: rec.mayMerge,
      why: typeof rec.why === "string" ? rec.why : "",
    },
  };
}

export function readMergeReply(data: unknown): WriteOk<{ number: number; sha: string }> | WriteFail {
  if (typeof data !== "object" || data === null) return { ok: false, key: "write.noMerge" };
  const rec = data as { error?: unknown; number?: unknown; sha?: unknown };
  if (typeof rec.error === "string") return { ok: false, reason: rec.error };
  if (typeof rec.number !== "number") return { ok: false, key: "write.noPrNumber" };
  if (typeof rec.sha !== "string" || rec.sha === "") return { ok: false, key: "write.noMerge" };
  return { ok: true, number: rec.number, sha: rec.sha };
}
