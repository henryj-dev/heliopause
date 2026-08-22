// Screen 12 — what has been published, and what is live.
//
// ## Where the history actually is
//
// Neither the manager nor the relay keeps one, and both say why. `approval.ts` deletes a plan the
// moment it is published, because an approval that outlives its publish is a standing permission.
// `relay.ts` refuses to hold old generations, because holding them would imply it could serve one.
// The manager is also a single pod that restarts on every deploy — it restarted four times on
// 2026-08-07 alone — so an in-memory ledger would mostly say "nothing since I started".
//
// **The history is the policy repository's commit log.** A generation id *is* a commit: that is the
// whole point of `generationId`, and it is why the policy lives in its own repository. So this reads
// `git log` and marks the commits a manager says are live.
//
// ## What this is honest about
//
// A commit is a *candidate* generation, not evidence that it was published. Rendering every commit
// as "applied" would be a much stronger claim than the data supports — most commits never became a
// generation on any VPC. So a row says one of three things and never guesses:
//
//   - **live on dev, prod …** — a manager reported this generation
//   - **superseded** — older than the newest live generation: at least one VPC has moved past it
//   - **not published** — newer than every live generation: no VPC has reached it
//
// The middle one is deliberately weak. Making it stronger needs a record that does not exist, and
// inventing one here would put a claim on screen that nothing checks.
//
// And with no manager at all, every row is **unknown** rather than any of the three. The first
// version of this file called them all `superseded`, which reads as "these shipped and were
// replaced" — a statement about the fleet, made without asking the fleet.

/** One commit from the policy repository. */
export interface Commit {
  /** Short sha — the same string a generation id uses. */
  id: string;
  subject: string;
  author: string;
  /** ISO 8601. */
  at: string;
}

export type HistoryStatus =
  /** A manager reported this generation. */
  | "live"
  /** Older than something live. It was current at some point, or it never shipped. */
  | "superseded"
  /** Newer than everything live, so it has not reached any VPC this manager aggregates. */
  | "not-published"
  /** No manager answered. Nothing here knows what is running, and saying so beats guessing. */
  | "unknown";

export interface HistoryRow {
  commit: Commit;
  status: HistoryStatus;
  /** VPC names reporting this generation. Empty unless `status` is `live`. */
  liveOn: string[];
}

/**
 * Mark commits against the generations a manager reported.
 *
 * `liveIds` maps generation id → the VPCs on it. Without it every row is `not-published`, which is
 * the honest answer to "nobody told us what is running" — not an error, and not silence.
 *
 * Commits are expected newest-first, the order `git log` gives. The order is preserved: a history
 * sorted any other way stops being a history.
 */
export function historyRows(
  commits: readonly Commit[],
  liveIds: ReadonlyMap<string, readonly string[]> = new Map(),
): HistoryRow[] {
  if (liveIds.size === 0) {
    return commits.map((c) => ({ commit: c, status: "unknown" as const, liveOn: [] }));
  }

  // The watermark is the **newest** live generation — the smallest index, since `git log` is
  // newest-first. So `superseded` means precisely "at least one VPC has moved past this", and
  // `not-published` means "no VPC has reached it".
  //
  // The oldest live one does not work as the watermark. Two VPCs on different generations is the
  // normal state mid-rollout — this fleet was in it for two days — and a commit *between* them is
  // neither purely unshipped nor purely replaced. Anchoring on the newest gives each of the two
  // labels a definition that is true of every row it is applied to.
  //
  // Index rather than date: commits can share a second, and `git log` order is what the operator
  // sees everywhere else.
  let newestLive = commits.length;
  commits.forEach((c, i) => {
    if (liveIds.has(c.id) && i < newestLive) newestLive = i;
  });

  return commits.map((c, i) => {
    const on = liveIds.get(c.id);
    if (on) return { commit: c, status: "live" as const, liveOn: [...on] };
    return {
      commit: c,
      status: (i > newestLive ? "superseded" : "not-published") as HistoryStatus,
      liveOn: [],
    };
  });
}

/**
 * Which generations are live, from a manager's site view.
 *
 * Takes the `generations` array the manager already computes rather than re-deriving it from hosts:
 * that array is what the console shows, and two paths answering "what is live" is how they come to
 * disagree.
 */
export function liveGenerations(
  generations: readonly { generation: string | null; vpcs: readonly string[] }[],
): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const g of generations) {
    if (!g.generation) continue;
    // A `-dirty-…` id names a commit that does not describe what was published. It still matches a
    // commit prefix, and marking that commit "live" would say the repository holds those rules when
    // by construction it does not.
    if (g.generation.includes("-dirty")) continue;
    out.set(g.generation, [...g.vpcs]);
  }
  return out;
}
