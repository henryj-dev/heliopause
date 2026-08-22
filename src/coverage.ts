// Coverage verification — the only reading in this system that does not come from an agent.
//
// ## Why this exists separately from everything else
//
// Every other screen is built from what the fleet reported about itself. If an agent is compromised
// it can report whatever it likes, and the drift table, the audit table and the apply history all
// go along with it. This one probes from outside and believes nothing the fleet says. That is why
// the design puts it first in the compromise summary rather than last.
//
// ## The observation point is part of the design, not an implementation detail
//
// Two obvious places to run this from are both wrong here:
//
//   the operator's workstation   leaves over Cloudflare WARP, so a public-path result means nothing
//   a Vultr instance            outbound 25 is blocked, so mail-port checks come back "blocked"
//
// Both produce green cells that were never measured. `observedFrom` is recorded on every probe and
// rendered, so a result can be disbelieved by where it came from.
//
// ## Two distinctions this file exists to keep
//
// **IPv4 and IPv6 are separate cells, always.** Folding them into one is how an unverified v6 hides
// behind a passing v4, which is this environment's default failure. A check that does not apply to
// a family renders `n/a` — a different thing from `unknown`.
//
// **`refused` is not `blocked`.** A silent drop times out; a RST means the packet reached something
// that answered. For a rule that is supposed to drop traffic, an RST is a failure with a specific
// cause, and collapsing both into "could not connect" turns a hole into a green cell.

import { portsOverlap } from "./nft.ts";

export type Family = "v4" | "v6";

/** What the rule is supposed to do. */
export type Expect = "reach" | "blocked";

export interface CoverageTarget {
  /** Label for the row. Not resolved — see `addr4`/`addr6`. */
  host: string;
  /** Literal addresses. Absent means this family is not applicable to this target. */
  addr4?: string;
  addr6?: string;
  port: number;
  proto: "tcp" | "udp";
}

export interface CoverageCheck {
  /** `A1`, `B3` — the ids the design document uses. */
  id: string;
  title: string;
  expect: Expect;
  targets: CoverageTarget[];
  notes?: string;
  /**
   * A third-party address that **must** be reachable for this check's result to mean anything.
   *
   * This is how the Vultr lesson becomes code rather than a note. Outbound 25 is blocked on Vultr,
   * on Azure, and therefore on GitHub Actions runners — so a mail-port check run there comes back
   * "blocked" having measured the runner's own egress and nothing else. With a control target, the
   * prober checks it first: if the control cannot be reached, every probe for this check is an
   * `error` and the screen says "not measured" instead of showing a green cell.
   *
   * Point it at something outside this deployment. A control inside the site would fail for the
   * same reasons the targets do and would confirm nothing.
   */
  control?: { addr4?: string; addr6?: string; port: number };
  /**
   * Vantage labels whose answer to this check would not be about the internet.
   *
   * Matched as a substring against `observedFrom`. A probe from a matching vantage is recorded as
   * `error`, so the cell reads "not measured" rather than carrying a result that policy arranged.
   *
   * The case this exists for: ports opened to Cloudflare origin ranges. Measuring one of those from
   * a runner behind Cloudflare WARP asks "can Cloudflare reach it", which policy already answers
   * yes to — and the cell would go green or red for a reason that has nothing to do with the rule
   * being verified. The current checks avoid those ports, but the next one added might not, and a
   * vantage point that quietly stops meaning anything is the failure this whole screen exists to
   * avoid making elsewhere.
   */
  meaninglessFrom?: string[];
}

/** What a single connection attempt did. Raw, before any judgement. */
export type Outcome = "connected" | "refused" | "timeout" | "error";

export interface Probe {
  checkId: string;
  family: Family;
  /** The literal address attempted, so a result can be matched to a target later. */
  addr: string;
  port: number;
  outcome: Outcome;
  /** RFC3339. */
  at: string;
  /** Where the probe ran. Rendered — a result is only as good as its vantage point. */
  observedFrom: string;
  ms: number;
  detail?: string;
}

/**
 * The judgement for one cell.
 *
 * `unknown` is not a shade of pass. It means nothing was measured, or the measurement failed, and
 * the screen says so rather than leaving the cell blank — a blank reads as "nothing wrong".
 */
export type Verdict = "pass" | "fail" | "unknown" | "n/a";

/**
 * Turn a raw outcome into a verdict.
 *
 * The `blocked`/`refused` pair is the whole reason this is a function rather than a boolean. A rule
 * that should drop traffic has not done its job if the far end sent back a RST: the packet was not
 * dropped, it was answered. Reporting that as "blocked" because `connect()` failed would hide
 * exactly the case where a firewall rule is missing and only a closed port is standing in for it.
 */
export function verdictFor(expect: Expect, outcome: Outcome | undefined): Verdict {
  if (outcome === undefined) return "unknown";
  if (outcome === "error") return "unknown";
  if (expect === "reach") return outcome === "connected" ? "pass" : "fail";
  // expect === "blocked"
  return outcome === "timeout" ? "pass" : "fail";
}

/**
 * Why a cell reads the way it does, as a message key.
 *
 * A key rather than a sentence because this is rendered in two languages and printed by the CLI.
 * Returning prose here would mean the screen and the command could drift apart in wording while
 * agreeing on the verdict — and the wording is the part that says *why*, which is the whole reason
 * the column exists.
 */
export function verdictReasonKey(expect: Expect, outcome: Outcome | undefined): string {
  if (outcome === undefined) return "cov.notMeasuredReason";
  switch (outcome) {
    case "error":
      return "cov.errorReason";
    case "connected":
      return expect === "reach" ? "cov.connectedReach" : "cov.connectedBlocked";
    case "refused":
      return expect === "reach" ? "cov.refusedReach" : "cov.refusedBlocked";
    case "timeout":
      return expect === "reach" ? "cov.timeoutReach" : "cov.timeoutBlocked";
  }
}

export interface CoverageCell {
  verdict: Verdict;
  outcome?: Outcome;
  /** Message key — see `verdictReasonKey`. */
  reasonKey: string;
  /** Newest probe instant for this cell, when there was one. */
  at?: string;
  observedFrom?: string;
  /** Seconds since `at`, against the `now` passed to `coverageRows`. */
  ageSec?: number;
  /** `true` when the newest probe is older than the caller's freshness window. */
  stale?: boolean;
}

export interface CoverageRow {
  check: CoverageCheck;
  v4: CoverageCell;
  v6: CoverageCell;
  /** Target labels, for the row's second column. */
  targets: string[];
}

const NA: CoverageCell = { verdict: "n/a", reasonKey: "cov.naReason" };

/**
 * Pick the worst cell across a check's targets for one family.
 *
 * Worst rather than newest: a check covering three hosts is only satisfied if all three are, and
 * showing the newest would let a passing probe taken a second ago paper over a failure on another
 * host. `unknown` outranks `pass` for the same reason — an unmeasured target is not a satisfied one.
 */
function worst(cells: CoverageCell[]): CoverageCell {
  if (!cells.length) return NA;
  const rank: Record<Verdict, number> = { fail: 0, unknown: 1, pass: 2, "n/a": 3 };
  return cells.slice().sort((a, b) => rank[a.verdict] - rank[b.verdict])[0]!;
}

export interface RowOptions {
  /** Instant to measure staleness against. Passed in so rendering is deterministic in tests. */
  now: string;
  /** A probe older than this is marked stale. The screen shows the age either way. */
  staleAfterSec?: number;
}

/**
 * Build one row per check, with the two families kept apart.
 *
 * Probes are matched to targets by literal address, not by order — a probe list that arrived
 * partially, or out of order, must not shift results onto the wrong target.
 */
export function coverageRows(
  checks: readonly CoverageCheck[],
  probes: readonly Probe[],
  opts: RowOptions,
): CoverageRow[] {
  const nowMs = Date.parse(opts.now);
  const staleAfter = opts.staleAfterSec ?? 24 * 3600;

  const newest = new Map<string, Probe>();
  for (const p of probes) {
    const key = `${p.checkId}|${p.family}|${p.addr}|${p.port}`;
    const had = newest.get(key);
    if (!had || Date.parse(p.at) > Date.parse(had.at)) newest.set(key, p);
  }

  const cellFor = (check: CoverageCheck, t: CoverageTarget, family: Family): CoverageCell => {
    const addr = family === "v4" ? t.addr4 : t.addr6;
    if (!addr) return NA;
    const p = newest.get(`${check.id}|${family}|${addr}|${t.port}`);
    const verdict = verdictFor(check.expect, p?.outcome);
    const cell: CoverageCell = { verdict, reasonKey: verdictReasonKey(check.expect, p?.outcome) };
    if (!p) return cell;
    cell.outcome = p.outcome;
    cell.at = p.at;
    cell.observedFrom = p.observedFrom;
    const age = Math.max(0, Math.round((nowMs - Date.parse(p.at)) / 1000));
    cell.ageSec = age;
    cell.stale = age > staleAfter;
    return cell;
  };

  return checks.map((check) => ({
    check,
    targets: check.targets.map((t) => `${t.host}:${t.port}/${t.proto}`),
    v4: worst(check.targets.map((t) => cellFor(check, t, "v4"))),
    v6: worst(check.targets.map((t) => cellFor(check, t, "v6"))),
  }));
}

export interface CoverageSummary {
  /** Checks with at least one failing cell. */
  failing: number;
  /** Checks with at least one cell nobody measured. Counted apart from failures on purpose. */
  unknown: number;
  passing: number;
  /** Newest probe across everything, or `undefined` when there are none. */
  lastRun?: string;
  /** Distinct vantage points seen. More than one is worth showing. */
  observedFrom: string[];
}

/**
 * The banner above the table.
 *
 * `unknown` is counted separately from `failing` and neither is folded into a single "problems"
 * number. "Three checks failed" and "three checks never ran" call for different actions, and a
 * combined count is the kind of instrument that conflates two facts in one sentence.
 */
export function coverageSummary(
  rows: readonly CoverageRow[],
  opts: { families?: readonly Family[] } = {},
): CoverageSummary {
  // A run that probed one family sees the other as unmeasured, and counting that would make every
  // single-family run report gaps it never tried to fill — the exit code stops meaning anything and
  // then nobody reads it. Scoping to what was attempted keeps "not measured" for the case that
  // matters: a family this vantage point tried and could not reach.
  const scoped = opts.families;
  let failing = 0;
  let unknown = 0;
  let passing = 0;
  let lastRun: string | undefined;
  const from = new Set<string>();

  for (const r of rows) {
    const cells = [
      ...(!scoped || scoped.includes("v4") ? [r.v4] : []),
      ...(!scoped || scoped.includes("v6") ? [r.v6] : []),
    ];
    if (!cells.length) continue;
    if (cells.some((c) => c.verdict === "fail")) failing += 1;
    else if (cells.some((c) => c.verdict === "unknown")) unknown += 1;
    else if (cells.some((c) => c.verdict === "pass")) passing += 1;
    for (const c of cells) {
      if (c.observedFrom) from.add(c.observedFrom);
      if (c.at && (!lastRun || Date.parse(c.at) > Date.parse(lastRun))) lastRun = c.at;
    }
  }
  return { failing, unknown, passing, lastRun, observedFrom: [...from].sort() };
}

// ── The baseline, and whether anything measures it ───────────────────────────
//
// `nft.ts` states the gap this closes, at `RulesetPlan.assertions`:
//
//   "It is **not** a check on the baseline itself. If the configured baseline is wrong, the rules
//    and the assertions are wrong together and agree. Nothing inside the host can catch that;
//    verifying reachability from outside is a separate job (H29)."
//
// Both host-side checks are derived from the same config as the rules. `mustContain` asks whether
// the rendered rules reached the kernel; `expectAddrs` asks whether they name this machine. Neither
// can ask whether the *baseline* is right, because a wrong baseline produces a wrong rule and a
// matching wrong assertion, and they agree.
//
// The prober in `coverage-probe.ts` is what can ask. What was missing is the connection between the
// two lists: `cfg.baseline` and the site's coverage checks are written by hand, separately, and this
// repository's own finding about two lists is that they drift. Measured on dev when this was
// written — six checks, five `blocked` from the internet and one `reach` for IMAPS, and **not one
// of them on the management path**. The one thing H29 names was unmeasured, and nothing said so.

/** A management path the baseline promises and the coverage checks do not measure. */
export interface CoverageGap {
  /** The baseline entry, by its own description. */
  desc: string;
  proto: string;
  ports: string;
  /**
   * `unmeasured` — nothing probes this port for reachability.
   * `unmeasurable` — this prober cannot speak the protocol, so no check could exist.
   *
   * Kept apart for the same reason `coverage.ts` keeps `n/a` and `unknown` apart: one is work
   * somebody has not done, and the other is a question this tool cannot answer. Reporting the second
   * as a gap would ask for a check that cannot be written.
   */
  kind: "unmeasured" | "unmeasurable";
}

/**
 * Which baseline entries no coverage check verifies as reachable.
 *
 * ## Why only `expect: "reach"` counts
 *
 * A baseline entry is a promise that a management path stays **open**. `B1 internet → 22 blocked`
 * names port 22 and proves the opposite thing from a different vantage point — public SSH being shut
 * says nothing about whether the operator's path works. Counting it would turn the check into one
 * that reports coverage it does not have, which is the failure this whole file is written against.
 *
 * ## What it does not claim
 *
 * That a matching check was run, or run from the right place. `observedFrom` answers that and a
 * person reads it. This answers the earlier question — whether a check for that path exists at all —
 * which is the one nobody could ask before.
 *
 * Port membership is decided by `portsOverlap` from the renderer rather than a second parser here.
 * The baseline's `ports` is the renderer's grammar (`"22"`, `"9000:9100"`, a comma list), and two
 * readers of one grammar is two things to keep in step.
 */
export function baselineCoverageGaps(
  baseline: readonly { desc: string; proto: string; ports: string }[],
  checks: readonly CoverageCheck[],
): CoverageGap[] {
  const reachTargets = checks
    .filter((c) => c.expect === "reach")
    .flatMap((c) => c.targets);
  const out: CoverageGap[] = [];
  for (const entry of baseline) {
    // ICMP and ICMPv6 carry no ports and the prober speaks TCP only — see its header on why a UDP
    // target is reported as unmeasured rather than blocked. The same honesty applies here.
    if (entry.proto !== "tcp") {
      out.push({ desc: entry.desc, proto: entry.proto, ports: entry.ports, kind: "unmeasurable" });
      continue;
    }
    const covered = reachTargets.some(
      (target) => target.proto === "tcp" && portsOverlap(String(target.port), entry.ports),
    );
    if (!covered) out.push({ desc: entry.desc, proto: entry.proto, ports: entry.ports, kind: "unmeasured" });
  }
  return out;
}
