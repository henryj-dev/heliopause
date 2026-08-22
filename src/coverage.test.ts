// Coverage verification, and the two collapses that would make it lie.
//
// This screen is the only reading not taken from an agent, so it is the one an attacker most wants
// green. Both ways it goes wrong produce green cells rather than errors: folding IPv6 into IPv4,
// and reading a refused connection as a blocked one.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  coverageRows,
  coverageSummary,
  verdictFor,
  verdictReasonKey,
  type CoverageCheck,
  type Probe,
  baselineCoverageGaps,
} from "./coverage.ts";

const NOW = "2026-08-12T12:00:00Z";

const check = (over: Partial<CoverageCheck> = {}): CoverageCheck => ({
  id: "B1",
  title: "internet → 22",
  expect: "blocked",
  targets: [{ host: "gw", addr4: "192.0.2.1", addr6: "2001:db8::1", port: 22, proto: "tcp" }],
  ...over,
});

const probe = (over: Partial<Probe> = {}): Probe => ({
  checkId: "B1",
  family: "v4",
  addr: "192.0.2.1",
  port: 22,
  outcome: "timeout",
  at: "2026-08-12T11:59:00Z",
  observedFrom: "github-actions",
  ms: 3000,
  ...over,
});

describe("verdictFor", () => {
  it("passes a reach check only when it connected", () => {
    assert.equal(verdictFor("reach", "connected"), "pass");
    assert.equal(verdictFor("reach", "timeout"), "fail");
    assert.equal(verdictFor("reach", "refused"), "fail");
  });

  it("passes a blocked check only on a silent drop", () => {
    assert.equal(verdictFor("blocked", "timeout"), "pass");
    assert.equal(verdictFor("blocked", "connected"), "fail");
  });

  // The collapse this function exists to prevent. `connect()` failed either way, so code that
  // asked "did it fail?" would call this blocked — and a missing firewall rule standing behind a
  // closed port would render green until the day something starts listening.
  it("fails a blocked check on refused — the packet reached the host", () => {
    assert.equal(verdictFor("blocked", "refused"), "fail");
    assert.equal(verdictReasonKey("blocked", "refused"), "cov.refusedBlocked");
  });

  it("reports a probe error as unknown, never as a pass", () => {
    assert.equal(verdictFor("blocked", "error"), "unknown");
    assert.equal(verdictFor("reach", "error"), "unknown");
  });

  it("reports an absent measurement as unknown", () => {
    assert.equal(verdictFor("blocked", undefined), "unknown");
    assert.equal(verdictReasonKey("blocked", undefined), "cov.notMeasuredReason");
  });
});

describe("coverageRows", () => {
  it("keeps the families in separate cells", () => {
    const rows = coverageRows([check()], [probe({ family: "v4" })], { now: NOW });
    assert.equal(rows[0]!.v4.verdict, "pass");
    // Nothing measured v6. It must not inherit v4's pass.
    assert.equal(rows[0]!.v6.verdict, "unknown");
  });

  // The environment's default failure, stated as a test.
  it("does not let a passing v4 hide an unmeasured v6", () => {
    const rows = coverageRows([check()], [probe({ family: "v4", outcome: "timeout" })], { now: NOW });
    const s = coverageSummary(rows);
    assert.equal(s.unknown, 1, "the check counts as unknown, not as passing");
    assert.equal(s.passing, 0);
  });

  it("marks a family the target has no address for as n/a, not unknown", () => {
    const c = check({ targets: [{ host: "gw", addr4: "192.0.2.1", port: 22, proto: "tcp" }] });
    const rows = coverageRows([c], [probe()], { now: NOW });
    assert.equal(rows[0]!.v6.verdict, "n/a");
    // n/a is not a gap in coverage, so it must not inflate the unknown count.
    assert.equal(coverageSummary(rows).unknown, 0);
  });

  it("matches probes to targets by address, not by order", () => {
    const c = check({
      targets: [
        { host: "a", addr4: "192.0.2.1", port: 22, proto: "tcp" },
        { host: "b", addr4: "192.0.2.2", port: 22, proto: "tcp" },
      ],
    });
    const rows = coverageRows(
      [c],
      [probe({ addr: "192.0.2.2", outcome: "connected" }), probe({ addr: "192.0.2.1", outcome: "timeout" })],
      { now: NOW },
    );
    // b connected, which for a blocked check is a failure. Order must not move it onto a.
    assert.equal(rows[0]!.v4.verdict, "fail");
  });

  // A check covering three hosts is satisfied only if all three are.
  it("takes the worst target, not the newest", () => {
    const c = check({
      targets: [
        { host: "a", addr4: "192.0.2.1", port: 22, proto: "tcp" },
        { host: "b", addr4: "192.0.2.2", port: 22, proto: "tcp" },
      ],
    });
    const rows = coverageRows(
      [c],
      [
        probe({ addr: "192.0.2.1", outcome: "connected", at: "2026-08-12T10:00:00Z" }),
        probe({ addr: "192.0.2.2", outcome: "timeout", at: "2026-08-12T11:59:00Z" }),
      ],
      { now: NOW },
    );
    assert.equal(rows[0]!.v4.verdict, "fail");
  });

  it("ranks an unmeasured target below a passing one", () => {
    const c = check({
      targets: [
        { host: "a", addr4: "192.0.2.1", port: 22, proto: "tcp" },
        { host: "b", addr4: "192.0.2.2", port: 22, proto: "tcp" },
      ],
    });
    const rows = coverageRows([c], [probe({ addr: "192.0.2.1" })], { now: NOW });
    assert.equal(rows[0]!.v4.verdict, "unknown");
  });

  it("keeps the newest probe for a given target", () => {
    const rows = coverageRows(
      [check()],
      [
        probe({ outcome: "connected", at: "2026-08-12T09:00:00Z" }),
        probe({ outcome: "timeout", at: "2026-08-12T11:59:00Z" }),
      ],
      { now: NOW },
    );
    assert.equal(rows[0]!.v4.verdict, "pass");
  });

  it("reports the age of the newest probe", () => {
    const rows = coverageRows([check()], [probe()], { now: NOW });
    assert.equal(rows[0]!.v4.ageSec, 60);
    assert.equal(rows[0]!.v4.stale, false);
  });

  // A value that was right when it was taken is the failure mode this column exists for.
  it("marks a probe older than the window as stale", () => {
    const rows = coverageRows([check()], [probe({ at: "2026-07-29T14:10:00Z" })], {
      now: NOW,
      staleAfterSec: 3600,
    });
    assert.equal(rows[0]!.v4.stale, true);
    // Still a pass — stale says how old, not whether it was right.
    assert.equal(rows[0]!.v4.verdict, "pass");
  });

  it("carries the vantage point onto the cell", () => {
    const rows = coverageRows([check()], [probe({ observedFrom: "github-actions" })], { now: NOW });
    assert.equal(rows[0]!.v4.observedFrom, "github-actions");
  });
});

describe("coverageSummary", () => {
  it("counts failures and gaps apart", () => {
    const rows = coverageRows(
      [
        check({ id: "B1", targets: [{ host: "a", addr4: "192.0.2.1", port: 22, proto: "tcp" }] }),
        check({ id: "B3", targets: [{ host: "b", addr4: "192.0.2.2", port: 5432, proto: "tcp" }] }),
      ],
      [
        probe({ checkId: "B1", addr: "192.0.2.1", outcome: "connected" }),
        // B3 never ran.
      ],
      { now: NOW },
    );
    const s = coverageSummary(rows);
    assert.equal(s.failing, 1);
    assert.equal(s.unknown, 1);
    assert.equal(s.passing, 0);
  });

  it("reports the newest probe instant across everything", () => {
    const rows = coverageRows(
      [check()],
      [probe({ at: "2026-08-12T09:00:00Z" }), probe({ family: "v6", addr: "2001:db8::1", at: "2026-08-12T11:00:00Z" })],
      { now: NOW },
    );
    assert.equal(coverageSummary(rows).lastRun, "2026-08-12T11:00:00Z");
  });

  it("lists every vantage point seen", () => {
    const rows = coverageRows(
      [check()],
      [probe({ observedFrom: "github-actions" }), probe({ family: "v6", addr: "2001:db8::1", observedFrom: "laptop" })],
      { now: NOW },
    );
    assert.deepEqual(coverageSummary(rows).observedFrom, ["github-actions", "laptop"]);
  });

  it("says nothing ran when nothing ran", () => {
    const s = coverageSummary(coverageRows([check()], [], { now: NOW }));
    assert.equal(s.lastRun, undefined);
    assert.equal(s.unknown, 1);
    assert.equal(s.passing, 0);
  });
});

describe("coverageSummary scoped to the families a run attempted", () => {
  // A vantage point that can only do one family sees the other as unmeasured. Counting that makes
  // every single-family run report gaps it never tried to fill, and an exit code that is always
  // the same is one nobody reads.
  it("ignores a family this run did not attempt", () => {
    const rows = coverageRows([check()], [probe({ family: "v4" })], { now: NOW });
    assert.equal(coverageSummary(rows).unknown, 1, "unscoped still sees the v6 gap");
    const s = coverageSummary(rows, { families: ["v4"] });
    assert.equal(s.unknown, 0);
    assert.equal(s.passing, 1);
  });

  // The case the scoping must not hide: a family that was attempted and could not be reached.
  it("still counts a family it attempted and could not measure", () => {
    const rows = coverageRows(
      [check()],
      [probe({ family: "v4" }), probe({ family: "v6", addr: "2001:db8::1", outcome: "error" })],
      { now: NOW },
    );
    const s = coverageSummary(rows, { families: ["v4", "v6"] });
    assert.equal(s.unknown, 1);
    assert.equal(s.passing, 0);
  });

  it("counts a failure in an attempted family", () => {
    const rows = coverageRows([check()], [probe({ family: "v4", outcome: "connected" })], { now: NOW });
    assert.equal(coverageSummary(rows, { families: ["v4"] }).failing, 1);
  });
});

// ── Does anything measure the baseline? ──────────────────────────────────────
//
// `nft.ts` states the gap: the host's own checks are derived from the same config as its rules, so a
// wrong baseline produces a wrong rule and a matching wrong assertion, and they agree. Only a probe
// from outside can ask — and only for paths somebody wrote a check for. `cfg.baseline` and
// `site.coverage` are two hand-written lists, and two lists drift.

describe("baseline paths nothing measures", () => {
  const reach = (port: number, proto: "tcp" | "udp" = "tcp"): CoverageCheck => ({
    id: "R", title: "reach", expect: "reach",
    targets: [{ host: "h", addr4: "10.0.0.1", port, proto }],
  });
  const blocked = (port: number): CoverageCheck => ({
    id: "B", title: "blocked", expect: "blocked",
    targets: [{ host: "h", addr4: "203.0.113.1", port, proto: "tcp" }],
  });
  const ssh = { desc: "management SSH", proto: "tcp", ports: "22" };

  // The known positive. Without it every gap below would also be reported by a function that
  // reports everything, which is what "the check is broken" looks like from the outside.
  it("says nothing when a reach check covers the port", () => {
    assert.deepEqual(baselineCoverageGaps([ssh], [reach(22)]), []);
  });

  it("names a baseline path with no reach check at all", () => {
    const gaps = baselineCoverageGaps([ssh], []);
    assert.equal(gaps.length, 1);
    assert.equal(gaps[0]!.kind, "unmeasured");
    assert.equal(gaps[0]!.desc, "management SSH");
  });

  // The distinction the whole function exists for. `B1 internet → 22 blocked` names port 22 and
  // proves the opposite thing from a different vantage point: public SSH being shut says nothing
  // about whether the operator's path works. Counting it would report coverage that is not there.
  it("does not count a blocked check on the same port as coverage", () => {
    const gaps = baselineCoverageGaps([ssh], [blocked(22)]);
    assert.equal(gaps.length, 1, "a blocked-from-the-internet check is not a reachability check");
    assert.equal(gaps[0]!.kind, "unmeasured");
  });

  it("counts a reach check whose port falls inside a range", () => {
    // The baseline grammar allows `9000:9100`, and membership is decided by the renderer's own
    // `portsOverlap` rather than a second parser here.
    assert.deepEqual(baselineCoverageGaps([{ desc: "app", proto: "tcp", ports: "9000:9100" }], [reach(9050)]), []);
    assert.equal(baselineCoverageGaps([{ desc: "app", proto: "tcp", ports: "9000:9100" }], [reach(8999)]).length, 1);
  });

  it("counts a reach check naming one port of a comma list", () => {
    assert.deepEqual(baselineCoverageGaps([{ desc: "web", proto: "tcp", ports: "80,443" }], [reach(443)]), []);
  });

  // Separate from a gap, and that separation is the point. A UDP or ICMP path cannot be probed by a
  // TCP prober, so reporting it as unmeasured would ask somebody to write a check that cannot exist
  // — the same reason `coverage.ts` keeps `n/a` and `unknown` apart.
  it("marks a path this prober cannot speak as unmeasurable rather than as a gap", () => {
    const gaps = baselineCoverageGaps(
      [{ desc: "ICMPv6 (NDP)", proto: "icmpv6", ports: "" }, { desc: "DHCP", proto: "udp", ports: "67" }],
      [],
    );
    assert.deepEqual(gaps.map((g) => g.kind), ["unmeasurable", "unmeasurable"]);
  });

  it("does not let a UDP reach check cover a TCP baseline path", () => {
    assert.equal(baselineCoverageGaps([ssh], [reach(22, "udp")]).length, 1);
  });
});
