// The prober, and the one mapping that would turn an unmeasured family green.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { outcomeForError, probeAll, probeOne } from "./coverage-probe.ts";
import { coverageRows, coverageSummary, type CoverageCheck, type Family } from "./coverage.ts";

const opts = { observedFrom: "test", timeoutMs: 1500, now: () => "2026-08-12T12:00:00Z" };

const check = (over: Partial<CoverageCheck> = {}): CoverageCheck => ({
  id: "B1",
  title: "internet → 22",
  expect: "blocked",
  targets: [{ host: "gw", addr4: "192.0.2.1", addr6: "2001:db8::1", port: 22, proto: "tcp" }],
  ...over,
});

describe("probeOne", () => {
  it("reports a live listener as connected", async () => {
    const srv = createServer();
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as { port: number }).port;
    try {
      const r = await probeOne("127.0.0.1", port, "v4", opts);
      assert.equal(r.outcome, "connected");
    } finally {
      srv.close();
    }
  });

  it("reports a closed port as refused, not as timeout", async () => {
    const srv = createServer();
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as { port: number }).port;
    await new Promise<void>((r) => srv.close(() => r()));
    const r = await probeOne("127.0.0.1", port, "v4", opts);
    assert.equal(r.outcome, "refused");
    assert.match(r.detail ?? "", /RST/);
  });

  // The mapping the whole file exists for. A machine with no route to a family answers instantly,
  // and calling that a timeout would credit a firewall that never saw the packet.
  it("reports a local-stack error as error, never as timeout", async () => {
    // 240.0.0.0/4 is reserved and unroutable, so the local stack refuses to send.
    const r = await probeOne("240.0.0.1", 22, "v4", { ...opts, timeoutMs: 1200 });
    assert.notEqual(r.outcome, "refused");
    if (r.outcome === "error") {
      assert.match(r.detail ?? "", /nothing was measured|E[A-Z]+/);
    } else {
      // Some stacks do let this out and it simply never answers. That is a real timeout.
      assert.equal(r.outcome, "timeout");
    }
  });
});

describe("probeAll", () => {
  const usableAll = async () => ({ usable: true, reason: "control answered connected" });

  it("records the vantage point on every probe", async () => {
    const ps = await probeAll([check()], {
      ...opts,
      usable: usableAll,
      probe: async () => ({ outcome: "timeout" as const, ms: 1 }),
    });
    assert.equal(ps.length, 2);
    assert.ok(ps.every((p) => p.observedFrom === "test"));
  });

  // Without this, a runner with no IPv6 renders every v6 "must be blocked" cell green.
  it("emits error probes for a family this machine cannot route", async () => {
    const ps = await probeAll([check()], {
      ...opts,
      probe: async () => ({ outcome: "timeout" as const, ms: 1 }),
      usable: async (f: Family) => ({ usable: f === "v4", reason: f === "v4" ? "connected" : "ENETUNREACH — network is unreachable" }),
    });
    const v6 = ps.find((p) => p.family === "v6")!;
    assert.equal(v6.outcome, "error");
    assert.match(v6.detail ?? "", /no usable v6 path/);

    // And the screen must show that as a gap, not as a pass.
    const rows = coverageRows([check()], ps, { now: "2026-08-12T12:00:00Z" });
    assert.equal(rows[0]!.v6.verdict, "unknown");
    assert.equal(coverageSummary(rows).unknown, 1);
    assert.equal(coverageSummary(rows).passing, 0);
  });

  it("does not attempt a family it declared unusable", async () => {
    const tried: Family[] = [];
    await probeAll([check()], {
      ...opts,
      usable: async (f: Family) => ({ usable: f === "v4", reason: f === "v4" ? "connected" : "ENETUNREACH — network is unreachable" }),
      probe: async (_a, _p, f) => {
        tried.push(f);
        return { outcome: "timeout" as const, ms: 1 };
      },
    });
    assert.deepEqual(tried, ["v4"]);
  });

  it("reports a udp target as unmeasured rather than blocked", async () => {
    const c = check({ targets: [{ host: "gw", addr4: "192.0.2.1", port: 67, proto: "udp" }] });
    const ps = await probeAll([c], { ...opts, usable: usableAll, probe: async () => ({ outcome: "timeout" as const, ms: 1 }) });
    assert.equal(ps[0]!.outcome, "error");
    assert.match(ps[0]!.detail ?? "", /not probed/);
    assert.equal(coverageRows([c], ps, { now: "2026-08-12T12:00:00Z" })[0]!.v4.verdict, "unknown");
  });

  it("skips a family the target has no address for", async () => {
    const c = check({ targets: [{ host: "gw", addr4: "192.0.2.1", port: 22, proto: "tcp" }] });
    const ps = await probeAll([c], { ...opts, usable: usableAll, probe: async () => ({ outcome: "timeout" as const, ms: 1 }) });
    assert.equal(ps.length, 1);
    assert.equal(ps[0]!.family, "v4");
  });

  it("carries a probe's own detail through", async () => {
    const ps = await probeAll([check()], {
      ...opts,
      usable: usableAll,
      probe: async () => ({ outcome: "refused" as const, ms: 2, detail: "RST — the host answered" }),
    });
    assert.match(ps[0]!.detail ?? "", /RST/);
  });
});

describe("control target", () => {
  const c = (): CoverageCheck => ({
    id: "B8",
    title: "internet → mailer 995",
    expect: "blocked",
    targets: [{ host: "mailer", addr4: "192.0.2.9", port: 25, proto: "tcp" }],
    control: { addr4: "198.51.100.9", port: 25 },
  });

  // The Vultr lesson as code. Outbound 25 is blocked on Vultr, on Azure and therefore on GitHub
  // Actions runners — so the target times out, "blocked" renders green, and what was measured was
  // the runner's own egress.
  it("reports unmeasured when the control target cannot be reached", async () => {
    const ps = await probeAll([c()], {
      ...opts,
      usable: async () => ({ usable: true, reason: "control answered connected" }),
      probe: async (addr) => (addr === "198.51.100.9"
        ? { outcome: "timeout" as const, ms: 1 }
        : { outcome: "timeout" as const, ms: 1 }),
    });
    assert.equal(ps[0]!.outcome, "error");
    assert.match(ps[0]!.detail ?? "", /control target for B8/);
    const rows = coverageRows([c()], ps, { now: "2026-08-12T12:00:00Z" });
    assert.equal(rows[0]!.v4.verdict, "unknown", "a blocked check must not pass on a blind vantage point");
  });

  it("probes normally when the control target answers", async () => {
    const ps = await probeAll([c()], {
      ...opts,
      usable: async () => ({ usable: true, reason: "control answered connected" }),
      probe: async (addr) => (addr === "198.51.100.9"
        ? { outcome: "connected" as const, ms: 1 }
        : { outcome: "timeout" as const, ms: 1 }),
    });
    assert.equal(ps[0]!.outcome, "timeout");
    assert.equal(coverageRows([c()], ps, { now: "2026-08-12T12:00:00Z" })[0]!.v4.verdict, "pass");
  });

  it("treats a control with no address in this family as unmeasurable", async () => {
    const ck = { ...c(), control: { addr4: "198.51.100.9", port: 25 } };
    ck.targets = [{ host: "mailer", addr6: "2001:db8::9", port: 25, proto: "tcp" }];
    const ps = await probeAll([ck], {
      ...opts,
      usable: async () => ({ usable: true, reason: "control answered connected" }),
      probe: async () => ({ outcome: "connected" as const, ms: 1 }),
    });
    assert.equal(ps[0]!.outcome, "error");
  });
});

describe("outcomeForError", () => {
  // This mapping is the difference between "the firewall dropped it" and "this machine never sent
  // it". A runner without IPv6 answers ENETUNREACH instantly for every v6 target.
  it("maps a local-stack errno to error, never to timeout", () => {
    for (const code of ["ENETUNREACH", "EAFNOSUPPORT", "EHOSTUNREACH", "EADDRNOTAVAIL"]) {
      const r = outcomeForError(code);
      assert.equal(r.outcome, "error", `${code} must not be read as a drop`);
      assert.match(r.detail ?? "", /nothing was measured/);
    }
  });

  it("maps ECONNREFUSED to refused", () => {
    assert.equal(outcomeForError("ECONNREFUSED").outcome, "refused");
  });

  // Only a real timeout is a drop.
  it("maps ETIMEDOUT to timeout", () => {
    assert.equal(outcomeForError("ETIMEDOUT").outcome, "timeout");
  });

  it("maps anything unrecognised to error", () => {
    assert.equal(outcomeForError("EWEIRD").outcome, "error");
    assert.equal(outcomeForError("", "socket exploded").detail, "socket exploded");
  });
});

describe("why a family was unusable", () => {
  // The first real run recorded "no usable v6 path" on every IPv6 cell and nothing else, which left
  // "this runner has no IPv6" and "our prober is broken" looking identical in the stored results.
  it("carries the reachability probe's answer into the probe detail", async () => {
    const ps = await probeAll([check()], {
      ...opts,
      probe: async () => ({ outcome: "timeout" as const, ms: 1 }),
      usable: async (f: Family) => ({
        usable: f === "v4",
        reason: f === "v4" ? "connected" : "ENETUNREACH — this machine cannot reach that family",
      }),
    });
    const v6 = ps.find((p) => p.family === "v6")!;
    assert.match(v6.detail ?? "", /ENETUNREACH/);
    assert.match(v6.detail ?? "", /reachability probe:/);
  });
});

describe("a vantage point policy treats specially", () => {
  const c = (): CoverageCheck => ({
    id: "B-NODEPORT",
    title: "internet → 30444",
    expect: "blocked",
    targets: [{ host: "k3s", addr4: "192.0.2.30", port: 30444, proto: "tcp" }],
    meaninglessFrom: ["warp"],
  });

  // Policy opens this port to Cloudflare origin ranges. Asked from behind WARP the question becomes
  // "can Cloudflare reach it", which policy already answers yes to — a green or red cell either way
  // would be about the rule that grants Cloudflare access, not the rule being verified.
  it("records unmeasured rather than a result policy arranged", async () => {
    const ps = await probeAll([c()], {
      ...opts,
      observedFrom: "github-actions/warp/991",
      usable: async () => ({ usable: true, reason: "connected" }),
      probe: async () => ({ outcome: "connected" as const, ms: 1 }),
    });
    assert.equal(ps[0]!.outcome, "error");
    assert.match(ps[0]!.detail ?? "", /would not be about the internet/);
    assert.equal(coverageRows([c()], ps, { now: "2026-08-12T12:00:00Z" })[0]!.v4.verdict, "unknown");
  });

  it("measures normally from a vantage point it does not name", async () => {
    const ps = await probeAll([c()], {
      ...opts,
      observedFrom: "github-actions/991",
      usable: async () => ({ usable: true, reason: "connected" }),
      probe: async () => ({ outcome: "timeout" as const, ms: 1 }),
    });
    assert.equal(ps[0]!.outcome, "timeout");
    assert.equal(coverageRows([c()], ps, { now: "2026-08-12T12:00:00Z" })[0]!.v4.verdict, "pass");
  });

  it("leaves a check that names no vantage alone", async () => {
    const plain = { ...c() };
    delete plain.meaninglessFrom;
    const ps = await probeAll([plain], {
      ...opts,
      observedFrom: "github-actions/warp/991",
      usable: async () => ({ usable: true, reason: "connected" }),
      probe: async () => ({ outcome: "timeout" as const, ms: 1 }),
    });
    assert.equal(ps[0]!.outcome, "timeout");
  });
});

describe("a vantage point that fabricates connections", () => {
  // The site module already records that a row of timeouts proves nothing without a positive taken
  // the same way. The inverse is what this guards: three-for-three connects, including two that
  // must be dropped, is what a tunnel completing local handshakes looks like — and reporting it
  // would page somebody about an SSH hole that is not there.
  it("refuses to report anything from a vantage that connects to an unroutable address", async () => {
    const ps = await probeAll([check()], {
      ...opts,
      usable: async () => ({ usable: true, reason: "reachable" }),
      fabricates: async () => ({ fabricates: true, reason: "2001:db8::1:443 answered connected" }),
      probe: async () => ({ outcome: "connected" as const, ms: 1 }),
    });
    assert.ok(ps.every((p) => p.outcome === "error"), "every probe must be unmeasured");
    assert.match(ps[0]!.detail ?? "", /fabricates connections/);

    // And the screen must call it a gap, never a failing firewall.
    const rows = coverageRows([check()], ps, { now: "2026-08-12T12:00:00Z" });
    assert.equal(rows[0]!.v4.verdict, "unknown");
    assert.equal(coverageSummary(rows).failing, 0);
  });

  it("measures normally when the known negative times out", async () => {
    const ps = await probeAll([check()], {
      ...opts,
      usable: async () => ({ usable: true, reason: "reachable" }),
      fabricates: async () => ({ fabricates: false, reason: "192.0.2.1:443 answered timeout" }),
      probe: async () => ({ outcome: "timeout" as const, ms: 1 }),
    });
    assert.ok(ps.every((p) => p.outcome === "timeout"));
  });

  it("does not run the known negative for a family that is unusable anyway", async () => {
    let asked = 0;
    await probeAll([check()], {
      ...opts,
      usable: async () => ({ usable: false, reason: "ENETUNREACH" }),
      fabricates: async () => {
        asked += 1;
        return { fabricates: false, reason: "" };
      },
      probe: async () => ({ outcome: "timeout" as const, ms: 1 }),
    });
    assert.equal(asked, 0);
  });
});
