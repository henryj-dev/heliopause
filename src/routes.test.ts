import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { compareRoutes, managementGuard, originOf, readyToApply, type ObservedRoute, type RouteDecl } from "./routes.ts";

/**
 * The fixture follows a real kernel's route table, read on 2026-08-17, with addresses
 * rewritten to documentation ranges (RFC 5737). The public-history scanner refuses a
 * real via or management source, and the thing being tested is the classification of
 * what kernels report — protocol keys, not addresses. The two `proto static` rows and
 * the four with **no protocol key at all** are the whole point.
 */
const GW: ObservedRoute[] = [
  { dst: "default", via: "192.0.2.1", dev: "enp1s0", proto: "dhcp", table: "main" },
  { dst: "10.16.0.0/16", via: "", dev: "wg0", proto: "", table: "main" },
  { dst: "10.17.0.0/16", via: "", dev: "enp8s0", proto: "kernel", table: "main" },
  { dst: "10.17.128.0/18", via: "10.17.0.10", dev: "enp8s0", proto: "static", table: "main" },
  { dst: "10.17.192.0/18", via: "10.17.0.10", dev: "enp8s0", proto: "static", table: "main" },
  { dst: "10.253.0.0/16", via: "", dev: "wg0", proto: "", table: "main" },
  { dst: "10.254.0.0/16", via: "", dev: "wg0", proto: "", table: "main" },
  { dst: "10.255.0.0/16", via: "", dev: "wg0", proto: "", table: "main" },
];

const decl = (over: Partial<RouteDecl> & Pick<RouteDecl, "dst">): RouteDecl =>
  ({ owner: "operator", note: "n", ...over });

describe("what the kernel says about where a route came from", () => {
  it("separates a missing protocol from a static one", () => {
    // The bug this replaces. The first classifier folded these together and called both hand-added,
    // which made four of gw-01.dev's six flagged routes false positives — they are wg-quick's, from
    // the peer's AllowedIPs, measured to match exactly.
    assert.equal(originOf(""), "unstated");
    assert.equal(originOf("static"), "static");
  });

  it("leaves a route with an owner alone", () => {
    for (const p of ["kernel", "dhcp", "ra", "bird", "bgp", "zebra"]) {
      assert.equal(originOf(p), "automatic", p);
    }
  });

  it("counts boot as a person too", () => {
    // `ip route add` with no protocol given writes `boot`. Same author as `static`, different default.
    assert.equal(originOf("boot"), "static");
  });
});

describe("a host with no route declaration", () => {
  it("says so instead of calling every route undeclared", () => {
    // Three of the seven hosts publish from their own site modules, so the dev model says nothing
    // about them. "We have not described this host" and "this route is not in our description" are
    // different statements, and rendering them alike would invent findings for half the fleet.
    const c = compareRoutes(undefined, GW);
    assert.equal(c.rows, null);
    assert.deepEqual([c.missing, c.undeclared, c.unstated], [0, 0, 0]);
  });

  it("says so when the host could not report either", () => {
    // The other absence. `null` from the agent means the routes could not be read — a missing `ip`, a
    // permission error — and that must not read as "declared and gone".
    assert.equal(compareRoutes([decl({ dst: "10.0.0.0/8" })], null).rows, null);
  });
});

describe("declared against observed", () => {
  const DECLARED: RouteDecl[] = [
    decl({ dst: "10.17.128.0/18", via: "10.17.0.10", dev: "enp8s0", note: "cluster pods" }),
    decl({ dst: "10.17.192.0/18", via: "10.17.0.10", dev: "enp8s0", note: "cluster services" }),
    decl({ dst: "10.16.0.0/16", dev: "wg0", owner: "wireguard", note: "prod, via the mesh" }),
    decl({ dst: "10.253.0.0/16", dev: "wg0", owner: "wireguard", note: "util, via the mesh" }),
    decl({ dst: "10.254.0.0/16", dev: "wg0", owner: "wireguard", note: "operators, via the mesh" }),
    decl({ dst: "10.255.0.0/16", dev: "wg0", owner: "wireguard", note: "mesh transit" }),
  ];

  it("finds nothing wrong with the live table once it is declared", () => {
    // The whole of gw-01.dev, declared. Every remaining row is the kernel's or a DHCP lease's, and the
    // column that used to read "6 by hand" now reads clean — which is the outcome that makes the
    // column worth having.
    const c = compareRoutes(DECLARED, GW);
    assert.deepEqual([c.missing, c.undeclared, c.unstated], [0, 0, 0]);
    // The known positive: it looked at all eight rather than filtering the answer down to nothing.
    assert.equal(c.rows?.length, 8);
    assert.equal(c.rows?.filter((r) => r.verdict === "ok").length, 6);
    assert.equal(c.rows?.filter((r) => r.verdict === "automatic").length, 2);
  });

  it("reports a declared route that is not on the host", () => {
    // The finding the declaration exists for. Rebuild gw-01 and the two cluster routes are gone; until
    // now nothing in this system would have noticed until the gateway stopped reaching the cluster.
    const c = compareRoutes(DECLARED, GW.filter((r) => r.dst !== "10.17.192.0/18"));
    assert.equal(c.missing, 1);
    const row = c.rows?.[0];
    assert.equal(row?.verdict, "missing");
    assert.equal(row?.dst, "10.17.192.0/18");
    assert.equal(row?.note, "cluster services");
  });

  it("reports a static route nobody declared", () => {
    const c = compareRoutes(DECLARED.slice(1), GW);
    assert.equal(c.undeclared, 1);
    assert.equal(c.rows?.[0]?.dst, "10.17.128.0/18");
    assert.equal(c.rows?.[0]?.verdict, "undeclared");
  });

  it("calls an undeclared route with no protocol unstated, not undeclared", () => {
    // Keeping the two apart is the correction. "A person put this here and did not write it down" and
    // "the kernel did not say who put this here" call for different next steps, and one of them is not
    // a finding against anybody.
    const c = compareRoutes([], GW);
    assert.equal(c.undeclared, 2, "the two proto static routes");
    assert.equal(c.unstated, 4, "the four wg0 routes");
    assert.equal(c.rows?.filter((r) => r.verdict === "automatic").length, 2);
  });

  it("puts the findings before everything else", () => {
    // A table of eighteen rows with the one that matters in the middle is a table that gets skimmed.
    const c = compareRoutes(DECLARED.slice(1), GW);
    assert.deepEqual(c.rows?.slice(0, 1).map((r) => r.verdict), ["undeclared"]);
    assert.ok(c.rows!.findIndex((r) => r.verdict === "ok") > 0);
  });

  it("matches on destination and table, and on dev or via only when declared", () => {
    // A declaration that names where a route goes and leaves the interface open is legitimate: the
    // mesh routes are identified by destination, and an interface rename should not read as drift.
    const open = compareRoutes([decl({ dst: "10.254.0.0/16", owner: "wireguard" })], GW);
    assert.equal(open.missing, 0);
    // But a declaration that *does* name the interface holds the host to it.
    const pinned = compareRoutes([decl({ dst: "10.254.0.0/16", dev: "eth9", owner: "wireguard" })], GW);
    assert.equal(pinned.missing, 1);
  });

  it("treats an absent table as main on both sides", () => {
    const c = compareRoutes([decl({ dst: "10.17.128.0/18" })], [
      { dst: "10.17.128.0/18", via: "10.17.0.10", dev: "enp8s0", proto: "static", table: "" },
    ]);
    assert.equal(c.missing, 0);
    assert.equal(c.rows?.[0]?.table, "main");
  });

  it("does not let one declaration claim two identical routes", () => {
    // Two routes to the same place through different next hops is a real configuration. One
    // declaration matching both would hide the second and report a clean table over a duplicate.
    const twice: ObservedRoute[] = [
      { dst: "10.9.0.0/16", via: "10.0.0.1", dev: "eth0", proto: "static", table: "main" },
      { dst: "10.9.0.0/16", via: "10.0.0.2", dev: "eth0", proto: "static", table: "main" },
    ];
    const c = compareRoutes([decl({ dst: "10.9.0.0/16" })], twice);
    assert.equal(c.undeclared, 1, "the second route was absorbed by the one declaration");
  });

  it("shows the observed protocol on a matched row, so a wrong owner is visible", () => {
    // A declaration saying wg-quick owns a route the kernel calls `static` is a claim that has come
    // apart from the mechanism. Smoothing it over would make the declaration unfalsifiable.
    const c = compareRoutes([decl({ dst: "10.17.128.0/18", owner: "wireguard" })], GW);
    const row = c.rows?.find((r) => r.dst === "10.17.128.0/18");
    assert.equal(row?.verdict, "ok");
    assert.equal(row?.origin, "static");
    assert.equal(row?.owner, "wireguard");
  });
});

describe("an older agent's report", () => {
  it("is classified from the protocol rather than from its own flag", () => {
    // Agents before 2026-08-17 send `handAdded` with the meaning that produced the false positive.
    // Trusting it would put a known-wrong verdict beside a correct one in the same column during the
    // rollout, which is worse than either.
    const old: ObservedRoute[] = [{ dst: "10.254.0.0/16", via: "", dev: "wg0", proto: "", table: "main", handAdded: true }];
    const c = compareRoutes([], old);
    assert.equal(c.unstated, 1);
    assert.equal(c.undeclared, 0, "the old flag was believed");
  });

  it("prefers the agent's own classification when it sends one", () => {
    const fresh: ObservedRoute[] = [{ dst: "10.9.0.0/16", via: "", dev: "eth0", proto: "", table: "main", origin: "static" }];
    assert.equal(compareRoutes([], fresh).undeclared, 1);
  });
});

describe("what heliopause would apply", () => {
  it("counts only the routes it owns", () => {
    // The safety boundary, stated as a number rather than as a comment. heliopause fighting wg-quick
    // or a DHCP lease over a route is a loop with a fleet on the other end.
    const mixed: RouteDecl[] = [
      decl({ dst: "10.1.0.0/16", owner: "wireguard" }),
      decl({ dst: "10.2.0.0/16", owner: "operator" }),
      decl({ dst: "10.3.0.0/16", owner: "heliopause" }),
    ];
    assert.equal(readyToApply(mixed), 1);
  });

  it("is zero for the fleet as declared today", () => {
    // Deliberate. Nothing writes routes yet, and this asserts that the declaration format arriving did
    // not quietly bring an applier with it.
    assert.equal(readyToApply(undefined), 0);
  });
});

describe("the ranges a route may not be written over", () => {
  // ## The gap this closes
  //
  // The applier's only verification is the heartbeat, and a heartbeat proves the **relay** path
  // survived. Management arrives from somewhere else, so a declared route that redirects the
  // management range locks every operator out and then confirms cleanly — the deadline exists and has
  // nothing to notice. `mustContain` is the same protection on the ruleset side, and it is a refusal
  // there for the same reason it is one here: by the time you could look, the path you would look
  // through is gone.
  const baseline = [
    { desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: ["10.254.0.0/16", "10.255.0.0/16", "203.0.113.25/32"] },
    { desc: "ICMPv6 (NDP)", proto: "icmpv6", ports: "", srcCidrs: [] },
  ];

  it("derives the guard from the baseline rather than from a second list", () => {
    // A separate list would be a second thing to keep in step, and that failure is silent: the two
    // agree today and disagree after the change nobody propagated.
    assert.deepEqual(managementGuard(baseline), ["10.254.0.0/16", "10.255.0.0/16", "203.0.113.25/32"]);
  });

  it("skips a baseline entry that names every source", () => {
    // An empty `srcCidrs` means "any source", which names no particular return path. Treating it as
    // every address would refuse every route including the safe ones, and a guard that refuses
    // everything gets deleted rather than obeyed.
    assert.deepEqual(managementGuard([{ srcCidrs: [] }]), []);
  });

  it("leaves out v6, which the applier cannot compare", () => {
    // The agent reads `ip -4 route`. Carrying a v6 range to a check that cannot use it reads as
    // protection and is not — the same failure as an expectation nobody evaluates.
    assert.deepEqual(managementGuard([{ srcCidrs: ["10.0.0.0/8", "fd00::/8"] }]), ["10.0.0.0/8"]);
  });

  it("is empty for a deployment with no baseline, and says so by being empty", () => {
    assert.deepEqual(managementGuard(undefined), []);
    assert.deepEqual(managementGuard([]), []);
  });

  it("deduplicates, because two baseline rules usually share a source", () => {
    assert.deepEqual(managementGuard([{ srcCidrs: ["10.254.0.0/16"] }, { srcCidrs: ["10.254.0.0/16"] }]), ["10.254.0.0/16"]);
  });
});

describe("the manager must not turn an absent declaration into an empty one", () => {
  // ## The defect this pins, found in production twenty minutes after shipping it
  //
  // The `/routes` handler read the declaration as
  // `declaredBy.has(host) ? (declaredBy.get(host) ?? []) : undefined`, meaning a host present in the
  // site model with no `routes` key was compared against an **empty declaration** rather than none.
  //
  // Against the live fleet that produced `missing 0 · undeclared 0 · unstated 0` for k3s-01 and the
  // three mailers — the best-looking result the screen can print — over four hosts nobody had
  // described. It also put the handler in disagreement with `policy/dev-routes.test.ts`, which asserts
  // `rows === null` for those same hosts: two halves of one answer, quietly contradicting each other.
  //
  // The assertion is on the source rather than through a server because what went wrong was one
  // expression, and a test that stands up a manager to check it would be slower and no more specific.
  it("passes the declaration through instead of defaulting it", () => {
    const src = readFileSync(new URL("./manager-server.ts", import.meta.url), "utf8");
    const call = /compareRoutes\(([^;]*?), h\.routes\)/.exec(src)?.[1] ?? "";
    assert.ok(call, "the /routes handler no longer calls compareRoutes — this test is measuring nothing");
    assert.equal(/\?\?\s*\[\]/.test(call), false, `an absent declaration is being defaulted to []: ${call}`);
    assert.equal(/\.has\(/.test(call), false, `presence in the model is being read as a declaration: ${call}`);
  });

  it("keeps the two absences meaning the same thing to a reader", () => {
    // A host outside the model and a host inside it with nothing declared are both "no route
    // declaration for this host". Only an explicit `routes: []` says "looked, nothing to declare",
    // and that still produces rows.
    assert.equal(compareRoutes(undefined, GW).rows, null);
    assert.notEqual(compareRoutes([], GW).rows, null);
    assert.equal(compareRoutes([], GW).rows?.length, GW.length);
  });
});
