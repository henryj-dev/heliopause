// Renderer tests.
//
// **Baseline protection is why this module exists** — a rule that severs the management path is
// how you lose a host. The rejection cases are therefore pinned hardest.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { contains, excludes, ordered } from "./test-util.ts";
import { defineConfig, tableRef, type Config } from "./config.ts";
import {
  baselineConflict,
  cidrsOverlap,
  portsOverlap,
  planHostRuleset,
  renderHostRuleset,
  RenderError,
  type EgressItem,
  type InputItem,
} from "./nft.ts";
import { renderHostRulesetJson } from "./nft-json.ts";
import type { Policy } from "./policy.ts";

const MGMT = ["10.254.0.0/16"];

const cfg: Config = defineConfig({
  tableName: "heliopause",
  internalSupernet: "10.0.0.0/8",
  baseline: [
    { desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: MGMT },
    { desc: "DNS", proto: "udp", ports: "53", srcCidrs: [] },
  ],
});

function policy(over: Partial<Policy> = {}): Policy {
  return {
    id: "p1",
    name: "test policy",
    src: { kind: "cidr", value: "10.1.0.0/16" },
    dst: { kind: "host", value: "db-01" },
    proto: "tcp",
    ports: "5432",
    action: "deny",
    denyMode: "drop",
    priority: 100,
    enabled: true,
    notes: "",
    ...over,
  };
}
function item(over: Partial<InputItem> = {}): InputItem {
  return { policy: policy(), srcCidrs: ["10.1.0.5/32"], dstCidrs: ["10.2.0.7/32"], ...over };
}

describe("cidrsOverlap", () => {
  it("treats containment as overlap", () => {
    assert.equal(cidrsOverlap("10.1.0.0/16", "10.1.0.5/32"), true);
    assert.equal(cidrsOverlap("10.1.0.5/32", "10.1.0.0/16"), true);
  });
  it("separate ranges do not overlap", () => {
    assert.equal(cidrsOverlap("10.1.0.0/16", "10.2.0.0/16"), false);
  });
  it("**undecidable input counts as overlapping** — bias toward protection", () => {
    // Treating unparseable input as "no overlap" would silently bypass baseline protection.
    assert.equal(cidrsOverlap("garbage", "10.254.0.0/16"), true);
    assert.equal(cidrsOverlap("10.254.0.0/16", "10.254.0.0/notanumber"), true);
    // Embedded IPv4 is refused rather than expanded, the same call `familyOf` makes, so it lands in
    // the conservative bucket rather than being reasoned about as though it were IPv4.
    assert.equal(cidrsOverlap("::ffff:10.254.0.5/128", "10.254.0.0/16"), true);
  });

  // ## IPv6 was in the undecidable bucket, and that was the wrong bucket
  //
  // `ipToInt` returned null for anything with a colon, so every comparison involving an IPv6 CIDR
  // answered `true`. `baselineConflict` **rejects** the policy it finds a conflict for, so that was
  // not caution — it threw away every IPv6 deny whose protocol and ports touched a baseline entry
  // and gave "could block a protected path" as the reason, which is false: an `ip6 saddr` rule
  // matches no IPv4 packet. On a fleet where every host has a public IPv6 address.
  it("compares IPv6 rather than calling it undecidable", () => {
    assert.equal(cidrsOverlap("2001:db8:1::/48", "2001:db8:1::5/128"), true);
    assert.equal(cidrsOverlap("2001:db8:1::/48", "2001:db8:2::/48"), false);
  });

  it("never calls two different families an overlap", () => {
    // `groupByFamily` exists because a rule renders into one family's chain and matches nothing in
    // the other. This says the same thing where the decision is made.
    assert.equal(cidrsOverlap("2001:db8::/32", "10.254.0.0/16"), false);
    assert.equal(cidrsOverlap("fd00::/8", "10.254.0.0/16"), false);
    // `::/0` spans a larger number than `0.0.0.0/0`; compared as bare integers it contains it.
    assert.equal(cidrsOverlap("::/0", "0.0.0.0/0"), false);
  });

  it("masks the base to the prefix", () => {
    // `10.1.0.5/16` is `10.1.0.0/16`. Read unmasked it would run 65,536 addresses past `.0.5` and
    // into `10.2.x`, which is a different zone and, here, a different baseline decision.
    assert.equal(cidrsOverlap("10.1.0.5/16", "10.2.0.1/32"), false);
    assert.equal(cidrsOverlap("10.1.0.5/16", "10.1.255.254/32"), true);
  });
});

describe("baselineConflict — IPv6", () => {
  it("does not reject an IPv6 deny over an IPv4 management path", () => {
    // The live consequence of the bucket above. `cfg`'s baseline protects an IPv4 management range
    // on tcp/22; an IPv6 source cannot reach it, and the policy must survive.
    assert.equal(baselineConflict(cfg, policy({ proto: "tcp", ports: "22" }), ["2001:db8::/32"]), null);
  });

  it("still rejects one that could block an IPv6 management path", () => {
    // The known positive. Without it the test above passes against a function that has stopped
    // checking IPv6 altogether, which is the same defect with the sign flipped.
    const v6cfg = { ...cfg, baseline: [{ ...cfg.baseline[0]!, srcCidrs: ["2001:db8:ff::/48"] }] };
    contains(
      baselineConflict(v6cfg, policy({ proto: "tcp", ports: "22" }), ["2001:db8:ff::5/128"])?.desc,
      "management SSH",
    );
  });
});

describe("portsOverlap", () => {
  it("handles single, list and range", () => {
    assert.equal(portsOverlap("22", "22"), true);
    assert.equal(portsOverlap("80,443", "443"), true);
    assert.equal(portsOverlap("20:30", "22"), true);
    assert.equal(portsOverlap("80,443", "22"), false);
  });
  it("empty policy ports means all ports and overlaps everything", () => {
    assert.equal(portsOverlap("", "22"), true);
  });
});

describe("baselineConflict", () => {
  it("rejects a policy that could block management SSH", () => {
    contains(baselineConflict(cfg, policy({ proto: "tcp", ports: "22" }), ["10.254.0.5/32"])?.desc, "management SSH");
  });
  it("an unrestricted source overlaps the management path too", () => {
    assert.notEqual(baselineConflict(cfg, policy({ proto: "tcp", ports: "22" }), []), null);
  });
  it("allows blocking 22 from a source the baseline does not cover", () => {
    assert.equal(baselineConflict(cfg, policy({ proto: "tcp", ports: "22" }), ["10.1.0.5/32"]), null);
  });
  it("a baseline entry with no source restriction protects against every source", () => {
    assert.notEqual(baselineConflict(cfg, policy({ proto: "udp", ports: "53" }), ["10.1.0.5/32"]), null);
  });
  it("proto=any conflicts with both tcp and udp baselines", () => {
    assert.notEqual(baselineConflict(cfg, policy({ proto: "any", ports: "53" }), []), null);
  });
  it("an empty baseline protects nothing", () => {
    const bare = defineConfig({ baseline: [] });
    assert.equal(baselineConflict(bare, policy({ proto: "tcp", ports: "22" }), []), null);
  });
});

describe("renderHostRuleset", () => {
  it("declares only its own table and never a forward hook", () => {
    const r = renderHostRuleset(cfg, "db-01", [item()]);
    const T = tableRef(cfg);
    contains(r.ruleset, `table ${T} {`);
    // Count actual declarations, not the word appearing in a comment.
    const declared = [...r.ruleset.matchAll(/^\s*(?:delete )?table\s+(\S+\s+\S+)/gm)].map((m) => m[1]);
    assert.deepEqual([...new Set(declared)], [T]);
    excludes(r.ruleset, "hook forward");
    contains(r.ruleset, "hook input");
    contains(r.ruleset, "hook output");
  });

  it("puts delete table before the definition so re-apply is idempotent", () => {
    const r = renderHostRuleset(cfg, "db-01", []);
    const T = tableRef(cfg);
    ordered(r.ruleset, `table ${T} {}`, `delete table ${T}`);
  });

  it("**conntrack accept is the first rule in both chains**", () => {
    // Without it a broad deny drops replies to connections this host opened.
    const r = renderHostRuleset(cfg, "db-01", [item()]);
    for (const chain of ["input", "output"]) {
      const body = r.ruleset.split(`chain ${chain} {`)[1]!.split("}")[0]!;
      const rules = body
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("#") && !l.startsWith("type filter hook"))
        .filter((l) => l.includes("accept") || l.includes("drop") || l.includes("reject"));
      contains(rules[0], "ct state established,related accept");
    }
  });

  it("baseline rules render before policy denies", () => {
    const r = renderHostRuleset(cfg, "db-01", [item()]);
    ordered(r.ruleset, "baseline:", "drop");
  });

  it("renders a deny rule", () => {
    const r = renderHostRuleset(cfg, "db-01", [item()]);
    assert.equal(r.ruleCount, 1);
    contains(
      r.ruleset,
      'ip saddr 10.1.0.5/32 ip daddr 10.2.0.7/32 meta l4proto tcp tcp dport 5432 drop comment "p1 test policy"',
    );
  });

  it("converts port ranges to nft notation and lists to sets", () => {
    contains(renderHostRuleset(cfg, "h", [item({ policy: policy({ ports: "8000:8080" }) })]).ruleset, "tcp dport 8000-8080");
    contains(renderHostRuleset(cfg, "h", [item({ policy: policy({ ports: "8080,9090" }) })]).ruleset, "tcp dport { 8080, 9090 }");
  });

  it("omits the source match when there is no source restriction", () => {
    const r = renderHostRuleset(cfg, "h", [item({ srcCidrs: [], policy: policy({ ports: "8080" }) })]);
    const deny = r.ruleset.split("\n").find((l) => l.includes("drop"))!;
    contains(deny, "ip daddr");
    excludes(deny, "ip saddr");
  });

  // Under an accepting chain policy an allow rule changes nothing, so rendering one would let
  // somebody read a no-op as enforcement.
  it("**allow policies are skipped while the chain policy accepts**", () => {
    const r = renderHostRuleset(cfg, "h", [item({ policy: policy({ action: "allow" }) })]);
    assert.equal(r.ruleCount, 0);
    contains(r.skipped[0]!.reason, "no effect");
  });

  it("skips disabled policies and unresolvable destinations", () => {
    contains(renderHostRuleset(cfg, "h", [item({ policy: policy({ enabled: false }) })]).skipped[0]!.reason, "disabled");
    contains(renderHostRuleset(cfg, "h", [item({ dstCidrs: [] })]).skipped[0]!.reason, "does not resolve");
  });

  it("strips quotes and newlines from comments so the syntax cannot break", () => {
    const r = renderHostRuleset(cfg, "h", [item({ policy: policy({ name: 'evil" \n drop all' }) })]);
    const line = r.ruleset.split("\n").find((l) => l.includes("comment"))!;
    assert.equal((line.match(/"/g) ?? []).length, 2);
  });
});

describe("denyMode", () => {
  it("drop is the default", () => {
    contains(renderHostRuleset(cfg, "h", [item()]).ruleset, "tcp dport 5432 drop");
  });
  it("tcp reject uses a TCP reset so the client fails immediately", () => {
    const r = renderHostRuleset(cfg, "h", [item({ policy: policy({ denyMode: "reject" }) })]);
    contains(r.ruleset, "tcp dport 5432 reject with tcp reset");
  });
  it("**proto=any must not use tcp reset** — TCP is not guaranteed", () => {
    const r = renderHostRuleset(cfg, "h", [item({ policy: policy({ proto: "any", ports: "8080", denyMode: "reject" }) })]);
    const line = r.ruleset.split("\n").find((l) => l.includes("reject"))!;
    contains(line, "reject");
    excludes(line, "tcp reset");
  });
});

describe("egress", () => {
  const eg = (over: Partial<EgressItem> = {}): EgressItem => ({
    policy: policy({ id: "e1", name: "egress", dst: { kind: "internet", value: "" }, ports: "25" }),
    dstCidrs: null,
    ...over,
  });

  it("renders 'to the internet' as a negated internal supernet", () => {
    const r = renderHostRuleset(cfg, "h", [], [eg()]);
    contains(r.ruleset, "ip daddr != 10.0.0.0/8 meta l4proto tcp tcp dport 25 drop");
  });

  it("renders explicit destinations as an address match", () => {
    const r = renderHostRuleset(cfg, "h", [], [eg({ dstCidrs: ["10.9.0.1/32"] })]);
    contains(r.ruleset, "ip daddr 10.9.0.1/32");
  });

  it("never emits a source match (the output hook implies this host)", () => {
    const deny = renderHostRuleset(cfg, "h", [], [eg()]).ruleset.split("\n").find((l) => l.includes("drop"))!;
    excludes(deny, "saddr");
  });

  it("**rejects an empty destination list** — it would become 'drop all outbound'", () => {
    const r = renderHostRuleset(cfg, "h", [], [eg({ dstCidrs: [] })]);
    assert.equal(r.ruleCount, 0);
    contains(r.skipped[0]!.reason, "does not resolve");
    assert.equal(r.skipped[0]!.hook, "output");
  });

  it("counts input and output rules together", () => {
    assert.equal(renderHostRuleset(cfg, "h", [item()], [eg()]).ruleCount, 2);
  });
});

// ── Input validation (H34 — audit H-2 · M-5 · M-6) ───────────────────────────
//
// These pin the boundary between "understood and deliberately not rendered" and "could not be
// understood". The second must not become the first: a deny that quietly vanishes because a
// resolver returned garbage is an open port that every dashboard reports as closed.

describe("host names", () => {
  // The measured failure: a host name carrying newlines forges the text preview. The header
  // comment ends up displaying `tcp dport 22 accept` — a rule that is not in the ruleset.
  it("refuses a name that would forge the preview", () => {
    const evil = "web-01\n#   tcp dport 22 accept";
    assert.throws(() => renderHostRuleset(cfg, evil, [item()]), RenderError);
  });

  it("refuses a name that is not an identifier", () => {
    for (const bad of ["../etc/passwd", "host name", '"quoted"', "", ".leading-dot"]) {
      assert.throws(() => renderHostRuleset(cfg, bad, [item()]), RenderError, `expected refusal: ${bad}`);
    }
  });

  it("accepts an ordinary FQDN", () => {
    // A long multi-label name, because the check above rejects on shape and the risk is that it
    // rejects too much. `example.com` is the reserved documentation domain (RFC 2606).
    const r = renderHostRuleset(cfg, "k3s-01.dev-icn-vtr.internal.example.com", [item()]);
    assert.equal(r.ruleCount, 1);
  });
});

describe("unresolved object references", () => {
  // `@web` is not a syntax error in nft text — it is a **named set reference**, so the rule
  // renders and then matches some unrelated set or fails at apply. In JSON it becomes NaN, which
  // JSON.stringify writes as null. Neither failure announces itself.
  it("refuses a ports field the resolver never expanded", () => {
    assert.throws(
      () => renderHostRuleset(cfg, "h", [item({ policy: policy({ ports: "@web" }) })]),
      /unresolved service-object reference/,
    );
  });

  it("refuses it in the JSON emitter too", () => {
    assert.throws(
      () => renderHostRulesetJson(cfg, "h", [item({ policy: policy({ ports: "@web" }) })]),
      /unresolved service-object reference/,
    );
  });
});

describe("resolver output", () => {
  // Nothing else checks this. The policy model validates the *reference* — a host name, an object
  // name — and never what the resolver hands back for it.
  it("refuses addresses that are not IPv4", () => {
    for (const bad of ["not-an-ip", "10.0.0.0/999", "", "10.1.0.0/16 }; drop; #", "999.1.1.1"]) {
      assert.throws(
        () => renderHostRuleset(cfg, "h", [item({ srcCidrs: [bad] })]),
        RenderError,
        `expected refusal: ${JSON.stringify(bad)}`,
      );
    }
  });

  it("renders IPv6 sources with the ip6 qualifier", () => {
    const r = renderHostRuleset(cfg, "h", [
      item({ srcCidrs: ["fd10:3ff1:4a9:11::/64"], dstCidrs: ["fd10:3ff1:4a9:11::10"] }),
    ]);
    contains(r.ruleset, "ip6 saddr fd10:3ff1:4a9:11::/64");
    contains(r.ruleset, "ip6 daddr fd10:3ff1:4a9:11::10");
  });

  it("refuses malformed IPv6", () => {
    for (const bad of ["fd10::3ff1::1", "fd10:3ff1:4a9:11::/999", "gggg::1", "::ffff:10.0.0.1"]) {
      assert.throws(
        () => renderHostRuleset(cfg, "h", [item({ srcCidrs: [bad], dstCidrs: ["fd10::1"] })]),
        RenderError,
        `expected refusal: ${bad}`,
      );
    }
  });

  // One nft rule cannot mix families in an address set, so a policy resolving to both must become
  // two rules. Rendering only the first family would silently drop half the intent.
  it("splits a mixed-family source list into one rule per family", () => {
    const r = renderHostRuleset(cfg, "h", [
      item({ srcCidrs: ["10.1.0.0/16", "fd10::/64"], dstCidrs: ["10.2.0.7", "fd10::7"] }),
    ]);
    assert.equal(r.ruleCount, 2);
    contains(r.ruleset, "ip saddr 10.1.0.0/16 ip daddr 10.2.0.7");
    contains(r.ruleset, "ip6 saddr fd10::/64 ip6 daddr fd10::7");
  });

  it("refuses the same input through the JSON emitter", () => {
    assert.throws(() => renderHostRulesetJson(cfg, "h", [item({ srcCidrs: ["not-an-ip"] })]), RenderError);
  });

  // A policy that was never going to be enforced must not fail the render — otherwise one stale
  // disabled rule blocks every host in the fleet from getting an artifact.
  it("ignores bad input on a policy that is skipped anyway", () => {
    const r = renderHostRuleset(cfg, "h", [
      item({ srcCidrs: ["not-an-ip"], policy: policy({ enabled: false }) }),
    ]);
    assert.equal(r.ruleCount, 0);
    assert.equal(r.skipped.length, 1);
  });
});

describe("ports", () => {
  it("refuses ports outside 1-65535 and backwards ranges", () => {
    for (const bad of ["0", "70000", "8080:80", "http"]) {
      assert.throws(
        () => renderHostRuleset(cfg, "h", [item({ policy: policy({ ports: bad }) })]),
        RenderError,
        `expected refusal: ${bad}`,
      );
    }
  });
});

describe("baseline validation", () => {
  // Baseline comes from config, so no policy-authoring path has checked it — and it is the one
  // thing that must never be wrong, since it is what keeps the host reachable.
  it("refuses a malformed baseline source", () => {
    const bad = defineConfig({ baseline: [{ desc: "x", proto: "tcp", ports: "22", srcCidrs: ["nope"] }] });
    assert.throws(() => renderHostRuleset(bad, "h", []), RenderError);
  });

  it("refuses a malformed baseline port", () => {
    const bad = defineConfig({ baseline: [{ desc: "x", proto: "tcp", ports: "22:", srcCidrs: [] }] });
    assert.throws(() => renderHostRuleset(bad, "h", []), RenderError);
  });
});

// ── default-deny (H1 · H5 · H6 · H7) ─────────────────────────────────────────

const DENY_CFG = defineConfig({
  tableName: "heliopause",
  internalSupernet: "10.0.0.0/8",
  hookPolicy: { input: "drop", output: "accept" },
  baseline: [
    { desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: [] },
    { desc: "NDP", proto: "icmpv6", ports: "", srcCidrs: [] },
  ],
});

describe("hook policy", () => {
  it("renders the configured policy on each chain", () => {
    const r = renderHostRuleset(DENY_CFG, "h", []);
    contains(r.ruleset, "hook input priority filter; policy drop;");
    contains(r.ruleset, "hook output priority filter; policy accept;");
  });

  // Closing outbound in the same change would cut the agent's heartbeat, which is what confirms an
  // apply and what carries the instruction to undo one. The asymmetry is the migration plan.
  it("keeps output accepting while input drops", () => {
    assert.equal(DENY_CFG.hookPolicy.output, "accept");
  });

  // The one configuration that is certainly wrong: nothing is accepted before the drop, so the
  // host answers nothing at all — including the way back in.
  it("refuses a dropping input hook with no baseline", () => {
    assert.throws(
      () => defineConfig({ hookPolicy: { input: "drop", output: "accept" }, baseline: [] }),
      /locks every host out/,
    );
  });
});

describe("loopback", () => {
  // Measured, not assumed: with `policy drop` and no loopback rule, 127.0.0.1:22 is unreachable.
  // Every service talking to localhost over TCP breaks — including the "bind to 127.0.0.1 behind a
  // reverse proxy" pattern this design recommends.
  it("is accepted first once the input hook drops", () => {
    const r = renderHostRuleset(DENY_CFG, "h", []);
    const body = r.ruleset.split("chain input {")[1]!.split("  }")[0]!;
    const first = body.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("type"))[0];
    contains(first, 'iif "lo" accept');
  });

  // Under an accepting policy it would be pure noise — the packet was going to be accepted anyway.
  it("is not emitted while the chain accepts", () => {
    excludes(renderHostRuleset(cfg, "h", []).ruleset, "iif");
  });
});

describe("baseline under default-deny", () => {
  // A rule with no address match carries no family qualifier and so covers both families. That is
  // why an unrestricted management path is the safe shape.
  it("renders a source-less entry without a family qualifier", () => {
    const r = renderHostRuleset(DENY_CFG, "h", []);
    contains(r.ruleset, 'tcp dport 22 accept comment "baseline: management SSH"');
    excludes(r.ruleset, "ip saddr 0.0.0.0/0");
  });

  // NDP runs over ICMPv6. Without it IPv6 on the link stops working entirely — including the path
  // you would use to undo the change.
  it("renders an ICMPv6 baseline entry with no ports", () => {
    contains(renderHostRuleset(DENY_CFG, "h", []).ruleset, "meta l4proto icmpv6 accept");
  });

  it("pins a source-restricted entry to that source's family", () => {
    const c = defineConfig({
      hookPolicy: { input: "drop", output: "accept" },
      baseline: [{ desc: "mgmt", proto: "tcp", ports: "22", srcCidrs: ["10.254.0.0/16", "fd10::/48"] }],
    });
    const r = renderHostRuleset(c, "h", []);
    contains(r.ruleset, "ip saddr 10.254.0.0/16 tcp dport 22 accept");
    contains(r.ruleset, "ip6 saddr fd10::/48 tcp dport 22 accept");
  });
});

describe("allow policies under default-deny", () => {
  it("renders them as accept rules", () => {
    const r = renderHostRuleset(DENY_CFG, "h", [
      item({ policy: policy({ id: "A1", action: "allow", ports: "6443" }) }),
    ]);
    assert.equal(r.ruleCount, 1);
    contains(r.ruleset, 'tcp dport 6443 accept comment "A1 test policy"');
  });

  // First match wins, so a narrow deny placed before a broad allow is the only way to express
  // "open to this network except that host".
  it("orders denies before allows", () => {
    const r = renderHostRuleset(DENY_CFG, "h", [
      item({ policy: policy({ id: "A1", action: "allow", ports: "6443" }) }),
      item({ policy: policy({ id: "D1", action: "deny", ports: "6443" }), srcCidrs: ["10.9.0.0/16"] }),
    ]);
    ordered(r.ruleset, "D1", "A1");
  });

  // An allow cannot take a protected path away, so it has no reason to be checked against one.
  it("does not baseline-conflict an allow on a protected port", () => {
    const r = renderHostRuleset(DENY_CFG, "h", [
      item({ policy: policy({ id: "A2", action: "allow", ports: "22" }) }),
    ]);
    assert.equal(r.ruleCount, 1);
    assert.equal(r.skipped.length, 0);
  });
});

describe("assertions (H3)", () => {
  // Built from the configured baseline, not from the assembled rules — so a mistake in assembly
  // cannot produce a matching mistake here. It is not a check on the baseline itself; if that is
  // wrong, rules and assertions are wrong together and agree.
  it("names every baseline entry", () => {
    const plan = planHostRuleset(DENY_CFG, "h", []);
    assert.deepEqual(plan.assertions, [
      "baseline: loopback",
      "baseline: management SSH",
      "baseline: NDP",
    ]);
  });

  it("requires the loopback rule only when the input hook drops", () => {
    excludes(planHostRuleset(cfg, "h", []).assertions.join("|"), "loopback");
    contains(planHostRuleset(DENY_CFG, "h", []).assertions.join("|"), "loopback");
  });

  // Every assertion has to correspond to a rule the same plan emits, or the agent would revert a
  // ruleset that was in fact correct — and a check that fails on good input gets removed.
  it("only names rules the plan actually renders", () => {
    const plan = planHostRuleset(DENY_CFG, "h", [item()]);
    const rendered = new Set(plan.input.map((r) => r.comment));
    for (const a of plan.assertions) {
      assert.ok(rendered.has(a), `assertion ${JSON.stringify(a)} has no matching rule`);
    }
  });

  it("travels with the JSON artifact", () => {
    contains(renderHostRulesetJson(DENY_CFG, "h", []).assertions.join("|"), "baseline: management SSH");
  });
});

// ── The forward hook ──────────────────────────────────────────────────────────
//
// This chain exists so that retiring another firewall from a router is not also a routing change.
// Every test here is about that: what it must not break, and the one thing it must refuse.
describe("the forward chain", () => {
  const routing = defineConfig({
    baseline: [{ desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: MGMT }],
    forward: { guardInternal: true, hosts: ["^gw-"] },
  });

  it("is absent entirely when forward is null", () => {
    // Not an empty chain — absent. A host that does not route must have its forward hook untouched,
    // and an empty chain in a dump is indistinguishable from one whose rules were lost.
    const plan = planHostRuleset(cfg, "h-a", []);
    assert.equal(plan.forward, null);
    excludes(renderHostRuleset(cfg, "h-a", []).ruleset, "hook forward");
  });

  it("refuses routing into the internal supernet from outside it", () => {
    const out = renderHostRuleset(routing, "gw-01", []).ruleset;
    contains(out, "ip daddr 10.0.0.0/8 ip saddr != 10.0.0.0/8 drop");
  });

  it("accepts replies before the guard can drop them", () => {
    // A reply to an internally-originated flow has an external source and an internal destination —
    // exactly the shape the guard refuses. Order is the only thing separating "the VPC can reach the
    // internet" from "the VPC can send but never receive".
    const out = renderHostRuleset(routing, "gw-01", []).ruleset;
    ordered(out, "ct state established,related accept", "ip daddr 10.0.0.0/8 ip saddr !=");
  });

  it("accepts DNATed traffic before the guard can drop it", () => {
    // A published container port is DNATed to an address inside the supernet, so the guard would
    // refuse the traffic the publish exists to admit. firewalld carries the same rule in the same
    // position; this was read from its chain rather than guessed.
    const out = renderHostRuleset(routing, "gw-01", []).ruleset;
    ordered(out, "ct status dnat accept", "ip daddr 10.0.0.0/8 ip saddr !=");
  });

  it("keeps the chain policy accept even when input drops", () => {
    // Forward is not a default-deny surface: the traffic it carries includes container and VM
    // networking that no policy file describes. A default-deny here would be a firewall for traffic
    // nobody wrote down.
    const dropping = defineConfig({
      baseline: [{ desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: MGMT }],
      hookPolicy: { input: "drop", output: "accept" },
      forward: { guardInternal: true, hosts: ["^gw-"] },
    });
    contains(renderHostRuleset(dropping, "gw-01", []).ruleset, "hook forward priority filter; policy accept;");
  });

  it("is absent on a host the config does not name", () => {
    // The blast radius is the point. A site is a mix — gateways route, mail hosts do not, and a
    // cluster node routes traffic no policy file describes. Rendering this everywhere would put a
    // drop rule in front of pod traffic, which is invisible from the node and from these tests.
    assert.equal(planHostRuleset(routing, "mailer-01", []).forward, null);
    assert.notEqual(planHostRuleset(routing, "gw-01", []).forward, null);
  });

  it("renders the same decisions in JSON as in text", () => {
    // The agent applies the JSON. A guard that exists only in the preview is worse than no guard.
    const doc = JSON.parse(renderHostRulesetJson(routing, "gw-01", []).json);
    const fwd = doc.nftables.filter(
      (e: { add?: { rule?: { chain?: string } } }) => e.add?.rule?.chain === "forward",
    );
    assert.equal(fwd.length, 4, "conntrack, dnat, invalid, guard");
    const chain = doc.nftables.find(
      (e: { add?: { chain?: { hook?: string } } }) => e.add?.chain?.hook === "forward",
    );
    assert.equal(chain.add.chain.policy, "accept");
  });
});
