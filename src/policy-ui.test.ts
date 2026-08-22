// The policy page. Rendered by calling the functions, because they are ordinary functions.
//
// That is the whole reason this page has no script. The console's renderers live inside a template
// literal and had to be reached by executing it in a `new Function` harness; the first version of
// those tests grepped the page source instead, which passes when a value is computed and discarded.
// Nothing here needs a harness.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ADDRESS_COLUMNS, BASELINE_COLUMNS, FEED_COLUMNS, HISTORY_COLUMNS, HOST_COLUMNS,
  HOST_FLEET_COLUMNS, MEMBERSHIP_COLUMNS, OBJECT_COLUMNS, POLICY_COLUMNS, WORKLOAD_COLUMNS,
  RULE_COLUMNS,
  addressSpaceTable, baselineTable, feedTable, historyTable, hostTable, membershipTable,
  fileEditors, objectTable, placementCell, policyPage, policyRowHtml, riskCell, ruleTable, sourceCell, workloadTable,
} from "./policy-ui.ts";
import type { PolicyRisk, PolicyRow } from "./policy-view.ts";
import { t } from "./i18n.ts";

const row = (over: Partial<PolicyRow> = {}): PolicyRow => ({
  id: "DEV-SSH", name: "ssh from mgmt", action: "allow", denyMode: "drop",
  proto: "tcp", ports: "22", priority: 100, enabled: true, notes: null,
  hosts: ["gw-01.dev"], skippedOn: [], egressHosts: [], srcCidrs: ["10.254.0.0/16"],
  placementKnown: true, risks: [], ...over,
});

const meta = { site: "policy/dev.ts", generation: "abc1234", hosts: ["gw-01.dev", "k3s-01.dev"] };

describe("the risk cell", () => {
  it("draws renders-nowhere as an error and width as a warning", () => {
    // Wide is often correct — a public mail port is any-source by definition. Grading it as a
    // failure is how the column stops being read, and then the one that means "this rule does
    // nothing" goes unread with it.
    assert.match(riskCell(row({ risks: ["renders-nowhere"] })), /class="chip bad"/);
    assert.match(riskCell(row({ risks: ["any-source"] })), /class="chip warn"/);
    assert.match(riskCell(row({ risks: ["disabled"] })), /class="chip mute"/);
  });

  it("gives the three findings three different shapes, not only three colours", () => {
    // 시안 A9 — 「모양이 뜻이다」. The colours are what a reader who can see them uses; the shapes
    // are what everyone else uses, and what survives a screenshot pasted into a grey ticket.
    //
    // This is the known positive for the icon layer on this page: an `icon()` that returned nothing,
    // or three findings that all named the same glyph, would pass every other assertion in this file.
    const glyph = (r: PolicyRisk) => /href="#i-([a-z-]+)"/.exec(riskCell(row({ risks: [r] })))?.[1] ?? null;
    const shapes = [glyph("renders-nowhere"), glyph("any-source"), glyph("disabled")];
    assert.deepEqual(shapes, ["x", "triangle-alert", "diamond"]);
    assert.equal(new Set(shapes).size, 3, "two findings share a shape");
  });

  it("is empty for a rule with nothing to say about it", () => {
    assert.equal(riskCell(row()), "");
  });
});

describe("the placement cell", () => {
  it("names the hosts a policy renders on", () => {
    assert.match(placementCell(row({ hosts: ["a", "b"] })), /a, b/);
  });

  it("shows skips beside placements, not instead of them", () => {
    // "on 2 hosts" and "on 2, skipped on 3" are different facts, and the second is what a policy
    // covering less than its author thought looks like. The count alone reads as success.
    const out = placementCell(row({ hosts: ["a", "b"], skippedOn: ["c", "d", "e"] }));
    assert.match(out, /a, b/);
    assert.match(out, /skipped: c, d, e/);
  });

  it("says no host, loudly, when nothing rendered", () => {
    assert.match(placementCell(row({ hosts: [], skippedOn: ["a"] })), /class="bad"[^>]*>no host/);
  });

  it("refuses to say 'renders on' when the renderer was not run", () => {
    // The distinction the projection carries all the way here. Without it a reader takes a count
    // nobody checked for a fact somebody did.
    const out = placementCell(row({ placementKnown: false, hosts: ["a"] }));
    assert.match(out, /listed on 1/);
    assert.match(out, /not rendered/);
  });

  it("keeps egress hosts labelled", () => {
    assert.match(placementCell(row({ hosts: [], egressHosts: ["a"] })), /egress: a/);
  });
});

describe("the source cell", () => {
  it("says any when nothing resolved, and warns about it", () => {
    // Empty resolved sources is what the renderer turns into "any source". Rendering it blank would
    // make the widest rule on the page look like the narrowest.
    assert.match(sourceCell(row({ srcCidrs: [] })), /class="warn"[^>]*>any/);
  });

  it("folds a long list rather than stretching the row", () => {
    const out = sourceCell(row({ srcCidrs: ["10.0.0.0/8", "10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"] }));
    assert.match(out, /10\.0\.0\.0\/8, 10\.1\.0\.0\/16/);
    assert.match(out, /\+2/);
    // The half that makes this a fold rather than a decoration. Asserting only on the "+2" passes
    // when every address is printed *and* the count is appended — measured, by injecting exactly
    // that.
    assert.equal(out.includes("10.2.0.0/16"), false, out);
    assert.equal(out.includes("10.3.0.0/16"), false, out);
  });
});

describe("the row", () => {
  it("marks every port as wide", () => {
    // An empty `ports` is every port on the protocol. Printing nothing there would be the same
    // mistake as printing nothing for an empty source.
    assert.match(policyRowHtml(row({ ports: "" })), /class="warn"[^>]*>all/);
    assert.match(policyRowHtml(row({ ports: "22" })), />22</);
  });

  it("separates deny from its mode", () => {
    const out = policyRowHtml(row({ action: "deny", denyMode: "reject" }));
    assert.match(out, /class="chip bad"[^>]*>[\s\S]*?deny/);
    assert.match(out, /reject/);
  });

  it("shows notes under the name", () => {
    assert.match(policyRowHtml(row({ notes: "opened for the migration" })), /opened for the migration/);
  });

  it("has a cell for every declared column", () => {
    // A cell without a header shifts every column after it and the page still renders.
    const cells = (policyRowHtml(row()).match(/<td/g) ?? []).length;
    assert.equal(cells, POLICY_COLUMNS.length, `${cells} cells, ${POLICY_COLUMNS.length} columns`);
  });

  it("escapes a policy name", () => {
    // A policy name is text from a repository. It is not attacker-controlled in the usual sense, but
    // this page renders it into HTML and there is no reason for that to be the assumption holding.
    const out = policyRowHtml(row({ name: "<img src=x onerror=alert(1)>" }));
    assert.equal(out.includes("<img"), false, out);
    assert.match(out, /&lt;img/);
  });
});

describe("the page", () => {
  it("carries no script at all", () => {
    // The reason the rest of this file can call functions instead of executing a harness. It is also
    // what makes the page safe without a CSP nonce: nothing here can be made to run.
    const html = policyPage([row()], meta);
    assert.equal(/<script/i.test(html), false);
    // Anchored on a word boundary: an unanchored /on[a-z]+=/ matches the "ontent=" inside
    // `content=`, which is the meta tag and not a handler.
    assert.equal(/\son[a-z]+\s*=/i.test(html), false, "no inline handlers");
  });

  it("counts policies that render nowhere in the header", () => {
    const html = policyPage([row(), row({ id: "GHOST", risks: ["renders-nowhere"] })], meta);
    assert.match(html, /2 policies/);
    assert.match(html, /1 render nowhere/);
  });

  it("warns in the header when placement was not computed", () => {
    const html = policyPage([row({ placementKnown: false })], meta);
    assert.match(html, /placement not computed/);
  });

  it("confirms freshness on a good load, not only complains on a bad one", () => {
    // A banner that appears only on trouble teaches the reader that its absence means nothing was
    // checked — which was literally true here until 2026-08-16, and is how the screen stayed eleven
    // hours behind without anybody noticing. The quiet confirmation is what makes the loud one
    // legible.
    const html = policyPage([row()], { ...meta, freshness: { state: "fresh" } });
    assert.match(html, /class="fresh banner ok"/);
    assert.match(html, /current head/);
  });

  it("names both shas when the page is behind the repository", () => {
    const html = policyPage([row()], {
      ...meta,
      freshness: { state: "stale", rendered: "bda12f6", repository: "08da995aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    });
    assert.match(html, /class="fresh banner bad"/);
    assert.match(html, /bda12f6/);
    // Abbreviated on the way out: forty characters of hex in a sentence is not read, it is skipped.
    assert.match(html, /08da995</);
    assert.equal(html.includes("08da995aaaaaaaa"), false, "it printed the whole forty characters");
  });

  it("says it could not check rather than saying nothing", () => {
    // The known negative this whole banner rests on. "Could not check" and "checked, fine" look
    // identical in silence, and silence is what the console offered while it was wrong.
    const html = policyPage([row()], { ...meta, freshness: { state: "unknown", why: "403: bad credential" } });
    // Drawn on a hatch rather than in a colour — 시안 G4 puts unknown on the same mark the fleet
    // table uses for a value nobody measured, which is exactly what an unrun check is.
    assert.match(html, /class="fresh banner hatch"/);
    assert.match(html, /could not check/);
    assert.match(html, /bad credential/);
    // Not dressed as an error: nothing is known to be wrong, only unverified.
    assert.equal(/class="fresh banner bad"/.test(html), false);
  });

  it("says nothing when the renderer is the same build as the console", () => {
    // 🔑 The known negative, and the one that keeps this banner readable. Measured 2026-08-18 the
    // renderer was eleven commits behind the manager; the reason nobody saw it is that everything
    // else on the page was correct. A banner that also appears when they agree would be on during
    // every normal page view and would be skipped on the day it matters.
    const html = policyPage([row()], { ...meta, renderer: { build: "abc123abc123", mine: "abc123abc123" } });
    assert.equal(html.includes("different build"), false);
    assert.equal(html.includes("abc123abc123"), false, "it printed a build id nobody needs to read");
  });

  it("names both builds when the renderer is not the console's build", () => {
    const html = policyPage([row()], { ...meta, renderer: { build: "b32a7c6b32a7", mine: "3e1c2483e1c2" } });
    assert.match(html, /class="fresh banner warn"/);
    assert.match(html, /different build/);
    assert.match(html, /b32a7c6b32a7/);
    assert.match(html, /3e1c2483e1c2/);
    // Not an error. During a rollout the two legitimately differ for a minute, and grading that as a
    // failure is how a reader learns to ignore the one that lasts.
    assert.equal(/class="fresh banner bad"/.test(html), false);
  });

  it("treats a renderer that cannot say as a finding, not as agreement", () => {
    // `null` is "it predates the field", which is itself a lower bound on how old it is. Rendering
    // that the same as a match would turn the oldest renderers into the quietest ones.
    const html = policyPage([row()], { ...meta, renderer: { build: null, mine: "3e1c2483e1c2" } });
    assert.match(html, /class="fresh banner warn"/);
    assert.match(html, /did not say which build/);
  });

  it("says nothing about a renderer on a workstation render", () => {
    // The workstation evaluates the policy in the same process. There is no second build to
    // disagree with, and printing a comparison of a thing with itself is noise.
    const html = policyPage([row()], meta);
    assert.equal(html.includes("different build"), false);
    assert.equal(html.includes("did not say which build"), false);
  });

  it("draws no banner where nothing asked the question", () => {
    // `heliopause-ui` on a workstation has no repository credential and no console around it. A
    // banner there would be an unanswerable question rather than a warning.
    const html = policyPage([row()], meta);
    assert.equal(/class="fresh/.test(html), false);
  });

  it("carries the console's menu when it is being served as one of its screens", () => {
    // `/policy` is in the menu, and until now it was the one screen in the menu that did not carry
    // the menu — the operator sent there to read the rules they are approving had the footer link
    // and the back button. The groups are passed in rather than built here; see the `nav` field.
    const html = policyPage([row()], {
      ...meta,
      nav: [{ label: "fleet", items: [{ href: "/fleet", label: "fleet" }] }],
    });
    assert.match(html, /<nav class="sidenav"/);
    assert.match(html, /href="\/fleet"/);
  });

  it("draws no menu on a workstation, where those screens do not exist", () => {
    // `heliopause-ui` serves this page from a checkout on somebody's laptop. Links to `/fleet` there
    // would point at a console that is not running, which is worse than no menu: it looks like the
    // page is broken rather than like it is a different tool.
    //
    // The **sections** group is still drawn — this page's own navigation is not the console's — so
    // the assertion is about the console's routes, not about the sidebar existing.
    const html = policyPage([row()], meta);
    assert.equal(/href="\/fleet"/.test(html), false, "it invented a menu it was not given");
    assert.match(html, /<nav class="sidenav"/, "the sections must still be reachable");
  });

  it("puts the sections in the side with their counts, which is the first question here", () => {
    // 시안 G1: 「섹션 · 렌더된 것만」 with a figure against every name — 「무엇이 비어 있지 않은가」
    // is what a reader arrives with, and one section is shown at a time so the count is the only
    // place that answer exists.
    const html = policyPage([row(), row({ id: "B" })], meta);
    const side = /<nav class="sidenav"[\s\S]*?<\/nav>/.exec(html)?.[0] ?? "";
    assert.match(side, /policies<span class="n">2<\/span>/);
    // The one that is showing is marked, and marked in a way a screen reader hears.
    assert.match(side, /class="on" aria-current="page"/);
  });

  it("gives the reader a way back to the fleet console", () => {
    // The page was a dead end in production on 2026-08-16: served from the manager at `/policy` it
    // contained zero internal links, so an approver who followed the footer here to read the rules
    // had no route back to the plan they were approving. The footer had always been able to draw
    // this link — it just needed a manager URL, and the manager never passed one, so the page took
    // the other branch and printed advice about a `--manager=URL` flag that means nothing when the
    // manager is the thing serving it. The strings written for it were called from nowhere.
    const html = policyPage([row()], { ...meta, manager: "/" });
    assert.match(html, /<a href="\/">/, "the policy page has no link back to the console");
    // Named, not printed raw. A link whose text is "/" tells the reader nothing about where it goes.
    assert.match(html, /manager console<\/a>/);
  });

  it("still prints an absolute manager address verbatim", () => {
    // The workstation case, where this is another machine and the operator wants to see which one
    // before clicking. Naming it "manager console" there would hide the hostname.
    const html = policyPage([row()], { ...meta, manager: "https://heliopause.example/" });
    assert.match(html, /heliopause\.example/);
  });

  it("says so plainly when there is no console to link to", () => {
    // `heliopause-policy` rendering a file on a workstation with no manager configured. The advice
    // about `--manager=URL` belongs here and only here.
    const html = policyPage([row()], meta);
    assert.equal(/<a href="\//.test(html), false, "it invented a link to a console it was not given");
    assert.match(html, /--manager=URL/);
  });

  it("does not warn when it was", () => {
    assert.equal(/placement not computed/.test(policyPage([row()], meta)), false);
  });

  it("says it is read-only and where editing happens", () => {
    // 결정 8. Someone who finds this page and starts looking for a save button should be told in the
    // page, not in a document they have not read.
    assert.match(policyPage([row()], meta), /read-only/);
    assert.match(policyPage([row()], meta), /git commit/);
  });

  it("adds the editor only for a managed policy document", () => {
    const html = policyPage([row()], { ...meta, editable: true });
    assert.match(html, /id="policy-editor"/);
    assert.match(html, /fetch\('\/api\/policies\//);
    assert.match(html, /saved atomically/);
    assert.match(html, /placements JSON/);
    assert.match(html, /delete loaded policy/);
    const script = /<script>([\s\S]*?)<\/script>/.exec(html)?.[1];
    assert.ok(script); assert.doesNotThrow(() => new Function(script));
  });

  it("offers render and propose only when manager credentials are configured", () => {
    const html = policyPage([row()], { ...meta, proposable: true });
    assert.match(html, /render &amp; propose for review/);
    assert.match(html, /fetch\('\/api\/propose'/);
    for (const script of [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)]) assert.doesNotThrow(() => new Function(script[1]!));
  });

  it("renders with no policies without breaking", () => {
    assert.match(policyPage([], meta), /0 policies/);
  });
});

describe("the other three tables", () => {
  const base = [
    { desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: ["10.254.0.0/16"], anySource: false },
    { desc: "ICMP", proto: "icmp", ports: "", srcCidrs: [], anySource: true },
  ];
  const hosts = [
    { id: "gw-01.dev", stage: "gateway", inputCount: 4, egressCount: 0,
      skipped: [], placementKnown: true, protected: true },
    { id: "k3s-01.dev", stage: "canary", inputCount: 3, egressCount: 1,
      skipped: ["DEV-X"], placementKnown: true, protected: false },
  ];
  const work = [
    { id: "W1", name: "runners cannot reach data", action: "deny", src: "k8s-namespace:arc-runners",
      dst: "k8s-namespace:tinyuniverse", proto: "any", ports: "", enabled: true, notes: null },
  ];

  it("shows the baseline above the policies, because policy cannot override it", () => {
    // A reader who scans only the policy table has seen every rule an operator wrote and none of
    // these. For management SSH that is the difference between "how do I get in" and "nothing does".
    const html = policyPage([row()], { ...meta, section: "all" }, { baseline: base });
    assert.ok(html.indexOf("policy cannot override") < html.indexOf("<h2>policies</h2>"), "order");
  });

  it("renders an unrestricted baseline rule as neutral, not as a warning", () => {
    // ICMP unrestricted is deliberate. Colouring it red teaches a reader to ignore the column.
    const out = baselineTable(base);
    assert.match(out, /management SSH/);
    assert.match(out, /class="dim"[^>]*>any/);
    assert.equal(/class="bad"/.test(out), false, out);
  });

  it("marks the host protected from lockout", () => {
    // `protectedHosts` is what stops a generation from locking the relay out of its own VPC.
    const out = hostTable(hosts);
    assert.match(out, /protected from lockout/);
    assert.match(out, /DEV-X/, "skips are named, not just counted");
  });

  it("warns when the host counts were never rendered", () => {
    const out = hostTable(hosts.map((h) => ({ ...h, placementKnown: false })));
    assert.match(out, /listed, not rendered/);
  });

  it("keeps the workload table free of a placement column", () => {
    // A CiliumNetworkPolicy is cluster-scoped. Inventing a host column here would assert something
    // the model does not have.
    const out = workloadTable(work);
    assert.match(out, /cluster-scoped, not per host/);
    assert.equal(/skipped|renders on/.test(out), false, out);
  });

  it("gives every table a cell for each declared column", () => {
    for (const [cols, html] of [
      [BASELINE_COLUMNS, baselineTable(base)],
      [HOST_COLUMNS, hostTable(hosts)],
      [WORKLOAD_COLUMNS, workloadTable(work)],
    ] as const) {
      const firstRow = /<tbody>(<tr>[\s\S]*?<\/tr>)/.exec(html)?.[1] ?? "";
      assert.equal((firstRow.match(/<td/g) ?? []).length, cols.length, html.slice(0, 200));
    }
  });

  it("omits a table entirely when it has no rows", () => {
    // An empty table reads as "this site has no baseline", which is a different claim from "not
    // shown". Three of the designed screens would have been empty tables for this site.
    assert.equal(baselineTable([]), "");
    assert.equal(hostTable([]), "");
    assert.equal(workloadTable([]), "");
  });

  it("still renders the policy screen alone", () => {
    const html = policyPage([row()], meta);
    assert.match(html, /<h2>policies<\/h2>/);
    assert.equal(/policy cannot override/.test(html), false);
  });
});

describe("the hosts table's fleet half", () => {
  const base = {
    id: "gw-01.dev", stage: "gateway", inputCount: 3, egressCount: 0,
    skipped: [], placementKnown: true, protected: false,
  };
  const fleet = (over = {}) => ({
    state: "confirmed", generation: "abc1234", current: true,
    drifted: false, ageSec: 4, blockedBy: null, ...over,
  });

  it("adds the columns only when a manager answered", () => {
    // The screen is split across two surfaces. Columns that are always there but empty read as
    // "this host reported nothing", which is the alarming reading of "we did not ask".
    const without = hostTable([base]);
    const with_ = hostTable([{ ...base, fleet: fleet() }]);
    // The constants hold message keys now; the header carries the translated label.
    for (const key of HOST_FLEET_COLUMNS) {
      const c = t("en", key as Parameters<typeof t>[1]);
      assert.equal(without.includes(`<th>${c}</th>`), false, `${c} appeared unasked`);
      assert.ok(with_.includes(`<th>${c}</th>`), `${c} missing`);
    }
  });

  it("says 'not aggregated here' for a host the manager did not know", () => {
    // Row-level absence inside a joined table. Blank would be the same failure one row down.
    const out = hostTable([{ ...base, fleet: fleet() }, { ...base, id: "gw-01.prod" }]);
    assert.match(out, /not aggregated here/);
  });

  it("shows drift ahead of the reported state", () => {
    // A drifted host has confirmed. Saying so would be true and useless — the console makes the same
    // choice for the same reason.
    const out = hostTable([{ ...base, fleet: fleet({ drifted: true }) }]);
    assert.match(out, /class="bad"[^>]*>DRIFT/);
    assert.equal(/confirmed/.test(out), false, out);
  });

  it("marks a host the manager wants on another generation", () => {
    const out = hostTable([{ ...base, fleet: fleet({ current: false, generation: "old1234" }) }]);
    assert.match(out, /class="warn"[^>]*>old1234/);
    assert.match(out, /wanted elsewhere/);
  });

  it("shows blockedBy, which is empty on every good day", () => {
    const out = hostTable([{ ...base, fleet: fleet({ blockedBy: "canary is not confirmed" }) }]);
    assert.match(out, /blocked: canary is not confirmed/);
  });

  it("keeps a cell for every column once joined", () => {
    const out = hostTable([{ ...base, fleet: fleet() }]);
    const firstRow = /<tbody>(<tr>[\s\S]*?<\/tr>)/.exec(out)?.[1] ?? "";
    assert.equal((firstRow.match(/<td/g) ?? []).length,
      HOST_COLUMNS.length + HOST_FLEET_COLUMNS.length, out.slice(0, 300));
  });
});

describe("the catalogue tables", () => {
  const commit = (id: string) => ({ id, subject: `s-${id}`, author: "a", at: "2026-08-07T00:00:00Z" });

  it("distinguishes 'no manager asked' from 'not published'", () => {
    // `unknown` is the absence of a manager, not a milder "has not shipped". Rendering them the same
    // would let a page with no fleet data read as a page reporting on the fleet.
    const unknown = historyTable([{ commit: commit("a1"), status: "unknown", liveOn: [] }]);
    const notPub = historyTable([{ commit: commit("a1"), status: "not-published", liveOn: [] }]);
    assert.match(unknown, /no manager asked/);
    assert.equal(/not published/.test(unknown), false, unknown);
    assert.match(notPub, /not published/);
    assert.equal(/no manager asked/.test(notPub), false, notPub);
  });

  it("names the VPCs a live generation is on", () => {
    const out = historyTable([{ commit: commit("a1"), status: "live", liveOn: ["prod", "util"] }]);
    assert.match(out, /class="ok"[^>]*>live/);
    assert.match(out, /prod, util/);
  });

  it("marks an object nothing references", () => {
    // Dead configuration that still reads as protection to whoever scans the catalogue.
    const used = objectTable("x", [{ id: "o1", name: "n", members: ["cidr:10.0.0.0/8"], notes: null, usedBy: ["P1"] }]);
    const unused = objectTable("x", [{ id: "o1", name: "n", members: [], notes: null, usedBy: [] }]);
    assert.match(unused, /class="warn"[^>]*>unused/);
    assert.equal(/unused/.test(used), false, used);
  });

  it("shows an empty namespace as a count with a reason, not as blank", () => {
    // Zero pods in a CI namespace means "no job right now", not "safe".
    const out = membershipTable([
      { kind: "namespace", name: "arc-runners", members: [], at: "2026-08-07T01:00:00Z", host: "k3s-01.dev", usedBy: ["RUNNERS-DENY-IDP"] },
    ]);
    assert.match(out, /none right now/);
    assert.match(out, /2026-08-07T01:00:00Z/, "the read time travels with the count");
    // M10: the count alone cannot separate "idle between jobs" from "this rule governs nothing".
    // Naming the rules beside it is what lets an operator tell them apart.
    assert.match(out, /RUNNERS-DENY-IDP/, "an empty count must name what depends on it");
  });

  it("labels the address space as derived", () => {
    // It is the union of what the rules reference, not an inventory of the site's networks. The two
    // differ exactly where a network exists and no rule mentions it.
    const out = addressSpaceTable([{ cidr: "10.0.0.0/8", asSource: 3, asHost: [] }]);
    assert.match(out, /not an inventory/);
  });

  it("labels feeds as referenced rather than configured", () => {
    const out = feedTable([{ ref: "https://feed.example.invalid/kr", usedBy: ["A"] }]);
    assert.match(out, /not a registry/);
  });

  it("omits every catalogue table when it is empty", () => {
    assert.equal(objectTable("x", []), "");
    assert.equal(feedTable([]), "");
    assert.equal(membershipTable([]), "");
    assert.equal(addressSpaceTable([]), "");
    assert.equal(historyTable([]), "");
  });

  it("gives each catalogue table a cell per declared column", () => {
    const cases = [
      [OBJECT_COLUMNS, objectTable("x", [{ id: "o", name: "n", members: [], notes: null, usedBy: [] }])],
      [FEED_COLUMNS, feedTable([{ ref: "r", usedBy: ["A"] }])],
      [MEMBERSHIP_COLUMNS, membershipTable([{ kind: "namespace", name: "n", members: [], at: "t", host: "h", usedBy: [] }])],
      [ADDRESS_COLUMNS, addressSpaceTable([{ cidr: "c", asSource: 0, asHost: [] }])],
      [HISTORY_COLUMNS, historyTable([{ commit: commit("a1"), status: "unknown", liveOn: [] }])],
    ] as const;
    for (const [cols, html] of cases) {
      const firstRow = /<tbody>(<tr>[\s\S]*?<\/tr>)/.exec(html)?.[1] ?? "";
      assert.equal((firstRow.match(/<td/g) ?? []).length, cols.length, html.slice(0, 220));
    }
  });
});

describe("the section index", () => {
  const links = (html: string) => {
    // The section list is a group inside the shared side nav now — 시안 puts it in the left column.
    const nav = /<nav class="sidenav"[^>]*>([\s\S]*?)<\/nav>/.exec(html);
    return [...(nav?.[1] ?? "").matchAll(/href="\?s=([^"&]+)"/g)].map((m) => decodeURIComponent(m[1]!));
  };
  const anchors = (html: string) => [...html.matchAll(/<section id="([^"]+)"/g)].map((m) => m[1]!);

  // Eleven tables stacked on one page with no way to jump between them is not a screen anybody can
  // find their way around. It was built that way and nobody could see what had been built.
  it("lists every section that rendered", () => {
    const html = policyPage([row()], { ...meta, section: "all" }, {
      zones: [], crossings: [],
      hosts: [{ id: "h", stage: "canary", input: 1, egress: 0, skipped: [] } as never],
    });
    assert.ok(links(html).includes("policies"));
    assert.ok(links(html).includes("hosts"));
  });

  // A link to a section that emitted nothing is a promise the page does not keep. Empty tables are
  // omitted on purpose, so the index has to be built from what actually rendered.
  it("does not link a section that rendered nothing", () => {
    const html = policyPage([row()], meta);
    assert.ok(!links(html).includes("zones"), "no zones were supplied, so no zones link");
    assert.ok(!links(html).includes("coverage"));
  });

  // The failure this pins: an id renamed on one side and not the other. Nothing throws — the link
  // just stops going anywhere, and only a person clicking it finds out.
  it("every link has a matching anchor", () => {
    // Sections must actually render for their links to be exercised. The first version of this
    // test passed `zones: []`, so the zones table emitted nothing and the zones anchor was never
    // checked — renaming it went undetected. A fixture that produces empty tables tests nothing.
    const html = policyPage([row()], { ...meta, section: "all" }, {
      zones: [{ zone: { id: "mgmt", name: "management", cidrs: ["10.254.0.0/16"], trust: 3 }, asSource: 1, asDestination: 0, admits: 0 }],
      crossings: [],
      hosts: [{ id: "h", stage: "canary", input: 1, egress: 0, skipped: [] } as never],
    });
    assert.ok(links(html).includes("zones"), "the fixture must render the zones section");
    const ids = anchors(html);
    // `all` is a mode, not a section — it is the one link with no anchor behind it, on purpose.
    for (const l of links(html).filter((x) => x !== "all")) {
      assert.ok(ids.includes(l), `${l} has no section`);
    }
  });

  it("puts the index before the first section", () => {
    const html = policyPage([row()], meta);
    assert.ok(html.indexOf('<nav class="index"') < html.indexOf('<section id="policies"'));
  });
});

describe("the other half of the console", () => {
  // A page that shows half the screens and never mentions the other half reads as the whole
  // product. That is how eleven tables got built without anybody being able to find them.
  it("names the manager when one was joined", () => {
    const html = policyPage([row()], { ...meta, manager: "https://manager.example.com" });
    assert.match(html, /manager\.example\.com/);
  });

  it("says where fleet state lives even without one", () => {
    const html = policyPage([row()], meta);
    assert.match(html, /manager console/);
    assert.match(html, /--manager=URL/);
  });
});

describe("the rule table", () => {
  const edit = {
    path: "policies.json",
    nonce: "N0NCE",
    content: JSON.stringify({ schemaVersion: 1, groups: { gwPolicies: [{ id: "A", name: "a" }] } }),
  };

  // The property the rest of this file leans on: a read-only page can be tested by calling
  // functions instead of executing a harness, and it needs no `unsafe-inline`.
  it("keeps the page script-free when there is nothing to edit", () => {
    assert.doesNotMatch(policyPage([row()], meta), /<script/i);
  });

  it("appears only when the caller may write", () => {
    assert.doesNotMatch(policyPage([row()], meta), /id="rules"/);
    assert.match(policyPage([row()], { ...meta, edit }), /id="rules"/);
  });

  // The point of the change: a firewall is edited by adding and removing rows, not by being
  // careful about TypeScript syntax in order to change a port number.
  it("offers add, delete and save rather than a text box", () => {
    const html = policyPage([row()], { ...meta, edit });
    assert.match(html, /id="rule-add"/);
    assert.match(html, /id="rule-save"/);
    assert.match(html, /id="rule-propose"/);
    assert.doesNotMatch(html, /<textarea/i, "the text editor it replaced must be gone");
  });

  it("carries the nonce on its one script", () => {
    const html = policyPage([row()], { ...meta, edit });
    assert.match(html, /<script nonce="N0NCE">/);
    assert.equal((html.match(/<script/gi) ?? []).length, 1);
  });

  // The document is embedded as a JS string literal. A policy name carrying `</script>` would end
  // the block early and everything after it would be parsed as markup.
  it("embeds the document so its content cannot end the script", () => {
    const html = policyPage([row()], {
      ...meta,
      edit: { ...edit, content: '{"x":"</script><script>bad()"}' },
    });
    assert.equal((html.match(/<script/gi) ?? []).length, 1);
    assert.doesNotMatch(html, /<script>bad\(\)/);
  });

  it("is listed in the index", () => {
    // The index switches sections rather than scrolling to them, so the links are queries.
    const nav = /<nav class="sidenav"[^>]*>([\s\S]*?)<\/nav>/.exec(policyPage([row()], { ...meta, edit }));
    assert.match(nav?.[1] ?? "", /href="\?s=rules"/);
  });

  // A reader who thinks the buttons finish the job will click propose and expect the fleet to move.
  it("says saving writes a branch and proposing does not publish", () => {
    const html = policyPage([row()], { ...meta, edit });
    assert.match(html, /edits write a branch, never main/);
    assert.match(html, /it does not publish/);
  });
});

describe("one section at a time", () => {
  const full = { ...meta, hosts: ["h"] };
  const withZones = {
    zones: [{ zone: { id: "mgmt", name: "management", cidrs: ["10.254.0.0/16"], trust: 3 }, asSource: 1, asDestination: 0, admits: 0 }],
  };

  // Twelve tables stacked on one page is a page nobody reads to the end of.
  it("shows only the section asked for", () => {
    const html = policyPage([row()], { ...full, section: "zones" }, withZones as never);
    assert.match(html, /<section id="zones"/);
    assert.doesNotMatch(html, /<section id="policies"/);
  });

  it("shows the first section when none was asked for", () => {
    const html = policyPage([row()], full, withZones as never);
    assert.match(html, /<section id="policies"/);
    assert.doesNotMatch(html, /<section id="zones"/);
  });

  // An empty page reads as "this site has none of that", which is a different claim from "that
  // section is not on this screen".
  it("falls back to the first section rather than rendering none", () => {
    const html = policyPage([row()], { ...full, section: "nonexistent" }, withZones as never);
    assert.match(html, /<section id="policies"/);
  });

  it("renders everything for section=all", () => {
    const html = policyPage([row()], { ...full, section: "all" }, withZones as never);
    assert.match(html, /<section id="policies"/);
    assert.match(html, /<section id="zones"/);
  });

  it("marks which section is showing", () => {
    const html = policyPage([row()], { ...full, section: "zones" }, withZones as never);
    assert.match(html, /<a href="\?s=zones" class="on" aria-current="page"/);
  });

  it("keeps every section in the index even when one is shown", () => {
    const nav = /<nav class="sidenav"[^>]*>([\s\S]*?)<\/nav>/.exec(
      policyPage([row()], { ...full, section: "zones" }, withZones as never),
    );
    assert.match(nav?.[1] ?? "", /href="\?s=policies"/);
    assert.match(nav?.[1] ?? "", /href="\?s=zones"/);
  });
});

describe("the language", () => {
  it("renders Korean headings when asked", () => {
    const html = policyPage([row()], { ...meta, lang: "ko", section: "all" }, {
      zones: [{ zone: { id: "z", name: "z", cidrs: ["10.0.0.0/8"], trust: 1 }, asSource: 1, asDestination: 0, admits: 0 }],
    } as never);
    assert.match(html, /존 —/);
    assert.doesNotMatch(html, /zones — trust is stated/);
  });

  it("defaults to English", () => {
    assert.match(policyPage([row()], { ...meta, section: "all" }, {
      zones: [{ zone: { id: "z", name: "z", cidrs: ["10.0.0.0/8"], trust: 1 }, asSource: 1, asDestination: 0, admits: 0 }],
    } as never), /zones — trust is stated/);
  });

  // A link should carry the language, or sending a screen to a colleague means explaining how to
  // change it first.
  it("keeps the language in the section links", () => {
    const html = policyPage([row()], { ...meta, lang: "ko" });
    // `&amp;` rather than a bare `&`: it is the same URL and the correct spelling of it in an
    // attribute. The old markup emitted the bare form, which browsers forgive and validators do not.
    assert.match(html, /\?s=policies&amp;lang=ko/);
  });

  it("offers the other language", () => {
    const html = policyPage([row()], { ...meta, lang: "ko" });
    assert.match(html, /href="\?s=[^"]*&amp;lang=en"/);
    assert.match(html, /<span class="on" aria-current="true">한국어<\/span>/);
  });

  it("names leftover placement and banner copy in the language asked for", () => {
    const listed = placementCell(row({ placementKnown: false, hosts: ["a"] }), "ko");
    assert.equal(listed.includes("listed on"), false, listed);
    assert.equal(listed.includes("not rendered"), false, listed);
    assert.match(listed, /렌더되지 않음/);
    assert.match(placementCell(row({ placementKnown: false, hosts: ["a"] })), /listed on 1/);
    assert.match(placementCell(row({ placementKnown: false, hosts: ["a"] })), /not rendered/);
    const koFresh = policyPage([row()], { ...meta, lang: "ko", freshness: { state: "fresh" } });
    assert.equal(koFresh.includes("showing the repository"), false, koFresh);
    assert.equal(koFresh.includes("current head"), false, koFresh);
    const koUnknown = policyPage([row()], { ...meta, lang: "ko", freshness: { state: "unknown", why: "403" } });
    assert.equal(koUnknown.includes("could not check whether this is current"), false, koUnknown);
    const koStale = policyPage([row()], {
      ...meta, lang: "ko",
      freshness: { state: "stale", rendered: "bda12f6", repository: "08da995aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    });
    assert.equal(koStale.includes("this page is not showing the repository"), false, koStale);
    const koRender = policyPage([row()], { ...meta, lang: "ko", renderer: { build: null, mine: "abc" } });
    assert.equal(koRender.includes("the policy renderer did not say which build it is"), false, koRender);
    const koDiff = policyPage([row()], { ...meta, lang: "ko", renderer: { build: "b32a7c6b32a7", mine: "3e1c2483e1c2" } });
    assert.equal(koDiff.includes("the policy renderer is a different build from this console"), false, koDiff);
    const enFresh = policyPage([row()], { ...meta, freshness: { state: "fresh" } });
    assert.match(enFresh, /current head/);
  });

  it("names leftover placement prefixes, lockout, and banner leads in the language asked for", () => {
    const koPlace = placementCell(row({ hosts: [], skippedOn: ["a"] }), "ko");
    assert.equal(koPlace.includes("no host"), false, koPlace);
    assert.equal(koPlace.includes("skipped:"), false, koPlace);
    assert.match(koPlace, /호스트 없음/);
    const koEg = placementCell(row({ hosts: [], egressHosts: ["a"] }), "ko");
    assert.equal(koEg.includes("egress:"), false, koEg);
    assert.match(placementCell(row({ hosts: [], skippedOn: ["a"] })), /no host/);
    assert.match(placementCell(row({ hosts: [], egressHosts: ["a"] })), /egress: a/);
    const lock = [{
      id: "h", stage: "canary", inputCount: 1, egressCount: 0, skipped: [] as string[], protected: true, placementKnown: true,
    }];
    const koHost = hostTable(lock as never, "ko");
    assert.equal(koHost.includes("protected from lockout"), false, koHost);
    assert.match(hostTable(lock as never), /protected from lockout/);
    const koFresh = policyPage([row()], { ...meta, lang: "ko", freshness: { state: "fresh" } });
    assert.equal(koFresh.includes("fresh</span>"), false, koFresh);
    assert.match(koFresh, /최신<\/span>/);
    const koStale = policyPage([row()], {
      ...meta, lang: "ko",
      freshness: { state: "stale", rendered: "aaa", repository: "bbbbbbbcccccccc" },
    });
    assert.equal(koStale.includes("stale</span>"), false, koStale);
    const koUnknown = policyPage([row()], { ...meta, lang: "ko", freshness: { state: "unknown", why: "x" } });
    assert.equal(koUnknown.includes("unknown</span>"), false, koUnknown);
    const koRend = policyPage([row()], { ...meta, lang: "ko", renderer: { build: null, mine: "abc" } });
    assert.equal(koRend.includes("renderer</span>"), false, koRend);
    assert.match(policyPage([row()], { ...meta, freshness: { state: "fresh" } }), /fresh<\/span>/);
  });

  it("names the editor and propose forms in the language asked for", () => {
    const ko = policyPage([row()], { ...meta, lang: "ko", editable: true, proposable: true });
    assert.equal(ko.includes("source kind"), false, ko);
    assert.equal(ko.includes("destination kind"), false, ko);
    assert.equal(ko.includes("target VPC"), false, ko);
    assert.equal(ko.includes("policy editor"), false, ko);
    assert.equal(ko.includes("propose rendered policy"), false, ko);
    assert.match(ko, /출발지 종류/);
    assert.match(ko, /대상 VPC/);
    assert.match(ko, /정책 편집기/);
    assert.match(ko, /<option>tcp<\/option>/);
    assert.match(ko, /<option>allow<\/option>/);
    assert.match(ko, /placeholder="dev"/);
    const en = policyPage([row()], { ...meta, editable: true, proposable: true });
    assert.match(en, /source kind/);
    assert.match(en, /target VPC/);
    assert.match(en, /policy editor/);
    assert.match(en, /<option>tcp<\/option>/);
    assert.match(en, /<option value="true">/);
  });
});

describe("the rule table's script parses", () => {
  // The gap this closes. Every other test on this page reads the HTML with a regex, so a script
  // that does not parse renders, matches every assertion, and fails only in a browser — which is
  // exactly what happened: `'\n'` inside the template became a real newline and left an
  // unterminated string literal.
  //
  // `new Function` compiles without executing, so this checks syntax without needing a DOM.
  const parse = (content: string) => {
    const html = policyPage([row()], {
      ...meta,
      edit: { path: "policies.json", content, nonce: "N" },
    });
    const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html)?.[1] ?? "";
    assert.ok(script.length > 100, "no script was rendered");
    new Function(script);
    return script;
  };

  it("compiles with an ordinary document", () => {
    parse(JSON.stringify({ schemaVersion: 1, groups: { gwPolicies: [{ id: "A", name: "a" }] } }));
  });

  // The document is a policy file. Everything in it arrives in the literal.
  it("compiles with newlines, quotes and backslashes in the document", () => {
    parse(JSON.stringify({ groups: { g: [{ id: "A", name: 'a "b" \\ c\nd' }] } }));
  });

  it("compiles with markup that would end the block", () => {
    const script = parse(JSON.stringify({ groups: { g: [{ id: "</script><script>bad()", name: "x" }] } }));
    assert.equal(script.includes("</script>"), false);
  });
});

describe("the rule table is translated", () => {
  // ## The gap this closes
  //
  // `ruleTable` and `RULE_COLUMNS` were not imported by this file at all, so nothing here looked at
  // the one screen an operator edits through. It took `lang` and ignored it: nine column headers
  // rendered as the literal keys `c.id`, `c.source`, … and the buttons and heading were hardcoded
  // English. `?lang=ko` produced a section containing no Korean whatsoever, and every existing
  // i18n test passed — they cover the tables that came before this one.
  //
  // The same shape as the `policy:188` syntax error: the rule table is the newest surface and keeps
  // falling outside checks written for the older ones.
  const render = (lang: "en" | "ko") => ruleTable({ path: "policies.json", content: "{}", nonce: "n" }, lang);

  it("leaves no message key visible, in either language", () => {
    for (const lang of ["en", "ko"] as const) {
      const found = render(lang).match(/>(?:c|s|rule)\.[a-zA-Z]+</g) ?? [];
      assert.deepEqual(found, [], `${lang} renders raw keys: ${found.join(", ")}`);
    }
  });

  // "No raw key" alone would pass against hardcoded English, which is exactly what was there
  // before. This is the half that says the language argument reaches the markup.
  it("actually renders Korean when asked for Korean", () => {
    const ko = render("ko");
    assert.match(ko, /출발지/, "the source column is not translated");
    assert.match(ko, /목적지/, "the destination column is not translated");
    assert.match(ko, /규칙 추가/, "the add button is not translated");
    assert.match(ko, /브랜치에 저장/, "the save button is not translated");
  });

  it("differs between the two languages", () => {
    // A single assertion that catches "somebody wired both branches to the same catalogue entry".
    assert.notEqual(render("en"), render("ko"));
  });

  it("keeps a header cell for every declared column", () => {
    // Including the two blank ones. A missing header shifts every column after it and the table
    // still renders, which is how a row's `action` ends up read as its `proto`.
    const ths = (render("en").match(/<th>/g) ?? []).length;
    assert.equal(ths, RULE_COLUMNS.length, `${ths} headers, ${RULE_COLUMNS.length} columns`);
  });

  it("names the edited file inside the translated sentence", () => {
    // The `{path}` placeholder is filled by splitting, not by string concatenation around the
    // sentence — a rewrite that appends the path would read correctly in English and put it in the
    // wrong clause in Korean.
    for (const lang of ["en", "ko"] as const) {
      assert.match(render(lang), /<code>policies\.json<\/code>/, `${lang} does not name the file`);
    }
    assert.doesNotMatch(render("ko"), /\{path\}/);
  });

  it("escapes the file name rather than trusting it", () => {
    const out = ruleTable({ path: "<img src=x onerror=alert(1)>", content: "{}", nonce: "n" }, "en");
    assert.equal(out.includes("<img"), false, out);
  });
});

describe("the other editable files get a box each", () => {
  const two = [{ path: "dev.ts", content: "export const site = {};" }];

  it("renders a box and a save button per file", () => {
    const out = fileEditors(two, "en");
    assert.match(out, /<textarea[^>]*data-file="dev\.ts"/);
    assert.match(out, /data-save-file="dev\.ts"/);
  });

  it("renders nothing when there is no second file", () => {
    // An empty section would put a link in the page index that lands on nothing.
    assert.equal(fileEditors([], "en"), "");
  });

  it("leaves no message key visible, in either language", () => {
    for (const lang of ["en", "ko"] as const) {
      const found = fileEditors(two, lang).match(/>(?:c|s|file)\.[a-zA-Z]+</g) ?? [];
      assert.deepEqual(found, [], `${lang} renders raw keys: ${found.join(", ")}`);
    }
  });

  it("keeps the file's text out of the markup entirely", () => {
    // The content is served as a JS literal and written into the box by script. Putting it inside the
    // element would let a file containing the closing tag end it and spill the rest onto the page as
    // markup — and one of these files is TypeScript, which may well quote HTML.
    const out = fileEditors([{ path: "dev.ts", content: "</textarea><img src=x onerror=alert(1)>" }], "en");
    assert.equal(out.includes("<img"), false, out);
    assert.equal(out.includes("</textarea><"), false, out);
  });

  it("escapes a path that tries to be markup", () => {
    // The path comes from configuration, not from the policy repository, but it lands in three
    // attributes here and the rule table pins the same thing one section up.
    const out = fileEditors([{ path: '"><img src=x onerror=alert(1)>', content: "x" }], "en");
    assert.equal(out.includes("<img"), false, out);
  });

  // ## Every control on this page has something listening
  //
  // The failure this exists for has happened twice in this console in two days: a button rendered
  // with no handler, and a menu entry pointing at a view that did not exist. Both looked finished and
  // did nothing when clicked, and neither showed up in a test — the markup was correct and the
  // wiring was missing, so nothing on either side could tell.
  //
  // Written in both directions on purpose. Checking only "every button has a handler" passes on a
  // page with no buttons at all, and this section is exactly the kind that renders empty.
  // This page shows one section at a time and defaults to the first, so asking for `files` is what
  // an operator clicking the index does. A test that renders the default and looks for the box would
  // find nothing and would be measuring the wrong thing.
  const page = (more: readonly { path: string; content: string }[], section?: string) =>
    policyPage([row()], { ...meta, section, edit: { path: "policies.json", content: "{}", nonce: "n", more } });

  it("wires a handler for every save button it renders", () => {
    const html = page(two, "files");
    assert.ok(html.includes('id="files"'), "the section did not render — this test would prove nothing");
    const boxes = [...html.matchAll(/<textarea[^>]*data-file="([^"]+)"/g)].map((m) => m[1]);
    assert.deepEqual(boxes, ["dev.ts"]);
    assert.match(html, /querySelector\('\[data-save-file=/);
    // The content travels in the script rather than the markup, so the box has something to fill.
    assert.match(html, /const FILES = JSON\.parse\(/);
    assert.ok(html.includes("export const site"), "the file's text never reached the page");
  });

  it("keeps the section out of the index when there is no second file", () => {
    // The other direction, and the defect it names is the one this console shipped two days ago: an
    // index entry whose section renders nothing. Checking only "the section appears when there are
    // files" would pass on a page that always shows it.
    const html = page([], "all");
    assert.equal(html.includes('id="files"'), false);
    assert.equal(/<textarea[^>]*data-file=/.test(html), false);
  });

  it("blocks the proposal while a file box is unsaved", () => {
    // Both editors commit to one branch. A proposal opened with one of them unsaved would describe a
    // branch the operator has not finished writing, and the reviewer would see half the change.
    assert.match(page(two, "files"), /fileDirty\.size/);
  });
});

describe("the rule table's script survives its section being absent", () => {
  // ## What the parse test above cannot see
  //
  // `new Function` compiles without executing, which was right for the failure it was written for —
  // a real newline left an unterminated string. It cannot see a script that parses and then throws
  // on its first statement in a browser.
  //
  // The script is emitted whenever `meta.edit` is set, but the elements it names live in sections
  // this page shows **one at a time**: `#rule-add`, `#rule-save`, `#rule-propose` and `#rule-rows`
  // are all in `rules`. A writer opening the manager's `/policy?s=zones` got the script with none of
  // them present, and the first `addEventListener` threw at load.
  //
  // **Nothing visible broke** — everything below the throw serves the `rules` section, which is not
  // on that page. It is guarded because a routine page view should not throw: an exception that is
  // always there is one nobody reads, and the next real one lands in a console that already has red.
  //
  // The fixtures are this file's `row`/`meta` on purpose. A second copy in a second file is how the
  // first attempt at this test failed — the copy was thinner than the original and threw inside the
  // renderer, which looks exactly like the defect under test.
  const noop = () => {};
  const element = () => ({ addEventListener: noop, textContent: "", className: "", style: {},
                           appendChild: noop, setAttribute: noop, value: "", innerHTML: "" });
  const run = (getElementById: (id: string) => unknown) => {
    const html = policyPage([row()], {
      ...meta,
      // A whole policy, not a stub. `render()` reads `src.kind` and `dst.kind`, so a thinner
      // document throws inside the script — which would pass the "does not throw" test only by
      // never getting there, and fail the positive for the wrong reason.
      edit: {
        path: "policies.json",
        content: JSON.stringify({
          schemaVersion: 1,
          groups: { gwPolicies: [{
            id: "A", name: "a", enabled: true, priority: 100, proto: "tcp", ports: "22",
            action: "allow", denyMode: "drop", notes: "",
            src: { kind: "cidr", value: "10.0.0.0/8" }, dst: { kind: "any", value: "" },
          }] },
        }),
        nonce: "N",
      },
    });
    const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html)?.[1] ?? "";
    assert.ok(script.length > 100, "no script was rendered");
    new Function("document", "fetch", script)(
      { getElementById, createElement: element },
      async () => ({ ok: true, json: async () => ({}) }),
    );
  };

  it("runs when the document has none of its elements", () => {
    assert.doesNotThrow(() => run(() => null));
  });

  it("still draws the table when the section is there", () => {
    // 🔑 The known positive. Without it the assertion above is satisfied by a script that does
    // nothing at all — guards can be added until the page stops drawing and this file stays green.
    let cleared = 0;
    const tbody = new Proxy(element(), {
      set: (t, k, v) => { if (k === "textContent") cleared++; return Reflect.set(t, k, v); },
    });
    run((id) => (id === "rule-rows" ? tbody : element()));
    assert.ok(cleared > 0, "render() never touched the table body — the guard swallowed the draw");
  });
});

/**
 * What the table can actually write.
 *
 * The first version edited nine fields; the document uses eleven. The two it left out were `notes`
 * and `denyMode`, and the group was read-only text. Measured on the live document at the time: 77
 * rules, 76 of them carrying a note — so the table could *read* every reason and write none, and a
 * rule created here was the one rule with no reason. Moving a rule between groups meant deleting it
 * and adding it back, which dropped the note, so the two gaps multiplied.
 *
 * These assert on the JSON that reaches `POST /policy/edit`, not on the DOM. A cell that renders and
 * does not survive the save is the failure this is for, and only the saved document shows it.
 */
describe("the rule table writes every field the document uses", () => {
  type Listener = () => unknown;
  interface El {
    tag: string;
    children: El[];
    on: Record<string, Listener[]>;
    value: string;
    checked: boolean;
    textContent: string;
    className: string;
    appendChild: (c: El) => El;
    addEventListener: (t: string, f: Listener) => void;
    setAttribute: (k: string, v: string) => void;
    rows?: number;
    cols?: number;
    size?: number;
    type?: string;
  }
  const make = (tag: string): El => {
    const el: El = {
      tag, children: [], on: {}, value: "", checked: false, textContent: "", className: "",
      appendChild: (c) => { el.children.push(c); return c; },
      addEventListener: (t, f) => { (el.on[t] ??= []).push(f); },
      setAttribute: () => {},
    };
    return el;
  };
  const fire = (el: El, type: string) => { for (const f of el.on[type] ?? []) f(); };
  const walk = (el: El): El[] => [el, ...el.children.flatMap(walk)];

  const NOTE = "why this rule exists";
  // Typed rather than inferred: `k3sPolicies: []` infers `never[]`, and every assertion about a rule
  // that arrives in it by being moved or added then fails to compile against `never`.
  type Rule = Record<string, unknown> & { notes?: string; denyMode?: string };
  const doc = (): { schemaVersion: number; groups: { gwPolicies: Rule[]; k3sPolicies: Rule[] } } => ({
    schemaVersion: 1,
    groups: {
      gwPolicies: [{
        id: "A", name: "a", enabled: true, priority: 100, proto: "tcp", ports: "22",
        action: "deny", denyMode: "drop", notes: NOTE,
        src: { kind: "cidr", value: "10.0.0.0/8" }, dst: { kind: "any", value: "" },
      }],
      k3sPolicies: [],
    },
  });

  const boot = (group = "k3sPolicies") => {
    const ids = ["edit-result", "rule-dirty", "rule-rows", "rule-add", "rule-save", "rule-propose"];
    const byId: Record<string, El> = {};
    for (const id of ids) byId[id] = make("div");
    const posts: { url: string; body: Record<string, string> }[] = [];
    const html = policyPage([row()], {
      ...meta,
      edit: { path: "policies.json", nonce: "N", content: JSON.stringify(doc()) },
    });
    const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html)?.[1] ?? "";
    assert.ok(script.length > 100, "no script was rendered");
    new Function("document", "fetch", "prompt", "confirm", script)(
      { getElementById: (id: string) => byId[id] ?? null, createElement: make },
      async (url: string, init?: { body?: string }) => {
        // The CSRF hop the save path takes first. Answering it lets the POST under test happen.
        //
        // Matched by suffix, not by equality. These routes are moving under `/api/` in three steps
        // and this harness is not the place that decides which spelling is current — `manager-ui.
        // test.ts` scans the scripts and refuses a caller left on a top-level path that has an alias.
        // Pinning the literal here would make every step of that move break tests that are not about
        // it, and the equality check already did: the script moved to `/api/authz` and this returned
        // the commit stub for it, so `token()` read `.csrf` off a commit and came back empty.
        if (url.endsWith("/authz")) return { ok: true, json: async () => ({ csrf: "t" }) };
        posts.push({ url, body: JSON.parse(init?.body ?? "{}") as Record<string, string> });
        return { ok: true, json: async () => ({ branch: "edit-1", commit: "abcdef1234567" }) };
      },
      () => group,
      () => true,
    );
    return { byId, posts };
  };

  /** Click save and hand back the document the server would receive. */
  const saved = async (h: ReturnType<typeof boot>) => {
    fire(h.byId["rule-save"]!, "click");
    await new Promise((r) => setTimeout(r, 0));
    // Suffix again, for the reason given on the stub above.
    const post = h.posts.find((p) => p.url.endsWith("/policy/edit"));
    assert.ok(post, `save did not POST to policy/edit — it sent ${JSON.stringify(h.posts.map((p) => p.url))}`);
    return JSON.parse(post.body.content!) as ReturnType<typeof doc>;
  };

  const cells = (h: ReturnType<typeof boot>) => walk(h.byId["rule-rows"]!);
  const selectFor = (h: ReturnType<typeof boot>, option: string) =>
    cells(h).find((e) => e.tag === "select" && e.children.some((o) => o.value === option));

  it("draws exactly as many cells as it drew headings", () => {
    // Adding a field means touching two lists in two files, and this repository has lost a field in
    // the last column four times — three in aggregation, once in a renderer. A row one cell short
    // does not throw; it shifts every heading right of the gap onto the wrong data.
    const h = boot();
    const tr = h.byId["rule-rows"]!.children[0];
    assert.ok(tr, "no row was drawn");
    assert.equal(tr.children.length, RULE_COLUMNS.length,
      "the row and the heading row disagree — a column is showing the next column's data");
  });

  it("saves an edited note", async () => {
    const h = boot();
    const box = cells(h).find((e) => e.tag === "textarea");
    assert.ok(box, "no notes editor in the row — 76 of 77 rules carry the field this cannot write");
    assert.equal(box.value, NOTE, "the existing note did not reach the box");
    box.value = "a better reason";
    fire(box, "input");
    const out = await saved(h);
    assert.equal(out.groups.gwPolicies[0]!.notes, "a better reason");
  });

  it("can choose reject, and can take the deny mode away entirely", async () => {
    const h = boot();
    const deny = selectFor(h, "reject");
    assert.ok(deny, "no deny-mode control — every rule written here was a drop");
    deny.value = "reject";
    fire(deny, "change");
    assert.equal((await saved(h)).groups.gwPolicies[0]!.denyMode, "reject");

    // Absence is a value here: an allow rule has no deny mode, and '' is not one the schema takes.
    const h2 = boot();
    const off = selectFor(h2, "reject")!;
    off.value = "";
    fire(off, "change");
    assert.equal("denyMode" in (await saved(h2)).groups.gwPolicies[0]!, false,
      "an empty choice wrote a blank string instead of removing the field");
  });

  it("moves a rule to another group without losing why it exists", async () => {
    const h = boot();
    const group = selectFor(h, "gwPolicies");
    assert.ok(group, "the group column is not selectable — a rule cannot be moved");
    group.value = "k3sPolicies";
    fire(group, "change");
    const out = await saved(h);
    assert.equal(out.groups.gwPolicies.length, 0);
    assert.equal(out.groups.k3sPolicies.length, 1);
    // 🔑 The half that made the old workaround lossy. Delete-and-add could reach the same group.
    assert.equal(out.groups.k3sPolicies[0]!.notes, NOTE, "the move dropped the rule's reason");
  });

  it("gives a new rule the field, so it can be given a reason before it is saved", async () => {
    const h = boot("k3sPolicies");
    fire(h.byId["rule-add"]!, "click");
    const out = await saved(h);
    const added = out.groups.k3sPolicies[0];
    assert.ok(added, "add put the rule in no group");
    assert.equal("notes" in added, true, "a rule created here has nowhere to record why");
  });

  it("names the rules that reached the branch with no reason", async () => {
    const h = boot();
    const box = cells(h).find((e) => e.tag === "textarea")!;
    box.value = "";
    fire(box, "input");
    await saved(h);
    // Named rather than counted, and after the commit rather than instead of it — the branch's
    // reviewer is who can insist, and a save that refused would send the operator back to git.
    assert.match(h.byId["edit-result"]!.textContent, /No reason recorded for: A\./);
    assert.equal(h.byId["edit-result"]!.className, "bad");
  });

  it("still commits when every rule has one", async () => {
    // The negative control for the line above: a warning that is always there is one nobody reads.
    const h = boot();
    await saved(h);
    assert.doesNotMatch(h.byId["edit-result"]!.textContent, /No reason recorded/);
    assert.equal(h.byId["edit-result"]!.className, "dim");
  });
});
