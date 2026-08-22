// The workstation screens, rendered on the server.
//
// Four tables: **baseline**, **policies**, **workload**, **hosts**. Screens 9, 10, 10-b and the
// policy half of 4 in `GUI-테이블-설계.md`.
//
// ## What is deliberately absent
//
// The design document lists zones (3), address objects (5) and a service catalogue (6) before these.
// Measured 2026-08-07: `EndpointKind` has no zone, and this site references zero objects — every
// endpoint across all three VPCs is a literal `cidr` or `host`. Building them would have produced
// three empty tables and the impression the screens were done. `site-view.ts` records the counts.
//
// ## Why the default page has no script
//
// `manager-ui.ts` polls, because the fleet changes underneath it. A policy does not: it is a file,
// so the read-only page is built here and shipped as HTML.
//
// That is not only simpler, it is testable. The console's renderers had to be reached by executing
// its inline script inside a `new Function` harness, and the first version of those tests grepped
// the page source instead — which passes when the value is computed and thrown away. These functions
// are called directly.
//
// It also removes the CSP problem entirely. No script means no nonce, no `unsafe-inline`, and
// nothing an attacker could get executed by influencing a policy name.
//
// ## When it is editable
//
// The default stays read-only. When the caller explicitly supplies a managed JSON document, a small
// editor talks only to the loopback server that owns that document. The server validates through the
// same policy and render path; publishing still requires a separate proposal/approval operation.
//
// ## Why an empty table is omitted rather than drawn
//
// A table with a header and no rows reads as "this site has no baseline". That is a claim, and it is
// a different one from "not shown". Every table here disappears when it has nothing, so the page
// never asserts an absence it was not asked about.

import { policySummary } from "./policy-view.ts";
import type { PolicyRow, PolicyRisk } from "./policy-view.ts";
import type { BaselineRow, HostRow, WorkloadRow } from "./site-view.ts";
import type { HistoryRow } from "./history-view.ts";
import { TRUST_LABEL, type Crossing, type ZoneRow } from "./zones.ts";
import type { AddressSpaceRow, FeedRow, MembershipRow, ObjectRow } from "./catalog-view.ts";
import type { DeviceScreen, UserScreenRow } from "./device-view.ts";
import type { CoverageCell, CoverageRow, CoverageSummary } from "./coverage.ts";
import { LANG_NAME, LANGS, t, type Lang } from "./i18n.ts";

import { TOKENS_CSS, BASE_CSS } from "./design-tokens.ts";
import { GLYPH, ICON_CSS, icon, iconSprite } from "./icons.ts";
import { SHELL_CSS, appShell, langSwitch, type NavGroup, NAV_CSS } from "./app-shell.ts";

/** The other three tables. Optional so a caller can render the policy screen alone. */
export interface SiteSections {
  baseline?: readonly BaselineRow[];
  hosts?: readonly HostRow[];
  workload?: readonly WorkloadRow[];
  objects?: readonly ObjectRow[];
  services?: readonly ObjectRow[];
  feeds?: readonly FeedRow[];
  membership?: readonly MembershipRow[];
  addressSpace?: readonly AddressSpaceRow[];
  history?: readonly HistoryRow[];
  zones?: readonly ZoneRow[];
  crossings?: readonly Crossing[];
  coverage?: { rows: readonly CoverageRow[]; summary: CoverageSummary };
  devices?: DeviceScreen;
  users?: readonly UserScreenRow[];
}

/** What the page says about where it is looking. */
export interface PolicyPageMeta {
  /** Path of the site module, as the operator typed it. */
  site: string;
  /** Generation id, when the caller could compute one. */
  generation: string | null;
  /** Host ids in the site, for the header count. */
  hosts: readonly string[];
  /**
   * What the repository says its base branch is on, when the console could ask.
   *
   * Three states, and the third is the reason this is not a boolean. `fresh` means the checkout this
   * page was rendered from is the repository's head. `stale` means it is not, and names both shas so
   * the reader can see which way. `unknown` means the question could not be put — no credential, or
   * GitHub did not answer — and it says so rather than staying quiet, because "could not check" and
   * "checked, fine" look identical in silence and this banner exists because of a screen that was
   * confidently wrong for eleven hours.
   */
  freshness?:
    | { state: "fresh" }
    | { state: "stale"; rendered: string | null; repository: string }
    | { state: "unknown"; why: string };
  /**
   * The console's menu, already rendered, when a test (or a leftover caller) folds this
   * page into the classic shell.
   *
   * The manager no longer serves this document as `/policy` — GET 302s to `/app/policy`.
   * `heliopause-ui` still renders it when `packages/web/build` is missing, and that
   * workstation has no `/fleet` to link to, so it omits `nav`. Building the menu here
   * would put links to a console that is not running into a page rendered beside a laptop.
   */
  /**
   * The console's screens, for the top of the side nav.
   *
   * Data rather than markup, and **absent rather than empty** when this page is served from a
   * workstation: those routes do not exist there, and a group of links to screens the deployment
   * does not carry is worse than no group. `sideNav` drops a group with no items for that reason.
   */
  nav?: readonly NavGroup[];
  /** The loopback server has a managed policy document and exposes its edit API. */
  editable?: boolean;
  /** Manager and credentials were supplied, so this workstation can propose the rendered document. */
  proposable?: boolean;
  /**
   * The manager this page was joined against, when one was given.
   *
   * Rendered as the other half of the console. This page shows the policy; the manager shows what
   * the fleet reports about itself, and neither mentioned the other until they did — a reader who
   * found one had no way to learn the other existed.
   */
  manager?: string;
  /**
   * The build that evaluated the policy, and the build drawing this page.
   *
   * Only the manager sets it — a workstation render has no renderer to disagree with, and passing
   * itself here would print a comparison of a thing with itself.
   */
  renderer?: { build: string | null; mine: string };
  /**
   * The console may write. Carries the file to edit and a CSP nonce for the one script.
   *
   * Read-only pages keep having no script at all — that is what lets the rest of this file be
   * tested by calling functions instead of executing a harness, and what makes the page safe
   * without `unsafe-inline`. The editor is the exception and pays for itself with a nonce.
   */
  edit?: {
    path: string;
    content: string;
    nonce: string;
    /**
     * The other editable files, each getting a plain text box.
     *
     * The allowlist has held two files since the console learned to write, and only the first ever
     * reached the page — so `dev.ts`, which is where a device approval or a new zone is actually
     * written, was configured as editable and could not be edited from here. The write route
     * accepted it the whole time; nothing offered it.
     *
     * They are separate editors because they are separate kinds of document. `policies.json` is data
     * and gets the rule table; `dev.ts` is code with the reasoning in it and gets a text box — which
     * is the thing the rule table was built to stop being the *only* option, not a thing never to
     * offer. The alternative is the one we had: an operator opening a terminal to change a comment.
     */
    more?: readonly { path: string; content: string }[];
  };
  /** Which language to render. Defaults to English so an existing caller keeps its output. */
  lang?: Lang;
  /**
   * Which single section to show.
   *
   * Twelve tables stacked on one page is a page nobody reads to the end of. Showing one at a time
   * makes the index a real control rather than a list of anchors, and it is done on the server so
   * the read-only page keeps having no script at all.
   *
   * `"all"` renders everything, which is what the workstation command does by default — a checkout
   * is a place to scroll. Absent means the first section.
   */
  section?: string;
}

/**
 * Embed a value as a JavaScript literal inside `<script>`.
 *
 * `JSON.stringify` alone is not enough. The HTML parser looks for `</script` before the JavaScript
 * parser sees anything, so a `</script>` *inside a string literal* still ends the block and the
 * rest is parsed as markup — the document this page embeds is a policy file, and a policy name is
 * a place an attacker-influenced string can arrive. Escaping `<` as `\u003C` keeps the literal
 * meaning identical to JavaScript while making it invisible to the HTML parser.
 */
const jsLiteral = (v: unknown): string => JSON.stringify(v).replace(/</g, "\\u003C");

const esc = (s: unknown): string =>
  String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/** Human wording for a flag. Kept beside the slug so tests can assert on either. */
const RISK_TEXT: Record<PolicyRisk, string> = {
  "renders-nowhere": "renders nowhere",
  "any-source": "any source",
  "all-ports": "all ports",
  disabled: "disabled",
};

/**
 * The badge cell.
 *
 * `renders-nowhere` is the only one drawn as an error. The others describe a rule that is wide, and
 * wide is often correct — a public mail port is any-source by definition. Grading those as failures
 * is how a table stops being read, and then the one that means "this rule does nothing" goes with it.
 */
export function riskCell(row: PolicyRow, lang: Lang = "en"): string {
  if (!row.risks.length) return "";
  return `<div class="chips">` + row.risks
    .map((r) => {
      // 시안 G1 gives each finding its own shape as well as its own colour: `✕ renders-nowhere` on a
      // filled danger chip, `△ any-source` / `△ all-ports` on warn, `◇ disabled` on mute — and says
      // what the third one means beside it, 「의도적으로 꺼둔 것」. disabled is not a fault and must
      // not carry a fault's mark; a diamond is the shape this console uses for anything a person
      // declared on purpose, the same one the fleet table uses for maintenance.
      const [cls, glyph] = r === "renders-nowhere"
        ? (["bad", GLYPH.broken] as const)
        : r === "disabled"
          ? (["mute", GLYPH.declared] as const)
          : (["warn", GLYPH.warn] as const);
      const key = ({ "renders-nowhere": "r.rendersNowhere", "any-source": "r.anySource",
        "all-ports": "r.allPorts", disabled: "r.disabled" } as const)[r];
      return `<span class="chip ${cls}">${icon(glyph)}${esc(t(lang, key))}</span>`;
    })
    .join("") + `</div>`;
}

/**
 * Where a policy landed.
 *
 * Shows skips explicitly rather than only counting placements. "on 2 hosts" and "on 2, skipped on 3"
 * are different facts, and the second is how a policy that covers less than its author thought
 * looks — the count alone reads as success.
 */
export function placementCell(row: PolicyRow, lang: Lang = "en"): string {
  if (!row.placementKnown) {
    // Said, not implied. Without render results this column is "listed on", and a reader who takes
    // it for "renders on" has been told something nobody checked.
    const n = row.hosts.length + row.egressHosts.length;
    return `<span class="dim">${esc(t(lang, "p.listedOn", { n }))}</span>`;
  }
  const parts: string[] = [];
  if (row.hosts.length) parts.push(`${esc(row.hosts.join(", "))}`);
  if (row.egressHosts.length) parts.push(`<span class="dim">${esc(t(lang, "p.egress", { hosts: row.egressHosts.join(", ") }))}</span>`);
  if (!parts.length) parts.push(`<span class="bad">${esc(t(lang, "p.noHost"))}</span>`);
  if (row.skippedOn.length) {
    parts.push(`<span class="warn">${esc(t(lang, "p.skipped", { hosts: row.skippedOn.join(", ") }))}</span>`);
  }
  return parts.join("<br>");
}

/** Resolved sources, folded. Empty means the renderer matches any source. */
export function sourceCell(row: PolicyRow): string {
  if (!row.srcCidrs.length) return '<span class="warn">any</span>';
  const head = row.srcCidrs.slice(0, 2).map(esc).join(", ");
  const rest = row.srcCidrs.length - 2;
  return `<span class="mono">${head}</span>` + (rest > 0 ? ` <span class="dim">+${rest}</span>` : "");
}

/** One row. Separate so a test can read the cells back without parsing the whole page. */
export function policyRowHtml(row: PolicyRow, lang: Lang = "en"): string {
  // 시안 draws these as `■ deny` / `□ allow` — a filled square against an empty one. Those two are
  // the *same shape* and differ only by fill, which fails the design's own rule that the vocabulary
  // reads without colour (A9); so the pair became shield-with-a-cross and shield-with-a-tick, which
  // are two different outlines and stay two different outlines in a screenshot printed in grey.
  const action =
    row.action === "deny"
      ? `<span class="chip bad">${icon(GLYPH.deny)}${esc(t(lang, "v.deny"))}</span> <span class="dim">${esc(row.denyMode)}</span>`
      : `<span class="chip ok">${icon(GLYPH.allow)}${esc(t(lang, "v.allow"))}</span>`;
  return (
    "<tr>" +
    `<td class="dim">${esc(row.priority)}</td>` +
    `<td class="mono">${esc(row.id)}</td>` +
    `<td>${esc(row.name)}${row.notes ? `<div class="dim">${esc(row.notes)}</div>` : ""}</td>` +
    `<td>${action}</td>` +
    `<td class="dim">${esc(row.proto)}</td>` +
    `<td class="mono">${row.ports.trim() === "" ? '<span class="warn">all</span>' : esc(row.ports)}</td>` +
    `<td>${sourceCell(row)}</td>` +
    `<td>${placementCell(row, lang)}</td>` +
    `<td>${riskCell(row, lang)}</td>` +
    "</tr>"
  );
}

/** Declared once so the header and the row cannot drift apart. */
export const POLICY_COLUMNS = ["c.pri","c.id","c.name","c.action","c.proto","c.ports","c.source","c.rendersOn","c.risk"];


/** Declared once each, for the same reason as `POLICY_COLUMNS`. */
export const BASELINE_COLUMNS = ["c.what","c.proto","c.ports","c.source"];
export const HOST_COLUMNS = ["c.host","c.stage","c.input","c.egress","c.skipped",""];
/** Added only when a manager answered. The screen is split across two surfaces (결정 10). */
export const HOST_FLEET_COLUMNS = ["c.state","c.generation","c.age"];
export const WORKLOAD_COLUMNS = ["c.id","c.name","c.action","c.source","c.destination","c.proto","c.ports"];

/**
 * The baseline table.
 *
 * Rendered above the policies, because it is the layer policy cannot override. A reader who scans
 * the policy table alone has seen every rule an operator wrote and none of these — which for
 * management SSH is the difference between "how do I get in" and "nothing lets me in".
 */
export function baselineTable(rows: readonly BaselineRow[], lang: Lang = "en"): string {
  if (!rows.length) return "";
  return section("baseline", t(lang, "s.baseline.heading"), BASELINE_COLUMNS,
    rows.map((r) =>
      "<tr>" +
      `<td>${esc(r.desc)}</td>` +
      `<td class="dim">${esc(r.proto)}</td>` +
      `<td class="mono">${r.ports.trim() === "" ? '<span class="dim">all</span>' : esc(r.ports)}</td>` +
      // Neutral, not a warning. ICMP unrestricted is deliberate — a host that cannot be pinged is
      // harder to debug — and colouring it red would teach a reader to ignore the column.
      `<td>${r.anySource ? '<span class="dim">any</span>' : `<span class="mono">${esc(r.srcCidrs.join(", "))}</span>`}</td>` +
      "</tr>").join(""), lang);
}

/**
 * The hosts table.
 *
 * Two halves from two surfaces. The policy half always renders; the fleet half appears only when a
 * manager answered, and then it appears for **every** row — including rows that manager did not know
 * about, which show an explicit dash rather than blank. Blank would be indistinguishable from "this
 * host reported nothing", and that is the reading that sends somebody to check an agent that is fine.
 */
export function hostTable(rows: readonly HostRow[], lang: Lang = "en"): string {
  if (!rows.length) return "";
  const known = rows[0]!.placementKnown;
  const joined = rows.some((r) => r.fleet !== undefined);
  const note = known ? "" : ` <span class="warn">&middot; ${esc(t(lang, "p.listedCounts"))}</span>`;
  const columns = joined ? [...HOST_COLUMNS, ...HOST_FLEET_COLUMNS] : HOST_COLUMNS;
  return section("hosts", "hosts" + note, columns,
    rows.map((r) =>
      "<tr>" +
      `<td>${esc(r.id)}</td>` +
      `<td class="dim">${esc(r.stage)}</td>` +
      `<td class="dim">${esc(r.inputCount)}</td>` +
      `<td class="dim">${r.egressCount ? esc(r.egressCount) : "&mdash;"}</td>` +
      `<td>${r.skipped.length ? `<span class="warn">${esc(r.skipped.join(", "))}</span>` : ""}</td>` +
      // `protectedHosts` is what stops a generation from locking the relay out of its own VPC.
      `<td>${r.protected ? `<span class="ok">${esc(t(lang, "p.lockout"))}</span>` : ""}</td>` +
      (joined ? fleetCells(r.fleet) : "") +
      "</tr>").join(""), lang);
}

/** The three fleet cells. `undefined` is "this manager does not know this host", not "no report". */
function fleetCells(f: HostRow["fleet"]): string {
  if (!f) {
    return '<td class="dim">not aggregated here</td><td class="dim">&mdash;</td><td class="dim">&mdash;</td>';
  }
  const word = f.drifted
    ? '<span class="bad">DRIFT</span>'
    : f.state === null
      ? '<span class="bad">never seen</span>'
      : f.state === "confirmed"
        ? '<span class="ok">confirmed</span>'
        : `<span class="warn">${esc(f.state)}</span>`;
  // `blockedBy` under the state word, same as the console. It is the only field that says why a
  // rollout stopped, and it is empty on every good day.
  const why = f.blockedBy ? `<div class="dim">blocked: ${esc(f.blockedBy)}</div>` : "";
  // Not current means the manager wants this host on a different generation. Mid-rollout that is
  // normal; an hour later it is a stall, and the page cannot tell which — so it marks, not judges.
  const genCls = f.current ? "dim" : "warn";
  const gen = `<td class="${genCls}">${esc(f.generation ?? "—")}${f.current ? "" : " &larr; wanted elsewhere"}</td>`;
  return `<td>${word}${why}</td>${gen}<td class="dim">${f.ageSec === null ? "&mdash;" : `${esc(f.ageSec)}s`}</td>`;
}

/** The Cilium half. No placement column — a CiliumNetworkPolicy is not addressed to a host. */
export function workloadTable(rows: readonly WorkloadRow[], lang: Lang = "en"): string {
  if (!rows.length) return "";
  return section("workload", t(lang, "s.workload.heading"), WORKLOAD_COLUMNS,
    rows.map((r) =>
      "<tr>" +
      `<td class="mono">${esc(r.id)}</td>` +
      `<td>${esc(r.name)}${r.notes ? `<div class="dim">${esc(r.notes)}</div>` : ""}${r.enabled ? "" : ' <span class="dim">(disabled)</span>'}</td>` +
      `<td>${r.action === "deny" ? `<span class="bad">${esc(t(lang, "v.deny"))}</span>` : `<span class="ok">${esc(t(lang, "v.allow"))}</span>`}</td>` +
      `<td class="mono">${esc(r.src)}</td>` +
      `<td class="mono">${esc(r.dst)}</td>` +
      `<td class="dim">${esc(r.proto)}</td>` +
      `<td class="mono">${r.ports.trim() === "" ? '<span class="dim">all</span>' : esc(r.ports)}</td>` +
      "</tr>").join(""), lang);
}


export const ZONE_COLUMNS = ["c.zone","c.trust","c.ranges","c.asSource","c.asDestination","c.admits","c.notes"];
export const CROSSING_COLUMNS = ["c.gain","c.from","c.to","c.action","c.policy"];

export const COVERAGE_COLUMNS = ["c.id","c.check","c.expect","IPv4","IPv6","c.lastMeasured","c.observedFrom"];

export const DEVICE_COLUMNS = ["c.device","c.user","c.meshV4","c.meshV6","c.zone","c.vsCloudflare","c.notes"];
export const USER_COLUMNS = ["c.user","c.devices","c.zones","c.addresses"];

export const OBJECT_COLUMNS = ["c.id","c.name","c.members","c.usedBy"];
export const FEED_COLUMNS = ["c.feed","c.usedBy"];
export const MEMBERSHIP_COLUMNS = ["c.kind","c.name","c.pods","c.usedBy","c.readAt","c.reportedBy"];
export const ADDRESS_COLUMNS = ["c.cidr","c.asSource","c.asDestination"];
export const HISTORY_COLUMNS = ["c.commit","c.status","c.subject","c.author","c.when"];

/** Address objects and service objects share a shape, so they share a renderer. */
/**
 * The zones, and how much policy points at each.
 *
 * A zone nothing references stays in the table: a range someone named and no rule uses is a finding,
 * and dropping the row is how it stays invisible. That is the same reason `objectTable` keeps an
 * unused object.
 */
export function zoneTable(rows: readonly ZoneRow[], lang: Lang = "en"): string {
  if (!rows.length) return "";
  return section("zones", t(lang, "s.zones.heading"), ZONE_COLUMNS,
    rows.map((r) => {
      const unused = r.asSource === 0 && r.asDestination === 0;
      return "<tr>" +
        `<td class="mono">${esc(r.zone.id)}</td>` +
        // The word, not the number. A bare 2 invites someone to read it as a score out of ten.
        `<td>${esc(t(lang, `trust.${r.zone.trust}` as Parameters<typeof t>[1]))} <span class="dim">${r.zone.trust}</span></td>` +
        `<td class="mono">${esc(r.zone.cidrs.join(", "))}</td>` +
        `<td>${unused ? '<span class="warn">0</span>' : r.asSource}</td>` +
        `<td>${unused ? '<span class="warn">0</span>' : r.asDestination}</td>` +
        // Zero admits is the ordinary case and gets no colour; a count is a pointer into the table
        // below rather than a verdict.
        `<td>${r.admits ? `<span class="dim">${r.admits}</span>` : ""}</td>` +
        `<td class="dim">${esc(r.zone.notes ?? "")}</td>` +
        "</tr>";
    }).join(""), lang);
}

/**
 * Policies that admit a less trusted zone into a more trusted one.
 *
 * **Not a fault list, and the heading says so.** Letting the internet reach a mail server on 25 is
 * this table's largest row and is exactly right. What it replaces is the review an operator would
 * otherwise do by reading every rule and holding the trust ordering in their head.
 *
 * Empty is a real answer here, unlike the tables above — a policy set with no inward crossing is
 * possible and worth stating rather than rendering nothing.
 */
export function crossingTable(rows: readonly Crossing[], lang: Lang = "en"): string {
  if (!rows.length) {
    return section("crossings", t(lang, "s.crossings.headingPlain"), CROSSING_COLUMNS,
      '<tr><td colspan="5" class="dim">no policy admits a less trusted zone &mdash; ' +
      "either the ordering is never crossed, or no endpoint resolved into a zone</td></tr>");
  }
  return section("crossings", t(lang, "s.crossings.heading"), CROSSING_COLUMNS,
    rows.map((r) =>
      "<tr>" +
      // Larger gain is a longer reach across the ordering. Two levels from the internet is a
      // different kind of row from one level between neighbours, and the number says which.
      `<td class="${r.gain >= 3 ? "bad" : r.gain >= 2 ? "warn" : "dim"}">+${r.gain}</td>` +
      `<td class="mono">${esc(r.from.id)} <span class="dim">${esc(t(lang, `trust.${r.from.trust}` as Parameters<typeof t>[1]))}</span></td>` +
      `<td class="mono">${esc(r.to.id)} <span class="dim">${esc(t(lang, `trust.${r.to.trust}` as Parameters<typeof t>[1]))}</span></td>` +
      // A deny crossing inward is usually the opposite of a concern, so it is marked rather than
      // hidden — a table calling itself crossings that showed only allows would be lying by name.
      `<td>${r.action === "deny" ? '<span class="dim">deny</span>' : "allow"}</td>` +
      `<td class="mono">${esc(r.policyId)}<div class="dim">${esc(r.policyName)}</div></td>` +
      "</tr>").join(""), lang);
}

/** One verdict cell. The age sits with it — a verdict without its instant reads as current. */
function coverageCell(c: CoverageCell, lang: Lang): string {
  // 시안 G2 draws all four verdicts and then the thing this cell exists for: a row that is `✓ pass`
  // **and** `△ stale` at the same time, with the note 「pass인데 낡았다 — 실재하는 조합이다」. So the
  // verdict and the staleness are two chips, never one merged word — a single green cell would say
  // "passing now" about a measurement three hours old.
  const label: Record<CoverageCell["verdict"], string> = {
    pass: `<span class="chip ok">${icon(GLYPH.confirmed)}pass</span>`,
    fail: `<span class="chip bad">${icon(GLYPH.broken)}fail</span>`,
    // Hatched and question-marked, not grey. An unmeasured cell is a hole in the only independent
    // reading in the system, and grey is the colour a reader skips. 시안 G2: 「물어볼 수 없었다 ≠
    // 물어봤고 괜찮다」.
    unknown: `<span class="chip none hatch">${icon(GLYPH.unexplained)}not measured</span>`,
    "n/a": '<span class="chip mute">n/a</span>',
  };
  const stale = c.stale ? ` <span class="chip warn hatch">${icon(GLYPH.warn)}stale</span>` : "";
  return `${label[c.verdict]}${stale}<div class="dim">${esc(t(lang, c.reasonKey as Parameters<typeof t>[1]))}</div>`;
}

/**
 * Coverage verification.
 *
 * **This is the only table on any screen not built from what the fleet said about itself**, which
 * is why the design puts it first in the compromise summary. Everything else would go along with a
 * compromised agent; this would not.
 *
 * The two families get their own columns and never share one. Folding them is how an unverified
 * IPv6 hides behind a passing IPv4 — this deployment's default failure — and the fold is invisible
 * afterwards because the merged cell is green either way.
 */
export function coverageTable(rows: readonly CoverageRow[], summary: CoverageSummary, lang: Lang = "en"): string {
  if (!rows.length) return "";

  // Failures and gaps are counted apart. "three failed" and "three never ran" call for different
  // actions, and one combined number is an instrument that says neither.
  const banner =
    `<div class="dim">` +
    (summary.lastRun ? `last measured ${esc(summary.lastRun)}` : '<span class="warn">never measured</span>') +
    ` &middot; <span class="${summary.failing ? "bad" : "ok"}">${summary.failing} failing</span>` +
    ` &middot; <span class="${summary.unknown ? "warn" : "dim"}">${summary.unknown} not measured</span>` +
    ` &middot; ${summary.passing} passing` +
    (summary.observedFrom.length ? ` &middot; from ${esc(summary.observedFrom.join(", "))}` : "") +
    `</div>`;

  const body = rows.map((r) => {
    const newest = [r.v4.at, r.v6.at].filter(Boolean).sort().at(-1);
    const from = [r.v4.observedFrom, r.v6.observedFrom].filter(Boolean);
    return "<tr>" +
      `<td class="mono">${esc(r.check.id)}</td>` +
      `<td>${esc(r.check.title)}<div class="dim">${esc(r.targets.join(", "))}</div>` +
      `${r.check.notes ? `<div class="dim">${esc(r.check.notes)}</div>` : ""}</td>` +
      `<td class="dim">${esc(r.check.expect === "blocked" ? t(lang, "cov.mustBeBlocked") : t(lang, "cov.mustReach"))}</td>` +
      `<td>${coverageCell(r.v4, lang)}</td>` +
      `<td>${coverageCell(r.v6, lang)}</td>` +
      `<td class="dim mono">${esc(newest ?? "—")}</td>` +
      // Where it was measured, because two vantage points give wrong answers here and the reader
      // needs to be able to disbelieve a row by its origin.
      `<td class="dim">${from.length ? esc([...new Set(from)].join(", ")) : "—"}</td>` +
      "</tr>";
  }).join("");

  const warning =
    '<tr><td colspan="7" class="warn">Do not run this from a Vultr instance &mdash; outbound 25 is ' +
    "blocked there, so mail-port checks come back &ldquo;blocked&rdquo; without anything having been " +
    "measured. Nor from the operator workstation, which leaves over Cloudflare WARP.</td></tr>";

  return section(
    "coverage",
    t(lang, "s.coverage.heading") + banner,
    COVERAGE_COLUMNS,
    body + warning,
    lang,
  );
}


/** Columns the rule editor exposes. Everything `normalizePolicy` validates, nothing it does not. */
export const RULE_COLUMNS = ["c.group","c.id","c.name","c.source","c.destination","c.proto","c.ports","c.action","c.deny","c.pri","c.on","c.notes",""];

/**
 * The rule table — add a row, edit a row, delete a row.
 *
 * **This is the editor, and the text one it replaced was a mistake.** Editing a firewall through a
 * TypeScript file in a textarea asks an operator to be careful about syntax in order to change a
 * port number, and syntax is not the thing they are trying to get right.
 *
 * The rows come from `policies.json`, which holds the data and nothing else — the reasoning stayed
 * behind in `dev.ts` as prose, where it is read, rather than being squeezed into a field. Saving
 * writes that one file to a branch; it does not touch `main` and it does not publish.
 */
export function ruleTable(edit: NonNullable<PolicyPageMeta["edit"]>, lang: Lang = "en"): string {
  // `rule.help` names the file inside the sentence, and the sentence is translated. Substituting a
  // `<code>` element through `t` would put markup somewhere `esc` has to run, so the placeholder is
  // filled with a character that cannot occur in the catalogue and the halves are escaped either
  // side of it. Escaping the whole rendered string instead would print the tags.
  const [helpBefore = "", helpAfter = ""] = t(lang, "rule.help", { path: "\u0000" }).split("\u0000");
  return `<section id="rules"><h2>${esc(t(lang, "rule.heading"))}</h2>
  <div class="scroll"><table id="rule-table"><thead><tr>${
    // One of these is deliberately empty — the delete column has no heading. `t` on an empty key
    // would return the key, which is how `c.id` reached the page in the first place.
    //
    // The group column used to be the other one, because it was read-only text and a heading over a
    // column nobody can change is noise. It is a select now, so it is named.
    RULE_COLUMNS.map((c) => `<th>${c ? esc(t(lang, c as Parameters<typeof t>[1])) : ""}</th>`).join("")
  }</tr></thead><tbody id="rule-rows"></tbody></table></div>
  <div class="editrow">
    <button type="button" id="rule-add">${esc(t(lang, "rule.add"))}</button>
    <button type="button" id="rule-save">${esc(t(lang, "rule.save"))}</button>
    <button type="button" id="rule-propose">${esc(t(lang, "rule.propose"))}</button>
    <span id="rule-dirty" class="warn"></span>
  </div>
  <div id="edit-result" class="dim">${esc(helpBefore)}<code>${esc(edit.path)}</code>${esc(helpAfter)}</div>
  </section>`;
}

/**
 * The other editable files, as text.
 *
 * **This exists because a configured capability was not offered.** `HELIOPAUSE_POLICY_EDITABLE` has
 * named two files since the console learned to write, the write route has always accepted either,
 * and the page only ever carried the first — so `dev.ts` was editable everywhere except the one
 * place an operator would look. That shape has cost this project seven findings; the cure is to
 * render what the configuration says, not what the first element of it says.
 *
 * A text box and not a second structured editor: `dev.ts` is prose and code together, and the value
 * of the structure is in the reasoning, which no table has a column for.
 */
export function fileEditors(
  more: readonly { path: string; content: string }[],
  lang: Lang = "en",
): string {
  if (!more.length) return "";
  return `<section id="files"><h2>${esc(t(lang, "file.heading"))}</h2>
  <p class="dim">${esc(t(lang, "file.help"))}</p>
  ${more
    .map(
      (f, i) => `<div class="filebox">
    <label for="file-${i}"><code>${esc(f.path)}</code></label>
    <textarea id="file-${i}" data-file="${esc(f.path)}" spellcheck="false" rows="18"></textarea>
    <div class="editrow">
      <button type="button" data-save-file="${esc(f.path)}">${esc(t(lang, "file.save"))}</button>
      <span data-dirty-file="${esc(f.path)}" class="warn"></span>
    </div>
  </div>`,
    )
    .join("")}
  <div id="file-result" class="dim"></div>
  </section>`;
}

/**
 * The approved device registry, and how it compares to Cloudflare.
 *
 * **The heading changes with whether a comparison happened.** A page that renders the approved list
 * and shows no differences is making two very different claims depending on whether it reached
 * Cloudflare at all, and only one of them is "these are correct". Cloudflare assigns these
 * addresses, so an uncompared render is a snapshot of an intention, not of the network.
 */
export function deviceTable(screen: DeviceScreen, lang: Lang = "en"): string {
  if (!screen.rows.length && !screen.unapproved.length) return "";
  const drift = screen.rows.filter((r) => r.state === "moved" || r.state === "gone").length;
  const heading = !screen.compared
    ? "devices &mdash; approved registry, <span class=\"warn\">not compared against Cloudflare in this render</span>"
    : drift || screen.unapproved.length
      ? `devices &mdash; <span class="bad">${drift + screen.unapproved.length} differ from Cloudflare</span>, read ${esc(screen.readAt ?? "")}`
      : `devices &mdash; matched Cloudflare at ${esc(screen.readAt ?? "")}`;

  const body = screen.rows.map((r) => {
    // A device whose address moved is the failure this screen exists for: the rule still names the
    // old address, which now belongs to nobody or to someone else.
    //
    // 시안 G2 gives these four the fleet table's vocabulary rather than a set of their own: `✓ ok`,
    // `→ moved`, `✕ gone`, and `◇ unchecked` on a hatch with the note 「실측을 안 했다. **ok가
    // 아니다.**」 — unchecked is a thing nobody measured, which is the hatch's whole meaning
    // everywhere else on these screens.
    const cell =
      r.state === "moved"
        ? `<span class="chip warn">${icon(GLYPH.waiting)}${esc(t(lang, "d.moved"))}</span><div class="dim mono">${esc(t(lang, "d.movedNow", { addr: r.liveV4 ?? "" }))}</div>`
        : r.state === "gone"
          ? `<span class="chip bad">${icon(GLYPH.broken)}${esc(t(lang, "d.gone"))}</span>`
          : r.state === "ok"
            ? `<span class="chip ok">${icon(GLYPH.confirmed)}${esc(t(lang, "d.matches"))}</span>`
            : `<span class="chip none hatch">${icon(GLYPH.declared)}${esc(t(lang, "d.unchecked"))}</span>`;
    return "<tr>" +
      `<td>${esc(r.deviceName)}</td>` +
      `<td class="dim">${esc(r.userEmail)}</td>` +
      `<td class="mono">${esc(r.v4)}</td>` +
      `<td class="mono">${esc(r.v6)}</td>` +
      // No zone means no stated trust for an address policy hands out access on. That is a finding,
      // not a blank.
      `<td>${r.zone ? `${esc(r.zone.id)} <span class="dim">${esc(t(lang, `trust.${r.zone.trust}` as Parameters<typeof t>[1]))}</span>` : `<span class="warn">${esc(t(lang, "d.noZone"))}</span>`}</td>` +
      `<td>${cell}</td>` +
      `<td class="dim">${esc(r.notes)}</td>` +
      "</tr>";
  }).join("");

  // Devices Cloudflare knows and policy has never approved. Listed rather than counted: the whole
  // point of the approval step is that a human reads which device appeared.
  const extra = screen.unapproved.map((c) =>
    "<tr>" +
    `<td>${esc(c.deviceName)}</td>` +
    `<td class="dim">${esc(c.userEmail)}</td>` +
    `<td class="mono">${esc(c.after?.v4 ?? "")}</td>` +
    `<td class="mono">${esc(c.after?.v6 ?? "")}</td>` +
    "<td></td>" +
    '<td><span class="warn">not approved</span></td>' +
    '<td class="dim">registered with Cloudflare, absent from the site module</td>' +
    "</tr>").join("");

  const foot = screen.addressless
    ? `<tr><td colspan="7" class="dim">${screen.addressless} registration(s) carry no mesh address and are excluded from policy</td></tr>`
    : "";
  return section("devices", heading, DEVICE_COLUMNS, body + extra + foot, lang);
}

/** Users and the devices registered to them &mdash; what a `cf-user` endpoint expands to. */
export function userTable(rows: readonly UserScreenRow[], lang: Lang = "en"): string {
  if (!rows.length) return "";
  return section("users", t(lang, "s.users.heading"), USER_COLUMNS,
    rows.map((r) =>
      "<tr>" +
      `<td>${esc(r.email)}</td>` +
      `<td>${r.devices}</td>` +
      // A user whose devices straddle zones is the case where naming the user is doing more than
      // whoever wrote the rule expected.
      `<td>${r.zones.length > 1 ? `<span class="warn">${esc(r.zones.join(", "))}</span>` : `<span class="dim">${esc(r.zones.join(", "))}</span>`}</td>` +
      `<td class="mono">${esc(r.v4.join(", "))}</td>` +
      "</tr>").join(""), lang);
}

export function objectTable(heading: string, rows: readonly ObjectRow[], lang: Lang = "en"): string {
  if (!rows.length) return "";
  return section(heading.includes("service") ? "services" : "objects", heading, OBJECT_COLUMNS,
    rows.map((r) =>
      "<tr>" +
      `<td class="mono">${esc(r.id)}</td>` +
      `<td>${esc(r.name)}${r.notes ? `<div class="dim">${esc(r.notes)}</div>` : ""}</td>` +
      `<td class="mono">${esc(r.members.join(", "))}</td>` +
      // Nothing referencing an object is the finding this table exists for: dead configuration that
      // still reads as protection to whoever scans the catalogue.
      `<td>${r.usedBy.length ? `<span class="dim">${esc(r.usedBy.join(", "))}</span>` : '<span class="warn">unused</span>'}</td>` +
      "</tr>").join(""), lang);
}

export function feedTable(rows: readonly FeedRow[], lang: Lang = "en"): string {
  if (!rows.length) return "";
  return section("feeds", t(lang, "s.feeds.heading"), FEED_COLUMNS,
    rows.map((r) =>
      `<tr><td class="mono">${esc(r.ref)}</td>` +
      `<td class="dim">${esc(r.usedBy.join(", "))}</td></tr>`).join(""), lang);
}

/**
 * Pod membership.
 *
 * The read time sits in its own column rather than a footnote. A count of zero in a CI namespace
 * means "no job right now", not "safe" — the pods appear the moment one starts — and a number
 * without the instant it was true is one an operator reads as current.
 */
export function membershipTable(rows: readonly MembershipRow[], lang: Lang = "en"): string {
  if (!rows.length) return "";
  return section("membership", t(lang, "s.membership.heading"), MEMBERSHIP_COLUMNS,
    rows.map((r) =>
      "<tr>" +
      `<td class="dim">${esc(r.kind)}</td>` +
      `<td class="mono">${esc(r.name)}</td>` +
      `<td>${r.members.length ? `${r.members.length} <span class="dim">${esc(r.members.slice(0, 2).join(", "))}${r.members.length > 2 ? ` +${r.members.length - 2}` : ""}</span>` : '<span class="dim">0 &mdash; none right now</span>'}</td>` +
      // An empty count beside the rules that depend on it. Zero pods is normal between CI jobs, so
      // this is deliberately not a warning — it is the pairing an operator needs to tell "idle" from
      // "this rule governs nothing", which the count alone cannot say.
      `<td class="mono">${r.usedBy.length ? esc(r.usedBy.join(", ")) : '<span class="dim">&mdash;</span>'}</td>` +
      `<td class="dim">${esc(r.at)}</td>` +
      `<td class="dim">${esc(r.host)}</td>` +
      "</tr>").join(""), lang);
}

/** The address space the rules touch. Derived — see `catalog-view.ts`. */
export function addressSpaceTable(rows: readonly AddressSpaceRow[], lang: Lang = "en"): string {
  if (!rows.length) return "";
  return section("address-space", t(lang, "s.addressSpace.heading"), ADDRESS_COLUMNS,
    rows.map((r) =>
      "<tr>" +
      `<td class="mono">${esc(r.cidr)}</td>` +
      `<td class="dim">${r.asSource ? esc(r.asSource) : "&mdash;"}</td>` +
      `<td class="dim">${r.asHost.length ? esc(r.asHost.join(", ")) : "&mdash;"}</td>` +
      "</tr>").join(""), lang);
}

/**
 * Publication history.
 *
 * `superseded` is deliberately weak — it means "older than something live", not "was published".
 * Neither the manager nor the relay keeps a record of what shipped, so a stronger word here would be
 * a claim nothing checks.
 */
export function historyTable(rows: readonly HistoryRow[], lang: Lang = "en"): string {
  if (!rows.length) return "";
  return section("history", t(lang, "s.history.heading"), HISTORY_COLUMNS,
    rows.map((r) => {
      const status = r.status === "live"
        ? `<span class="ok">live</span> <span class="dim">${esc(r.liveOn.join(", "))}</span>`
        : r.status === "superseded"
          ? '<span class="dim">superseded</span>'
          // `unknown` is not a milder "not published" — it is the absence of a manager. Rendering the
          // two the same would let a page with no fleet data read as a page reporting on the fleet.
          : r.status === "unknown"
            ? `<span class="dim">${esc(t(lang, "h.noManagerAsked"))}</span>`
            : '<span class="warn">not published</span>';
      return "<tr>" +
        `<td class="mono">${esc(r.commit.id)}</td>` +
        `<td>${status}</td>` +
        `<td>${esc(r.commit.subject)}</td>` +
        `<td class="dim">${esc(r.commit.author)}</td>` +
        `<td class="dim">${esc(r.commit.at)}</td>` +
        "</tr>";
    }).join(""), lang);
}

/**
 * One table, with the anchor the index links to.
 *
 * The `id` is passed in rather than derived from the heading: headings carry markup, em dashes and
 * live counts, so a slug made from one would change the moment a number in it changed — and every
 * link to it would break silently.
 */
function section(id: string, heading: string, columns: readonly string[], body: string, lang: Lang = "en"): string {
  // Column labels arrive as message keys. Anything that is not a key renders as written — `IPv4`
  // and `IPv6` are the same word in both languages and a catalogue entry for them would be a place
  // to make a mistake without buying anything.
  const label = (c: string) =>
    c.startsWith("c.") ? t(lang, c as Parameters<typeof t>[1]) : c;
  return `<section id="${id}"><h2>${heading}</h2><div class="scroll"><table><thead><tr>${
    columns.map((c) => `<th>${esc(label(c))}</th>`).join("")
  }</tr></thead><tbody>${body}</tbody></table></div></section>`;
}

/** The whole page. */
/**
 * The line that tells the reader whether this page is showing the repository or a memory of it.
 *
 * Drawn for all three states including the good one. A banner that appears only on trouble teaches
 * the reader that its absence means nothing was checked — which was true here until 2026-08-16, and
 * is why the screen could be eleven hours behind without anybody noticing. A quiet confirmation on
 * every load is what makes the loud one legible.
 */
export function freshnessBanner(
  f:
    | { state: "fresh" }
    | { state: "stale"; rendered: string | null; repository: string }
    | { state: "unknown"; why: string }
    | undefined,
  lang: Lang = "en",
): string {
  if (!f) return "";
  if (f.state === "fresh") {
    return `<div class="fresh banner ok"><span class="lead">${icon(GLYPH.confirmed)}${esc(t(lang, "p.leadFresh"))}</span>` +
      `${esc(t(lang, "p.freshOk"))}</div>`;
  }
  if (f.state === "unknown") {
    // Deliberately not styled as an error. Nothing is known to be wrong; what is known is that the
    // usual check did not run, and the reader should weigh what is below accordingly.
    //
    // 시안 G4 puts this one on a hatch and a dashed border rather than on a colour, and says why:
    // 「이 화면이 11시간 동안 확신에 차서 틀린 값을 보여준 적이 있어서, unknown은 fresh처럼 보이지
    // 않고 조용히 넘어가지도 않는다」. The hatch is the same mark the fleet table uses for a value
    // nobody measured, which is exactly what this is.
    return `<div class="fresh banner hatch"><span class="lead">${icon(GLYPH.unexplained)}${esc(t(lang, "p.leadUnknown"))}</span>` +
      `${esc(t(lang, "p.freshUnknown", { why: f.why }))}</div>`;
  }
  const rendered = f.rendered ?? "an unnamed checkout";
  // **시안 G4 draws stale in warn; this stays in danger.** The legend there is a swatch of the three
  // states, and it was drawn without the one fact that decided this colour: this screen was eleven
  // hours behind the repository, said nothing, and was believed. Quieting it on the strength of a
  // legend would undo that fix. The icon and the word are the design's; only the tone is not.
  return `<div class="fresh banner bad"><span class="lead">${icon(GLYPH.warn)}${esc(t(lang, "p.leadStale"))}</span>` +
    `<span><strong>${esc(t(lang, "p.freshStaleLead"))}</strong> ` +
    `${esc(t(lang, "p.freshStaleFrom"))} <code>${esc(rendered)}</code>` +
    `${esc(t(lang, "p.freshStaleRepo"))} <code>${esc(f.repository.slice(0, 7))}</code>` +
    `${esc(t(lang, "p.freshStaleLag"))}</span></div>`;
}

/**
 * Whether the process that evaluated the policy is the same build as the one drawing this page.
 *
 * ## Why this is on the screen and not only in a log
 *
 * The two are separate Deployments and nothing keeps them in step: the pipeline rewrites one
 * manifest per component directory, and the renderer's manifest is a second file inside the
 * manager's, so it is simply never named. Measured 2026-08-18 — manager `3e1c248`, renderer eleven
 * commits behind. Everything looked healthy, because everything below this line was.
 *
 * Silent when they agree. A banner that is always there is one nobody reads, which is the same
 * argument `freshnessBanner` makes about itself.
 *
 * `null` is not "fine". A renderer too old to name itself is at least as old as the change that
 * taught it to, and saying so is the difference between a fact and an absence.
 */
export function rendererBanner(
  r: { build: string | null; mine: string } | undefined,
  lang: Lang = "en",
): string {
  if (!r) return "";
  if (r.build === r.mine) return "";
  // Drawn as the same banner `freshnessBanner` draws, because it answers the same question one
  // layer further out — "is what I am reading current" — and two shapes for one question is how a
  // reader learns that only the loud one counts.
  if (r.build === null) {
    return `<div class="fresh banner warn"><span class="lead">${icon(GLYPH.warn)}${esc(t(lang, "p.leadRenderer"))}</span>` +
      `<span>${esc(t(lang, "p.rendererUnnamed", { mine: r.mine }))}</span></div>`;
  }
  return `<div class="fresh banner warn"><span class="lead">${icon(GLYPH.warn)}${esc(t(lang, "p.leadRenderer"))}</span>` +
    `<span>${esc(t(lang, "p.rendererDiff", { build: r.build, mine: r.mine }))}</span></div>`;
}

export function policyPage(
  rows: readonly PolicyRow[],
  meta: PolicyPageMeta,
  extra: SiteSections = {},
): string {
  // Counted in `policy-view.ts`, not here. That module's comment says why — "derived here so the
  // page cannot compute them differently" — and the page was computing them here anyway, which is
  // how one number in a header starts disagreeing with the table under it.
  const counts = policySummary(rows);
  const known = rows.length === 0 || rows[0]!.placementKnown;

  const lang = meta.lang ?? "en";
  // Every section, with the label the index shows. Built as a list rather than concatenated inline
  // so the index can be derived from what actually rendered — a link to a section that emitted
  // nothing would be a promise the page does not keep, and empty tables are omitted on purpose.
  const built = [
    ...(meta.edit ? [{ id: "rules", label: t(lang,"s.rules"), count: undefined, html: ruleTable(meta.edit, lang) }] : []),
    // Only when there is a second file. The index is built from what rendered, so an empty section
    // here would put a link in the index that lands on nothing.
    ...(meta.edit?.more?.length
      ? [{ id: "files", label: t(lang,"s.files"), count: meta.edit.more.length, html: fileEditors(meta.edit.more, lang) }]
      : []),
    { id: "baseline", label: t(lang,"s.baseline"), count: extra.baseline?.length, html: baselineTable(extra.baseline ?? [], lang) },
    {
      id: "policies",
      label: t(lang,"s.policies"),
      count: rows.length,
      // Built through `section` like the rest. Hand-rolling it here is how its column headers ended
      // up rendering as raw message keys while every other table was translated.
      html: section("policies", t(lang, "s.policies"), POLICY_COLUMNS,
        rows.map((r) => policyRowHtml(r, lang)).join(""), lang),
    },
    { id: "zones", label: t(lang,"s.zones"), count: extra.zones?.length, html: zoneTable(extra.zones ?? [], lang) },
    { id: "crossings", label: t(lang,"s.crossings"), count: extra.crossings?.length, html: crossingTable(extra.crossings ?? [], lang) },
    {
      id: "coverage",
      label: t(lang,"s.coverage"),
      count: extra.coverage?.rows.length,
      html: extra.coverage ? coverageTable(extra.coverage.rows, extra.coverage.summary, lang) : "",
    },
    { id: "devices", label: t(lang,"s.devices"), count: extra.devices?.rows.length, html: extra.devices ? deviceTable(extra.devices, lang) : "" },
    { id: "users", label: t(lang,"s.users"), count: extra.users?.length, html: userTable(extra.users ?? [], lang) },
    { id: "workload", label: t(lang,"s.workload"), count: extra.workload?.length, html: workloadTable(extra.workload ?? [], lang) },
    { id: "hosts", label: t(lang,"s.hosts"), count: extra.hosts?.length, html: hostTable(extra.hosts ?? [], lang) },
    { id: "membership", label: t(lang,"s.membership"), count: extra.membership?.length, html: membershipTable(extra.membership ?? [], lang) },
    { id: "objects", label: t(lang,"s.objects"), count: extra.objects?.length, html: objectTable(t(lang, "s.objects"), extra.objects ?? [], lang) },
    { id: "services", label: t(lang,"s.services"), count: extra.services?.length, html: objectTable(t(lang, "s.services"), extra.services ?? [], lang) },
    { id: "feeds", label: t(lang,"s.feeds"), count: extra.feeds?.length, html: feedTable(extra.feeds ?? [], lang) },
    { id: "address-space", label: t(lang,"s.addressSpace"), count: extra.addressSpace?.length, html: addressSpaceTable(extra.addressSpace ?? [], lang) },
    { id: "history", label: t(lang,"s.history"), count: extra.history?.length, html: historyTable(extra.history ?? [], lang) },
  ].filter((b) => b.html !== "");

  const wanted = meta.section ?? built[0]?.id;
  const showAll = wanted === "all";
  const shown = showAll ? built : built.filter((b) => b.id === wanted);
  // A section that was asked for and produced nothing falls back to the first rather than an empty
  // page — an empty page reads as "this site has none of that", which is a different claim.
  const visible = shown.length ? shown : built.slice(0, 1);

  const q = (id: string) => {
    const parts = [`s=${encodeURIComponent(id)}`];
    if (meta.lang) parts.push(`lang=${meta.lang}`);
    return `?${parts.join("&")}`;
  };

  // The sections, in the side. 시안 G1 draws them as a left column with a count against every name,
  // because the first question at this page is 「무엇이 비어 있지 않은가」 — which of these has
  // anything in it — and with one section shown at a time the count is the only way to know.
  //
  // They sit in the **same** side nav as the console's screens, as a second group under them, so an
  // operator who arrived here from /fleet does not lose the way back. That is the whole reason this
  // page and the console share `appShell`: two sidebars of different widths on two pages of one
  // product is the drift `NAV_CSS` was written to prevent, one level up.
  const sectionGroup: NavGroup = {
    label: t(lang, "s.sections"),
    items: [
      ...built.map((b) => ({
        href: q(b.id),
        label: b.label,
        on: !showAll && visible.some((v) => v.id === b.id),
        ...(b.count === undefined ? {} : { count: b.count }),
      })),
      { href: q("all"), label: t(lang, "page.showAll"), on: showAll },
    ],
  };
  const groups: NavGroup[] = [...(meta.nav ?? []), sectionGroup];
  const langs = langSwitch(lang, (l) => `?s=${encodeURIComponent(wanted ?? "")}&lang=${l}`);

  const summary =
    `<span class="${counts.nowhere ? "bad" : "dim"}">${counts.total} policies` +
    (counts.nowhere ? ` · ${counts.nowhere} render nowhere` : "") +
    "</span>" +
    ` <span class="dim">· ${meta.hosts.length} hosts · ${esc(meta.generation ?? "no generation")}</span>` +
    (known
      ? ""
      : ' <span class="warn">· placement not computed — the renderer was not run</span>');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>heliopause — policy</title>
<style>
${TOKENS_CSS}
${BASE_CSS}
${ICON_CSS}
.editrow { display: flex; gap: .5rem; align-items: center; margin: .75rem 0; flex-wrap: wrap; }
.filebox { margin: 1rem 0; }
.filebox label { display: block; margin-bottom: .35rem; }
/* Monospace and no wrapping: this is source, and a wrapped line hides which column a bracket is in.
   The box scrolls rather than the page — a long file must not make the whole console scroll sideways. */
.filebox textarea { width: 100%; box-sizing: border-box;
  font-family: var(--font-mono); font-size: 11.5px; line-height: 1.6;
  white-space: pre; overflow: auto; tab-size: 2; padding: 8px; background: var(--surface-sunken); }
/* Anchored jumps land under the sticky index instead of behind it. */
section[id] { scroll-margin-top: 3.5rem; }
/* No padding — the shell fills the viewport. Same rule as the console; see SHELL_CSS. */
/* The name lives in the bar now. This one stays for the document outline and the screen reader —
   a page with no h1 has no name — and is taken out of the visual flow. */
h1 { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0;
     overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
.sub { font-family: var(--font-mono); font-size: 11px; color: var(--text-2);
       display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin: 0 0 var(--sec-gap); }
/* freshness is not a boolean and is drawn for all three states, the good one included — see
   freshnessBanner(). 시안 G4 gives each its own shape as well as its own colour, and draws unknown
   on a hatch: 물어볼 수 없었다 must not look like 물어봤고 괜찮다. */
.fresh { margin: 0 0 var(--sec-gap); }
section { margin-bottom: var(--sec-gap); }
h2 { font-size: 15px; letter-spacing: -.01em; color: var(--text-1); font-weight: 600; margin: 0 0 9px; }
${SHELL_CSS}
${NAV_CSS}
table { min-width: 56rem; }
td { white-space: nowrap; }
footer { color: var(--text-2); font-family: var(--font-mono); font-size: 11px; margin-top: var(--sp-6);
         border-top: 1px solid var(--bd-1); padding-top: var(--sp-3); line-height: 1.7; }
form { display: grid; grid-template-columns: repeat(4, minmax(10rem, 1fr)); gap: .65rem;
       padding: 12px; background: var(--surface-card);
       border: 1px solid var(--accent-bd); border-top: 2px solid var(--accent);
       border-radius: var(--r-md); margin-bottom: var(--sec-gap); }
label { color: var(--text-3); font-family: var(--font-mono); font-size: 11px; }
input, select, textarea, button { width: 100%; margin-top: .2rem; }
textarea { min-height: 4.5rem; }
.wide { grid-column: span 2; } #edit-result { grid-column: 1 / -1; }
</style>
</head>
<body>
${iconSprite()}
<h1>heliopause &mdash; policy</h1>
${appShell({
  crumbs: ["policy", showAll ? t(lang, "page.showAll") : (visible[0]?.label ?? "policy")],
  groups,
  navFoot: esc(t(lang, "g.sectionNote")),
  // The site and the generation this page was rendered from. 시안 G1 keeps them in the bar for the
  // same reason the fleet screen keeps its read-time there: every number below is only true of that
  // one commit, and a reader who scrolled past the header has lost which commit it was.
  status: `<span class="mono">${esc(meta.site)} &middot; ${esc(meta.generation ?? t(lang, "page.noGeneration"))}</span>`,
  langs,
  main: `
  <div class="sub">${summary}</div>
  ${freshnessBanner(meta.freshness, lang)}
  ${rendererBanner(meta.renderer, lang)}
  ${meta.editable ? `<section><h2>${esc(t(lang, "ed.heading"))}</h2>
    <form id="policy-editor">
      <label class="wide">${esc(t(lang, "ed.existing"))}<select id="existing-policy"><option value="">${esc(t(lang, "ed.newPolicy"))}</option>${rows.map((row) => `<option value="${esc(row.id)}">${esc(row.id)} — ${esc(row.name)}</option>`).join("")}</select></label>
      <label><button type="button" id="load-policy">${esc(t(lang, "ed.load"))}</button></label><label><button type="button" id="delete-policy">${esc(t(lang, "ed.delete"))}</button></label>
      <label>${esc(t(lang, "c.id"))}<input name="id" required></label><label class="wide">${esc(t(lang, "c.name"))}<input name="name" required></label>
      <label>${esc(t(lang, "ed.enabled"))}<select name="enabled"><option value="true">${esc(t(lang, "ed.enabled"))}</option><option value="false">${esc(t(lang, "ed.disabled"))}</option></select></label>
      <label>${esc(t(lang, "ed.srcKind"))}<input name="srcKind" required></label><label>${esc(t(lang, "ed.srcValue"))}<input name="srcValue"></label>
      <label>${esc(t(lang, "ed.dstKind"))}<input name="dstKind" required></label><label>${esc(t(lang, "ed.dstValue"))}<input name="dstValue"></label>
      <label>${esc(t(lang, "ed.protocol"))}<select name="proto"><option>tcp</option><option>udp</option><option>icmp</option><option>any</option></select></label>
      <label>${esc(t(lang, "c.ports"))}<input name="ports"></label><label>${esc(t(lang, "c.action"))}<select name="action"><option>allow</option><option>deny</option></select></label>
      <label>${esc(t(lang, "ed.denyMode"))}<select name="denyMode"><option>drop</option><option>reject</option></select></label>
      <label>${esc(t(lang, "ed.priority"))}<input name="priority" type="number" value="100"></label>
      <label class="wide">${esc(t(lang, "c.notes"))}<textarea name="notes"></textarea></label>
      <label class="wide">${esc(t(lang, "ed.placements"))}<textarea name="placements" required>[]</textarea></label>
      <label><button type="submit">${esc(t(lang, "ed.save"))}</button></label><div id="edit-result" class="dim">${esc(t(lang, "ed.hint"))}</div>
    </form></section>` : ""}
  ${meta.proposable ? `<section><h2>${esc(t(lang, "ed.proposeHeading"))}</h2><form id="proposal-form">
    <label>${esc(t(lang, "ed.targetVpc"))}<input name="vpc" required placeholder="dev"></label>
    <label><button type="submit">${esc(t(lang, "ed.propose"))}</button></label>
    <div id="proposal-result" class="dim">${esc(t(lang, "ed.proposeHint"))}</div>
  </form></section>` : ""}
  ${visible.map((b) => b.html).join("\n  ")}
  ${meta.edit ? `<script nonce="${esc(meta.edit.nonce)}">
// The rule table. Rows come from policies.json; every edit is local until "save to branch".
const DOC = ${jsLiteral(meta.edit.content)};
const PATH = ${jsLiteral(meta.edit.path)};
const doc = JSON.parse(DOC);
const out = document.getElementById('edit-result');
const dirtyMark = document.getElementById('rule-dirty');
const tbody = document.getElementById('rule-rows');
let dirty = false;
let branch = '';
// Guarded because this script outlives its elements. It is emitted whenever meta.edit is set, but
// the elements it names live in sections the page shows one at a time -- rule-dirty and rule-rows
// are in the rules section, edit-result is in the editor form. Open the manager's /policy?s=zones
// as a writer and the first getElementById(...).addEventListener threw at load.
//
// Nothing visible broke: everything below the throw serves the rules section, which is not on that
// page. It is guarded because a routine page view should not throw -- an exception that is always
// there is one nobody reads, and the next real one arrives into a console that already has red.
//
// NOTE no backticks in this comment. It lives inside a template literal; one would end the block.
const say = (t, bad) => { if (out) { out.textContent = t; out.className = bad ? 'bad' : 'dim'; } };
const mark = () => { dirty = true; if (dirtyMark) dirtyMark.textContent = 'unsaved changes'; };
const esc = (v) => String(v == null ? '' : v);
// Every field the document actually uses, which is the point: the first version of this table had
// nine of the eleven, and the two it left out were denyMode and notes. 76 of the 77 rules carry a
// note, so the table could read the document but could not write one -- a rule created here was born
// without the reason it exists, and the only way to give it one was to leave the console.
//
// The empty first option on denyMode is absence, not a value. An allow rule has no deny mode.
const FIELDS = [
  ['id', 'text'], ['name', 'text'], ['src', 'ep'], ['dst', 'ep'],
  ['proto', ['tcp','udp','icmp','any']], ['ports', 'text'],
  ['action', ['allow','deny']], ['denyMode', ['','drop','reject']],
  ['priority', 'number'], ['enabled', 'bool'], ['notes', 'prose'],
];
const KINDS = ['host','host-group','cidr','object','internet','any','k8s-namespace','k8s-label'];
function cell(policy, group, field, kind) {
  const td = document.createElement('td');
  let el;
  if (kind === 'bool') {
    el = document.createElement('input'); el.type = 'checkbox'; el.checked = !!policy[field];
    el.addEventListener('change', () => { policy[field] = el.checked; mark(); });
  } else if (kind === 'ep') {
    el = document.createElement('span');
    const k = document.createElement('select');
    for (const o of KINDS) { const opt = document.createElement('option'); opt.value = opt.textContent = o; k.appendChild(opt); }
    k.value = policy[field].kind;
    const v = document.createElement('input'); v.type = 'text'; v.value = esc(policy[field].value); v.size = 14;
    k.addEventListener('change', () => { policy[field].kind = k.value; mark(); });
    v.addEventListener('input', () => { policy[field].value = v.value; mark(); });
    el.appendChild(k); el.appendChild(v);
  } else if (kind === 'prose') {
    // A textarea, not an input. The notes in the live document run to three thousand characters and
    // the median is a short paragraph; a one-line box would present the field as a label and get
    // labels written into it.
    el = document.createElement('textarea');
    el.rows = 2; el.cols = 30;
    el.value = esc(policy[field]);
    el.addEventListener('input', () => { policy[field] = el.value; mark(); });
  } else if (Array.isArray(kind)) {
    el = document.createElement('select');
    for (const o of kind) { const opt = document.createElement('option'); opt.value = o; opt.textContent = o || '—'; el.appendChild(opt); }
    el.value = esc(policy[field]);
    el.addEventListener('change', () => {
      // An empty choice is absence, not a blank value. Writing '' into denyMode would put a string
      // the document schema does not accept where the field simply was not there.
      if (el.value === '') delete policy[field]; else policy[field] = el.value;
      mark();
    });
  } else {
    el = document.createElement('input'); el.type = kind; el.value = esc(policy[field]);
    el.size = kind === 'number' ? 4 : 12;
    el.addEventListener('input', () => {
      policy[field] = kind === 'number' ? Number(el.value) : el.value; mark();
    });
  }
  td.appendChild(el);
  return td;
}
function render() {
  tbody.textContent = '';
  for (const [group, list] of Object.entries(doc.groups)) {
    for (const policy of list) {
      const tr = document.createElement('tr');
      // The group decides which hosts render the rule, so this select moves a rule between machines.
      // It was read-only text, and the only way to move a rule was to delete it and add it back --
      // which loses its notes, because the add path cannot carry them. Two gaps that multiplied.
      const g = document.createElement('td');
      const gs = document.createElement('select');
      for (const name of Object.keys(doc.groups)) {
        const opt = document.createElement('option');
        opt.value = name; opt.textContent = name.replace('Policies','');
        gs.appendChild(opt);
      }
      gs.value = group;
      gs.addEventListener('change', () => {
        const from = doc.groups[group];
        from.splice(from.indexOf(policy), 1);
        doc.groups[gs.value].push(policy);
        mark(); render();
      });
      g.appendChild(gs);
      tr.appendChild(g);
      for (const [f, kind] of FIELDS) tr.appendChild(cell(policy, group, f, kind));
      const del = document.createElement('td');
      const b = document.createElement('button'); b.type = 'button'; b.textContent = 'delete';
      b.addEventListener('click', () => {
        // Removing a rule is removing a hole or a permission. Say which one before it happens.
        const what = policy.action === 'allow' ? 'allow' : 'deny';
        if (!confirm('Delete ' + policy.id + '? It is an ' + what + ' rule and this removes it from the branch.')) return;
        list.splice(list.indexOf(policy), 1); mark(); render();
      });
      del.appendChild(b); tr.appendChild(del);
      tbody.appendChild(tr);
    }
  }
}
document.getElementById('rule-add')?.addEventListener('click', () => {
  const group = prompt('Which group? ' + Object.keys(doc.groups).join(', '), Object.keys(doc.groups)[0]);
  if (!group || !doc.groups[group]) return;
  doc.groups[group].push({
    id: 'NEW-RULE', name: '', src: { kind: 'cidr', value: '' }, dst: { kind: 'host', value: '' },
    proto: 'tcp', ports: '', action: 'allow', denyMode: 'drop', priority: 100, enabled: true,
    // Empty rather than absent, so the row shows the box. An absent field would render the same
    // empty textarea and then not be there to save, which is how a rule reaches main with no reason.
    notes: '',
  });
  mark(); render();
});
let csrf = null;
// ## Why these three carry the prefix, and why that is not the workstation's prefix
//
// This script is emitted only when meta.edit is set, and only the manager sets it — the workstation
// passes editable/proposable and never edit. So authz, policy/edit and policy/propose here are
// always the manager's routes, aliased under the prefix while the move off the top level is in
// flight.
//
// The workstation's own api/policies and api/propose further down this file belong to a *different*
// server that happens to share the prefix. They do not collide, since api/policy/edit is not under
// api/policies/ — but the two must not be read as one namespace, and neither server answers the
// other's paths.
//
// ## Why an empty answer is not cached
//
// The earlier version cached on "not null", so a miss -- a route that did not carry the field, or one
// request that failed -- was stored as '' and returned forever after: token() never asked again,
// every write went out with no header, and the server refused them all with a message about CSRF
// that named nothing an operator could act on. That is how a csrf field this route did not have
// stayed invisible for the whole life of this editor. A session always has a token, so an empty
// answer is never a fact worth keeping; a certificate caller has none and pays one GET per write.
//
// NOTE no backticks in this comment. It lives inside a template literal; one would end the block.
const token = async () => {
  if (csrf) return csrf;
  const r = await fetch('/api/authz');
  csrf = r.ok ? ((await r.json()).csrf || '') : '';
  return csrf;
};
const send = async (path, body) => {
  const h = { 'content-type': 'application/json' };
  const t = await token();
  if (t) h['x-heliopause-csrf'] = t;
  const r = await fetch(path, { method: 'POST', headers: h, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
  return j;
};
document.getElementById('rule-save')?.addEventListener('click', async () => {
  say('saving…');
  try {
    const j = await send('/api/policy/edit', {
      path: PATH,
      content: JSON.stringify(doc, null, 2) + String.fromCharCode(10),
      branch: branch || undefined,
    });
    branch = j.branch; dirty = false; dirtyMark.textContent = '';
    // Named, not counted, and after the commit rather than instead of it. The reviewer of the branch
    // is the one who can insist on a reason; a save button that refuses would send the operator to
    // git for the one edit this table exists to keep out of git.
    const bare = [];
    for (const list of Object.values(doc.groups)) for (const p of list) if (!p.notes) bare.push(p.id);
    say('committed ' + j.commit.slice(0, 8) + ' to ' + j.branch + ' — nothing is published yet.'
      + (bare.length ? ' No reason recorded for: ' + bare.join(', ') + '.' : ''), bare.length > 0);
  } catch (err) { say(String(err.message), true); }
});
// ── the other editable files ────────────────────────────────────────────────
//
// Their content arrives as a JS literal rather than inside the textarea's HTML. A file that contains
// the closing tag as text would otherwise end the element and put the rest of it on the page as
// markup — and one of these files is TypeScript that may well quote HTML.
//
// They share the branch variable with the rule table on purpose. Saving each to its own branch would produce
// two branches and a pull request carrying half the change, which is the shape where a reviewer
// approves a rule whose reason went somewhere else.
const FILES = JSON.parse(${jsLiteral(JSON.stringify((meta.edit.more ?? []).map((f) => ({ path: f.path, content: f.content }))))});
const fileDirty = new Set();
const fileOut = document.getElementById('file-result');
const sayFile = (t, bad) => { if (fileOut) { fileOut.textContent = t; fileOut.className = bad ? 'bad' : 'dim'; } };
for (let i = 0; i < FILES.length; i++) {
  const f = FILES[i];
  const box = document.getElementById('file-' + i);
  if (!box) continue;
  box.value = f.content;
  const flag = document.querySelector('[data-dirty-file="' + CSS.escape(f.path) + '"]');
  box.addEventListener('input', () => {
    // Compared against the text that was served, not a one-way flag: typing a character and deleting
    // it should not leave the page claiming an unsaved change and blocking the proposal.
    if (box.value === f.content) fileDirty.delete(f.path);
    else fileDirty.add(f.path);
    if (flag) flag.textContent = fileDirty.has(f.path) ? ${jsLiteral(t(lang, "file.dirty"))} : '';
  });
  const btn = document.querySelector('[data-save-file="' + CSS.escape(f.path) + '"]');
  if (btn) btn.addEventListener('click', async () => {
    // The server refuses an empty body too. Saying it here as well means the operator learns it
    // before a round trip, and the server keeps saying it because the page is not the only caller.
    if (!box.value) return sayFile(${jsLiteral(t(lang, "file.empty"))}, true);
    sayFile(${jsLiteral(t(lang, "rule.saving"))});
    try {
      const j = await send('/api/policy/edit', { path: f.path, content: box.value, branch: branch || undefined });
      branch = j.branch;
      f.content = box.value;
      fileDirty.delete(f.path);
      if (flag) flag.textContent = '';
      sayFile(${jsLiteral(t(lang, "file.saved"))} + ' ' + j.commit.slice(0, 8) + ' → ' + j.branch);
    } catch (err) { sayFile(String(err.message), true); }
  });
}
document.getElementById('rule-propose')?.addEventListener('click', async () => {
  if (!branch) return say('save first — a pull request needs a branch.', true);
  if (dirty) return say('unsaved changes — save before proposing.', true);
  // The file editors block the proposal too. They commit to the same branch, so a proposal opened
  // while one of them is unsaved would describe a branch the operator has not finished writing.
  if (fileDirty.size) return say('unsaved changes in ' + [...fileDirty].join(', ') + ' — save before proposing.', true);
  say('opening…');
  try {
    const j = await send('/api/policy/propose', { branch });
    say('pull request #' + j.number + ' — ' + j.url + '. Merging adopts the source; publishing is separate.');
  } catch (err) { say(String(err.message), true); }
});
if (tbody) render();
</script>` : ""}
  <footer>
    ${esc(meta.site)} &middot; ${meta.editable ? "managed policy document · saved atomically; commit before publish" : "read-only · editing a policy is a git commit"}
    ${meta.manager
      // A relative value means the manager is serving this page itself, and printing "/" as the
      // link text tells the reader nothing. Absolute stays verbatim: there it is the address of
      // another machine and the operator wants to see which one before clicking.
      ? `<div class="dim">fleet state, audit and approvals: <a href="${esc(meta.manager)}">${
          meta.manager.startsWith("/") ? "manager console" : esc(meta.manager)
        }</a></div>`
      : `<div class="dim">fleet state, audit and approvals live in the manager console &mdash; pass <code>--manager=URL</code> to fold it in</div>`}
  </footer>
`,
})}
${meta.editable ? `<script>
const form = document.getElementById('policy-editor');
const result = document.getElementById('edit-result');
let loadedId = null;
document.getElementById('load-policy').addEventListener('click', async () => {
  const id = document.getElementById('existing-policy').value;
  if (!id) { form.reset(); form.elements.placements.value = '[]'; loadedId = null; return; }
  const doc = await (await fetch('/api/policies')).json(); const p = doc.policies.find((item) => item.id === id);
  if (!p) return; loadedId = id;
  for (const [name, value] of Object.entries({ id: p.id, name: p.name, srcKind: p.src.kind, srcValue: p.src.value,
    dstKind: p.dst.kind, dstValue: p.dst.value, proto: p.proto, ports: p.ports, action: p.action,
    denyMode: p.denyMode, priority: p.priority, enabled: String(p.enabled), notes: p.notes || '' })) form.elements[name].value = value;
  form.elements.placements.value = JSON.stringify((doc.placements || []).filter((placement) => placement.policyId === id), null, 2);
});
document.getElementById('delete-policy').addEventListener('click', async () => {
  const id = loadedId || form.elements.id.value; if (!id || !confirm('Delete policy ' + id + ' and all of its placements?')) return;
  const response = await fetch('/api/policies/' + encodeURIComponent(id), { method: 'DELETE' }); const body = await response.json();
  if (!response.ok) { result.className = 'bad'; result.textContent = body.error || 'delete failed'; return; }
  location.reload();
});
form.addEventListener('submit', async (event) => {
  event.preventDefault(); result.textContent = 'validating…';
  const value = Object.fromEntries(new FormData(form));
  const policy = { id: value.id, name: value.name,
    src: { kind: value.srcKind, value: value.srcValue }, dst: { kind: value.dstKind, value: value.dstValue },
    proto: value.proto, ports: value.ports, action: value.action, denyMode: value.denyMode,
    priority: Number(value.priority), enabled: value.enabled === 'true', notes: value.notes };
  let placements;
  try { placements = JSON.parse(value.placements); if (!Array.isArray(placements)) throw new Error('not an array'); }
  catch (e) { result.className = 'bad'; result.textContent = 'placements must be a JSON array: ' + e.message; return; }
  const response = await fetch('/api/policies/' + encodeURIComponent(policy.id), {
    method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ policy, placements })
  });
  const body = await response.json();
  if (!response.ok) { result.className = 'bad'; result.textContent = body.error || 'save failed'; return; }
  result.className = 'ok'; result.textContent = 'saved ' + policy.id + ' — reloading rendered view';
  setTimeout(() => location.reload(), 300);
});
</script>` : ""}
${meta.proposable ? `<script>
document.getElementById('proposal-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const result = document.getElementById('proposal-result'); result.textContent = 'rendering and submitting…';
  const vpc = new FormData(event.target).get('vpc'); const response = await fetch('/api/propose', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ vpc })
  }); const body = await response.json();
  result.className = response.ok ? 'ok' : 'bad'; result.textContent = response.ok ? body.output : body.error;
});
</script>` : ""}
</body>
</html>`;
}
