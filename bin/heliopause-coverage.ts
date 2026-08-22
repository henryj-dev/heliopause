#!/usr/bin/env node
// Run the coverage checks and write what was observed.
//
// ## Where this may run
//
// Not the operator's workstation — it leaves over Cloudflare WARP, so a public-path result is about
// Cloudflare's network rather than ours. Not a Vultr instance — outbound 25 is blocked there, so
// every mail-port check comes back "blocked" without anything having been measured. Both produce
// green cells nobody measured, which is worse than a red one.
//
// `--from` is required and is written onto every probe. A result whose vantage point is wrong can
// then be disbelieved by reading it, instead of being trusted because it is green.
//
// ## Why the whole probe set is rewritten each run
//
// The file holds the latest run and nothing else; the failure history is the file's git history.
// Appending would grow a file whose old entries are indistinguishable from current ones at a glance,
// and the screen already refuses to treat a stale probe as current — one place for that rule is
// enough.
//
// Exits 1 when a check failed, 2 when something was not measured. Those are different states and a
// pipeline should be able to act on them differently: a failure is a hole in the firewall, an
// unmeasured check is a hole in the measuring.
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { probeAll } from "../src/coverage-probe.ts";
import { t } from "../src/i18n.ts";
import {
  baselineCoverageGaps, coverageRows, coverageSummary, type CoverageCheck, type Family,
} from "../src/coverage.ts";
import type { Site } from "./heliopause-publish.ts";
import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();
const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

const siteArg = args[0]?.startsWith("--") ? undefined : args[0];
const from = flag("--from");

if (!siteArg || !from || args.includes("--help")) {
  console.error(
    "usage: heliopause-coverage <site.ts> --from <label> [--out <file>] [--families v4,v6] [--timeout-ms N]\n" +
      "\n" +
      "  --from is required and is recorded on every probe. Do NOT run this from the operator\n" +
      "  workstation (Cloudflare WARP) or a Vultr instance (outbound 25 blocked) — both produce\n" +
      "  results that look measured and are not.\n" +
      "\n" +
      "  Write each vantage point to its own --out file (coverage-<name>.json). The screen reads\n" +
      "  every coverage-*.json beside the site module, so two writers never touch one file.\n" +
      "\n" +
      "  exit 0 all checks passed · 1 a check failed · 2 something was not measured\n" +
      "         (a baseline path with no reach check counts as not measured)",
  );
  process.exit(args.includes("--help") ? 0 : 64);
}

const mod = (await import(pathToFileURL(resolve(siteArg)).href)) as { site?: Site };
const checks: CoverageCheck[] = mod.site?.coverage ?? [];

// ## The baseline, before anything is probed
//
// `nft.ts` says plainly that the host-side checks cannot catch a wrong baseline: the rules and the
// assertions come from the same config, so they are wrong together and agree. This prober is what
// can catch it — and only for the paths somebody wrote a check for.
//
// `cfg.baseline` and `site.coverage` are two hand-written lists, and this repository's finding about
// two lists is that they drift. Reported before the probes so it is read even when every probe
// passes: a green table over an unmeasured management path is exactly the shape being guarded
// against.
const gaps = baselineCoverageGaps(mod.site?.cfg?.baseline ?? [], checks);
const unmeasured = gaps.filter((g) => g.kind === "unmeasured");
if (gaps.length) {
  console.log("baseline paths and whether anything measures them:");
  for (const g of gaps) {
    console.log(
      g.kind === "unmeasured"
        ? `  ⚠ ${g.desc} (${g.proto}/${g.ports}) — no reach check probes this port`
        : `  · ${g.desc} (${g.proto}) — this prober speaks TCP only, so no check can cover it`,
    );
  }
  if (unmeasured.length) {
    console.log(
      `  ${unmeasured.length} management path(s) the baseline promises and nothing verifies.\n` +
        "  A blocked-from-the-internet check on the same port is not this: it proves the opposite\n" +
        "  thing from a different vantage point.",
    );
  }
  console.log("");
}
if (!checks.length) {
  console.error(`${siteArg} declares no coverage checks — nothing to measure`);
  process.exit(64);
}

const families = (flag("--families") ?? "v4,v6").split(",").map((s) => s.trim()) as Family[];
const timeoutMs = Number(flag("--timeout-ms") ?? "5000");

const probes = await probeAll(checks, { observedFrom: from, families, timeoutMs });
const now = new Date().toISOString();
const rows = coverageRows(checks, probes, { now });
const summary = coverageSummary(rows, { families });

for (const r of rows) {
  const cell = (label: string, c: (typeof r)["v4"]) =>
    c.verdict === "n/a" ? "" : `  ${label} ${c.verdict.padEnd(11)} ${t("en", c.reasonKey as Parameters<typeof t>[1])}`;
  console.log(`${r.check.id.padEnd(4)} ${r.check.title}`);
  for (const line of [cell("v4", r.v4), cell("v6", r.v6)]) if (line) console.log(line);
}
console.log(
  `\n${summary.failing} failing · ${summary.unknown} not measured · ${summary.passing} passing` +
    ` — observed from ${from} at ${now}`,
);

const out = flag("--out");
if (out) {
  writeFileSync(
    resolve(out),
    JSON.stringify({ schemaVersion: 1, at: now, observedFrom: from, probes }, null, 2) + "\n",
    "utf8",
  );
  console.log(`wrote ${probes.length} probe(s) to ${out}`);
}

// Failure outranks a gap: a hole in the firewall is the more urgent of the two, and a run with both
// should exit on the one that needs acting on first. An unmeasured baseline path joins the existing
// exit 2 — it is the same statement as an unknown cell, one level up: a hole in the measuring.
process.exit(summary.failing ? 1 : (summary.unknown || unmeasured.length) ? 2 : 0);
