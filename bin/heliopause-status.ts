#!/usr/bin/env node
// Read the fleet's state from a relay and print it.
//
//   heliopause-status <url> [--site] [--pki=DIR] [--operator=NAME] [--json] [--watch[=SEC]]
//
// Two endpoints, one command. Without `--site` this reads a relay's `/status` — one VPC, the view
// that has existed since the beginning. With `--site` it reads a manager's `/site`, which is every
// VPC in one answer.
//
// ## `--site` is the normal path for an operator. The relay path is the fallback
//
// This was written the other way round, and the fleet disagreed. Measured 2026-08-10.
//
// Each VPC has **its own certificate authority** — same `CN=heliopause-ca` in all of them, three
// different keys. So an operator certificate is not fleet-wide: it authenticates to the one VPC
// whose CA signed it, and presenting it to another relay fails in TLS with `unable to get local
// issuer certificate` before any authorisation decision is reached. The relay's
// `HELIOPAUSE_OPERATOR_CNS` may well list that operator; it never gets asked.
//
// The manager already holds one operator certificate **per VPC**, which is what `HELIOPAUSE_RELAYS`
// carries: a URL and a PKI directory for each. It is the one caller positioned to read all of them,
// so a cross-VPC read goes through `--site`. An operator with one VPC's certificate reading another
// VPC's relay directly is not a supported path — not policy, arithmetic.
//
// ## Why the relay path stays anyway
//
// It is the fallback, and the fallback is not optional. There is one manager and three relays; the
// design puts a relay on each gateway precisely so a gateway outage is contained. The moment the
// manager is down, or the cluster it runs in is the thing being debugged, `--site` returns nothing —
// and that is exactly when the fleet needs reading.
//
// **What that fallback actually covers is worth stating plainly**, because it is narrower than it
// looks: an operator falls back to the VPC they hold a certificate for, and to no other. Reaching
// the rest during a manager outage means either a certificate from each VPC's CA on the
// workstation, or a shell on that VPC's gateway. Neither is a path this tool provides.
//
// A single CA across VPCs would remove the whole issue and is not obviously wrong — the isolation
// bought by separate CAs is real but so is the failure mode above. It has not been decided.
//
// The alternative this replaces is `ssh` to each host and read its journal. That does not scale, and
// worse, it never describes the fleet at a single consistent moment — which during a staged rollout
// is exactly the thing you need: which stage is open, what is still pending, what drifted.
//
// Read-only by construction. There is no flag here that applies, publishes, or rolls anything back;
// this connects to an endpoint that only reads. Changing the fleet means publishing a generation.
//
// Requires an **operator** certificate — an agent's will be refused with 403. See CertRole in
// src/pki.ts for why those are separate roles.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { request } from "node:https";
import { rootCertificates } from "node:tls";
import { wrongCaHint } from "../src/pki.ts";
import { hostVerdict, STALE_SEC } from "../src/rollout.ts";
import type { FleetView, HostView } from "../src/relay.ts";
import type { SiteView } from "../src/manager.ts";
import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();

const args = process.argv.slice(2);
const flags = new Map(
  args.filter((a) => a.startsWith("--")).map((a) => {
    const [k, v] = a.replace(/^--/, "").split("=", 2);
    return [k!, v ?? "true"];
  }),
);
const [relayUrl] = args.filter((a) => !a.startsWith("--"));
const siteMode = flags.has("site");

if (!relayUrl || flags.has("help")) {
  console.error(
    "usage: heliopause-status <url> [--site] [--pki=DIR] [--operator=NAME] [--json] [--watch[=SEC]]\n" +
      "                             [--timeout-ms=N]\n" +
      "\n" +
      "  --site           read a manager's /site (every VPC) instead of a relay's /status (one)\n" +
      "  --pki=DIR        directory holding ca.pem and operator-<name>.pem/.key (default ./pki)\n" +
      "  --operator=NAME  which operator certificate to present (default: the only one present)\n" +
      "  --json           emit the raw response instead of a table\n" +
      "  --watch[=SEC]    redraw every SEC seconds (default 5)\n" +
      "  --timeout-ms=N   give up on one request after N ms (default 20000)\n",
  );
  process.exit(2);
}

const pkiDir = resolve(flags.get("pki") ?? "./pki");

/** Pick the operator certificate, and say so clearly when the choice is ambiguous. */
function operatorFiles(): { cert: Buffer; key: Buffer; ca: Buffer; name: string } {
  const ca = join(pkiDir, "ca.pem");
  if (!existsSync(ca)) {
    throw new Error(
      `no ca.pem in ${pkiDir}. Point --pki at the directory heliopause-pki wrote, or issue a CA ` +
        `with \`heliopause-pki init\`.`,
    );
  }
  const found = readdirSync(pkiDir)
    .filter((f) => f.startsWith("operator-") && f.endsWith(".pem"))
    .map((f) => f.slice("operator-".length, -".pem".length));
  const want = flags.get("operator");
  const name = want ?? found[0];
  if (!name) {
    throw new Error(
      `no operator certificate in ${pkiDir}. Issue one with:\n` +
        `  heliopause-pki issue ${pkiDir} <your-name> --role=operator\n` +
        `then add its CN to the relay's HELIOPAUSE_OPERATOR_CNS.`,
    );
  }
  if (!want && found.length > 1) {
    throw new Error(`several operator certificates in ${pkiDir} (${found.join(", ")}) — pass --operator=NAME`);
  }
  const base = join(pkiDir, `operator-${name}`);
  if (!existsSync(`${base}.pem`)) throw new Error(`no operator certificate named ${name} in ${pkiDir}`);
  return {
    cert: readFileSync(`${base}.pem`),
    key: readFileSync(`${base}.key`),
    ca: readFileSync(ca),
    name,
  };
}

/**
 * Strip control characters out of anything a server said before it reaches the terminal.
 *
 * This page is a table an operator reads to decide whether the fleet is healthy, and every string
 * in it — hostname, generation id, problem text — comes from the relay or the manager. A newline in
 * a hostname forges a row; an `\x1b[` sequence repaints one, and this renderer already writes real
 * ANSI (`c(RED, …)`), so an injected sequence is indistinguishable from the tool's own colour. The
 * failure that matters here is not a crash: it is a status display that says "healthy" about a host
 * whose row was overwritten.
 *
 * Applied where the server's bytes first become values — the `JSON.parse` reviver below and the
 * non-200 body — so no renderer has to remember. `\n` and `\t` go too: no field in a fleet or site
 * view legitimately holds one, and they are the forgery primitive in a column layout. U+FFFD rather
 * than deletion, so a value that was tampered with looks tampered with instead of merely odd.
 *
 * Not a defence against a relay that lies in ordinary text — it can still report a host as healthy.
 * That is the trust the client certificate establishes and this cannot second-guess. What it stops
 * is a relay rewriting *other* rows than its own.
 */
const CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/g;
const scrub = (text: string): string => text.replace(CONTROL_CHARS, "\uFFFD");

/**
 * How long this waits for the whole answer, and how much of it it will hold.
 *
 * ## Neither existed
 *
 * `request()` was called with no `timeout` and the body was accumulated with an unbounded
 * `chunks.push`. A relay that completes the handshake and then says nothing left this command
 * **hanging with no output** — which is what an operator runs first during an incident, and the one
 * moment a hang is indistinguishable from a slow fleet. A relay that answers forever filled the
 * workstation's memory instead.
 *
 * Both are the same failure this repository has now fixed in `feed-fetch.ts`, `otp.ts`, `oidc.ts`
 * and `cert-api.ts`. This one is a CLI rather than the manager, so the cost is a crashed command
 * instead of an outage — which is why it survived, and not a reason to leave it.
 *
 * `--timeout-ms` because the honest value depends on the link: the same command is run from a
 * workstation on the VPC and over a tunnel from elsewhere. Twenty seconds is generous for a status
 * page and short enough to be a failure rather than a wait.
 *
 * The byte ceiling is `MAX_RELAY_RESPONSE_BYTES` from `manager-server.ts`, not a fresh number: that
 * is the manager's bound on **this same answer** read from the same relay, and two limits on one
 * body would only ever be an opportunity for them to disagree.
 */
const DEFAULT_TIMEOUT_MS = 20_000;
const MAX_VIEW_BYTES = 8 * 1024 * 1024;
const timeoutMs = flags.has("timeout-ms") ? Number(flags.get("timeout-ms")) : DEFAULT_TIMEOUT_MS;
if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
  console.error(`[status] --timeout-ms must be a positive number of milliseconds`);
  process.exit(2);
}

async function fetchView<T>(path: string): Promise<T> {
  const { cert, key, ca } = operatorFiles();
  const url = new URL(path, relayUrl);
  return new Promise((ok, fail) => {
    const req = request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: "GET",
        cert,
        key,
        // Socket inactivity. The deadline below is the one that ends a peer trickling bytes; this
        // one ends a peer that has stopped sending them, without waiting out the whole deadline.
        timeout: timeoutMs,
        // Setting `ca` replaces Node's Web PKI roots. Status supports both private relay
        // certificates and a publicly certified manager, so retain both trust stores.
        ca: [...rootCertificates, ca],
      },
      (res) => {
        const chunks: Buffer[] = [];
        let total = 0;
        res.on("data", (c: Buffer) => {
          total += c.length;
          if (total > MAX_VIEW_BYTES) {
            // Rejected before the destroy, so the reason is the size and not the `aborted` the
            // destroy raises — a promise keeps its first settlement, and those two send a reader to
            // opposite places.
            fail(new Error(`${siteMode ? "manager" : "relay"} answer exceeded ${MAX_VIEW_BYTES} bytes`));
            res.destroy();
            return;
          }
          chunks.push(c);
        });
        res.on("end", () => {
          // One decode of the whole body. Decoding each chunk would corrupt any multi-byte character
          // that straddled a chunk boundary, which is `bounded-body.ts`'s reason for existing and is
          // exactly what a Korean `detail` field in a fleet view would hit.
          const body = Buffer.concat(chunks).toString("utf8");
          if (res.statusCode !== 200) {
            // 403 is the common one and deserves the actionable message rather than a bare code:
            // it means the certificate is valid and simply not on the relay's allowlist.
            const hint =
              res.statusCode === 403
                ? `\n  This certificate is not in the ${siteMode ? "manager" : "relay"}'s HELIOPAUSE_OPERATOR_CNS.`
                : res.statusCode === 404
                  // The most likely mistake once there are two endpoints: asking one server for the
                  // other's path. Say which, rather than leaving a bare 404.
                  ? siteMode
                    ? "\n  This URL has no /site — it is probably a relay. Drop --site."
                    : "\n  This URL has no /status — it is probably a manager. Add --site."
                  : "";
            return fail(new Error(`${siteMode ? "manager" : "relay"} returned ${res.statusCode}: ${scrub(body)}${hint}`));
          }
          try {
            // The reviver is the choke point: every string in the response passes through it once,
            // before any renderer or `--json` dump can see it.
            ok(JSON.parse(body, (_key, value) => (typeof value === "string" ? scrub(value) : value)) as T);
          } catch (e) {
            fail(new Error(`${siteMode ? "manager" : "relay"} returned unparseable JSON: ${(e as Error).message}`));
          }
        });
      },
    );
    req.on("timeout", () => {
      req.destroy(new Error(`no answer within ${timeoutMs}ms`));
    });
    // The wall clock, distinct from the socket timeout above: a peer sending one byte at a time
    // resets an inactivity timer forever. Armed before the request so the TLS handshake counts.
    const deadline = setTimeout(() => {
      req.destroy(new Error(`did not finish within ${timeoutMs}ms`));
    }, timeoutMs);
    const settled = () => clearTimeout(deadline);
    req.on("close", settled);
    req.on("error", (e) => {
      settled();
      const hint = wrongCaHint((e as NodeJS.ErrnoException).code, siteMode, pkiDir);
      fail(new Error(`cannot reach ${relayUrl}: ${e.message}${hint}`));
    });
    req.end();
  });
}

// ── rendering ─────────────────────────────────────────────────────────────────

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const GREEN = "\x1b[32m";
const colour = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string, s: string) => (colour ? `${code}${s}${RESET}` : s);

/**
 * One word for what a host is doing, chosen so the bad cases cannot be mistaken for the good ones.
 *
 * `drift` outranks `confirmed` deliberately: a drifted host *has* confirmed, and reporting that
 * would be true and useless — the interesting fact is that its ruleset changed afterwards.
 */
/** Colour for a verdict. Separate from the judging so both views cannot disagree about the words. */
function paint(v: ReturnType<typeof hostVerdict>): string {
  switch (v.kind) {
    case "drift": return c(RED, "DRIFT");
    case "never-seen": return c(RED, "never seen");
    case "silent": return c(RED, `silent ${v.ageSec}s`);
    // Dim, not red: silent and accounted for. A colour that reads as a fault would put this host
    // back in the pile an operator has to triage, which is the thing the flag removes it from.
    case "maintenance": return c(DIM, "maintenance");
    case "rolled-back": return c(RED, "rolled-back");
    // Yellow, not green: the host is healthy about a generation that is no longer the target.
    case "behind": return c(YELLOW, v.blockedBy ? "waiting" : (v.state ?? "behind"));
    case "confirmed": return c(GREEN, "confirmed");
    case "other": return c(YELLOW, v.state);
  }
}

function verdict(h: HostView, relayAgeSec: number | null): string {
  // The one judgement this view makes that the shared one cannot: a relay restarted moments ago has
  // heard from nobody, because its state is memory-only and every agent beats on its own schedule.
  // Calling that "never seen" made a healthy fleet read as two thirds dead — measured, right after
  // `systemctl restart heliopause-relay`. The site view has no equivalent because it aggregates
  // three relays and cannot attribute one host's silence to one relay's youth.
  //
  // Everything else goes to `hostVerdict`. It used to be a second copy of those rules, and the copy
  // drifted twice: once missing the staleness check (a nine-hour-dead host drawn green) and once
  // missing `current` (a host mid-rollout drawn green next to a `wanted elsewhere` generation).
  if (h.ageSec === null && relayAgeSec !== null && relayAgeSec <= STALE_SEC) return c(DIM, "unknown");
  return paint(hostVerdict(h));
}

function render(v: FleetView): string {
  const out: string[] = [];
  out.push(
    `${c(BOLD, "generation")} ${v.generation ?? c(RED, "(none)")}` +
      (v.issuedAt ? c(DIM, `  issued ${v.issuedAt}`) : ""),
  );
  out.push("");

  const rows = v.hosts.map((h) => ({
    host: h.host,
    stage: h.stage ?? "?",
    verdict: verdict(h, v.relayAgeSec),
    gen: h.generation ?? "—",
    age: h.ageSec === null ? "—" : `${h.ageSec}s`,
    why: h.blockedBy ?? h.detail ?? "",
  }));

  // Padding is computed on the visible text, not the coloured string — escape codes have length.
  const plain = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");
  const w = (key: keyof (typeof rows)[0]) =>
    Math.max(key.length, ...rows.map((r) => plain(String(r[key])).length));
  const pad = (s: string, n: number) => s + " ".repeat(Math.max(0, n - plain(s).length));

  out.push(
    c(DIM, `${pad("HOST", w("host"))}  ${pad("STAGE", w("stage"))}  ${pad("STATE", w("verdict"))}  ${pad("GENERATION", w("gen"))}  AGE`),
  );
  for (const r of rows) {
    out.push(
      `${pad(r.host, w("host"))}  ${pad(r.stage, w("stage"))}  ${pad(r.verdict, w("verdict"))}  ` +
        `${pad(r.gen, w("gen"))}  ${pad(r.age, w("age"))}` +
        (r.why ? c(DIM, `  ${r.why}`) : ""),
    );
  }

  if (v.problems.length) {
    out.push("");
    out.push(c(BOLD, `${v.problems.length} problem(s):`));
    for (const p of v.problems) out.push(`  ${c(RED, "•")} ${p}`);
  } else {
    out.push("");
    out.push(c(GREEN, "no problems"));
  }

  // Say so rather than letting `unknown` rows look unexplained. A reader who does not know the
  // relay just restarted would otherwise be left guessing what "unknown" means.
  if (v.relayAgeSec !== null && v.relayAgeSec <= STALE_SEC && v.hosts.some((h) => h.ageSec === null)) {
    out.push(
      c(DIM, `\nthe relay started ${v.relayAgeSec}s ago and its state is memory-only — ` +
        `hosts shown as "unknown" have simply not beaten yet`),
    );
  }
  return out.join("\n");
}


/**
 * The site view: every VPC in one table.
 *
 * Deliberately not the same table as `render` with a column bolted on. A relay knows things a
 * manager cannot — `stage`, `blockedBy`, how long ago the relay itself started — and a site view
 * that showed those columns empty would read as "no stage" rather than "not asked". What the
 * aggregate adds instead is the VPC, whether each relay answered at all, and whether the site agrees
 * on a generation.
 */
function renderSite(v: SiteView): string {
  const out: string[] = [];
  const plain = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");
  const pad = (s: string, n: number) => s + " ".repeat(Math.max(0, n - plain(s).length));

  // Reachability first. A VPC whose relay did not answer contributes no rows at all, so a table read
  // without this line silently under-reports the fleet — the hosts are not "fine", they are unseen.
  const reach =
    v.reachable === v.asked
      ? c(GREEN, `${v.reachable}/${v.asked} relays`)
      : c(RED, `${v.reachable}/${v.asked} relays`);
  out.push(`${c(BOLD, "site")}  ${reach}  ${c(DIM, v.vpcs.map((x) => x.name).join(", "))}`);

  // One generation is the quiet case and gets one line. More than one is normal mid-rollout and a
  // problem afterwards, and the manager cannot tell which — so it lists them and lets a reader who
  // knows when the publish happened decide.
  if (v.generations.length === 1) {
    out.push(`${c(BOLD, "generation")} ${v.generations[0]!.generation ?? c(RED, "(none)")}`);
  } else {
    out.push(c(BOLD, `${v.generations.length} generations in play:`));
    for (const g of v.generations) {
      out.push(`  ${pad(g.generation ?? c(RED, "(none)"), 26)} ${c(DIM, g.vpcs.join(", "))}`);
    }
  }
  out.push("");

  const rows = v.hosts.map((h) => ({
    vpc: h.vpc,
    host: h.host,
    // Silence outranks the stored state, and getting that order wrong is how this column lied.
    //
    // `state` is the last thing the host said. On 2026-08-11 `mailer-03` had been dead for nine
    // hours — Vultr moved it onto a CPU its glibc will not run on, so init never started — and this
    // column printed a green `confirmed`, because that *was* its last word. The relay path already
    // refused to do that (`verdict()` returns `silent Ns`); this one had its own copy of the
    // decision and the copy was missing the check.
    //
    // A firewall console that reports a host as confirmed while the host does not exist is worse
    // than one that reports nothing: it answers the question an operator actually asked — "is the
    // fleet applying my policy" — with a confident no-longer-true yes.
    state: paint(hostVerdict(h)),
    // Its own column, never folded into STATE. A host confirmed on its own layer and rolled back in
    // the cluster is the combination this half exists to keep separable, and one word cannot say
    // both. `—` on the hosts with no workload assigned, which is most of them.
    workload: !h.workload
      ? c(DIM, "—")
      : h.workload.state === "confirmed"
        ? c(GREEN, "confirmed")
        : h.workload.state === null
          ? c(RED, "not reported")
          : c(RED, h.workload.state),
    gen: h.generation ?? "—",
    age: h.ageSec === null ? "—" : `${h.ageSec}s`,
    // Empty on a host that reported none, and a word on a host that did not report at all — the two
    // are different answers and the table is where that difference has to survive.
    other: h.unexpectedFilters === null ? c(DIM, "unreported") : h.unexpectedFilters.join(", "),
  }));
  const w = (key: keyof (typeof rows)[0]) =>
    Math.max(key.length, ...rows.map((r) => plain(String(r[key])).length));

  out.push(
    c(DIM, `${pad("VPC", w("vpc"))}  ${pad("HOST", w("host"))}  ${pad("STATE", w("state"))}  ` +
      `${pad("WORKLOAD", w("workload"))}  ${pad("GENERATION", w("gen"))}  ${pad("AGE", w("age"))}  OTHER FILTERS`),
  );
  for (const r of rows) {
    out.push(
      `${pad(r.vpc, w("vpc"))}  ${pad(r.host, w("host"))}  ${pad(r.state, w("state"))}  ` +
        `${pad(r.workload, w("workload"))}  ${pad(r.gen, w("gen"))}  ${pad(r.age, w("age"))}  ${r.other}`,
    );
  }

  // ## Why a stalled host is stalled, under the table rather than in it
  //
  // A blocked host is the normal state of a staged rollout, so this is empty most of the time and a
  // column would be mostly padding. It is also the one thing this view could not say: on
  // 2026-08-11 `gw-01.dev` sat on the previous generation while every other row read `confirmed`,
  // and the site view had no answer — the relay, asked directly, said *"waiting on general:
  // mailer-03.dev has not reported this generation"*. The manager had been dropping `stage` and
  // `blockedBy` on the way through.
  //
  // Printed per host rather than summarised, because "which stage is open" is exactly the question
  // and one line collapsing several hosts would lose it.
  const blocked = v.hosts.filter((h) => h.blockedBy);
  if (blocked.length) {
    out.push("");
    for (const h of blocked) {
      out.push(c(YELLOW, `  ${h.vpc}/${h.host}${h.stage ? ` (${h.stage})` : ""}: ${h.blockedBy}`));
    }
  }

  // Under the table rather than in it: pod counts are per selector, and a column would either show
  // one of them or a number that means nothing. Printed with the time the cluster was read, because
  // membership goes stale in seconds and a count read as current is one an operator acts on.
  for (const h of v.hosts) {
    const m = h.workload?.membership;
    if (!m) continue;
    const parts = [
      ...Object.entries(m.namespaces).map(([ns, pods]) => `${ns}=${pods.length}`),
      ...Object.entries(m.labelled).map(([sel, pods]) => `${sel}=${pods.length}`),
    ];
    out.push(
      c(DIM, `\n${h.vpc}/${h.host} selectors as of ${m.at}: ` +
        (parts.length ? parts.join("  ") : "nothing asked for")),
    );
  }

  if (v.problems.length) {
    out.push("");
    out.push(c(BOLD, `${v.problems.length} problem(s):`));
    for (const p of v.problems) out.push(`  ${c(RED, "\u2022")} ${p}`);
  } else {
    out.push("");
    out.push(c(GREEN, "no problems"));
  }
  return out.join("\n");
}

// ── run ───────────────────────────────────────────────────────────────────────

try {
  if (flags.has("watch")) {
    const sec = Math.max(1, Number(flags.get("watch") === "true" ? 5 : flags.get("watch")));
    for (;;) {
      const v = await (siteMode ? fetchView<SiteView>("/api/site") : fetchView<FleetView>("/status"))
        .catch((e: Error) => e);
      // Clear and redraw rather than scrolling: during a rollout the useful thing is the current
      // state, and a scrolling log of near-identical tables buries it.
      process.stdout.write("\x1b[2J\x1b[H");
      console.log(
        v instanceof Error
          ? c(RED, v.message)
          : siteMode
            ? renderSite(v as SiteView)
            : render(v as FleetView),
      );
      console.log(c(DIM, `\n${new Date().toISOString()} — refreshing every ${sec}s, ctrl-c to stop`));
      await new Promise((r) => setTimeout(r, sec * 1000));
    }
  }

  const v = siteMode ? await fetchView<SiteView>("/api/site") : await fetchView<FleetView>("/status");
  console.log(
    flags.has("json")
      ? JSON.stringify(v, null, 2)
      : siteMode
        ? renderSite(v as SiteView)
        : render(v as FleetView),
  );
  // Non-zero when something needs attention, so this is usable from a cron or a CI check without
  // parsing the output.
  if (v.problems.length) process.exitCode = 1;
} catch (e) {
  console.error(`[status] ${e instanceof Error ? e.message : String(e)}`);
  process.exit(2);
}
