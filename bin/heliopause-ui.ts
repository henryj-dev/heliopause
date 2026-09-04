#!/usr/bin/env node
// The policy screens, served from where the policy is.
//
//   heliopause-ui <site-module> [--port=8500] [--open]
//
// ## Why this is a second surface and not another manager route
//
// The manager cannot answer these. It receives a `PlanBundle` — a manifest plus rendered nftables
// and Cilium text — and a bundle carries no zones, no address objects, no service catalogue and no
// policy rows. That is not an omission to fix: the manager pod runs inside the cluster it protects,
// so the policy repository is deliberately absent from its image.
//
// Nine of the fourteen designed screens are therefore workstation screens. 인터페이스-설계.md 결정 10
// has the split and the reasoning; this command is the first of them.
//
// ## Why it binds to loopback and has no authentication
//
// Both, and they are the same decision. Anyone who can run this can already read `policy/*.ts` — it
// is a file in a repository they have checked out. Putting a login in front of it would guard a door
// beside an open wall.
//
// **The bind address is the control.** On `0.0.0.0` this becomes an unauthenticated policy-disclosure
// service reachable from the network, and the policy is a map of every allowed path into the site.
// So the host is not configurable, and there is no flag to change it. If a future version needs to
// serve someone else, it needs a different design, not a wider bind.
//
// ## Why it runs the renderer
//
// A site module says which policies exist and which hosts they are listed against. It does **not**
// say which of them produce a rule — the renderer decides that, and skips one whose destination does
// not cover the host. Without running it, "renders on 3 hosts" would mean "listed next to 3 hosts",
// and a policy that protects nothing would look identical to one that works. That distinction is the
// most valuable thing this screen shows, so the renderer runs and the page says so when it did not.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";
import { policyPage } from "../src/policy-ui.ts";
import { buildScreen, type FleetAnswer } from "../src/policy-screen.ts";
import type { Site } from "./heliopause-publish.ts";
import type { AddressObject, FirewallObject, ServiceObject } from "../src/objects.ts";
import { loadPolicyDocument, putPolicy, removePolicy, replacePolicyPlacements, savePolicyDocument, type PolicyPlacement } from "../src/policy-store.ts";
import { applyPolicyDocument } from "../src/site-policy.ts";
import type { Policy } from "../src/policy.ts";
import { expectsJsonBody, isWriteMethod, localUiBoundaryError, readUiBody, UiRequestError } from "../src/local-ui-security.ts";
import { resolveWebRoot, serveConsole } from "../src/web-console.ts";
import { workstationAppPath } from "../src/app-shell.ts";
import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();

const args = process.argv.slice(2);
const flagValue = (name: string): string | undefined => {
  const hit = args.find((a) => a.startsWith(`${name}=`));
  return hit ? hit.slice(name.length + 1) : undefined;
};
const [siteArg] = args.filter((a) => !a.startsWith("--"));

if (!siteArg || args.includes("--help")) {
  console.error(
    "usage: heliopause-ui <site-module> [--port=8500] [--manager=URL] [--pki=DIR] [--operator=NAME] [--policies=FILE]\n" +
      "\n" +
      "  Serves the workstation screens on 127.0.0.1 only. --policies enables atomic editing.\n" +
      "  The renderer is run so the table can say which policies produce no rule at all.\n" +
      "\n" +
      "  --manager  fold the fleet's own state onto the hosts table. Needs an operator certificate,\n" +
      "             and the manager verifies against the internal CA — use its address, not its\n" +
      "             public name, whose certificate is a public one.\n",
  );
  process.exit(2);
}

const sitePath = resolve(siteArg);
const mod = (await import(pathToFileURL(sitePath).href)) as { site?: Site };
if (!mod.site) throw new Error(`${siteArg} does not export \`site\``);
const policyPath = flagValue("--policies") ? resolve(flagValue("--policies")!) : undefined;
let site = policyPath ? applyPolicyDocument(mod.site, loadPolicyDocument(policyPath)) : mod.site;

/**
 * Fold the manager's view onto the hosts, when one was given.
 *
 * **A failure here never blanks the page.** This is a viewer; the policy is on disk and readable
 * whether or not a manager answers, and hiding it because the fleet is unreachable would remove the
 * screen at the moment somebody is trying to work out why the fleet is unreachable. The hosts table
 * simply keeps its policy half, which is exactly what it knew before.
 */
type SiteAnswer = FleetAnswer;

async function askManager(): Promise<SiteAnswer | null> {
  const url = flagValue("--manager");
  if (!url) return null;
  try {
    const { api, operatorCreds } = await import("../src/api-client.ts");
    const creds = operatorCreds(resolve(flagValue("--pki") ?? "./pki"), flagValue("--operator"));
    return await api<SiteAnswer>(url, "/api/site", "GET", undefined, creds);
  } catch (e) {
    console.error(`[ui] the manager did not answer, so its half is not shown: ${(e as Error).message}`);
    return null;
  }
}


const build = () =>
  buildScreen({
    sitePath,
    label: siteArg,
    site: site as never,
    fleet: answer as never,
    editable: Boolean(policyPath),
    proposable: Boolean(policyPath && flagValue("--manager")),
    ...(flagValue("--manager") ? { manager: flagValue("--manager")! } : {}),
  });

const answer = await askManager();
let siteView: unknown = answer;
let { rows, meta, extra } = build();
const webRoot = resolveWebRoot(import.meta.dirname);
const serveApp = webRoot ? serveConsole(webRoot) : null;

const MANAGER_READS = new Set([
  "/api/plans",
  "/api/enrollment/requests",
  "/api/enrollment/tokens",
  "/api/enrollment/revocations",
  "/api/enrollment/audit",
]);

async function proxyManagerGet(path: string, res: ServerResponse, missing: string): Promise<void> {
  const manager = flagValue("--manager");
  if (!manager) {
    sendError(res, 503, missing);
    return;
  }
  try {
    const { api, operatorCreds } = await import("../src/api-client.ts");
    const creds = operatorCreds(resolve(flagValue("--pki") ?? "./pki"), flagValue("--operator"));
    const listing = await api<unknown>(manager, path, "GET", undefined, creds);
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(listing));
  } catch (e) {
    // 404 / 400 / 503 are answers the screens already know how to draw ("no reader",
    // "no policy repository", "port is not a port"). Collapsing them into 502 would
    // turn those sentences into a transport error.
    const status = e instanceof Error && "status" in e && typeof (e as { status: unknown }).status === "number"
      ? (e as { status: number }).status
      : 0;
    if (status === 400 || status === 404 || status === 503) {
      sendError(res, status, (e as Error).message);
      return;
    }
    sendError(res, 502, (e as Error).message);
  }
}

/**
 * Rebuild after an edit.
 *
 * The whole view, not the parts an edit was expected to touch. The version this replaced updated
 * five fields by hand — a policy edit that moved a zone crossing or a placement would have left the
 * old value on the page beside the new one, with nothing saying which was which.
 */
function refreshPolicyView(): void {
  ({ rows, meta, extra } = build());
}

const port = Number(flagValue("--port") ?? "8500");
if (!Number.isInteger(port) || port < 0 || port > 65_535) throw new Error("--port must be an integer from 0 to 65535");

function sendError(res: ServerResponse, status: number, error: string): void {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify({ error }));
}

const server = createServer((req, res) => {
  void handle(req, res).catch((e) => {
    if (res.headersSent) return void res.end();
    const status = e instanceof UiRequestError ? e.status : 500;
    sendError(res, status, status === 500 ? "internal error" : e.message);
  });
});

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const address = server.address();
  const listeningPort = typeof address === "object" && address ? address.port : port;
  const self = new URL(`http://127.0.0.1:${listeningPort}`);
  const url = new URL(req.url ?? "/", self);
  // Both derived from the method — see `isWriteMethod`. These used to be two hand-written lists of
  // (path, method) pairs, which is a way of remembering to register every new mutating route.
  const boundaryError = localUiBoundaryError(req.headers, self, {
    write: isWriteMethod(req.method),
    json: expectsJsonBody(req.method),
  });
  if (boundaryError) return sendError(res, boundaryError.status, boundaryError.message);

  if (serveApp?.(req, res)) return;

  if (url.pathname === "/api/site" && req.method === "GET") {
    if (!siteView) {
      return sendError(res, 503, "no manager — pass --manager to fold the fleet into this UI");
    }
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    return void res.end(JSON.stringify(siteView));
  }
  if (url.pathname === "/api/plans" && req.method === "GET") {
    return void await proxyManagerGet(url.pathname, res, "no manager — pass --manager to read pending plans");
  }
  if (url.pathname.startsWith("/api/enrollment/") && req.method === "GET") {
    if (!MANAGER_READS.has(url.pathname)) {
      return sendError(res, 404, "not found");
    }
    return void await proxyManagerGet(
      url.pathname,
      res,
      "no manager — pass --manager to read enrollment",
    );
  }
  if (url.pathname === "/api/policy/lookup" && req.method === "GET") {
    return void await proxyManagerGet(
      url.pathname + url.search,
      res,
      "no manager — pass --manager to look up a flow",
    );
  }
  if (url.pathname === "/api/policy/where-used" && req.method === "GET") {
    return void await proxyManagerGet(
      url.pathname + url.search,
      res,
      "no manager — pass --manager to find where a value is written",
    );
  }
  if (url.pathname === "/api/workload-traffic" && req.method === "GET") {
    return void await proxyManagerGet(
      url.pathname,
      res,
      "no manager — pass --manager to read workload traffic",
    );
  }
  if (url.pathname === "/api/routes" && req.method === "GET") {
    return void await proxyManagerGet(
      url.pathname,
      res,
      "no manager — pass --manager to compare routes",
    );
  }
  if (url.pathname === "/api/policy/screen" && req.method === "GET") {
    // The checkout is the policy source on a workstation. Proxying this to the
    // manager would answer from a different tree than the tables this process drew.
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    return void res.end(JSON.stringify({
      rows,
      extra,
      site: meta.site,
      generation: meta.generation,
      hosts: meta.hosts,
      canWrite: Boolean(policyPath),
    }));
  }

  if (url.pathname === "/api/policies" && req.method === "GET" && policyPath) {
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    return void res.end(JSON.stringify(loadPolicyDocument(policyPath)));
  }
  if (url.pathname === "/api/propose" && req.method === "POST" && policyPath && flagValue("--manager")) {
    try {
      const body = await readUiBody(req);
      const vpc = String((JSON.parse(body) as { vpc?: unknown }).vpc ?? "").trim();
      if (!/^[a-z0-9][a-z0-9-]{0,31}$/.test(vpc)) throw new Error("target VPC must be a lowercase identifier");
      const command = [resolve(import.meta.dirname, "heliopause-publish.ts"), sitePath, vpc,
        `--policies=${policyPath}`, `--propose=${flagValue("--manager")}`, `--pki=${resolve(flagValue("--pki") ?? "./pki")}`,
        ...(flagValue("--operator") ? [`--operator=${flagValue("--operator")}`] : [])];
      const output = execFileSync("node", command, { encoding: "utf8", cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"] });
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      return void res.end(JSON.stringify({ output }));
    } catch (e) {
      const error = e as { stderr?: Buffer | string; message: string };
      const status = e instanceof UiRequestError ? e.status : 400;
      sendError(res, status, String(error.stderr ?? error.message).trim());
      return;
    }
  }
  if (url.pathname.startsWith("/api/policies/") && req.method === "PUT" && policyPath) {
    try {
      const body = await readUiBody(req);
      const id = decodeURIComponent(url.pathname.slice("/api/policies/".length));
      const input = JSON.parse(body) as Policy | { policy: Policy; placements?: PolicyPlacement[] };
      const candidate = "policy" in input ? input.policy : input;
      const placements = "policy" in input ? input.placements : undefined;
      if (candidate.id !== id) throw new Error("URL policy id and body id differ");
      const current = loadPolicyDocument(policyPath);
      let updated = putPolicy(current, candidate).document;
      if (placements) updated = replacePolicyPlacements(updated, id, placements);
      const nextSite = applyPolicyDocument(mod.site!, updated);
      savePolicyDocument(policyPath, updated);
      site = nextSite;
      refreshPolicyView();
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      return void res.end(JSON.stringify({ policy: updated.policies.find((policy) => policy.id === id), placements: updated.placements?.filter((placement) => placement.policyId === id) ?? [] }));
    } catch (e) {
      sendError(res, e instanceof UiRequestError ? e.status : 400, (e as Error).message);
      return;
    }
  }
  if (url.pathname.startsWith("/api/policies/") && req.method === "DELETE" && policyPath) {
    try {
      const id = decodeURIComponent(url.pathname.slice("/api/policies/".length));
      const updated = removePolicy(loadPolicyDocument(policyPath), id); const nextSite = applyPolicyDocument(mod.site!, updated);
      savePolicyDocument(policyPath, updated); site = nextSite; refreshPolicyView();
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }); return void res.end(JSON.stringify({ deleted: id }));
    } catch (e) {
      res.writeHead(400, { "content-type": "application/json", "cache-control": "no-store" }); return void res.end(JSON.stringify({ error: (e as Error).message }));
    }
  }
  if (req.method !== "GET") {
    res.writeHead(405, { allow: "GET" });
    return void res.end();
  }
  // `/app` is the console. These paths keep bookmarks and the old listen URL.
  // Without a build the classic page stays — a workstation with no `packages/web/build`
  // still has to show the tables when the cluster does not.
  if (webRoot) {
    const to = workstationAppPath(url.pathname, url.searchParams.get("s"));
    if (to) {
      res.writeHead(302, { location: to, "cache-control": "no-store" });
      return void res.end();
    }
  }
  // No `Set-Cookie`, no session, nothing to protect against cross-site requests — this server holds
  // no authority. `X-Content-Type-Options` still matters: it is the one header that stops a policy
  // name from being sniffed into something executable.
  res.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  // A checkout is a place to scroll, and this page is served to one reader on loopback.
  // The manager splits sections because it is the address people open; here it would only
  // add a click between an operator and the table they already know they want.
  res.end(policyPage(rows, { ...meta, section: "all" }, extra));
}

// Loopback, not configurable. See the header.
server.listen(port, "127.0.0.1", () => {
  const address = server.address();
  const listeningPort = typeof address === "object" && address ? address.port : port;
  const placement = meta.generation ? "renderer run" : "placement not computed";
  console.log(
    `heliopause-ui — ${rows.length} policies · ${extra.baseline?.length ?? 0} baseline · ` +
      `${extra.hosts?.length ?? 0} hosts · ${extra.workload?.length ?? 0} workload, from ${siteArg} (${placement})\n` +
      `  http://127.0.0.1:${listeningPort}${webRoot ? "/app/policy/all" : "/"}`,
  );
});
