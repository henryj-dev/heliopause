#!/usr/bin/env node
// Review, approve and push a proposed generation.
//
//   heliopause-approve <manager-url> [--pki=DIR] [--operator=NAME]              list pending plans
//   heliopause-approve <manager-url> <plan-hash> --show [--rules]               read what it changes
//   heliopause-approve <manager-url> <plan-hash> --approve                      approve one
//   heliopause-approve <manager-url> <plan-hash> --push                         publish an approved one
//
// The other half of `heliopause-publish --propose`. Separate command because it is a separate person:
// the manager refuses an approval from whoever proposed the plan, so these are run from different
// workstations with different certificates.
//
// ## Why approving and pushing are separate flags
//
// They could be one step — approve and immediately publish. They are not, because the approver is the
// person who did *not* render the plan, and making their action also push means the fleet changes at
// the moment someone finishes reading a diff. Splitting them means the change happens when somebody
// chooses to make it happen, which for a firewall is worth one extra command.
//
// Either operator may push; the manager does not require it to be the proposer or the approver. The
// rule is that two people signed off, not that a particular one runs the push — requiring that would
// make the fleet unpublishable whenever one of them is away.
//
// ## What this cannot do
//
// Approve its own proposal, publish an unapproved plan, or publish one twice. None of those are
// enforced here — this is a client, and a client enforcing them would be a suggestion. They are
// enforced by the manager, which is the thing holding the state.

import { resolve } from "node:path";
import { api, ApiError, operatorCreds, printPlan, type PlanView } from "../src/api-client.ts";
import { NoPromptError, otpFor } from "../src/otp-prompt.ts";
import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();

const args = process.argv.slice(2);
const flags = new Map(
  args
    .filter((a) => a.startsWith("--"))
    .map((a) => {
      const [k, v] = a.replace(/^--/, "").split("=", 2);
      return [k!, v ?? "true"];
    }),
);
const [managerUrl, hash] = args.filter((a) => !a.startsWith("--"));

if (!managerUrl || flags.has("help")) {
  console.error(
    "usage: heliopause-approve <manager-url> [--pki=DIR] [--operator=NAME]\n" +
      "       heliopause-approve <manager-url> <plan-hash> --show [--rules]\n" +
      "       heliopause-approve <manager-url> <plan-hash> --approve\n" +
      "       heliopause-approve <manager-url> <plan-hash> --push\n" +
      "\n" +
      "  no flag     list pending plans\n" +
      "  --show      read what this plan changes: the policy diff, and what each host's rules\n" +
      "              become. Run this before --approve — without it, approving is a comparison\n" +
      "              of hashes and no check at all on what the rules say.\n" +
      "  --rules     with --show, also print each host's full rendered ruleset (the bytes the\n" +
      "              agent applies, which is what rulesetHash covers).\n" +
      "  --approve   approve a plan. Must be a different operator than the one who proposed it.\n" +
      "  --push      publish an approved plan to its target VPC. This changes the fleet.\n" +
      "\n" +
      "  --pki=DIR        directory holding ca.pem and operator-<name>.pem/.key (default ./pki)\n" +
      "  --operator=NAME  which operator certificate to present (default: the only one present)\n" +
      "  --otp=CODE       the one-time code. Omit it and you are asked, without echo, which is\n" +
      "                   preferred: a code on the command line is kept in shell history.\n" +
      "                   HELIOPAUSE_OTP is read too, for scripts.\n",
  );
  process.exit(2);
}

// Narrowed once, here, because the guard above does not follow into a function body — `show` would
// otherwise see `string | undefined` for something the process has already exited without.
const manager: string = managerUrl;

const creds = operatorCreds(resolve(flags.get("pki") ?? "./pki"), flags.get("operator"));

/** Where the manager's refusals get turned into something actionable. */
function fail(e: unknown): never {
  if (e instanceof NoPromptError) {
    console.error(`\n${e.message}`);
    process.exit(2);
  }
  if (e instanceof ApiError) {
    console.error(`\n${e.message}`);
    if (e.status === 401) {
      console.error("  Retype it — a code is single-use and expires in about thirty seconds.");
    }
    if (e.status === 503) {
      // The distinction `otp.ts` exists to preserve. Retyping a correct code against a broken
      // service token is the loop this line is here to stop.
      console.error(
        "  This is the deployment, not your code — the manager could not reach the identity\n" +
          "  provider, or its service token was refused. Retyping will not help; check the\n" +
          "  manager's log, which names which of the two it was.",
      );
    }
    if (e.status === 403) {
      // Several 403s mean quite different things and all are common. Distinguishing them saves an
      // operator from checking their certificate when the answer is "get someone else to approve
      // it" — or from checking anything at all when the answer is at the identity provider.
      console.error(
        e.message.includes("one-time code")
          ? `  ${creds.name} has no TOTP enrolled at the identity provider, or is not mapped to an\n` +
            `  account there. Neither is fixed from this side — see HELIOPAUSE_OTP_USERS.`
          : e.message.includes("cannot approve")
            ? "  This is the two-person rule working. Someone who did not propose it must approve it."
            : e.message.includes("not been approved")
              ? "  Approve it first: heliopause-approve <url> <hash> --approve (as a different operator)"
              : `  Add ${creds.name} to the manager's HELIOPAUSE_WRITER_CNS if it should be able to do this.`,
      );
    }
    if (e.status === 410) {
      console.error("  Re-render and re-propose, so what is published describes the policy as it is now.");
    }
    process.exit(1);
  }
  throw e;
}

// ── What the second person is agreeing to ─────────────────────────────────────
//
// ## Why this had to exist
//
// `manager-server.ts` wrote the problem down and then solved it for one audience:
//
//   > The approver saw a host name, a stage, a rule *count* and a digest. Nothing else. So approval
//   > was a comparison of hashes — which is a real check against tampering in transit and no check
//   > at all on what the rules say.
//
// Three routes were added for that — `/changes`, `/ruleset`, `/ruleset-diff` — and all three were
// reachable only from the browser. `/ruleset-diff` had **no caller anywhere**: implemented, tested,
// and never fetched by any screen or command. So for a CLI approver the two-person rule was still
// a hash comparison, which is the thing the routes were built to end.
//
// ## What it shows, in the order an approver needs it
//
//   1. the policy diff — the text a person wrote, which is where intent lives
//   2. per host, what the *rules* become — because one edit to an address object moves every rule
//      that names it, and a rule can move with no line of policy changing at all
//
// The full rendered ruleset is behind `--rules`. It is what lands and it is worth having, but six
// hosts of nft JSON is not something anyone reads by default, and a screen nobody reads is the
// failure this is fixing rather than a second instance of it.
async function show(planHash: string, withRules: boolean): Promise<void> {
  const encoded = encodeURIComponent(planHash);
  const { plans } = await api<{ plans: PlanView[] }>(manager, "/api/plans", "GET", undefined, creds);
  const plan = plans.find((p) => p.hash === planHash);
  if (!plan) throw new ApiError(`no pending plan ${planHash} — it may have expired or been published`, 404);
  printPlan(plan);

  // Reported, never swallowed. An approver shown nothing concludes nothing changed, and every one of
  // these routes answers 200 with an `unavailable` sentence rather than an error for exactly that
  // reason — so the sentence has to reach the terminal.
  console.log("\n── what changed in the policy ──");
  const changes = await api<{
    unavailable?: string; same?: boolean; base?: string; head?: string;
    commits?: { sha: string; message: string; author: string }[];
    files?: { filename: string; status: string; additions: number; deletions: number }[];
    generated?: { filename: string; additions: number; deletions: number }[];
  }>(manager, `/api/plans/${encoded}/changes`, "GET", undefined, creds);
  if (changes.unavailable) {
    console.log(`  ${changes.unavailable}`);
  } else if (changes.same) {
    console.log(`  nothing — the fleet is already on ${changes.head}`);
  } else {
    console.log(`  ${changes.base} → ${changes.head}`);
    for (const c of changes.commits ?? []) console.log(`  ${c.sha}  ${c.message}  (${c.author})`);
    for (const f of changes.files ?? []) {
      console.log(`    ${f.status.padEnd(9)} ${f.filename}  +${f.additions} -${f.deletions}`);
    }
    // Listed, never hidden: the generation being approved does contain them, and an approver who
    // later found unlisted changes in it would be right to distrust this output. Summarised, because
    // the first real diff this console produced was 174 of 176 lines of coverage output with the one
    // authored line underneath.
    const generated = changes.generated ?? [];
    if (generated.length) {
      const added = generated.reduce((n, f) => n + f.additions, 0);
      const removed = generated.reduce((n, f) => n + f.deletions, 0);
      console.log(`    generated ${generated.length} file(s), +${added} -${removed} (machine-written)`);
    }
  }

  for (const host of plan.summary.hosts) {
    console.log(`\n── ${host.host}  ${host.stage}  ${host.ruleCount} rules ──`);
    const diff = await api<{
      unavailable?: string; added?: boolean; base?: string;
      changes?: { comment: string; kind: "added" | "removed" | "changed" }[];
      unchanged?: number; before?: number; after?: number;
    }>(manager, `/api/plans/${encoded}/ruleset-diff?host=${encodeURIComponent(host.host)}`, "GET", undefined, creds);
    if (diff.unavailable) {
      console.log(`  ${diff.unavailable}`);
    } else if (diff.added) {
      console.log(`  new host — every rule is an addition`);
    } else if (!diff.changes?.length) {
      console.log(`  no rule changed (${diff.unchanged ?? 0} unchanged)`);
    } else {
      // Removals first, which is the order the server produced them in and the order that matters:
      // a rule that disappeared is the one that opens a port, and it is the change an approver is
      // least likely to notice on their own.
      for (const c of diff.changes) {
        console.log(`  ${c.kind === "removed" ? "-" : c.kind === "added" ? "+" : "~"} ${c.comment}`);
      }
      console.log(`  ${diff.before} rules → ${diff.after}, ${diff.unchanged ?? 0} unchanged`);
    }
    if (withRules) {
      const full = await api<{ ruleset: string; rulesetHash: string }>(
        manager, `/api/plans/${encoded}/ruleset?host=${encodeURIComponent(host.host)}`, "GET", undefined, creds,
      );
      // The stored bytes, which are what the agent applies and what `rulesetHash` covers — not a
      // fresh render of the same policy. See the route's own comment.
      console.log(`  ${full.rulesetHash}`);
      for (const line of full.ruleset.split("\n")) console.log(`    ${line}`);
    }
  }
  console.log(`\nTo approve: heliopause-approve ${manager} ${planHash} --approve`);
}

try {
  if (flags.has("approve")) {
    if (!hash) throw new Error("--approve needs a plan hash");
    // Asked before the request, not after a 401. The manager refuses without a code, so prompting
    // first turns one round trip into one; prompting on the refusal would mean the operator sees a
    // failure for something they were never asked for.
    const otp = await otpFor("approving this plan", flags.get("otp"));
    const p = await api<PlanView>(managerUrl, "/api/approve", "POST", { hash, otp }, creds);
    console.log(`approved as ${creds.name}\n`);
    printPlan(p);
    console.log(`\nTo publish: heliopause-approve ${managerUrl} ${p.hash} --push`);
  } else if (flags.has("push")) {
    if (!hash) throw new Error("--push needs a plan hash");
    // A second code, not the one used to approve. The IdP refuses a code at or below the last step
    // it accepted, so pushing right after approving waits for the next thirty-second window — which
    // is the mechanism working, not a bug to route around.
    const otp = await otpFor("publishing to the fleet", flags.get("otp"));
    const r = await api<{
      published: boolean;
      target: string;
      generation: string;
      serving: string | null;
      proposedBy: string;
      approvedBy: string | null;
      publishedBy: string;
    }>(managerUrl, "/api/publish", "POST", { hash, otp }, creds);
    console.log(`published ${r.generation} to ${r.target}`);
    console.log(`  proposed by ${r.proposedBy}, approved by ${r.approvedBy}, pushed by ${r.publishedBy}`);
    // The relay's own answer about what it is now serving, not what we sent. "We wrote it" and "it is
    // serving it" are different claims and only the second means the rollout has started.
    console.log(`  ${r.target} is serving ${r.serving ?? "(nothing — check the relay's journal)"}`);
    if (r.serving !== r.generation) {
      console.error(
        `\nWARNING: ${r.target} accepted the generation but reports serving ${r.serving}. ` +
          `Check that relay before assuming the rollout has begun.`,
      );
      process.exit(1);
    }
    console.log(`\nWatch it roll out: heliopause-status ${managerUrl} --site --watch`);
  } else if (flags.has("show")) {
    if (!hash) throw new Error("--show needs a plan hash");
    await show(hash, flags.has("rules"));
  } else {
    const { plans, limits } = await api<{
      plans: PlanView[];
      limits: { ttlSec: number; maxPending: number };
    }>(managerUrl, "/api/plans", "GET", undefined, creds);
    if (plans.length === 0) {
      console.log("no pending plans");
    } else {
      console.log(`${plans.length} pending plan(s), each publishable for ${limits.ttlSec}s from proposal\n`);
      for (const p of plans) {
        printPlan(p);
        console.log("");
      }
    }
  }
} catch (e) {
  fail(e);
}
