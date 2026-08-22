#!/usr/bin/env node
// Review, approve and push a proposed generation.
//
//   heliopause-approve <manager-url> [--pki=DIR] [--operator=NAME]              list pending plans
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
      "       heliopause-approve <manager-url> <plan-hash> --approve\n" +
      "       heliopause-approve <manager-url> <plan-hash> --push\n" +
      "\n" +
      "  no flag     list pending plans\n" +
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
