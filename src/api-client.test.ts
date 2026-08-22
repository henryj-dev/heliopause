// The plan printout — specifically the line that tells an operator what to run next.
//
// ## Why a test for a string
//
// It said `heliopause-approve <url> <hash>`, with no `--approve`. That command is the CLI's *list*
// mode: it prints the pending plans, which prints this very line again — so an operator who follows
// the instruction verbatim sees "approved — not yet" a second time and has approved nothing. It fails
// safely and it reads exactly like a refusal.
//
// Measured 2026-08-15, on a live proposal. Nothing caught it because the string had no test and the
// two halves live in different files: the message is written here, the flags are parsed in
// `bin/heliopause-approve.ts`, and neither knows what the other says.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { printPlan, requestPath, type PlanView } from "./api-client.ts";

const plan = (over: Partial<PlanView> = {}): PlanView => ({
  hash: "sha256:abc123",
  generation: "0000000",
  proposedBy: "ops-a",
  proposedAt: "2026-01-01T00:00:00.000Z",
  approval: null,
  publishedBy: null,
  publishedAt: null,
  summary: { hosts: [{ host: "h1", stage: "canary", ruleCount: 12, rulesetHash: "sha256:deadbeefdeadbeef" }] },
  ...over,
} as PlanView);

/** Capture what `printPlan` writes, so the instruction can be read the way an operator reads it. */
const printed = (p: PlanView): string => {
  const lines: string[] = [];
  const real = console.log;
  console.log = (...args: unknown[]) => void lines.push(args.join(" "));
  try {
    printPlan(p);
  } finally {
    console.log = real;
  }
  return lines.join("\n");
};

describe("the path sent to the manager", () => {
  it("keeps the query string lookup and where-used carry", () => {
    const base = "https://manager.example";
    const lookup = new URL("/api/policy/lookup?src=10.0.0.5&dst=10.0.0.6", base);
    assert.equal(requestPath(lookup), "/api/policy/lookup?src=10.0.0.5&dst=10.0.0.6");
    assert.equal(
      requestPath(new URL("/api/policy/where-used?q=10.0.0.0%2F8", base)),
      "/api/policy/where-used?q=10.0.0.0%2F8",
    );
    assert.equal(requestPath(new URL("/api/policy/where-used?q=", base)), "/api/policy/where-used?q=");
    assert.equal(requestPath(new URL("/api/site", base)), "/api/site");
  });
});

describe("the instruction printed to the operator", () => {
  it("names the VPC the plan is for when the manager sent one", () => {
    assert.match(printed(plan({ target: "dev" })), /target     dev/);
    assert.doesNotMatch(printed(plan()), /target/);
  });

  it("names the flag that actually approves", () => {
    // Without `--approve` the command means "list", and the CLI's own usage text is the authority on
    // that: `heliopause-approve <manager-url> <plan-hash> --approve`.
    const out = printed(plan());
    assert.match(out, /heliopause-approve <url> sha256:abc123 --approve/);
  });

  it("says who has to run it", () => {
    // The other half of the sentence, and the one the manager enforces. Losing it turns a two-person
    // control into a command someone runs twice and wonders why it fails.
    assert.match(printed(plan()), /A different operator/);
  });

  it("stops instructing once the plan is approved", () => {
    // An approved plan needs `--push`, not `--approve`. Printing the approve instruction next to an
    // approval that already happened is the same class of wrong answer as the missing flag.
    const out = printed(plan({ approval: { by: "ops-b", at: "2026-01-01T00:01:00.000Z" } } as Partial<PlanView>));
    assert.match(out, /approved   ops-b/);
    assert.doesNotMatch(out, /--approve/);
  });
});
