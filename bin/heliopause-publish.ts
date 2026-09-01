#!/usr/bin/env node
// Publish a generation: render every host and write the artifact directory the relay serves.
//
//   heliopause-publish <site-module> <artifact-dir> [--allow-dirty] [--dry-run]
//
// The site module exports a `site` object naming the config and the hosts. Everything specific to
// a deployment lives there; this file only decides *whether* to publish and where to put it.

import { execFileSync } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { planPublish, type PublishHost } from "../src/publish.ts";
import {
  signAuthorizedArtifactBundle,
  artifactSigningKeyId,
  writeAuthorizedArtifactBundle,
  privateKeyFileModeError,
  privateKeyFileOwnerError,
} from "../src/artifact-signature.ts";
import type { Config } from "../src/config.ts";
import type { FirewallObject } from "../src/objects.ts";
// Type-only, so it stays a static import while the API client itself is loaded lazily below — the
// direct publish path must not need it. A `type` specifier inside a destructuring `await import` is
// not valid syntax, and `tsc` accepts it: only running the file catches that.
import type { PlanView } from "../src/api-client.ts";
import { podsFromMembership, membershipJumps, type CiliumItem, type ResolveService, type WorkloadBaseline } from "../src/cilium.ts";
import {
  asPodLists,
  countsFrom,
  readMembershipRecord,
  writeMembershipRecord,
} from "../src/membership-record.ts";
import type { SelectorMembership } from "../src/protocol.ts";
import type { Zone } from "../src/zones.ts";
import type { ApprovedDevice } from "../src/device-view.ts";
import type { CoverageCheck } from "../src/coverage.ts";
import { loadPolicyDocument } from "../src/policy-store.ts";
import { applyPolicyDocument } from "../src/site-policy.ts";

export interface Site {
  cfg: Config;
  hosts: PublishHost[];
  /**
   * Policies for the workload layer. Not per-host — a CiliumNetworkPolicy is cluster-scoped, so the
   * whole set renders once and lands on `cfg.workload.applier`.
   */
  workload?: CiliumItem[];
  /** Namespace posture declarations, rendered alongside workload flows. */
  workloadBaselines?: WorkloadBaseline[];
  resolveService?: ResolveService;
  /**
   * Named ranges and how far this deployment trusts each (`zones.ts`).
   *
   * Optional, and absent means the zone screen renders nothing rather than guessing. There is no
   * property of an address that yields a trust level — it is a judgement about this deployment, so
   * a default here would be a number nobody decided appearing in a column that looks like a control.
   *
   * Not read by the renderer. Zones describe the policy set; they do not change what it renders.
   */
  zones?: Zone[];
  /**
   * The approved device registry (`device-view.ts`, H12).
   *
   * Cloudflare assigns these addresses and reassigns them on re-registration, so this list is a
   * record of what a human approved, not a live reading. The sync path compares it against the
   * registry and proposes a diff; git remains the interface for changing it, as with every other
   * policy edit.
   */
  devices?: ApprovedDevice[];
  /**
   * Coverage checks (`coverage.ts`, screen 13).
   *
   * The only readings in this system that do not come from an agent. Optional, and absent means
   * the screen renders nothing rather than an empty table implying everything passed.
   *
   * Not read by the renderer — these describe what the firewall should do, measured from outside.
   */
  coverage?: CoverageCheck[];
  /**
   * Reusable address and service objects (`objects.ts`).
   *
   * Optional, and this site uses none — every endpoint across all three VPCs is a literal `cidr` or
   * `host`. The field exists because the model does and a site had nowhere to carry them:
   * `heliopause-ui` projects the catalogue, and without this there was nothing to project.
   */
  objects?: FirewallObject[];
}

import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();
const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith("--")));

/** `--pki=./pki` → `./pki`. Undefined when the flag was not given. */
const flagValue = (name: string): string | undefined => {
  const hit = args.find((a) => a.startsWith(`${name}=`));
  return hit ? hit.slice(name.length + 1) : undefined;
};
const [siteArg, dirArg] = args.filter((a) => !a.startsWith("--"));

/**
 * `--propose=https://manager:8444` switches the second positional from a directory to a VPC name.
 *
 * Two modes in one command rather than two commands, because the rendering must be identical. A
 * separate proposer would be a second code path producing what gets published, and the whole reason
 * the CLI is moving onto the API is that a plan shown by one path and published by another drift.
 */
const propose = flagValue("--propose");

if (!siteArg || !dirArg) {
  console.error(
    "usage: heliopause-publish <site-module> <artifact-dir> --break-glass --target=NAME --signing-key=FILE --key-id=sha256:... [--authorization-ttl-sec=900] [--allow-dirty] [--dry-run]\n" +
      "       heliopause-publish <site-module> <vpc-name> --propose=<manager-url> [--pki=DIR] [--operator=NAME]\n" +
      "\n" +
      "  --policies=FILE overlays an exact-id JSON policy document created by heliopause-policy.\n" +
      "\n" +
      "  Without --propose, direct publication is an explicit break-glass operation. Its offline\n" +
      "  Ed25519 key must be separate from the manager key and the authorization expires.\n" +
      "\n" +
      "  With --propose it is submitted to the manager for a second operator to approve, and\n" +
      "  <vpc-name> names which relay it is for (the manager's HELIOPAUSE_RELAYS name).\n",
  );
  process.exit(2);
}

/** Run git against the repository holding the site module, not the process's cwd. */
const gitIn = (dir: string, ...a: string[]) =>
  execFileSync("git", ["-C", dir, ...a], { encoding: "utf8" }).trim();

/**
 * The generation id is a git commit, so it has to actually identify the content.
 *
 * With uncommitted changes it does not: two publishes claim the same generation while shipping
 * different rules, and every audit trail that keys off the id — which is all of them, by design —
 * silently describes the wrong thing. Refusing here is cheaper than discovering it later from a
 * ruleset that does not match the commit it names.
 *
 * ## Two ways that guarantee was quietly lost, both fixed here
 *
 * **The repository has to be the one holding the policy.** The site module is loaded from an
 * arbitrary path, so under the documented operating model — the public library and the site's policy
 * in separate repositories — the id came from whatever repository the operator happened to be
 * standing in. It described the wrong tree, and described it confidently. The fix is that every
 * `git` call here is `-C dirname(sitePath)`: the policy's own repository, not the caller's cwd.
 *
 * **That is also the whole mechanism.** There is no flag for selecting a policy repository, and the
 * `policyStore` field in `src/config.ts` is read by nothing. Publishing from inside the policy
 * repository is what makes the id name the policy — which is why this file's errors say to move the
 * policy rather than to configure something.
 *
 * **The site module has to be tracked.** `git status` says nothing about ignored files, so once
 * `policy/dev.ts` was moved out of version control the dirty check stopped seeing edits to the very
 * file being published. Measured: editing the policy left the tree reading clean, and the publish
 * reused the previous commit's id for materially different rules.
 *
 * The fix is `check-ignore` on the site module rather than `status --ignored`. Listing every ignored
 * file would refuse to publish over `node_modules/` and `pki/` — a check that always fails is a
 * blocker, not a check. What matters is narrower and exact: is *this policy* in the history the id
 * names?
 */
function generationId(siteDir: string, sitePath: string, policyPath?: string): string {
  let dirty = "";
  try {
    dirty = gitIn(siteDir, "status", "--porcelain");
  } catch {
    // No repository at all. `--allow-dirty` already means "I know this id is approximate", and
    // refusing here anyway made that flag mean different things in two situations that differ only
    // in degree — a tree with uncommitted edits versus one with no history to be uncommitted
    // against. It also broke `rollback-test.sh`, which builds a site module in a temporary directory
    // on purpose: the thing under test is the kernel, not the audit trail.
    if (!flags.has("--allow-dirty")) {
      throw new Error(
        `${siteDir} is not inside a git repository — the generation id has nothing to be. The site ` +
          `module's own repository is what the id must describe, so run \`git init\` there and commit ` +
          `the policy (the documented split: the library public, the policy private), or pass ` +
          `--allow-dirty for a throwaway.`,
      );
    }
    // Timestamped rather than a fixed string, so two throwaway publishes never claim one id. It
    // cannot identify content — nothing here can — but it can at least stop two different rulesets
    // from being indistinguishable in a log.
    return `no-git-${Math.floor(Date.now() / 1000)}`;
  }

  // Exit 0 means the path is ignored. Untracked-but-not-ignored is caught by `status` above, so this
  // covers the remaining case: a policy deliberately excluded from the repository it is published
  // from, whose content therefore cannot be in any commit.
  let ignored = false;
  try {
    execFileSync("git", ["-C", siteDir, "check-ignore", "-q", sitePath], { stdio: "ignore" });
    ignored = true;
  } catch {
    ignored = false;
  }
  if (ignored && !flags.has("--allow-dirty")) {
    throw new Error(
      `${sitePath} is ignored by its repository, so the generation id cannot describe it.\n` +
        `Two publishes would claim the same id while shipping different rules.\n\n` +
        `Make the directory holding this policy its own git repository and commit the policy there\n` +
        `(the documented split: the library public, the policy private). The id is taken from the\n` +
        `site module's own repository, so that is all it takes — there is no flag to set.\n` +
        `Or pass --allow-dirty for a throwaway.`,
    );
  }

  if (dirty && !flags.has("--allow-dirty")) {
    throw new Error(
      `working tree has uncommitted changes, so the commit id would not describe what is being\n` +
        `published. Commit first, or pass --allow-dirty if this is a throwaway.\n\n${dirty}`,
    );
  }
  const head = gitIn(siteDir, "rev-parse", "--short", "HEAD");
  if (!dirty && !ignored) {
    if (!policyPath) return head;
    const policyHash = createHash("sha256").update(readFileSync(policyPath)).digest("hex").slice(0, 8);
    return `${head}-policy-${policyHash}`;
  }

  // ## Why the approximate id still has to be unique
  //
  // This returned the constant `${head}-dirty`, and that made two *different* rulesets share one id
  // for as long as HEAD stood still. Which is always, in the documented operating model: `policy/` is
  // ignored on purpose, so `ignored` is permanently true and no policy edit moves HEAD.
  //
  // The consequence is not a cosmetic one. `heliopause-pull.py` skips an artifact whose generation
  // equals the one it has already confirmed:
  //
  //     if wanted == st["generation"] and st["state"] == "confirmed": return
  //
  // So a publish that changes real rules under a repeated id is accepted by the relay, reported by
  // every agent as `confirmed`, and never applied. The fleet view says the new generation is live
  // while the kernel is still running the old one — a firewall reporting the opposite of the truth,
  // which is the single worst failure this project can have.
  //
  // Measured 2026-08-02: the live generation was `8b59baf-dirty` and a publish adding two hosts and
  // opening a public port produced `8b59baf-dirty` again.
  //
  // ## What the suffix hashes
  //
  // The site module's own bytes, plus `git diff HEAD` for the tracked files it imports. Between them
  // they cover both halves of the split model — the ignored policy by content, and uncommitted edits
  // to the renderer by content. `status --porcelain` alone would not do: it lists paths, so editing
  // the same file twice produces the same output.
  //
  // This is still an approximation and is meant to read as one. It is not a content address of the
  // published plan — an import this file cannot see could change without changing the id. `-dirty`
  // is kept in front of the hash so the id remains visibly non-reproducible at a glance, which is the
  // property `--allow-dirty` is trading away.
  const h = createHash("sha256");
  h.update(readFileSync(sitePath));
  h.update("\0");
  h.update(dirty);
  h.update("\0");
  try {
    h.update(gitIn(siteDir, "diff", "HEAD"));
  } catch {
    // An unborn HEAD has nothing to diff against. The site module's bytes are already in the hash,
    // so the id stays distinguishing; there is nothing to report.
  }
  if (policyPath) h.update(readFileSync(policyPath));
  return `${head}-dirty-${h.digest("hex").slice(0, 8)}`;
}

const sitePath = resolve(siteArg);
const siteUrl = pathToFileURL(sitePath).href;
const mod = (await import(siteUrl)) as { site?: Site };
if (!mod.site) throw new Error(`${siteArg} does not export \`site\``);
const policyPath = flagValue("--policies") ? resolve(flagValue("--policies")!) : undefined;
const site = policyPath
  ? applyPolicyDocument(mod.site, loadPolicyDocument(policyPath))
  : mod.site;

const generation = generationId(dirname(sitePath), sitePath, policyPath);

/**
 * Pod membership as the applier last reported it, read back from a relay (H14a).
 *
 * **A failure here never stops a publish.** The reading makes the plan more legible — it is what
 * turns "membership not reported" into a pod list — but a firewall generation that cannot be
 * published because an observation endpoint was unreachable would be the tail wagging the dog. So
 * this warns and returns undefined, and the render says "not known", which is exactly true.
 */
async function readMembership(): Promise<SelectorMembership | undefined> {
  const url = flagValue("--membership-from");
  if (!url) return undefined;
  // Resolved against *this* process's cwd before being handed on. `heliopause-status` resolves a
  // relative `--pki` against its own, and the two are not the same when it runs as a child — measured:
  // `--pki=./pki` became `/private/tmp/pki` and the read failed with a path the operator never typed.
  const pki = resolve(flagValue("--pki") ?? "./pki");
  try {
    // `heliopause-status` exits 1 when the fleet has problems — a silent host, a drift — and that is
    // correct for a human at a terminal. Here it made `--membership-from` unusable exactly when it
    // matters: `execFileSync` throws on a non-zero exit, the JSON on stdout was discarded, and the
    // failure surfaced as "cannot read membership", which reads as an unreachable endpoint. Measured
    // 2026-08-11 with one host out of service.
    //
    // So the output is taken from the error too. What decides usability here is whether the body
    // parses, not whether the fleet is healthy.
    let out: string;
    try {
      out = runStatus();
    } catch (e) {
      const partial = (e as { stdout?: string }).stdout;
      if (!partial) throw e;
      out = partial;
    }
    const view = JSON.parse(out) as {
      hosts: Array<{ host: string; workload?: { membership?: SelectorMembership | null } | null }>;
    };
    // The applier is the only host that reports one, so the first non-null is the answer.
    const found = view.hosts.find((h) => h.workload?.membership)?.workload?.membership;
    if (!found) {
      console.warn(`[publish] ${url} has no membership reading yet — pod lists will show as unknown`);
      return undefined;
    }
    // Printed with its own timestamp rather than silently trusted: pod membership goes stale in
    // seconds, and an operator reading a pod list needs to know when it was true.
    console.log(`[publish] membership as of ${found.at} (from ${url})`);
    return found;
  } catch (e) {
    console.warn(`[publish] cannot read membership from ${url}: ${(e as Error).message}`);
    console.warn(`[publish] continuing — pod lists will show as unknown`);
    return undefined;
  }

  function runStatus(target = url as string): string {
    return execFileSync(
      "node",
      [
        resolve(dirname(fileURLToPath(import.meta.url)), "heliopause-status.ts"),
        target,
        `--pki=${pki}`,
        // Passed through, and its absence was a real defect: this PKI directory holds three operator
        // certificates, so the child refused with "several operator certificates … pass
        // --operator=NAME" on every run. `--membership-from` could not be used on this fleet at all,
        // and the failure looked like the endpoint being unreachable because that is the branch it
        // lands in.
        ...(flagValue("--operator") ? [`--operator=${flagValue("--operator")}`] : []),
        "--json",
      ],
      // stderr inherited, not captured. A failure here is reported by the child in a sentence written
      // for a human ("no ca.pem in …"), and swallowing it leaves only "Command failed", which says
      // nothing an operator can act on.
      { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] },
    );
  }
}

const membership = await readMembership();

// Stamped once here rather than inside the planner, which stays pure so it can be tested without
// a clock.
const plan = planPublish({
  ...site,
  generation,
  issuedAt: new Date().toISOString(),
  // The site module may inject its own; an explicit `--membership-from` reading wins because it came
  // from the cluster rather than from a file.
  ...(membership ? { resolvePods: podsFromMembership(membership) } : {}),
});

console.log(`generation ${generation}  (${plan.artifacts.length} hosts)`);
for (const a of plan.artifacts) {
  // "policy rules" rather than "rules": this excludes the baseline, conntrack and loopback rules the
  // same render emits, so a host with no policy at all correctly reads `0 policy rules` while still
  // permitting SSH. The manager's plan summary counts every rule in the artifact, and the two numbers
  // disagreeing for one generation is expected — measured, and confusing until both said which.
  console.log(`  ${a.host.padEnd(16)} ${a.entry.stage.padEnd(8)} ${a.ruleCount} policy rules  ${a.entry.rulesetHash.slice(0, 20)}`);
  for (const s of a.skipped) console.log(`      skipped ${s.policyId}: ${s.reason}`);
}

// The workload half, if any. Printed in full rather than summarised: these are the policies with no
// host-layer rule behind them, so the objects and the pods they select are what an operator has to
// read before believing the generation. Warnings are not indented under a host because they belong to
// the cluster, not to the node that happens to apply them.
if (plan.workload) {
  const w = plan.workload;
  console.log(
    `\nworkload  cluster ${w.cluster}  applier ${w.applier}  ` +
      `${w.entry.policyCount} object(s)  ${w.entry.policiesHash.slice(0, 20)}`,
  );
  for (const o of w.entry.mustExist) console.log(`  ${o}`);
  // Keyed by policy id, so it is printed as its own list rather than joined onto the object names —
  // deriving one from the other would mean parsing the slug back, which is not reversible.
  //
  // Three outcomes, printed differently on purpose (H14a). "selects nothing" is a claim about the
  // cluster; "membership not reported" is a claim about what we know. An operator deciding whether a
  // containment policy is live needs to tell them apart, and printing both as an absence — which is
  // what this did before membership was reported at all — hides the difference.
  for (const [policyId, pods] of Object.entries(w.affectedPods)) {
    if (pods === null) console.log(`  ${policyId} — membership not reported`);
    else if (pods.length === 0) console.log(`  ${policyId} selects nothing right now`);
    else console.log(`  ${policyId} selects ${pods.join(", ")}`);
  }
  for (const s of w.skipped) console.log(`      skipped ${s.policyId}: ${s.reason}`);
  // Never suppressed and never folded into a count. Each one means the rendered rule is narrower or
  // wider than what was written.
  for (const warn of w.warnings) console.log(`      WARNING ${warn.policyId}: ${warn.warning}`);
}

if (flags.has("--dry-run")) {
  console.log("dry run — nothing written");
} else if (propose) {
  // ## The API mode: propose, do not publish
  //
  // This renders exactly as the direct mode does and submits the result to the manager, which stores
  // it and waits for a second operator. It cannot publish — that is `heliopause-approve` followed by
  // `heliopause-push`, and the separation is the point (docs/인터페이스-설계.md 결정 4).
  //
  // ## Why the renderer runs here and not in the manager
  //
  // The manager has no policy and must not: its image runs inside the cluster whose firewall it
  // governs, and the policy repository is private. So the rendering happens where the policy is — on
  // an operator's workstation — and the manager's contribution is the part a workstation cannot do:
  // remembering who proposed what, requiring someone else, and being the only thing that can reach
  // every relay.
  const { bundleFromPlan } = await import("../src/bundle.ts");
  const { api, ApiError, operatorCreds, printPlan } = await import("../src/api-client.ts");
  const creds = operatorCreds(resolve(flagValue("--pki") ?? "./pki"), flagValue("--operator"));
  const bundle = bundleFromPlan(plan);
  console.log(`\nproposing to ${propose} as ${creds.name} (target ${dirArg})`);
  try {
    const view = await api<PlanView>(propose, "/api/plan", "POST", { target: dirArg, bundle }, creds);
    console.log("");
    printPlan(view);
  } catch (e) {
    // Caught rather than left to the default handler. An unhandled `ApiError` prints a stack trace
    // through `api-client.ts`, which buries the manager's own message — measured: a correct 403
    // ("this certificate may read the site but is not authorised to change the fleet") arrived as
    // fifteen lines of Node internals, and the actionable sentence was in the middle of them.
    if (!(e instanceof ApiError)) throw e;
    console.error(`\n${e.message}`);
    if (e.status === 403) {
      console.error(
        `  Add ${creds.name} to the manager's HELIOPAUSE_WRITER_CNS, or publish directly:\n` +
          `    heliopause-publish ${siteArg} <artifact-dir>`,
      );
    }
    if (e.status === 400) {
      console.error(`  The manager rejected the plan itself. Nothing was stored and nothing changed.`);
    }
    process.exit(1);
  }
} else {
  const dir = resolve(dirArg);
  if (!flags.has("--break-glass")) {
    console.error("direct publication requires the explicit --break-glass flag; ordinary changes use --propose");
    process.exit(2);
  }
  const target = flagValue("--target");
  const signingKeyFile = flagValue("--signing-key");
  const expectedKeyId = flagValue("--key-id");
  if (!target || !signingKeyFile || !expectedKeyId) {
    console.error("direct publication requires --target=NAME, --signing-key=FILE and --key-id=sha256:...");
    process.exit(2);
  }
  const ttlSec = Number(flagValue("--authorization-ttl-sec") ?? "900");
  if (!Number.isSafeInteger(ttlSec) || ttlSec < 900 || ttlSec > 24 * 60 * 60) {
    console.error("--authorization-ttl-sec must be an integer between 900 and 86400");
    process.exit(2);
  }
  const signingKeyPath = resolve(signingKeyFile);
  let keyFd: number;
  try {
    // No `O_CLOEXEC`: Node leaves it off `fs.constants`, so the term was `undefined` and contributed
    // nothing to this mask — see the same removal in `heliopause-manager.ts`. `O_NOFOLLOW` is the
    // flag that matters here, and it is real.
    keyFd = openSync(signingKeyPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    console.error(`cannot securely open --signing-key: ${(error as Error).message}`);
    process.exit(2);
  }
  const keyInfo = fstatSync(keyFd!);
  const uid = process.getuid?.();
  // The same predicate the manager uses, not a second copy of it. They drift in one direction that
  // matters: one process accepting a key the other refuses, discovered during an incident.
  const keyModeError = privateKeyFileModeError(keyInfo, process.getgid?.()) ?? privateKeyFileOwnerError(keyInfo, uid);
  if (!keyInfo.isFile() || keyModeError) {
    closeSync(keyFd!);
    console.error(
      `--signing-key must be a regular private key owned by this account and ${keyModeError ?? "readable only by it"}`,
    );
    process.exit(2);
  }
  const keyBytes = readFileSync(keyFd!);
  let signingKey;
  try {
    signingKey = createPrivateKey(keyBytes);
  } finally {
    keyBytes.fill(0);
    closeSync(keyFd!);
  }
  const actualKeyId = artifactSigningKeyId(createPublicKey(signingKey));
  if (actualKeyId !== expectedKeyId) {
    console.error(`--key-id ${expectedKeyId} does not match signing key SPKI ${actualKeyId}`);
    process.exit(2);
  }
  // ## The jump check, finally wired
  //
  // `membershipJumps` has existed and been tested since the workload layer landed, and never once
  // ran: it compares a selector's pod count against the previous generation's, and nothing kept the
  // previous count. The relay holds only the latest reading, the manifest carries pods per policy
  // rather than per selector, and the bundle is a wire format. So the record is written here, beside
  // the artifacts, and read here on the next publish.
  //
  // Before the write, so a publish that fails partway does not leave the new counts as the baseline
  // for a generation that never shipped.
  const previous = await readMembershipRecord(dir);
  if (previous && membership) {
    const jumps = membershipJumps(asPodLists(previous.counts), asPodLists(countsFrom(membership)));
    for (const j of jumps) {
      console.warn(`[publish] SELECTOR JUMP ${j.selector}: ${j.reason}`);
    }
    if (jumps.length) {
      // Warned, not refused. The check cannot tell a widened selector from a genuine burst of pods,
      // and a firewall tool that blocks a publish on a guess would teach operators to reach for a
      // bypass flag — which is worse than the ambiguity it was avoiding.
      console.warn(
        `[publish] ${jumps.length} selector(s) grew sharply since ${previous.generation}. ` +
          `Check what they now cover before this reaches the fleet.`,
      );
    }
  }

  const { bundleFromPlan } = await import("../src/bundle.ts");
  const authorizedAt = new Date();
  const signed = signAuthorizedArtifactBundle({
    target,
    bundle: bundleFromPlan(plan),
    authorizedAt,
    expiresAt: new Date(authorizedAt.getTime() + ttlSec * 1000),
    authorizationMode: "break-glass",
  }, signingKey);
  await writeAuthorizedArtifactBundle(dir, signed);
  // After the artifacts, so the record can never describe a generation that failed to write.
  if (membership) {
    await writeMembershipRecord(dir, {
      generation: plan.manifest.generation,
      at: membership.at,
      counts: countsFrom(membership),
    });
  }
  console.log(`BREAK-GLASS authorization written to ${dir}; target ${target}; expires ${new Date(authorizedAt.getTime() + ttlSec * 1000).toISOString()}`);
}
