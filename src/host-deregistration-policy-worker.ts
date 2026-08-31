import { createHash } from "node:crypto";
import {
  completeHostDeregistrationPolicy,
  emptyHostDeregistrationPolicyAutomation,
  loadEnrollmentDocument,
  recordHostDeregistrationPolicyWorkerStep,
  withEnrollmentTransaction,
  type HostDeregistrationPolicyAutomation,
  type HostDeregistrationRecord,
} from "./enrollment-store.ts";
import {
  ensureRepositoryFileOnBranch,
  findPullRequestByBranch,
  openPullRequest,
  pullRequestHumanApprovals,
  pullRequestStatus,
  readRepositoryFile,
  sameCommit,
  type AppCredentials,
  type Fetcher,
  type ProposalTarget,
} from "./policy-proposal.ts";
import { parseRetiredHostsDocument, retireHost } from "./retired-hosts.ts";
export { parseRetiredHostsDocument, retireHost, withoutRetiredHosts } from "./retired-hosts.ts";
export type { RetiredHostsDocument } from "./retired-hosts.ts";

export interface PolicyWorkerRelayView {
  name: string;
  ok: boolean;
  generation: string | null;
  /** Exact bundle manifest timestamp; generation alone does not bind a unique rendered bundle. */
  issuedAt: string | null;
  /** Exact plan digest reported from the relay's loaded authorized bundle. */
  planHash: string | null;
  /** Exact manifest keys, obtained independently from relay GET /status. */
  hosts: string[];
  error?: string;
}

export interface PolicyWorkerRendererView {
  headSha: string | null;
  dirty: boolean;
  repositoryHead: string;
  hosts: string[];
}

export interface PolicyWorkerPlan {
  relay: string;
  hash: string;
  generation: string;
  proposedAt: string;
}

export interface HostDeregistrationPolicyWorkerOptions {
  storeFile: string;
  retiredHostsPath: string;
  creds: AppCredentials;
  target: ProposalTarget;
  fetcher: Fetcher;
  relayNames: readonly string[];
  renderer: () => Promise<PolicyWorkerRendererView>;
  relays: () => Promise<PolicyWorkerRelayView[]>;
  /** Creates or re-creates an in-memory plan. It never approves or publishes it. */
  propose: (relay: string, previous?: { generation: string; proposedAt: string }) => Promise<PolicyWorkerPlan>;
  now?: () => Date;
  actor?: string;
}

export type PolicyWorkerResult =
  | { state: "idle" }
  | { state: "advanced"; operationId: string; policyState: string }
  | { state: "waiting"; operationId: string; reason: string };

const automationOf = (row: HostDeregistrationRecord): HostDeregistrationPolicyAutomation =>
  ({ ...emptyHostDeregistrationPolicyAutomation(), ...structuredClone(row.policy.automation ?? {}) });

function operationKey(row: HostDeregistrationRecord): string {
  return `${row.hostname}\0${row.externalOperationId}\0${row.hostLifecycleId}`;
}

function deterministicBranch(row: HostDeregistrationRecord): string {
  const slug = row.externalOperationId.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^[.-]+|[.-]+$/g, "")
    .slice(0, 80) || "operation";
  const suffix = createHash("sha256").update(operationKey(row)).digest("hex").slice(0, 10);
  return `policy/host-deregister/${slug}-${suffix}`;
}

function activeOperation(storeFile: string): HostDeregistrationRecord | null {
  return loadEnrollmentDocument(storeFile).hostDeregistrations
    .filter((row) => row.infrastructure.state === "destroyed"
      && ["queued", "pr_open", "merged", "awaiting_publish", "published"].includes(row.policy.state))
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt))[0] ?? null;
}

function relayMap(views: readonly PolicyWorkerRelayView[], expected: readonly string[]): Map<string, PolicyWorkerRelayView> {
  const map = new Map(views.map((view) => [view.name, view]));
  if (map.size !== views.length || expected.some((name) => !map.has(name))
    || views.some((view) => !expected.includes(view.name))) {
    throw new Error("relay observation does not exactly match the configured relay set");
  }
  return map;
}

const configuredRelays = (options: HostDeregistrationPolicyWorkerOptions): string[] =>
  [...new Set(options.relayNames)].sort();

const sameStrings = (a: readonly string[], b: readonly string[]): boolean =>
  a.length === b.length && a.every((value, index) => value === b[index]);

function verifyRecoveredRetirement(content: string, row: HostDeregistrationRecord, source: string): void {
  const document = parseRetiredHostsDocument(content, source);
  if (content !== JSON.stringify(document, null, 2) + "\n") {
    throw new Error(`${source}: retirement document is not canonical`);
  }
  const retirement = document.retiredHosts.find((entry) => entry.hostname === row.hostname);
  if (!retirement
    || retirement.hostLifecycleId !== row.hostLifecycleId
    || retirement.externalOperationId !== row.externalOperationId
    || retirement.retiredAt !== row.infrastructure.destroyedAt) {
    throw new Error(`${source}: exact host retirement evidence is missing`);
  }
}

function resetForRelaySet(
  options: HostDeregistrationPolicyWorkerOptions,
  row: HostDeregistrationRecord,
  automation: HostDeregistrationPolicyAutomation,
): PolicyWorkerResult | null {
  const current = configuredRelays(options);
  if (sameStrings([...automation.affectedRelays].sort(), current)) return null;
  automation.affectedRelays = current;
  automation.planGeneration = null;
  automation.planProposedAt = null;
  automation.plans = [];
  automation.lastAttemptAt = (options.now ?? (() => new Date()))().toISOString();
  automation.lastError = null;
  const applied = cas(options, row, row.policy.state, "merged", automation);
  return applied
    ? { state: "advanced", operationId: row.externalOperationId, policyState: "merged" }
    : { state: "waiting", operationId: row.externalOperationId, reason: "relay set changed during recovery" };
}

function cas(
  options: HostDeregistrationPolicyWorkerOptions,
  row: HostDeregistrationRecord,
  expectedState: HostDeregistrationRecord["policy"]["state"],
  nextState: HostDeregistrationRecord["policy"]["state"],
  automation: HostDeregistrationPolicyAutomation,
  evidence: {
    pullRequestUrl?: string | null; commitSha?: string | null; publishedGeneration?: string | null;
    relayConfirmations?: Array<{ name: string; absentAt: string }>;
  } = {},
): boolean {
  return withEnrollmentTransaction(options.storeFile, (document) =>
    recordHostDeregistrationPolicyWorkerStep(document, {
      hostname: row.hostname,
      externalOperationId: row.externalOperationId,
      hostLifecycleId: row.hostLifecycleId,
      expectedState,
      expectedPolicy: structuredClone(row.policy),
      nextState,
      automation,
      actor: options.actor ?? "policy-worker",
      now: (options.now ?? (() => new Date()))(),
      ...evidence,
    }).applied).valueOf();
}

/** Perform at most one durable transition. The caller serializes invocations. */
export async function runHostDeregistrationPolicyWorkerOnce(
  options: HostDeregistrationPolicyWorkerOptions,
): Promise<PolicyWorkerResult> {
  const row = activeOperation(options.storeFile);
  if (!row) return { state: "idle" };
  const now = options.now ?? (() => new Date());
  const nowSec = Math.floor(now().getTime() / 1000);
  const operationId = row.externalOperationId;
  const automation = automationOf(row);

  if (row.policy.state === "queued") {
    const observations = await options.relays();
    const relays = relayMap(observations, options.relayNames);
    const unreachable = [...relays.values()].filter((view) => !view.ok);
    if (unreachable.length) {
      automation.lastAttemptAt = now().toISOString();
      automation.lastError = `relay observation unavailable: ${unreachable.map((r) => r.name).join(", ")}`;
      cas(options, row, "queued", "queued", automation);
      return { state: "waiting", operationId, reason: `relay observation unavailable: ${unreachable.map((r) => r.name).join(", ")}` };
    }
    const branch = deterministicBranch(row);
    const recovered = await findPullRequestByBranch(
      options.creds, options.target, options.fetcher, nowSec, branch,
    );
    // Look for a PR before touching the branch. A crash can happen after GitHub accepted the PR but
    // before our CAS recorded its number; an auto-deleted merged branch must not be recreated merely
    // to recover that durable evidence.
    let commit: { commit: string };
    if (recovered) {
      if (recovered.headRef !== branch || recovered.baseRef !== options.target.base) {
        throw new Error("recovered policy pull request does not match the deterministic branch and base");
      }
      const recoveredFile = await readRepositoryFile(
        options.creds, options.target, options.fetcher, nowSec,
        options.retiredHostsPath, recovered.headSha,
      );
      verifyRecoveredRetirement(
        recoveredFile.content,
        row,
        `recovered policy pull request head ${recovered.headSha}`,
      );
      commit = { commit: recovered.headSha };
    } else {
      commit = await ensureRepositoryFileOnBranch(
        options.creds, options.fetcher, nowSec, {
          target: options.target,
          path: options.retiredHostsPath,
          transform: (current) => retireHost(current, {
            hostname: row.hostname,
            hostLifecycleId: row.hostLifecycleId,
            externalOperationId: row.externalOperationId,
            retiredAt: row.infrastructure.destroyedAt!,
          }).content,
          branch,
          message: `policy: retire ${row.hostname} after infrastructure destroy`,
        },
      );
    }
    const pr = recovered ?? await openPullRequest(options.creds, options.fetcher, nowSec, {
      target: options.target,
      branch,
      title: `policy: retire ${row.hostname}`,
      body: [
        `Host lifecycle \`${row.hostLifecycleId}\` was destroyed by operation \`${row.externalOperationId}\`.`,
        "",
        "This pull request removes the exact hostname from future rendered manifests.",
        "Merging does not publish. The rendered bundle still requires the normal human approval and publish gate.",
      ].join("\n"),
    });
    automation.branch = branch;
    automation.pullRequestNumber = pr.number;
    automation.patchCommitSha = commit.commit;
    // Every configured relay receives and proves the reviewed generation. Selecting only relays
    // whose current manifest contains the host makes an already-absent host a vacuous success with
    // no rendered plan, approval or publish evidence at all.
    automation.affectedRelays = configuredRelays(options);
    automation.lastAttemptAt = now().toISOString();
    automation.lastError = null;
    const applied = cas(options, row, "queued", "pr_open", automation, {
      pullRequestUrl: pr.url,
      commitSha: commit.commit,
    });
    return applied
      ? { state: "advanced", operationId, policyState: "pr_open" }
      : { state: "waiting", operationId, reason: "operation changed while the pull request was created" };
  }

  if (row.policy.state === "pr_open") {
    if (automation.pullRequestNumber === null) throw new Error("pr_open operation has no pull request number");
    const pr = await pullRequestStatus(
      options.creds, options.target, options.fetcher, nowSec, automation.pullRequestNumber,
    );
    if (pr.headRef !== automation.branch || pr.baseRef !== options.target.base
      || pr.headSha !== automation.patchCommitSha) {
      automation.lastAttemptAt = now().toISOString();
      automation.lastError = "policy pull request no longer matches the durable branch, base and patch commit";
      cas(options, row, "pr_open", "pr_open", automation);
      return { state: "waiting", operationId, reason: automation.lastError };
    }
    if (!pr.merged) {
      if (pr.state === "closed") {
        automation.lastAttemptAt = now().toISOString();
        automation.lastError = "policy pull request closed without merge";
        cas(options, row, "pr_open", "pr_open", automation);
      }
      return {
        state: "waiting",
        operationId,
        reason: pr.state === "open" ? "waiting for human policy review and merge" : "policy pull request closed without merge",
      };
    }
    if (!pr.mergeCommitSha) throw new Error("merged pull request has no merge commit sha");
    const reviewers = await pullRequestHumanApprovals(
      options.creds, options.target, options.fetcher, nowSec, automation.pullRequestNumber, automation.patchCommitSha!,
    );
    if (reviewers.length === 0) {
      automation.lastAttemptAt = now().toISOString();
      automation.lastError = "merged policy pull request has no human approval of the durable patch commit";
      cas(options, row, "pr_open", "pr_open", automation);
      return { state: "waiting", operationId, reason: automation.lastError };
    }
    automation.mergeCommitSha = pr.mergeCommitSha;
    automation.reviewedBy = reviewers;
    automation.lastAttemptAt = now().toISOString();
    automation.lastError = null;
    const applied = cas(options, row, "pr_open", "merged", automation, {
      pullRequestUrl: pr.url,
      commitSha: pr.mergeCommitSha,
    });
    return applied
      ? { state: "advanced", operationId, policyState: "merged" }
      : { state: "waiting", operationId, reason: "operation changed while merge evidence was recorded" };
  }

  if (row.policy.state === "merged") {
    const relayReset = resetForRelaySet(options, row, automation);
    if (relayReset) return relayReset;
    const renderer = await options.renderer();
    if (renderer.dirty || !sameCommit(renderer.headSha, renderer.repositoryHead)) {
      return { state: "waiting", operationId, reason: "waiting for a clean renderer at repository HEAD" };
    }
    if (renderer.hosts.includes(row.hostname)) {
      return { state: "waiting", operationId, reason: "merged renderer still contains the retired hostname" };
    }
    if (automation.planGeneration !== renderer.headSha || automation.planProposedAt === null) {
      automation.planGeneration = renderer.headSha!;
      automation.planProposedAt = now().toISOString();
      automation.plans = [];
      automation.lastAttemptAt = now().toISOString();
      automation.lastError = null;
      const reserved = cas(options, row, "merged", "merged", automation);
      return reserved
        ? { state: "advanced", operationId, policyState: "merged" }
        : { state: "waiting", operationId, reason: "another worker reserved the rendered plan" };
    }
    const reservation = { generation: automation.planGeneration!, proposedAt: automation.planProposedAt! };
    const proposed = await Promise.all(automation.affectedRelays.map((relay) => options.propose(relay, reservation)));
    if (proposed.some((plan) => plan.generation !== reservation.generation
      || plan.proposedAt !== reservation.proposedAt)
      || !sameStrings(proposed.map((plan) => plan.relay).sort(), [...automation.affectedRelays].sort())) {
      throw new Error("renderer proposal did not match the durable plan reservation");
    }
    automation.plans = proposed.map((plan) => ({ ...plan, publishedAt: null }))
      .sort((a, b) => a.relay.localeCompare(b.relay));
    automation.lastAttemptAt = now().toISOString();
    automation.lastError = null;
    const applied = cas(options, row, "merged", "awaiting_publish", automation, {
      publishedGeneration: reservation.generation,
    });
    return applied
      ? { state: "advanced", operationId, policyState: "awaiting_publish" }
      : { state: "waiting", operationId, reason: "operation changed while plans were proposed" };
  }

  if (row.policy.state === "awaiting_publish") {
    const relayReset = resetForRelaySet(options, row, automation);
    if (relayReset) return relayReset;
    const renderer = await options.renderer();
    if (renderer.dirty || !sameCommit(renderer.headSha, renderer.repositoryHead)) {
      return { state: "waiting", operationId, reason: "waiting for a clean renderer at repository HEAD" };
    }
    if (renderer.hosts.includes(row.hostname)) {
      return { state: "waiting", operationId, reason: "current renderer again contains the retired hostname" };
    }
    if (automation.planGeneration !== renderer.headSha || automation.planProposedAt === null) {
      automation.planGeneration = renderer.headSha!;
      automation.planProposedAt = now().toISOString();
      automation.plans = [];
      automation.lastAttemptAt = now().toISOString();
      automation.lastError = null;
      const reset = cas(options, row, "awaiting_publish", "merged", automation, {
        publishedGeneration: renderer.headSha,
      });
      return reset
        ? { state: "advanced", operationId, policyState: "merged" }
        : { state: "waiting", operationId, reason: "renderer advanced during plan replacement" };
    }
    // The plan identity is durable; the manager's publishable bundle and approval are memory-only.
    // Re-proposing reconstructs the exact durable hash after a crash, never the approval: a human
    // must approve and publish again.
    const reservation = { generation: automation.planGeneration!, proposedAt: automation.planProposedAt! };
    const ensured = await Promise.all(automation.affectedRelays.map((relay) => options.propose(relay, reservation)));
    const ensuredByRelay = new Map(ensured.map((plan) => [plan.relay, plan]));
    for (const plan of automation.plans) {
      const current = ensuredByRelay.get(plan.relay);
      if (!current || current.hash !== plan.hash || current.generation !== plan.generation
        || current.proposedAt !== plan.proposedAt) {
        throw new Error(`reconstructed plan for ${plan.relay} does not match durable hash and manifest`);
      }
    }
    const observations = await options.relays();
    const relays = relayMap(observations, options.relayNames);
    let publicationChanged = false;
    for (const plan of automation.plans) {
      const view = relays.get(plan.relay)!;
      if (view.ok && view.generation === plan.generation && view.issuedAt === plan.proposedAt
        && view.planHash === plan.hash
        && !view.hosts.includes(row.hostname) && plan.publishedAt === null) {
        plan.publishedAt = now().toISOString();
        publicationChanged = true;
      }
    }
    const published = automation.plans.every((plan) => plan.publishedAt !== null);
    const absentEverywhere = [...relays.values()].every((view) => view.ok && !view.hosts.includes(row.hostname));
    if (!published || !absentEverywhere) {
      if (publicationChanged) {
        automation.lastAttemptAt = now().toISOString();
        automation.lastError = null;
        cas(options, row, "awaiting_publish", "awaiting_publish", automation);
      }
      return { state: "waiting", operationId, reason: "waiting for human approval/publish and relay manifest absence" };
    }
    automation.lastAttemptAt = now().toISOString();
    automation.lastError = null;
    const applied = cas(options, row, "awaiting_publish", "published", automation);
    return applied
      ? { state: "advanced", operationId, policyState: "published" }
      : { state: "waiting", operationId, reason: "operation changed while publish evidence was recorded" };
  }

  if (row.policy.state === "published") {
    const relayReset = resetForRelaySet(options, row, automation);
    if (relayReset) return relayReset;
    const observations = await options.relays();
    const relays = relayMap(observations, options.relayNames);
    const planByRelay = new Map(automation.plans.map((plan) => [plan.relay, plan]));
    if ([...relays.values()].some((view) => {
      const plan = planByRelay.get(view.name);
      return !view.ok || !plan || view.generation !== plan.generation
        || view.issuedAt !== plan.proposedAt || view.planHash !== plan.hash || view.hosts.includes(row.hostname);
    })) {
      return { state: "waiting", operationId, reason: "relay manifest absence could not be independently reconfirmed" };
    }
    const at = now().toISOString();
    const confirmations = [...relays.values()].map((view) => ({ name: view.name, absentAt: at })).sort((a, b) => a.name.localeCompare(b.name));
    const generations = [...new Set(automation.plans.map((plan) => plan.generation))];
    if (generations.length > 1) throw new Error("policy plans do not agree on one rendered generation");
    const generation = generations[0] ?? row.policy.publishedGeneration;
    if (!generation || !row.policy.pullRequestUrl || !row.policy.commitSha) {
      throw new Error("published operation lacks durable Git or generation evidence");
    }
    const completed = withEnrollmentTransaction(options.storeFile, (document) => completeHostDeregistrationPolicy(document, {
      hostname: row.hostname,
      externalOperationId: row.externalOperationId,
      hostLifecycleId: row.hostLifecycleId,
      pullRequestUrl: row.policy.pullRequestUrl!,
      commitSha: row.policy.commitSha!,
      publishedGeneration: generation,
      relayConfirmations: confirmations,
      relayNames: options.relayNames,
      actor: options.actor ?? "policy-worker",
      now: now(),
    }));
    return { state: "advanced", operationId: completed.externalOperationId, policyState: "completed" };
  }

  return { state: "idle" };
}

/** A single-flight unref'd timer. Closing the manager server must call the returned stop function. */
export function startHostDeregistrationPolicyWorker(
  options: HostDeregistrationPolicyWorkerOptions,
  intervalMs = 30_000,
  onError: (error: Error) => void = () => {},
): () => void {
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 1_000) throw new Error("policy worker interval must be at least one second");
  if (options.relayNames.length === 0) throw new Error("policy worker requires at least one configured relay");
  if (new Set(options.relayNames).size !== options.relayNames.length) {
    throw new Error("policy worker requires unique configured relay names");
  }
  let stopped = false;
  let running = false;
  const run = async (): Promise<void> => {
    if (stopped || running) return;
    running = true;
    try { await runHostDeregistrationPolicyWorkerOnce(options); }
    catch (error) {
      const row = activeOperation(options.storeFile);
      if (row) {
        const automation = automationOf(row);
        automation.lastAttemptAt = (options.now ?? (() => new Date()))().toISOString();
        automation.lastError = (error as Error).message.slice(0, 500);
        try { cas(options, row, row.policy.state, row.policy.state, automation); } catch { /* report the original failure */ }
      }
      onError(error as Error);
    }
    finally { running = false; }
  };
  const timer = setInterval(() => { void run(); }, intervalMs);
  timer.unref();
  void run();
  return () => { stopped = true; clearInterval(timer); };
}
