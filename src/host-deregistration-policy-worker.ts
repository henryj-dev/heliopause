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
  pullRequestStatus,
  sameCommit,
  type AppCredentials,
  type Fetcher,
  type ProposalTarget,
} from "./policy-proposal.ts";
import { retireHost } from "./retired-hosts.ts";
export { parseRetiredHostsDocument, retireHost, withoutRetiredHosts } from "./retired-hosts.ts";
export type { RetiredHostsDocument } from "./retired-hosts.ts";

export interface PolicyWorkerRelayView {
  name: string;
  ok: boolean;
  generation: string | null;
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
  structuredClone(row.policy.automation ?? emptyHostDeregistrationPolicyAutomation());

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
    const commit = recovered ? { commit: recovered.headSha } : await ensureRepositoryFileOnBranch(
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
    automation.affectedRelays = [...relays.keys()].sort();
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
    automation.mergeCommitSha = pr.mergeCommitSha;
    automation.lastAttemptAt = now().toISOString();
    automation.lastError = null;
    const applied = cas(options, row, "pr_open", "merged", automation, { pullRequestUrl: pr.url });
    return applied
      ? { state: "advanced", operationId, policyState: "merged" }
      : { state: "waiting", operationId, reason: "operation changed while merge evidence was recorded" };
  }

  if (row.policy.state === "merged") {
    const renderer = await options.renderer();
    if (renderer.dirty || !sameCommit(renderer.headSha, renderer.repositoryHead)) {
      return { state: "waiting", operationId, reason: "waiting for a clean renderer at repository HEAD" };
    }
    if (renderer.hosts.includes(row.hostname)) {
      return { state: "waiting", operationId, reason: "merged renderer still contains the retired hostname" };
    }
    automation.plans = (await Promise.all(automation.affectedRelays.map((relay) => options.propose(relay))))
      .map((plan) => ({ ...plan, publishedAt: null }))
      .sort((a, b) => a.relay.localeCompare(b.relay));
    automation.lastAttemptAt = now().toISOString();
    automation.lastError = null;
    const generation = automation.plans[0]?.generation ?? renderer.headSha;
    const applied = cas(options, row, "merged", "awaiting_publish", automation, {
      publishedGeneration: generation,
    });
    return applied
      ? { state: "advanced", operationId, policyState: "awaiting_publish" }
      : { state: "waiting", operationId, reason: "operation changed while plans were proposed" };
  }

  if (row.policy.state === "awaiting_publish") {
    // Plans are memory-only by design. Re-proposing reconstructs them after a crash, but does not
    // reconstruct or bypass an approval: a human must approve and publish again.
    const previousByRelay = new Map(automation.plans.map((plan) => [plan.relay, plan]));
    const ensured = await Promise.all(automation.affectedRelays.map((relay) => {
      const previous = previousByRelay.get(relay);
      return options.propose(relay, previous
        ? { generation: previous.generation, proposedAt: previous.proposedAt }
        : undefined);
    }));
    const ensuredByRelay = new Map(ensured.map((plan) => [plan.relay, plan]));
    for (const plan of automation.plans) {
      const current = ensuredByRelay.get(plan.relay);
      if (current && (current.hash !== plan.hash || current.generation !== plan.generation)) {
        plan.hash = current.hash;
        plan.generation = current.generation;
        plan.proposedAt = current.proposedAt;
        plan.publishedAt = null;
      }
    }
    const observations = await options.relays();
    const relays = relayMap(observations, options.relayNames);
    for (const plan of automation.plans) {
      const view = relays.get(plan.relay)!;
      if (view.ok && view.generation === plan.generation && !view.hosts.includes(row.hostname) && plan.publishedAt === null) {
        plan.publishedAt = now().toISOString();
      }
    }
    const published = automation.plans.every((plan) => plan.publishedAt !== null);
    const absentEverywhere = [...relays.values()].every((view) => view.ok && !view.hosts.includes(row.hostname));
    if (!published || !absentEverywhere) {
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
    const observations = await options.relays();
    const relays = relayMap(observations, options.relayNames);
    if ([...relays.values()].some((view) => !view.ok || view.hosts.includes(row.hostname))) {
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
