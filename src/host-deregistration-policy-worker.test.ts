import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  beginHostDeregistration,
  confirmHostInfrastructureDestroyed,
  createNodeToken,
  initializeEnrollmentDocument,
  loadEnrollmentDocument,
  recordHostDeregistrationReplication,
  withEnrollmentTransaction,
} from "./enrollment-store.ts";
import { runHostDeregistrationPolicyWorkerOnce, type PolicyWorkerRelayView } from "./host-deregistration-policy-worker.ts";
import type { Fetcher } from "./policy-proposal.ts";

const root = mkdtempSync(join(tmpdir(), "hp-policy-worker-"));
after(() => rmSync(root, { recursive: true, force: true }));

function queuedStore(): string {
  const path = join(root, `store-${Math.random().toString(16).slice(2)}.json`);
  initializeEnrollmentDocument(path);
  const at = new Date("2026-08-31T00:00:00.000Z");
  withEnrollmentTransaction(path, (document) => {
    createNodeToken(document, { hostname: "web-01.dev", hostLifecycleId: "create-1", now: at });
    beginHostDeregistration(document, {
      hostname: "web-01.dev", externalOperationId: "destroy-1", hostLifecycleId: "create-1",
      reason: "instance-destroy", requestedBy: "stardust", actor: "app:destroyer", relayNames: ["dev"],
      scope: { appTokenId: "app-1", label: "destroyer", hostnamePattern: "*.dev" }, now: at,
    });
    recordHostDeregistrationReplication(document, [
      { name: "dev", ok: true, count: 0, snapshotFingerprints: [] },
    ], ["dev"], at);
    confirmHostInfrastructureDestroyed(document, {
      hostname: "web-01.dev", externalOperationId: "destroy-1", hostLifecycleId: "create-1",
      provider: "vultr", providerInstanceId: "vultr-1", destroyedAt: at.toISOString(),
      actor: "app:destroyer", now: at,
    });
  });
  return path;
}

describe("reviewed-Git host deregistration worker", () => {
  it("waits for human merge and publish, then independently proves relay manifest absence", async () => {
    const storeFile = queuedStore();
    // A second ready operation proves the worker owns a serial queue rather than two whole-file PRs.
    withEnrollmentTransaction(storeFile, (document) => {
      const at = new Date("2026-08-31T00:00:01.000Z");
      createNodeToken(document, { hostname: "web-02.dev", hostLifecycleId: "create-2", now: at });
      beginHostDeregistration(document, {
        hostname: "web-02.dev", externalOperationId: "destroy-2", hostLifecycleId: "create-2",
        reason: "instance-destroy", requestedBy: "stardust", actor: "app:destroyer", relayNames: ["dev"],
        scope: { appTokenId: "app-1", label: "destroyer", hostnamePattern: "*.dev" }, now: at,
      });
      recordHostDeregistrationReplication(document, [
        { name: "dev", ok: true, count: 0, snapshotFingerprints: [] },
      ], ["dev"], at);
      confirmHostInfrastructureDestroyed(document, {
        hostname: "web-02.dev", externalOperationId: "destroy-2", hostLifecycleId: "create-2",
        provider: "vultr", providerInstanceId: "vultr-2", destroyedAt: at.toISOString(),
        actor: "app:destroyer", now: at,
      });
    });
    const { privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "pkcs1", format: "pem" },
    });
    let branchContent = '{"schemaVersion":1,"retiredHosts":[]}\n';
    let merged = false;
    const full = "a".repeat(40);
    const patch = "b".repeat(40);
    const merge = "c".repeat(40);
    const fetcher: Fetcher = async (raw, init) => {
      const url = new URL(raw);
      const method = init?.method ?? "GET";
      let status = 200;
      let body: unknown = {};
      if (url.pathname.endsWith("/access_tokens")) body = { token: "installation" };
      else if (url.pathname.endsWith("/git/ref/heads/main")) body = { object: { sha: full } };
      else if (method === "POST" && url.pathname.endsWith("/git/refs")) body = {};
      else if (url.pathname.includes("/git/ref/heads/policy%2Fhost-deregister%2F")) body = { object: { sha: patch } };
      else if (method === "GET" && url.pathname.endsWith("/contents/retired-hosts.json")) {
        const ref = url.searchParams.get("ref");
        const content = ref === "main" ? '{"schemaVersion":1,"retiredHosts":[]}\n' : branchContent;
        body = { encoding: "base64", content: Buffer.from(content).toString("base64"), sha: "blob" };
      } else if (method === "PUT" && url.pathname.endsWith("/contents/retired-hosts.json")) {
        const request = JSON.parse(init?.body ?? "{}") as { content: string };
        branchContent = Buffer.from(request.content, "base64").toString("utf8");
        body = { commit: { sha: patch } };
      } else if (method === "GET" && url.pathname.endsWith("/pulls") && url.searchParams.get("state") === "all") {
        body = [];
      } else if (method === "POST" && url.pathname.endsWith("/pulls")) {
        body = { number: 7, html_url: "https://github.test/o/r/pull/7" };
      } else if (method === "GET" && url.pathname.endsWith("/pulls/7")) {
        body = {
          number: 7, html_url: "https://github.test/o/r/pull/7", state: merged ? "closed" : "open",
          merged, merge_commit_sha: merged ? merge : null, head: { sha: patch },
        };
      } else {
        status = 500;
        body = { error: `unexpected ${method} ${url.pathname}${url.search}` };
      }
      return { ok: status < 400, status, text: async () => JSON.stringify(body) };
    };

    // Already absent is deliberately not enough: dev must still receive the reviewed generation.
    let relay: PolicyWorkerRelayView = { name: "dev", ok: true, generation: "old", hosts: [] };
    const proposalPrevious: Array<{ generation: string; proposedAt: string } | undefined> = [];
    let nowMs = Date.parse("2026-08-31T00:01:00.000Z");
    const options = {
      storeFile,
      retiredHostsPath: "retired-hosts.json",
      creds: { appId: "1", installationId: "2", privateKey },
      target: { owner: "o", repo: "r", base: "main" },
      fetcher,
      relayNames: ["dev"],
      renderer: async () => ({ headSha: merge.slice(0, 7), dirty: false, repositoryHead: merge, hosts: [] }),
      relays: async () => [structuredClone(relay)],
      propose: async (name: string, previous?: { generation: string; proposedAt: string }) => {
        proposalPrevious.push(previous);
        return {
        relay: name, hash: `sha256:${"d".repeat(64)}`, generation: merge.slice(0, 7),
        proposedAt: previous?.proposedAt ?? "2026-08-31T00:01:00.000Z",
        };
      },
      now: () => new Date(nowMs++),
    };

    const advanced = async (state: string): Promise<void> => {
      const result = await runHostDeregistrationPolicyWorkerOnce(options);
      assert.equal(result.state, "advanced");
      if (result.state === "advanced") assert.equal(result.policyState, state);
    };
    await advanced("pr_open");
    assert.deepEqual(JSON.parse(branchContent).retiredHosts.map((entry: { hostname: string }) => entry.hostname), ["web-01.dev"]);
    assert.deepEqual(loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy.automation?.affectedRelays, ["dev"]);
    assert.equal(loadEnrollmentDocument(storeFile).hostDeregistrations[1]!.policy.state, "queued");
    const waitingReview = await runHostDeregistrationPolicyWorkerOnce(options);
    assert.deepEqual(waitingReview, { state: "waiting", operationId: "destroy-1", reason: "waiting for human policy review and merge" });
    assert.equal(loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy.state, "pr_open");

    merged = true;
    await advanced("merged");
    await advanced("awaiting_publish");
    const waitingPublish = await runHostDeregistrationPolicyWorkerOnce(options);
    assert.equal(waitingPublish.state, "waiting");
    assert.match((waitingPublish as { reason: string }).reason, /human approval\/publish/);
    assert.deepEqual(proposalPrevious, [undefined, {
      generation: merge.slice(0, 7), proposedAt: "2026-08-31T00:01:00.000Z",
    }], "restart/retry did not reuse the durable plan instant");
    assert.equal(loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy.state, "awaiting_publish");

    relay = { name: "dev", ok: true, generation: merge.slice(0, 7), hosts: [] };
    await advanced("published");
    await advanced("completed");
    const completed = loadEnrollmentDocument(storeFile).hostDeregistrations[0]!;
    assert.equal(completed.status, "completed");
    assert.deepEqual(completed.policy.relays.map((entry) => entry.name), ["dev"]);
    assert.equal(completed.policy.completedBy, "policy-worker");
    assert.equal(loadEnrollmentDocument(storeFile).hostDeregistrations[1]!.policy.state, "queued");
  });

  it("recovers a merged PR after a crash before the store CAS without recreating its deleted branch", async () => {
    const storeFile = queuedStore();
    const { privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "pkcs1", format: "pem" },
    });
    const patch = "b".repeat(40);
    const merge = "c".repeat(40);
    const seen: string[] = [];
    const fetcher: Fetcher = async (raw, init) => {
      const url = new URL(raw);
      const method = init?.method ?? "GET";
      seen.push(`${method} ${url.pathname}${url.search}`);
      let body: unknown;
      if (url.pathname.endsWith("/access_tokens")) body = { token: "installation" };
      else if (url.pathname.endsWith("/pulls") && url.searchParams.get("state") === "all") {
        body = [{
          number: 9, html_url: "https://github.test/o/r/pull/9", state: "closed",
          merged_at: "2026-08-31T00:00:00Z", merge_commit_sha: merge, head: { sha: patch },
        }];
      } else if (url.pathname.endsWith("/pulls/9")) {
        body = {
          number: 9, html_url: "https://github.test/o/r/pull/9", state: "closed",
          merged: true, merge_commit_sha: merge, head: { sha: patch },
        };
      } else {
        return { ok: false, status: 500, text: async () => JSON.stringify({ error: "unexpected route" }) };
      }
      return { ok: true, status: 200, text: async () => JSON.stringify(body) };
    };
    const options = {
      storeFile,
      retiredHostsPath: "retired-hosts.json",
      creds: { appId: "1", installationId: "2", privateKey },
      target: { owner: "o", repo: "r", base: "main" },
      fetcher,
      relayNames: ["dev"],
      renderer: async () => ({ headSha: merge, dirty: false, repositoryHead: merge, hosts: [] }),
      relays: async () => [{ name: "dev", ok: true, generation: "old", hosts: [] } as PolicyWorkerRelayView],
      propose: async () => ({ relay: "dev", hash: `sha256:${"d".repeat(64)}`, generation: merge, proposedAt: "2026-08-31T00:00:00.000Z" }),
      now: () => new Date("2026-08-31T00:00:01.000Z"),
    };

    const recovered = await runHostDeregistrationPolicyWorkerOnce(options);
    assert.deepEqual(recovered, { state: "advanced", operationId: "destroy-1", policyState: "pr_open" });
    const row = loadEnrollmentDocument(storeFile).hostDeregistrations[0]!;
    assert.equal(row.policy.pullRequestUrl, "https://github.test/o/r/pull/9");
    assert.equal(row.policy.automation?.pullRequestNumber, 9);
    assert.equal(row.policy.automation?.patchCommitSha, patch);
    assert.equal(seen.some((call) => call.includes("/git/refs") || call.includes("/contents/")), false,
      "recovering a PR must not recreate an auto-deleted branch");

    const merged = await runHostDeregistrationPolicyWorkerOnce(options);
    assert.deepEqual(merged, { state: "advanced", operationId: "destroy-1", policyState: "merged" });
  });

  it("persists retry diagnostics without advancing when a relay observation is unavailable", async () => {
    const storeFile = queuedStore();
    const result = await runHostDeregistrationPolicyWorkerOnce({
      storeFile,
      retiredHostsPath: "retired-hosts.json",
      creds: { appId: "unused", installationId: "unused", privateKey: "unused" },
      target: { owner: "o", repo: "r", base: "main" },
      fetcher: async () => { throw new Error("GitHub must not be called"); },
      relayNames: ["dev"],
      renderer: async () => { throw new Error("renderer must not be called"); },
      relays: async () => [{ name: "dev", ok: false, generation: null, hosts: [] }],
      propose: async () => { throw new Error("propose must not be called"); },
      now: () => new Date("2026-08-31T00:00:01.000Z"),
    });
    assert.deepEqual(result, {
      state: "waiting", operationId: "destroy-1", reason: "relay observation unavailable: dev",
    });
    const policy = loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy;
    assert.equal(policy.state, "queued");
    assert.equal(policy.automation?.lastError, "relay observation unavailable: dev");
    assert.equal(policy.automation?.lastAttemptAt, "2026-08-31T00:00:01.000Z");
  });
});
