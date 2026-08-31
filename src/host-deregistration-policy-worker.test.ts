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

function workerStateStore(
  state: "pr_open" | "merged" | "awaiting_publish" | "published",
  affectedRelays: string[] = ["dev"],
): string {
  const path = queuedStore();
  withEnrollmentTransaction(path, (document) => {
    const row = document.hostDeregistrations[0]!;
    const patch = "b".repeat(40);
    const merge = "c".repeat(40);
    row.policy.state = state;
    row.policy.pullRequestUrl = "https://github.test/o/r/pull/7";
    row.policy.commitSha = state === "pr_open" ? patch : merge;
    row.policy.publishedGeneration = ["awaiting_publish", "published"].includes(state) ? "generation-old" : null;
    row.policy.automation = {
      branch: "policy/host-deregister/destroy-1-ca761d98b2",
      pullRequestNumber: 7,
      patchCommitSha: patch,
      mergeCommitSha: state === "pr_open" ? null : merge,
      affectedRelays: [...affectedRelays].sort(),
      reviewedBy: state === "pr_open" ? [] : ["human-reviewer"],
      planGeneration: ["awaiting_publish", "published"].includes(state) ? "generation-old" : null,
      planProposedAt: ["awaiting_publish", "published"].includes(state) ? "2026-08-31T00:01:00.000Z" : null,
      plans: ["awaiting_publish", "published"].includes(state)
        ? affectedRelays.map((relay) => ({
          relay, hash: `sha256:${"d".repeat(64)}`, generation: "generation-old",
          proposedAt: "2026-08-31T00:01:00.000Z",
          publishedAt: state === "published" ? "2026-08-31T00:02:00.000Z" : null,
        })).sort((a, b) => a.relay.localeCompare(b.relay))
        : [],
      lastAttemptAt: null,
      lastError: null,
    };
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
          merged, merge_commit_sha: merged ? merge : null,
          head: { sha: patch, ref: "policy/host-deregister/destroy-1-ca761d98b2" }, base: { ref: "main" },
        };
      } else if (method === "GET" && url.pathname.endsWith("/pulls/7/reviews")) {
        body = [{
          id: 1, state: "APPROVED", commit_id: patch, submitted_at: "2026-08-31T00:00:30.000Z",
          user: { login: "human-reviewer", type: "User" },
        }];
      } else {
        status = 500;
        body = { error: `unexpected ${method} ${url.pathname}${url.search}` };
      }
      return { ok: status < 400, status, text: async () => JSON.stringify(body) };
    };

    // Already absent is deliberately not enough: dev must still receive the reviewed generation.
    let relay: PolicyWorkerRelayView = {
      name: "dev", ok: true, generation: "old", issuedAt: null, planHash: null, hosts: [],
    };
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
    await advanced("merged");
    const reservation = loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy.automation!;
    await advanced("awaiting_publish");
    const waitingPublish = await runHostDeregistrationPolicyWorkerOnce(options);
    assert.equal(waitingPublish.state, "waiting");
    assert.match((waitingPublish as { reason: string }).reason, /human approval\/publish/);
    assert.deepEqual(proposalPrevious, [
      { generation: reservation.planGeneration!, proposedAt: reservation.planProposedAt! },
      { generation: reservation.planGeneration!, proposedAt: reservation.planProposedAt! },
    ], "restart/retry did not reuse the durable plan reservation");
    assert.equal(loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy.state, "awaiting_publish");

    relay = {
      name: "dev", ok: true, generation: merge.slice(0, 7),
      issuedAt: reservation.planProposedAt!, planHash: `sha256:${"d".repeat(64)}`, hosts: [],
    };
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
    const policyAtRecoveredHead = JSON.stringify({
      schemaVersion: 1,
      retiredHosts: [{
        hostname: "web-01.dev",
        hostLifecycleId: "create-1",
        externalOperationId: "destroy-1",
        retiredAt: "2026-08-31T00:00:00.000Z",
      }],
    }, null, 2) + "\n";
    const seen: string[] = [];
    const fetcher: Fetcher = async (raw, init) => {
      const url = new URL(raw);
      const method = init?.method ?? "GET";
      seen.push(`${method} ${url.pathname}${url.search}`);
      let body: unknown;
      if (url.pathname.endsWith("/access_tokens")) body = { token: "installation" };
      else if (method === "GET" && url.pathname.endsWith("/contents/retired-hosts.json")
        && url.searchParams.get("ref") === patch) {
        body = { encoding: "base64", content: Buffer.from(policyAtRecoveredHead).toString("base64"), sha: "blob" };
      }
      else if (url.pathname.endsWith("/pulls") && url.searchParams.get("state") === "all") {
        body = [{
          number: 9, html_url: "https://github.test/o/r/pull/9", state: "closed",
          merged_at: "2026-08-31T00:00:00Z", merge_commit_sha: merge,
          head: { sha: patch, ref: "policy/host-deregister/destroy-1-ca761d98b2" }, base: { ref: "main" },
        }];
      } else if (url.pathname.endsWith("/pulls/9")) {
        body = {
          number: 9, html_url: "https://github.test/o/r/pull/9", state: "closed",
          merged: true, merge_commit_sha: merge,
          head: { sha: patch, ref: "policy/host-deregister/destroy-1-ca761d98b2" }, base: { ref: "main" },
        };
      } else if (url.pathname.endsWith("/pulls/9/reviews")) {
        body = [{
          id: 1, state: "APPROVED", commit_id: patch, submitted_at: "2026-08-31T00:00:00.000Z",
          user: { login: "human-reviewer", type: "User" },
        }];
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
      relays: async () => [{ name: "dev", ok: true, generation: "old", issuedAt: null, planHash: null, hosts: [] }],
      propose: async () => ({ relay: "dev", hash: `sha256:${"d".repeat(64)}`, generation: merge, proposedAt: "2026-08-31T00:00:00.000Z" }),
      now: () => new Date("2026-08-31T00:00:01.000Z"),
    };

    const recovered = await runHostDeregistrationPolicyWorkerOnce(options);
    assert.deepEqual(recovered, { state: "advanced", operationId: "destroy-1", policyState: "pr_open" });
    const row = loadEnrollmentDocument(storeFile).hostDeregistrations[0]!;
    assert.equal(row.policy.pullRequestUrl, "https://github.test/o/r/pull/9");
    assert.equal(row.policy.automation?.pullRequestNumber, 9);
    assert.equal(row.policy.automation?.patchCommitSha, patch);
    assert.equal(seen.filter((call) => call.includes(`/contents/retired-hosts.json?ref=${patch}`)).length, 1,
      "recovery must inspect policy bytes at the immutable PR head");
    assert.equal(seen.some((call) => call.startsWith("POST /repos/") || call.startsWith("PUT /repos/")), false,
      "recovering a PR must not recreate or mutate its branch");

    const merged = await runHostDeregistrationPolicyWorkerOnce(options);
    assert.deepEqual(merged, { state: "advanced", operationId: "destroy-1", policyState: "merged" });
  });

  it("fails closed when a recovered PR head lacks the exact canonical retirement tuple", async () => {
    const exact = {
      hostname: "web-01.dev",
      hostLifecycleId: "create-1",
      externalOperationId: "destroy-1",
      retiredAt: "2026-08-31T00:00:00.000Z",
    };
    const candidates = [
      {
        name: "wrong tuple",
        content: JSON.stringify({
          schemaVersion: 1,
          retiredHosts: [{ ...exact, externalOperationId: "destroy-other" }],
        }, null, 2) + "\n",
      },
      {
        name: "missing tuple",
        content: JSON.stringify({ schemaVersion: 1, retiredHosts: [] }, null, 2) + "\n",
      },
      {
        name: "alternate host retirement",
        content: JSON.stringify({
          schemaVersion: 1,
          retiredHosts: [{ ...exact, hostname: "web-02.dev" }],
        }, null, 2) + "\n",
      },
      {
        name: "non-canonical exact tuple",
        content: JSON.stringify({ schemaVersion: 1, retiredHosts: [exact] }),
      },
    ];

    for (const candidate of candidates) {
      const storeFile = queuedStore();
      const { privateKey } = generateKeyPairSync("rsa", {
        modulusLength: 2048,
        privateKeyEncoding: { type: "pkcs1", format: "pem" },
        publicKeyEncoding: { type: "pkcs1", format: "pem" },
      });
      const patch = "d".repeat(40);
      const seen: string[] = [];
      const fetcher: Fetcher = async (raw, init) => {
        const url = new URL(raw);
        const method = init?.method ?? "GET";
        seen.push(`${method} ${url.pathname}${url.search}`);
        let body: unknown;
        if (url.pathname.endsWith("/access_tokens")) body = { token: "installation" };
        else if (method === "GET" && url.pathname.endsWith("/pulls") && url.searchParams.get("state") === "all") {
          body = [{
            number: 10, html_url: "https://github.test/o/r/pull/10", state: "open",
            merged_at: null, merge_commit_sha: null,
            head: { sha: patch, ref: "policy/host-deregister/destroy-1-ca761d98b2" }, base: { ref: "main" },
          }];
        } else if (method === "GET" && url.pathname.endsWith("/contents/retired-hosts.json")
          && url.searchParams.get("ref") === patch) {
          body = { encoding: "base64", content: Buffer.from(candidate.content).toString("base64"), sha: "blob" };
        } else {
          return { ok: false, status: 500, text: async () => JSON.stringify({ error: "unexpected route" }) };
        }
        return { ok: true, status: 200, text: async () => JSON.stringify(body) };
      };

      await assert.rejects(runHostDeregistrationPolicyWorkerOnce({
        storeFile,
        retiredHostsPath: "retired-hosts.json",
        creds: { appId: "1", installationId: "2", privateKey },
        target: { owner: "o", repo: "r", base: "main" },
        fetcher,
        relayNames: ["dev"],
        renderer: async () => { throw new Error("renderer must not be called"); },
        relays: async () => [{ name: "dev", ok: true, generation: "old", issuedAt: null, planHash: null, hosts: [] }],
        propose: async () => { throw new Error("propose must not be called"); },
        now: () => new Date("2026-08-31T00:00:01.000Z"),
      }), /exact host retirement evidence is missing|retirement document is not canonical/, candidate.name);
      assert.equal(loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy.state, "queued", candidate.name);
      assert.equal(seen.some((call) => call.startsWith("POST /repos/") || call.startsWith("PUT /repos/")), false,
        `${candidate.name}: recovery must remain read-only`);
    }
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
      relays: async () => [{ name: "dev", ok: false, generation: null, issuedAt: null, planHash: null, hosts: [] }],
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

  it("durably reserves one manifest instant before any replica creates a plan", async () => {
    const storeFile = workerStateStore("merged");
    const waiting: Array<(view: { headSha: string; dirty: false; repositoryHead: string; hosts: never[] }) => void> = [];
    const renderer = () => new Promise<{ headSha: string; dirty: false; repositoryHead: string; hosts: never[] }>((resolve) => {
      waiting.push(resolve);
      if (waiting.length === 2) {
        for (const release of waiting) release({
          headSha: "generation-new", dirty: false, repositoryHead: "generation-new", hosts: [],
        });
      }
    });
    let proposals = 0;
    const common = {
      storeFile, retiredHostsPath: "retired-hosts.json",
      creds: { appId: "unused", installationId: "unused", privateKey: "unused" },
      target: { owner: "o", repo: "r", base: "main" },
      fetcher: async () => { throw new Error("GitHub must not be called"); },
      relayNames: ["dev"], renderer,
      relays: async () => [{ name: "dev", ok: true, generation: null, issuedAt: null, planHash: null, hosts: [] }],
      propose: async (relay: string, previous?: { generation: string; proposedAt: string }) => {
        proposals += 1;
        return { relay, hash: `sha256:${"e".repeat(64)}`, ...previous! };
      },
    };
    const [one, two] = await Promise.all([
      runHostDeregistrationPolicyWorkerOnce({ ...common, now: () => new Date("2026-08-31T00:03:00.000Z") }),
      runHostDeregistrationPolicyWorkerOnce({ ...common, now: () => new Date("2026-08-31T00:04:00.000Z") }),
    ]);
    assert.equal(proposals, 0, "a replica proposed before the reservation CAS won");
    assert.deepEqual([one.state, two.state].sort(), ["advanced", "waiting"]);
    const reservation = loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy.automation!;
    assert.ok(["2026-08-31T00:03:00.000Z", "2026-08-31T00:04:00.000Z"].includes(reservation.planProposedAt!));

    const next = await runHostDeregistrationPolicyWorkerOnce({
      ...common,
      renderer: async () => ({ headSha: "generation-new", dirty: false, repositoryHead: "generation-new", hosts: [] }),
      now: () => new Date("2026-08-31T00:05:00.000Z"),
    });
    assert.deepEqual(next, { state: "advanced", operationId: "destroy-1", policyState: "awaiting_publish" });
    assert.equal(proposals, 1);
    const durable = loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy.automation!;
    assert.equal(durable.plans[0]?.proposedAt, reservation.planProposedAt);
  });

  it("persists a new reservation before replacing plans when repository HEAD advances", async () => {
    const storeFile = workerStateStore("awaiting_publish");
    const proposedWith: Array<{ generation: string; proposedAt: string } | undefined> = [];
    const options = {
      storeFile, retiredHostsPath: "retired-hosts.json",
      creds: { appId: "unused", installationId: "unused", privateKey: "unused" },
      target: { owner: "o", repo: "r", base: "main" },
      fetcher: async () => { throw new Error("GitHub must not be called"); },
      relayNames: ["dev"],
      renderer: async () => ({ headSha: "generation-new", dirty: false, repositoryHead: "generation-new", hosts: [] }),
      relays: async () => [{
        name: "dev", ok: true, generation: "generation-old",
        issuedAt: "2026-08-31T00:01:00.000Z", planHash: `sha256:${"d".repeat(64)}`, hosts: [],
      }],
      propose: async (relay: string, previous?: { generation: string; proposedAt: string }) => {
        proposedWith.push(previous);
        return { relay, hash: `sha256:${"e".repeat(64)}`, ...previous! };
      },
      now: () => new Date("2026-08-31T00:06:00.000Z"),
    };
    assert.deepEqual(await runHostDeregistrationPolicyWorkerOnce(options), {
      state: "advanced", operationId: "destroy-1", policyState: "merged",
    });
    let durable = loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy.automation!;
    assert.equal(durable.planGeneration, "generation-new");
    assert.equal(durable.planProposedAt, "2026-08-31T00:06:00.000Z");
    assert.deepEqual(durable.plans, []);
    assert.deepEqual(proposedWith, [], "the new plan existed only in memory before its reservation was stored");

    await runHostDeregistrationPolicyWorkerOnce(options);
    durable = loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy.automation!;
    assert.deepEqual(proposedWith, [{ generation: "generation-new", proposedAt: "2026-08-31T00:06:00.000Z" }]);
    assert.equal(durable.plans[0]?.proposedAt, "2026-08-31T00:06:00.000Z");
  });

  it("resets both awaiting and published work when a relay is added and another removed", async () => {
    for (const state of ["awaiting_publish", "published"] as const) {
      const storeFile = workerStateStore(state, ["dev", "old"]);
      const result = await runHostDeregistrationPolicyWorkerOnce({
        storeFile, retiredHostsPath: "retired-hosts.json",
        creds: { appId: "unused", installationId: "unused", privateKey: "unused" },
        target: { owner: "o", repo: "r", base: "main" },
        fetcher: async () => { throw new Error("GitHub must not be called"); },
        relayNames: ["dev", "new"],
        renderer: async () => { throw new Error("renderer must wait for the relay-set CAS"); },
        relays: async () => { throw new Error("relay absence must not complete a changed set"); },
        propose: async () => { throw new Error("proposal must wait for the relay-set CAS"); },
        now: () => new Date("2026-08-31T00:07:00.000Z"),
      });
      assert.deepEqual(result, { state: "advanced", operationId: "destroy-1", policyState: "merged" });
      const row = loadEnrollmentDocument(storeFile).hostDeregistrations[0]!;
      assert.equal(row.policy.state, "merged");
      assert.deepEqual(row.policy.automation?.affectedRelays, ["dev", "new"]);
      assert.deepEqual(row.policy.automation?.plans, []);
    }
  });

  it("does not mistake matching generation and issuedAt for the durable published plan hash", async () => {
    const storeFile = workerStateStore("awaiting_publish");
    const result = await runHostDeregistrationPolicyWorkerOnce({
      storeFile, retiredHostsPath: "retired-hosts.json",
      creds: { appId: "unused", installationId: "unused", privateKey: "unused" },
      target: { owner: "o", repo: "r", base: "main" },
      fetcher: async () => { throw new Error("GitHub must not be called"); },
      relayNames: ["dev"],
      renderer: async () => ({
        headSha: "generation-old", dirty: false, repositoryHead: "generation-old", hosts: [],
      }),
      relays: async () => [{
        name: "dev", ok: true, generation: "generation-old", issuedAt: "2026-08-31T00:01:00.000Z",
        planHash: `sha256:${"e".repeat(64)}`, hosts: [],
      }],
      propose: async (relay: string, previous?: { generation: string; proposedAt: string }) => ({
        relay, hash: `sha256:${"d".repeat(64)}`, ...previous!,
      }),
      now: () => new Date("2026-08-31T00:07:00.000Z"),
    });
    assert.equal(result.state, "waiting");
    const plan = loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy.automation?.plans[0];
    assert.equal(plan?.publishedAt, null);
  });

  it("refuses a merged PR whose durable head, base, or human approval does not match", async () => {
    const { privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "pkcs1", format: "pem" },
    });
    for (const mismatch of ["head", "base", "review"] as const) {
      const storeFile = workerStateStore("pr_open");
      const patch = "b".repeat(40);
      const fetcher: Fetcher = async (raw) => {
        const url = new URL(raw);
        let body: unknown;
        if (url.pathname.endsWith("/access_tokens")) body = { token: "installation" };
        else if (url.pathname.endsWith("/pulls/7")) body = {
          number: 7, html_url: "https://github.test/o/r/pull/7", state: "closed", merged: true,
          merge_commit_sha: "c".repeat(40),
          head: {
            sha: mismatch === "head" ? "d".repeat(40) : patch,
            ref: "policy/host-deregister/destroy-1-ca761d98b2",
          },
          base: { ref: mismatch === "base" ? "other" : "main" },
        };
        else if (url.pathname.endsWith("/pulls/7/reviews")) body = [];
        else return { ok: false, status: 500, text: async () => "unexpected" };
        return { ok: true, status: 200, text: async () => JSON.stringify(body) };
      };
      const result = await runHostDeregistrationPolicyWorkerOnce({
        storeFile, retiredHostsPath: "retired-hosts.json",
        creds: { appId: "1", installationId: "2", privateKey },
        target: { owner: "o", repo: "r", base: "main" }, fetcher, relayNames: ["dev"],
        renderer: async () => { throw new Error("renderer must not be called"); },
        relays: async () => { throw new Error("relays must not be called"); },
        propose: async () => { throw new Error("propose must not be called"); },
        now: () => new Date("2026-08-31T00:08:00.000Z"),
      });
      assert.equal(result.state, "waiting");
      assert.equal(loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy.state, "pr_open");
      assert.match(loadEnrollmentDocument(storeFile).hostDeregistrations[0]!.policy.automation?.lastError ?? "",
        mismatch === "review" ? /no human approval/ : /match/);
    }
  });
});
