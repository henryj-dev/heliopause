// The two steps that used to leave the console, exercised against a real TLS server.
//
// `policy-merge.test.ts` proves the rule and `kube-read.test.ts` proves the reader. Neither says
// anything about the thing that decides who is asking — and the identity is half of this gate. The
// two-person rule compares the proposer with *the caller's certificate CN*, so a route that read the
// right rule against the wrong name would pass both of those suites and still let an operator merge
// their own change. That pairing only exists where TLS and the handler meet, which is here.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:https";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { startManager } from "./manager-server.ts";
import { forgetInstallationTokens } from "./policy-proposal.ts";
import type { KubeFetcher } from "./kube-read.ts";

const dir = mkdtempSync(join(tmpdir(), "hp-loop-"));
const HEAD = "a".repeat(40);

/** A throwaway CA, a server leaf, and one client leaf per operator this suite speaks as. */
function pki(): void {
  const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
      "-days", "1", "-subj", "/CN=test-ca");
  writeFileSync(join(dir, "server.ext"), "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=critical,serverAuth\n");
  run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=manager");
  run("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", "server.pem", "-days", "1", "-extfile", "server.ext");
  writeFileSync(join(dir, "client.ext"), "extendedKeyUsage=critical,clientAuth\n");
  // Three names, because the cases below are exactly about which of them is asking: the operator who
  // proposed, a second operator, and one who may read the fleet but not change it.
  for (const cn of ["ops-alice", "ops-henry", "ops-view"]) {
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${cn}.key`, "-out", `${cn}.csr`, "-subj", `/CN=${cn}`);
    run("x509", "-req", "-in", `${cn}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", `${cn}.pem`, "-days", "1", "-extfile", "client.ext");
  }
}

const ghKey = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "pkcs1", format: "pem" },
}).privateKey;

/** What the route table saw, so a test can assert the merge was pinned to a head. */
const ghSeen: Array<{ url: string; method: string; body?: unknown }> = [];
/** Flipped by a test that needs the pull request to look different without a second server. */
let prOverride: Record<string, unknown> = {};
let checkRuns: unknown[] = [{ name: "check", status: "completed", conclusion: "success" }];

const ghFetch = (async (url: string, init?: { method?: string; body?: string }) => {
  const method = init?.method ?? "GET";
  ghSeen.push({ url, method, ...(init?.body ? { body: JSON.parse(init.body) } : {}) });
  const reply = (status: number, body: unknown) => ({ ok: status < 400, status, text: async () => JSON.stringify(body) });
  if (method === "POST" && /access_tokens$/.test(url)) return reply(200, { token: "t" });
  if (method === "GET" && /pulls\/7$/.test(url)) {
    return reply(200, {
      number: 7, html_url: "https://example.invalid/pull/7", state: "open", merged: false,
      head: { sha: HEAD, ref: "policy/ops-alice/20260920-000000" }, base: { sha: "b", ref: "main" },
      mergeable: true, mergeable_state: "clean",
      body: "Proposed from the heliopause console by `ops-alice`.\n\nheliopause-proposed-by: `ops-alice`",
      ...prOverride,
    });
  }
  if (method === "GET" && /check-runs/.test(url)) return reply(200, { total_count: checkRuns.length, check_runs: checkRuns });
  if (method === "GET" && /commits\/[0-9a-f]+\/status/.test(url)) return reply(200, { statuses: [] });
  if (method === "PUT" && /pulls\/7\/merge$/.test(url)) return reply(200, { merged: true, sha: "c".repeat(40) });
  throw new Error(`no route for ${method} ${url}`);
}) as unknown as NonNullable<Parameters<typeof startManager>[0]["policyWrite"]>["fetch"];

const kubeFetch: KubeFetcher = async (path) => {
  if (path.includes("/pods")) {
    return {
      status: 200,
      text: JSON.stringify({
        items: [{
          metadata: { name: "test-0", labels: { "app.kubernetes.io/name": "test", "stardust.io/database-id": "74e4726f" } },
          spec: { containers: [{ ports: [{ containerPort: 5432 }] }] },
        }],
      }),
    };
  }
  if (path.includes("/services")) {
    return {
      status: 200,
      text: JSON.stringify({
        items: [{ metadata: { name: "test" }, spec: { clusterIP: "10.17.202.239", selector: { app: "test" }, ports: [{ port: 5432 }] } }],
      }),
    };
  }
  throw new Error(`no route for ${path}`);
};

let port = 0;
let bare = 0;
let close: () => void = () => {};
let closeBare: () => void = () => {};

before(async () => {
  pki();
  const tls = { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") };
  const relays = [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }];
  const started = await startManager({
    port: 0, hostname: "127.0.0.1", relays, tls, timeoutMs: 200,
    // `ops-view` is an operator and not a writer. Without that pair the write gate has no known
    // negative and this suite would pass with `mayWrite` deleted.
    operatorCNs: ["ops-alice", "ops-henry", "ops-view"],
    writerCNs: ["ops-alice", "ops-henry"],
    policyWrite: {
      creds: { appId: "1", installationId: "2", privateKey: ghKey },
      target: { owner: "o", repo: "r", base: "main" },
      allowPaths: ["policies.json"],
      fetch: ghFetch,
    },
    kubeRead: {
      namespaces: ["stardust-databases"],
      apiUrl: "https://kubernetes.invalid",
      tokenFile: "/dev/null",
      caFile: "/dev/null",
      fetch: kubeFetch,
    },
  });
  port = (started.server.address() as { port: number }).port;
  close = () => started.server.close();

  // The same manager with neither power. A 404 here is what a deployment that was never granted
  // anything must look like — and the difference between 404 and 403 is the difference between "this
  // console does not do that" and "you may not", which is the sentence an operator debugs from.
  const plain = await startManager({
    port: 0, hostname: "127.0.0.1", relays, tls, timeoutMs: 200,
    operatorCNs: ["ops-alice"], writerCNs: ["ops-alice"],
  });
  bare = (plain.server.address() as { port: number }).port;
  closeBare = () => plain.server.close();
});

after(() => { close(); closeBare(); rmSync(dir, { recursive: true, force: true }); });

function call(
  as: string,
  path: string,
  method = "GET",
  body?: string,
  at = 0,
): Promise<{ status: number; json: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const r = request({
      host: "127.0.0.1", port: at || port, path, method,
      ca: [readFileSync(join(dir, "ca.pem"))],
      cert: readFileSync(join(dir, `${as}.pem`)), key: readFileSync(join(dir, `${as}.key`)),
      ...(body ? { headers: { "content-type": "application/json" } } : {}),
    }, (res) => {
      let b = ""; res.on("data", (d) => (b += d));
      res.on("end", () => {
        let json: Record<string, unknown> = {};
        try { json = JSON.parse(b) as Record<string, unknown>; } catch { json = { raw: b }; }
        resolve({ status: res.statusCode ?? 0, json });
      });
    });
    r.on("error", reject);
    if (body) r.write(body);
    r.end();
  });
}

describe("the console measures a destination", () => {
  it("answers what it may look at before it is asked for a namespace", async () => {
    const r = await call("ops-henry", "/policy/measure");
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.namespaces, ["stardust-databases"]);
    assert.equal(r.json.pods, undefined, "a namespace list is not a measurement");
  });

  it("reports the labels a selector should be written against", async () => {
    const r = await call("ops-henry", "/policy/measure?ns=stardust-databases");
    assert.equal(r.status, 200);
    const pods = r.json.pods as Array<{ name: string; stable: Record<string, string> }>;
    assert.equal(pods[0]?.name, "test-0");
    assert.deepEqual(pods[0]?.stable, {
      "app.kubernetes.io/name": "test",
      "stardust.io/database-id": "74e4726f",
    });
    const services = r.json.services as Array<{ clusterIP: string }>;
    assert.equal(services[0]?.clusterIP, "10.17.202.239");
  });

  it("answers on the /api prefix the console actually calls", async () => {
    const r = await call("ops-henry", "/api/policy/measure?ns=stardust-databases");
    assert.equal(r.status, 200);
  });

  it("refuses a namespace outside the list the RoleBinding was written for", async () => {
    const r = await call("ops-henry", "/policy/measure?ns=kube-system");
    assert.equal(r.status, 403);
    assert.match(String(r.json.error), /may only look in/);
  });

  // Behind the write gate. A viewer has no rule to author, and this is the one route on the console
  // that reads the cluster rather than the policy.
  it("is not offered to a caller who may read but not write", async () => {
    const r = await call("ops-view", "/policy/measure?ns=stardust-databases");
    assert.equal(r.status, 403);
  });

  it("is a 404 and not a 403 on a manager that was never granted it", async () => {
    const r = await call("ops-alice", "/policy/measure", "GET", undefined, bare);
    assert.equal(r.status, 404);
  });
});

describe("the console merges its own pull request", () => {
  before(() => forgetInstallationTokens());

  it("tells the screen why the button is not live", async () => {
    const r = await call("ops-alice", "/policy/pr?number=7");
    assert.equal(r.status, 200);
    assert.equal(r.json.proposedBy, "ops-alice");
    assert.equal(r.json.mayMerge, false, "alice proposed #7");
    assert.match(String(r.json.why), /proposed by ops-alice/);
  });

  it("says the same pull request is mergeable by somebody else", async () => {
    const r = await call("ops-henry", "/policy/pr?number=7");
    assert.equal(r.json.mayMerge, true);
    assert.equal(r.json.why, undefined);
  });

  // The identity half. Everything the rule needs was already true — green checks, a clean merge —
  // and the only thing standing between alice and her own merge is the CN on the connection.
  it("refuses the proposer at the route, not only on the screen", async () => {
    const before = ghSeen.filter((s) => s.method === "PUT").length;
    const r = await call("ops-alice", "/policy/merge", "POST", JSON.stringify({ number: 7 }));
    assert.equal(r.status, 409);
    assert.match(String(r.json.error), /does not merge it/);
    assert.equal(ghSeen.filter((s) => s.method === "PUT").length, before, "it must not have asked to merge");
  });

  it("merges for a second operator, pinned to the head it checked", async () => {
    const r = await call("ops-henry", "/policy/merge", "POST", JSON.stringify({ number: 7 }));
    assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.equal(r.json.sha, "c".repeat(40));
    // Merging moves the source. An operator reading "merged" on a policy screen has every reason to
    // think the fleet moved, and it has not.
    assert.equal(r.json.published, false);
    const puts = ghSeen.filter((call) => call.method === "PUT");
    const put = puts[puts.length - 1];
    assert.deepEqual(put?.body, { merge_method: "squash", sha: HEAD });
  });

  it("refuses a red check even when the two operators differ", async () => {
    checkRuns = [{ name: "defense-in-depth leak scan", status: "completed", conclusion: "failure" }];
    try {
      const r = await call("ops-henry", "/policy/merge", "POST", JSON.stringify({ number: 7 }));
      assert.equal(r.status, 409);
      assert.match(String(r.json.error), /leak scan/);
    } finally {
      checkRuns = [{ name: "check", status: "completed", conclusion: "success" }];
    }
  });

  // Fail closed on a pull request this console did not open. Without the trailer there is no second
  // person to compare against, and "nobody proposed it" must not mean "anybody may merge it".
  it("refuses a pull request it cannot attribute", async () => {
    prOverride = { body: "opened by hand" };
    try {
      const r = await call("ops-henry", "/policy/merge", "POST", JSON.stringify({ number: 7 }));
      assert.equal(r.status, 409);
      assert.match(String(r.json.error), /cannot say who proposed/);
    } finally {
      prOverride = {};
    }
  });

  it("is not offered to a caller who may read but not write", async () => {
    const r = await call("ops-view", "/policy/merge", "POST", JSON.stringify({ number: 7 }));
    assert.equal(r.status, 403);
  });

  it("refuses a body with no pull request number", async () => {
    const r = await call("ops-henry", "/policy/merge", "POST", JSON.stringify({ number: "seven" }));
    assert.equal(r.status, 400);
  });

  it("is a 404 on a manager holding no write credential", async () => {
    const r = await call("ops-alice", "/policy/merge", "POST", JSON.stringify({ number: 7 }), bare);
    assert.equal(r.status, 404);
  });
});
