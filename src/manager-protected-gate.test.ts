// The protected-host gate on the **console** propose path.
//
// ## Why this file exists at all
//
// The gate's unit tests call `assertProtectedAllowed` directly, so removing the call from a propose
// path leaves every one of them green — an independent review measured exactly that and it was
// right. The CLI's wiring is covered by `publish-cli.test.ts`, which runs the real binary. This
// covers the other path an operator actually uses: prod and util are published from the console,
// whose only host is a protected gateway, so most of what the gate protects lives here.
//
// ## Why there is no HTTP stub for the renderer
//
// `ManagerOptions.policySource.fetch` is injectable "for tests" by its own comment, so the renderer
// is a function returning one JSON body rather than a second server. The body is built by the real
// `collectPolicySource` + `JSON.stringify` crossing rather than hand-written, so it has the shape
// the renderer actually produces.
//
// ⚠️ That is **not** a guarantee the manager accepts it — a second review measured configs that
// collect fine and are then refused by `parsePolicySource`, which is what the first version of this
// comment implied could not happen. What the crossing buys is realism, not acceptance; acceptance
// is why the fixture below carries `head` and `repo` explicitly, having been refused twice without.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:https";
import { startManager } from "./manager-server.ts";
import { collectPolicySource } from "./policy-source.ts";
import { defineConfig } from "./config.ts";
import { contains } from "./test-util.ts";
import type { Policy } from "./policy.ts";

let dir = "";
let port = 0;
let close: () => void = () => {};

const read = (f: string) => readFileSync(join(dir, f));

/** A site whose single host is protected — the shape prod and util actually have. */
function guardedSite() {
  const policy: Policy = {
    id: "P1", name: "management", src: { kind: "cidr", value: "10.0.0.0/8" },
    dst: { kind: "host", value: "gw-01.dev" }, proto: "tcp", ports: "22",
    action: "allow", denyMode: "drop", priority: 100, enabled: true, notes: "",
  };
  return {
    cfg: defineConfig({
      baseline: [{ desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: ["10.0.0.0/8"] }],
      protectedHosts: ["^gw-01\\."],
    }),
    hosts: [{ id: "gw-01.dev", stage: "canary" as const, items: [{ policy, dstCidrs: ["10.0.0.1"] }] }],
  };
}

/** The renderer's answer, as JSON that has actually crossed `JSON.stringify`. */
function sourceBody(): string {
  const collected = collectPolicySource({
    site: guardedSite() as never,
    sitePath: "/nonexistent/policy/site.ts",
    label: "test",
    allowPaths: [],
  });
  // `repo` and `head` are separate and both required: `repo` is what the renderer found beside the
  // module (probes, commits), `head` is the checkout it rendered from. The propose path refuses an
  // unnamed or dirty head, so `sha` has to be set and `dirty` false for the gate to be what this
  // test measures.
  return JSON.stringify({
    ...collected,
    head: { sha: "a".repeat(40), dirty: false },
    repo: { probes: [], commits: [], generation: "a".repeat(7) },
  });
}

/** POST as the operator. Returns status and parsed body. */
function post(path: string, body: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = request({
      host: "127.0.0.1", port, path, method: "POST",
      ca: [read("ca.pem")], cert: read("ops.pem"), key: read("ops.key"),
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) },
    }, (res) => {
      let b = ""; res.on("data", (d) => (b += d));
      res.on("end", () => {
        let parsed: Record<string, unknown> = {};
        try { parsed = JSON.parse(b) as Record<string, unknown>; } catch { parsed = { raw: b }; }
        resolve({ status: res.statusCode ?? 0, body: parsed });
      });
    });
    req.on("error", reject);
    req.end(payload);
  });
}

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "hp-protected-gate-"));
  const ssl = (...a: string[]) => execFileSync("openssl", a, { cwd: dir, stdio: "pipe" });
  ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
    "-days", "1", "-subj", "/CN=test-ca");
  for (const [name, cn] of [["server", "127.0.0.1"], ["ops", "ops-alice"]] as const) {
    ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`,
      "-subj", `/CN=${cn}`);
    ssl("x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key",
      "-CAcreateserial", "-out", `${name}.pem`, "-days", "1",
      ...(name === "server" ? ["-extfile", writeExt(dir)] : []));
  }
  const body = sourceBody();
  const started = await startManager({
    port: 0,
    hostname: "127.0.0.1",
    relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
    tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
    operatorCNs: ["ops-alice"],
    writerCNs: ["ops-alice"],
    timeoutMs: 500,
    policySource: {
      url: "http://renderer.invalid",
      // One body, every time. The gate runs after the render, so the render has to succeed for the
      // refusal under test to be the one being measured.
      fetch: (async () => new Response(body, {
        status: 200, headers: { "content-type": "application/json" },
      })) as unknown as typeof fetch,
    },
  } as Parameters<typeof startManager>[0]);
  port = (started.server.address() as { port: number }).port;
  close = () => started.server.close();
});

after(() => {
  close();
  rmSync(dir, { recursive: true, force: true });
});

function writeExt(d: string): string {
  const path = join(d, "server.ext");
  writeFileSync(path, "subjectAltName=IP:127.0.0.1\n");
  return path;
}

describe("the console propose path and protected hosts", () => {
  it("answers 409 with needsAllowProtected, naming the host", () => {
    // 🔴 Removing `assertProtectedAllowed(...)` from the console branch of `manager-server.ts`
    // fails here. That is the gap the unit tests did not cover.
    return post("/policy/plan", { target: "dev" }).then((r) => {
      assert.equal(r.status, 409, `body: ${JSON.stringify(r.body)}`);
      assert.equal(r.body.needsAllowProtected, true);
      contains(String(r.body.error), "gw-01.dev");
    });
  });

  it("proposes with the opt-in carried, and records it on the plan", () => {
    // 🔴 This asserted only `status !== 409` first, with a comment claiming 200 could not be
    // asserted because the relay is unreachable. A second review measured both halves of that
    // wrong: the proposal **does** answer 200 (proposing stores a plan; it does not reach a relay),
    // and the loose assertion stayed green when the recording spread at the console's `planPublish`
    // call was deleted. So it tested the gate twice and the recording not at all.
    //
    // `summary.allowProtected` is the record: `summarise` reads it off the bundle, and that is what
    // `printPlan` turns into the sentence the approver sees. Deleting the recording fails here.
    return post("/policy/plan", { target: "dev", allowProtected: true }).then((r) => {
      assert.equal(r.status, 200, `body: ${JSON.stringify(r.body)}`);
      const summary = r.body.summary as { allowProtected?: unknown } | undefined;
      assert.equal(summary?.allowProtected, true, "the plan did not record the opt-in");
    });
  });

  it("treats a looser opt-in as no opt-in", () => {
    // `=== true` and nothing else. A client that sent `"true"` meant yes, but a reader that accepts
    // it also accepts whatever another client sends by accident, and this field is the whole opt-in.
    return post("/policy/plan", { target: "dev", allowProtected: "true" }).then((r) => {
      assert.equal(r.status, 409, `a string opt-in was accepted: ${JSON.stringify(r.body)}`);
    });
  });
});
