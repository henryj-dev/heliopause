// `GET /routes` through a real manager: one policy source read per relay, by that relay's name.
//
// The joining is `routes-view.test.ts`. This file is about the handler — that it asks the renderer
// for every relay's site and not only the first, that one site failing does not take the others
// with it, and that every site failing is still a 503.

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

let dir = "";
const closers: Array<() => void> = [];
const read = (f: string) => readFileSync(join(dir, f));

/** What the fake renderer was asked for, in order. */
const asked: Array<string | null> = [];

/** The renderer's answer for one site: a distinct commit per site, so the response shows which was read. */
function body(site: string): string {
  const collected = collectPolicySource({
    site: { cfg: defineConfig({ baseline: [] }), hosts: [] } as never,
    sitePath: "/nonexistent/site.ts", label: site, allowPaths: [],
  });
  const sha = (site === "dev" ? "d" : site === "az01" ? "a" : "f").repeat(40);
  return JSON.stringify({ ...collected, head: { sha, dirty: false }, repo: { probes: [], commits: [], generation: sha.slice(0, 7) } });
}

async function manager(failing: ReadonlySet<string>): Promise<number> {
  const started = await startManager({
    port: 0,
    hostname: "127.0.0.1",
    relays: [
      { name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir },
      { name: "az01", url: "https://127.0.0.1:1/", pkiDir: dir },
      { name: "prod", url: "https://127.0.0.1:1/", pkiDir: dir },
    ],
    tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
    operatorCNs: ["ops-alice"],
    writerCNs: ["ops-alice"],
    timeoutMs: 500,
    log: () => {},
    policySource: {
      url: "http://renderer.invalid",
      fetch: (async (u: string) => {
        const site = new URL(u).searchParams.get("site");
        asked.push(site);
        if (site && failing.has(site)) {
          return new Response(JSON.stringify({ error: `no such site ${site}` }), { status: 400, headers: { "content-type": "application/json" } });
        }
        return new Response(body(site ?? "none"), { status: 200, headers: { "content-type": "application/json" } });
      }) as unknown as typeof fetch,
    },
  } as Parameters<typeof startManager>[0]);
  closers.push(() => started.server.close());
  return (started.server.address() as { port: number }).port;
}

function get(port: number, path: string): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const req = request({
      host: "127.0.0.1", port, path, method: "GET",
      ca: [read("ca.pem")], cert: read("ops.pem"), key: read("ops.key"),
      signal: AbortSignal.timeout(10_000),
    }, (res) => {
      let b = ""; res.on("data", (d) => (b += d));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: JSON.parse(b) }));
    });
    req.on("error", reject);
    req.end();
  });
}

before(() => {
  dir = mkdtempSync(join(tmpdir(), "hp-routes-"));
  const ssl = (...a: string[]) => execFileSync("openssl", a, { cwd: dir, stdio: "pipe" });
  ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=test-ca");
  writeFileSync(join(dir, "server.ext"), "subjectAltName=IP:127.0.0.1\n");
  for (const [name, cn] of [["server", "127.0.0.1"], ["ops", "ops-alice"]] as const) {
    ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", `/CN=${cn}`);
    ssl("x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", `${name}.pem`, "-days", "1", ...(name === "server" ? ["-extfile", "server.ext"] : []));
  }
  // The manager names its own client certificate per relay; one operator file in `dir` is enough.
  ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "operator-hp.key", "-out", "operator-hp.csr", "-subj", "/CN=hp");
  ssl("x509", "-req", "-in", "operator-hp.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "operator-hp.pem", "-days", "1");
});

after(() => {
  for (const c of closers) c();
  rmSync(dir, { recursive: true, force: true });
});

describe("GET /routes reads one policy source per relay", () => {
  it("asks the renderer for every relay's site by name, not only the first", async () => {
    const port = await manager(new Set());
    asked.length = 0;
    const r = await get(port, "/routes");
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual([...asked].sort(), ["az01", "dev", "prod"]);
    assert.deepEqual(r.body.sites.map((s: any) => [s.site, s.generation?.[0], s.error]),
      [["dev", "d", null], ["az01", "a", null], ["prod", "f", null]]);
    assert.equal(r.body.generation, "d".repeat(40), "the top-level generation is no longer the first relay's");
  });

  it("answers for the sites it could read when one cannot be", async () => {
    const port = await manager(new Set(["az01"]));
    const r = await get(port, "/routes");
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const az = r.body.sites.find((s: any) => s.site === "az01");
    assert.match(az.error, /the policy could not be read: no such site az01/);
    assert.deepEqual(r.body.sites.filter((s: any) => s.error === null).map((s: any) => s.site), ["dev", "prod"]);
  });

  it("is a 503 when no site can be read, and still names each one", async () => {
    const port = await manager(new Set(["dev", "az01", "prod"]));
    const r = await get(port, "/routes");
    assert.equal(r.status, 503);
    assert.match(r.body.error, /the policy could not be read/);
    assert.deepEqual(r.body.sites.map((s: any) => s.site), ["dev", "az01", "prod"]);
  });
});
