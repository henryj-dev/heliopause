// `POST /policy/preview` on the manager: relayed to the renderer, writers only, and nothing else.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:https";
import { startManager } from "./manager-server.ts";

let dir = "";
let port = 0;
let close: () => void = () => {};
const seen: { url: string; body: string; auth: string | null }[] = [];

const read = (f: string) => readFileSync(join(dir, f));

function post(path: string, body: string, who: "ops" | "reader"): Promise<{ status: number; body: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const req = request({
      host: "127.0.0.1", port, path, method: "POST",
      ca: [read("ca.pem")], cert: read(`${who}.pem`), key: read(`${who}.key`),
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
    }, (res) => {
      let b = ""; res.on("data", (d) => (b += d));
      res.on("end", () => {
        let parsed: Record<string, unknown> = {};
        try { parsed = JSON.parse(b) as Record<string, unknown>; } catch { parsed = { raw: b }; }
        resolve({ status: res.statusCode ?? 0, body: parsed });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "hp-manager-preview-"));
  const ssl = (...a: string[]) => execFileSync("openssl", a, { cwd: dir, stdio: "pipe" });
  ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
    "-days", "1", "-subj", "/CN=test-ca");
  for (const [name, cn] of [["server", "127.0.0.1"], ["ops", "ops-alice"], ["reader", "ops-bob"]] as const) {
    ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", `/CN=${cn}`);
    const ext = join(dir, "server.ext");
    writeFileSync(ext, "subjectAltName=IP:127.0.0.1\n");
    ssl("x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", `${name}.pem`, "-days", "1", ...(name === "server" ? ["-extfile", ext] : []));
  }
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const started = await startManager({
    port: 0,
    hostname: "127.0.0.1",
    relays: [{ name: "alpha", url: "https://127.0.0.1:1/", pkiDir: dir }],
    tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
    operatorCNs: ["ops-alice", "ops-bob"],
    writerCNs: ["ops-alice"],
    timeoutMs: 2_000,
    policySource: {
      url: "http://renderer.invalid",
      token: "renderer-bearer",
      fetch: (async (url: string, init: RequestInit) => {
        seen.push({
          url,
          body: String(init.body),
          auth: (init.headers as Record<string, string>)?.authorization ?? null,
        });
        return new Response(JSON.stringify({ site: "alpha", changes: [] }), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }) as unknown as typeof fetch,
    },
    policyWrite: {
      creds: { appId: "1", installationId: "2", privateKey: privateKey.export({ type: "pkcs8", format: "pem" }) as string },
      target: { owner: "o", repo: "r", base: "main" },
      allowPaths: ["policies.json"],
      fetch: (async () => { throw new Error("the preview must not reach GitHub"); }) as never,
    },
  } as Parameters<typeof startManager>[0]);
  port = (started.server.address() as { port: number }).port;
  close = () => started.server.close();
});

after(() => {
  close();
  rmSync(dir, { recursive: true, force: true });
});

describe("the manager relays a preview to the renderer", () => {
  it("forwards the edit with the renderer's bearer and returns its answer", async () => {
    seen.length = 0;
    const edit = JSON.stringify({ path: "policies.json", content: "{}" });
    const r = await post("/policy/preview?site=alpha", edit, "ops");
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body, { site: "alpha", changes: [] });
    assert.equal(seen.length, 1);
    assert.match(seen[0]!.url, /^http:\/\/renderer\.invalid\/preview\?site=alpha$/);
    assert.equal(seen[0]!.body, edit);
    assert.equal(seen[0]!.auth, "Bearer renderer-bearer");
  });

  it("refuses a reader, an unknown site, and never reaches the renderer for them", async () => {
    seen.length = 0;
    const edit = JSON.stringify({ path: "policies.json", content: "{}" });
    assert.equal((await post("/policy/preview?site=alpha", edit, "reader")).status, 403);
    assert.equal((await post("/policy/preview?site=beta", edit, "ops")).status, 400);
    assert.equal(seen.length, 0);
  });
});
