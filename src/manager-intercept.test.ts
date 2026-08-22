import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { startManager } from "./manager-server.ts";

const dir = mkdtempSync(join(tmpdir(), "hp-intercept-"));
let port = 0;
let close: () => void = () => {};

function pki(): void {
  const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
    "-days", "1", "-subj", "/CN=test-ca");
  for (const [name, eku] of [["server", "serverAuth"], ["ops", "clientAuth"]] as const) {
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`,
      "-subj", `/CN=${name === "server" ? "manager" : "ops-alice"}`);
    writeFileSync(join(dir, `${name}.ext`),
      `extendedKeyUsage=critical,${eku}\n` + (name === "server" ? "subjectAltName=IP:127.0.0.1\n" : ""));
    run("x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", `${name}.pem`, "-days", "1", "-extfile", `${name}.ext`);
  }
}

function get(path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({
      host: "127.0.0.1",
      port,
      path,
      method: "GET",
      ca: [readFileSync(join(dir, "ca.pem"))],
      cert: readFileSync(join(dir, "ops.pem")),
      key: readFileSync(join(dir, "ops.key")),
    }, (res) => {
      let b = "";
      res.on("data", (d) => (b += d));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b }));
    });
    req.on("error", reject);
    req.end();
  });
}

before(async () => {
  pki();
  const started = await startManager({
    port: 0,
    hostname: "127.0.0.1",
    relays: [{ name: "dev", url: "https://127.0.0.1:1/", pkiDir: dir }],
    tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
    operatorCNs: ["ops-alice"],
    timeoutMs: 200,
    intercept: (req, res) => {
      const path = new URL(req.url ?? "/", "https://manager.invalid").pathname;
      if (path !== "/app") return false;
      res.writeHead(200, { "content-type": "text/plain" }).end("new-console");
      return true;
    },
  });
  port = (started.server.address() as { port: number }).port;
  close = () => started.server.close();
});

after(() => {
  close();
  rmSync(dir, { recursive: true, force: true });
});

describe("manager intercept", () => {
  it("lets the workspace console claim /app without moving /healthz or /site", async () => {
    assert.equal((await get("/app")).body, "new-console");
    assert.equal((await get("/healthz")).body, JSON.stringify({ ok: true }));
    assert.equal((await get("/site")).status, 200);
  });
});
