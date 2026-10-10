/**
 * The manager's entry point, started as a process, read off its startup line (#154, #161).
 *
 * `startManager` is tested in-process everywhere else, and that left the wiring in
 * `bin/heliopause-manager.ts` unseen: reverting it to "pass plan limits only when
 * `HELIOPAUSE_PLAN_TTL_SEC` is set" — the defect #161 fixed — kept every in-process test green. Only
 * the binary reads the environment, so only the binary can show that a variable reaches the manager.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";

const BIN = join(import.meta.dirname, "..", "bin", "heliopause-manager.ts");
const dir = mkdtempSync(join(tmpdir(), "hp-mgr-bin-"));
const signingKey = join(dir, "signing.pem");

before(() => {
  const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
      "-days", "1", "-subj", "/CN=test-ca");
  run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=manager");
  writeFileSync(join(dir, "server.ext"), "extendedKeyUsage=critical,serverAuth\nsubjectAltName=IP:127.0.0.1\n");
  run("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", "server.pem", "-days", "1", "-extfile", "server.ext");
  writeFileSync(signingKey, generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }));
  chmodSync(signingKey, 0o600);
});

after(() => rmSync(dir, { recursive: true, force: true }));

/** Start the binary, return its `limits:` line, and stop it. Fails if it exits or stays silent. */
function startupLimitsLine(extraEnv: Record<string, string>): Promise<string> {
  const proc = spawn(process.execPath, [BIN], {
    env: {
      PATH: process.env.PATH ?? "",
      HELIOPAUSE_RELAYS: `alpha=https://127.0.0.1:1/=${dir}`,
      HELIOPAUSE_MANAGER_PORT: "0",
      HELIOPAUSE_MANAGER_HOST: "127.0.0.1",
      HELIOPAUSE_CERT_FILE: join(dir, "server.pem"),
      HELIOPAUSE_KEY_FILE: join(dir, "server.key"),
      HELIOPAUSE_CA_FILE: join(dir, "ca.pem"),
      HELIOPAUSE_ARTIFACT_SIGNING_KEY_FILE: signingKey,
      HELIOPAUSE_OPERATOR_CNS: "ops-alice",
      ...extraEnv,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  return new Promise((resolve, reject) => {
    let err = "";
    const timer = setTimeout(() => { proc.kill("SIGKILL"); reject(new Error(`no limits line in 20s:\n${err}`)); }, 20_000);
    proc.stderr.on("data", (b: Buffer) => {
      err += b;
      const line = err.split("\n").find((l) => / limits: /.test(l));
      if (line) { clearTimeout(timer); proc.kill("SIGKILL"); resolve(line); }
    });
    proc.on("exit", (code) => { clearTimeout(timer); reject(new Error(`the manager exited ${code} first:\n${err}`)); });
  });
}

describe("the manager binary passes each plan limit on its own (#161)", () => {
  it("uses a pending cap given without a plan TTL", { timeout: 30_000 }, async () => {
    const line = await startupLimitsLine({ HELIOPAUSE_MAX_PENDING_PLANS: "5" });
    assert.match(line, /plan TTL 10m \(default\); at most 5 pending plans \(env\)$/);
  });

  it("uses a plan TTL given without a pending cap", { timeout: 30_000 }, async () => {
    const line = await startupLimitsLine({ HELIOPAUSE_PLAN_TTL_SEC: "120" });
    assert.match(line, /plan TTL 2m \(env\); at most 32 pending plans \(default\)$/);
  });

  it("names the defaults when neither is set, with the authorization TTL beside the protocol cap", { timeout: 30_000 }, async () => {
    const line = await startupLimitsLine({});
    assert.match(line, /limits: artifact authorization TTL 24h \(default\), protocol cap 168h; plan TTL 10m \(default\); at most 32 pending plans \(default\)$/);
  });
});
