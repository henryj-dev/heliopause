/**
 * Each service's default log writer prefixes a line once (#163).
 *
 * The default writer and `log`/`logEvent` each added the service tag, so a line written without an
 * injected `log` read `[relay] [relay] …`. Every other test passes `log`, which bypasses the default
 * writer — so these start the services without one and read what reaches `console.error`.
 * The manager's half is in `src/manager-startup-env.test.ts`.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRelay } from "./relay.ts";
import { initializeRevocationSnapshot } from "./revocation-snapshot.ts";
import { installRevocationSnapshot, startRevocationWriter } from "./revocation-writer.ts";

const dir = mkdtempSync(join(tmpdir(), "hp-log-prefix-"));

before(() => {
  const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
      "-days", "1", "-subj", "/CN=test-ca");
  run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "relay.key", "-out", "relay.csr", "-subj", "/CN=relay");
  writeFileSync(join(dir, "relay.ext"), "extendedKeyUsage=critical,serverAuth\nsubjectAltName=IP:127.0.0.1\n");
  run("x509", "-req", "-in", "relay.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", "relay.pem", "-days", "1", "-extfile", "relay.ext");
});

after(() => rmSync(dir, { recursive: true, force: true }));

describe("the default log writer prefixes a line once (#163)", () => {
  it("relay", async (t) => {
    const errors = t.mock.method(console, "error", () => {});
    const artifactDir = join(dir, "artifacts");
    mkdirSync(artifactDir, { recursive: true });
    const relay = await startRelay({
      artifactDir, port: 0, hostname: "127.0.0.1",
      tls: { certFile: join(dir, "relay.pem"), keyFile: join(dir, "relay.key"), caFile: join(dir, "ca.pem") },
      operatorCNs: ["ops-alice"],
    });
    await new Promise<void>((resolve) => relay.server.close(() => resolve()));
    const lines = errors.mock.calls.map((c) => String(c.arguments[0]));
    const listening = lines.find((l) => l.includes("listening on"));
    assert.ok(listening, lines.join("\n"));
    assert.match(listening, /^\[relay\] listening on /);
    assert.deepEqual(lines.filter((l) => l.startsWith("[relay] [relay]")), []);
  });

  it("revocation writer", async (t) => {
    const errors = t.mock.method(console, "error", () => {});
    const snapshotFile = join(dir, "revocations.json");
    const socketPath = join(dir, "writer.sock");
    await initializeRevocationSnapshot(snapshotFile, undefined, { mode: 0o644 });
    const writer = await startRevocationWriter({ snapshotFile, socketPath });
    try {
      await installRevocationSnapshot(socketPath, { schemaVersion: 1, revocations: [] });
    } finally {
      await new Promise<void>((resolve) => writer.server.close(() => resolve()));
    }
    const lines = errors.mock.calls.map((c) => String(c.arguments[0]));
    assert.ok(lines.length > 0, "the writer logged nothing to check");
    for (const line of lines) assert.match(line, /^\[revocation-writer\] (?!\[revocation-writer\])/);
  });
});
