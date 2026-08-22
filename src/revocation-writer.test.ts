import assert from "node:assert/strict";
import { createConnection } from "node:net";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  MAX_REVOCATION_SNAPSHOT_BYTES,
  initializeRevocationSnapshot,
} from "./revocation-snapshot.ts";
import { installRevocationSnapshot, startRevocationWriter } from "./revocation-writer.ts";

const row = (fingerprint: string) => ({
  fingerprint256: fingerprint.repeat(64),
  subject: `CN=node-${fingerprint}`,
  reason: "test",
  actor: "ops",
  revokedAt: "2026-08-15T00:00:00.000Z",
});

const close = (server: Awaited<ReturnType<typeof startRevocationWriter>>["server"]) =>
  new Promise<void>((resolve) => server.close(() => resolve()));

describe("privilege-separated revocation writer", () => {
  it("serializes competing updates and never removes an installed row", async () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-revocation-writer-"));
    const snapshotFile = join(root, "revocations.json");
    const socketPath = join(root, "writer.sock");
    await initializeRevocationSnapshot(snapshotFile, undefined, { mode: 0o644 });
    const writer = await startRevocationWriter({ snapshotFile, socketPath, log: () => {} });
    try {
      const first = row("a");
      await installRevocationSnapshot(socketPath, { schemaVersion: 1, revocations: [first] });
      assert.equal(statSync(snapshotFile).mode & 0o777, 0o644);

      const candidates = [row("b"), row("c")];
      const results = await Promise.allSettled(candidates.map((candidate) =>
        installRevocationSnapshot(socketPath, { schemaVersion: 1, revocations: [first, candidate] })));
      assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
      assert.equal(results.filter((result) => result.status === "rejected").length, 1);
      const installed = JSON.parse(readFileSync(snapshotFile, "utf8"));
      assert.equal(installed.revocations.length, 2);
      assert.deepEqual(installed.revocations[0], first);

      await assert.rejects(
        installRevocationSnapshot(socketPath, { schemaVersion: 1, revocations: [] }),
        /refused/,
      );
      assert.deepEqual(JSON.parse(readFileSync(snapshotFile, "utf8")), installed);
    } finally {
      await close(writer.server);
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("bounds both client and raw socket request bodies", async () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-revocation-writer-limit-"));
    const snapshotFile = join(root, "revocations.json");
    const socketPath = join(root, "writer.sock");
    await initializeRevocationSnapshot(snapshotFile, undefined, { mode: 0o644 });
    const writer = await startRevocationWriter({
      snapshotFile,
      socketPath,
      log: () => {},
      requestTimeoutMs: 30,
    });
    try {
      // ## The oversized body has to be *valid* to reach the byte bound
      //
      // Padding it with an unknown key never got there: `parseRevocationSnapshot` rejects unsupported
      // fields first, so the assertion passed on "contains unsupported fields" — a different refusal
      // that would still fire with no byte bound in the code at all.
      //
      // So the payload here is a structurally perfect snapshot, filled to each field's own limit.
      // 141 maximally-sized rows fit in 254,541 bytes and 150 do not, while the row cap is 2,048 —
      // which is what makes the byte bound reachable rather than shadowed by the row count. The match
      // is on the byte message specifically, because `exceeds` alone also matches the row refusal.
      const fat = (i: number) => ({
        fingerprint256: i.toString(16).padStart(64, "0"),
        subject: "s".repeat(1_024),
        reason: "r".repeat(500),
        actor: "a".repeat(120),
        revokedAt: "2026-01-01T00:00:00.000Z",
      });
      assert.throws(
        () => installRevocationSnapshot(socketPath, {
          schemaVersion: 1,
          revocations: Array.from({ length: 150 }, (_, i) => fat(i + 1)),
        }),
        new RegExp(`exceeds ${MAX_REVOCATION_SNAPSHOT_BYTES} bytes`),
      );

      const rawRequest = (payload?: Buffer) => new Promise<{ response: string; destroyed: boolean }>((resolve, reject) => {
        const socket = createConnection(socketPath);
        let response = "";
        socket.setEncoding("utf8");
        socket.once("connect", () => { if (payload) socket.write(payload); });
        socket.on("data", (chunk) => { response += chunk; });
        socket.once("close", () => resolve({ response, destroyed: socket.destroyed }));
        socket.once("error", reject);
      });

      // Do not half-close either request: the writer itself must terminate abusive/idle peers.
      const oversized = await rawRequest(Buffer.alloc(MAX_REVOCATION_SNAPSHOT_BYTES + 1, 0x78));
      assert.equal((JSON.parse(oversized.response) as { ok?: unknown }).ok, false);
      assert.equal(oversized.destroyed, true);

      const timedOut = await rawRequest();
      assert.equal((JSON.parse(timedOut.response) as { error?: unknown }).error, "request timed out");
      assert.equal(timedOut.destroyed, true);
      assert.deepEqual(JSON.parse(readFileSync(snapshotFile, "utf8")), { schemaVersion: 1, revocations: [] });
    } finally {
      await close(writer.server);
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("refuses to serve when durable state is missing", async () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-revocation-writer-missing-"));
    await assert.rejects(
      startRevocationWriter({ snapshotFile: join(root, "missing.json"), socketPath: join(root, "writer.sock") }),
      /ENOENT/,
    );
    rmSync(root, { recursive: true, force: true });
  });
});
