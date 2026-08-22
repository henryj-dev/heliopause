import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  initializeRevocationSnapshot, MAX_REVOCATION_ROWS, MAX_REVOCATION_SNAPSHOT_BYTES,
  parseRevocationSnapshot, serializeRevocationSnapshot, writeRevocationSnapshot,
  planRevocationCompaction,
} from "./revocation-snapshot.ts";
import { revocationReplicationBody } from "./manager-server.ts";

const row = {
  fingerprint256: "a".repeat(64), subject: "CN=host-01", reason: "test", actor: "ops-alice",
  revokedAt: "2026-08-10T00:00:00.000Z",
};

describe("revocation snapshot", () => {
  it("accepts only the minimal denylist schema", () => {
    assert.deepEqual(parseRevocationSnapshot({ schemaVersion: 1, revocations: [row] }).revocations, [row]);
    assert.throws(() => parseRevocationSnapshot({ schemaVersion: 1, revocations: [row], tokens: [] }));
    assert.throws(() => parseRevocationSnapshot({ schemaVersion: 1, revocations: [{ ...row, fingerprint256: "bad" }] }));
    assert.throws(() => parseRevocationSnapshot({ schemaVersion: 1, revocations: [row, row] }), /duplicate/);
    assert.throws(() => parseRevocationSnapshot({ schemaVersion: 1, revocations: [{ ...row, revokedAt: "never" }] }), /revokedAt/);
    assert.throws(
      () => parseRevocationSnapshot({ schemaVersion: 1, revocations: [{ ...row, tokens: ["must-not-cross-boundary"] }] }),
      /unsupported fields/,
    );
    assert.throws(
      () => parseRevocationSnapshot({ schemaVersion: 1, revocations: Array(MAX_REVOCATION_ROWS + 1).fill(row) }),
      /exceeds.*rows/,
    );
    assert.throws(
      () => parseRevocationSnapshot({ schemaVersion: 1, revocations: [{ ...row, reason: "x".repeat(501) }] }),
      /reason/,
    );
  });

  it("requires explicit initialization and writes a complete private document", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-revocations-"));
    try {
      const path = join(dir, "revocations.json");
      await assert.rejects(() => writeRevocationSnapshot(path, { schemaVersion: 1, revocations: [row] }), /ENOENT/);
      await initializeRevocationSnapshot(path);
      assert.equal(statSync(path).mode & 0o777, 0o600);
      await assert.rejects(
        () => initializeRevocationSnapshot(join(dir, "writable.json"), undefined, { mode: 0o666 }),
        /must not be group\/world writable/,
      );
      await writeRevocationSnapshot(path, { schemaVersion: 1, revocations: [row] });
      assert.deepEqual(JSON.parse(readFileSync(path, "utf8")).revocations, [row]);
      await assert.rejects(() => initializeRevocationSnapshot(path), /EEXIST/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses rollback, un-revoke, and mutation of an existing record", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-revocations-floor-"));
    try {
      const path = join(dir, "revocations.json");
      await initializeRevocationSnapshot(path, { schemaVersion: 1, revocations: [row] });
      await assert.rejects(() => writeRevocationSnapshot(path, { schemaVersion: 1, revocations: [] }), /rollback refused/);
      await assert.rejects(
        () => writeRevocationSnapshot(path, { schemaVersion: 1, revocations: [{ ...row, reason: "rewritten" }] }),
        /rewrite refused/,
      );
      assert.deepEqual(JSON.parse(readFileSync(path, "utf8")).revocations, [row]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("provisions a relay-readable bootstrap file through the CLI", () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-revocations-cli-"));
    try {
      const path = join(dir, "revocations.json");
      execFileSync(process.execPath, ["bin/heliopause-revocations.ts", "init", path], { cwd: process.cwd() });
      assert.equal(statSync(path).mode & 0o777, 0o644);
      assert.deepEqual(JSON.parse(readFileSync(path, "utf8")), { schemaVersion: 1, revocations: [] });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("uses one compact representation for the socket and persisted byte limit", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-revocations-bytes-"));
    try {
      const rows: Array<typeof row> = [];
      let candidate: { schemaVersion: 1; revocations: Array<typeof row> } | null = null;
      for (let index = 0; index < MAX_REVOCATION_ROWS; index += 1) {
        rows.push({
          fingerprint256: index.toString(16).padStart(64, "0"),
          subject: `CN=${"s".repeat(1_021)}`,
          reason: "r".repeat(500),
          actor: "a".repeat(120),
          revokedAt: "2026-08-15T00:00:00.000Z",
        });
        const snapshot = { schemaVersion: 1 as const, revocations: [...rows] };
        const compactBytes = Buffer.byteLength(`${JSON.stringify(snapshot)}\n`);
        const prettyBytes = Buffer.byteLength(`${JSON.stringify(snapshot, null, 2)}\n`);
        if (compactBytes <= MAX_REVOCATION_SNAPSHOT_BYTES && prettyBytes > MAX_REVOCATION_SNAPSHOT_BYTES) {
          candidate = snapshot;
          break;
        }
      }
      assert.ok(candidate, "fixture must straddle the former compact-vs-pretty boundary");

      const path = join(dir, "at-limit.json");
      const exact = serializeRevocationSnapshot(candidate);
      assert.equal(revocationReplicationBody(candidate.revocations).equals(exact), true);
      await initializeRevocationSnapshot(path, candidate);
      assert.equal(readFileSync(path).equals(exact), true);
      assert.ok(statSync(path).size <= MAX_REVOCATION_SNAPSHOT_BYTES);

      const oversizedRows = [...candidate.revocations];
      while (Buffer.byteLength(`${JSON.stringify({ schemaVersion: 1, revocations: oversizedRows })}\n`)
        <= MAX_REVOCATION_SNAPSHOT_BYTES) {
        const index = oversizedRows.length;
        oversizedRows.push({
          fingerprint256: index.toString(16).padStart(64, "0"),
          subject: `CN=${"z".repeat(1_021)}`,
          reason: "r".repeat(500),
          actor: "a".repeat(120),
          revokedAt: "2026-08-15T00:00:00.000Z",
        });
      }
      const tooLarge = { schemaVersion: 1 as const, revocations: oversizedRows };
      const refused = join(dir, "oversized.json");
      await assert.rejects(() => initializeRevocationSnapshot(refused, tooLarge), /exceeds.*bytes/);
      assert.equal(existsSync(refused), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ── Compaction ───────────────────────────────────────────────────────────────
//
// The list only grows, by design: `assertMonotonic` refuses any update that omits a row, and that is
// what stops a shorter list from un-revoking a credential. It is also why `MAX_REVOCATION_ROWS` is a
// real ceiling — at 2,048 the relay stops accepting new revocations, which is the one failure a
// denylist cannot have.

describe("planning a compaction", () => {
  const row = (fp: string, subject = "CN=h") => ({
    fingerprint256: fp, subject, reason: "test", actor: "ops", revokedAt: "2026-01-01T00:00:00.000Z",
  });
  const snap = (...rows: ReturnType<typeof row>[]) => parseRevocationSnapshot({ schemaVersion: 1, revocations: rows });
  const NOW = new Date("2026-08-22T00:00:00.000Z");
  const A = "a".repeat(64), B = "b".repeat(64), C = "c".repeat(64);

  it("drops a revocation whose certificate has already expired", () => {
    // The known positive. Without it every refusal below passes against a planner that drops nothing,
    // which is also what "compaction does not work" looks like.
    const plan = planRevocationCompaction(
      snap(row(A)), new Map([[A, "2026-08-01T00:00:00.000Z"]]), NOW,
    );
    assert.equal(plan.drop.length, 1);
    assert.equal(plan.drop[0]!.notAfter, "2026-08-01T00:00:00.000Z");
    assert.deepEqual(plan.keep, []);
  });

  it("keeps one that has not expired yet", () => {
    const plan = planRevocationCompaction(
      snap(row(A)), new Map([[A, "2027-01-01T00:00:00.000Z"]]), NOW,
    );
    assert.deepEqual(plan.drop, []);
    assert.equal(plan.keep.length, 1);
  });

  // The property the whole thing rests on. A fingerprint this deployment cannot date is not a
  // fingerprint it may drop — that would un-revoke a credential that is very possibly still valid,
  // which is precisely what monotonicity exists to prevent.
  it("keeps a revocation the enrollment store cannot date, and says so", () => {
    const plan = planRevocationCompaction(snap(row(A), row(B)), new Map([[B, "2026-08-01T00:00:00.000Z"]]), NOW);
    assert.equal(plan.unknown.length, 1);
    assert.equal(plan.unknown[0]!.fingerprint256, A);
    assert.ok(plan.keep.some((r) => r.fingerprint256 === A), "an undatable row must survive");
    assert.equal(plan.drop.length, 1);
  });

  it("treats an unreadable expiry as undatable rather than as expired", () => {
    // A date this code cannot parse is not evidence that a certificate stopped working.
    const plan = planRevocationCompaction(snap(row(A)), new Map([[A, "whenever"]]), NOW);
    assert.deepEqual(plan.drop, []);
    assert.equal(plan.unknown.length, 1);
  });

  it("treats expiry at the exact instant as expired", () => {
    const plan = planRevocationCompaction(snap(row(A)), new Map([[A, NOW.toISOString()]]), NOW);
    assert.equal(plan.drop.length, 1);
  });

  it("partitions every row into exactly one of keep or drop", () => {
    // `unknown` is a subset of `keep`, not a third bucket — a caller that wrote `keep.concat(unknown)`
    // would duplicate rows, and `parseRevocationSnapshot` refuses duplicates, so the mistake would
    // surface as a compaction that cannot be written rather than one that loses a revocation.
    const plan = planRevocationCompaction(
      snap(row(A), row(B), row(C)),
      new Map([[A, "2026-08-01T00:00:00.000Z"], [B, "2027-01-01T00:00:00.000Z"]]),
      NOW,
    );
    assert.equal(plan.keep.length + plan.drop.length, 3);
    assert.ok(plan.unknown.every((u) => plan.keep.includes(u)));
  });
});
