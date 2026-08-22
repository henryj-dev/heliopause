import { randomBytes } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { CertificateRevocation } from "./enrollment-store.ts";

const FINGERPRINT = /^[0-9a-f]{64}$/;
const writes = new Map<string, Promise<void>>();
export const MAX_REVOCATION_ROWS = 2_048;
export const MAX_REVOCATION_SNAPSHOT_BYTES = 256 * 1024;

export interface RevocationSnapshot {
  schemaVersion: 1;
  revocations: CertificateRevocation[];
}

/**
 * Encode the exact bytes installed on disk and sent across the local writer socket.
 *
 * Keeping this canonical matters for the byte limit: accepting compact JSON at the socket and then
 * expanding it with pretty-print whitespace on disk could create a file that the relay refuses to
 * read on its next request or restart. The trailing newline is part of the persisted representation
 * and therefore part of the bound.
 */
export function serializeRevocationSnapshot(value: unknown): Buffer {
  const snapshot = parseRevocationSnapshot(value);
  const encoded = Buffer.from(`${JSON.stringify(snapshot)}\n`);
  if (encoded.length > MAX_REVOCATION_SNAPSHOT_BYTES) {
    throw new Error(`revocation snapshot exceeds ${MAX_REVOCATION_SNAPSHOT_BYTES} bytes`);
  }
  return encoded;
}

/** Relay가 받아도 되는 enrollment 정보는 폐기 목록뿐이다. 토큰·CSR·감사는 거부한다. */
export function parseRevocationSnapshot(value: unknown): RevocationSnapshot {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("revocation snapshot must be an object");
  const doc = value as { schemaVersion?: unknown; revocations?: unknown; [key: string]: unknown };
  if (Object.keys(doc).some((key) => !["schemaVersion", "revocations"].includes(key))) throw new Error("revocation snapshot contains unsupported fields");
  if (doc.schemaVersion !== 1 || !Array.isArray(doc.revocations)) throw new Error("invalid revocation snapshot schema");
  if (doc.revocations.length > MAX_REVOCATION_ROWS) throw new Error(`revocation snapshot exceeds ${MAX_REVOCATION_ROWS} rows`);
  const seen = new Set<string>();
  const revocations = doc.revocations.map((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("invalid revocation row");
    const row = raw as Record<string, unknown>;
    if (Object.keys(row).some((key) => !["fingerprint256", "subject", "reason", "actor", "revokedAt"].includes(key))) {
      throw new Error("revocation row contains unsupported fields");
    }
    if (typeof row.fingerprint256 !== "string" || !FINGERPRINT.test(row.fingerprint256)) throw new Error("invalid certificate fingerprint");
    if (seen.has(row.fingerprint256)) throw new Error("duplicate certificate fingerprint");
    seen.add(row.fingerprint256);
    if (row.subject !== null && (typeof row.subject !== "string" || Buffer.byteLength(row.subject) > 1_024)) {
      throw new Error("invalid certificate subject");
    }
    const limits = { reason: 500, actor: 120, revokedAt: 64 } as const;
    for (const key of ["reason", "actor", "revokedAt"] as const) {
      if (typeof row[key] !== "string" || Buffer.byteLength(row[key]) === 0 || Buffer.byteLength(row[key]) > limits[key]) {
        throw new Error(`invalid revocation ${key}`);
      }
    }
    if (!Number.isFinite(Date.parse(row.revokedAt as string))) throw new Error("invalid revocation revokedAt");
    return {
      fingerprint256: row.fingerprint256,
      subject: row.subject as string | null,
      reason: row.reason as string,
      actor: row.actor as string,
      revokedAt: row.revokedAt as string,
    };
  });
  return { schemaVersion: 1, revocations };
}

/** One-time provisioning only. Runtime code must never turn a missing denylist into an empty one. */
export async function initializeRevocationSnapshot(
  path: string,
  value: unknown = { schemaVersion: 1, revocations: [] },
  options: { mode?: number } = {},
): Promise<RevocationSnapshot> {
  const snapshot = parseRevocationSnapshot(value);
  const encoded = serializeRevocationSnapshot(snapshot);
  const full = resolve(path);
  const mode = options.mode ?? 0o600;
  assertSnapshotMode(mode);
  await mkdir(dirname(full), { recursive: true, mode: 0o700 });
  await writeFile(full, encoded, { mode, flag: "wx" });
  await chmod(full, mode);
  return snapshot;
}

function assertMonotonic(previous: RevocationSnapshot, next: RevocationSnapshot): void {
  const current = new Map(next.revocations.map((row) => [row.fingerprint256, row]));
  for (const row of previous.revocations) {
    const replacement = current.get(row.fingerprint256);
    if (!replacement) throw new Error(`revocation rollback refused for fingerprint ${row.fingerprint256}`);
    if (JSON.stringify(replacement) !== JSON.stringify(row)) {
      throw new Error(`revocation rewrite refused for fingerprint ${row.fingerprint256}`);
    }
  }
}

function assertSnapshotMode(mode: number): void {
  if (!Number.isSafeInteger(mode) || mode < 0 || mode > 0o777 || (mode & 0o022) !== 0) {
    throw new Error("revocation snapshot mode must not be group/world writable");
  }
}

async function writeExisting(path: string, snapshot: RevocationSnapshot, mode: number): Promise<RevocationSnapshot> {
  const full = resolve(path);
  const encoded = serializeRevocationSnapshot(snapshot);
  const current = parseRevocationSnapshot(JSON.parse(await readFile(full, "utf8")));
  assertMonotonic(current, snapshot);
  const temp = `${full}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  try {
    await writeFile(temp, encoded, { mode, flag: "wx" });
    await chmod(temp, mode);
    const tempHandle = await open(temp, "r");
    try { await tempHandle.sync(); } finally { await tempHandle.close(); }
    await rename(temp, full);
    const directoryHandle = await open(dirname(full), "r");
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  } catch (error) {
    await unlink(temp).catch(() => {});
    throw error;
  }
  return snapshot;
}

/**
 * Atomically install a superset of the existing denylist.
 *
 * Revocation is permanent: an authorised publisher may add fingerprints, never omit or rewrite an
 * existing row. A missing file is not an empty set; it is an error that keeps the relay fail-closed
 * until an operator restores it or performs the explicit one-time initialization above.
 */
export function writeRevocationSnapshot(
  path: string,
  value: unknown,
  options: { mode?: number } = {},
): Promise<RevocationSnapshot> {
  const snapshot = parseRevocationSnapshot(value);
  const mode = options.mode ?? 0o600;
  assertSnapshotMode(mode);
  const full = resolve(path);
  const previous = writes.get(full) ?? Promise.resolve();
  const result = previous.catch(() => {}).then(() => writeExisting(full, snapshot, mode));
  const settled = result.then(() => undefined, () => undefined);
  writes.set(full, settled);
  return result.finally(() => {
    if (writes.get(full) === settled) writes.delete(full);
  });
}

// ── Compaction ───────────────────────────────────────────────────────────────
//
// Revocation is monotonic: `assertMonotonic` refuses any update that omits or rewrites a row, and
// that rule is what stops a compromised publisher from un-revoking a credential by pushing a shorter
// list. It is also why the list only ever grows, and `MAX_REVOCATION_ROWS` is a real ceiling — at
// 2,048 the relay stops accepting new revocations, which is the one failure a denylist cannot have.
//
// A fingerprint whose certificate has expired is no longer doing any work: the certificate is refused
// by every TLS peer on its own. Dropping those is the only safe way to make room, and it is
// deliberately **not** something the writer socket accepts — the writer's whole job is to refuse
// shrinking lists. Compaction is an operator action, taken with the writer stopped, and this is the
// half of it that can be reasoned about.

/** What a compaction would do. Nothing here writes; the caller decides. */
export interface RevocationCompaction {
  /** Rows that stay. Everything not provably expired. */
  keep: CertificateRevocation[];
  /** Rows whose certificate has expired, with the expiry that proves it. */
  drop: Array<{ row: CertificateRevocation; notAfter: string }>;
  /**
   * Rows this deployment cannot place — no certificate in the enrollment store carries the
   * fingerprint, so there is nothing to prove expiry with.
   *
   * **Kept, and reported.** Dropping a fingerprint we cannot date would un-revoke a credential that
   * may well still be valid, which is exactly what monotonicity exists to prevent. A revocation for a
   * certificate issued outside this enrollment store — a break-glass credential, one from before the
   * store existed — lands here and stays forever, which is the correct answer for a denylist.
   */
  unknown: CertificateRevocation[];
}

/**
 * Decide which revocations a compaction could drop. Pure — takes the clock.
 *
 * `expiry` maps a certificate fingerprint to its `notAfter`, as the enrollment store records it. A
 * fingerprint absent from the map is *unknown*, not expired; see `RevocationCompaction.unknown`.
 *
 * An unparseable `notAfter` is treated as unknown for the same reason: a date this code cannot read
 * is not evidence that a certificate has stopped working.
 */
export function planRevocationCompaction(
  snapshot: RevocationSnapshot,
  expiry: ReadonlyMap<string, string>,
  now: Date,
): RevocationCompaction {
  const keep: CertificateRevocation[] = [];
  const drop: Array<{ row: CertificateRevocation; notAfter: string }> = [];
  const unknown: CertificateRevocation[] = [];
  for (const row of snapshot.revocations) {
    const notAfter = expiry.get(row.fingerprint256);
    const at = notAfter === undefined ? Number.NaN : Date.parse(notAfter);
    if (!Number.isFinite(at)) {
      unknown.push(row);
      keep.push(row);
      continue;
    }
    if (at <= now.getTime()) drop.push({ row, notAfter: notAfter! });
    else keep.push(row);
  }
  return { keep, drop, unknown };
}
