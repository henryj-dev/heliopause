import { readFileSync, statSync } from "node:fs";
import type { IncomingMessage } from "node:http";
import {
  MAX_REVOCATION_SNAPSHOT_BYTES,
  parseRevocationSnapshot,
  type RevocationSnapshot,
} from "./revocation-snapshot.ts";

export type RevocationSourceFormat = "snapshot" | "enrollment";

export function peerFingerprint256(req: IncomingMessage): string | null {
  const socket = req.socket as unknown as { authorized?: boolean; getPeerCertificate?: () => { fingerprint256?: string } | null };
  if (!socket.authorized) return null; const value = socket.getPeerCertificate?.()?.fingerprint256;
  return value ? value.replaceAll(":", "").toLowerCase() : null;
}

function parseEnrollmentRevocations(value: unknown): RevocationSnapshot {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("enrollment revocation source must be an object");
  const document = value as Record<string, unknown>;
  // ## Two lists over one file, and the cost of them disagreeing
  //
  // `enrollment-store.ts` decides what an enrollment store may contain; this decides what this
  // reader will accept of it. They are separate on purpose — this one must not be widened by a field
  // the store gains — and **the day they disagree, every operator is locked out of the manager**:
  // an unrecognised field lands in the `catch` below, which fails closed, and a valid certificate is
  // reported as revoked. Measured, not imagined: adding `appTokens` to the store made 30 tests fail
  // with "client certificate has been revoked" before this list learned the name.
  //
  // So `appTokens` is optional rather than required. A store written before app tokens existed is a
  // correct store — schema 1 was deliberately not raised — and this reader has no opinion about the
  // field either way. The five below stay required: their absence is a truncated file, and a
  // truncated denylist is the thing that must never read as "nobody is revoked".
  const required = ["schemaVersion", "tokens", "requests", "audit", "revocations"];
  const optional = ["appTokens", "hostLifecycleTombstones", "hostDeregistrations"];
  const keys = Object.keys(document);
  if (required.some((key) => !keys.includes(key)) || keys.some((key) => !required.includes(key) && !optional.includes(key))) {
    throw new Error("enrollment revocation source contains unsupported or missing fields");
  }
  if (document.schemaVersion !== 1 || !Array.isArray(document.tokens)
    || !Array.isArray(document.requests) || !Array.isArray(document.audit)) {
    throw new Error("invalid enrollment revocation source schema");
  }
  return parseRevocationSnapshot({ schemaVersion: 1, revocations: document.revocations });
}

/**
 * Reloaded and strictly validated per request so an emergency revocation needs no restart.
 *
 * ## Deliberately not cached
 *
 * Caching it — keyed on mtime and inode, invalidated on change — was proposed and declined. The read
 * is synchronous and per request, which sounds like exactly the thing to cache, and two facts say
 * otherwise:
 *
 *   · **An unauthenticated caller never reaches it.** `peerFingerprint256` returns null unless
 *     `socket.authorized`, and the function returns before touching the disk. So the read is paid by
 *     peers holding a valid client certificate, not by anyone who can open a socket.
 *   · **The property being traded away is the one the file exists for.** "Revocation takes effect on
 *     the next request" would become "on the next request after the cache notices", and mtime has
 *     one-second granularity on some filesystems while a revocation is something an operator does
 *     because they are in a hurry.
 *
 * The cost is a small read of a bounded file. The benefit was microseconds. Written down here rather
 * than left as an absence, because "why is this not cached" is a question a reader will have.
 */
export function certificateIsRevoked(
  path: string | undefined,
  req: IncomingMessage,
  format: RevocationSourceFormat = "snapshot",
): boolean {
  if (!path) return false; const fingerprint = peerFingerprint256(req); if (!fingerprint) return false;
  try {
    if (format === "snapshot" && statSync(path).size > MAX_REVOCATION_SNAPSHOT_BYTES) {
      throw new Error("revocation snapshot is oversized");
    }
    const encoded = readFileSync(path);
    if (format === "snapshot" && encoded.length > MAX_REVOCATION_SNAPSHOT_BYTES) {
      throw new Error("revocation snapshot is oversized");
    }
    const raw: unknown = JSON.parse(encoded.toString("utf8"));
    const document = format === "snapshot" ? parseRevocationSnapshot(raw) : parseEnrollmentRevocations(raw);
    return document.revocations.some((row) => row.fingerprint256 === fingerprint);
  } catch {
    // A configured but unreadable, malformed, or wrong-format denylist must fail closed. Otherwise
    // truncating or structurally corrupting the file silently restores every credential it revoked.
    return true;
  }
}
