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
  const allowed = ["schemaVersion", "tokens", "requests", "audit", "revocations"];
  if (Object.keys(document).length !== allowed.length || Object.keys(document).some((key) => !allowed.includes(key))) {
    throw new Error("enrollment revocation source contains unsupported or missing fields");
  }
  if (document.schemaVersion !== 1 || !Array.isArray(document.tokens)
    || !Array.isArray(document.requests) || !Array.isArray(document.audit)) {
    throw new Error("invalid enrollment revocation source schema");
  }
  return parseRevocationSnapshot({ schemaVersion: 1, revocations: document.revocations });
}

/** Reloaded and strictly validated per request so an emergency revocation needs no restart. */
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
