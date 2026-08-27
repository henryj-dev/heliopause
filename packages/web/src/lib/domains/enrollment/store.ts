// GET /api/enrollment/*, as this package is allowed to see it.
//
// Duplicated rather than imported from `heliopause`: the web package must not
// pull the library into a Vite bundle. Token hashes never appear here — the
// manager strips them before the listing leaves the process.

export type CsrStatus = "pending" | "conflict" | "rejected" | "signed";

export interface TokenRow {
  id: string;
  hostname: string;
  label: string | null;
  createdAt: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

export interface AppTokenRow {
  id: string;
  label: string;
  scopes: string[];
  hostnamePattern: string;
  createdBy: string | null;
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

export interface RequestRow {
  id: string;
  hostname: string;
  status: CsrStatus;
  csrPem: string;
  csrSha256: string;
  publicKeySha256: string;
  nodeTokenId: string;
  sourceIp: string | null;
  createdAt: string;
  decisionReason: string | null;
  certificatePem: string | null;
  retrievedAt: string | null;
}

export interface RevocationRow {
  fingerprint256: string;
  subject: string | null;
  reason: string;
  revokedAt: string;
}

export interface AuditRow {
  at: string;
  actor: string;
  action: string;
  target: string;
  sourceIp: string | null;
  detail: Record<string, string | number | boolean | null>;
}

export interface EnrollmentView {
  tokens: TokenRow[];
  appTokens: AppTokenRow[];
  requests: RequestRow[];
  revocations: RevocationRow[];
  events: AuditRow[] | null;
}

export type EnrollmentRead =
  | { ok: true; view: EnrollmentView }
  | { ok: false; reason: string };

const CSR_STATUSES = new Set<CsrStatus>(["pending", "conflict", "rejected", "signed"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function readToken(value: unknown): TokenRow | null {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.hostname !== "string") return null;
  if (typeof value.createdAt !== "string") return null;
  if ("tokenHash" in value) return null;
  return {
    id: value.id,
    hostname: value.hostname,
    label: typeof value.label === "string" ? value.label : null,
    createdAt: value.createdAt,
    expiresAt: typeof value.expiresAt === "string" ? value.expiresAt : null,
    lastUsedAt: typeof value.lastUsedAt === "string" ? value.lastUsedAt : null,
    revokedAt: typeof value.revokedAt === "string" ? value.revokedAt : null,
  };
}

function readAppToken(value: unknown): AppTokenRow | null {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.label !== "string") return null;
  if (typeof value.hostnamePattern !== "string" || typeof value.createdAt !== "string") return null;
  if (typeof value.expiresAt !== "string") return null;
  if (!Array.isArray(value.scopes) || !value.scopes.every((s) => typeof s === "string")) return null;
  if ("tokenHash" in value) return null;
  return {
    id: value.id,
    label: value.label,
    scopes: value.scopes as string[],
    hostnamePattern: value.hostnamePattern,
    createdBy: typeof value.createdBy === "string" ? value.createdBy : null,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
    lastUsedAt: typeof value.lastUsedAt === "string" ? value.lastUsedAt : null,
    revokedAt: typeof value.revokedAt === "string" ? value.revokedAt : null,
  };
}

function readRequest(value: unknown): RequestRow | null {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.hostname !== "string") return null;
  if (typeof value.status !== "string" || !CSR_STATUSES.has(value.status as CsrStatus)) return null;
  if (typeof value.csrPem !== "string" || typeof value.csrSha256 !== "string") return null;
  if (typeof value.publicKeySha256 !== "string" || typeof value.nodeTokenId !== "string") return null;
  if (typeof value.createdAt !== "string") return null;
  return {
    id: value.id,
    hostname: value.hostname,
    status: value.status as CsrStatus,
    csrPem: value.csrPem,
    csrSha256: value.csrSha256,
    publicKeySha256: value.publicKeySha256,
    nodeTokenId: value.nodeTokenId,
    sourceIp: typeof value.sourceIp === "string" ? value.sourceIp : null,
    createdAt: value.createdAt,
    decisionReason: typeof value.decisionReason === "string" ? value.decisionReason : null,
    certificatePem: typeof value.certificatePem === "string" ? value.certificatePem : null,
    retrievedAt: typeof value.retrievedAt === "string" ? value.retrievedAt : null,
  };
}

function readRevocation(value: unknown): RevocationRow | null {
  if (!isRecord(value) || typeof value.fingerprint256 !== "string") return null;
  if (typeof value.reason !== "string" || typeof value.revokedAt !== "string") return null;
  return {
    fingerprint256: value.fingerprint256,
    subject: typeof value.subject === "string" ? value.subject : null,
    reason: value.reason,
    revokedAt: value.revokedAt,
  };
}

function readEvent(value: unknown): AuditRow | null {
  if (!isRecord(value) || typeof value.at !== "string" || typeof value.actor !== "string") return null;
  if (typeof value.action !== "string" || typeof value.target !== "string") return null;
  const detail: AuditRow["detail"] = {};
  if (isRecord(value.detail)) {
    for (const [key, item] of Object.entries(value.detail)) {
      if (item === null || typeof item === "string" || typeof item === "number" || typeof item === "boolean") {
        detail[key] = item;
      }
    }
  }
  return {
    at: value.at,
    actor: value.actor,
    action: value.action,
    target: value.target,
    sourceIp: typeof value.sourceIp === "string" ? value.sourceIp : null,
    detail,
  };
}

function readList<T>(value: unknown, read: (row: unknown) => T | null, label: string): { ok: true; rows: T[] } | { ok: false; reason: string } {
  if (!Array.isArray(value)) return { ok: false, reason: `${label} is missing` };
  const rows: T[] = [];
  for (const row of value) {
    const parsed = read(row);
    if (!parsed) return { ok: false, reason: `a ${label} row is malformed` };
    rows.push(parsed);
  }
  return { ok: true, rows };
}

export function readEnrollmentView(parts: {
  tokens: unknown;
  appTokens: unknown;
  requests: unknown;
  revocations: unknown;
  events: unknown;
}): EnrollmentRead {
  const tokens = readList(parts.tokens, readToken, "tokens");
  if (!tokens.ok) return tokens;
  const appTokens = readList(parts.appTokens, readAppToken, "app tokens");
  if (!appTokens.ok) return appTokens;
  const requests = readList(parts.requests, readRequest, "requests");
  if (!requests.ok) return requests;
  const revocations = readList(parts.revocations, readRevocation, "revocations");
  if (!revocations.ok) return revocations;
  let events: AuditRow[] | null = null;
  if (parts.events !== null) {
    const parsed = readList(parts.events, readEvent, "events");
    if (!parsed.ok) return parsed;
    events = parsed.rows;
  }
  return {
    ok: true,
    view: { tokens: tokens.rows, appTokens: appTokens.rows, requests: requests.rows, revocations: revocations.rows, events },
  };
}

export function canIssueToken(canWrite: boolean, stale = false): boolean {
  return canWrite && !stale;
}

export function canRevokeToken(token: TokenRow, canWrite: boolean): boolean {
  return canWrite && token.revokedAt === null;
}

export function canDecideCsr(request: RequestRow, canWrite: boolean): boolean {
  return canWrite && (request.status === "pending" || request.status === "conflict");
}

export function canRevokeCert(request: RequestRow, canWrite: boolean): boolean {
  return canWrite && request.status === "signed" && request.certificatePem !== null;
}

export function activeTokenCount(tokens: readonly TokenRow[]): number {
  return tokens.filter((token) => token.revokedAt === null).length;
}

export function canIssueAppToken(canWrite: boolean, stale = false): boolean {
  return canWrite && !stale;
}

export function canRevokeAppToken(row: AppTokenRow, canWrite: boolean): boolean {
  return canWrite && row.revokedAt === null;
}

export function activeAppTokenCount(rows: readonly AppTokenRow[]): number {
  return rows.filter((row) => row.revokedAt === null).length;
}
