import { t, type Lang } from "../../i18n.ts";
import type { AppTokenRow, EnrollmentView, RequestRow, TokenRow } from "./store.ts";

export function isTokenActive(token: TokenRow, nowMs: number): boolean {
  if (token.revokedAt) return false;
  if (token.expiresAt && Number.isFinite(Date.parse(token.expiresAt)) && Date.parse(token.expiresAt) <= nowMs) {
    return false;
  }
  return true;
}

export interface EnrollmentPipeline {
  tokens: number;
  unused: number;
  pending: number;
  conflict: number;
  signedWait: number;
  revocations: number;
}

/**
 * The five counts 시안 C1 pins above the lists. Unused tokens are still
 * active — lastUsedAt null is not revoked.
 */
export function enrollmentPipeline(view: EnrollmentView, nowMs: number): EnrollmentPipeline {
  const active = view.tokens.filter((token) => isTokenActive(token, nowMs));
  return {
    tokens: active.length,
    unused: active.filter((token) => token.lastUsedAt === null).length,
    pending: view.requests.filter((row) => row.status === "pending").length,
    conflict: view.requests.filter((row) => row.status === "conflict").length,
    signedWait: view.requests.filter((row) => row.status === "signed" && !row.retrievedAt).length,
    revocations: view.revocations.length,
  };
}

export type PipelineStep = "tokens" | "pending" | "signed";

/**
 * Where the operator's turn is. Pending beats signed-not-retrieved; unused
 * tokens are a wait on the host, not on us. Conflict is off this line.
 */
export function enrollmentFocus(pipe: EnrollmentPipeline): PipelineStep | null {
  if (pipe.pending > 0) return "pending";
  if (pipe.signedWait > 0) return "signed";
  if (pipe.unused > 0) return "tokens";
  return null;
}

export type TokenState = "unused" | "used" | "expired" | "revoked";

export function tokenState(token: TokenRow, nowMs: number): TokenState {
  if (token.revokedAt) return "revoked";
  if (!isTokenActive(token, nowMs)) return "expired";
  if (token.lastUsedAt === null) return "unused";
  return "used";
}

export function tokenTone(state: TokenState): "ok" | "warn" | "bad" | "info" | "mute" {
  if (state === "unused") return "info";
  if (state === "used") return "ok";
  return "mute";
}

export const TOKEN_STATE_KEY = {
  unused: "m.unused",
  used: "m.used",
  expired: "m.expired",
  revoked: "m.revoked",
} as const;

export const APP_TOKEN_EXPIRING_DAYS = 14;

export function appTokenActive(row: AppTokenRow, nowMs: number): boolean {
  if (row.revokedAt) return false;
  if (Number.isFinite(Date.parse(row.expiresAt)) && Date.parse(row.expiresAt) <= nowMs) return false;
  return true;
}

export function daysUntil(iso: string, nowMs: number): number | null {
  const parsed = Date.parse(iso);
  if (!Number.isFinite(parsed)) return null;
  return Math.floor((parsed - nowMs) / 86_400_000);
}

export type AppTokenState = "unused" | "used" | "expiring" | "expired" | "revoked";

export function appTokenState(row: AppTokenRow, nowMs: number): AppTokenState {
  if (row.revokedAt) return "revoked";
  if (!appTokenActive(row, nowMs)) return "expired";
  const left = daysUntil(row.expiresAt, nowMs);
  if (left !== null && left < APP_TOKEN_EXPIRING_DAYS) return "expiring";
  if (row.lastUsedAt === null) return "unused";
  return "used";
}

export function appTokenTone(state: AppTokenState): "ok" | "warn" | "bad" | "info" | "mute" {
  if (state === "expiring") return "warn";
  if (state === "unused") return "info";
  if (state === "used") return "ok";
  return "mute";
}

export const APP_TOKEN_STATE_KEY = {
  unused: "m.unused",
  used: "m.used",
  expiring: "m.appTokenExpiring",
  expired: "m.expired",
  revoked: "m.revoked",
} as const;

const SCOPE_KEY = {
  "enrollment:token-create": "m.scopeTokenCreate",
  "enrollment:requests-read": "m.scopeRequestsRead",
} as const;

export function scopeLabel(scope: string, lang: Lang = "en"): string {
  const key = SCOPE_KEY[scope as keyof typeof SCOPE_KEY];
  return key ? t(lang, key) : scope;
}

export const REQUEST_STATUS_KEY = {
  pending: "m.pending",
  conflict: "m.conflict",
  rejected: "m.rejected",
  signed: "m.signed",
} as const;

export const AUDIT_ACTION_KEY = {
  "node-token.create": "m.auditTokenCreate",
  "node-token.revoke": "m.auditTokenRevoke",
  "node-csr.submit": "m.auditCsrSubmit",
  "node-csr.reject": "m.auditCsrReject",
  "node-cert.upload": "m.auditCertUpload",
  "node-cert.fetch": "m.auditCertFetch",
  "certificate.revoke": "m.auditCertRevoke",
  "app-token.create": "m.auditAppTokenCreate",
  "app-token.revoke": "m.auditAppTokenRevoke",
} as const;

export function auditActionLabel(action: string, lang: Lang = "en"): string {
  const key = AUDIT_ACTION_KEY[action as keyof typeof AUDIT_ACTION_KEY];
  return key ? t(lang, key) : action;
}

export const AUDIT_DETAIL_KEY = {
  hostname: "c.hostname",
  status: "c.status",
  csrSha256: "m.csrSha",
  publicKeySha256: "m.pubSha",
  reason: "m.reason",
  caName: "m.caName",
  certificateSha256: "m.certSha",
  subject: "m.certSubject",
  hostnamePattern: "m.hostnamePattern",
  scopes: "m.scopes",
  appTokenId: "m.appTokenId",
  label: "c.label",
} as const;

export function auditDetailLine(
  detail: Record<string, string | number | boolean | null>,
  lang: Lang = "en",
): string {
  return Object.keys(detail).map((key) => {
    const labelled = key in AUDIT_DETAIL_KEY
      ? t(lang, AUDIT_DETAIL_KEY[key as keyof typeof AUDIT_DETAIL_KEY])
      : key;
    const raw = detail[key];
    const value = key === "status" && typeof raw === "string" && raw in REQUEST_STATUS_KEY
      ? t(lang, REQUEST_STATUS_KEY[raw as keyof typeof REQUEST_STATUS_KEY])
      : raw;
    return `${labelled}=${value}`;
  }).join(" · ");
}

export function requestTone(status: RequestRow["status"]): "ok" | "warn" | "bad" | "info" | "mute" {
  if (status === "pending") return "warn";
  if (status === "conflict") return "bad";
  if (status === "signed") return "info";
  return "mute";
}

export function requestCardClass(request: RequestRow): string {
  if (request.status === "pending") return "awaiting";
  if (request.status === "conflict") return "conflict";
  if (request.status === "signed" && !request.retrievedAt) return "approved";
  return "";
}

export function shortDigest(hex: string): string {
  if (hex.length <= 12) return hex;
  return `${hex.slice(0, 4)}…${hex.slice(-4)}`;
}

export const CSR_FILTERS = ["pending", "conflict", "rejected", "signed"] as const;
export type CsrFilter = (typeof CSR_FILTERS)[number];

export function readCsrFilter(asked: string): CsrFilter | null {
  return (CSR_FILTERS as readonly string[]).includes(asked) ? asked as CsrFilter : null;
}

/** Client-side. The listing is always the full store so the pipeline counts stay true. */
export function filteredRequests(requests: readonly RequestRow[], filter: CsrFilter | null): RequestRow[] {
  if (!filter) return [...requests];
  return requests.filter((row) => row.status === filter);
}

export function enrollmentPath(filter: CsrFilter | null): string {
  return filter ? `/enrollment/${filter}` : "/enrollment";
}
