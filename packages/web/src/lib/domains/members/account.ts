// `/api/me`, `/api/me/sessions` and `/api/me/identities`, read for the account page, and the SSO link.

import type { MessageKey } from "../../i18n.ts";
import { errorText, isRecord, type Refusal } from "./answer.ts";

export const ME_PATH = "/api/me";
export const ME_PASSWORD_PATH = "/api/me/password";
export const ME_SESSIONS_PATH = "/api/me/sessions";
export const ME_IDENTITIES_PATH = "/api/me/identities";
export const LINK_START_PATH = "/auth/link/start";

/** A linked SSO account as the server shows it: the issuer, and the subject's last four characters only. */
export interface IdentityRow {
  /** Opaque, from the server. */
  id: string;
  issuer: string;
  subject: string;
  linkedAt: string;
}

export function readIdentities(v: unknown): IdentityRow[] {
  if (!Array.isArray(v)) return [];
  return v.flatMap((i): IdentityRow[] => {
    if (!isRecord(i) || typeof i.id !== "string" || !/^[0-9a-f]{16}$/.test(i.id) || typeof i.issuer !== "string") return [];
    return [{
      id: i.id, issuer: i.issuer,
      subject: typeof i.subject === "string" ? i.subject : "",
      linkedAt: typeof i.linkedAt === "string" ? i.linkedAt : "",
    }];
  });
}

export interface MeView {
  username: string;
  principalName: string;
  email: string | null;
  roles: string[];
  mustChange: boolean;
  otpConfirmedAt: string | null;
  /** This session's CSRF token. `/api/authz` answers nothing while the password must change. */
  csrf: string | null;
  /** How this session signed in: `password` or `sso`. */
  via: string | null;
  /** Absent in an older answer, which only a password session could read: true. */
  hasPassword: boolean;
  identities: IdentityRow[];
}

const strOrNull = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);

export function readMe(body: unknown): MeView | null {
  if (!isRecord(body) || typeof body.username !== "string" || typeof body.principalName !== "string") return null;
  return {
    username: body.username,
    principalName: body.principalName,
    email: strOrNull(body.email),
    roles: Array.isArray(body.roles) ? body.roles.filter((r): r is string => typeof r === "string") : [],
    mustChange: body.mustChange === true,
    otpConfirmedAt: strOrNull(body.otpConfirmedAt),
    csrf: strOrNull(body.csrf),
    via: strOrNull(body.via),
    hasPassword: body.hasPassword !== false,
    identities: readIdentities(body.identities),
  };
}

/** Writers and admins confirm a link or an unlink with a one-time code as well as the password. */
export function reauthNeedsOtp(roles: readonly string[]): boolean {
  return roles.includes("writer") || roles.includes("admin");
}

export function reauthBody(password: string, otp: string | null): string {
  return JSON.stringify({ password, ...(otp ? { otp: otp.trim() } : {}) });
}

export function identityPath(id: string): string {
  return `${ME_IDENTITIES_PATH}/${encodeURIComponent(id)}`;
}

/** Statuses of a re-authenticated write (link start, unlink). `null` means it went through. */
export function readReauth(status: number, body: unknown, ok: number[] = [200]): Refusal | null {
  if (ok.includes(status)) return null;
  const key: MessageKey = status === 403 ? (/password session/.test(errorText(body)) ? "m.acSsoLinkNeedsPassword" : "m.mbCurrentWrong")
    : status === 401 ? "m.loginWrongCode"
    : status === 409 ? "m.acUnlinkNeedsPassword"
    : status === 429 ? "m.mbTooMany"
    : status >= 500 ? "m.mbUnavailable"
    : "m.mbFailed";
  return { key, detail: errorText(body), problems: [] };
}

/** Where `POST /auth/link/start` sends the browser: the identity provider, as an https URL only. */
export function readLinkStart(body: unknown): string | null {
  const to = isRecord(body) ? body.location : undefined;
  return typeof to === "string" && to.startsWith("https://") ? to : null;
}

/** What the callback's `?link=` says, as the page's sentence. Anything unknown is a plain failure. */
export function linkResult(param: string | null): { key: MessageKey; ok: boolean } | null {
  if (param === null) return null;
  if (param === "ok") return { key: "m.acLinked", ok: true };
  const key: MessageKey = param === "taken" ? "m.acLinkTaken" : param === "tombstone" ? "m.acLinkTombstone" : param === "ended" ? "m.acLinkEnded" : "m.acLinkFailed";
  return { key, ok: false };
}

export interface SessionRow {
  /** Opaque, from the server; not the session id. */
  id: string;
  createdAt: string;
  lastSeenAt: string;
  current: boolean;
}

export function readSessions(body: unknown): SessionRow[] {
  if (!isRecord(body) || !Array.isArray(body.sessions)) return [];
  return body.sessions.flatMap((s): SessionRow[] => {
    if (!isRecord(s) || typeof s.id !== "string" || !/^[0-9a-f]{16}$/.test(s.id)) return [];
    return [{
      id: s.id,
      createdAt: typeof s.createdAt === "string" ? s.createdAt : "",
      lastSeenAt: typeof s.lastSeenAt === "string" ? s.lastSeenAt : "",
      current: s.current === true,
    }];
  });
}

export function sessionPath(id: string): string {
  return `${ME_SESSIONS_PATH}/${encodeURIComponent(id)}`;
}

export function passwordChangeBody(current: string, next: string): string {
  return JSON.stringify({ current, next });
}
