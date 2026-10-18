// `/api/me` and `/api/me/sessions`, read for the account page.

import { isRecord } from "./answer.ts";

export const ME_PATH = "/api/me";
export const ME_PASSWORD_PATH = "/api/me/password";
export const ME_SESSIONS_PATH = "/api/me/sessions";

export interface MeView {
  username: string;
  principalName: string;
  email: string | null;
  roles: string[];
  mustChange: boolean;
  otpConfirmedAt: string | null;
  /** This session's CSRF token. `/api/authz` answers nothing while the password must change. */
  csrf: string | null;
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
  };
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
