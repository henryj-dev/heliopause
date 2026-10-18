// `/api/members`, read for the admin screen, and the bodies its writes send.

import type { MessageKey } from "../../i18n.ts";
import { isRecord } from "./answer.ts";

export const MEMBERS_PATH = "/api/members";
export const INVITES_PATH = "/api/members/invites";
export const ROLES = ["reader", "writer", "admin"] as const;
export type Role = (typeof ROLES)[number];

export const ROLE_KEY: Record<Role, MessageKey> = {
  reader: "m.roleReader",
  writer: "m.roleWriter",
  admin: "m.roleAdmin",
};

/** The store's four states. An unknown one is shown as sent. */
export const STATUS_KEY: Record<string, MessageKey> = {
  active: "m.mmActive",
  invited: "m.mmInvited",
  suspended: "m.mmSuspended",
  deleted: "m.mmDeleted",
};

export type MemberAction = "roles" | "suspend" | "unsuspend" | "delete" | "otp-user" | "cert-cns" | "password-reset";

/** What a member's panel asks the screen to send. */
export type PanelRequest =
  | { action: "roles"; roles: string[] }
  | { action: "suspend" | "unsuspend" | "delete" | "password-reset" }
  | { action: "otp-user"; otpUserId: string | null }
  | { action: "cert-cns"; change: { add: string } | { remove: string } };

export interface MemberRow {
  id: string;
  username: string;
  principalName: string;
  email: string | null;
  status: string;
  roles: string[];
  otpUserId: string | null;
  otpConfirmedAt: string | null;
  certCNs: string[];
  hasPassword: boolean;
  mustChange: boolean;
}

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
const strOrNull = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);

export function readMember(m: unknown): MemberRow | null {
  if (!isRecord(m) || typeof m.id !== "string" || typeof m.username !== "string") return null;
  return {
    id: m.id,
    username: m.username,
    principalName: typeof m.principalName === "string" ? m.principalName : m.username,
    email: strOrNull(m.email),
    status: typeof m.status === "string" ? m.status : "unknown",
    roles: strings(m.roles),
    otpUserId: strOrNull(m.otpUserId),
    otpConfirmedAt: strOrNull(m.otpConfirmedAt),
    certCNs: strings(m.certCNs),
    hasPassword: m.hasPassword === true,
    mustChange: m.mustChange === true,
  };
}

/** Deleted members are kept by the store for the audit trail; the list shows them last. */
export function readMembers(body: unknown): MemberRow[] {
  if (!isRecord(body) || !Array.isArray(body.members)) return [];
  const rows = body.members.map(readMember).filter((m): m is MemberRow => m !== null);
  return [...rows.filter((m) => m.status !== "deleted"), ...rows.filter((m) => m.status === "deleted")];
}

export function memberPath(id: string, action: MemberAction): string {
  return `${MEMBERS_PATH}/${encodeURIComponent(id)}/${action}`;
}

/** Which actions a row offers. A deleted member offers none; suspend and unsuspend follow the status. */
export function actionsFor(m: Pick<MemberRow, "status">): MemberAction[] {
  if (m.status === "deleted") return [];
  const toggle: MemberAction = m.status === "suspended" ? "unsuspend" : "suspend";
  return ["roles", toggle, "otp-user", "cert-cns", "password-reset", "delete"];
}

/** Roles in the order the store lists them, whatever order the boxes were ticked in. */
export function orderedRoles(picked: readonly string[]): Role[] {
  return ROLES.filter((r) => picked.includes(r));
}

export function inviteBody(email: string, roles: readonly string[], otp: string): string {
  return JSON.stringify({ email: email.trim(), roles: orderedRoles(roles), otp });
}

export function rolesBody(roles: readonly string[], otp: string): string {
  return JSON.stringify({ roles: orderedRoles(roles), otp });
}

/** `null` clears the code user. An empty or blank field is a clear, not a user named "". */
export function otpUserBody(otpUserId: string | null, otp: string): string {
  const id = otpUserId?.trim() ?? "";
  return JSON.stringify({ otpUserId: id === "" ? null : id, otp });
}

export function certCnBody(change: { add: string } | { remove: string }, otp: string): string {
  return JSON.stringify("add" in change ? { add: change.add.trim(), otp } : { remove: change.remove, otp });
}

export function otpOnlyBody(otp: string): string {
  return JSON.stringify({ otp });
}

/** The link a write answered with, shown once. Only an https URL counts. */
export function readLink(body: unknown, field: "inviteUrl" | "resetUrl"): string | null {
  if (!isRecord(body)) return null;
  const v = body[field];
  return typeof v === "string" && v.startsWith("https://") ? v : null;
}

/** One panel request as the screen sends it: where, with what body, and how the code dialog names it. */
export interface WritePlan {
  path: string;
  body: (otp: string) => string;
  what: { key: MessageKey; params: Record<string, string> };
  /** The field of the answer that carries a one-time link, shown once. */
  link: "resetUrl" | null;
}

export function planRequest(member: Pick<MemberRow, "id" | "username">, request: PanelRequest): WritePlan {
  const name = member.username;
  const plain = (key: MessageKey) => ({ key, params: { name } });
  switch (request.action) {
    case "roles":
      return { path: memberPath(member.id, "roles"), body: (otp) => rolesBody(request.roles, otp), what: plain("m.mmWhatRoles"), link: null };
    case "otp-user":
      return {
        path: memberPath(member.id, "otp-user"),
        body: (otp) => otpUserBody(request.otpUserId, otp),
        what: plain(request.otpUserId?.trim() ? "m.mmWhatOtpSet" : "m.mmWhatOtpClear"),
        link: null,
      };
    case "cert-cns": {
      const cn = "add" in request.change ? request.change.add.trim() : request.change.remove;
      return {
        path: memberPath(member.id, "cert-cns"),
        body: (otp) => certCnBody(request.change, otp),
        what: { key: "add" in request.change ? "m.mmWhatCertAdd" : "m.mmWhatCertRemove", params: { name, cn } },
        link: null,
      };
    }
    case "suspend":
      return { path: memberPath(member.id, "suspend"), body: otpOnlyBody, what: plain("m.mmWhatSuspend"), link: null };
    case "unsuspend":
      return { path: memberPath(member.id, "unsuspend"), body: otpOnlyBody, what: plain("m.mmWhatUnsuspend"), link: null };
    case "delete":
      return { path: memberPath(member.id, "delete"), body: otpOnlyBody, what: plain("m.mmWhatDelete"), link: null };
    case "password-reset":
      return { path: memberPath(member.id, "password-reset"), body: otpOnlyBody, what: plain("m.mmWhatReset"), link: "resetUrl" };
  }
}
