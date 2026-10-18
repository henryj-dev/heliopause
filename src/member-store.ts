/**
 * File-backed store for human member accounts (`members.json`).
 *
 * Durability comes from `json-store.ts`. `parse` refuses unknown fields and runs the record and
 * cross-record checks (`parseMember` … `checkCrossRecord`) on load and again in `saveMemberDocument`,
 * so a mutation that breaks one of those checks is refused rather than written.
 *
 * Mutation functions change the document in place and are meant to run inside
 * `withMemberTransaction`. Password hashing is async and runs before the transaction; the store
 * only receives the encoded hash.
 */
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { atomicWriteFile, createExclusiveFile, withFileLock } from "./json-store.ts";
import { parseEncodedHash } from "./password.ts";

export const MEMBER_SCHEMA = 1 as const;
export const MEMBER_TOKEN_PREFIX = "hpmem_";
export const MEMBER_ROLES = ["reader", "writer", "admin"] as const;
export const MEMBER_STATUSES = ["invited", "active", "suspended", "deleted"] as const;
export const MEMBER_TOKEN_KINDS = ["invite", "email-verify", "password-reset"] as const;
export const DEFAULT_TOKEN_TTL_SEC: Record<MemberTokenKind, number> = {
  "invite": 72 * 60 * 60,
  "email-verify": 24 * 60 * 60,
  "password-reset": 30 * 60,
};
const MAX_TOKEN_TTL_SEC = 7 * 24 * 60 * 60;
const MIN_TOKEN_TTL_SEC = 60;
const MEMBER_LOCK_WAIT_MS = 10_000;
const NAME = /^[a-z0-9][a-z0-9._-]{1,63}$/;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,189}$/;
const CERT_CN = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/;
const OTP_USER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const TOKEN_RE = new RegExp(`^${MEMBER_TOKEN_PREFIX}[0-9a-f]{64}$`);
// C0, DEL, C1 and the bidi embedding/override/isolate controls.
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/;
const printable = (value: string): boolean => value.length > 0 && !CONTROL.test(value);

export type MemberRole = typeof MEMBER_ROLES[number];
export type MemberStatus = typeof MEMBER_STATUSES[number];
export type MemberTokenKind = typeof MEMBER_TOKEN_KINDS[number];

export interface Member {
  id: string; username: string; principalName: string; email: string | null; emailVerifiedAt: string | null;
  status: MemberStatus; roles: MemberRole[]; soloApprove: boolean; otpUserId: string | null; certCNs: string[];
  createdAt: string; createdBy: string; updatedAt: string;
}
export interface PasswordCredential { memberId: string; kind: "password"; hash: string; changedAt: string; mustChange: boolean; }
export interface MemberIdentity { issuer: string; subject: string; memberId: string; linkedAt: string; linkedBy: string; }
export interface MemberToken {
  id: string; kind: MemberTokenKind; digest: string; memberId: string | null;
  roles?: MemberRole[]; email?: string;
  expiresAt: string; usedAt: string | null; createdAt: string; createdBy: string;
}
export interface MemberAuditEvent { at: string; actor: string; action: string; target: string; sourceIp: string | null; }
export interface MemberDocument {
  schemaVersion: typeof MEMBER_SCHEMA;
  members: Member[]; credentials: PasswordCredential[]; identities: MemberIdentity[];
  tokens: MemberToken[]; audit: MemberAuditEvent[];
}
/** Who is making a change. CLI callers pass `actor: "cli"`. */
export interface MemberContext { actor: string; sourceIp?: string | null; now?: Date; }

export class MemberError extends Error {
  readonly statusCode: number;
  constructor(message: string, statusCode = 400) { super(message); this.statusCode = statusCode; }
}
const memberFailure = (message: string, statusCode?: number): Error => new MemberError(message, statusCode);

const nowIso = (now = new Date()): string => now.toISOString();
const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");

/** NFKC, lowercase, then `^[a-z0-9][a-z0-9._-]{1,63}$`. Used for both username and principalName. */
export function normalizeMemberName(value: unknown, field = "username"): string {
  if (typeof value !== "string") throw new MemberError(`${field} must be a string`);
  const normalized = value.normalize("NFKC").toLowerCase();
  if (!NAME.test(normalized)) throw new MemberError(`${field} must match ${NAME.source} after NFKC and lowercasing`);
  return normalized;
}
export function normalizeEmail(value: unknown): string {
  if (typeof value !== "string") throw new MemberError("email must be a string");
  const normalized = value.normalize("NFKC").trim().toLowerCase();
  if (normalized.length > 254 || !EMAIL.test(normalized) || CONTROL.test(normalized)) throw new MemberError("email is invalid");
  return normalized;
}
function certCN(value: unknown): string {
  if (typeof value !== "string" || !CERT_CN.test(value)) throw new MemberError("certificate CN is invalid");
  return value;
}
function otpUserId(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" || !OTP_USER_ID.test(value)) throw new MemberError("otpUserId is invalid");
  return value;
}
function roleList(value: unknown): MemberRole[] {
  if (!Array.isArray(value) || value.some((role) => !MEMBER_ROLES.includes(role))) {
    throw new MemberError(`roles must be a list drawn from ${MEMBER_ROLES.join(", ")}`);
  }
  if (new Set(value).size !== value.length) throw new MemberError("roles must not repeat");
  return MEMBER_ROLES.filter((role) => value.includes(role));
}
function actorName(value: unknown): string {
  if (typeof value !== "string" || value.length > 120 || !printable(value)) {
    throw new MemberError("actor must be 1-120 printable characters");
  }
  return value;
}
/**
 * The issuer must already be in the URL parser's exact form (a bare origin may omit the trailing
 * slash). The parser strips surrounding whitespace, tabs and newlines and percent-encodes control
 * and bidi characters, so an issuer containing any of them differs from its `href` and is refused.
 * @see member-store.test.ts "refuses an issuer the URL parser would rewrite, or with control or bidi characters"
 */
function issuerUrl(value: unknown): string {
  if (typeof value !== "string" || value.length > 512) throw new MemberError("issuer is invalid");
  let url: URL;
  try { url = new URL(value); } catch { throw new MemberError("issuer is invalid"); }
  if (url.href !== value && !(url.pathname === "/" && url.href === `${value}/`)) throw new MemberError("issuer is not in canonical URL form");
  if (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) {
    throw new MemberError("issuer must be an https URL");
  }
  return value;
}
function subjectId(value: unknown): string {
  if (typeof value !== "string" || value.length > 255 || !printable(value)) {
    throw new MemberError("subject is invalid");
  }
  return value;
}

// ── parse ─────────────────────────────────────────────────────────────────────────────────────

function exactObject(value: unknown, required: readonly string[], optional: readonly string[], what: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))
    || required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) {
    throw new MemberError(`${what} has an invalid shape`);
  }
}
function isoTime(value: unknown, what: string): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) {
    throw new MemberError(`${what} is not an ISO timestamp`);
  }
  return value;
}
function isoOrNull(value: unknown, what: string): string | null { return value === null ? null : isoTime(value, what); }
function bool(value: unknown, what: string): boolean {
  if (typeof value !== "boolean") throw new MemberError(`${what} must be a boolean`);
  return value;
}
function unique(values: readonly string[], what: string): void {
  if (new Set(values).size !== values.length) throw new MemberError(`${what} is not unique`, 409);
}

const MEMBER_FIELDS = [
  "id", "username", "principalName", "email", "emailVerifiedAt", "status", "roles", "soloApprove",
  "otpUserId", "certCNs", "createdAt", "createdBy", "updatedAt",
] as const;

function parseMember(raw: unknown): Member {
  exactObject(raw, MEMBER_FIELDS, [], "member");
  if (typeof raw.id !== "string" || !UUID.test(raw.id)) throw new MemberError("member id is invalid");
  const username = normalizeMemberName(raw.username);
  const principalName = normalizeMemberName(raw.principalName, "principalName");
  if (username !== raw.username || principalName !== raw.principalName) throw new MemberError("member names are not normalized");
  const email = raw.email === null ? null : normalizeEmail(raw.email);
  if (email !== raw.email) throw new MemberError("member email is not normalized");
  const status = raw.status as MemberStatus;
  if (!MEMBER_STATUSES.includes(status)) throw new MemberError("member status is invalid");
  const roles = roleList(raw.roles);
  if (!Array.isArray(raw.certCNs)) throw new MemberError("certCNs must be a list");
  const member: Member = {
    id: raw.id, username, principalName, email,
    emailVerifiedAt: isoOrNull(raw.emailVerifiedAt, "emailVerifiedAt"),
    status, roles, soloApprove: bool(raw.soloApprove, "soloApprove"), otpUserId: otpUserId(raw.otpUserId),
    certCNs: raw.certCNs.map(certCN),
    createdAt: isoTime(raw.createdAt, "createdAt"), createdBy: actorName(raw.createdBy), updatedAt: isoTime(raw.updatedAt, "updatedAt"),
  };
  if (member.email === null && member.emailVerifiedAt !== null) throw new MemberError("emailVerifiedAt without an email");
  if (status === "active" && roles.length === 0) throw new MemberError(`active member ${username} has no roles`);
  if (status === "deleted" && (email !== null || member.certCNs.length > 0 || roles.length > 0 || member.otpUserId !== null || member.soloApprove)) {
    throw new MemberError(`deleted member ${username} still carries personal data or authority`);
  }
  return member;
}

function parseCredential(raw: unknown): PasswordCredential {
  exactObject(raw, ["memberId", "kind", "hash", "changedAt", "mustChange"], [], "credential");
  if (typeof raw.memberId !== "string") throw new MemberError("credential memberId is invalid");
  if (raw.kind !== "password") throw new MemberError("credential kind is invalid");
  if (typeof raw.hash !== "string" || !parseEncodedHash(raw.hash)) throw new MemberError("credential hash is malformed");
  return {
    memberId: raw.memberId, kind: "password", hash: raw.hash,
    changedAt: isoTime(raw.changedAt, "changedAt"), mustChange: bool(raw.mustChange, "mustChange"),
  };
}

function parseIdentity(raw: unknown): MemberIdentity {
  exactObject(raw, ["issuer", "subject", "memberId", "linkedAt", "linkedBy"], [], "identity");
  if (typeof raw.memberId !== "string") throw new MemberError("identity memberId is invalid");
  return {
    issuer: issuerUrl(raw.issuer), subject: subjectId(raw.subject), memberId: raw.memberId,
    linkedAt: isoTime(raw.linkedAt, "linkedAt"), linkedBy: actorName(raw.linkedBy),
  };
}

function parseToken(raw: unknown): MemberToken {
  exactObject(raw, ["id", "kind", "digest", "memberId", "expiresAt", "usedAt", "createdAt", "createdBy"], ["roles", "email"], "token");
  const kind = raw.kind as MemberTokenKind;
  if (!MEMBER_TOKEN_KINDS.includes(kind)) throw new MemberError("token kind is invalid");
  if (typeof raw.id !== "string" || !UUID.test(raw.id)) throw new MemberError("token id is invalid");
  if (typeof raw.digest !== "string" || !SHA256.test(raw.digest)) throw new MemberError("token digest is invalid");
  if (raw.memberId !== null && typeof raw.memberId !== "string") throw new MemberError("token memberId is invalid");
  const token: MemberToken = {
    id: raw.id, kind, digest: raw.digest, memberId: raw.memberId,
    expiresAt: isoTime(raw.expiresAt, "expiresAt"), usedAt: isoOrNull(raw.usedAt, "usedAt"),
    createdAt: isoTime(raw.createdAt, "createdAt"), createdBy: actorName(raw.createdBy),
  };
  if (raw.roles !== undefined) token.roles = roleList(raw.roles);
  if (raw.email !== undefined) {
    token.email = normalizeEmail(raw.email);
    if (token.email !== raw.email) throw new MemberError("token email is not normalized");
  }
  checkTokenShape(token);
  return token;
}

function checkTokenShape(token: MemberToken): void {
  if (token.kind === "invite") {
    if (!token.roles || token.roles.length === 0) throw new MemberError("an invite names at least one role");
  } else {
    if (token.memberId === null) throw new MemberError(`a ${token.kind} token names a member`);
    if (token.roles !== undefined) throw new MemberError(`a ${token.kind} token carries no roles`);
    if (token.kind === "email-verify" && token.email === undefined) throw new MemberError("an email-verify token names the address");
    if (token.kind === "password-reset" && token.email !== undefined) throw new MemberError("a password-reset token carries no email");
  }
}

function parseAudit(raw: unknown): MemberAuditEvent {
  exactObject(raw, ["at", "actor", "action", "target", "sourceIp"], [], "audit event");
  if (typeof raw.action !== "string" || typeof raw.target !== "string") throw new MemberError("audit event is invalid");
  if (raw.sourceIp !== null && typeof raw.sourceIp !== "string") throw new MemberError("audit sourceIp is invalid");
  return { at: isoTime(raw.at, "audit at"), actor: actorName(raw.actor), action: raw.action, target: raw.target, sourceIp: raw.sourceIp };
}

function parse(raw: unknown, source: string): MemberDocument {
  try {
    exactObject(raw, ["schemaVersion", "members", "credentials", "identities", "tokens", "audit"], [], "member store");
    if (raw.schemaVersion !== MEMBER_SCHEMA) throw new MemberError("unsupported member store schemaVersion");
    for (const key of ["members", "credentials", "identities", "tokens", "audit"] as const) {
      if (!Array.isArray(raw[key])) throw new MemberError(`${key} must be a list`);
    }
    const document: MemberDocument = {
      schemaVersion: MEMBER_SCHEMA,
      members: (raw.members as unknown[]).map(parseMember),
      credentials: (raw.credentials as unknown[]).map(parseCredential),
      identities: (raw.identities as unknown[]).map(parseIdentity),
      tokens: (raw.tokens as unknown[]).map(parseToken),
      audit: (raw.audit as unknown[]).map(parseAudit),
    };
    checkCrossRecord(document);
    return document;
  } catch (error) {
    if (error instanceof MemberError) throw new MemberError(`${source}: ${error.message}`, error.statusCode);
    throw error;
  }
}

function checkCrossRecord(document: MemberDocument): void {
  const members = document.members;
  unique(members.map((m) => m.id), "member id");
  unique(members.map((m) => m.username), "username");
  unique(members.map((m) => m.principalName), "principalName");
  unique(members.flatMap((m) => (m.email === null ? [] : [m.email])), "email");
  unique(members.flatMap((m) => m.certCNs), "certificate CN");
  // Approval compares principal names and certificate CNs as plain strings, so one member's CN
  // may not be another member's principalName. A member's own pair may match.
  for (const member of members) {
    const clash = members.find((other) => other.id !== member.id && other.certCNs.includes(member.principalName));
    if (clash) throw new MemberError(`principalName ${member.principalName} is another member's certificate CN`, 409);
  }
  const byId = new Map(members.map((m) => [m.id, m]));
  const live = (id: string | null, what: string): void => {
    const member = id === null ? undefined : byId.get(id);
    if (!member) throw new MemberError(`${what} names an unknown member`);
    if (member.status === "deleted") throw new MemberError(`${what} names a deleted member`);
  };
  for (const credential of document.credentials) live(credential.memberId, "credential");
  unique(document.credentials.map((c) => c.memberId), "credential per member");
  for (const identity of document.identities) live(identity.memberId, "identity");
  unique(document.identities.map((i) => JSON.stringify([i.issuer, i.subject])), "identity (issuer, subject)");
  unique(document.tokens.map((t) => t.id), "token id");
  unique(document.tokens.map((t) => t.digest), "token digest");
  for (const token of document.tokens) if (token.memberId !== null) live(token.memberId, "token");
}

// ── load / save / transaction ─────────────────────────────────────────────────────────────────

export const emptyMemberDocument = (): MemberDocument => ({
  schemaVersion: MEMBER_SCHEMA, members: [], credentials: [], identities: [], tokens: [], audit: [],
});

export function loadMemberDocument(path: string): MemberDocument {
  const full = resolve(path);
  let text: string;
  try { text = readFileSync(full, "utf8"); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new MemberError(`${full}: member store is unavailable`, 503);
    throw new MemberError(`${full}: ${(error as Error).message}`);
  }
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { throw new MemberError(`${full}: member store is not valid JSON`); }
  return parse(raw, full);
}

/** Validates the whole document, then replaces the file atomically. */
export function saveMemberDocument(path: string, document: MemberDocument): MemberDocument {
  const full = resolve(path);
  const valid = parse(document, full);
  atomicWriteFile(full, JSON.stringify(valid, null, 2) + "\n");
  return valid;
}

/** Explicit one-time provisioning; refuses to overwrite. Transactions never create the file. */
export function initializeMemberDocument(path: string): MemberDocument {
  const document = emptyMemberDocument();
  createExclusiveFile(path, JSON.stringify(document, null, 2) + "\n", "member store", memberFailure);
  return document;
}

const activeAdmins = (document: MemberDocument): number =>
  document.members.filter((m) => m.status === "active" && m.roles.includes("admin")).length;

/**
 * Load → mutate → validate → save under `<path>.lock`, waiting at most `waitMs` (≤ 10 s).
 * Nothing is saved when `mutate` returns a thenable (it must be synchronous), or when the store had
 * an active admin before `mutate` and has none after it.
 * @see member-store.test.ts "a transaction that removes the last active admin is not saved"
 */
export function withMemberTransaction<T>(path: string, mutate: (document: MemberDocument) => T, options: { waitMs?: number } = {}): T {
  const full = resolve(path);
  const waitMs = options.waitMs ?? MEMBER_LOCK_WAIT_MS;
  if (!Number.isSafeInteger(waitMs) || waitMs < 0 || waitMs > MEMBER_LOCK_WAIT_MS) throw new MemberError("member lock waitMs is invalid");
  return withFileLock(full, waitMs, "member store", memberFailure, () => {
    const document = loadMemberDocument(full);
    const adminsBefore = activeAdmins(document);
    const result = mutate(document);
    if (result !== null && (typeof result === "object" || typeof result === "function")
      && typeof (result as { then?: unknown }).then === "function") {
      // Observe a rejection so it does not surface as an unhandled rejection after this throw.
      (result as unknown as PromiseLike<unknown>).then(undefined, () => undefined);
      throw new MemberError("member transaction mutate must be synchronous", 500);
    }
    if (adminsBefore > 0 && activeAdmins(document) === 0) throw new MemberError("refusing to leave no active admin", 409);
    saveMemberDocument(full, document);
    return result;
  });
}

// ── lookups ───────────────────────────────────────────────────────────────────────────────────

function tryName(value: string): string | null { try { return normalizeMemberName(value); } catch { return null; } }
function tryEmail(value: string): string | null { try { return normalizeEmail(value); } catch { return null; } }

/** These four return the member in any status; callers check `status` (or use `activeMember`). */
export function findByUsername(document: MemberDocument, username: string): Member | null {
  const name = tryName(username);
  return name === null ? null : document.members.find((m) => m.username === name) ?? null;
}
export function findByEmail(document: MemberDocument, email: string): Member | null {
  const normalized = tryEmail(email);
  return normalized === null ? null : document.members.find((m) => m.email === normalized) ?? null;
}
/** Exact string match on issuer and subject; no URL normalization. */
export function findByIdentity(document: MemberDocument, issuer: string, subject: string): Member | null {
  const identity = document.identities.find((i) => i.issuer === issuer && i.subject === subject);
  return identity ? document.members.find((m) => m.id === identity.memberId) ?? null : null;
}
export function findByCertCN(document: MemberDocument, cn: string): Member | null {
  return document.members.find((m) => m.certCNs.includes(cn)) ?? null;
}
export function activeMember(document: MemberDocument, id: string): Member | null {
  const member = document.members.find((m) => m.id === id);
  return member && member.status === "active" ? member : null;
}
export function passwordCredential(document: MemberDocument, memberId: string): PasswordCredential | null {
  return document.credentials.find((c) => c.memberId === memberId) ?? null;
}

// ── mutations ─────────────────────────────────────────────────────────────────────────────────

function audit(document: MemberDocument, ctx: MemberContext, action: string, target: string): void {
  document.audit.push({ at: nowIso(ctx.now), actor: actorName(ctx.actor), action, target, sourceIp: ctx.sourceIp ?? null });
}
function requireMember(document: MemberDocument, id: string): Member {
  const member = document.members.find((m) => m.id === id);
  if (!member) throw new MemberError("member not found", 404);
  return member;
}
function requireNotDeleted(document: MemberDocument, id: string): Member {
  const member = requireMember(document, id);
  if (member.status === "deleted") throw new MemberError(`member ${member.username} is deleted`, 409);
  return member;
}
const isActiveAdmin = (status: MemberStatus, roles: readonly MemberRole[]): boolean => status === "active" && roles.includes("admin");

/**
 * Refuse a change that turns the last active admin into anything else.
 * @see member-store.test.ts "last-admin protection"
 */
function assertAdminRemains(document: MemberDocument, member: Member, next: { status: MemberStatus; roles: readonly MemberRole[] }): void {
  if (!isActiveAdmin(member.status, member.roles) || isActiveAdmin(next.status, next.roles)) return;
  const others = document.members.filter((m) => m.id !== member.id && isActiveAdmin(m.status, m.roles));
  if (others.length === 0) throw new MemberError("refusing to leave no active admin", 409);
}

export function createMember(document: MemberDocument, input: {
  username: string; principalName?: string; email?: string | null; emailVerified?: boolean;
  status?: "invited" | "active"; roles: readonly string[]; soloApprove?: boolean; otpUserId?: string | null; certCNs?: readonly string[];
}, ctx: MemberContext): Member {
  const at = nowIso(ctx.now);
  const username = normalizeMemberName(input.username);
  const principalName = normalizeMemberName(input.principalName ?? input.username, "principalName");
  const email = input.email === undefined || input.email === null ? null : normalizeEmail(input.email);
  const status = input.status ?? "invited";
  if (status !== "invited" && status !== "active") throw new MemberError("a new member is invited or active");
  const roles = roleList(input.roles);
  if (document.members.some((m) => m.username === username)) throw new MemberError(`username ${username} is taken`, 409);
  if (document.members.some((m) => m.principalName === principalName)) throw new MemberError(`principalName ${principalName} is taken`, 409);
  if (email !== null && document.members.some((m) => m.email === email)) throw new MemberError("email is already in use", 409);
  const cns = (input.certCNs ?? []).map(certCN);
  for (const cn of cns) if (findByCertCN(document, cn)) throw new MemberError(`certificate CN ${cn} is bound to another member`, 409);
  if (findByCertCN(document, principalName)) throw new MemberError(`principalName ${principalName} is another member's certificate CN`, 409);
  for (const cn of cns) {
    if (cn !== principalName && document.members.some((m) => m.principalName === cn)) {
      throw new MemberError(`certificate CN ${cn} is another member's principalName`, 409);
    }
  }
  const member: Member = {
    id: randomUUID(), username, principalName, email,
    emailVerifiedAt: email !== null && input.emailVerified === true ? at : null,
    status, roles, soloApprove: input.soloApprove === true, otpUserId: otpUserId(input.otpUserId),
    certCNs: [...new Set(cns)], createdAt: at, createdBy: actorName(ctx.actor), updatedAt: at,
  };
  if (status === "active" && roles.length === 0) throw new MemberError("an active member needs at least one role");
  document.members.push(member);
  audit(document, ctx, "member.create", member.id);
  return member;
}

/** Store an already-computed `hashPassword` result. */
export function setPassword(document: MemberDocument, memberId: string, hash: string, options: { mustChange: boolean }, ctx: MemberContext): PasswordCredential {
  requireNotDeleted(document, memberId);
  if (!parseEncodedHash(hash)) throw new MemberError("password hash is malformed");
  const credential: PasswordCredential = { memberId, kind: "password", hash, changedAt: nowIso(ctx.now), mustChange: options.mustChange === true };
  document.credentials = document.credentials.filter((c) => c.memberId !== memberId);
  document.credentials.push(credential);
  audit(document, ctx, "member.password-set", memberId);
  return credential;
}

export function suspendMember(document: MemberDocument, memberId: string, ctx: MemberContext): Member {
  const member = requireNotDeleted(document, memberId);
  if (member.status === "suspended") return member;
  assertAdminRemains(document, member, { status: "suspended", roles: member.roles });
  member.status = "suspended"; member.updatedAt = nowIso(ctx.now);
  audit(document, ctx, "member.suspend", memberId);
  return member;
}

export function unsuspendMember(document: MemberDocument, memberId: string, ctx: MemberContext): Member {
  const member = requireNotDeleted(document, memberId);
  if (member.status !== "suspended") throw new MemberError(`member ${member.username} is not suspended`, 409);
  if (member.roles.length === 0) throw new MemberError("an active member needs at least one role", 409);
  member.status = "active"; member.updatedAt = nowIso(ctx.now);
  audit(document, ctx, "member.unsuspend", memberId);
  return member;
}

/**
 * Soft delete. Keeps `id`, `username`, `principalName` (so they stay taken), clears email,
 * certificate CNs, roles, solo approval, OTP binding, the password credential, linked identities,
 * the member's tokens, and any token addressed to the member's email.
 */
export function deleteMember(document: MemberDocument, memberId: string, ctx: MemberContext): Member {
  const member = requireNotDeleted(document, memberId);
  assertAdminRemains(document, member, { status: "deleted", roles: [] });
  const email = member.email;
  Object.assign(member, {
    status: "deleted", email: null, emailVerifiedAt: null, certCNs: [], roles: [], soloApprove: false, otpUserId: null,
    updatedAt: nowIso(ctx.now),
  });
  document.credentials = document.credentials.filter((c) => c.memberId !== memberId);
  document.identities = document.identities.filter((i) => i.memberId !== memberId);
  document.tokens = document.tokens.filter((t) => t.memberId !== memberId && (email === null || t.email !== email));
  audit(document, ctx, "member.delete", memberId);
  return member;
}

export function setRoles(document: MemberDocument, memberId: string, roles: readonly string[], ctx: MemberContext): Member {
  const member = requireNotDeleted(document, memberId);
  const next = roleList(roles);
  if (member.status === "active" && next.length === 0) throw new MemberError("an active member needs at least one role");
  assertAdminRemains(document, member, { status: member.status, roles: next });
  member.roles = next; member.updatedAt = nowIso(ctx.now);
  audit(document, ctx, "member.roles", memberId);
  return member;
}

export function bindCertCN(document: MemberDocument, memberId: string, cn: string, ctx: MemberContext): Member {
  const member = requireNotDeleted(document, memberId);
  const name = certCN(cn);
  const owner = findByCertCN(document, name);
  if (owner && owner.id !== memberId) throw new MemberError(`certificate CN ${name} is bound to another member`, 409);
  if (owner) return member;
  if (document.members.some((m) => m.id !== memberId && m.principalName === name)) {
    throw new MemberError(`certificate CN ${name} is another member's principalName`, 409);
  }
  member.certCNs.push(name); member.updatedAt = nowIso(ctx.now);
  audit(document, ctx, "member.cert-bind", memberId);
  return member;
}

export function unbindCertCN(document: MemberDocument, memberId: string, cn: string, ctx: MemberContext): Member {
  const member = requireNotDeleted(document, memberId);
  if (!member.certCNs.includes(cn)) throw new MemberError("certificate CN is not bound to this member", 404);
  member.certCNs = member.certCNs.filter((c) => c !== cn); member.updatedAt = nowIso(ctx.now);
  audit(document, ctx, "member.cert-unbind", memberId);
  return member;
}

/**
 * Bind `(issuer, subject)` to the member the caller names. There is no lookup by email or
 * username here; a pair already bound to a different member is refused (409).
 */
export function linkIdentity(document: MemberDocument, input: { memberId: string; issuer: string; subject: string }, ctx: MemberContext): MemberIdentity {
  requireNotDeleted(document, input.memberId);
  const issuer = issuerUrl(input.issuer); const subject = subjectId(input.subject);
  const existing = document.identities.find((i) => i.issuer === issuer && i.subject === subject);
  if (existing && existing.memberId !== input.memberId) throw new MemberError("this identity is linked to another member", 409);
  if (existing) return existing;
  const identity: MemberIdentity = { issuer, subject, memberId: input.memberId, linkedAt: nowIso(ctx.now), linkedBy: actorName(ctx.actor) };
  document.identities.push(identity);
  audit(document, ctx, "member.identity-link", input.memberId);
  return identity;
}

/** Refuses (409) when the member has no password credential and this is their last identity. */
export function unlinkIdentity(document: MemberDocument, input: { memberId: string; issuer: string; subject: string }, ctx: MemberContext): void {
  requireNotDeleted(document, input.memberId);
  const own = document.identities.filter((i) => i.memberId === input.memberId);
  const target = own.find((i) => i.issuer === input.issuer && i.subject === input.subject);
  if (!target) throw new MemberError("identity is not linked to this member", 404);
  if (own.length === 1 && !passwordCredential(document, input.memberId)) {
    throw new MemberError("refusing to remove the member's last login method", 409);
  }
  document.identities = document.identities.filter((i) => i !== target);
  audit(document, ctx, "member.identity-unlink", input.memberId);
}

/**
 * Issue a single-use token and return its plaintext once; only the SHA-256 digest is stored.
 * Unused tokens of the same kind for the same member (or, for an invite with no member, the same
 * email) are removed first.
 */
export function issueToken(document: MemberDocument, input: {
  kind: MemberTokenKind; memberId?: string | null; roles?: readonly string[]; email?: string; ttlSec?: number;
}, ctx: MemberContext): { token: string; row: MemberToken } {
  if (!MEMBER_TOKEN_KINDS.includes(input.kind)) throw new MemberError("token kind is invalid");
  const memberId = input.memberId ?? null;
  if (memberId !== null) requireNotDeleted(document, memberId);
  const ttlSec = input.ttlSec ?? DEFAULT_TOKEN_TTL_SEC[input.kind];
  if (!Number.isSafeInteger(ttlSec) || ttlSec < MIN_TOKEN_TTL_SEC || ttlSec > MAX_TOKEN_TTL_SEC) throw new MemberError("token ttlSec is out of range");
  const issuedAt = ctx.now ?? new Date();
  const token = MEMBER_TOKEN_PREFIX + randomBytes(32).toString("hex");
  const row: MemberToken = {
    id: randomUUID(), kind: input.kind, digest: sha256(token), memberId,
    expiresAt: new Date(issuedAt.getTime() + ttlSec * 1_000).toISOString(), usedAt: null,
    createdAt: nowIso(issuedAt), createdBy: actorName(ctx.actor),
  };
  if (input.roles !== undefined) row.roles = roleList(input.roles);
  if (input.email !== undefined) row.email = normalizeEmail(input.email);
  checkTokenShape(row);
  const supersedes = (t: MemberToken): boolean => t.kind === row.kind && t.usedAt === null
    && (memberId !== null ? t.memberId === memberId : t.memberId === null && row.email !== undefined && t.email === row.email);
  document.tokens = document.tokens.filter((t) => !supersedes(t));
  document.tokens.push(row);
  audit(document, ctx, `token.issue.${row.kind}`, row.id);
  return { token, row };
}

/**
 * Mark a token used and return its row. Every stored digest of that kind is compared with
 * `timingSafeEqual`. Unknown, used and expired tokens all get the same 400. So does a token whose
 * member is suspended, or an invite bound to a member who is no longer invited.
 */
export function consumeToken(document: MemberDocument, input: { kind: MemberTokenKind; token: string }, ctx: MemberContext): MemberToken {
  const refuse = (): MemberError => new MemberError("token is invalid, used, or expired");
  if (typeof input.token !== "string" || !TOKEN_RE.test(input.token)) throw refuse();
  const digest = Buffer.from(sha256(input.token), "hex");
  let row: MemberToken | null = null;
  for (const candidate of document.tokens) {
    if (candidate.kind !== input.kind) continue;
    if (timingSafeEqual(Buffer.from(candidate.digest, "hex"), digest)) row = candidate;
  }
  const now = ctx.now ?? new Date();
  if (!row || row.usedAt !== null || Date.parse(row.expiresAt) <= now.getTime()) throw refuse();
  if (row.memberId !== null) {
    const member = requireMember(document, row.memberId);
    const allowed: MemberStatus[] = row.kind === "invite" ? ["invited"] : ["active", "invited"];
    if (!allowed.includes(member.status)) throw refuse();
  }
  row.usedAt = nowIso(now);
  audit(document, ctx, `token.consume.${row.kind}`, row.id);
  return row;
}
