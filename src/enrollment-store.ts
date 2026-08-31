import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, randomBytes, X509Certificate } from "node:crypto";
import {
  chmodSync, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { isMainThread, parentPort, Worker, workerData } from "node:worker_threads";
import {
  MAX_REVOCATION_ROWS, parseRevocationSnapshot, planRevocationCompaction, serializeRevocationSnapshot,
} from "./revocation-snapshot.ts";

export const ENROLLMENT_SCHEMA = 1 as const;
export const NODE_TOKEN_PREFIX = "stnode_";
export const DEFAULT_NODE_TOKEN_TTL_SEC = 7 * 24 * 60 * 60;
export const MAX_NODE_TOKEN_TTL_SEC = 30 * 24 * 60 * 60;
export const MAX_PENDING_CSRS_PER_HOST = 2;
const MIN_NODE_TOKEN_TTL_SEC = 5 * 60;
/**
 * The third principal: a credential a *program* holds.
 *
 * A different prefix from `stnode_` on purpose. The two are checked in different places and grant
 * different things, and a shared prefix would make the shape gates in front of both admit each
 * other's callers — the manager would then have to distinguish them by a store read, which is the
 * read the gate exists to avoid.
 *
 * The TTL floor is an hour rather than the node token's five minutes because nothing renews these:
 * an operator issues one, pastes it into another system's configuration, and does not come back.
 * A ceiling of a year is the point past which "still valid" stops meaning anything.
 */
export const APP_TOKEN_PREFIX = "hpapp_";
export const DEFAULT_APP_TOKEN_TTL_SEC = 90 * 24 * 60 * 60;
export const MAX_APP_TOKEN_TTL_SEC = 365 * 24 * 60 * 60;
const MIN_APP_TOKEN_TTL_SEC = 60 * 60;
/**
 * The bound on `createdBy`, exported because **something has to compose a value that fits it**.
 *
 * 🔴 It was a bare `120` inside `createNodeToken`, and the app-token path built `app:<label>#<id>`
 * without knowing about it. A label may be 120 characters; the composed string is then 141, and the
 * slice took the tail off — cutting the id, which is the half that says *which* credential minted
 * the token. The truncation silently removed the exact property the field had just been widened to
 * carry, and only for the longest labels.
 *
 * A duplicated literal is how that comes back, so the composer reads the same constant the
 * truncation does.
 */
export const MAX_CREATED_BY_CHARS = 120;

/**
 * `app:<label>#<id>`, built to fit `MAX_CREATED_BY_CHARS` with the id intact.
 *
 * The label loses characters and the id never does. That ordering is the decision: two live tokens
 * may share a label — rotation issues the replacement before revoking the old one — so a trimmed
 * label still reads as the same program, while a trimmed id names nothing at all. Raising the cap
 * instead was the other option; it was not taken because the cap bounds a field written from
 * operator-supplied text on the node-token path too, and widening it there buys nothing.
 */
export function appTokenCreatedBy(label: string, id: string): string {
  const stamp = `#${id}`;
  return `app:${label}`.slice(0, MAX_CREATED_BY_CHARS - stamp.length) + stamp;
}
const OPENSSL_TIMEOUT_MS = 5_000;
const CSR_WORKER_TIMEOUT_MS = 10_000;
const MAX_CSR_VALIDATION_WORKERS = 2;
const MAX_QUEUED_CSR_VALIDATIONS = 16;
const ENROLLMENT_LOCK_WAIT_MS = 10_000;
const LOCK_SLEEP = new Int32Array(new SharedArrayBuffer(4));
const HOSTNAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$/;
const SHA256 = /^[0-9a-f]{64}$/;
const CSR_PEM = /^-----BEGIN CERTIFICATE REQUEST-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE REQUEST-----\r?\n?$/;
const CERT_PEM = /^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?$/;

export type CsrStatus = "pending" | "conflict" | "rejected" | "signed" | "host-deregistered";
export interface NodeTokenRecord {
  id: string; hostname: string; tokenHash: string; label: string | null; createdBy: string | null;
  hostLifecycleId: string | null;
  createdAt: string; expiresAt: string; lastUsedAt: string | null; revokedAt: string | null;
}
export interface NodeCsrRecord {
  id: string; hostname: string; nodeTokenId: string; status: CsrStatus; csrPem: string;
  hostLifecycleId: string | null;
  csrSha256: string; publicKeySha256: string; keyAlgorithm: "ECDSA-P256"; createdAt: string;
  sourceIp: string | null; decidedAt: string | null; decidedBy: string | null;
  decisionReason: string | null; signedAt: string | null; caName: string | null;
  certificatePem: string | null; caPem: string | null; certificateSha256: string | null;
  certificateNotBefore: string | null; certificateNotAfter: string | null; retrievedAt: string | null;
}
export interface ValidatedNodeCsr {
  hostname: string; pem: string; csrSha256: string; publicKeySha256: string; keyAlgorithm: "ECDSA-P256";
}
export interface NodeCsrPreflight { hostname: string; pem: string; existing: NodeCsrRecord | null; }
export interface EnrollmentAuditEvent {
  at: string; actor: string; action: string; target: string; sourceIp: string | null;
  detail: Record<string, string | number | boolean | null>;
}
export interface CertificateRevocation { fingerprint256: string; subject: string | null; reason: string; actor: string; revokedAt: string; }
export type HostDeregistrationCredentialState =
  "accepted" | "closing" | "replicating" | "ready_for_infrastructure_destroy" | "blocked";
export interface HostLifecycleTombstone {
  hostname: string; hostLifecycleId: string; externalOperationId: string; createdAt: string;
}
export interface HostLifecycleBinding {
  hostname: string; hostLifecycleId: string; provider: "vultr"; providerInstanceId: string;
  evidenceSha256: string; boundAt: string; boundBy: string;
}
export interface HostDeregistrationRelay {
  name: string; state: "pending" | "installed" | "failed"; updatedAt: string | null; error: string | null;
}
export interface HostDeregistrationRecord {
  id: string;
  status: "credentials_pending" | "ready_for_infrastructure_destroy" | "policy_pending" | "completed" | "blocked";
  hostname: string; externalOperationId: string; hostLifecycleId: string;
  reason: "instance-destroy"; requestedBy: string; createdAt: string; updatedAt: string;
  scope: { appTokenId: string; label: string; hostnamePattern: string };
  credentials: {
    state: HostDeregistrationCredentialState; tombstone: "persisted";
    tokens: { revoked: number; alreadyRevoked: number };
    requests: { closed: number; alreadyClosed: number };
    certificates: { revoked: number; alreadyRevoked: number; expired: number };
    requiredRevocationFingerprints: string[];
    relays: HostDeregistrationRelay[];
  };
  infrastructure: {
    state: "waiting" | "destroyed"; provider: "vultr" | null; providerInstanceId: string | null;
    expectedProviderInstanceId: string | null; destroyedAt: string | null;
  };
  policy: {
    state: "waiting_for_infrastructure_destroy" | "queued" | "pr_open" | "merged" | "awaiting_publish" | "published" | "completed" | "blocked";
    queuedAt: string | null; completedAt: string | null; completedBy: string | null;
    pullRequestUrl: string | null; commitSha: string | null; publishedGeneration: string | null;
    relays: Array<{ name: string; absentAt: string }>;
    /** Durable orchestration evidence. Optional only for stores written before the worker existed. */
    automation?: {
      branch: string | null; pullRequestNumber: number | null; patchCommitSha: string | null;
      mergeCommitSha: string | null; affectedRelays: string[];
      /** Optional only while reading the first worker revision written before these fields existed. */
      reviewedBy?: string[]; planGeneration?: string | null; planProposedAt?: string | null;
      plans: Array<{
        relay: string; hash: string; generation: string; proposedAt: string;
        publishedAt: string | null;
      }>;
      lastAttemptAt: string | null; lastError: string | null;
    };
  };
  blocked: { code: string; operatorAction: string } | null;
}
/**
 * Everything an app token is allowed to ask for.
 *
 * There is no general `enrollment:sign`, `enrollment:certificate-upload` or `enrollment:revoke`.
 * `enrollment:host-deregister` is destructive, but only for one lifecycle under the token's
 * hostname pattern; issue it solely to the zone authority that already destroys those VMs. Signing
 * and arbitrary revocation stay with an operator holding a certificate and one-time code.
 */
export const APP_TOKEN_SCOPES = [
  "enrollment:token-create", "enrollment:requests-read", "enrollment:host-deregister",
] as const;
export type AppTokenScope = (typeof APP_TOKEN_SCOPES)[number];
export interface AppTokenRecord {
  id: string; label: string; tokenHash: string; scopes: AppTokenScope[]; hostnamePattern: string;
  createdBy: string | null; createdAt: string; expiresAt: string; lastUsedAt: string | null; revokedAt: string | null;
}
/**
 * The whole store, read and written as one document.
 *
 * ## `audit` and `requests` have no retention policy, and that is a decision rather than an omission
 *
 * Nothing here prunes either array. That was raised as a defect and measured before being accepted:
 * a row is appended by seven actions, and in steady state the only ones that recur are a certificate
 * rotation's — one token created, one revoked, one CSR submitted, one certificate uploaded, and one
 * `node-cert.fetch` (recorded on the **first** retrieval only, because `retrievedAt` gates it; the
 * agent polls). That is five rows per host per rotation. At seven hosts on a ninety-day certificate
 * this is **on the order of a hundred rows a year**.
 *
 * The cost of a large store is that `requireEnrollmentDocument` reads and parses all of it,
 * synchronously, on every enrollment request. What made that worth worrying about was that any
 * caller could trigger it; that is now bounded by `looksLikeNodeToken` and the manager's per-source
 * rate limit. At a hundred rows a year the parse is not measurable.
 *
 * So: no pruning, because discarding an audit trail needs a reason and "it might get big" is not one
 * at this rate. **Revisit when either is true** — the store passes 1 MB, or the fleet passes ~50
 * hosts. Both are checkable in one command:
 *
 *     ls -l <store.json> && jq '.audit | length, (.requests | length)' <store.json>
 *
 * At that point the shape is a compaction subcommand on `heliopause-enrollment`, matching the one
 * `heliopause-revocations compact` already has — an operator action, not a runtime sweep, for the
 * same reason revocation compaction is one.
 */
export interface EnrollmentDocument {
  schemaVersion: typeof ENROLLMENT_SCHEMA;
  tokens: NodeTokenRecord[]; requests: NodeCsrRecord[]; audit: EnrollmentAuditEvent[]; revocations: CertificateRevocation[];
  appTokens: AppTokenRecord[];
  hostLifecycleBindings: HostLifecycleBinding[];
  hostLifecycleTombstones: HostLifecycleTombstone[];
  hostDeregistrations: HostDeregistrationRecord[];
}
export class EnrollmentError extends Error { readonly statusCode: number; constructor(message: string, statusCode = 400) { super(message); this.statusCode = statusCode; } }

const nowIso = (now = new Date()): string => now.toISOString();
const sha256 = (value: string | Buffer): string => createHash("sha256").update(value).digest("hex");
const randomHex = (bytes: number): string => randomBytes(bytes).toString("hex");
function hostname(value: string): string {
  const out = value.trim().toLowerCase();
  if (!HOSTNAME.test(out)) throw new EnrollmentError(`invalid hostname: ${JSON.stringify(value)}`);
  return out;
}
const EXTERNAL_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|([+-])(\d{2}):(\d{2}))$/;
function boundedExternalId(value: string, field: string): string {
  const out = value.trim();
  if (!EXTERNAL_ID.test(out)) throw new EnrollmentError(`${field} must be 1-128 safe identifier characters`);
  return out;
}
export const normalizeHostLifecycleId = (value: string): string => boundedExternalId(value, "hostLifecycleId");
export const normalizeExternalOperationId = (value: string): string => boundedExternalId(value, "externalOperationId");
function normalizeRfc3339(value: string, field: string): string {
  const match = RFC3339.exec(value);
  if (!match) throw new EnrollmentError(`${field} must be an RFC3339 timestamp`);
  const [, year, month, day, hour, minute, second, fraction = "", zone, sign, offsetHour, offsetMinute] = match;
  const parts = [year, month, day, hour, minute, second].map(Number);
  const milliseconds = Number(fraction.padEnd(3, "0"));
  const wallClock = new Date(Date.UTC(parts[0]!, parts[1]! - 1, parts[2]!, parts[3]!, parts[4]!, parts[5]!, milliseconds));
  if (wallClock.getUTCFullYear() !== parts[0] || wallClock.getUTCMonth() !== parts[1]! - 1
    || wallClock.getUTCDate() !== parts[2] || wallClock.getUTCHours() !== parts[3]
    || wallClock.getUTCMinutes() !== parts[4] || wallClock.getUTCSeconds() !== parts[5]
    || (zone !== "Z" && (Number(offsetHour) > 23 || Number(offsetMinute) > 59))) {
    throw new EnrollmentError(`${field} must be a valid RFC3339 timestamp`);
  }
  const offset = zone === "Z" ? 0 : (Number(offsetHour) * 60 + Number(offsetMinute)) * (sign === "+" ? 1 : -1);
  return new Date(wallClock.getTime() - offset * 60_000).toISOString();
}
function normalizePastEvidenceTimestamp(value: string, field: string, now: Date): string {
  const canonical = normalizeRfc3339(value, field);
  if (Date.parse(canonical) > now.getTime()) throw new EnrollmentError(`${field} cannot be in the future`);
  return canonical;
}
function isCanonicalRfc3339(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try { return normalizeRfc3339(value, "timestamp") === value; } catch { return false; }
}
function lifecycleTombstone(document: EnrollmentDocument, host: string, lifecycle: string | null): HostLifecycleTombstone | null {
  return document.hostLifecycleTombstones.find((row) =>
    row.hostname === host && (lifecycle === null || row.hostLifecycleId === lifecycle)) ?? null;
}
function assertLifecycleMayProvision(document: EnrollmentDocument, host: string, lifecycle: string | null): void {
  const exact = lifecycleTombstone(document, host, lifecycle);
  if (exact) throw new EnrollmentError(`host lifecycle ${exact.hostLifecycleId} is deregistered`, 409);
  const retired = document.hostDeregistrations.find((row) => row.hostname === host);
  if (retired) {
    throw new EnrollmentError(
      `hostname ${host} is retired by deregistration ${retired.externalOperationId}; an operator must explicitly reopen it before reuse`,
      409,
    );
  }
}
function openssl(args: string[], input?: string | Buffer): Buffer {
  try {
    return execFileSync("openssl", args, {
      input,
      stdio: [input ? "pipe" : "ignore", "pipe", "pipe"],
      timeout: OPENSSL_TIMEOUT_MS,
      maxBuffer: 256 * 1024,
    });
  } catch {
    // OpenSSL's stderr can echo attacker-controlled subject or extension text. Keep the public API
    // useful without reflecting the submitted CSR back to its unauthenticated caller.
    throw new EnrollmentError(`openssl ${args[0] ?? "operation"} rejected the certificate material`);
  }
}
function parse(raw: unknown, source: string): EnrollmentDocument {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new EnrollmentError(`${source}: enrollment store must be an object`);
  const d = raw as Partial<EnrollmentDocument>;
  const allowed = [
    "schemaVersion", "tokens", "requests", "audit", "revocations", "appTokens",
    "hostLifecycleBindings", "hostLifecycleTombstones", "hostDeregistrations",
  ];
  if (Object.keys(d).some((key) => !allowed.includes(key))) {
    throw new EnrollmentError(`${source}: enrollment store contains unsupported fields`);
  }
  if (d.schemaVersion !== ENROLLMENT_SCHEMA || !Array.isArray(d.tokens) || !Array.isArray(d.requests) || !Array.isArray(d.audit)) {
    throw new EnrollmentError(`${source}: invalid enrollment schema`);
  }
  const tokens = (d.tokens as NodeTokenRecord[]).map((token) => {
    const lifecycle = parsedStoredLifecycle(token.hostLifecycleId, source, "node token");
    if (typeof token.expiresAt === "string" && Number.isFinite(Date.parse(token.expiresAt))) {
      return { ...token, hostLifecycleId: lifecycle };
    }
    // Schema-1 stores written before expiry was introduced are bounded from their original issue
    // time. They do not become immortal merely because they predate this field.
    const created = Date.parse(String(token.createdAt));
    return {
      ...token, hostLifecycleId: lifecycle,
      expiresAt: new Date(Number.isFinite(created) ? created + DEFAULT_NODE_TOKEN_TTL_SEC * 1_000 : 0).toISOString(),
    };
  });
  const revocations = d.revocations === undefined
    ? []
    : parseRevocationSnapshot({ schemaVersion: 1, revocations: d.revocations }).revocations;
  // `appTokens` arrived after schema 1 shipped and **the version was deliberately not raised**: a
  // store written before app tokens existed is a correct store, and a missing field there is the
  // normal case rather than damage. Present-but-not-an-array is refused, because that is a file
  // somebody broke rather than a file somebody wrote earlier.
  if (d.appTokens !== undefined && !Array.isArray(d.appTokens)) {
    throw new EnrollmentError(`${source}: enrollment store appTokens must be an array`);
  }
  if (d.hostLifecycleTombstones !== undefined && !Array.isArray(d.hostLifecycleTombstones)) {
    throw new EnrollmentError(`${source}: enrollment store hostLifecycleTombstones must be an array`);
  }
  if (d.hostLifecycleBindings !== undefined && !Array.isArray(d.hostLifecycleBindings)) {
    throw new EnrollmentError(`${source}: enrollment store hostLifecycleBindings must be an array`);
  }
  if (d.hostDeregistrations !== undefined && !Array.isArray(d.hostDeregistrations)) {
    throw new EnrollmentError(`${source}: enrollment store hostDeregistrations must be an array`);
  }
  const requests = (d.requests as NodeCsrRecord[]).map((request) => ({
    ...request, hostLifecycleId: parsedStoredLifecycle(request.hostLifecycleId, source, "CSR request"),
  }));
  // ## Why each row is checked and not merely counted
  //
  // 🔴 `scopes` is the field that decides authority, and the check that reads it is
  // `row.scopes.includes(scope)`. **A string answers that call too**: `"enrollment:token-create,
  // enrollment:requests-read".includes("enrollment:token-create")` is `true`, and so is
  // `.includes("token-cre")`. A store row written by hand, by an older tool, or by anything that
  // flattened the array to a comma-joined string would therefore authorise *substrings* of a scope
  // name. Refusing it at load is the only place that costs nothing.
  //
  // The other three are what every refusal message, audit row and revoke lookup is keyed on. A
  // non-string `id` cannot be revoked by an operator reading the list; a non-string `tokenHash`
  // silently never matches, which reads as "the token stopped working" with no reason anywhere.
  for (const row of (d.appTokens ?? []) as AppTokenRecord[]) {
    if (!row || typeof row !== "object" || Array.isArray(row)) throw new EnrollmentError(`${source}: app token rows must be objects`);
    for (const field of ["id", "label", "tokenHash", "hostnamePattern"] as const) {
      if (typeof row[field] !== "string") throw new EnrollmentError(`${source}: app token ${field} must be a string`);
    }
    if (!Array.isArray(row.scopes) || row.scopes.some((scope) => typeof scope !== "string")) {
      throw new EnrollmentError(`${source}: app token scopes must be an array of strings`);
    }
    // `expiresAt` decides liveness — `lookupAppToken` compares `Date.parse(expiresAt) > now` — and
    // `Date.parse` of anything unparseable is `NaN`, which is `>` nothing. So a broken value fails
    // closed rather than open, and this check is not what stops a forever-token. What it stops is the
    // *silence*: the row would simply never authenticate, with no reason recorded anywhere, and the
    // operator would be told their token stopped working. It also now travels out in a response
    // header, so it must be a value a caller can parse.
    if (typeof row.expiresAt !== "string" || !Number.isFinite(Date.parse(row.expiresAt))) {
      throw new EnrollmentError(`${source}: app token expiresAt must be an ISO timestamp`);
    }
    for (const field of ["createdAt"] as const) {
      if (typeof row[field] !== "string") throw new EnrollmentError(`${source}: app token ${field} must be a string`);
    }
    // The three nullable ones. `revokedAt` is read for truthiness, so a stray `0` or `false` would
    // read as "not revoked" — the one direction this must never be wrong in.
    for (const field of ["revokedAt", "lastUsedAt", "createdBy"] as const) {
      if (row[field] !== null && typeof row[field] !== "string") {
        throw new EnrollmentError(`${source}: app token ${field} must be a string or null`);
      }
    }
  }
  const bindings = (d.hostLifecycleBindings ?? []) as HostLifecycleBinding[];
  const bindingHosts = new Set<string>();
  const bindingLifecycles = new Set<string>();
  for (const row of bindings) {
    exactObject(row, ["hostname", "hostLifecycleId", "provider", "providerInstanceId",
      "evidenceSha256", "boundAt", "boundBy"], `${source}: lifecycle binding`);
    if (hostname(row.hostname) !== row.hostname || normalizeHostLifecycleId(row.hostLifecycleId) !== row.hostLifecycleId
      || row.provider !== "vultr"
      || boundedExternalId(row.providerInstanceId, "providerInstanceId") !== row.providerInstanceId
      || !SHA256.test(row.evidenceSha256) || !isCanonicalRfc3339(row.boundAt)
      || typeof row.boundBy !== "string" || !row.boundBy || row.boundBy.length > 200) {
      throw new EnrollmentError(`${source}: invalid lifecycle binding`);
    }
    if (bindingHosts.has(row.hostname) || bindingLifecycles.has(row.hostLifecycleId)) {
      throw new EnrollmentError(`${source}: duplicate lifecycle binding`);
    }
    bindingHosts.add(row.hostname);
    bindingLifecycles.add(row.hostLifecycleId);
  }
  const tombstones = (d.hostLifecycleTombstones ?? []) as HostLifecycleTombstone[];
  const tombstoneKeys = new Set<string>();
  for (const row of tombstones) {
    exactObject(row, ["hostname", "hostLifecycleId", "externalOperationId", "createdAt"], `${source}: lifecycle tombstone`);
    if (hostname(row.hostname) !== row.hostname || normalizeHostLifecycleId(row.hostLifecycleId) !== row.hostLifecycleId
      || normalizeExternalOperationId(row.externalOperationId) !== row.externalOperationId
      || !Number.isFinite(Date.parse(row.createdAt))) {
      throw new EnrollmentError(`${source}: invalid lifecycle tombstone`);
    }
    const key = `${row.hostname}\0${row.hostLifecycleId}`;
    if (tombstoneKeys.has(key)) throw new EnrollmentError(`${source}: duplicate lifecycle tombstone`);
    tombstoneKeys.add(key);
  }
  const deregistrations = (d.hostDeregistrations ?? []) as HostDeregistrationRecord[];
  const keys = new Set<string>();
  for (const row of deregistrations) {
    if ((row.infrastructure as { expectedProviderInstanceId?: unknown }).expectedProviderInstanceId === undefined) {
      row.infrastructure.expectedProviderInstanceId = null;
    }
    exactObject(row, [
      "id", "status", "hostname", "externalOperationId", "hostLifecycleId", "reason", "requestedBy", "scope",
      "credentials", "infrastructure", "policy", "blocked", "createdAt", "updatedAt",
    ], `${source}: host deregistration`);
    normalizeExternalOperationId(row.id);
    if (hostname(row.hostname) !== row.hostname || normalizeExternalOperationId(row.externalOperationId) !== row.externalOperationId
      || normalizeHostLifecycleId(row.hostLifecycleId) !== row.hostLifecycleId || row.reason !== "instance-destroy"
      || typeof row.requestedBy !== "string" || !row.requestedBy || row.requestedBy.length > 200
      || !Number.isFinite(Date.parse(row.createdAt)) || !Number.isFinite(Date.parse(row.updatedAt))) {
      throw new EnrollmentError(`${source}: invalid host deregistration identity`);
    }
    const key = `${row.hostname}\0${row.externalOperationId}`;
    if (keys.has(key)) throw new EnrollmentError(`${source}: duplicate host deregistration key`);
    keys.add(key);
    if (!["credentials_pending", "ready_for_infrastructure_destroy", "policy_pending", "completed", "blocked"].includes(row.status)) {
      throw new EnrollmentError(`${source}: invalid host deregistration status`);
    }
    exactObject(row.scope, ["appTokenId", "label", "hostnamePattern"], `${source}: host deregistration scope`);
    if (![row.scope.appTokenId, row.scope.label, row.scope.hostnamePattern].every((value) => typeof value === "string" && value.length > 0)
      || appTokenHostnamePattern(row.scope.hostnamePattern) !== row.scope.hostnamePattern) {
      throw new EnrollmentError(`${source}: invalid host deregistration scope`);
    }
    exactObject(row.credentials, [
      "state", "tombstone", "tokens", "requests", "certificates", "requiredRevocationFingerprints", "relays",
    ], `${source}: host deregistration credentials`);
    if (!["accepted", "closing", "replicating", "ready_for_infrastructure_destroy", "blocked"].includes(row.credentials.state)
      || row.credentials.tombstone !== "persisted" || !Array.isArray(row.credentials.relays)
      || !Array.isArray(row.credentials.requiredRevocationFingerprints)
      || row.credentials.requiredRevocationFingerprints.some((value) => typeof value !== "string" || !SHA256.test(value))) {
      throw new EnrollmentError(`${source}: invalid host deregistration credentials`);
    }
    for (const [value, fields, what] of [
      [row.credentials.tokens, ["revoked", "alreadyRevoked"], "tokens"],
      [row.credentials.requests, ["closed", "alreadyClosed"], "requests"],
      [row.credentials.certificates, ["revoked", "alreadyRevoked", "expired"], "certificates"],
    ] as const) {
      exactObject(value, fields, `${source}: host deregistration ${what}`);
      const counts = value as Record<string, unknown>;
      if (fields.some((field) => !Number.isSafeInteger(counts[field]) || (counts[field] as number) < 0)) {
        throw new EnrollmentError(`${source}: invalid host deregistration ${what} counts`);
      }
    }
    const relayNames = new Set<string>();
    for (const relay of row.credentials.relays) {
      exactObject(relay, ["name", "state", "updatedAt", "error"], `${source}: host deregistration relay`);
      if (typeof relay.name !== "string" || !relay.name || relay.name.length > 120 || relayNames.has(relay.name)
        || !["pending", "installed", "failed"].includes(relay.state)
        || (relay.updatedAt !== null && (typeof relay.updatedAt !== "string" || !Number.isFinite(Date.parse(relay.updatedAt))))
        || (relay.error !== null && typeof relay.error !== "string")) {
        throw new EnrollmentError(`${source}: invalid host deregistration relay`);
      }
      relayNames.add(relay.name);
    }
    exactObject(row.infrastructure, ["state", "provider", "providerInstanceId", "expectedProviderInstanceId", "destroyedAt"], `${source}: host deregistration infrastructure`);
    if (!["waiting", "destroyed"].includes(row.infrastructure.state)
      || (row.infrastructure.provider !== null && row.infrastructure.provider !== "vultr")
      || (row.infrastructure.providerInstanceId !== null && typeof row.infrastructure.providerInstanceId !== "string")
      || (row.infrastructure.expectedProviderInstanceId !== null
        && (typeof row.infrastructure.expectedProviderInstanceId !== "string"
          || boundedExternalId(row.infrastructure.expectedProviderInstanceId, "expectedProviderInstanceId")
            !== row.infrastructure.expectedProviderInstanceId))
      || (row.infrastructure.destroyedAt !== null && !isCanonicalRfc3339(row.infrastructure.destroyedAt))) {
      throw new EnrollmentError(`${source}: invalid host deregistration infrastructure`);
    }
    if (row.infrastructure.state === "waiting" && (row.infrastructure.provider !== null
      || row.infrastructure.providerInstanceId !== null || row.infrastructure.destroyedAt !== null)) {
      throw new EnrollmentError(`${source}: waiting infrastructure carries destruction evidence`);
    }
    if (row.infrastructure.state === "destroyed" && (row.infrastructure.provider !== "vultr"
      || typeof row.infrastructure.providerInstanceId !== "string"
      || boundedExternalId(row.infrastructure.providerInstanceId, "providerInstanceId") !== row.infrastructure.providerInstanceId
      || (row.infrastructure.expectedProviderInstanceId !== null
        && row.infrastructure.providerInstanceId !== row.infrastructure.expectedProviderInstanceId)
      || !isCanonicalRfc3339(row.infrastructure.destroyedAt))) {
      throw new EnrollmentError(`${source}: destroyed infrastructure lacks confirmation evidence`);
    }
    exactObjectOptional(row.policy, [
      "state", "queuedAt", "completedAt", "completedBy", "pullRequestUrl", "commitSha", "publishedGeneration", "relays",
    ], ["automation"], `${source}: host deregistration policy`);
    if (!["waiting_for_infrastructure_destroy", "queued", "pr_open", "merged", "awaiting_publish", "published", "completed", "blocked"].includes(row.policy.state)) {
      throw new EnrollmentError(`${source}: invalid host deregistration policy`);
    }
    for (const field of ["queuedAt", "completedAt"] as const) {
      if (row.policy[field] !== null && (typeof row.policy[field] !== "string" || !Number.isFinite(Date.parse(row.policy[field]!)))) {
        throw new EnrollmentError(`${source}: invalid host deregistration policy timestamp`);
      }
    }
    for (const field of ["completedBy", "pullRequestUrl", "commitSha", "publishedGeneration"] as const) {
      if (row.policy[field] !== null && typeof row.policy[field] !== "string") throw new EnrollmentError(`${source}: invalid host deregistration policy evidence`);
    }
    if (!Array.isArray(row.policy.relays)) throw new EnrollmentError(`${source}: invalid host deregistration policy relays`);
    const policyRelayNames = new Set<string>();
    for (const relay of row.policy.relays) {
      exactObject(relay, ["name", "absentAt"], `${source}: host deregistration policy relay`);
      if (typeof relay.name !== "string" || !relay.name || policyRelayNames.has(relay.name)
        || !isCanonicalRfc3339(relay.absentAt)) {
        throw new EnrollmentError(`${source}: invalid host deregistration policy relay`);
      }
      policyRelayNames.add(relay.name);
    }
    if (row.policy.automation !== undefined) {
      const automation = row.policy.automation;
      exactObjectOptional(automation, [
        "branch", "pullRequestNumber", "patchCommitSha", "mergeCommitSha", "affectedRelays", "plans",
        "lastAttemptAt", "lastError",
      ], ["reviewedBy", "planGeneration", "planProposedAt"], `${source}: host deregistration policy automation`);
      for (const field of ["branch", "patchCommitSha", "mergeCommitSha", "lastAttemptAt", "lastError"] as const) {
        if (automation[field] !== null && typeof automation[field] !== "string") {
          throw new EnrollmentError(`${source}: invalid host deregistration policy automation ${field}`);
        }
      }
      if (automation.lastAttemptAt !== null && !Number.isFinite(Date.parse(automation.lastAttemptAt))) {
        throw new EnrollmentError(`${source}: invalid host deregistration policy automation lastAttemptAt`);
      }
      if (automation.reviewedBy !== undefined && (!Array.isArray(automation.reviewedBy)
        || automation.reviewedBy.some((reviewer) => typeof reviewer !== "string" || !reviewer)
        || new Set(automation.reviewedBy).size !== automation.reviewedBy.length)) {
        throw new EnrollmentError(`${source}: invalid host deregistration policy reviewers`);
      }
      if (automation.planGeneration !== undefined && automation.planGeneration !== null
        && (typeof automation.planGeneration !== "string" || !automation.planGeneration)) {
        throw new EnrollmentError(`${source}: invalid host deregistration reserved generation`);
      }
      if (automation.planProposedAt !== undefined && automation.planProposedAt !== null
        && (typeof automation.planProposedAt !== "string" || !isCanonicalRfc3339(automation.planProposedAt))) {
        throw new EnrollmentError(`${source}: invalid host deregistration reserved proposal time`);
      }
      if (((automation.planGeneration ?? null) === null)
        !== ((automation.planProposedAt ?? null) === null)) {
        throw new EnrollmentError(`${source}: incomplete host deregistration plan reservation`);
      }
      if (automation.pullRequestNumber !== null
        && (!Number.isSafeInteger(automation.pullRequestNumber) || automation.pullRequestNumber < 1)) {
        throw new EnrollmentError(`${source}: invalid host deregistration pull request number`);
      }
      if (!Array.isArray(automation.affectedRelays)
        || automation.affectedRelays.some((name) => typeof name !== "string" || !name)
        || new Set(automation.affectedRelays).size !== automation.affectedRelays.length
        || !Array.isArray(automation.plans)) {
        throw new EnrollmentError(`${source}: invalid host deregistration policy automation relays`);
      }
      const planRelays = new Set<string>();
      for (const plan of automation.plans) {
        exactObject(plan, ["relay", "hash", "generation", "proposedAt", "publishedAt"], `${source}: host deregistration policy plan`);
        if (typeof plan.relay !== "string" || !plan.relay || planRelays.has(plan.relay)
          || !/^sha256:[0-9a-f]{64}$/.test(plan.hash) || typeof plan.generation !== "string" || !plan.generation
          || !Number.isFinite(Date.parse(plan.proposedAt))
          || (plan.publishedAt !== null && !Number.isFinite(Date.parse(plan.publishedAt)))) {
          throw new EnrollmentError(`${source}: invalid host deregistration policy plan`);
        }
        planRelays.add(plan.relay);
      }
      const needsPr = ["pr_open", "merged", "awaiting_publish", "published"].includes(row.policy.state);
      if (needsPr && (!automation.branch || automation.pullRequestNumber === null || !automation.patchCommitSha
        || automation.affectedRelays.length === 0 || !row.policy.pullRequestUrl)) {
        throw new EnrollmentError(`${source}: advanced host deregistration lacks pull request automation evidence`);
      }
      const needsMerge = ["merged", "awaiting_publish", "published"].includes(row.policy.state);
      if (needsMerge && (!automation.mergeCommitSha || (automation.reviewedBy?.length ?? 0) === 0
        || row.policy.commitSha !== automation.mergeCommitSha)) {
        throw new EnrollmentError(`${source}: merged host deregistration lacks reviewed merge evidence`);
      }
      if (["awaiting_publish", "published"].includes(row.policy.state)) {
        const affected = [...automation.affectedRelays].sort();
        const planned = [...planRelays].sort();
        if (!automation.planGeneration || !automation.planProposedAt
          || JSON.stringify(affected) !== JSON.stringify(planned)
          || automation.plans.some((plan) => plan.generation !== automation.planGeneration
            || plan.proposedAt !== automation.planProposedAt)
          || (row.policy.state === "published" && automation.plans.some((plan) => plan.publishedAt === null))) {
          throw new EnrollmentError(`${source}: publish-pending host deregistration lacks exact durable plans`);
        }
      }
    }
    if (row.blocked !== null) {
      exactObject(row.blocked, ["code", "operatorAction"], `${source}: host deregistration block`);
      if (typeof row.blocked.code !== "string" || typeof row.blocked.operatorAction !== "string") {
        throw new EnrollmentError(`${source}: invalid host deregistration block`);
      }
    }
    const matchingTombstone = tombstones.filter((tombstone) =>
      tombstone.hostname === row.hostname && tombstone.hostLifecycleId === row.hostLifecycleId
      && tombstone.externalOperationId === row.externalOperationId);
    if (matchingTombstone.length !== 1) throw new EnrollmentError(`${source}: host deregistration has no unique matching tombstone`);
    if (row.credentials.state === "ready_for_infrastructure_destroy"
      && (row.credentials.relays.length === 0 || row.credentials.relays.some((relay) => relay.state !== "installed"))) {
      throw new EnrollmentError(`${source}: host deregistration claims ready without relay installation evidence`);
    }
    if (row.infrastructure.state === "destroyed" && row.credentials.state !== "ready_for_infrastructure_destroy") {
      throw new EnrollmentError(`${source}: host deregistration destroyed infrastructure before credentials were ready`);
    }
    const policyAdvanced = row.policy.state !== "waiting_for_infrastructure_destroy";
    if (policyAdvanced && row.infrastructure.state !== "destroyed") {
      throw new EnrollmentError(`${source}: host deregistration advanced policy before infrastructure destruction`);
    }
    if (row.infrastructure.state === "destroyed" && row.policy.state === "waiting_for_infrastructure_destroy") {
      throw new EnrollmentError(`${source}: destroyed infrastructure did not queue policy removal`);
    }
    if (row.status !== hostDeregistrationStatus(row)) {
      throw new EnrollmentError(`${source}: host deregistration top-level status is inconsistent`);
    }
    if (row.policy.state === "completed" && (row.credentials.state !== "ready_for_infrastructure_destroy"
      || row.infrastructure.state !== "destroyed" || !row.policy.completedAt || !row.policy.completedBy
      || !row.policy.pullRequestUrl || !row.policy.commitSha || !row.policy.publishedGeneration
      || row.policy.relays.length === 0)) {
      throw new EnrollmentError(`${source}: completed host deregistration lacks policy publication evidence`);
    }
  }
  for (const tombstone of tombstones) {
    const operations = deregistrations.filter((row) => row.hostname === tombstone.hostname
      && row.hostLifecycleId === tombstone.hostLifecycleId && row.externalOperationId === tombstone.externalOperationId);
    if (operations.length !== 1) throw new EnrollmentError(`${source}: lifecycle tombstone has no unique operation`);
  }
  return {
    schemaVersion: ENROLLMENT_SCHEMA,
    tokens,
    requests,
    audit: d.audit as EnrollmentAuditEvent[],
    revocations,
    appTokens: (d.appTokens as AppTokenRecord[] | undefined) ?? [],
    hostLifecycleBindings: bindings,
    hostLifecycleTombstones: tombstones,
    hostDeregistrations: deregistrations,
  };
}

function parsedStoredLifecycle(value: unknown, source: string, what: string): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || normalizeHostLifecycleId(value) !== value) {
    throw new EnrollmentError(`${source}: ${what} hostLifecycleId is invalid`);
  }
  return value;
}

function exactObject(value: unknown, fields: readonly string[], what: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).some((key) => !fields.includes(key))
    || fields.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) {
    throw new EnrollmentError(`${what} has an invalid shape`);
  }
}
function exactObjectOptional(
  value: unknown, required: readonly string[], optional: readonly string[], what: string,
): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))
    || required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) {
    throw new EnrollmentError(`${what} has an invalid shape`);
  }
}
export const emptyEnrollmentDocument = (): EnrollmentDocument => ({
  schemaVersion: 1, tokens: [], requests: [], audit: [], revocations: [], appTokens: [],
  hostLifecycleBindings: [], hostLifecycleTombstones: [], hostDeregistrations: [],
});
function readEnrollmentDocument(path: string): EnrollmentDocument {
  const full = resolve(path);
  try { return parse(JSON.parse(readFileSync(full, "utf8")), full); }
  catch (e) {
    if (e instanceof EnrollmentError) throw e;
    const x = e as NodeJS.ErrnoException;
    if (x.code === "ENOENT") {
      throw new EnrollmentError(`${full}: enrollment store is unavailable`, 503);
    }
    throw new EnrollmentError(`${full}: ${x.message}`);
  }
}
export function loadEnrollmentDocument(path: string): EnrollmentDocument {
  return readEnrollmentDocument(path);
}
export function requireEnrollmentDocument(path: string): EnrollmentDocument {
  return readEnrollmentDocument(path);
}
export function saveEnrollmentDocument(path: string, document: EnrollmentDocument): EnrollmentDocument {
  const full = resolve(path); const valid = parse(document, full); mkdirSync(dirname(full), { recursive: true, mode: 0o700 });
  const tmp = `${full}.tmp-${process.pid}-${randomHex(4)}`;
  try {
    writeFileSync(tmp, JSON.stringify(valid, null, 2) + "\n", { mode: 0o600, flag: "wx" });
    chmodSync(tmp, 0o600);
    const fd = openSync(tmp, "r");
    try { fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, full);
    const directory = openSync(dirname(full), "r");
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } catch (error) {
    try { unlinkSync(tmp); } catch { /* the rename may already have installed it */ }
    throw error;
  }
  return valid;
}

function discardOwnedPath(path: string, fd: number): void {
  try {
    const owned = fstatSync(fd);
    const current = lstatSync(path);
    if (owned.dev === current.dev && owned.ino === current.ino) unlinkSync(path);
  } catch {
    // If creation failed before the pathname was installed, or another process already removed it,
    // there is no owned lock left to clean up.
  } finally {
    closeSync(fd);
  }
}

/** Explicit one-time provisioning. Runtime transactions never create a missing durable store. */
export function initializeEnrollmentDocument(path: string): EnrollmentDocument {
  const full = resolve(path);
  const document = emptyEnrollmentDocument();
  mkdirSync(dirname(full), { recursive: true, mode: 0o700 });
  let fd: number;
  try {
    fd = openSync(full, "wx", 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new EnrollmentError(`refusing to overwrite existing enrollment store: ${full}`);
    }
    throw new EnrollmentError(`${full}: cannot initialize enrollment store`);
  }
  try {
    writeFileSync(fd, JSON.stringify(document, null, 2) + "\n", "utf8");
    chmodSync(full, 0o600);
    fsyncSync(fd);
  } catch {
    discardOwnedPath(full, fd);
    throw new EnrollmentError(`${full}: cannot initialize enrollment store`);
  }
  closeSync(fd);
  const directory = openSync(dirname(full), "r");
  try { fsyncSync(directory); } finally { closeSync(directory); }
  return document;
}

/**
 * Cross-process transaction for the file-backed enrollment store.
 *
 * Atomic rename protects readers from partial JSON, but it does not protect two writers that both
 * loaded the same old document. The adjacent `O_EXCL` lock covers load → mutate → save as one unit.
 * An existing owner always makes the caller wait and then fail closed. Automatically unlinking a
 * supposedly stale pathname has no compare-and-delete primitive in portable Node: two reclaimers
 * can otherwise delete a newly acquired lock and reintroduce lost updates. After a confirmed crash,
 * an operator must stop every writer and explicitly remove the adjacent `.lock` file.
 */
export function withEnrollmentTransaction<T>(
  path: string,
  mutate: (document: EnrollmentDocument) => T,
  options: { waitMs?: number } = {},
): T {
  const full = resolve(path);
  const lockPath = `${full}.lock`;
  mkdirSync(dirname(full), { recursive: true, mode: 0o700 });
  const owner = JSON.stringify({ pid: process.pid, nonce: randomHex(16), createdAt: Date.now() });
  const waitMs = options.waitMs ?? ENROLLMENT_LOCK_WAIT_MS;
  if (!Number.isSafeInteger(waitMs) || waitMs < 0 || waitMs > ENROLLMENT_LOCK_WAIT_MS) {
    throw new EnrollmentError("enrollment lock waitMs is invalid");
  }
  const deadline = Date.now() + waitMs;
  let fd: number | null = null;

  while (fd === null) {
    let opened: number;
    try {
      opened = openSync(lockPath, "wx", 0o600);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") throw new EnrollmentError(`${full}: cannot lock enrollment store`);
      if (Date.now() >= deadline) throw new EnrollmentError(`${full}: enrollment store is busy`, 503);
      Atomics.wait(LOCK_SLEEP, 0, 0, 20);
      continue;
    }

    try {
      writeFileSync(opened, owner, "utf8");
      fd = opened;
    } catch {
      // `open("wx")` has already made the pathname visible. If writing the owner record fails,
      // release both the descriptor and that exact inode so restart cannot inherit a poison lock.
      discardOwnedPath(lockPath, opened);
      throw new EnrollmentError(`${full}: cannot initialize enrollment store lock`);
    }
  }

  try {
    const document = requireEnrollmentDocument(full);
    const result = mutate(document);
    saveEnrollmentDocument(full, document);
    return result;
  } finally {
    closeSync(fd);
    try {
      if (readFileSync(lockPath, "utf8") === owner) unlinkSync(lockPath);
    } catch {
      // A missing lock cannot make a committed mutation unsafe. A mismatched lock belongs to a
      // later owner and must never be removed here.
    }
  }
}
function audit(document: EnrollmentDocument, event: Omit<EnrollmentAuditEvent, "at">, now?: Date): void {
  document.audit.push({ at: nowIso(now), ...event });
}
/**
 * `appTokenId` is optional and additive: an operator issuing a token by hand does not have one.
 *
 * It exists because `createdBy` is text an operator reads, and **a label is not an identifier** —
 * two live app tokens may carry the same one, deliberately, so that a rotation has no gap. Writing
 * only the label into the audit row would mean the trail cannot say *which* credential minted a node
 * token, which is exactly the question asked when one of them turns out to be leaked. So the id goes
 * into `detail.appTokenId`, structured, next to a `createdBy` that carries both.
 */
export function createNodeToken(document: EnrollmentDocument, input: { hostname: string; hostLifecycleId?: string; label?: string; createdBy?: string; appTokenId?: string; revokeExisting?: boolean; ttlSec?: number; now?: Date }) {
  const host = hostname(input.hostname); const issuedAt = input.now ?? new Date(); const at = nowIso(issuedAt);
  const hostLifecycleId = input.hostLifecycleId === undefined ? null : normalizeHostLifecycleId(input.hostLifecycleId);
  assertLifecycleMayProvision(document, host, hostLifecycleId);
  if (input.revokeExisting !== undefined && typeof input.revokeExisting !== "boolean") {
    throw new EnrollmentError("revokeExisting must be a boolean");
  }
  const ttlSec = input.ttlSec ?? DEFAULT_NODE_TOKEN_TTL_SEC;
  if (!Number.isSafeInteger(ttlSec) || ttlSec < MIN_NODE_TOKEN_TTL_SEC || ttlSec > MAX_NODE_TOKEN_TTL_SEC) {
    throw new EnrollmentError(`node token ttlSec must be ${MIN_NODE_TOKEN_TTL_SEC}-${MAX_NODE_TOKEN_TTL_SEC}`);
  }
  if (input.revokeExisting ?? true) for (const token of document.tokens) if (token.hostname === host && !token.revokedAt) token.revokedAt = at;
  const token = `${NODE_TOKEN_PREFIX}${randomHex(32)}`;
  const row: NodeTokenRecord = { id: randomHex(8), hostname: host, tokenHash: sha256(token), label: input.label?.trim().slice(0, 120) || null,
    createdBy: input.createdBy?.trim().slice(0, MAX_CREATED_BY_CHARS) || null, hostLifecycleId, createdAt: at,
    expiresAt: new Date(issuedAt.getTime() + ttlSec * 1_000).toISOString(), lastUsedAt: null, revokedAt: null };
  document.tokens.push(row);
  audit(document, {
    actor: row.createdBy ?? "operator", action: "node-token.create", target: row.id, sourceIp: null,
    detail: { hostname: host, ...(hostLifecycleId === null ? {} : { hostLifecycleId }), ...(input.appTokenId === undefined ? {} : { appTokenId: input.appTokenId }) },
  }, input.now);
  return { document, token, row };
}
export function revokeNodeToken(document: EnrollmentDocument, id: string, actor = "operator", now = new Date()): NodeTokenRecord {
  const row = document.tokens.find((token) => token.id === id); if (!row) throw new EnrollmentError(`node token ${id} not found`, 404);
  if (!row.revokedAt) row.revokedAt = nowIso(now); audit(document, { actor, action: "node-token.revoke", target: id, sourceIp: null, detail: { hostname: row.hostname } }, now); return row;
}
/**
 * Is this shaped like a node token at all? **Not authentication** — `lookupNodeToken` still hashes
 * and compares inside the transaction, exactly as before.
 *
 * ## Why the prefix alone was not worth the name it was given
 *
 * `POST /infra/node-csrs` and `GET /infra/node-csrs/<id>/certificate` run before operator
 * authentication — a bootstrapping agent has no certificate yet — and the manager listens with
 * `rejectUnauthorized: false`, so anyone who completes a handshake reaches them. The gate in front
 * of the expensive work was `token.startsWith(NODE_TOKEN_PREFIX)`, described as leaving only "a
 * caller holding a well-formed but wrong token, and that one is worth a read".
 *
 * `NODE_TOKEN_PREFIX` is `"stnode_"`, a public constant in this file. So "well-formed" meant seven
 * fixed characters, and the remaining set was *everyone*: each such request costs a synchronous
 * `readFileSync` + `JSON.parse` of the whole enrollment store on the event loop, and the
 * certificate route additionally takes the `O_EXCL` lock.
 *
 * `createNodeToken` emits `prefix + randomHex(32)`, which is exactly 64 hex characters. Checking
 * that costs nothing and removes every caller who is not at least guessing in the right space.
 */
export function looksLikeNodeToken(plaintext: string): boolean {
  return NODE_TOKEN_RE.test(plaintext);
}

const NODE_TOKEN_RE = new RegExp(`^${NODE_TOKEN_PREFIX}[0-9a-f]{64}$`);

export function lookupNodeToken(document: EnrollmentDocument, plaintext: string, now = new Date()): NodeTokenRecord | null {
  if (!looksLikeNodeToken(plaintext)) return null; const digest = sha256(plaintext);
  const row = document.tokens.find((token) => token.tokenHash === digest && !token.revokedAt && Date.parse(token.expiresAt) > now.getTime()) ?? null;
  if (row) row.lastUsedAt = nowIso(now); return row;
}

/**
 * The hostname normaliser, exported so a caller can tell "not a hostname" from "not yours".
 *
 * Without it the app-token route would have to run an unvalidated string through
 * `appTokenAllowsHostname`, and a caller who typed nonsense would be told their token is not
 * authorised for it — advice pointing at the wrong thing, which `refuseWrite` already records as
 * costing more than a vague refusal. 400 for a malformed hostname, 403 for a real one outside the
 * pattern.
 */
export const normalizeEnrollmentHostname = (value: string): string => hostname(value);

/**
 * Does this app token's pattern cover this hostname? Pure, and deliberately narrow.
 *
 * A pattern is either an exact hostname or a leading `*.` — and the `*` stands for **exactly one
 * label**. `*.dev` covers `k3s-01.dev`; it does not cover `dev`, and it does not cover `a.b.dev`.
 * The second exclusion is the one worth stating: a suffix match would make `*.dev` cover
 * `k3s-01.attacker.dev`, and the token holder chooses the hostname it asks for.
 */
export function appTokenAllowsHostname(pattern: string, candidate: string): boolean {
  const p = pattern.trim().toLowerCase();
  const h = candidate.trim().toLowerCase();
  if (!p || !h) return false;
  if (!p.startsWith("*.")) return p === h;
  const dot = h.indexOf(".");
  // `dot > 0` rejects both "no label boundary at all" (`dev`) and an empty first label (`.dev`).
  return dot > 0 && h.slice(dot + 1) === p.slice(2);
}

function appTokenHostnamePattern(value: string): string {
  const out = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (!out) throw new EnrollmentError("app token hostnamePattern is required");
  const rest = out.startsWith("*.") ? out.slice(2) : out;
  // A `*` anywhere but the first label is refused rather than interpreted. `**.dev`, `*`, `a.*.dev`
  // and `*.*` all land here: every one of them is a caller believing in a matcher this does not
  // implement, and guessing what they meant is how a pattern ends up wider than it reads.
  if (rest.includes("*") || !HOSTNAME.test(rest)) {
    throw new EnrollmentError(
      `invalid app token hostnamePattern: ${JSON.stringify(value)} — use an exact hostname or one ` +
        `leading wildcard label such as "*.dev"`,
    );
  }
  return out.startsWith("*.") ? `*.${rest}` : rest;
}

export function createAppToken(document: EnrollmentDocument, input: {
  label: string; scopes: readonly string[]; hostnamePattern: string; createdBy?: string; ttlSec?: number; now?: Date;
}) {
  const issuedAt = input.now ?? new Date(); const at = nowIso(issuedAt);
  const label = typeof input.label === "string" ? input.label.trim() : "";
  // Not truncated to 120 like a node token's label, refused. A node token's label is a note; this one
  // is what every refusal message and audit row names the caller by, and a silently shortened name
  // is a name two tokens can share.
  if (!label || label.length > 120) throw new EnrollmentError("app token label must be 1-120 characters after trimming");
  if (!Array.isArray(input.scopes) || input.scopes.length === 0) {
    throw new EnrollmentError(`app token scopes must name at least one of: ${APP_TOKEN_SCOPES.join(", ")}`);
  }
  const scopes: AppTokenScope[] = [];
  for (const scope of input.scopes) {
    if (typeof scope !== "string" || !(APP_TOKEN_SCOPES as readonly string[]).includes(scope)) {
      throw new EnrollmentError(`unknown app token scope: ${JSON.stringify(scope)}`);
    }
    if (!scopes.includes(scope as AppTokenScope)) scopes.push(scope as AppTokenScope);
  }
  const hostnamePattern = appTokenHostnamePattern(input.hostnamePattern);
  const ttlSec = input.ttlSec ?? DEFAULT_APP_TOKEN_TTL_SEC;
  if (!Number.isSafeInteger(ttlSec) || ttlSec < MIN_APP_TOKEN_TTL_SEC || ttlSec > MAX_APP_TOKEN_TTL_SEC) {
    throw new EnrollmentError(`app token ttlSec must be ${MIN_APP_TOKEN_TTL_SEC}-${MAX_APP_TOKEN_TTL_SEC}`);
  }
  const token = `${APP_TOKEN_PREFIX}${randomHex(32)}`;
  const row: AppTokenRecord = {
    id: randomHex(8), label, tokenHash: sha256(token), scopes, hostnamePattern,
    createdBy: input.createdBy?.trim().slice(0, MAX_CREATED_BY_CHARS) || null, createdAt: at,
    expiresAt: new Date(issuedAt.getTime() + ttlSec * 1_000).toISOString(), lastUsedAt: null, revokedAt: null,
  };
  // A label is not an identifier and two live tokens may share one. Refusing a duplicate would make
  // rotation — issue the replacement, hand it over, revoke the old one — impossible without a gap.
  document.appTokens.push(row);
  audit(document, {
    actor: row.createdBy ?? "operator", action: "app-token.create", target: row.id, sourceIp: null,
    detail: { label, scopes: scopes.join(","), hostnamePattern },
  }, input.now);
  return { document, token, row };
}

export function revokeAppToken(document: EnrollmentDocument, id: string, actor = "operator", now = new Date()): AppTokenRecord {
  const row = document.appTokens.find((appToken) => appToken.id === id);
  if (!row) throw new EnrollmentError(`app token ${id} not found`, 404);
  if (!row.revokedAt) row.revokedAt = nowIso(now);
  audit(document, { actor, action: "app-token.revoke", target: id, sourceIp: null, detail: { label: row.label } }, now);
  return row;
}

/** The shape gate, for the same reason `looksLikeNodeToken` is one — see its comment. */
export function looksLikeAppToken(plaintext: string): boolean {
  return APP_TOKEN_RE.test(plaintext);
}

const APP_TOKEN_RE = new RegExp(`^${APP_TOKEN_PREFIX}[0-9a-f]{64}$`);

export function lookupAppToken(document: EnrollmentDocument, plaintext: string, now = new Date()): AppTokenRecord | null {
  if (!looksLikeAppToken(plaintext)) return null;
  const digest = sha256(plaintext);
  const row = document.appTokens.find(
    (appToken) => appToken.tokenHash === digest && !appToken.revokedAt && Date.parse(appToken.expiresAt) > now.getTime(),
  ) ?? null;
  if (row) row.lastUsedAt = nowIso(now);
  return row;
}

function normalizeCsrPem(csrPem: string): string {
  if (Buffer.byteLength(csrPem) === 0 || Buffer.byteLength(csrPem) > 16 * 1024 || !CSR_PEM.test(csrPem)) {
    throw new EnrollmentError("expected exactly one PEM CERTIFICATE REQUEST block (max 16 KiB)");
  }
  return csrPem.replace(/\r\n/g, "\n");
}

export function validateNodeCsr(csrPem: string, expectedHostname: string): ValidatedNodeCsr {
  const host = hostname(expectedHostname); const pem = normalizeCsrPem(csrPem);
  openssl(["req", "-verify", "-noout"], pem); const der = openssl(["req", "-outform", "DER"], pem);
  const subject = openssl(["req", "-noout", "-subject", "-nameopt", "RFC2253"], pem).toString().trim();
  if (subject !== `subject=CN=${host}`) throw new EnrollmentError(`CSR subject must be exactly CN=${host}`);
  const publicPem = openssl(["req", "-pubkey", "-noout"], pem);
  const publicKey = createPublicKey(publicPem);
  if (publicKey.asymmetricKeyType !== "ec" || publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new EnrollmentError("CSR public key must be ECDSA P-256");
  const text = openssl(["req", "-noout", "-text"], pem).toString();
  const attributes = text.split("Attributes:")[1]?.split("Requested Extensions:")[0]?.trim();
  const requested = text.split("Requested Extensions:")[1]?.split("Signature Algorithm:")[0]?.trim();
  if (attributes !== "(none)" || requested) throw new EnrollmentError("CSR attributes and requested extensions are not allowed");
  const publicDer = openssl(["pkey", "-pubin", "-outform", "DER"], publicPem);
  return { hostname: host, pem, csrSha256: sha256(der), publicKeySha256: sha256(publicDer), keyAlgorithm: "ECDSA-P256" };
}

let activeCsrValidationWorkers = 0;
interface CsrValidationWaiter {
  deadline: number;
  timer: ReturnType<typeof setTimeout>;
  grant: () => void;
  reject: (error: Error) => void;
}
const csrValidationWaiters: CsrValidationWaiter[] = [];

async function claimCsrValidationWorker(timeoutMs: number): Promise<number> {
  const deadline = Date.now() + timeoutMs;
  if (activeCsrValidationWorkers < MAX_CSR_VALIDATION_WORKERS) {
    activeCsrValidationWorkers += 1;
    return deadline;
  }
  if (csrValidationWaiters.length >= MAX_QUEUED_CSR_VALIDATIONS) {
    throw new EnrollmentError("CSR validation capacity is exhausted", 503);
  }
  return await new Promise<number>((resolve, reject) => {
    const waiter = {} as CsrValidationWaiter;
    waiter.deadline = deadline;
    waiter.reject = reject;
    waiter.grant = () => {
      clearTimeout(waiter.timer);
      resolve(deadline);
    };
    waiter.timer = setTimeout(() => {
      const index = csrValidationWaiters.indexOf(waiter);
      if (index < 0) return;
      csrValidationWaiters.splice(index, 1);
      reject(new EnrollmentError("CSR validation timed out", 503));
    }, timeoutMs);
    csrValidationWaiters.push(waiter);
  });
}

function releaseCsrValidationWorker(): void {
  const next = csrValidationWaiters.shift();
  if (next) {
    // The occupied slot is handed directly to this waiter. Decrementing first would briefly expose
    // a free slot: a new request could claim it before the waiter's promise continuation increments
    // the counter, allowing more than MAX_CSR_VALIDATION_WORKERS to run.
    next.grant();
  } else {
    activeCsrValidationWorkers -= 1;
  }
}

/** Run synchronous OpenSSL parsing in a bounded worker so an enrollment request cannot block HTTP. */
export async function validateNodeCsrAsync(
  csrPem: string,
  expectedHostname: string,
  options: { timeoutMs?: number } = {},
): Promise<ValidatedNodeCsr> {
  const host = hostname(expectedHostname); const pem = normalizeCsrPem(csrPem);
  const timeoutMs = options.timeoutMs ?? CSR_WORKER_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > CSR_WORKER_TIMEOUT_MS) {
    throw new EnrollmentError(`CSR validation timeout must be between 1 and ${CSR_WORKER_TIMEOUT_MS} ms`);
  }
  const deadline = await claimCsrValidationWorker(timeoutMs);
  try {
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) throw new EnrollmentError("CSR validation timed out", 503);
    return await new Promise<ValidatedNodeCsr>((resolveWorker, rejectWorker) => {
      const worker = new Worker(new URL(import.meta.url), {
        workerData: { heliopauseCsrValidation: true, csrPem: pem, expectedHostname: host },
      });
      let settled = false;
      const finish = (error: Error | null, result?: ValidatedNodeCsr) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        // Do not hand the capacity slot to another request until this worker has actually stopped.
        // Otherwise a timed-out OpenSSL process and its replacement can overlap above the bound.
        void worker.terminate().then(
          () => error ? rejectWorker(error) : resolveWorker(result!),
          () => error ? rejectWorker(error) : rejectWorker(new EnrollmentError("CSR validation worker failed", 503)),
        );
      };
      const timer = setTimeout(
        () => finish(new EnrollmentError("CSR validation timed out", 503)),
        remainingMs,
      );
      worker.once("message", (message: { ok?: unknown; result?: unknown }) => {
        if (message?.ok === true) finish(null, message.result as ValidatedNodeCsr);
        else finish(new EnrollmentError("OpenSSL rejected the certificate request"));
      });
      worker.once("error", () => finish(new EnrollmentError("CSR validation worker failed", 503)));
      worker.once("exit", (code) => {
        if (!settled) finish(new EnrollmentError(`CSR validation worker exited before replying (${code})`, 503));
      });
    });
  } finally {
    releaseCsrValidationWorker();
  }
}

export function preflightNodeCsr(
  document: EnrollmentDocument,
  input: { csrPem: string; token: string; now?: Date },
): NodeCsrPreflight {
  const token = lookupNodeToken(document, input.token, input.now);
  if (!token) throw new EnrollmentError("unauthorized node token", 401);
  assertLifecycleMayProvision(document, token.hostname, token.hostLifecycleId);
  const pem = normalizeCsrPem(input.csrPem);
  const existing = document.requests.find((row) => row.hostname === token.hostname && row.csrPem === pem) ?? null;
  if (!existing) {
    const unresolved = document.requests.filter(
      (row) => row.hostname === token.hostname && (row.status === "pending" || row.status === "conflict"),
    );
    if (unresolved.length >= MAX_PENDING_CSRS_PER_HOST) {
      throw new EnrollmentError("too many unresolved CSRs for hostname", 429);
    }
  }
  return { hostname: token.hostname, pem, existing };
}

export function touchExistingNodeCsr(
  document: EnrollmentDocument,
  input: { csrPem: string; token: string; now?: Date },
) {
  const preflight = preflightNodeCsr(document, input);
  if (!preflight.existing) throw new EnrollmentError("CSR changed during preflight", 409);
  return { document, row: preflight.existing, created: false as const };
}

export function submitValidatedNodeCsr(
  document: EnrollmentDocument,
  input: { csr: ValidatedNodeCsr; token: string; sourceIp?: string | null; now?: Date },
) {
  const token = lookupNodeToken(document, input.token, input.now);
  if (!token) throw new EnrollmentError("unauthorized node token", 401);
  assertLifecycleMayProvision(document, token.hostname, token.hostLifecycleId);
  const csr = input.csr;
  if (csr.hostname !== token.hostname || csr.pem !== normalizeCsrPem(csr.pem)) {
    throw new EnrollmentError("validated CSR does not match the node token", 409);
  }
  const same = document.requests.find((row) => row.hostname === csr.hostname && row.csrSha256 === csr.csrSha256);
  if (same) return { document, row: same, created: false };
  const unresolved = document.requests.filter((row) => row.hostname === csr.hostname && (row.status === "pending" || row.status === "conflict"));
  if (unresolved.length >= MAX_PENDING_CSRS_PER_HOST) throw new EnrollmentError("too many unresolved CSRs for hostname", 429);
  const status: CsrStatus = unresolved.length ? "conflict" : "pending";
  const row: NodeCsrRecord = { id: randomHex(16), hostname: csr.hostname, nodeTokenId: token.id, hostLifecycleId: token.hostLifecycleId,
    status, csrPem: csr.pem, csrSha256: csr.csrSha256,
    publicKeySha256: csr.publicKeySha256, keyAlgorithm: csr.keyAlgorithm, createdAt: nowIso(input.now), sourceIp: input.sourceIp ?? null,
    decidedAt: null, decidedBy: null, decisionReason: null, signedAt: null, caName: null, certificatePem: null, caPem: null,
    certificateSha256: null, certificateNotBefore: null, certificateNotAfter: null, retrievedAt: null };
  document.requests.push(row); audit(document, { actor: `node-token:${token.id}`, action: "node-csr.submit", target: row.id, sourceIp: row.sourceIp,
    detail: { hostname: row.hostname, status, csrSha256: row.csrSha256, publicKeySha256: row.publicKeySha256 } }, input.now); return { document, row, created: true };
}

export function submitNodeCsr(document: EnrollmentDocument, input: { csrPem: string; token: string; sourceIp?: string | null; now?: Date }) {
  const preflight = preflightNodeCsr(document, input);
  if (preflight.existing) return { document, row: preflight.existing, created: false };
  return submitValidatedNodeCsr(document, {
    csr: validateNodeCsr(preflight.pem, preflight.hostname), token: input.token,
    sourceIp: input.sourceIp, now: input.now,
  });
}
export function rejectNodeCsr(document: EnrollmentDocument, id: string, actor: string, reason: string, now = new Date()): NodeCsrRecord {
  const row = document.requests.find((request) => request.id === id); if (!row || !["pending", "conflict"].includes(row.status)) throw new EnrollmentError("CSR not found or already decided", 404);
  if (!reason.trim()) throw new EnrollmentError("rejection reason is required"); row.status = "rejected"; row.decidedAt = nowIso(now); row.decidedBy = actor; row.decisionReason = reason.trim().slice(0, 500);
  audit(document, { actor, action: "node-csr.reject", target: id, sourceIp: null, detail: { hostname: row.hostname, reason: row.decisionReason } }, now); return row;
}

export function validateNodeCertificate(certificatePem: string, caPem: string, request: NodeCsrRecord, now = new Date()) {
  if (!CERT_PEM.test(certificatePem) || !CERT_PEM.test(caPem)) throw new EnrollmentError("certificate and CA must each contain exactly one PEM certificate");
  const leaf = new X509Certificate(certificatePem); const ca = new X509Certificate(caPem);
  if (leaf.subject !== `CN=${request.hostname}`) throw new EnrollmentError(`certificate subject must be exactly CN=${request.hostname}`);
  const leafPub = openssl(["x509", "-pubkey", "-noout"], certificatePem); const leafPubDer = openssl(["pkey", "-pubin", "-outform", "DER"], leafPub);
  if (sha256(leafPubDer) !== request.publicKeySha256) throw new EnrollmentError("certificate public key does not match the CSR");
  if (!ca.ca || !ca.verify(ca.publicKey)) throw new EnrollmentError("selected CA is not a self-signed CA certificate");
  if (!leaf.verify(ca.publicKey) || leaf.issuer !== ca.subject) throw new EnrollmentError("certificate is not signed by the selected CA");
  const text = openssl(["x509", "-noout", "-text"], certificatePem).toString();
  if (!/X509v3 Basic Constraints: critical\s*\n\s*CA:FALSE/.test(text) || !/X509v3 Key Usage: critical\s*\n\s*Digital Signature/.test(text) || !/X509v3 Extended Key Usage: critical\s*\n\s*TLS Web Client Authentication/.test(text) || /X509v3 Subject Alternative Name/.test(text)) throw new EnrollmentError("certificate does not match the fixed agent clientAuth profile");
  const notBefore = new Date(leaf.validFrom); const notAfter = new Date(leaf.validTo); if (notBefore > now || notAfter <= now) throw new EnrollmentError("certificate is not currently valid");
  if (notAfter.getTime() - notBefore.getTime() > 90 * 86_400_000 + 5 * 60_000) throw new EnrollmentError("certificate validity exceeds 90 days");
  return { certificatePem: leaf.toString(), caPem: ca.toString(), certificateSha256: leaf.fingerprint256.replaceAll(":", "").toLowerCase(), notBefore: notBefore.toISOString(), notAfter: notAfter.toISOString() };
}

type VerifiedStoredCertificate = ReturnType<typeof validateNodeCertificate> & { certificate: X509Certificate };

/** Validate stored certificate truth independently of its mutable cached metadata. */
function verifyStoredCertificate(request: NodeCsrRecord, trustedCaPems: readonly string[]): VerifiedStoredCertificate {
  if (!request.certificatePem) throw new EnrollmentError(`signed CSR request ${request.id} lacks certificate PEM inventory`, 409);
  let certificate: X509Certificate;
  try { certificate = new X509Certificate(request.certificatePem); }
  catch { throw new EnrollmentError(`signed CSR request ${request.id} has invalid certificate PEM inventory`, 409); }
  const validFrom = Date.parse(certificate.validFrom);
  const validTo = Date.parse(certificate.validTo);
  const historicalNow = new Date(Math.max(validFrom, validTo - 1));
  for (const caPem of trustedCaPems) {
    try {
      return { ...validateNodeCertificate(certificate.toString(), caPem, request, historicalNow), certificate };
    } catch { /* try the next configured trust anchor */ }
  }
  throw new EnrollmentError(`signed CSR request ${request.id} certificate is not valid under a configured trusted CA`, 409);
}

function storedCertificateMetadataMatches(request: NodeCsrRecord, verified: VerifiedStoredCertificate): boolean {
  return request.certificateSha256 === verified.certificateSha256
    && request.certificateNotBefore === verified.notBefore
    && request.certificateNotAfter === verified.notAfter;
}
export function storeNodeCertificate(document: EnrollmentDocument, input: { requestId: string; certificatePem: string; caPem: string; caName: string; actor: string; now?: Date }): NodeCsrRecord {
  const row = document.requests.find((request) => request.id === input.requestId); if (!row || !["pending", "conflict"].includes(row.status)) throw new EnrollmentError("CSR not found or already decided", 404);
  assertLifecycleMayProvision(document, row.hostname, row.hostLifecycleId);
  const rivals = document.requests.filter((request) => request.hostname === row.hostname && request.id !== row.id && ["pending", "conflict"].includes(request.status));
  if (rivals.length) throw new EnrollmentError("unresolved CSR conflict for hostname", 409);
  const cert = validateNodeCertificate(input.certificatePem, input.caPem, row, input.now); row.status = "signed"; row.decidedAt = nowIso(input.now); row.decidedBy = input.actor; row.signedAt = row.decidedAt;
  row.caName = input.caName; row.certificatePem = cert.certificatePem; row.caPem = cert.caPem; row.certificateSha256 = cert.certificateSha256; row.certificateNotBefore = cert.notBefore; row.certificateNotAfter = cert.notAfter;
  audit(document, { actor: input.actor, action: "node-cert.upload", target: row.id, sourceIp: null, detail: { hostname: row.hostname, caName: input.caName, certificateSha256: cert.certificateSha256 } }, input.now); return row;
}
export function fetchNodeCertificate(document: EnrollmentDocument, requestId: string, plaintextToken: string, sourceIp?: string | null, now = new Date()) {
  const token = lookupNodeToken(document, plaintextToken, now); if (!token) throw new EnrollmentError("unauthorized node token", 401);
  assertLifecycleMayProvision(document, token.hostname, token.hostLifecycleId);
  const row = document.requests.find((request) => request.id === requestId && request.nodeTokenId === token.id && request.status === "signed");
  if (!row?.certificatePem || !row.caPem || !row.certificateSha256) {
    // ## Why this can be "not ready" for a certificate that is sitting right there
    //
    // The match is on `nodeTokenId`, so a request submitted under an *earlier* token for the same
    // host is invisible to a later one — and `createNodeToken` revokes the host's existing tokens by
    // default. Reissue a token between "agent submits CSR" and "operator signs it" and the agent can
    // never collect its own certificate: it polls, gets 404, and the message says the certificate is
    // not ready when the truth is that it was asked for by somebody the store no longer recognises.
    //
    // The binding itself is kept. Loosening it to the hostname would let any live token for a host
    // collect a certificate requested by a different key, which is a wider grant than this route
    // should have. So the fix here is the sentence, not the query — an operator who reissued a token
    // needs to be told that is what happened.
    const forThisHost = document.requests.find(
      (request) => request.id === requestId && request.hostname === token.hostname && request.status === "signed",
    );
    if (forThisHost) {
      throw new EnrollmentError(
        "this certificate was requested under a different node token for the same host — the token " +
          "was reissued after the CSR was submitted. Submit a new CSR with the current token.",
        409,
      );
    }
    throw new EnrollmentError("certificate not ready", 404);
  }
  if (!row.retrievedAt) {
    row.retrievedAt = nowIso(now);
    // Polling is expected during bootstrap. Record the first successful retrieval, not one
    // unbounded audit row per retry with the same token and request id.
    audit(document, { actor: `node-token:${token.id}`, action: "node-cert.fetch", target: row.id, sourceIp: sourceIp ?? null, detail: { hostname: row.hostname, certificateSha256: row.certificateSha256 } }, now);
  }
  return { certificatePem: row.certificatePem, caPem: row.caPem, certificateSha256: row.certificateSha256 };
}

export function revokeCertificate(document: EnrollmentDocument, input: { certificatePem: string; reason: string; actor: string; now?: Date }): CertificateRevocation {
  if (!input.reason.trim()) throw new EnrollmentError("revocation reason is required");
  let cert: X509Certificate; try { cert = new X509Certificate(input.certificatePem); } catch { throw new EnrollmentError("certificate is not valid X.509 PEM"); }
  const fingerprint256 = cert.fingerprint256.replaceAll(":", "").toLowerCase();
  const existing = document.revocations.find((row) => row.fingerprint256 === fingerprint256); if (existing) return existing;
  const row: CertificateRevocation = { fingerprint256, subject: cert.subject || null, reason: input.reason.trim().slice(0, 500), actor: input.actor, revokedAt: nowIso(input.now) };
  document.revocations.push(row); audit(document, { actor: input.actor, action: "certificate.revoke", target: fingerprint256, sourceIp: null, detail: { subject: row.subject, reason: row.reason } }, input.now); return row;
}

export type LegacyLifecycleInventoryEvidence = {
  stardustCreateOperationId: string;
  provider: "vultr";
  providerInstanceId: string;
  nodeTokenIds: string[];
  csrRequestIds: string[];
  certificateFingerprints: string[];
};

function exactEvidenceIds(values: readonly string[], field: string): string[] {
  if (!Array.isArray(values) || values.some((value) => typeof value !== "string" || !value.trim() || value.length > 200)) {
    throw new EnrollmentError(`${field} must contain non-empty strings up to 200 characters`);
  }
  const out = [...values].sort();
  if (new Set(out).size !== out.length) throw new EnrollmentError(`${field} must not contain duplicates`);
  return out;
}

/**
 * Bind legacy-null enrollment rows only when an operator supplies the exact local inventory and the
 * immutable Stardust create operation that owns it. Nothing selects rows by hostname alone: every
 * token and CSR id is named, cross-checked, and bound in the same transaction.
 */
export function bindLegacyHostLifecycle(document: EnrollmentDocument, input: {
  hostname: string; hostLifecycleId: string; evidence: LegacyLifecycleInventoryEvidence;
  trustedCaPems: readonly string[]; actor: string; now?: Date;
}): { hostname: string; hostLifecycleId: string; tokensBound: number; requestsBound: number; evidenceSha256: string } {
  const host = hostname(input.hostname);
  const lifecycle = normalizeHostLifecycleId(input.hostLifecycleId);
  const actor = input.actor.trim();
  if (!actor || actor.length > 200) throw new EnrollmentError("actor must be 1-200 characters");
  const createOperationId = normalizeHostLifecycleId(input.evidence.stardustCreateOperationId);
  if (createOperationId !== lifecycle) throw new EnrollmentError("Stardust create operation does not match hostLifecycleId", 409);
  if (input.evidence.provider !== "vultr") throw new EnrollmentError('provider must be exactly "vultr"');
  const providerInstanceId = boundedExternalId(input.evidence.providerInstanceId, "providerInstanceId");
  const nodeTokenIds = exactEvidenceIds(input.evidence.nodeTokenIds, "nodeTokenIds");
  const csrRequestIds = exactEvidenceIds(input.evidence.csrRequestIds, "csrRequestIds");
  const certificateFingerprints = exactEvidenceIds(input.evidence.certificateFingerprints, "certificateFingerprints");
  if (nodeTokenIds.length === 0 && csrRequestIds.length === 0) {
    throw new EnrollmentError("explicit token or CSR inventory evidence is required; hostname-only binding is refused");
  }
  if (certificateFingerprints.some((value) => !SHA256.test(value))) {
    throw new EnrollmentError("certificateFingerprints must be lowercase SHA-256 fingerprints");
  }
  if (document.hostLifecycleTombstones.some((row) => row.hostname === host && row.hostLifecycleId === lifecycle)
    || document.hostLifecycleBindings.some((row) => row.hostname === host || row.hostLifecycleId === lifecycle)
    || document.tokens.some((row) => row.hostname === host && row.hostLifecycleId === lifecycle)
    || document.requests.some((row) => row.hostname === host && row.hostLifecycleId === lifecycle)) {
    throw new EnrollmentError("host lifecycle is already bound; rebinding is refused", 409);
  }

  // "Exact inventory" means the complete legacy-null inventory for this host, not merely that every
  // submitted id exists. Otherwise an operator could omit an unreferenced live token, bind the rest,
  // and the later deregistration would truthfully close every lifecycle-bound credential while the
  // omitted legacy credential remained usable.
  const legacyTokenIds = document.tokens
    .filter((row) => row.hostname === host && row.hostLifecycleId === null)
    .map((row) => row.id).sort();
  const legacyRequestIds = document.requests
    .filter((row) => row.hostname === host && row.hostLifecycleId === null)
    .map((row) => row.id).sort();
  if (JSON.stringify(nodeTokenIds) !== JSON.stringify(legacyTokenIds)
    || JSON.stringify(csrRequestIds) !== JSON.stringify(legacyRequestIds)) {
    throw new EnrollmentError(
      "nodeTokenIds and csrRequestIds must exactly match the complete legacy inventory for this host",
      409,
    );
  }

  const tokens = nodeTokenIds.map((id) => {
    const row = document.tokens.find((candidate) => candidate.id === id);
    if (!row || row.hostname !== host) throw new EnrollmentError(`node token ${id} is not in the exact host inventory`, 409);
    if (row.hostLifecycleId !== null) throw new EnrollmentError(`node token ${id} is already lifecycle-bound`, 409);
    return row;
  });
  const requests = csrRequestIds.map((id) => {
    const row = document.requests.find((candidate) => candidate.id === id);
    if (!row || row.hostname !== host) throw new EnrollmentError(`CSR request ${id} is not in the exact host inventory`, 409);
    if (row.hostLifecycleId !== null) throw new EnrollmentError(`CSR request ${id} is already lifecycle-bound`, 409);
    if (document.tokens.some((token) => token.id === row.nodeTokenId) && !nodeTokenIds.includes(row.nodeTokenId)) {
      throw new EnrollmentError(`CSR request ${id} references node token ${row.nodeTokenId}, which is absent from the evidence`, 409);
    }
    return row;
  });
  const observedFingerprints = requests
    .filter((row) => row.status === "signed")
    .map((row) => {
      const verified = verifyStoredCertificate(row, input.trustedCaPems);
      if (!storedCertificateMetadataMatches(row, verified)) {
        throw new EnrollmentError(`signed CSR request ${row.id} certificate metadata conflicts with its trusted PEM`, 409);
      }
      return verified.certificateSha256;
    }).sort();
  if (JSON.stringify(observedFingerprints) !== JSON.stringify(certificateFingerprints)) {
    throw new EnrollmentError("certificateFingerprints do not exactly match the selected signed CSR inventory", 409);
  }
  const evidence = {
    stardustCreateOperationId: createOperationId, provider: input.evidence.provider, providerInstanceId,
    nodeTokenIds, csrRequestIds, certificateFingerprints,
  };
  const evidenceSha256 = sha256(JSON.stringify(evidence));
  audit(document, {
    actor, action: "host-lifecycle.bind-before", target: lifecycle, sourceIp: null,
    detail: { hostname: host, provider: "vultr", providerInstanceId, tokens: tokens.length,
      requests: requests.length, certificates: certificateFingerprints.length, evidenceSha256 },
  }, input.now);
  for (const row of tokens) row.hostLifecycleId = lifecycle;
  for (const row of requests) row.hostLifecycleId = lifecycle;
  document.hostLifecycleBindings.push({
    hostname: host, hostLifecycleId: lifecycle, provider: "vultr", providerInstanceId,
    evidenceSha256, boundAt: nowIso(input.now), boundBy: actor,
  });
  audit(document, {
    actor, action: "host-lifecycle.bind-after", target: lifecycle, sourceIp: null,
    detail: { hostname: host, provider: "vultr", providerInstanceId, tokens: tokens.length,
      requests: requests.length, certificates: certificateFingerprints.length, evidenceSha256 },
  }, input.now);
  return { hostname: host, hostLifecycleId: lifecycle, tokensBound: tokens.length,
    requestsBound: requests.length, evidenceSha256 };
}

export type HostDeregistrationRequest = {
  hostname: string; externalOperationId: string; hostLifecycleId: string;
  reason: "instance-destroy"; requestedBy: string; actor: string; relayNames: readonly string[];
  scope: { appTokenId: string; label: string; hostnamePattern: string };
  trustedCaPems: readonly string[]; now?: Date;
};

function normalizedRelayNames(names: readonly string[]): string[] {
  const out = [...new Set(names.map((name) => name.trim()).filter(Boolean))].sort();
  if (out.length !== names.length || out.some((name) => name.length > 120)) {
    throw new EnrollmentError("configured relay names must be unique non-empty strings up to 120 characters", 503);
  }
  return out;
}

export function reconcileHostDeregistrationRelays(
  row: HostDeregistrationRecord, relayNames: readonly string[], now = new Date(),
): HostDeregistrationRecord {
  if (row.infrastructure.state === "destroyed") return row;
  const at = nowIso(now);
  const existing = new Map(row.credentials.relays.map((relay) => [relay.name, relay]));
  row.credentials.relays = normalizedRelayNames(relayNames).map((name) => existing.get(name) ?? ({
    name, state: "pending", updatedAt: null, error: null,
  }));
  if (row.credentials.state !== "blocked") {
    row.credentials.state = row.credentials.relays.length > 0
      && row.credentials.relays.every((relay) => relay.state === "installed")
      ? "ready_for_infrastructure_destroy"
      : "replicating";
  }
  row.status = hostDeregistrationStatus(row);
  row.updatedAt = at;
  return row;
}

export function beginHostDeregistration(
  document: EnrollmentDocument, input: HostDeregistrationRequest,
): { row: HostDeregistrationRecord; created: boolean } {
  const host = hostname(input.hostname);
  const externalOperationId = normalizeExternalOperationId(input.externalOperationId);
  const hostLifecycleId = normalizeHostLifecycleId(input.hostLifecycleId);
  if (input.reason !== "instance-destroy") throw new EnrollmentError('reason must be exactly "instance-destroy"');
  const requestedBy = input.requestedBy.trim();
  if (!requestedBy || requestedBy.length > 200) throw new EnrollmentError("requestedBy must be 1-200 characters");
  const existing = document.hostDeregistrations.find((row) =>
    row.hostname === host && row.externalOperationId === externalOperationId);
  if (existing) {
    if (existing.hostLifecycleId !== hostLifecycleId || existing.reason !== input.reason || existing.requestedBy !== requestedBy) {
      throw new EnrollmentError("host deregistration idempotency key was reused with a different request", 409);
    }
    if (existing.blocked?.code === "no_relays_configured" && input.relayNames.length > 0) {
      existing.blocked = null;
      existing.credentials.state = "replicating";
      existing.status = "credentials_pending";
    }
    return {
      row: existing.status === "completed" ? existing : reconcileHostDeregistrationRelays(existing, input.relayNames, input.now),
      created: false,
    };
  }
  const known = document.tokens.some((row) => row.hostname === host && row.hostLifecycleId === hostLifecycleId)
    || document.requests.some((row) => row.hostname === host && row.hostLifecycleId === hostLifecycleId);
  if (!known) throw new EnrollmentError("host lifecycle not found", 404);
  const sameLifecycle = document.hostDeregistrations.find((row) =>
    row.hostname === host && row.hostLifecycleId === hostLifecycleId);
  if (sameLifecycle) throw new EnrollmentError("host lifecycle already belongs to another deregistration operation", 409);
  const competing = document.hostDeregistrations.find((row) =>
    row.hostname === host && row.hostLifecycleId !== hostLifecycleId && row.policy.state !== "completed");
  if (competing) throw new EnrollmentError("hostname already has an unfinished deregistration", 409);

  const at = nowIso(input.now);
  const lifecycleBinding = document.hostLifecycleBindings.find((binding) =>
    binding.hostname === host && binding.hostLifecycleId === hostLifecycleId);
  const expectedProviderInstanceId = lifecycleBinding?.providerInstanceId ?? null;
  const row: HostDeregistrationRecord = {
    id: randomHex(16), status: "credentials_pending", hostname: host, externalOperationId, hostLifecycleId,
    reason: input.reason, requestedBy, scope: { ...input.scope },
    createdAt: at, updatedAt: at,
    credentials: {
      state: "accepted", tombstone: "persisted", tokens: { revoked: 0, alreadyRevoked: 0 },
      requests: { closed: 0, alreadyClosed: 0 }, certificates: { revoked: 0, alreadyRevoked: 0, expired: 0 },
      requiredRevocationFingerprints: [],
      relays: normalizedRelayNames(input.relayNames).map((name) => ({
        name, state: "pending", updatedAt: null, error: null,
      })),
    },
    infrastructure: {
      state: "waiting", provider: null, providerInstanceId: null,
      expectedProviderInstanceId,
      destroyedAt: null,
    },
    policy: {
      state: "waiting_for_infrastructure_destroy", queuedAt: null, completedAt: null, completedBy: null,
      pullRequestUrl: null, commitSha: null, publishedGeneration: null, relays: [],
      automation: {
        branch: null, pullRequestNumber: null, patchCommitSha: null, mergeCommitSha: null,
        affectedRelays: [], plans: [], lastAttemptAt: null, lastError: null,
      },
    },
    blocked: null,
  };
  document.hostLifecycleTombstones.push({ hostname: host, hostLifecycleId, externalOperationId, createdAt: at });
  document.hostDeregistrations.push(row);
  row.credentials.state = "closing";

  for (const token of document.tokens) {
    if (token.hostname !== host || token.hostLifecycleId !== hostLifecycleId) continue;
    if (!token.revokedAt) { token.revokedAt = at; row.credentials.tokens.revoked += 1; }
    else row.credentials.tokens.alreadyRevoked += 1;
  }
  const certificatesToRevoke = new Map<string, string>();
  for (const request of document.requests) {
    if (request.hostname !== host || request.hostLifecycleId !== hostLifecycleId) continue;
    if (request.status === "pending" || request.status === "conflict") {
      request.status = "host-deregistered"; request.decidedAt = at; request.decidedBy = input.actor;
      request.decisionReason = "host-deregistered";
      row.credentials.requests.closed += 1;
    } else {
      row.credentials.requests.alreadyClosed += 1;
    }
    if (request.status === "signed") {
      let verified: VerifiedStoredCertificate;
      try {
        verified = verifyStoredCertificate(request, input.trustedCaPems);
      } catch {
        row.credentials.state = "blocked";
        row.blocked = {
          code: "certificate_inventory_incomplete",
          operatorAction: `attach a trusted certificate PEM for request ${request.id}`,
        };
        continue;
      }
      if (!storedCertificateMetadataMatches(request, verified)) {
        row.credentials.state = "blocked";
        row.blocked = {
          code: "certificate_inventory_incomplete",
          operatorAction: `repair certificate metadata from trusted PEM for request ${request.id}`,
        };
      }
      if (Date.parse(verified.notAfter) <= Date.parse(at)) row.credentials.certificates.expired += 1;
      else certificatesToRevoke.set(verified.certificateSha256, verified.certificatePem);
    }
  }
  let revocationCapacityAvailable = true;
  {
    const newRevocations: CertificateRevocation[] = [];
    for (const [fingerprint, certificatePem] of certificatesToRevoke) {
      const cert = new X509Certificate(certificatePem);
      if (document.revocations.some((revocation) => revocation.fingerprint256 === fingerprint)) {
        row.credentials.certificates.alreadyRevoked += 1;
      } else {
        newRevocations.push({
          fingerprint256: fingerprint, subject: cert.subject || null,
          reason: `host lifecycle deregistration ${externalOperationId}`, actor: input.actor, revokedAt: at,
        });
      }
      row.credentials.requiredRevocationFingerprints.push(fingerprint);
    }
    row.credentials.requiredRevocationFingerprints.sort();
    const prospective = [...document.revocations, ...newRevocations];
    try {
      if (prospective.length > MAX_REVOCATION_ROWS) throw new Error("row limit reached");
      serializeRevocationSnapshot({ schemaVersion: 1, revocations: prospective });
    } catch {
      revocationCapacityAvailable = false;
      row.credentials.state = "blocked";
      row.blocked = {
        code: "revocation_capacity_exhausted",
        operatorAction: "compact expired revocations and have an operator repair this blocked operation",
      };
    }
  }
  if (revocationCapacityAvailable) {
    for (const certificatePem of certificatesToRevoke.values()) {
      const before = document.revocations.length;
      revokeCertificate(document, {
        certificatePem,
        reason: `host lifecycle deregistration ${externalOperationId}`,
        actor: input.actor,
        now: input.now,
      });
      if (document.revocations.length > before) row.credentials.certificates.revoked += 1;
    }
  }
  if (row.credentials.state !== "blocked") {
    row.credentials.state = "replicating";
    if (row.credentials.relays.length === 0) {
      row.credentials.state = "blocked";
      row.blocked = {
        code: "no_relays_configured", operatorAction: "configure at least one relay and retry replication",
      };
    }
  }
  row.status = hostDeregistrationStatus(row);
  audit(document, {
    actor: input.actor, action: "host-deregistration.accept", target: externalOperationId, sourceIp: null,
    detail: {
      hostname: host, hostLifecycleId, requestedBy, appTokenId: input.scope.appTokenId,
      hostnamePattern: input.scope.hostnamePattern, credentialsState: row.credentials.state,
      revokedNodeTokens: row.credentials.tokens.revoked, closedRequests: row.credentials.requests.closed,
      revokedCertificates: row.credentials.certificates.revoked,
    },
  }, input.now);
  return { row, created: true };
}

function hostDeregistrationStatus(row: HostDeregistrationRecord): HostDeregistrationRecord["status"] {
  if (row.blocked || row.credentials.state === "blocked" || row.policy.state === "blocked") return "blocked";
  if (row.policy.state === "completed") return "completed";
  if (row.infrastructure.state === "destroyed") return "policy_pending";
  if (row.credentials.state === "ready_for_infrastructure_destroy") return "ready_for_infrastructure_destroy";
  return "credentials_pending";
}

function deregistrationForRepair(document: EnrollmentDocument, input: {
  hostname: string; externalOperationId: string; hostLifecycleId: string;
}): HostDeregistrationRecord {
  const host = hostname(input.hostname);
  const operationId = normalizeExternalOperationId(input.externalOperationId);
  const lifecycle = normalizeHostLifecycleId(input.hostLifecycleId);
  const row = document.hostDeregistrations.find((candidate) =>
    candidate.hostname === host && candidate.externalOperationId === operationId);
  if (!row || row.hostLifecycleId !== lifecycle) throw new EnrollmentError("host deregistration not found", 404);
  return row;
}

function requireRepairableDeregistration(row: HostDeregistrationRecord, blockedCode: string): void {
  if (row.blocked?.code !== blockedCode || row.credentials.state !== "blocked") {
    throw new EnrollmentError(`operation is not blocked by ${blockedCode}`, 409);
  }
}

function candidateCertificates(document: EnrollmentDocument, row: HostDeregistrationRecord, now: Date,
  trustedCaPems: readonly string[]): Array<{
  request: NodeCsrRecord; certificate: X509Certificate; fingerprint: string;
}> {
  const out: Array<{ request: NodeCsrRecord; certificate: X509Certificate; fingerprint: string }> = [];
  for (const request of document.requests) {
    if (request.hostname !== row.hostname || request.hostLifecycleId !== row.hostLifecycleId || request.status !== "signed") continue;
    const verified = verifyStoredCertificate(request, trustedCaPems);
    if (!storedCertificateMetadataMatches(request, verified)) {
      throw new EnrollmentError(`certificate inventory metadata conflicts for request ${request.id}`, 409);
    }
    if (Date.parse(verified.notAfter) <= now.getTime()) continue;
    out.push({ request, certificate: verified.certificate, fingerprint: verified.certificateSha256 });
  }
  return out;
}

function installDeregistrationRevocations(
  document: EnrollmentDocument, row: HostDeregistrationRecord,
  certificates: Array<{ request: NodeCsrRecord; certificate: X509Certificate; fingerprint: string }>,
  actor: string, now: Date,
): boolean {
  const newCertificates = certificates.filter(({ fingerprint }) =>
    !document.revocations.some((revocation) => revocation.fingerprint256 === fingerprint));
  try {
    if (document.revocations.length + newCertificates.length > MAX_REVOCATION_ROWS) throw new Error("row limit reached");
    serializeRevocationSnapshot({
      schemaVersion: 1,
      revocations: [...document.revocations, ...newCertificates.map(({ certificate, fingerprint }) => ({
        fingerprint256: fingerprint, subject: certificate.subject || null,
        reason: `host lifecycle deregistration ${row.externalOperationId}`, actor, revokedAt: nowIso(now),
      }))],
    });
  } catch {
    row.credentials.state = "blocked";
    row.blocked = {
      code: "revocation_capacity_exhausted",
      operatorAction: "compact expired revocations on every relay, then repair this same operation",
    };
    row.status = hostDeregistrationStatus(row); row.updatedAt = nowIso(now);
    return false;
  }
  const required = new Set(row.credentials.requiredRevocationFingerprints);
  for (const { request, certificate, fingerprint } of certificates) {
    request.certificateSha256 ??= fingerprint;
    request.certificateNotBefore ??= new Date(certificate.validFrom).toISOString();
    request.certificateNotAfter ??= new Date(certificate.validTo).toISOString();
    required.add(fingerprint);
    const before = document.revocations.length;
    revokeCertificate(document, {
      certificatePem: request.certificatePem!, reason: `host lifecycle deregistration ${row.externalOperationId}`,
      actor, now,
    });
    if (document.revocations.length > before) row.credentials.certificates.revoked += 1;
  }
  row.credentials.requiredRevocationFingerprints = [...required].sort();
  row.blocked = null;
  row.credentials.state = row.credentials.relays.length === 0 ? "blocked" : "replicating";
  if (row.credentials.relays.length === 0) {
    row.blocked = { code: "no_relays_configured", operatorAction: "configure at least one relay and retry replication" };
  }
  row.status = hostDeregistrationStatus(row); row.updatedAt = nowIso(now);
  return true;
}

export function repairHostDeregistrationCertificateInventory(document: EnrollmentDocument, input: {
  hostname: string; externalOperationId: string; hostLifecycleId: string;
  certificates: Array<{ requestId: string; certificatePem: string }>; trustedCaPems: readonly string[];
  actor: string; now?: Date;
}): HostDeregistrationRecord {
  const row = deregistrationForRepair(document, input);
  if (!Array.isArray(input.certificates) || input.certificates.length === 0) {
    throw new EnrollmentError("certificates must explicitly repair every incomplete request");
  }
  const ids = exactEvidenceIds(input.certificates.map((entry) => entry.requestId), "certificates.requestId");
  if (ids.length !== input.certificates.length) throw new EnrollmentError("certificates.requestId must not contain duplicates");
  const now = input.now ?? new Date();
  const presented = input.certificates.map((entry) => {
    const request = document.requests.find((candidate) => candidate.id === entry.requestId);
    if (!request || request.hostname !== row.hostname || request.hostLifecycleId !== row.hostLifecycleId
      || request.status !== "signed") {
      throw new EnrollmentError(`CSR request ${entry.requestId} is not in the exact signed lifecycle inventory`, 409);
    }
    let certificate: X509Certificate;
    try { certificate = new X509Certificate(entry.certificatePem); }
    catch { throw new EnrollmentError(`certificatePem for request ${entry.requestId} is not valid X.509 PEM`); }
    return {
      request, certificate, fingerprint: certificate.fingerprint256.replaceAll(":", "").toLowerCase(),
      pem: certificate.toString(),
    };
  });
  const evidenceSha256 = sha256(JSON.stringify(presented.map(({ request, fingerprint }) =>
    ({ requestId: request.id, fingerprint })).sort((a, b) => a.requestId.localeCompare(b.requestId))));
  const completedRepair = document.audit.find((event) => event.action === "host-deregistration.certificate-repair-after"
    && event.target === row.externalOperationId && event.detail.hostname === row.hostname
    && event.detail.hostLifecycleId === row.hostLifecycleId);
  if (completedRepair) {
    if (completedRepair.detail.evidenceSha256 === evidenceSha256) return row;
    throw new EnrollmentError("certificate repair replay conflicts with the committed repair evidence", 409);
  }
  requireRepairableDeregistration(row, "certificate_inventory_incomplete");
  const incomplete = document.requests.filter((request) => {
    if (request.hostname !== row.hostname || request.hostLifecycleId !== row.hostLifecycleId || request.status !== "signed") return false;
    try { return !storedCertificateMetadataMatches(request, verifyStoredCertificate(request, input.trustedCaPems)); }
    catch { return true; }
  }).map((request) => request.id).sort();
  if (JSON.stringify(ids) !== JSON.stringify(incomplete)) {
    throw new EnrollmentError("certificates must exactly match every incomplete request in this lifecycle", 409);
  }
  const repaired = presented.map(({ request, certificate, fingerprint, pem }) => {
    if (certificate.subject !== `CN=${row.hostname}`) {
      throw new EnrollmentError(`certificate subject for request ${request.id} must be exactly CN=${row.hostname}`, 409);
    }
    const historicalNow = new Date(Math.max(Date.parse(certificate.validFrom), Date.parse(certificate.validTo) - 1));
    let validated: ReturnType<typeof validateNodeCertificate> | null = null;
    for (const caPem of input.trustedCaPems) {
      try { validated = validateNodeCertificate(certificate.toString(), caPem, request, historicalNow); break; }
      catch { /* try the next configured trust anchor */ }
    }
    if (!validated) throw new EnrollmentError(`certificate for request ${request.id} is not valid under a configured trusted CA`, 409);
    const certificatePublicKey = openssl(["x509", "-pubkey", "-noout"], certificate.toString());
    const certificatePublicKeyDer = openssl(["pkey", "-pubin", "-outform", "DER"], certificatePublicKey);
    if (sha256(certificatePublicKeyDer) !== request.publicKeySha256) {
      throw new EnrollmentError(`certificate public key conflicts with CSR request ${request.id}`, 409);
    }
    return { request, certificate, fingerprint, pem, validated };
  });
  audit(document, {
    actor: input.actor, action: "host-deregistration.certificate-repair-before", target: row.externalOperationId,
    sourceIp: null, detail: { hostname: row.hostname, hostLifecycleId: row.hostLifecycleId,
      certificates: repaired.length, evidenceSha256 },
  }, now);
  for (const item of repaired) {
    item.request.certificatePem = item.pem;
    item.request.certificateSha256 = item.validated.certificateSha256;
    item.request.certificateNotBefore = item.validated.notBefore;
    item.request.certificateNotAfter = item.validated.notAfter;
  }
  const resumed = installDeregistrationRevocations(document, row,
    candidateCertificates(document, row, now, input.trustedCaPems), input.actor, now);
  audit(document, {
    actor: input.actor, action: "host-deregistration.certificate-repair-after", target: row.externalOperationId,
    sourceIp: null, detail: { hostname: row.hostname, hostLifecycleId: row.hostLifecycleId,
      certificates: repaired.length, evidenceSha256, resumed, credentialsState: row.credentials.state },
  }, now);
  return row;
}

export function repairHostDeregistrationRevocationCapacity(document: EnrollmentDocument, input: {
  hostname: string; externalOperationId: string; hostLifecycleId: string;
  relayConfirmations: Array<{ name: string; compactedAt: string; retainedFingerprintSha256: string }>;
  relayNames: readonly string[]; actor: string; now?: Date;
  trustedCaPems: readonly string[];
}): HostDeregistrationRecord {
  const row = deregistrationForRepair(document, input);
  const now = input.now ?? new Date();
  const expectedRelays = normalizedRelayNames(input.relayNames);
  if (!Array.isArray(input.relayConfirmations)) throw new EnrollmentError("relayConfirmations must be an array");
  const confirmations = input.relayConfirmations.map((confirmation) => ({
    name: confirmation.name.trim(),
    compactedAt: normalizePastEvidenceTimestamp(confirmation.compactedAt, "relayConfirmations.compactedAt", now),
    retainedFingerprintSha256: confirmation.retainedFingerprintSha256,
  })).sort((a, b) => a.name.localeCompare(b.name));
  if (confirmations.length !== expectedRelays.length || confirmations.some((confirmation, index) =>
    confirmation.name !== expectedRelays[index] || !SHA256.test(confirmation.retainedFingerprintSha256))) {
    throw new EnrollmentError("relayConfirmations must name every configured relay with a snapshot fingerprint", 409);
  }
  const confirmationEvidenceSha256 = sha256(JSON.stringify(confirmations));
  const completedRepair = document.audit.find((event) => event.action === "host-deregistration.capacity-repair-after"
    && event.target === row.externalOperationId && event.detail.hostname === row.hostname
    && event.detail.hostLifecycleId === row.hostLifecycleId);
  if (completedRepair) {
    if (completedRepair.detail.confirmationEvidenceSha256 === confirmationEvidenceSha256) return row;
    throw new EnrollmentError("revocation capacity repair replay conflicts with the committed relay evidence", 409);
  }
  requireRepairableDeregistration(row, "revocation_capacity_exhausted");
  const expiry = new Map<string, string>();
  for (const request of document.requests) {
    if (request.status !== "signed") continue;
    try {
      const verified = verifyStoredCertificate(request, input.trustedCaPems);
      if (!storedCertificateMetadataMatches(request, verified)) continue;
      expiry.set(verified.certificateSha256, verified.notAfter);
    } catch { /* unverifiable inventory is never compaction proof */ }
  }
  const plan = planRevocationCompaction({ schemaVersion: 1, revocations: document.revocations }, expiry, now);
  if (plan.drop.length === 0) throw new EnrollmentError("no expired revocations are safely compactable", 409);
  const retainedFingerprintSha256 = sha256(JSON.stringify(plan.keep.map((entry) => entry.fingerprint256).sort()));
  if (confirmations.some((confirmation) => confirmation.retainedFingerprintSha256 !== retainedFingerprintSha256)) {
    throw new EnrollmentError("relayConfirmations must attest the exact compacted snapshot on every configured relay", 409);
  }
  audit(document, {
    actor: input.actor, action: "host-deregistration.capacity-repair-before", target: row.externalOperationId,
    sourceIp: null, detail: { hostname: row.hostname, hostLifecycleId: row.hostLifecycleId,
      dropped: plan.drop.length, retained: plan.keep.length, relays: confirmations.length,
      retainedFingerprintSha256, confirmationEvidenceSha256 },
  }, now);
  document.revocations = plan.keep;
  const resumed = installDeregistrationRevocations(document, row,
    candidateCertificates(document, row, now, input.trustedCaPems), input.actor, now);
  if (!resumed) throw new EnrollmentError("compaction did not create enough revocation capacity", 409);
  audit(document, {
    actor: input.actor, action: "host-deregistration.capacity-repair-after", target: row.externalOperationId,
    sourceIp: null, detail: { hostname: row.hostname, hostLifecycleId: row.hostLifecycleId,
      dropped: plan.drop.length, retained: plan.keep.length, relays: confirmations.length,
      retainedFingerprintSha256, confirmationEvidenceSha256, credentialsState: row.credentials.state },
  }, now);
  return row;
}

export type RevocationReplicationResult =
  { name: string; ok: true; count: number; snapshotFingerprints: readonly string[] }
  | { name: string; ok: false; error: string; snapshotFingerprints: readonly string[] };

export function recordHostDeregistrationReplication(
  document: EnrollmentDocument, results: readonly RevocationReplicationResult[], relayNames: readonly string[], now = new Date(),
): HostDeregistrationRecord[] {
  const at = nowIso(now);
  const resultByName = new Map(results.map((result) => [result.name, result]));
  const changed: HostDeregistrationRecord[] = [];
  for (const row of document.hostDeregistrations) {
    if (row.credentials.state === "blocked" || row.infrastructure.state === "destroyed") continue;
    reconcileHostDeregistrationRelays(row, relayNames, now);
    for (const relay of row.credentials.relays) {
      const result = resultByName.get(relay.name);
      if (!result) continue;
      relay.updatedAt = at;
      const snapshot = new Set(result.snapshotFingerprints);
      const coversOperation = row.credentials.requiredRevocationFingerprints.every((fingerprint) => snapshot.has(fingerprint));
      if (result.ok && coversOperation) { relay.state = "installed"; relay.error = null; }
      else if (result.ok) { /* an older in-flight snapshot cannot prove this operation installed */ }
      else if (relay.state !== "installed") { relay.state = "failed"; relay.error = result.error.slice(0, 500); }
    }
    row.credentials.state = row.credentials.relays.length > 0
      && row.credentials.relays.every((relay) => relay.state === "installed")
      ? "ready_for_infrastructure_destroy"
      : "replicating";
    row.status = hostDeregistrationStatus(row);
    row.updatedAt = at;
    changed.push(row);
  }
  return changed;
}

export function confirmHostInfrastructureDestroyed(document: EnrollmentDocument, input: {
  hostname: string; externalOperationId: string; hostLifecycleId: string; provider: "vultr";
  providerInstanceId: string; destroyedAt: string; actor: string; now?: Date;
}): HostDeregistrationRecord {
  const host = hostname(input.hostname);
  const operationId = normalizeExternalOperationId(input.externalOperationId);
  const lifecycle = normalizeHostLifecycleId(input.hostLifecycleId);
  const row = document.hostDeregistrations.find((candidate) =>
    candidate.hostname === host && candidate.externalOperationId === operationId);
  if (!row || row.hostLifecycleId !== lifecycle) throw new EnrollmentError("host deregistration not found", 404);
  if (input.provider !== "vultr") throw new EnrollmentError('provider must be exactly "vultr"');
  const providerInstanceId = boundedExternalId(input.providerInstanceId, "providerInstanceId");
  if (row.infrastructure.expectedProviderInstanceId !== null
    && row.infrastructure.expectedProviderInstanceId !== providerInstanceId) {
    throw new EnrollmentError("providerInstanceId conflicts with the lifecycle binding inventory", 409);
  }
  const now = input.now ?? new Date();
  const destroyedAt = normalizePastEvidenceTimestamp(input.destroyedAt, "destroyedAt", now);
  if (row.infrastructure.state === "destroyed") {
    if (row.infrastructure.provider !== input.provider || row.infrastructure.providerInstanceId !== providerInstanceId
      || row.infrastructure.destroyedAt !== destroyedAt) {
      throw new EnrollmentError("infrastructure confirmation conflicts with the stored confirmation", 409);
    }
    return row;
  }
  if (row.credentials.state !== "ready_for_infrastructure_destroy") {
    throw new EnrollmentError(`credentials are ${row.credentials.state}; infrastructure destroy is not allowed`, 409);
  }
  const at = nowIso(now);
  row.infrastructure = {
    state: "destroyed", provider: input.provider, providerInstanceId,
    expectedProviderInstanceId: row.infrastructure.expectedProviderInstanceId, destroyedAt,
  };
  row.policy.state = "queued"; row.policy.queuedAt = at; row.updatedAt = at;
  row.status = hostDeregistrationStatus(row);
  audit(document, {
    actor: input.actor, action: "host-deregistration.infrastructure-destroyed", target: operationId, sourceIp: null,
    detail: { hostname: host, hostLifecycleId: lifecycle, provider: input.provider, providerInstanceId, destroyedAt },
  }, now);
  return row;
}

export type HostDeregistrationPolicyAutomation = NonNullable<HostDeregistrationRecord["policy"]["automation"]>;

export function emptyHostDeregistrationPolicyAutomation(): HostDeregistrationPolicyAutomation {
  return {
    branch: null, pullRequestNumber: null, patchCommitSha: null, mergeCommitSha: null,
    affectedRelays: [], reviewedBy: [], planGeneration: null, planProposedAt: null,
    plans: [], lastAttemptAt: null, lastError: null,
  };
}

/**
 * Durable compare-and-set for one worker step.
 *
 * The network call that produced `automation` must already be over. This function only acquires the
 * enrollment lock, verifies that another worker or break-glass operator did not move the operation,
 * and records the evidence. A stale result is discarded rather than applied to a newer state.
 */
export function recordHostDeregistrationPolicyWorkerStep(document: EnrollmentDocument, input: {
  hostname: string; externalOperationId: string; hostLifecycleId: string;
  expectedState: HostDeregistrationRecord["policy"]["state"];
  expectedPolicy: HostDeregistrationRecord["policy"];
  nextState: HostDeregistrationRecord["policy"]["state"];
  automation: HostDeregistrationPolicyAutomation;
  pullRequestUrl?: string | null; commitSha?: string | null; publishedGeneration?: string | null;
  relayConfirmations?: Array<{ name: string; absentAt: string }>;
  actor: string; now?: Date;
}): { row: HostDeregistrationRecord; applied: boolean } {
  const host = hostname(input.hostname);
  const operationId = normalizeExternalOperationId(input.externalOperationId);
  const lifecycle = normalizeHostLifecycleId(input.hostLifecycleId);
  const row = document.hostDeregistrations.find((candidate) =>
    candidate.hostname === host && candidate.externalOperationId === operationId);
  if (!row || row.hostLifecycleId !== lifecycle) throw new EnrollmentError("host deregistration not found", 404);
  if (row.policy.state !== input.expectedState
    || JSON.stringify(row.policy) !== JSON.stringify(input.expectedPolicy)) return { row, applied: false };
  const allowed: Record<string, readonly string[]> = {
    queued: ["queued", "pr_open"],
    pr_open: ["pr_open", "merged"],
    merged: ["merged", "awaiting_publish"],
    awaiting_publish: ["merged", "awaiting_publish", "published"],
    published: ["merged", "published", "completed"],
  };
  if (!(allowed[input.expectedState] ?? []).includes(input.nextState)) {
    throw new EnrollmentError(`invalid policy worker transition ${input.expectedState} -> ${input.nextState}`);
  }
  const now = input.now ?? new Date();
  const at = nowIso(now);
  row.policy.state = input.nextState;
  row.policy.automation = structuredClone(input.automation);
  if (input.pullRequestUrl !== undefined) row.policy.pullRequestUrl = input.pullRequestUrl;
  if (input.commitSha !== undefined) row.policy.commitSha = input.commitSha;
  if (input.publishedGeneration !== undefined) row.policy.publishedGeneration = input.publishedGeneration;
  if (input.relayConfirmations !== undefined) row.policy.relays = input.relayConfirmations.map((relay) => ({ ...relay }));
  if (input.nextState === "completed") {
    row.policy.completedAt = at;
    row.policy.completedBy = input.actor;
  }
  row.updatedAt = at;
  row.status = hostDeregistrationStatus(row);
  audit(document, {
    actor: input.actor,
    action: `host-deregistration.policy-worker.${input.nextState}`,
    target: operationId,
    sourceIp: null,
    detail: {
      hostname: host, hostLifecycleId: lifecycle,
      from: input.expectedState, to: input.nextState,
      ...(input.automation.pullRequestNumber === null ? {} : { pullRequestNumber: input.automation.pullRequestNumber }),
      plans: input.automation.plans.length,
    },
  }, now);
  return { row, applied: true };
}

export function completeHostDeregistrationPolicy(document: EnrollmentDocument, input: {
  hostname: string; externalOperationId: string; hostLifecycleId: string; pullRequestUrl: string;
  commitSha: string; publishedGeneration: string; relayConfirmations: Array<{ name: string; absentAt: string }>;
  relayNames: readonly string[]; actor: string; now?: Date;
}): HostDeregistrationRecord {
  const host = hostname(input.hostname);
  const operationId = normalizeExternalOperationId(input.externalOperationId);
  const lifecycle = normalizeHostLifecycleId(input.hostLifecycleId);
  const row = document.hostDeregistrations.find((candidate) =>
    candidate.hostname === host && candidate.externalOperationId === operationId);
  if (!row || row.hostLifecycleId !== lifecycle) throw new EnrollmentError("host deregistration not found", 404);
  const pullRequestUrl = input.pullRequestUrl.trim();
  if (!/^https:\/\//.test(pullRequestUrl) || pullRequestUrl.length > 500) throw new EnrollmentError("pullRequestUrl must be an HTTPS URL");
  const commitSha = input.commitSha.trim().toLowerCase();
  if (!/^[0-9a-f]{40,64}$/.test(commitSha)) throw new EnrollmentError("commitSha must be a full hexadecimal commit id");
  const publishedGeneration = boundedExternalId(input.publishedGeneration, "publishedGeneration");
  const expectedRelays = normalizedRelayNames(input.relayNames);
  const now = input.now ?? new Date();
  const confirmations = input.relayConfirmations.map((confirmation) => ({
    name: confirmation.name,
    absentAt: normalizePastEvidenceTimestamp(confirmation.absentAt, "relayConfirmations.absentAt", now),
  })).sort((a, b) => a.name.localeCompare(b.name));
  if (confirmations.length !== expectedRelays.length || confirmations.some((confirmation, index) =>
    confirmation.name !== expectedRelays[index])) {
    throw new EnrollmentError("relayConfirmations must prove hostname absence on every configured relay", 409);
  }
  if (row.policy.state === "completed") {
    if (row.policy.pullRequestUrl !== pullRequestUrl || row.policy.commitSha !== commitSha
      || row.policy.publishedGeneration !== publishedGeneration
      || JSON.stringify(row.policy.relays) !== JSON.stringify(confirmations)) {
      throw new EnrollmentError("policy completion conflicts with the stored completion", 409);
    }
    return row;
  }
  if (!["queued", "pr_open", "merged", "awaiting_publish", "published"].includes(row.policy.state)
    || row.infrastructure.state !== "destroyed") {
    throw new EnrollmentError("policy removal is not pending after infrastructure destruction", 409);
  }
  const at = nowIso(now);
  row.policy = {
    state: "completed", queuedAt: row.policy.queuedAt, completedAt: at, completedBy: input.actor,
    pullRequestUrl, commitSha, publishedGeneration, relays: confirmations,
    ...(row.policy.automation ? { automation: row.policy.automation } : {}),
  };
  row.updatedAt = at; row.status = hostDeregistrationStatus(row);
  audit(document, {
    actor: input.actor, action: "host-deregistration.policy-completed", target: operationId, sourceIp: null,
    detail: { hostname: host, hostLifecycleId: lifecycle, pullRequestUrl, commitSha, publishedGeneration, relays: confirmations.length },
  }, now);
  return row;
}

const csrWorkerRequest = workerData as { heliopauseCsrValidation?: unknown; csrPem?: unknown; expectedHostname?: unknown } | null;
if (!isMainThread && csrWorkerRequest?.heliopauseCsrValidation === true) {
  try {
    if (typeof csrWorkerRequest.csrPem !== "string" || typeof csrWorkerRequest.expectedHostname !== "string") {
      throw new EnrollmentError("invalid CSR worker request");
    }
    parentPort?.postMessage({
      ok: true,
      result: validateNodeCsr(csrWorkerRequest.csrPem, csrWorkerRequest.expectedHostname),
    });
  } catch {
    parentPort?.postMessage({ ok: false });
  } finally {
    parentPort?.close();
  }
}
