import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, randomBytes, X509Certificate } from "node:crypto";
import {
  chmodSync, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { isMainThread, parentPort, Worker, workerData } from "node:worker_threads";
import { parseRevocationSnapshot } from "./revocation-snapshot.ts";

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

export type CsrStatus = "pending" | "conflict" | "rejected" | "signed";
export interface NodeTokenRecord {
  id: string; hostname: string; tokenHash: string; label: string | null; createdBy: string | null;
  createdAt: string; expiresAt: string; lastUsedAt: string | null; revokedAt: string | null;
}
export interface NodeCsrRecord {
  id: string; hostname: string; nodeTokenId: string; status: CsrStatus; csrPem: string;
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
/**
 * Everything an app token is allowed to ask for. **These two and no more.**
 *
 * There is no `enrollment:sign`, no `enrollment:certificate-upload` and no `enrollment:revoke`, and
 * that is the argument for issuing these at all: the worst a leaked app token can do is mint node
 * tokens inside its hostname pattern and read the CSR queue. Signing stays with an operator holding
 * a certificate and a one-time code. Adding a scope here moves that line — do not do it to make a
 * caller's day easier.
 */
export const APP_TOKEN_SCOPES = ["enrollment:token-create", "enrollment:requests-read"] as const;
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
  const allowed = ["schemaVersion", "tokens", "requests", "audit", "revocations", "appTokens"];
  if (Object.keys(d).some((key) => !allowed.includes(key))) {
    throw new EnrollmentError(`${source}: enrollment store contains unsupported fields`);
  }
  if (d.schemaVersion !== ENROLLMENT_SCHEMA || !Array.isArray(d.tokens) || !Array.isArray(d.requests) || !Array.isArray(d.audit)) {
    throw new EnrollmentError(`${source}: invalid enrollment schema`);
  }
  const tokens = (d.tokens as NodeTokenRecord[]).map((token) => {
    if (typeof token.expiresAt === "string" && Number.isFinite(Date.parse(token.expiresAt))) return token;
    // Schema-1 stores written before expiry was introduced are bounded from their original issue
    // time. They do not become immortal merely because they predate this field.
    const created = Date.parse(String(token.createdAt));
    return {
      ...token,
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
  return {
    schemaVersion: ENROLLMENT_SCHEMA,
    tokens,
    requests: d.requests as NodeCsrRecord[],
    audit: d.audit as EnrollmentAuditEvent[],
    revocations,
    appTokens: (d.appTokens as AppTokenRecord[] | undefined) ?? [],
  };
}
export const emptyEnrollmentDocument = (): EnrollmentDocument => ({ schemaVersion: 1, tokens: [], requests: [], audit: [], revocations: [], appTokens: [] });
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
export function createNodeToken(document: EnrollmentDocument, input: { hostname: string; label?: string; createdBy?: string; appTokenId?: string; revokeExisting?: boolean; ttlSec?: number; now?: Date }) {
  const host = hostname(input.hostname); const issuedAt = input.now ?? new Date(); const at = nowIso(issuedAt);
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
    createdBy: input.createdBy?.trim().slice(0, MAX_CREATED_BY_CHARS) || null, createdAt: at,
    expiresAt: new Date(issuedAt.getTime() + ttlSec * 1_000).toISOString(), lastUsedAt: null, revokedAt: null };
  document.tokens.push(row);
  audit(document, {
    actor: row.createdBy ?? "operator", action: "node-token.create", target: row.id, sourceIp: null,
    detail: { hostname: host, ...(input.appTokenId === undefined ? {} : { appTokenId: input.appTokenId }) },
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
  const csr = input.csr;
  if (csr.hostname !== token.hostname || csr.pem !== normalizeCsrPem(csr.pem)) {
    throw new EnrollmentError("validated CSR does not match the node token", 409);
  }
  const same = document.requests.find((row) => row.hostname === csr.hostname && row.csrSha256 === csr.csrSha256);
  if (same) return { document, row: same, created: false };
  const unresolved = document.requests.filter((row) => row.hostname === csr.hostname && (row.status === "pending" || row.status === "conflict"));
  if (unresolved.length >= MAX_PENDING_CSRS_PER_HOST) throw new EnrollmentError("too many unresolved CSRs for hostname", 429);
  const status: CsrStatus = unresolved.length ? "conflict" : "pending";
  const row: NodeCsrRecord = { id: randomHex(16), hostname: csr.hostname, nodeTokenId: token.id, status, csrPem: csr.pem, csrSha256: csr.csrSha256,
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
export function storeNodeCertificate(document: EnrollmentDocument, input: { requestId: string; certificatePem: string; caPem: string; caName: string; actor: string; now?: Date }): NodeCsrRecord {
  const row = document.requests.find((request) => request.id === input.requestId); if (!row || !["pending", "conflict"].includes(row.status)) throw new EnrollmentError("CSR not found or already decided", 404);
  const rivals = document.requests.filter((request) => request.hostname === row.hostname && request.id !== row.id && ["pending", "conflict"].includes(request.status));
  if (rivals.length) throw new EnrollmentError("unresolved CSR conflict for hostname", 409);
  const cert = validateNodeCertificate(input.certificatePem, input.caPem, row, input.now); row.status = "signed"; row.decidedAt = nowIso(input.now); row.decidedBy = input.actor; row.signedAt = row.decidedAt;
  row.caName = input.caName; row.certificatePem = cert.certificatePem; row.caPem = cert.caPem; row.certificateSha256 = cert.certificateSha256; row.certificateNotBefore = cert.notBefore; row.certificateNotAfter = cert.notAfter;
  audit(document, { actor: input.actor, action: "node-cert.upload", target: row.id, sourceIp: null, detail: { hostname: row.hostname, caName: input.caName, certificateSha256: cert.certificateSha256 } }, input.now); return row;
}
export function fetchNodeCertificate(document: EnrollmentDocument, requestId: string, plaintextToken: string, sourceIp?: string | null, now = new Date()) {
  const token = lookupNodeToken(document, plaintextToken, now); if (!token) throw new EnrollmentError("unauthorized node token", 401);
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
