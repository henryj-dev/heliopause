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
export interface EnrollmentDocument {
  schemaVersion: typeof ENROLLMENT_SCHEMA;
  tokens: NodeTokenRecord[]; requests: NodeCsrRecord[]; audit: EnrollmentAuditEvent[]; revocations: CertificateRevocation[];
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
  const allowed = ["schemaVersion", "tokens", "requests", "audit", "revocations"];
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
  return {
    schemaVersion: ENROLLMENT_SCHEMA,
    tokens,
    requests: d.requests as NodeCsrRecord[],
    audit: d.audit as EnrollmentAuditEvent[],
    revocations,
  };
}
export const emptyEnrollmentDocument = (): EnrollmentDocument => ({ schemaVersion: 1, tokens: [], requests: [], audit: [], revocations: [] });
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
export function createNodeToken(document: EnrollmentDocument, input: { hostname: string; label?: string; createdBy?: string; revokeExisting?: boolean; ttlSec?: number; now?: Date }) {
  const host = hostname(input.hostname); const issuedAt = input.now ?? new Date(); const at = nowIso(issuedAt);
  const ttlSec = input.ttlSec ?? DEFAULT_NODE_TOKEN_TTL_SEC;
  if (!Number.isSafeInteger(ttlSec) || ttlSec < MIN_NODE_TOKEN_TTL_SEC || ttlSec > MAX_NODE_TOKEN_TTL_SEC) {
    throw new EnrollmentError(`node token ttlSec must be ${MIN_NODE_TOKEN_TTL_SEC}-${MAX_NODE_TOKEN_TTL_SEC}`);
  }
  if (input.revokeExisting !== false) for (const token of document.tokens) if (token.hostname === host && !token.revokedAt) token.revokedAt = at;
  const token = `${NODE_TOKEN_PREFIX}${randomHex(32)}`;
  const row: NodeTokenRecord = { id: randomHex(8), hostname: host, tokenHash: sha256(token), label: input.label?.trim().slice(0, 120) || null,
    createdBy: input.createdBy?.trim().slice(0, 120) || null, createdAt: at,
    expiresAt: new Date(issuedAt.getTime() + ttlSec * 1_000).toISOString(), lastUsedAt: null, revokedAt: null };
  document.tokens.push(row); audit(document, { actor: row.createdBy ?? "operator", action: "node-token.create", target: row.id, sourceIp: null, detail: { hostname: host } }, input.now);
  return { document, token, row };
}
export function revokeNodeToken(document: EnrollmentDocument, id: string, actor = "operator", now = new Date()): NodeTokenRecord {
  const row = document.tokens.find((token) => token.id === id); if (!row) throw new EnrollmentError(`node token ${id} not found`, 404);
  if (!row.revokedAt) row.revokedAt = nowIso(now); audit(document, { actor, action: "node-token.revoke", target: id, sourceIp: null, detail: { hostname: row.hostname } }, now); return row;
}
export function lookupNodeToken(document: EnrollmentDocument, plaintext: string, now = new Date()): NodeTokenRecord | null {
  if (!plaintext.startsWith(NODE_TOKEN_PREFIX)) return null; const digest = sha256(plaintext);
  const row = document.tokens.find((token) => token.tokenHash === digest && !token.revokedAt && Date.parse(token.expiresAt) > now.getTime()) ?? null;
  if (row) row.lastUsedAt = nowIso(now); return row;
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
  if (!row?.certificatePem || !row.caPem || !row.certificateSha256) throw new EnrollmentError("certificate not ready", 404);
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
