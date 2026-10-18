/**
 * Password hashing for member accounts: scrypt from `node:crypto`, a two-slot concurrency limit,
 * and the length/containment policy.
 *
 * The encoded form is `scrypt$<N>$<r>$<p>$<saltB64url>$<dkB64url>`. Verification reads the
 * parameters from the string, so stored hashes keep working after the defaults are raised and
 * `needsRehash` says when a stored hash is below them.
 */
import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from "node:crypto";

export const SCRYPT_DEFAULTS = { N: 2 ** 15, r: 8, p: 1, keylen: 32, saltBytes: 16 } as const;
/** In-flight scrypt calls allowed at once; the next one is refused, not queued. */
export const MAX_CONCURRENT_HASHES = 2;
export const MIN_PASSWORD_CODE_POINTS = 12;
export const MAX_PASSWORD_BYTES = 1024;

// Bounds on parameters read back from a stored hash: one verification's `maxmem` stays at or
// below `MAX_SCRYPT_MEMORY`. That bound also caps N from above, so N has no separate upper limit.
const MAX_R = 32;
// Below the default (16) so a short legacy salt still verifies and is flagged by `needsRehash`.
const MIN_SALT_BYTES = 8;
const MAX_P = 16;
const MAX_SCRYPT_MEMORY = 256 * 1024 * 1024;
// CPU work grows with N·r·p; allow up to 8× the default (2^15·8·1).
const MAX_SCRYPT_WORK = 8 * SCRYPT_DEFAULTS.N * SCRYPT_DEFAULTS.r * SCRYPT_DEFAULTS.p;
const ENCODED = /^scrypt\$(\d{1,8})\$(\d{1,3})\$(\d{1,3})\$([A-Za-z0-9_-]{11,128})\$([A-Za-z0-9_-]{22,128})$/;

/** Thrown when `MAX_CONCURRENT_HASHES` calls are already running. A server maps this to 429. */
export class PasswordBusyError extends Error {
  readonly statusCode = 429;
  constructor() { super("too many password checks are in progress"); }
}

export interface ScryptParams { N: number; r: number; p: number; salt: Buffer; dk: Buffer; }

let inFlight = 0;

/** OpenSSL's scrypt allocates 128·r·(N + 2) + 128·r·p bytes; `maxmem` is twice that. */
const scryptMemory = (N: number, r: number, p: number): number => 2 * 128 * r * (N + 2 + p);

/**
 * One scrypt call holding one limiter slot. The slot is released on the callback and on a
 * synchronous throw (a non-string password, or parameters `scrypt` refuses before starting).
 * @see password.test.ts "a failing call releases its limiter slot"
 */
function derive(password: string, salt: Buffer, N: number, r: number, p: number, keylen: number): Promise<Buffer> {
  if (inFlight >= MAX_CONCURRENT_HASHES) return Promise.reject(new PasswordBusyError());
  inFlight += 1;
  const options: ScryptOptions = { N, r, p, maxmem: scryptMemory(N, r, p) };
  return new Promise<Buffer>((resolveKey, reject) => {
    try {
      scrypt(password.normalize("NFKC"), salt, keylen, options, (error, key) => {
        inFlight -= 1;
        if (error) reject(error); else resolveKey(key);
      });
    } catch (error) {
      inFlight -= 1;
      reject(error);
    }
  });
}

/** Parse an encoded hash, or return null when it is malformed or its parameters are out of bounds. */
export function parseEncodedHash(encoded: string): ScryptParams | null {
  const match = ENCODED.exec(encoded);
  if (!match) return null;
  const N = Number(match[1]); const r = Number(match[2]); const p = Number(match[3]);
  const isPowerOfTwo = N >= 2 && (N & (N - 1)) === 0;
  if (!isPowerOfTwo || r < 1 || r > MAX_R || p < 1 || p > MAX_P) return null;
  // OpenSSL refuses N ≥ 2^(16·r).
  if (N >= 2 ** (16 * r)) return null;
  if (scryptMemory(N, r, p) > MAX_SCRYPT_MEMORY) return null;
  if (N * r * p > MAX_SCRYPT_WORK) return null;
  const salt = Buffer.from(match[4]!, "base64url");
  const dk = Buffer.from(match[5]!, "base64url");
  if (salt.length < MIN_SALT_BYTES || dk.length < 16 || salt.toString("base64url") !== match[4] || dk.toString("base64url") !== match[5]) {
    return null;
  }
  return { N, r, p, salt, dk };
}

export async function hashPassword(password: string): Promise<string> {
  const { N, r, p, keylen, saltBytes } = SCRYPT_DEFAULTS;
  const salt = randomBytes(saltBytes);
  const dk = await derive(password, salt, N, r, p, keylen);
  return `scrypt$${N}$${r}$${p}$${salt.toString("base64url")}$${dk.toString("base64url")}`;
}

/**
 * Compare `password` with `encoded` using `timingSafeEqual`. A malformed `encoded` throws: that is
 * a damaged store, not a wrong password. `needsRehash` is true when the stored parameters or key
 * length differ from `SCRYPT_DEFAULTS`, or the salt is shorter than the default.
 */
export async function verifyPassword(password: string, encoded: string): Promise<{ ok: boolean; needsRehash: boolean }> {
  const params = parseEncodedHash(encoded);
  if (!params) throw new Error("stored password hash is malformed");
  const actual = await derive(password, params.salt, params.N, params.r, params.p, params.dk.length);
  const ok = timingSafeEqual(actual, params.dk);
  const d = SCRYPT_DEFAULTS;
  const needsRehash = params.N !== d.N || params.r !== d.r || params.p !== d.p || params.dk.length !== d.keylen
    || params.salt.length < d.saltBytes;
  return { ok, needsRehash };
}

/**
 * Run one scrypt derivation at the default parameters and return `false`. For the unknown-user
 * branch of a login: its work equals a verify against a hash at default parameters, and it takes
 * a limiter slot. A stored hash at other parameters costs differently.
 * @see password.test.ts "dummyVerify spends a scrypt derivation and a limiter slot"
 */
export async function dummyVerify(password: string): Promise<false> {
  const { N, r, p, keylen, saltBytes } = SCRYPT_DEFAULTS;
  await derive(password, randomBytes(saltBytes), N, r, p, keylen);
  return false;
}

/**
 * Length bounds and a containment check. No composition rules. Returns the reasons a password is
 * refused; an empty list means it is accepted.
 */
export function checkPasswordPolicy(password: string, context: { username?: string | null; email?: string | null } = {}): string[] {
  const normalized = password.normalize("NFKC");
  const problems: string[] = [];
  if ([...normalized].length < MIN_PASSWORD_CODE_POINTS) problems.push(`must be at least ${MIN_PASSWORD_CODE_POINTS} characters`);
  if (Buffer.byteLength(normalized, "utf8") > MAX_PASSWORD_BYTES) problems.push(`must be at most ${MAX_PASSWORD_BYTES} bytes`);
  const lowered = normalized.toLowerCase();
  const localPart = context.email ? context.email.split("@")[0] ?? "" : "";
  for (const [label, value] of [["username", context.username ?? ""], ["email address", localPart]] as const) {
    const needle = value.normalize("NFKC").toLowerCase();
    if (needle.length >= 3 && lowered.includes(needle)) problems.push(`must not contain the ${label}`);
  }
  return problems;
}
