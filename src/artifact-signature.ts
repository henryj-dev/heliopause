/**
 * Manager authorization for one host artifact.
 *
 * A relay is an untrusted courier.  Hashes carried by that relay only detect accidental
 * corruption: a compromised relay can replace both a ruleset and its claimed hash.  This envelope
 * instead binds the exact host payload to a dedicated manager Ed25519 key.  Agents need only the
 * corresponding public key; the relay never receives signing material.
 *
 * The signed bytes are deliberately small and language-neutral:
 *
 *     frame(domain) || frame(keyId) || frame(canonicalPayload)
 *
 * where every frame is a four-byte big-endian length followed by the UTF-8 bytes.  The payload is
 * base64url encoded only for transport.  Its decoded bytes, not a re-serialised object, are what the
 * signature covers.  Requiring those bytes to be the one canonical JSON encoding removes parser and
 * key-order ambiguity when the Python agent validates the same envelope.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  verify,
  type KeyLike,
  type KeyObject,
} from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, rename, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { bundleHash, planHash, validateBundle, type PlanBundle } from "./bundle.ts";
import {
  SCHEMA_VERSION,
  type Manifest,
  type ManifestEntry,
  type RolloutStage,
  type WorkloadEntry,
  type ArtifactAuthorizationMode,
} from "./protocol.ts";

export const HOST_ARTIFACT_SIGNATURE_DOMAIN = "heliopause-host-artifact-authorization-v1";
export const HOST_ARTIFACT_ENVELOPE_VERSION = "heliopause-ed25519-v1";
export const HOST_ARTIFACT_TRUST_DOMAIN = "heliopause-host-artifact-trust-v1";

/**
 * The old per-host response is bounded at 4 MiB. The signed payload carries those same per-host
 * fields plus a small manifest header and provenance metadata, so 5 MiB preserves that boundary
 * without exposing the full fleet manifest. The Python response reader must use
 * `MAX_HOST_ARTIFACT_ENVELOPE_BYTES`, not its old 4 MiB pre-signature limit.
 */
export const MAX_HOST_ARTIFACT_PAYLOAD_BYTES = 5 * 1024 * 1024;
/** Base64 expands by 4/3. This also bounds hostile input before JSON/base64 decoding allocates it. */
export const MAX_HOST_ARTIFACT_ENVELOPE_BYTES =
  Math.ceil(MAX_HOST_ARTIFACT_PAYLOAD_BYTES / 3) * 4 + 1024;
/** Atomic relay snapshot containing all per-host envelopes. */
export const MAX_AUTHORIZED_ARTIFACT_BUNDLE_BYTES = 16 * 1024 * 1024;
export const AUTHORIZED_ARTIFACT_BUNDLE_FILE = "authorized-bundle.json";

export const MIN_HOST_AUTHORIZATION_LIFETIME_MS = 15 * 60 * 1000;
export const MAX_MANAGER_AUTHORIZATION_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
export const MAX_BREAK_GLASS_AUTHORIZATION_LIFETIME_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_AUTHORIZATION_CLOCK_SKEW_MS = 60 * 1000;

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const STAGES = new Set<RolloutStage>(["canary", "general", "gateway"]);
const MODES = new Set<AuthorizationMode>(["two-person", "solo-otp", "break-glass"]);

export type AuthorizationMode = ArtifactAuthorizationMode;
export type ArtifactSigningTrustClass = "manager" | "break-glass";

/** Generation facts safe to disclose to one host; the full fleet host map remains relay/operator-only. */
export interface ArtifactManifestHeader {
  generation: string;
  issuedAt: string;
  schemaVersion: number;
}

/**
 * Every manager fact an agent needs to distinguish an approved artifact from one invented by a
 * relay. `manifest` is deliberately only a generation header; `entry` is the exact host record the
 * signer extracted from the validated full bundle. This avoids disclosing fleet inventory to each
 * host while binding every host/workload check the agent applies.
 */
export interface HostArtifactAuthorizationPayload {
  version: 1;
  target: string;
  planHash: string;
  bundleHash: string;
  authorizedAt: string;
  expiresAt: string;
  authorizationMode: AuthorizationMode;
  host: string;
  manifest: ArtifactManifestHeader;
  entry: ManifestEntry;
  ruleset: string;
  /** Exact Cilium document for the applier, or null when this host has no workload assignment. */
  workload: string | null;
}

export interface HostArtifactEnvelope {
  version: typeof HOST_ARTIFACT_ENVELOPE_VERSION;
  algorithm: "Ed25519";
  /** SHA-256 of the DER SubjectPublicKeyInfo bytes, not of a PEM text representation. */
  keyId: string;
  /** Canonical UTF-8 JSON bytes, unpadded base64url. */
  payload: string;
  /** Raw 64-byte Ed25519 signature, unpadded base64url. */
  signature: string;
}

/** The relay persists and serves this as one opaque, atomically replaced snapshot. */
export interface AuthorizedArtifactBundle {
  version: 1;
  manifest: Manifest;
  artifacts: Record<string, HostArtifactEnvelope>;
  /** Exact publish receipt, also carried at top level for relay status. */
  planHash: string;
}

export interface BuildHostAuthorizationInput {
  target: string;
  bundle: PlanBundle;
  host: string;
  authorizedAt: Date | string;
  expiresAt: Date | string;
  authorizationMode: AuthorizationMode;
}

export interface BuildAuthorizedBundleInput extends Omit<BuildHostAuthorizationInput, "host"> {}

export interface VerifyHostAuthorizationOptions {
  /**
   * Online manager keys and offline emergency keys are separate trust classes. An envelope's mode
   * must agree with the class containing its key, so neither key can make the other's audit claim.
   */
  trustedKeys: ArtifactSigningTrustRings;
  /** Must come from the agent's independent `HELIOPAUSE_TARGET` setting, never from the envelope. */
  expectedTarget: string;
  expectedHost: string;
  now: Date;
  maxClockSkewMs?: number;
}

export interface ArtifactSigningTrustRings {
  /** Online keys: only two-person and solo-with-OTP authorizations. */
  manager: readonly (KeyObject | KeyLike)[];
  /** Offline keys: only explicit break-glass authorizations. */
  breakGlass: readonly (KeyObject | KeyLike)[];
}

/** Bounded, non-secret telemetry an agent can place in its heartbeat. */
export interface ArtifactSigningTrustSummary {
  managerKeyIds: string[];
  breakGlassKeyIds: string[];
  /** Length-framed digest of both labelled, sorted rings. */
  digest: string;
}

export class ArtifactSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ArtifactSignatureError";
  }
}

/**
 * Process-local millisecond issuer for replay-watermark-safe authorizations.
 *
 * Every host envelope in one publish must use the one value returned for that publish. A second
 * publish observed in the same clock millisecond receives `last + 1`, so agents never have to
 * choose between two different payloads carrying an equal `authorizedAt` watermark.
 */
export class AuthorizationTimestampIssuer {
  #last = -1;

  next(now: Date): Date {
    const observed = now.getTime();
    if (!Number.isFinite(observed)) throw new ArtifactSignatureError("authorization clock is invalid");
    const issued = Math.max(observed, this.#last + 1);
    if (issued > 8_640_000_000_000_000) {
      throw new ArtifactSignatureError("authorization timestamp exceeds the JavaScript date range");
    }
    this.#last = issued;
    return new Date(issued);
  }
}

/** Compute the stable identifier agents pin for an Ed25519 public key. */
/**
 * Why a private key file is unacceptable, or `null` when it is fine.
 *
 * ## The rule, and why it is not simply `mode & 0o077`
 *
 * That is the rule for a key on a workstation, and it is what this started as. It cannot hold where
 * the manager actually runs. Kubernetes projects a Secret to a non-root process through `fsGroup`:
 * kubelet takes group ownership and **adds the group read bit itself**, so `defaultMode: 0400`
 * arrives as `0440`. Measured 2026-08-15 on the first rollout of the signing path — mode `0440`
 * owned `10001:10001` with `runAsUser` = `runAsGroup` = `fsGroup` = 10001 — and the manager
 * crashlooped on a file that nothing but itself could read.
 *
 * So the question is asked properly instead. Group read is accepted **only** when the file's group
 * is the one this process runs as, which is exactly what kubelet creates and is no wider than
 * owner-read. What the check exists for stays refused: any access for other, any write for group,
 * and group read by a group this process is not in.
 *
 * Ownership is separate and checked by the caller — a key owned by someone else is a different
 * failure and deserves its own sentence.
 */
export function privateKeyFileModeError(
  file: { mode: number; gid: number },
  processGid: number | undefined,
): string | null {
  if ((file.mode & 0o007) !== 0) return "must not be reachable by other";
  const group = file.mode & 0o070;
  if (group === 0) return null;
  if (group !== 0o040) return "must not be writable or executable by group";
  if (processGid === undefined || file.gid !== processGid) {
    return "may be group-readable only by the group this process runs as";
  }
  return null;
}

/**
 * Why the ownership of a private key file is unacceptable, or `null`.
 *
 * ## Root-owned is not a failure, and Kubernetes makes it the normal case
 *
 * `uid !== process.getuid()` is the workstation rule and it refuses the only shape a Secret has.
 * kubelet writes secret files **owned by root**, takes group ownership for `fsGroup`, and lets the
 * workload read them through the group bit — that pairing is the whole mechanism, which is why the
 * mode check above had to accept group read in the first place. Measured 2026-08-15: with the mode
 * check fixed, the very next start refused the same file for being owned by uid 0.
 *
 * Root owning the key is strictly safer than this process owning it: root can already read anything
 * here, and an account that is *not* root and *not* us is the case worth refusing — it can rewrite
 * the key and choose what every firewall in the fleet accepts.
 */
export function privateKeyFileOwnerError(
  file: { uid: number },
  processUid: number | undefined,
): string | null {
  if (processUid === undefined) return null;
  if (file.uid === processUid || file.uid === 0) return null;
  return "must be owned by this account or by root";
}

export function artifactSigningKeyId(key: KeyObject | KeyLike): string {
  const publicKey = asEd25519PublicKey(key);
  const spki = publicKey.export({ format: "der", type: "spki" });
  return "sha256:" + createHash("sha256").update(spki).digest("hex");
}

/** Digest used in an agent's durable equal-timestamp replay record. Trust is established separately. */
export function artifactAuthorizationPayloadHash(input: string | unknown): string {
  const envelope = decodeHostArtifactEnvelope(input);
  const payload = decodeBase64Url(envelope.payload, "payload", MAX_HOST_ARTIFACT_PAYLOAD_BYTES, false);
  return "sha256:" + createHash("sha256").update(payload).digest("hex");
}

/**
 * Describe the independently configured trust rings without exposing key bytes.
 *
 * The digest labels each ring and length-prefixes every field, so moving a key from the manager ring
 * to the emergency ring changes it even though the set of key ids is otherwise identical.
 */
export function artifactSigningTrustSummary(rings: ArtifactSigningTrustRings): ArtifactSigningTrustSummary {
  const trusted = trustedKeyIndex(rings);
  const managerKeyIds = [...trusted.values()]
    .filter((item) => item.trustClass === "manager")
    .map((item) => item.keyId)
    .sort();
  const breakGlassKeyIds = [...trusted.values()]
    .filter((item) => item.trustClass === "break-glass")
    .map((item) => item.keyId)
    .sort();
  const hash = createHash("sha256");
  hash.update(frame(Buffer.from(HOST_ARTIFACT_TRUST_DOMAIN, "utf8")));
  for (const [trustClass, ids] of [
    ["manager", managerKeyIds],
    ["break-glass", breakGlassKeyIds],
  ] as const) {
    hash.update(frame(Buffer.from(trustClass, "utf8")));
    for (const id of ids) hash.update(frame(Buffer.from(id, "utf8")));
  }
  return { managerKeyIds, breakGlassKeyIds, digest: "sha256:" + hash.digest("hex") };
}

interface PreparedAuthorization {
  target: string;
  bundle: PlanBundle;
  authorizedAt: string;
  expiresAt: string;
  authorizationMode: AuthorizationMode;
  planHash: string;
  bundleHash: string;
}

/** Validate and hash common publish material once, even for a maximum-size host manifest. */
function prepareAuthorization(input: BuildAuthorizedBundleInput): PreparedAuthorization {
  let bundle: PlanBundle;
  try {
    bundle = validateBundle(input.bundle);
  } catch (error) {
    throw new ArtifactSignatureError(`cannot authorize an invalid bundle: ${(error as Error).message}`);
  }
  validateName(input.target, "target", 128);
  if (!MODES.has(input.authorizationMode)) {
    throw new ArtifactSignatureError(`unsupported authorizationMode ${JSON.stringify(input.authorizationMode)}`);
  }
  const authorizedAt = exactIso(input.authorizedAt, "authorizedAt");
  const expiresAt = exactIso(input.expiresAt, "expiresAt");
  validateAuthorizationWindow(authorizedAt, expiresAt, input.authorizationMode);
  const computedBundleHash = bundleHash(bundle);
  return {
    target: input.target,
    bundle,
    authorizedAt,
    expiresAt,
    authorizationMode: input.authorizationMode,
    planHash: planHash(input.target, bundle),
    bundleHash: computedBundleHash,
  };
}

function buildPayloadFromValidated(
  common: PreparedAuthorization,
  host: string,
): HostArtifactAuthorizationPayload {
  validateName(host, "host", 253);
  const { bundle } = common;
  const entry = bundle.manifest.hosts[host];
  const ruleset = bundle.rulesets[host];
  if (!entry || typeof ruleset !== "string") {
    throw new ArtifactSignatureError(`bundle does not contain host ${JSON.stringify(host)}`);
  }

  const payload: HostArtifactAuthorizationPayload = {
    version: 1,
    target: common.target,
    planHash: common.planHash,
    bundleHash: common.bundleHash,
    authorizedAt: common.authorizedAt,
    expiresAt: common.expiresAt,
    authorizationMode: common.authorizationMode,
    host,
    manifest: {
      generation: bundle.manifest.generation,
      issuedAt: bundle.manifest.issuedAt,
      schemaVersion: bundle.manifest.schemaVersion,
    },
    entry,
    ruleset,
    workload: bundle.workload[host] ?? null,
  };
  // The signer must fail before performing a private-key operation when the eventual agent would
  // reject the payload. This is also the single size check for callers using the builder directly.
  validatePayload(payload);
  encodeCanonicalPayload(payload);
  return payload;
}

/** Sign one validated host artifact with a dedicated Ed25519 private key. */
export function signHostArtifactAuthorization(
  input: BuildHostAuthorizationInput,
  key: KeyObject | KeyLike,
): HostArtifactEnvelope {
  const privateKey = asEd25519PrivateKey(key);
  const keyId = artifactSigningKeyId(createPublicKey(privateKey));
  const payload = encodeCanonicalPayload(buildPayloadFromValidated(prepareAuthorization(input), input.host));
  return signPreparedPayload(payload, privateKey, keyId);
}

function signPreparedPayload(payload: Buffer, privateKey: KeyObject, keyId: string): HostArtifactEnvelope {
  const signature = sign(null, signatureInput(keyId, payload), privateKey);
  if (signature.length !== 64) throw new ArtifactSignatureError("Ed25519 produced a non-64-byte signature");
  return {
    version: HOST_ARTIFACT_ENVELOPE_VERSION,
    algorithm: "Ed25519",
    keyId,
    payload: payload.toString("base64url"),
    signature: signature.toString("base64url"),
  };
}

/** Sign every host from one plan with one shared authorization timestamp and expiry. */
export function signAuthorizedArtifactBundle(
  input: BuildAuthorizedBundleInput,
  key: KeyObject | KeyLike,
): AuthorizedArtifactBundle {
  const common = prepareAuthorization(input);
  const privateKey = asEd25519PrivateKey(key);
  const keyId = artifactSigningKeyId(createPublicKey(privateKey));
  const artifacts: Record<string, HostArtifactEnvelope> = {};
  for (const host of Object.keys(common.bundle.manifest.hosts).sort()) {
    const payload = encodeCanonicalPayload(buildPayloadFromValidated(common, host));
    artifacts[host] = signPreparedPayload(payload, privateKey, keyId);
  }
  return validateAuthorizedArtifactBundle({
    version: 1, manifest: common.bundle.manifest, artifacts, planHash: common.planHash,
  });
}

/**
 * Strict validation for relay storage. The relay decodes only enough of the signed payload to prove
 * every artifact names one plan receipt and the same outer manifest. It still cannot turn those
 * bytes into applyable policy: signature trust and authorization remain agent-side checks.
 */
export function validateAuthorizedArtifactBundle(input: unknown): AuthorizedArtifactBundle {
  if (!isRecord(input)) throw new ArtifactSignatureError("authorized artifact bundle is not an object");
  const outerKeys = Object.keys(input);
  if (outerKeys.some((key) => !["artifacts", "manifest", "planHash", "version"].includes(key))
    || ["artifacts", "manifest", "version"].some((key) => !outerKeys.includes(key))) {
    throw new ArtifactSignatureError("authorized artifact bundle contains unsupported or missing fields");
  }
  if (input.version !== 1) throw new ArtifactSignatureError("unsupported authorized artifact bundle version");
  const manifest = validateManifest(input.manifest);
  if (!isRecord(input.artifacts)) throw new ArtifactSignatureError("authorized artifact bundle has no artifacts map");
  const named = Object.keys(manifest.hosts).sort();
  const carried = Object.keys(input.artifacts).sort();
  if (named.length !== carried.length || named.some((host, index) => host !== carried[index])) {
    throw new ArtifactSignatureError("authorized artifact bundle hosts do not exactly match its manifest");
  }
  const artifacts: Record<string, HostArtifactEnvelope> = {};
  const signedPlanHashes = new Set<string>();
  for (const host of named) {
    const envelope = decodeHostArtifactEnvelope(input.artifacts[host]);
    artifacts[host] = envelope;
    const payloadBytes = decodeBase64Url(envelope.payload, "payload", MAX_HOST_ARTIFACT_PAYLOAD_BYTES, false);
    let parsed: unknown;
    try { parsed = JSON.parse(decodeUtf8(payloadBytes)) as unknown; }
    catch { throw new ArtifactSignatureError(`artifact ${host} signed payload is not JSON`); }
    if (canonicalJson(parsed) !== decodeUtf8(payloadBytes)) {
      throw new ArtifactSignatureError(`artifact ${host} signed payload is not canonical JSON`);
    }
    const payload = validatePayload(parsed);
    if (payload.host !== host || payload.manifest.generation !== manifest.generation
      || payload.manifest.issuedAt !== manifest.issuedAt) {
      throw new ArtifactSignatureError(`artifact ${host} does not bind the outer manifest`);
    }
    signedPlanHashes.add(payload.planHash);
  }
  if (signedPlanHashes.size > 1) throw new ArtifactSignatureError("artifacts do not agree on one signed planHash");
  const carriedPlanHash = input.planHash;
  if (carriedPlanHash !== undefined && (typeof carriedPlanHash !== "string" || !DIGEST.test(carriedPlanHash))) {
    throw new ArtifactSignatureError("authorized artifact bundle planHash is not a sha256 digest");
  }
  const signedPlanHash = signedPlanHashes.values().next().value as string | undefined;
  if (signedPlanHash && carriedPlanHash !== undefined && carriedPlanHash !== signedPlanHash) {
    throw new ArtifactSignatureError("authorized artifact bundle planHash differs from its signed artifacts");
  }
  if (!signedPlanHash) throw new ArtifactSignatureError("authorized artifact bundle has no signed planHash");
  return { version: 1, manifest, artifacts, planHash: carriedPlanHash ?? signedPlanHash };
}

export function encodeAuthorizedArtifactBundle(input: unknown): string {
  const bundle = validateAuthorizedArtifactBundle(input);
  const encoded = JSON.stringify(sortKeys(bundle)) + "\n";
  if (Buffer.byteLength(encoded) > MAX_AUTHORIZED_ARTIFACT_BUNDLE_BYTES) {
    throw new ArtifactSignatureError("authorized artifact bundle exceeds its byte limit");
  }
  return encoded;
}

/** One rename is the activation point: a relay can never observe a new manifest with old envelopes. */
export async function writeAuthorizedArtifactBundle(dir: string, input: unknown): Promise<void> {
  const encoded = encodeAuthorizedArtifactBundle(input);
  await mkdir(dir, { recursive: true });
  const destination = join(dir, AUTHORIZED_ARTIFACT_BUNDLE_FILE);
  const tmp = `${destination}.${process.pid}.${randomBytes(16).toString("hex")}.tmp`;
  const handle = await open(tmp, "wx", 0o640);
  try {
    await handle.truncate(0);
    await handle.writeFile(encoded, "utf8");
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => undefined);
    await rm(tmp, { force: true });
    throw error;
  }
  await handle.close();
  try {
    await rename(tmp, destination);
    const directory = await open(dirname(destination), "r");
    try { await directory.sync(); } finally { await directory.close(); }
  } catch (error) {
    await rm(tmp, { force: true });
    throw error;
  }
}

export async function loadAuthorizedArtifactBundle(dir: string): Promise<AuthorizedArtifactBundle> {
  const path = join(dir, AUTHORIZED_ARTIFACT_BUNDLE_FILE);
  // 🔴 **Check and read the same open file, not the same path twice.**
  //
  // This used to `lstat(path)`, refuse a symlink, then `readFile(path)` — and `readFile` follows
  // links. Between the two calls the name can be replaced, so the thing refused and the thing read
  // were never guaranteed to be the same object. The size limit survived that (it is re-checked on
  // the bytes actually read, below), but **the symlink refusal did not**: it was the one check here
  // that a swap could step around, and it guards what this function is for — deciding that a
  // generation was authorized.
  //
  // `O_NOFOLLOW` makes the kernel refuse the open itself if the final component is a link, and
  // everything after is asked of the descriptor rather than the name. `O_NOFOLLOW` is POSIX; on a
  // platform without it the constant is undefined and the `?? 0` leaves the old behaviour rather
  // than throwing at import time — the agent and the manager both run on Linux, and a build that
  // silently could not open its own bundle would be a worse failure than the race.
  const handle = await open(path, (constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))).catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code === "ELOOP" || error.code === "EMLINK") {
        throw new ArtifactSignatureError("authorized artifact bundle is not a regular file");
      }
      throw error;
    },
  );
  let encoded: Buffer;
  try {
    const info = await handle.stat();
    if (!info.isFile()) {
      throw new ArtifactSignatureError("authorized artifact bundle is not a regular file");
    }
    if (info.size > MAX_AUTHORIZED_ARTIFACT_BUNDLE_BYTES) {
      throw new ArtifactSignatureError("authorized artifact bundle exceeds its byte limit");
    }
    encoded = await handle.readFile();
  } finally {
    await handle.close().catch(() => undefined);
  }
  // Still re-checked on the bytes in hand: the file can grow between the `stat` and the read even
  // when both are on this descriptor.
  if (encoded.length > MAX_AUTHORIZED_ARTIFACT_BUNDLE_BYTES) {
    throw new ArtifactSignatureError("authorized artifact bundle exceeds its byte limit");
  }
  try {
    return validateAuthorizedArtifactBundle(JSON.parse(encoded.toString("utf8")));
  } catch (error) {
    if (error instanceof ArtifactSignatureError) throw error;
    throw new ArtifactSignatureError(`authorized artifact bundle is not JSON: ${(error as Error).message}`);
  }
}

/** Canonical JSON transport encoding. The signature itself covers the decoded payload bytes. */
export function encodeHostArtifactEnvelope(envelope: HostArtifactEnvelope): string {
  const checked = decodeHostArtifactEnvelope(envelope);
  return JSON.stringify(sortKeys(checked));
}

/** Strictly decode the small outer envelope without trusting or parsing its signed payload yet. */
export function decodeHostArtifactEnvelope(input: string | unknown): HostArtifactEnvelope {
  let value: unknown = input;
  if (typeof input === "string") {
    if (Buffer.byteLength(input, "utf8") > MAX_HOST_ARTIFACT_ENVELOPE_BYTES) {
      throw new ArtifactSignatureError("artifact authorization envelope exceeds its byte limit");
    }
    try {
      value = JSON.parse(input) as unknown;
    } catch {
      throw new ArtifactSignatureError("artifact authorization envelope is not JSON");
    }
  }
  if (!isRecord(value)) throw new ArtifactSignatureError("artifact authorization envelope is not an object");
  exactKeys(value, ["algorithm", "keyId", "payload", "signature", "version"], "envelope");
  if (value.version !== HOST_ARTIFACT_ENVELOPE_VERSION) {
    throw new ArtifactSignatureError(`unsupported artifact envelope version ${JSON.stringify(value.version)}`);
  }
  if (value.algorithm !== "Ed25519") {
    throw new ArtifactSignatureError(`unsupported artifact signature algorithm ${JSON.stringify(value.algorithm)}`);
  }
  if (typeof value.keyId !== "string" || !DIGEST.test(value.keyId)) {
    throw new ArtifactSignatureError("artifact envelope keyId is not an SPKI sha256 digest");
  }
  if (typeof value.payload !== "string") throw new ArtifactSignatureError("artifact envelope payload is not text");
  if (typeof value.signature !== "string") throw new ArtifactSignatureError("artifact envelope signature is not text");

  // Bound the base64 text before decoding. `input` may already be an object and therefore did not
  // pass through the encoded-envelope length check above.
  const maxPayloadText = Math.ceil(MAX_HOST_ARTIFACT_PAYLOAD_BYTES / 3) * 4;
  if (value.payload.length > maxPayloadText) {
    throw new ArtifactSignatureError("artifact authorization payload exceeds its byte limit");
  }
  decodeBase64Url(value.payload, "payload", MAX_HOST_ARTIFACT_PAYLOAD_BYTES, false);
  const sig = decodeBase64Url(value.signature, "signature", 64, false);
  if (sig.length !== 64) throw new ArtifactSignatureError("artifact envelope has a non-64-byte Ed25519 signature");

  const encodedBytes = Buffer.byteLength(JSON.stringify(value), "utf8");
  if (encodedBytes > MAX_HOST_ARTIFACT_ENVELOPE_BYTES) {
    throw new ArtifactSignatureError("artifact authorization envelope exceeds its byte limit");
  }
  return value as unknown as HostArtifactEnvelope;
}

/** Verify provenance, freshness, target and host before returning any applyable bytes. */
export function verifyHostArtifactAuthorization(
  input: string | unknown,
  options: VerifyHostAuthorizationOptions,
): HostArtifactAuthorizationPayload {
  const envelope = decodeHostArtifactEnvelope(input);
  const keys = trustedKeyIndex(options.trustedKeys);
  const trusted = keys.get(envelope.keyId);
  if (!trusted) throw new ArtifactSignatureError(`artifact was signed by untrusted key ${envelope.keyId}`);

  const payloadBytes = decodeBase64Url(
    envelope.payload,
    "payload",
    MAX_HOST_ARTIFACT_PAYLOAD_BYTES,
    false,
  );
  const signature = decodeBase64Url(envelope.signature, "signature", 64, false);
  if (!verify(null, signatureInput(envelope.keyId, payloadBytes), trusted.publicKey, signature)) {
    throw new ArtifactSignatureError("artifact authorization signature is invalid");
  }

  const text = decodeUtf8(payloadBytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new ArtifactSignatureError("signed artifact payload is not JSON");
  }
  if (canonicalJson(parsed) !== text) {
    throw new ArtifactSignatureError("signed artifact payload is not in canonical JSON form");
  }
  const payload = validatePayload(parsed);
  const requiredTrustClass: ArtifactSigningTrustClass =
    payload.authorizationMode === "break-glass" ? "break-glass" : "manager";
  if (trusted.trustClass !== requiredTrustClass) {
    throw new ArtifactSignatureError(
      `${payload.authorizationMode} authorization was signed by a ${trusted.trustClass} key; ` +
        `${requiredTrustClass} trust is required`,
    );
  }

  validateName(options.expectedTarget, "expectedTarget", 128);
  validateName(options.expectedHost, "expectedHost", 253);
  if (payload.target !== options.expectedTarget) {
    throw new ArtifactSignatureError(
      `artifact target ${JSON.stringify(payload.target)} does not match ${JSON.stringify(options.expectedTarget)}`,
    );
  }
  if (payload.host !== options.expectedHost) {
    throw new ArtifactSignatureError(
      `artifact host ${JSON.stringify(payload.host)} does not match ${JSON.stringify(options.expectedHost)}`,
    );
  }

  const now = options.now.getTime();
  if (!Number.isFinite(now)) throw new ArtifactSignatureError("verification clock is invalid");
  const skew = options.maxClockSkewMs ?? DEFAULT_AUTHORIZATION_CLOCK_SKEW_MS;
  if (!Number.isSafeInteger(skew) || skew < 0 || skew > 5 * 60 * 1000) {
    throw new ArtifactSignatureError("maxClockSkewMs must be an integer between 0 and 300000");
  }
  const authorized = Date.parse(payload.authorizedAt);
  const expires = Date.parse(payload.expiresAt);
  if (authorized > now + skew) throw new ArtifactSignatureError("artifact authorization is from the future");
  // Expiry has no grace period: skew is only for a manager clock that is slightly ahead, never a
  // reason to extend a signed capability beyond the exact instant it names.
  if (expires <= now) throw new ArtifactSignatureError("artifact authorization has expired");

  return payload;
}

function validatePayload(value: unknown): HostArtifactAuthorizationPayload {
  if (!isRecord(value)) throw new ArtifactSignatureError("signed artifact payload is not an object");
  exactKeys(value, [
    "authorizationMode", "authorizedAt", "bundleHash", "entry", "expiresAt", "host",
    "manifest", "planHash", "ruleset", "target", "version", "workload",
  ], "payload");
  if (value.version !== 1) throw new ArtifactSignatureError("unsupported signed artifact payload version");
  if (typeof value.target !== "string") throw new ArtifactSignatureError("payload target is not text");
  if (typeof value.host !== "string") throw new ArtifactSignatureError("payload host is not text");
  validateName(value.target, "target", 128);
  validateName(value.host, "host", 253);
  if (typeof value.planHash !== "string" || !DIGEST.test(value.planHash)) {
    throw new ArtifactSignatureError("payload planHash is not a sha256 digest");
  }
  if (typeof value.bundleHash !== "string" || !DIGEST.test(value.bundleHash)) {
    throw new ArtifactSignatureError("payload bundleHash is not a sha256 digest");
  }
  if (value.planHash !== planHashFromBundleHash(value.target, value.bundleHash)) {
    throw new ArtifactSignatureError("payload planHash does not bind its target and bundleHash");
  }
  if (typeof value.authorizationMode !== "string" || !MODES.has(value.authorizationMode as AuthorizationMode)) {
    throw new ArtifactSignatureError("payload authorizationMode is unsupported");
  }
  const authorizedAt = exactIso(value.authorizedAt as string, "authorizedAt");
  const expiresAt = exactIso(value.expiresAt as string, "expiresAt");
  validateAuthorizationWindow(authorizedAt, expiresAt, value.authorizationMode as AuthorizationMode);

  const manifest = validateManifestHeader(value.manifest);
  const entry = validateManifestEntry(value.entry, "payload.entry");
  if (typeof value.ruleset !== "string") throw new ArtifactSignatureError("payload ruleset is not text");
  const gotRuleset = "sha256:" + createHash("sha256").update(value.ruleset).digest("hex");
  if (entry.rulesetHash !== gotRuleset) {
    throw new ArtifactSignatureError("payload ruleset does not match the signed manifest entry hash");
  }
  if (value.workload !== null && typeof value.workload !== "string") {
    throw new ArtifactSignatureError("payload workload must be text or null");
  }
  if (entry.workload) {
    if (typeof value.workload !== "string") {
      throw new ArtifactSignatureError("payload omits the workload assigned by its manifest entry");
    }
    const gotWorkload = "sha256:" + createHash("sha256").update(value.workload).digest("hex");
    if (entry.workload.policiesHash !== gotWorkload) {
      throw new ArtifactSignatureError("payload workload does not match the signed manifest entry hash");
    }
  } else if (value.workload !== null) {
    throw new ArtifactSignatureError("payload carries workload without a manifest assignment");
  }
  if (Date.parse(manifest.issuedAt) > Date.parse(authorizedAt) + DEFAULT_AUTHORIZATION_CLOCK_SKEW_MS) {
    throw new ArtifactSignatureError("manifest issuedAt is later than artifact authorization");
  }

  return value as unknown as HostArtifactAuthorizationPayload;
}

function validateManifestHeader(value: unknown): ArtifactManifestHeader {
  if (!isRecord(value)) throw new ArtifactSignatureError("payload manifest is not an object");
  exactKeys(value, ["generation", "issuedAt", "schemaVersion"], "manifest");
  if (typeof value.generation !== "string" || value.generation.length < 1 || value.generation.length > 256) {
    throw new ArtifactSignatureError("manifest generation is empty or overlong");
  }
  exactIso(value.issuedAt as string, "manifest.issuedAt");
  if (value.schemaVersion !== SCHEMA_VERSION) {
    throw new ArtifactSignatureError(`manifest schemaVersion must be ${SCHEMA_VERSION}`);
  }
  return { generation: value.generation, issuedAt: value.issuedAt as string, schemaVersion: SCHEMA_VERSION };
}

function validateManifest(value: unknown): Manifest {
  if (!isRecord(value)) throw new ArtifactSignatureError("bundle manifest is not an object");
  exactKeys(value, ["generation", "hosts", "issuedAt", "schemaVersion"], "bundle manifest");
  const header = validateManifestHeader({
    generation: value.generation,
    issuedAt: value.issuedAt,
    schemaVersion: value.schemaVersion,
  });
  if (!isRecord(value.hosts)) throw new ArtifactSignatureError("manifest hosts is not an object");
  const names = Object.keys(value.hosts);
  if (names.length < 1 || names.length > 4096) {
    throw new ArtifactSignatureError("manifest host count is outside 1..4096");
  }
  const hosts: Record<string, ManifestEntry> = {};
  for (const name of names) {
    validateName(name, "manifest host", 253);
    hosts[name] = validateManifestEntry(value.hosts[name], `manifest.hosts[${JSON.stringify(name)}]`);
  }
  return { ...header, hosts };
}

function validateManifestEntry(value: unknown, where: string): ManifestEntry {
  if (!isRecord(value)) throw new ArtifactSignatureError(`${where} is not an object`);
  exactAllowedKeys(
    value,
    [
      "confirmTimeoutSec", "expectAddrs", "expectFilters", "maintenance", "mustContain",
      "routeGuard", "routes", "rulesetHash", "stage", "workload",
    ],
    ["confirmTimeoutSec", "mustContain", "rulesetHash", "stage"],
    where,
  );
  if (typeof value.stage !== "string" || !STAGES.has(value.stage as RolloutStage)) {
    throw new ArtifactSignatureError(`${where}.stage is unsupported`);
  }
  if (typeof value.rulesetHash !== "string" || !DIGEST.test(value.rulesetHash)) {
    throw new ArtifactSignatureError(`${where}.rulesetHash is not a sha256 digest`);
  }
  validateSeconds(value.confirmTimeoutSec, `${where}.confirmTimeoutSec`);
  validateStringArray(value.mustContain, `${where}.mustContain`, 4096, 2048);
  if (value.expectFilters !== undefined) validateStringArray(value.expectFilters, `${where}.expectFilters`, 256, 256);
  if (value.expectAddrs !== undefined) validateStringArray(value.expectAddrs, `${where}.expectAddrs`, 4096, 256);
  if (value.maintenance !== undefined &&
      (typeof value.maintenance !== "string" || value.maintenance.length < 1 || value.maintenance.length > 2048)) {
    throw new ArtifactSignatureError(`${where}.maintenance is empty or overlong`);
  }
  if (value.workload !== undefined) validateWorkloadEntry(value.workload, `${where}.workload`);
  validateRoutes(value, where);
  return value as unknown as ManifestEntry;
}

/**
 * The declared routes and the ranges they may not disturb.
 *
 * ## Why these were absent from the allowlist until 2026-08-22
 *
 * They were not omitted deliberately — `planPublish` has emitted both since the routing half was
 * written, and this validator has always refused unknown keys. So a host declaring a route produced
 * a manifest entry that could not be signed, and the failure was total: `payload.entry has
 * unsupported or missing fields`, for the whole generation rather than that host. Nothing hit it
 * only because no site module has declared an `owner: "heliopause"` route yet.
 *
 * ## The pair travels together, and `routes` alone is refused
 *
 * `routeGuard` names the management ranges the applier must not route over. It is derived from
 * `cfg.baseline` rather than kept as a second list, and it is the routing half's `mustContain`: a
 * route that moves the operator's return path confirms cleanly, because the heartbeat leaves by a
 * different one. An entry carrying routes without it is one that lost the field somewhere, and the
 * agent refuses that case too — the difference between "nothing is protected" and "we did not say"
 * is the whole lesson of the apply path.
 *
 * ## What is bounded here, and what is not
 *
 * Shape, length and count. Whether a route is *safe* is decided at the applier, which refuses a
 * default route, a prefix shorter than /8, a table other than main, a spec with neither `via` nor
 * `dev`, and anything covering the relay or a guarded range. That check stays there because only the
 * host knows its own relay address — and because a receiver that trusts a signature to mean "safe"
 * has confused provenance with correctness.
 */
function validateRoutes(value: Record<string, unknown>, where: string): void {
  if (value.routes === undefined) {
    if (value.routeGuard !== undefined) {
      throw new ArtifactSignatureError(`${where}.routeGuard travels only with routes`);
    }
    return;
  }
  if (!Array.isArray(value.routes) || value.routes.length < 1 || value.routes.length > 64) {
    throw new ArtifactSignatureError(`${where}.routes is not an array of 1..64 specs`);
  }
  for (const [index, spec] of value.routes.entries()) {
    const at = `${where}.routes[${index}]`;
    if (!isRecord(spec)) throw new ArtifactSignatureError(`${at} is not an object`);
    exactAllowedKeys(spec, ["dev", "dst", "table", "via"], ["dst"], at);
    for (const field of ["dst", "via", "dev", "table"] as const) {
      const item = spec[field];
      if (item === undefined) continue;
      if (typeof item !== "string" || item.length < 1 || item.length > 128 || hasUnpairedSurrogate(item)) {
        throw new ArtifactSignatureError(`${at}.${field} is empty, overlong, or not text`);
      }
    }
  }
  // Required alongside routes, and non-empty. `managementGuard` returns `[]` for a baseline whose
  // entries name no source — which is exactly what this site's baseline looks like — and an empty
  // guard would reach the applier as a list it accepts and then protects nothing. Refused at the
  // signer so a generation that cannot protect the management path is never authorized at all.
  validateStringArray(value.routeGuard, `${where}.routeGuard`, 64, 128);
  if ((value.routeGuard as string[]).length === 0) {
    throw new ArtifactSignatureError(
      `${where}.routeGuard is empty — routes cannot be published without the management ranges they ` +
        `must not disturb. Give the baseline entries a source, or do not declare heliopause-owned routes.`,
    );
  }
}

function validateWorkloadEntry(value: unknown, where: string): WorkloadEntry {
  if (!isRecord(value)) throw new ArtifactSignatureError(`${where} is not an object`);
  exactAllowedKeys(
    value,
    ["cluster", "confirmTimeoutSec", "ingressProtectedSelectors", "mustExist", "policiesHash", "policyCount", "watchSelectors"],
    ["cluster", "confirmTimeoutSec", "mustExist", "policiesHash", "policyCount"],
    where,
  );
  if (typeof value.policiesHash !== "string" || !DIGEST.test(value.policiesHash)) {
    throw new ArtifactSignatureError(`${where}.policiesHash is not a sha256 digest`);
  }
  if (typeof value.cluster !== "string" || value.cluster.length < 1 || value.cluster.length > 128) {
    throw new ArtifactSignatureError(`${where}.cluster is empty or overlong`);
  }
  validateStringArray(value.mustExist, `${where}.mustExist`, 128, 512);
  validateSeconds(value.confirmTimeoutSec, `${where}.confirmTimeoutSec`);
  if (!Number.isSafeInteger(value.policyCount) || (value.policyCount as number) < 0 || (value.policyCount as number) > 128) {
    throw new ArtifactSignatureError(`${where}.policyCount is outside 0..128`);
  }
  if (value.ingressProtectedSelectors !== undefined) {
    if (!Array.isArray(value.ingressProtectedSelectors) || value.ingressProtectedSelectors.length > 128) {
      throw new ArtifactSignatureError(`${where}.ingressProtectedSelectors exceeds its item limit`);
    }
    for (const [index, selector] of value.ingressProtectedSelectors.entries()) {
      validateStringMap(selector, `${where}.ingressProtectedSelectors[${index}]`, 32, 256);
    }
  }
  if (value.watchSelectors !== undefined) {
    if (!isRecord(value.watchSelectors)) throw new ArtifactSignatureError(`${where}.watchSelectors is not an object`);
    exactKeys(value.watchSelectors, ["labels", "namespaces"], `${where}.watchSelectors`);
    validateStringArray(value.watchSelectors.namespaces, `${where}.watchSelectors.namespaces`, 32, 256);
    validateStringArray(value.watchSelectors.labels, `${where}.watchSelectors.labels`, 32, 1024);
  }
  return value as unknown as WorkloadEntry;
}

function validateAuthorizationWindow(
  authorizedAt: string,
  expiresAt: string,
  mode: AuthorizationMode,
): void {
  const start = Date.parse(authorizedAt);
  const end = Date.parse(expiresAt);
  if (end <= start) throw new ArtifactSignatureError("expiresAt must be later than authorizedAt");
  if (end - start < MIN_HOST_AUTHORIZATION_LIFETIME_MS) {
    throw new ArtifactSignatureError("artifact authorization lifetime is shorter than 15 minutes");
  }
  const max = mode === "break-glass"
    ? MAX_BREAK_GLASS_AUTHORIZATION_LIFETIME_MS
    : MAX_MANAGER_AUTHORIZATION_LIFETIME_MS;
  if (end - start > max) {
    throw new ArtifactSignatureError(
      `artifact authorization lifetime exceeds the ${mode === "break-glass" ? "24-hour emergency" : "7-day manager"} limit`,
    );
  }
}

function planHashFromBundleHash(target: string, digest: string): string {
  const h = createHash("sha256");
  h.update(frame(Buffer.from("heliopause-plan-v1", "utf8")));
  h.update(frame(Buffer.from(target, "utf8")));
  h.update(frame(Buffer.from(digest, "utf8")));
  return "sha256:" + h.digest("hex");
}

function signatureInput(keyId: string, payload: Buffer): Buffer {
  return Buffer.concat([
    frame(Buffer.from(HOST_ARTIFACT_SIGNATURE_DOMAIN, "utf8")),
    frame(Buffer.from(keyId, "utf8")),
    frame(payload),
  ]);
}

function frame(bytes: Buffer): Buffer {
  if (bytes.length > 0xffff_ffff) throw new ArtifactSignatureError("signed field exceeds uint32 framing limit");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function encodeCanonicalPayload(payload: HostArtifactAuthorizationPayload): Buffer {
  const encoded = Buffer.from(canonicalJson(payload), "utf8");
  if (encoded.length > MAX_HOST_ARTIFACT_PAYLOAD_BYTES) {
    throw new ArtifactSignatureError("artifact authorization payload exceeds its byte limit");
  }
  return encoded;
}

function canonicalJson(value: unknown): string {
  boundedJson(value, "canonical JSON");
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) out[key] = sortKeys(value[key]);
    return out;
  }
  return value;
}

function boundedJson(root: unknown, where: string): void {
  let nodes = 0;
  const seen = new Set<object>();
  const walk = (value: unknown, depth: number): void => {
    if (++nodes > 100_000) throw new ArtifactSignatureError(`${where} has too many values`);
    if (depth > 32) throw new ArtifactSignatureError(`${where} is nested too deeply`);
    if (typeof value === "string") {
      if (hasUnpairedSurrogate(value)) throw new ArtifactSignatureError(`${where} contains invalid Unicode`);
      return;
    }
    if (value === null || typeof value === "boolean") return;
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value)) throw new ArtifactSignatureError(`${where} contains a non-integer or unsafe number`);
      return;
    }
    if (typeof value !== "object") throw new ArtifactSignatureError(`${where} contains a non-JSON value`);
    if (seen.has(value)) throw new ArtifactSignatureError(`${where} contains a cycle`);
    seen.add(value);
    if (Array.isArray(value)) {
      for (const item of value) walk(item, depth + 1);
    } else {
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new ArtifactSignatureError(`${where} contains a non-plain object`);
      }
      for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
        if (hasUnpairedSurrogate(key)) throw new ArtifactSignatureError(`${where} contains an invalid object key`);
        walk(item, depth + 1);
      }
    }
    seen.delete(value);
  };
  walk(root, 0);
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return true;
  }
  return false;
}

function exactIso(value: Date | string, where: string): string {
  const text = value instanceof Date ? value.toISOString() : value;
  if (typeof text !== "string") throw new ArtifactSignatureError(`${where} is not text`);
  const milliseconds = Date.parse(text);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== text) {
    throw new ArtifactSignatureError(`${where} is not an exact ISO 8601 UTC timestamp`);
  }
  return text;
}

function validateName(value: string, where: string, max: number): void {
  if (!SAFE_NAME.test(value) || value.length > max) {
    throw new ArtifactSignatureError(`${where} is empty, overlong, or contains unsafe characters`);
  }
}

function validateSeconds(value: unknown, where: string): void {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 86_400) {
    throw new ArtifactSignatureError(`${where} is outside 1..86400`);
  }
}

function validateStringArray(value: unknown, where: string, maxItems: number, maxLength: number): void {
  if (!Array.isArray(value) || value.length > maxItems) {
    throw new ArtifactSignatureError(`${where} is not an array within its item limit`);
  }
  for (const item of value) {
    if (typeof item !== "string" || item.length > maxLength || hasUnpairedSurrogate(item)) {
      throw new ArtifactSignatureError(`${where} contains a non-string or overlong value`);
    }
  }
}

function validateStringMap(value: unknown, where: string, maxItems: number, maxLength: number): void {
  if (!isRecord(value) || Object.keys(value).length > maxItems) {
    throw new ArtifactSignatureError(`${where} is not an object within its item limit`);
  }
  for (const [key, item] of Object.entries(value)) {
    if (key.length < 1 || key.length > maxLength || hasUnpairedSurrogate(key) ||
        typeof item !== "string" || item.length > maxLength || hasUnpairedSurrogate(item)) {
      throw new ArtifactSignatureError(`${where} contains a non-string or overlong key/value`);
    }
  }
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], where: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, i) => key !== wanted[i])) {
    throw new ArtifactSignatureError(`${where} has unsupported or missing fields`);
  }
}

function exactAllowedKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  required: readonly string[],
  where: string,
): void {
  const allowedSet = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedSet.has(key)) || required.some((key) => !(key in value))) {
    throw new ArtifactSignatureError(`${where} has unsupported or missing fields`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function decodeUtf8(bytes: Buffer): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new ArtifactSignatureError("signed artifact payload is not valid UTF-8");
  }
}

function decodeBase64Url(value: string, where: string, maxBytes: number, allowEmpty: boolean): Buffer {
  if ((!allowEmpty && value.length === 0) || (value.length > 0 && !BASE64URL.test(value))) {
    throw new ArtifactSignatureError(`artifact envelope ${where} is not canonical base64url`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length > maxBytes || decoded.toString("base64url") !== value) {
    throw new ArtifactSignatureError(`artifact envelope ${where} is invalid or overlong`);
  }
  return decoded;
}

function trustedKeyIndex(rings: ArtifactSigningTrustRings): Map<
  string,
  { keyId: string; publicKey: KeyObject; trustClass: ArtifactSigningTrustClass }
> {
  if (!rings || !Array.isArray(rings.manager) || !Array.isArray(rings.breakGlass)) {
    throw new ArtifactSignatureError("artifact signing trust rings are not configured");
  }
  if (rings.manager.length > 8 || rings.breakGlass.length > 8) {
    throw new ArtifactSignatureError("too many trusted artifact signing keys (limit is 8 per trust class)");
  }
  if (rings.manager.length + rings.breakGlass.length === 0) {
    throw new ArtifactSignatureError("no trusted artifact signing public key is configured");
  }
  const keys = new Map<string, {
    keyId: string;
    publicKey: KeyObject;
    trustClass: ArtifactSigningTrustClass;
  }>();
  for (const [trustClass, candidates] of [
    ["manager", rings.manager],
    ["break-glass", rings.breakGlass],
  ] as const) {
    for (const candidate of candidates) {
      const publicKey = asEd25519PublicKey(candidate);
      const keyId = artifactSigningKeyId(publicKey);
      if (keys.has(keyId)) {
        throw new ArtifactSignatureError(
          `artifact signing key ${keyId} is configured more than once or in both trust classes`,
        );
      }
      keys.set(keyId, { keyId, publicKey, trustClass });
    }
  }
  return keys;
}

function asEd25519PrivateKey(value: KeyObject | KeyLike): KeyObject {
  let key: KeyObject;
  try {
    key = value instanceof Object && "type" in value && "export" in value
      ? value as KeyObject
      : createPrivateKey(value as string | Buffer);
  } catch {
    throw new ArtifactSignatureError("artifact signing key is not a readable private key");
  }
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    throw new ArtifactSignatureError("artifact signing key must be a dedicated Ed25519 private key");
  }
  return key;
}

function asEd25519PublicKey(value: KeyObject | KeyLike): KeyObject {
  let key: KeyObject;
  try {
    key = value instanceof Object && "type" in value && "export" in value
      ? value as KeyObject
      : createPublicKey(value as KeyLike);
  } catch {
    throw new ArtifactSignatureError("artifact verification key is not a readable public key");
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw new ArtifactSignatureError("artifact verification key must be an Ed25519 public key");
  }
  return key;
}
