// The public server certificate, fetched from stardust's cert-api.
//
// ## Why fetched rather than mounted
//
// The certificate for the console's public name is issued by cert-manager and lives in a Secret in
// the `vm-certs` namespace. Secrets do not cross namespaces and this cluster runs no reflector, so a
// pod in `heliopause` cannot mount it.
//
// The obvious workaround — a second `Certificate` in this namespace for the same name — was written
// and then thrown away. Two independent ACME orders for one DNS name compete for the same
// `_acme-challenge` TXT record, and the failure mode is *renewal quietly not happening*: exactly the
// ninety-day trap the whole arrangement exists to avoid. There is already one certificate, managed
// and auditable through the dashboard like every other certificate on this site. This reads it.
//
// The token is scoped to a single certificate name — the dispatcher checks revocation, expiry **and**
// that the name is in the token's scope list — so what this credential can do is fetch one public
// certificate. It is not an admin token.
//
// ## The failure direction is chosen, not incidental
//
// This runs inside the firewall control plane. If the dispatcher is unreachable when the manager
// starts, the manager must still start: the operator CLI verifies against the internal CA and does
// not need this at all, so a fetch failure may cost the browser path and nothing else. Every function
// here returns or throws in a way that lets the caller carry on without a public certificate.

import { createPrivateKey, X509Certificate } from "node:crypto";
import { BodyTooLargeError, readBoundedText } from "./bounded-body.ts";

/**
 * The most this will read of a certificate bundle.
 *
 * A cert plus a key is a few kilobytes; a chain with several intermediates is still well under a
 * hundred. This is the bound on what the manager will buffer for one, for the reason `oidc.ts`
 * bounds its own reads: the process holds the artifact signing key and runs as a single pod, so an
 * unbounded body from any external service is an outage of the control plane.
 */
export const MAX_CERT_BUNDLE_BYTES = 1024 * 1024;

/** A certificate and its key, as PEM. */
export interface CertBundle {
  cert: string;
  key: string;
  /** Fingerprint of the leaf, for deciding whether anything actually changed. */
  fingerprint: string;
  /**
   * DNS names the certificate itself carries, lowercased and sorted.
   *
   * Here so a caller can report what it is *serving* separately from what it is *configured to
   * answer for*. On 2026-08-11 the manager's startup line named the SNI allowlist and nothing else,
   * and both teams read that list as the certificate's SAN — for half a day, while the certificate
   * in memory still carried a third name that had been removed from the allowlist. The two lists
   * are usually equal, which is exactly why nobody checks.
   */
  sans: string[];
}

export interface CertApiOptions {
  /** Base URL of the dispatcher's mesh service — `https://10.17.192.11`. */
  baseUrl: string;
  /** Certificate name, which is also what the token is scoped to. */
  name: string;
  /** The `stcert_…` bearer token. */
  token: string;
  timeoutMs?: number;
}

export class CertApiError extends Error {
  readonly status: number;
  constructor(message: string, status = 0) {
    super(message);
    this.name = "CertApiError";
    this.status = status;
  }
}

/**
 * Fetch one certificate bundle.
 *
 * Validates before returning. A bundle that does not parse, or whose key does not match its
 * certificate, is worse than no bundle: it would be installed as a TLS context and fail every
 * handshake for that name, which reads like a network problem rather than a bad file.
 */
export async function fetchCert(o: CertApiOptions, fetchImpl: typeof fetch = fetch): Promise<CertBundle> {
  if (!o.baseUrl.startsWith("https://")) {
    throw new CertApiError(`refusing to fetch a private key over plaintext (${o.baseUrl})`);
  }
  if (!o.token.startsWith("stcert_")) {
    throw new CertApiError("cert-api token does not look like one (expected a stcert_ prefix)");
  }
  const url = `${o.baseUrl.replace(/\/$/, "")}/cert-api/v1/certs/${encodeURIComponent(o.name)}`;
  const res = await fetchImpl(url, {
    headers: { authorization: `Bearer ${o.token}`, accept: "application/json" },
    redirect: "error",
    signal: AbortSignal.timeout(o.timeoutMs ?? 10_000),
  });
  if (!res.ok) {
    // 401 here means the token is revoked, expired, or not scoped to this name — three different
    // operator actions, and the dispatcher does not distinguish them. Say what to check.
    const hint = res.status === 401 ? " — token revoked, expired, or not scoped to this certificate" : "";
    throw new CertApiError(`cert-api answered ${res.status} for ${o.name}${hint}`, res.status);
  }
  // Bounded, not `res.json()`. The failure direction this file chose is that a fetch failure costs
  // the browser path and nothing else — which only holds if the failure is a thrown `CertApiError`
  // and not the pod running out of memory.
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(await readBoundedText(res, MAX_CERT_BUNDLE_BYTES, `cert-api ${o.name}`)) as Record<string, unknown>;
  } catch (e) {
    if (e instanceof BodyTooLargeError) throw new CertApiError(e.message, res.status);
    body = {};
  }
  if (typeof body.cert !== "string" || typeof body.key !== "string" || !body.cert || !body.key) {
    throw new CertApiError(`cert-api returned no cert/key for ${o.name}`, res.status);
  }
  return validate(body.cert, body.key, o.name);
}

/**
 * Parse the pair and check they belong together.
 *
 * `checkPrivateKey` is the part worth having. A cert and a key that are each individually valid but
 * unrelated is a plausible mistake on the serving side, and Node accepts them into a SecureContext
 * without complaint — the failure appears later, per handshake, as an error the client sees and the
 * server logs nothing about.
 */
function validate(cert: string, key: string, name: string): CertBundle {
  let x: X509Certificate;
  try {
    x = new X509Certificate(cert);
  } catch (e) {
    throw new CertApiError(`certificate for ${name} does not parse: ${(e as Error).message}`);
  }
  try {
    if (!x.checkPrivateKey(createPrivateKeyOrThrow(key, name))) {
      throw new CertApiError(`the key returned for ${name} does not match its certificate`);
    }
  } catch (e) {
    if (e instanceof CertApiError) throw e;
    throw new CertApiError(`key for ${name} is unusable: ${(e as Error).message}`);
  }
  // Expiry is reported, not enforced. Refusing an expired certificate here would take the browser
  // path down at the moment somebody needs the console to find out why renewal stopped.
  return { cert, key, fingerprint: x.fingerprint256, sans: dnsNames(x) };
}

/**
 * The `DNS:` entries of `subjectAltName`, lowercased and sorted.
 *
 * `subjectAltName` is a display string — `DNS:a.example, IP Address:10.0.0.1` — so this takes the
 * DNS entries and drops the rest. An unparseable or absent value yields `[]` rather than throwing:
 * this is for reporting, and a certificate that works but describes itself oddly should not stop
 * the manager from serving it.
 */
function dnsNames(x: X509Certificate): string[] {
  const raw = x.subjectAltName;
  if (!raw) return [];
  return raw
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.toLowerCase().startsWith("dns:"))
    .map((part) => part.slice(4).trim().toLowerCase())
    .sort();
}

function createPrivateKeyOrThrow(pem: string, name: string) {
  try {
    return createPrivateKey(pem);
  } catch (e) {
    throw new CertApiError(`key for ${name} does not parse: ${(e as Error).message}`);
  }
}

/**
 * How long until this certificate expires, in whole days. Negative once it has.
 *
 * Floored rather than returned raw. The only caller prints it — `expires in ${days} day(s)` in the
 * manager's refresh log — and an unrounded value renders as `expires in 74.53157407407407 day(s)`,
 * which reads as a number nobody meant to show. Floor rather than round because the question is
 * "how many whole days of validity are left", and rounding 0.6 up to 1 would report a day of
 * validity that does not exist on the morning it matters.
 */
export function daysUntilExpiry(cert: string, now = new Date()): number {
  const x = new X509Certificate(cert);
  return Math.floor((new Date(x.validTo).getTime() - now.getTime()) / 86_400_000);
}
