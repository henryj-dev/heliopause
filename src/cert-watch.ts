// How close a certificate is to expiring, as one word — and the facts it was judged from.
//
// Pure. The relay records what an agent presented and the manager reports it; neither decides what
// "close" means on its own, so the two cannot disagree about which certificate needs attention.
//
// The thresholds travel with every report (`CERT_THRESHOLDS`). A consumer that re-derives the state
// from `daysLeft` with its own numbers is a second copy of this rule, and the copy is the one that
// goes stale.

import { X509Certificate } from "node:crypto";
import { RENEW_BEFORE_DAYS } from "./pki.ts";

/** Inside this many days the certificate is an incident rather than a chore. */
export const CRITICAL_DAYS = 7;

export const CERT_THRESHOLDS = { renewBeforeDays: RENEW_BEFORE_DAYS, criticalDays: CRITICAL_DAYS } as const;

export type CertState = "ok" | "renew" | "critical" | "expired" | "unknown";

const DAY_MS = 86_400_000;

/**
 * The state of a certificate whose `notAfter` is given.
 *
 * `unknown` when the date does not parse. Not `ok`: a certificate this code cannot read is one it
 * cannot vouch for, and defaulting the other way is how a check reports health it never measured.
 *
 * `daysLeft` is whole days, rounded down, so a certificate with 7.9 days left is critical — the
 * renewal has to happen inside the window, not on its last afternoon.
 */
export function certState(
  notAfter: string | Date | null | undefined,
  now: Date,
): { state: CertState; daysLeft: number | null } {
  const when = notAfter instanceof Date ? notAfter : notAfter ? new Date(notAfter) : null;
  if (!when || Number.isNaN(when.getTime())) return { state: "unknown", daysLeft: null };
  const ms = when.getTime() - now.getTime();
  // Expired: whole days since, negated — a certificate one second past its end is 0 days, not -1.
  if (ms <= 0) return { state: "expired", daysLeft: -Math.floor(-ms / DAY_MS) || 0 };
  const daysLeft = Math.floor(ms / DAY_MS);
  if (daysLeft <= CRITICAL_DAYS) return { state: "critical", daysLeft };
  if (daysLeft <= RENEW_BEFORE_DAYS) return { state: "renew", daysLeft };
  return { state: "ok", daysLeft };
}

/** What a report says about one certificate, independent of where it was seen. */
export interface CertFacts {
  cn: string | null;
  serial: string;
  /** Lower-case hex, no separators — the same shape the enrollment store uses. */
  sha256: string;
  notBefore: string;
  notAfter: string;
}

/** How many certificates a PEM file holds. `certFactsFromPem` reads only the first. */
export function pemCertificateCount(pem: string | Buffer): number {
  return (String(pem).match(/-----BEGIN CERTIFICATE-----/g) ?? []).length;
}

/** Facts from the first certificate in a PEM file. Throws on anything that is not one. */
export function certFactsFromPem(pem: string | Buffer): CertFacts {
  const x = new X509Certificate(pem);
  return {
    cn: /(?:^|\n)CN=([^\n]*)/.exec(x.subject)?.[1] ?? null,
    serial: x.serialNumber,
    sha256: x.fingerprint256.replaceAll(":", "").toLowerCase(),
    notBefore: new Date(x.validFrom).toISOString(),
    notAfter: new Date(x.validTo).toISOString(),
  };
}

/** The subset of `tls.PeerCertificate` this module reads. */
export interface PeerCertificateLike {
  /** An array when the certificate carries several CNs — ambiguous, so read as no name. */
  subject?: { CN?: string | string[] };
  serialNumber?: string;
  fingerprint256?: string;
  valid_from?: string;
  valid_to?: string;
}

/**
 * Facts from what a TLS peer presented, or null when the presentation is incomplete.
 *
 * Null rather than a partial record: a row with a serial and no expiry would be reported as
 * `unknown`, which is correct, but it would also be counted as observed — and the count is what
 * tells a reader whether every certificate was seen.
 */
export function certFactsFromPeer(peer: PeerCertificateLike | null | undefined): CertFacts | null {
  if (!peer?.serialNumber || !peer.fingerprint256 || !peer.valid_from || !peer.valid_to) return null;
  const notBefore = new Date(peer.valid_from);
  const notAfter = new Date(peer.valid_to);
  if (Number.isNaN(notBefore.getTime()) || Number.isNaN(notAfter.getTime())) return null;
  return {
    cn: typeof peer.subject?.CN === "string" ? peer.subject.CN : null,
    serial: peer.serialNumber,
    sha256: peer.fingerprint256.replaceAll(":", "").toLowerCase(),
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
  };
}
