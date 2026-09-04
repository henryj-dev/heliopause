// The PKI heliopause issues for its own mTLS — policy and planning, no I/O.
//
// ## Why this exists at all
//
// The design document says two things, and only the first one is right:
//
//   1. "heliopause takes certificate file paths as configuration. It does not know who issued
//      them, nor whether the trust model is CA verification or pinning."
//   2. "certificate issuance and distribution are delegated to stardust."
//
// The first is proper decoupling. The second quietly converted "we don't need to know the issuer"
// into "another system must be the issuer", and that turned an unrelated repository into a hard
// prerequisite for turning on a firewall. A host firewall manager that cannot secure its own
// control channel without a second product is not finished.
//
// So heliopause issues its own. Statement 1 still holds — the relay and agent read paths and
// nothing here changes that, and an operator who *does* have a corporate CA keeps using it by
// pointing the config elsewhere. This is a default, not a requirement.
//
// ## openssl is the signing engine, this file is the policy
//
// Node's `crypto` can *read* X.509 (`X509Certificate`) but cannot sign one — measured, there is no
// certificate-creation API. Writing a DER/ASN.1 signer by hand to avoid a dependency that is
// already installed on every host (openssl 3.5.5 on all three, measured) would be inventing a
// cryptographic primitive to save a subprocess call.
//
// What must not live in shell scripts is the *policy*: which extensions, which validity, which
// subject. Those are the parts that decide whether a certificate is safe, so they are here, as
// data, testable without a filesystem or a subprocess.

/** What a certificate is allowed to do. Deliberately not a free-form string. */
/**
 * What a certificate is allowed to do. Deliberately not a free-form string.
 *
 * `operator` is a client role like `agent`, separated because it reads a different thing. An agent
 * fetches its own ruleset and reports its own state; an operator reads the whole fleet's. Issuing
 * one certificate that does both would mean a compromise of any single host yields an inventory of
 * every host, its generation, and whether its ruleset has drifted — a map for choosing the next
 * target. The relay checks the role by CN against an explicit allowlist.
 */
// `isIP` only, so this module stays pure: it decides what a certificate should say and performs no
// I/O. See `sanEntry` for why the hand-rolled address test it replaces was a hole rather than a
// simplification.
import { isIP } from "node:net";

export type CertRole = "ca" | "relay" | "agent" | "operator";

export class PkiError extends Error {
  override readonly name = "PkiError";
}

/**
 * ECDSA P-256, not RSA.
 *
 * Measured on this fleet: a Python agent talks to a Node relay over P-256 and the relay reads the
 * client CN correctly, which is the one property identity binding depends on. P-256 handshakes
 * cost meaningfully less CPU and produce smaller certificates than RSA-2048, and the gateways this
 * runs on have 1 vCPU and 948MB while also serving DHCP and WireGuard.
 */
export const CURVE = "prime256v1";

/**
 * Ten years for the CA, ninety days for leaves.
 *
 * The asymmetry is the point. Rotating the CA means touching every host's trust anchor at once —
 * the one operation that can lock out the whole fleet simultaneously — so it should be rare.
 * Rotating a leaf touches one host, and the agent's own rollback covers a host that gets it wrong.
 *
 * Ninety days rather than a year because an expiry that has never happened is an expiry nobody has
 * tested. At ninety days the renewal path gets exercised while the people who built it are still
 * around; at a year it gets exercised by whoever is on call in twelve months.
 */
export const CA_DAYS = 3650;
export const LEAF_DAYS = 90;

/** Renew this far ahead of expiry. Two intervals of slack over a weekend, not one. */
export const RENEW_BEFORE_DAYS = 30;

export interface CertRequest {
  /** Subject CN. For an agent this **must** be its host id — see `subjectFor`. */
  name: string;
  role: CertRole;
  /** DNS names and IPs a relay certificate is valid for. Rejected for other roles. */
  sans?: readonly string[];
  days?: number;
}

/** An openssl extension file's contents, plus the argv needed to apply it. */
export interface CertPlan {
  name: string;
  role: CertRole;
  subject: string;
  days: number;
  /**
   * Filename stem, **role-prefixed**. Not the same thing as `name`.
   *
   * The two differ because a gateway runs both the relay and its own agent, so it needs two
   * certificates whose CN is the same string. Naming files after the CN alone made the second
   * issuance silently overwrite the first — measured: `gw-01.dev.pem` came out as `clientAuth` with
   * no SAN, which is a relay certificate that every agent refuses on hostname verification. The
   * whole VPC would have stopped receiving policy, and the artifact left on disk looks fine.
   */
  fileBase: string;
  /** Lines of an openssl `-extfile`. Order is irrelevant; content is not. */
  extensions: string[];
}

/** `relay-gw-01.dev` / `agent-k3s-01.dev` / `ca`. Parsed back by `roleFromFileBase`. */
export function fileBaseFor(name: string, role: CertRole): string {
  return role === "ca" ? "ca" : `${role}-${name}`;
}

/** Inverse of `fileBaseFor`. Returns null for anything not issued by this tool. */
export function roleFromFileBase(base: string): { name: string; role: CertRole } | null {
  if (base === "ca") return { name: "heliopause-ca", role: "ca" };
  for (const role of ["relay", "agent", "operator"] as const) {
    if (base.startsWith(`${role}-`)) return { name: base.slice(role.length + 1), role };
  }
  return null;
}

const NAME_OK = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$/;

/**
 * The subject is the identity, so it gets validated rather than interpolated.
 *
 * The relay compares a heartbeat's `host` field against the client certificate's CN and returns
 * 403 when they differ. That check is the only thing stopping any holder of a valid certificate
 * from collecting another host's ruleset — so a CN carrying a comma, a slash or an equals sign
 * would not merely be untidy, it would be an opportunity to inject a second RDN and make the
 * subject ambiguous. Refuse instead.
 */
export function subjectFor(name: string): string {
  if (!NAME_OK.test(name)) {
    throw new PkiError(
      `certificate name ${JSON.stringify(name)} is not usable as a subject CN — expected letters, ` +
        `digits, dot, underscore or hyphen (1-64 chars, not starting or ending with punctuation). ` +
        `For an agent this must equal its HELIOPAUSE_HOST_ID exactly, because the relay compares ` +
        `the two and rejects a mismatch.`,
    );
  }
  return `/CN=${name}`;
}

/**
 * `10.17.0.1` / `::1` → IP SAN, a plausible hostname → DNS SAN, anything else → refused.
 *
 * ⚠️ **The IP test used to be `/^[0-9.]+$/.test(v) || v.includes(":")`, and the second half of that
 * disjunction turned the whole validation off.** Any value containing a colon was declared an IP
 * and skipped the name check entirely — including one containing a newline. The extensions this
 * builds are written out with `lines.join("\n")` into the openssl `-extfile`
 * (`bin/heliopause-pki.ts`, `withExtFile`), so a newline in a SAN is not a cosmetic problem: it is
 * **a second extension line, chosen by whoever supplied `--san`**. Measured — this was accepted:
 *
 *     planCert({name: "gw-01", role: "relay", sans: ["<v6 literal>\nbasicConstraints=critical,CA:TRUE"]})
 *
 * and the relay leaf comes back able to issue certificates. The everyday version of the same hole
 * is quieter and more likely: `--san=gw.example:8443` was silently minted as `IP:gw.example:8443`,
 * a SAN no client will ever match, so hostname verification fails later and somewhere else.
 *
 * `isIP` answers the question the regex was approximating, and answers it exactly — it rejects
 * anything with a stray character, which is every form this needs to refuse.
 */
function sanEntry(v: string): string {
  if (isIP(v)) return `IP:${v}`;
  // Address-shaped but not an address is refused, never demoted to a DNS SAN. `10.17.0.256` and
  // `10.17.0` both satisfy `NAME_OK` — they are digits and dots — so falling through would mint
  // `DNS:10.17.0.256`, a SAN that is syntactically fine and matches nothing, turning a typo in an
  // address into a hostname-verification failure discovered later and somewhere else. Whoever
  // wrote digits and colons meant an address; say the address is wrong.
  if (/^[0-9.]+$/.test(v) || v.includes(":")) {
    throw new PkiError(`subjectAltName ${JSON.stringify(v)} is written as an address but is not a valid one`);
  }
  if (!NAME_OK.test(v.replace(/\*\./, "x."))) {
    throw new PkiError(`subjectAltName ${JSON.stringify(v)} is neither an IP nor a plausible DNS name`);
  }
  return `DNS:${v}`;
}

/**
 * Turn a request into the exact extensions openssl should apply.
 *
 * ## Why the two leaf roles are separate
 *
 * `serverAuth` and `clientAuth` are issued as *different* roles rather than both being put on every
 * certificate for convenience. If an agent's certificate carried `serverAuth`, a host holding one
 * could stand up something that an agent would accept as its relay — and whatever an agent accepts
 * as its relay gets to set that host's firewall. That is the most valuable capability in this
 * system, so it is not handed out as a side effect of making issuance simpler.
 */
export function planCert(req: CertRequest): CertPlan {
  const subject = subjectFor(req.name);
  const days = req.days ?? (req.role === "ca" ? CA_DAYS : LEAF_DAYS);
  if (!Number.isInteger(days) || days < 1) {
    throw new PkiError(`validity must be a positive whole number of days, got ${req.days}`);
  }

  if (req.role === "ca") {
    if (req.sans?.length) throw new PkiError("a CA certificate takes no subjectAltName");
    return {
      name: req.name,
      role: req.role,
      subject,
      days,
      fileBase: fileBaseFor(req.name, req.role),
      extensions: [
        // `pathlen:0` — this CA may sign leaves and **may not sign another CA**. Without it, a
        // leaked leaf key that happened to be issued with CA:TRUE could mint further identities.
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "keyUsage=critical,keyCertSign,cRLSign",
        "subjectKeyIdentifier=hash",
      ],
    };
  }

  const eku = req.role === "relay" ? "serverAuth" : "clientAuth";
  const extensions = [
    // Critical, and FALSE. A leaf that can sign is a second CA.
    "basicConstraints=critical,CA:FALSE",
    `extendedKeyUsage=critical,${eku}`,
    "keyUsage=critical,digitalSignature",
    "subjectKeyIdentifier=hash",
    "authorityKeyIdentifier=keyid,issuer",
  ];

  if (req.role === "relay") {
    // A modern TLS client ignores CN for hostname verification and looks only at the SAN, so a
    // relay certificate without one fails verification everywhere — including in the Python agent,
    // whose `create_default_context` checks hostnames by default and has no unverified mode.
    if (!req.sans?.length) {
      throw new PkiError(
        `relay certificate ${req.name} needs at least one subjectAltName: agents verify the ` +
          `hostname and ignore CN, so a SAN-less certificate is refused by every client. Pass the ` +
          `address agents actually connect to (e.g. the gateway's private IP).`,
      );
    }
    extensions.push(`subjectAltName=${req.sans.map(sanEntry).join(",")}`);
  } else if (req.sans?.length) {
    // Client certificates are matched by CN, never by SAN. Accepting one here would let two
    // identities travel in one certificate while only one of them is the one the relay checks.
    throw new PkiError(
      `${req.role} certificate ${req.name} must not carry a subjectAltName — the relay identifies ` +
        `a client by CN, so a SAN would be an identity nothing verifies`,
    );
  }

  return { name: req.name, role: req.role, subject, days, fileBase: fileBaseFor(req.name, req.role), extensions };
}

export interface CertStatus {
  name: string;
  notAfter: Date;
  daysLeft: number;
  expired: boolean;
  dueForRenewal: boolean;
}

/** Days until `notAfter`, and whether that is close enough to act on. Pure, so it is testable. */
export function certStatus(name: string, notAfter: Date, now: Date): CertStatus {
  const daysLeft = Math.floor((notAfter.getTime() - now.getTime()) / 86_400_000);
  return {
    name,
    notAfter,
    daysLeft,
    expired: daysLeft < 0,
    dueForRenewal: daysLeft <= RENEW_BEFORE_DAYS,
  };
}

/**
 * Which hosts a site needs certificates for, derived from the site itself.
 *
 * Taking this from the site module rather than from a hand-kept list means the answer to "did every
 * host get a certificate" has the same source as "which hosts get a ruleset". A host added to the
 * site and forgotten here would fail to heartbeat, and its firewall would silently never update.
 */
export function requiredCerts(hostIds: readonly string[], relayName: string, relaySans: readonly string[]): CertRequest[] {
  if (!hostIds.length) throw new PkiError("the site names no hosts, so there is nothing to issue");
  const seen = new Set<string>();
  for (const id of hostIds) {
    if (seen.has(id)) throw new PkiError(`host ${id} appears twice`);
    seen.add(id);
  }
  return [
    { name: relayName, role: "relay", sans: relaySans },
    ...hostIds.map((name): CertRequest => ({ name, role: "agent" })),
  ];
}

/**
 * Explain a TLS chain failure as what it nearly always is: the wrong VPC's CA.
 *
 * **Each VPC has its own certificate authority, and all of them are named `CN=heliopause-ca`.**
 * Measured 2026-08-10 — three distinct keys, dev issued 2026-07-31 and prod·util 2026-08-02. So an
 * operator certificate authenticates to exactly one VPC; presented to another relay it fails during
 * the handshake, before any authorisation decision. The relay's `HELIOPAUSE_OPERATOR_CNS` may list
 * that operator and will never be consulted.
 *
 * The reason this needs a message rather than a comment is that OpenSSL's wording for it —
 * `self-signed certificate in certificate chain` — reads like a broken deployment. On the day it was
 * found, the first hypothesis was that a release had broken certificate trust; the three CAs had
 * been sitting side by side for eight days. A caller who reads the raw error goes looking in the
 * wrong place.
 *
 * Returns "" when there is nothing useful to add, so callers can always concatenate.
 *
 * @param code    Node's `err.code` from the request's error event.
 * @param siteMode Whether `--site` was used, i.e. the failure is the manager's, not a relay's.
 * @param pkiDir  The directory whose `ca.pem` was trusted, named so the operator can check it.
 */
export function wrongCaHint(code: string | undefined, siteMode: boolean, pkiDir: string): string {
  const chainFailure =
    code === "SELF_SIGNED_CERT_IN_CHAIN" || code === "UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
  // In `--site` mode the manager is the thing that failed, and the manager is also the advice this
  // hint would give. Repeating it would send an operator in a circle.
  if (!chainFailure || siteMode) return "";
  return (
    `\n  The CA in ${pkiDir} did not issue this relay's certificate. Each VPC has its own CA,` +
    `\n  so an operator certificate authenticates to one VPC only. To read every VPC, ask the` +
    `\n  manager instead: heliopause-status <manager-url> --site`
  );
}
