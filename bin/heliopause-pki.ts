#!/usr/bin/env node
// Issue and renew the mTLS certificates heliopause uses for its own control channel.
//
//   heliopause-pki init   <dir>                      create the CA
//   heliopause-pki issue  <dir> <name> --role=…       issue or replace one certificate
//   heliopause-pki site   <dir> <site-module>         issue everything a site needs
//   heliopause-pki status <dir>                       what expires when
//   heliopause-pki renew  <dir> [--force]             reissue what is due
//   heliopause-pki sign-csr <dir> <csr> <out> --name=HOST --expect-sha256=HEX
//
// This exists because the design document's "delegate issuance to stardust" turned a separate
// repository into a hard prerequisite for turning on a firewall. See the header of src/pki.ts.
// An operator with a corporate CA ignores this command and points the config at their own files;
// the relay and agent only ever read paths.
//
// Policy — extensions, validity, subject rules — lives in src/pki.ts and is unit tested. This file
// is the I/O: it runs openssl, sets permissions, and prints.

import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { X509Certificate, createHash, createPublicKey } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  CURVE,
  LEAF_DAYS,
  PkiError,
  certStatus,
  planCert,
  requiredCerts,
  roleFromFileBase,
  type CertPlan,
  type CertRole,
} from "../src/pki.ts";

import { installCliLanguage } from "../src/operator-i18n.ts";

const lang = installCliLanguage();
const args = process.argv.slice(2);
const flags = new Map(
  args.filter((a) => a.startsWith("--")).map((a) => {
    const [k, v] = a.replace(/^--/, "").split("=", 2);
    return [k!, v ?? "true"];
  }),
);
const positional = args.filter((a) => !a.startsWith("--"));
const [cmd, dirArg, ...rest] = positional;

const USAGE = lang === "ko" ? `사용법:
  heliopause-pki init   <dir>                      CA를 생성
  heliopause-pki issue  <dir> <name> --role=…       인증서를 발급 또는 교체
  heliopause-pki site   <dir> <site-module>         사이트에 필요한 인증서를 모두 발급
  heliopause-pki status <dir>                       인증서 만료 시점을 표시
  heliopause-pki renew  <dir> [--force]             기한이 된 인증서를 다시 발급
  heliopause-pki sign-csr <dir> <csr> <out> --name=HOST --expect-sha256=HEX [--days=N]`
  : `usage:
  heliopause-pki init   <dir>
  heliopause-pki issue  <dir> <name> --role=relay|agent [--san=addr,addr] [--days=N]
  heliopause-pki site   <dir> <site-module> [--relay-name=NAME] [--san=addr,addr]
  heliopause-pki status <dir>
  heliopause-pki renew  <dir> [--force]
  heliopause-pki sign-csr <dir> <csr> <out> --name=HOST --expect-sha256=HEX [--days=N]`;

if (!cmd || !dirArg) {
  console.error(USAGE);
  process.exit(2);
}

const dir = resolve(dirArg);
const caKey = join(dir, "ca.key");
const caCert = join(dir, "ca.pem");

const openssl = (...a: string[]): string => {
  try {
    return execFileSync("openssl", a, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    const err = e as { stderr?: Buffer | string; message: string };
    const detail = String(err.stderr ?? err.message).trim();
    throw new PkiError(`openssl ${a[0]} failed: ${detail}`);
  }
};

/**
 * A private key is written 0600 before anything is written *into* it.
 *
 * `openssl genpkey -out` creates the file with the process umask, so on a default umask the key is
 * briefly world-readable. Narrow the file first, then let openssl write through the existing inode.
 */
function generateKey(path: string): void {
  writeFileSync(path, "", { mode: 0o600 });
  chmodSync(path, 0o600);
  openssl("genpkey", "-algorithm", "EC", "-pkeyopt", `ec_paramgen_curve:${CURVE}`, "-out", path);
  chmodSync(path, 0o600);
}

/** Write the extension file in a private temp dir — it names the identity being minted. */
function withExtFile<T>(lines: string[], fn: (path: string) => T): T {
  const tmp = mkdtempSync(join(tmpdir(), "heliopause-pki-"));
  try {
    const path = join(tmp, "ext.cnf");
    writeFileSync(path, lines.join("\n") + "\n", { mode: 0o600 });
    return fn(path);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function requireCa(): void {
  if (!existsSync(caCert) || !existsSync(caKey)) {
    throw new PkiError(`no CA in ${dir} — run \`heliopause-pki init ${dirArg}\` first`);
  }
}

function initCa(): void {
  if (existsSync(caCert)) {
    throw new PkiError(
      `${caCert} already exists. Refusing to overwrite: a new CA invalidates every certificate ` +
        `already issued from the old one, which means every agent stops being able to reach its ` +
        `relay at the same moment. Move the directory aside deliberately if that is the intent.`,
    );
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const plan = planCert({ name: "heliopause-ca", role: "ca" });
  generateKey(caKey);
  // `openssl req` takes no -extfile — measured, it rejects the flag outright. Extensions reach it
  // through a config file with a named section plus `-extensions`, unlike `openssl x509` which does
  // take -extfile. Same policy lines either way; only the plumbing differs.
  withExtFile(["[v3_ca]", ...plan.extensions], (ext) => {
    openssl(
      "req", "-x509", "-new", "-key", caKey, "-days", String(plan.days),
      "-subj", plan.subject, "-out", caCert, "-config", ext, "-extensions", "v3_ca",
    );
  });
  chmodSync(caCert, 0o644);
  const cert = new X509Certificate(readFileSync(caCert));
  console.log(`CA created: ${caCert}`);
  console.log(`  subject   ${cert.subject.replace(/\n/g, " ")}`);
  console.log(`  expires   ${cert.validTo}`);
  console.log(`  key       ${caKey} (0600 — this file is the trust root; back it up somewhere else)`);
}

function issue(plan: CertPlan): void {
  requireCa();
  // fileBase, not name — a gateway needs a relay and an agent certificate sharing one CN, and
  // naming by CN alone made the second overwrite the first. See CertPlan.fileBase.
  const key = join(dir, `${plan.fileBase}.key`);
  const crt = join(dir, `${plan.fileBase}.pem`);
  const csr = join(dir, `${plan.fileBase}.csr`);
  generateKey(key);
  try {
    openssl("req", "-new", "-key", key, "-subj", plan.subject, "-out", csr);
    withExtFile(plan.extensions, (ext) => {
      openssl(
        "x509", "-req", "-in", csr, "-CA", caCert, "-CAkey", caKey, "-CAcreateserial",
        "-days", String(plan.days), "-out", crt, "-extfile", ext,
      );
    });
  } finally {
    rmSync(csr, { force: true });
  }
  chmodSync(crt, 0o644);
  const cert = new X509Certificate(readFileSync(crt));
  console.log(`  ${plan.role.padEnd(5)} ${plan.fileBase.padEnd(22)} CN=${plan.name.padEnd(16)} expires ${cert.validTo}`);
}

/** Sign a host-generated CSR while keeping both private keys on their respective machines. */
function signCsr(csrArg: string, outArg: string): void {
  requireCa();
  const csr = resolve(csrArg);
  const out = resolve(outArg);
  const name = flags.get("name");
  if (!name) throw new PkiError("sign-csr requires --name=HOST");
  const expected = (flags.get("expect-sha256") ?? "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expected)) {
    throw new PkiError("sign-csr requires --expect-sha256=<64 hex chars> copied from the host console");
  }
  if (!existsSync(csr)) throw new PkiError(`CSR not found: ${csr}`);
  if (existsSync(out)) throw new PkiError(`refusing to overwrite existing output: ${out}`);

  // Mandatory rather than informational: the digest has to come from the host console over a
  // second channel. A stolen bootstrap token can submit a different CSR under the same hostname.
  // Dispatcher fingerprints the PKCS#10 DER, not its PEM text representation. PEM line endings
  // and wrapping are transport details; hashing them would make the same CSR show a different
  // value after a harmless re-encode and would never match the enrollment queue.
  const der = execFileSync("openssl", ["req", "-in", csr, "-outform", "DER"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  const actual = createHash("sha256").update(der).digest("hex");
  if (actual !== expected) {
    throw new PkiError(`CSR SHA-256 mismatch: expected ${expected}, downloaded file is ${actual}`);
  }
  openssl("req", "-in", csr, "-noout", "-verify");
  const subject = openssl("req", "-in", csr, "-noout", "-subject", "-nameopt", "RFC2253").trim();
  const plan = planCert({
    name,
    role: "agent",
    days: flags.has("days") ? Number(flags.get("days")) : undefined,
  });
  if (subject !== `subject=CN=${name}`) {
    throw new PkiError(`CSR subject mismatch: expected exactly CN=${name}, got ${subject.replace(/^subject=/, "")}`);
  }
  const publicKey = createPublicKey(openssl("req", "-in", csr, "-pubkey", "-noout"));
  if (publicKey.asymmetricKeyType !== "ec" || publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new PkiError("CSR public key must be ECDSA P-256 (prime256v1)");
  }

  // No copy_extensions: the untrusted CSR cannot ask for serverAuth, SAN, or CA capability. The
  // only extensions on the result are the agent plan from the same policy used by normal issue.
  withExtFile(plan.extensions, (ext) => {
    openssl(
      "x509", "-req", "-in", csr, "-CA", caCert, "-CAkey", caKey, "-CAcreateserial",
      "-days", String(plan.days), "-out", out, "-extfile", ext,
    );
  });
  chmodSync(out, 0o644);
  openssl("verify", "-CAfile", caCert, out);
  const cert = new X509Certificate(readFileSync(out));
  console.log(`signed agent CSR: ${out}`);
  console.log(`  CN        ${name}`);
  console.log(`  csr sha   ${actual}`);
  console.log(`  expires   ${cert.validTo}`);
}

function parseRole(v: string | undefined): CertRole {
  // `ca` is deliberately absent: the CA is created by `init`, which refuses to overwrite an
  // existing one. Reaching it through `issue` would let a second CA be minted over the first.
  if (v === "relay" || v === "agent" || v === "operator") return v;
  throw new PkiError(`--role must be relay, agent or operator, got ${v ?? "(missing)"}`);
}

const sans = (): string[] =>
  (flags.get("san") ?? "").split(",").map((s) => s.trim()).filter(Boolean);

interface Issued {
  fileBase: string;
  name: string;
  role: CertRole;
  cert: X509Certificate;
}

/**
 * Certificates present in the directory, CA excluded — it is checked separately.
 *
 * The role comes from the filename, not from inspecting the certificate. Inferring "has a SAN ⇒
 * relay" would work today but would silently reissue with the wrong role the moment a certificate
 * arrives from somewhere else, and getting that wrong on renewal means handing an agent a
 * `serverAuth` certificate — the one thing planCert refuses to do deliberately.
 */
function issued(): Issued[] {
  const out: Issued[] = [];
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".pem") || f === "ca.pem") continue;
    const fileBase = f.replace(/\.pem$/, "");
    const parsed = roleFromFileBase(fileBase);
    if (!parsed || parsed.role === "ca") {
      console.error(`  (skipping ${f} — not named by this tool, so its role is unknown)`);
      continue;
    }
    out.push({ fileBase, ...parsed, cert: new X509Certificate(readFileSync(join(dir, f))) });
  }
  return out;
}

/** Reconstruct a plan from a certificate that already exists, so renewal keeps its role and SANs. */
function planFromExisting(i: Issued): CertPlan {
  const days = Number(flags.get("days") ?? LEAF_DAYS);
  if (i.role !== "relay") return planCert({ name: i.name, role: "agent", days });
  const sans = (i.cert.subjectAltName ?? "")
    .split(",")
    .map((s) => s.trim().replace(/^(DNS|IP Address|IP):/, ""))
    .filter(Boolean);
  return planCert({ name: i.name, role: "relay", sans, days });
}

try {
  switch (cmd) {
    case "init":
      initCa();
      break;

    case "issue": {
      const [name] = rest;
      if (!name) throw new PkiError("issue needs a name");
      const role = parseRole(flags.get("role"));
      const days = flags.has("days") ? Number(flags.get("days")) : undefined;
      console.log(`issuing from ${caCert}`);
      issue(planCert({ name, role, sans: role === "relay" ? sans() : undefined, days }));
      break;
    }

    // The whole point: the certificate set is derived from the same site module the publisher
    // renders, so a host cannot be in one and missing from the other.
    case "site": {
      const [siteArg] = rest;
      if (!siteArg) throw new PkiError("site needs a site module path");
      const mod = (await import(pathToFileURL(resolve(siteArg)).href)) as {
        site?: { cfg: { relay?: { url: string } }; hosts: Array<{ id: string; stage: string }> };
      };
      if (!mod.site) throw new PkiError(`${siteArg} does not export \`site\``);
      const relayUrl = mod.site.cfg.relay?.url;
      if (!relayUrl) throw new PkiError(`${siteArg}'s config has no relay.url, so there is no relay to name`);

      // `URL.hostname` brackets an IPv6 literal; a SAN must not carry the brackets.
      const dialed = new URL(relayUrl).hostname.replace(/^\[|\]$/g, "");

      // The relay certificate's SAN must cover the address agents actually dial — that is what
      // hostname verification checks, and it is the only field that matters for the relay. Its CN
      // is never verified, so it is named after the gateway host instead of after the address,
      // which keeps `relay-gw-01.dev.pem` readable when the URL is a bare IP.
      const gateway = mod.site.hosts.find((h) => h.stage === "gateway");
      const relayName = flags.get("relay-name") ?? gateway?.id ?? dialed;
      const relaySans = sans().length ? sans() : [dialed];
      if (!relaySans.includes(dialed)) relaySans.push(dialed);

      if (!existsSync(caCert)) initCa();
      console.log(`issuing for ${mod.site.hosts.length} host(s) + relay`);
      for (const req of requiredCerts(mod.site.hosts.map((h) => h.id), relayName, relaySans)) {
        issue(planCert(req));
      }
      console.log(`\ndone. Distribute per host:`);
      console.log(`  ca.pem            → /etc/heliopause/pki/ca.pem      (every host)`);
      console.log(`  <host>.pem/.key   → /etc/heliopause/pki/agent.pem|agent.key`);
      console.log(`  ${relayName}.pem/.key → /etc/heliopause/pki/relay.pem|relay.key (gateway only)`);
      console.log(`Keys must be 0600 root:root; the relay unit reads its key via LoadCredential.`);
      break;
    }

    case "status": {
      requireCa();
      const now = new Date();
      const ca = new X509Certificate(readFileSync(caCert));
      const rows = [
        // The override goes **after** the spread: `certStatus` returns its own `name`, so the other
        // order silently printed "ca" here. Live and unnoticed because `bin/` was outside
        // `tsconfig.json` until 2026-08-07 — the same reason the line below already had it right.
        { ...certStatus("ca", new Date(ca.validTo), now), name: "ca (trust root)" },
        // Listed by fileBase so a gateway's two certificates are distinguishable in the output;
        // by CN alone they would appear as the same row twice.
        ...issued().map((i) => ({ ...certStatus(i.fileBase, new Date(i.cert.validTo), now), name: i.fileBase })),
      ];
      for (const r of rows) {
        const mark = r.expired ? "EXPIRED" : r.dueForRenewal ? "renew  " : "ok     ";
        console.log(`  ${mark} ${r.name.padEnd(20)} ${String(r.daysLeft).padStart(5)}d  ${r.notAfter.toISOString()}`);
      }
      // Non-zero so a cron or a CI check can act on it without parsing this output.
      if (rows.some((r) => r.dueForRenewal)) process.exitCode = 1;
      break;
    }

    case "renew": {
      requireCa();
      const now = new Date();
      const force = flags.has("force");
      const due = issued().filter(
        (i) => force || certStatus(i.fileBase, new Date(i.cert.validTo), now).dueForRenewal,
      );
      if (!due.length) {
        console.log("nothing due for renewal");
        break;
      }
      // Renewal reissues from the same CA, so the anchor every host already trusts is unchanged and
      // certificates can be replaced one host at a time rather than fleet-wide.
      console.log(`renewing ${due.length} certificate(s) from the existing CA`);
      for (const i of due) issue(planFromExisting(i));
      console.log("\nreplace the files on each host and restart its unit — one host at a time.");
      break;
    }

    case "sign-csr": {
      const [csr, out] = rest;
      if (!csr || !out) throw new PkiError("sign-csr needs a CSR path and output certificate path");
      signCsr(csr, out);
      break;
    }

    default:
      console.error(USAGE);
      process.exit(2);
  }
} catch (e) {
  console.error(`[pki] ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}
