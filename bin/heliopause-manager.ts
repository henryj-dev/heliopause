#!/usr/bin/env node
// Manager entry point. One per site — see src/manager-server.ts for why it is not the relay.
//
// **Node, not Bun**, for the same reason as the relay: Bun does not expose the peer certificate to
// the handler, so the operator check would have nothing to check. Node 22+ runs this TypeScript
// directly via type stripping; there is no build step.
//
// Reads and writes. The write half is `POST /plan` → `POST /approve` → `POST /publish`, and the
// ordering between them is the permission model rather than an API convenience — see
// docs/인터페이스-설계.md 결정 4.
//
// Two allowlists, on purpose: `HELIOPAUSE_OPERATOR_CNS` may read the site, `HELIOPAUSE_WRITER_CNS`
// may change it. Both are deployment configuration and neither is reachable through the API, because
// an API that can grant itself permission is not a permission model (결정 6).

import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { artifactSigningKeyId, privateKeyFileModeError, privateKeyFileOwnerError } from "../src/artifact-signature.ts";
import { fetchCert } from "../src/cert-api.ts";
import { startManager } from "../src/manager-server.ts";
import type { RelaySource } from "../src/manager.ts";
import { resolveWebRoot, serveConsole } from "../src/web-console.ts";
import { formatOperatorLog, installCliLanguage, logLangFromEnv } from "../src/operator-i18n.ts";

const cliLangRequested = process.argv.slice(2).some((arg) => arg === "--lang" || arg.startsWith("--lang="));
const deploymentLogLang = logLangFromEnv();
const cliLang = installCliLanguage(deploymentLogLang);
const logLang = cliLangRequested ? cliLang : deploymentLogLang;

const env = (name: string, fallback?: string): string => {
  const v = process.env[name] ?? fallback;
  if (v === undefined) {
    console.error(`[manager] ${formatOperatorLog(logLang, "server.missingEnvironment", { name })}`);
    process.exit(2);
  }
  return v;
};

/**
 * `dev=https://10.0.0.1:8443=./pki,prod=https://10.0.1.1:8443=./pki-prod`
 *
 * Three fields because each VPC has its own CA (V39): the manager presents a different operator
 * certificate to each relay and verifies each against that VPC's own anchor. One shared PKI would
 * reach exactly one VPC and report the others as unreachable — measured while wiring this up.
 *
 * Named rather than positional so a site view can say which VPC is unreachable. "relay 2 is down" is
 * not something an operator can act on at three in the morning.
 */
function parseRelays(spec: string): RelaySource[] {
  const out: RelaySource[] = [];
  for (const entry of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    const parts = entry.split("=");
    if (parts.length !== 3 || parts.some((p) => !p)) {
      console.error(
        `[manager] malformed relay entry ${JSON.stringify(entry)} — expected name=url=pkiDir`,
      );
      process.exit(2);
    }
    const [name, url, pkiDir] = parts as [string, string, string];
    if (!url.startsWith("https://")) {
      // Refused rather than upgraded. The site view names every host in the fleet, and it travels
      // over this connection.
      console.error(`[manager] relay ${name} must be https — got ${JSON.stringify(url)}`);
      process.exit(2);
    }
    out.push({ name, url, pkiDir });
  }
  if (out.length === 0) {
    console.error("[manager] HELIOPAUSE_RELAYS is empty — there is nothing to aggregate");
    process.exit(2);
  }
  return out;
}

/**
 * `a=1,b=2` into a map, refusing anything malformed.
 *
 * Refusing rather than skipping. A dropped mapping here presents as "my approvals are refused and I
 * do not know why", with the operator looking at a configuration line that appears correct — the
 * same failure mode `parseAliases` exists to avoid, and worth avoiding the same way.
 */
/** A comma-separated environment list, trimmed and without empties. */
const list = (name: string): string[] =>
  (process.env[name] ?? "").split(",").map((x) => x.trim()).filter(Boolean);

function parsePairs(spec: string, name: string): Map<string, string> {
  const out = new Map<string, string>();
  let ordinal = 0;
  for (const entry of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    ordinal += 1;
    const eq = entry.indexOf("=");
    // 🔴 **The entry itself never reaches the log.** One caller is `HELIOPAUSE_OTP_USERS`, whose
    // values are shared OTP secrets, and this branch fires on exactly the inputs where we cannot
    // tell which half we are holding — a secret containing a comma splits into a fragment with no
    // `=`, and printing the "malformed entry" then writes that fragment to stderr and into
    // journald. A misconfiguration must not be the thing that publishes the secret.
    //
    // The ordinal is enough to fix it: the operator has the variable in front of them and can count
    // commas. Where the key is known to be a key — there is an `=`, the value is just empty — say
    // it, because "which one" is the whole question and the key half is not the secret.
    if (eq <= 0) {
      console.error(`[manager] ${name}: entry ${ordinal} is malformed — expected <key>=<value>`);
      process.exit(2);
    }
    if (eq === entry.length - 1) {
      console.error(`[manager] ${name}: entry ${ordinal} (${JSON.stringify(entry.slice(0, eq).trim())}) has an empty value — expected <key>=<value>`);
      process.exit(2);
    }
    const k = entry.slice(0, eq).trim();
    const v = entry.slice(eq + 1).trim();
    if (out.has(k)) {
      console.error(`[manager] ${name}: ${JSON.stringify(k)} is declared twice`);
      process.exit(2);
    }
    out.set(k, v);
  }
  return out;
}

const relays = parseRelays(env("HELIOPAUSE_RELAYS")).map((r) => ({
  ...r,
  // One name for every VPC. The manager has one identity conceptually — `hp-manager` — even though
  // the certificate proving it is different per VPC, because the CAs are separate.
  ...(process.env.HELIOPAUSE_OPERATOR_NAME ? { operatorName: process.env.HELIOPAUSE_OPERATOR_NAME } : {}),
}));
const port = Number(env("HELIOPAUSE_MANAGER_PORT", "8444"));
const hostname = process.env.HELIOPAUSE_MANAGER_HOST ?? "::";

function loadArtifactSigningKey(path: string) {
  // `O_CLOEXEC` is deliberately absent, and its absence is measured rather than assumed: Node does
  // not expose it on `fs.constants`, so `constants.O_CLOEXEC` is `undefined` and the term contributed
  // **zero** to this bitmask — the flag read as requested while doing nothing. libuv opens descriptors
  // close-on-exec itself, so nothing is lost; what was lost was the appearance of a guarantee.
  // `O_NOFOLLOW` is real (256) and is the one doing work here.
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let encoded: Buffer | undefined;
  try {
    const info = fstatSync(fd);
    if (!info.isFile()) {
      throw new Error("HELIOPAUSE_ARTIFACT_SIGNING_KEY_FILE must be a regular, non-symlink file");
    }
    // Shared with the break-glass key check in `heliopause-publish.ts`, and tested there rather than
    // restated here — a copy would drift, and the direction it drifts in is one process accepting a
    // key the other refuses.
    const modeError = privateKeyFileModeError(info, process.getgid?.());
    if (modeError) {
      throw new Error(`HELIOPAUSE_ARTIFACT_SIGNING_KEY_FILE ${modeError}`);
    }
    const ownerError = privateKeyFileOwnerError(info, process.getuid?.());
    if (ownerError) {
      throw new Error(`HELIOPAUSE_ARTIFACT_SIGNING_KEY_FILE ${ownerError}`);
    }
    encoded = readFileSync(fd);
    const key = createPrivateKey(encoded);
    // Validates both private/public type and Ed25519 before the manager opens a listening socket.
    artifactSigningKeyId(createPublicKey(key));
    return key;
  } finally {
    encoded?.fill(0);
    closeSync(fd);
  }
}

const artifactSigningKey = loadArtifactSigningKey(env("HELIOPAUSE_ARTIFACT_SIGNING_KEY_FILE"));
const artifactAuthorizationTtlSec = Number(env("HELIOPAUSE_ARTIFACT_AUTHORIZATION_TTL_SEC", "86400"));

// Unset means nobody may read, which is the right default. The site view is strictly more than any
// single relay exposes — every host across every VPC — so defaulting it open would make this the
// easiest way to enumerate the fleet.
const operatorCNs = (process.env.HELIOPAUSE_OPERATOR_CNS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

if (operatorCNs.length === 0) {
  console.error("[manager] HELIOPAUSE_OPERATOR_CNS is unset — nothing would be readable. Set it.");
  process.exit(2);
}

/**
 * Who may change the fleet. Separate from the readers, and empty by default.
 *
 * Empty means the write endpoints refuse everyone, which is the correct default rather than a
 * degraded one: publishing still works through the direct path on each gateway, so a manager that
 * cannot write is inconvenient and not an outage. Defaulting this to `operatorCNs` would mean every
 * read-only credential ever issued silently carried publish rights.
 */
const writerCNs = (process.env.HELIOPAUSE_WRITER_CNS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Refused rather than accepted with a warning. A writer who cannot read is a configuration mistake
// with a confusing symptom — 403 on `/plan` from an identity the operator can see in the writer list —
// and the earlier authorisation check is what would be rejecting it.
const strangers = writerCNs.filter((cn) => !operatorCNs.includes(cn));
if (strangers.length) {
  console.error(
    `[manager] HELIOPAUSE_WRITER_CNS names ${strangers.join(", ")}, which are not in ` +
      `HELIOPAUSE_OPERATOR_CNS. Every write endpoint checks read authorisation first, so these ` +
      `would be refused. Add them to both, or remove them here.`,
  );
  process.exit(2);
}

const webRoot = resolveWebRoot(import.meta.dirname);
const intercept = webRoot ? serveConsole(webRoot) : undefined;

const { server } = await startManager({
  logLang,
  port,
  hostname,
  relays,
  ...(intercept ? { intercept } : {}),
  artifactSigning: {
    privateKey: artifactSigningKey,
    authorizationTtlSec: artifactAuthorizationTtlSec,
  },
  ...(process.env.HELIOPAUSE_REVOCATION_FILE ? { revocationFile: process.env.HELIOPAUSE_REVOCATION_FILE } : {}),
  // Where the rendered policy comes from. **A URL and not a path**, which is the whole of C1's fix:
  // this process must not have a checkout, because a checkout is one `import()` away from running
  // the policy repository's code beside the signing key. `heliopause-policy-render` has the
  // checkout, runs the module, and answers in JSON.
  //
  // Absent means `/policy` answers 404 — a deployment without the repository says so rather than
  // serving an empty page that reads as "no policy".
  ...(process.env.HELIOPAUSE_POLICY_RENDER_URL
    ? {
        // Optional. Absent leaves the traffic screen saying so rather than showing an empty table —
        // a cluster with no reader and a cluster with no traffic are different findings.
        ...(process.env.HELIOPAUSE_TRAFFIC_READER_URL
          ? { trafficReader: { url: process.env.HELIOPAUSE_TRAFFIC_READER_URL } }
          : {}),
        policySource: {
          url: env("HELIOPAUSE_POLICY_RENDER_URL"),
          // A file, like every other secret this process holds: env survives in /proc/<pid>/environ
          // and in crash dumps.
          ...(process.env.HELIOPAUSE_POLICY_RENDER_TOKEN_FILE
            ? { token: readFileSync(env("HELIOPAUSE_POLICY_RENDER_TOKEN_FILE"), "utf8").trim() }
            : {}),
        },
      }
    : {}),
  // The console's write path. All four have to be present — a half-configured editor would render a
  // save button that fails at the moment somebody uses it, which is the worst time to find out.
  ...(process.env.HELIOPAUSE_CONSOLE_APP_ID &&
  process.env.HELIOPAUSE_CONSOLE_APP_INSTALLATION &&
  process.env.HELIOPAUSE_CONSOLE_APP_KEY_FILE &&
  process.env.HELIOPAUSE_POLICY_REPO
    ? {
        policyWrite: {
          creds: {
            appId: env("HELIOPAUSE_CONSOLE_APP_ID"),
            installationId: env("HELIOPAUSE_CONSOLE_APP_INSTALLATION"),
            privateKey: readFileSync(env("HELIOPAUSE_CONSOLE_APP_KEY_FILE"), "utf8"),
          },
          target: {
            owner: env("HELIOPAUSE_POLICY_REPO").split("/")[0] ?? "",
            repo: env("HELIOPAUSE_POLICY_REPO").split("/")[1] ?? "",
            base: process.env.HELIOPAUSE_POLICY_BASE ?? "main",
          },
          // Named files, not a pattern. A policy editor that can write `.github/workflows/*` is a
          // way to run code in CI, and no amount of path sanitising makes that a safe default.
          //
          // `policies.json` first because it is what the editor opens and where the rules live; the
          // site module second because approving a device or adding a zone is an edit to it, and a
          // console that cannot do those is not the console this is meant to be.
          //
          // Offering a textarea over executable code is safe *here* and would not have been before.
          // An edit lands on a branch, the renderer only ever evaluates the merged checkout, merging
          // takes a second person, and the evaluation happens in a pod holding no credential. The
          // dangerous version of this was the one where the manager itself ran what arrived.
          allowPaths: (process.env.HELIOPAUSE_POLICY_EDITABLE ?? "policies.json,dev.ts")
            .split(",")
            .map((p) => p.trim())
            .filter(Boolean),
        },
      }
    : {}),
  ...(process.env.HELIOPAUSE_ENROLLMENT_STORE
    ? {
        enrollment: {
          storeFile: env("HELIOPAUSE_ENROLLMENT_STORE"),
          trustedCaFiles: parsePairs(process.env.HELIOPAUSE_ENROLLMENT_TRUSTED_CAS ?? "", "HELIOPAUSE_ENROLLMENT_TRUSTED_CAS"),
        },
      }
    : {}),
  tls: {
    certFile: env("HELIOPAUSE_CERT_FILE"),
    keyFile: env("HELIOPAUSE_KEY_FILE"),
    caFile: env("HELIOPAUSE_CA_FILE"),
    // Optional second certificate, for the name a browser uses. Setting the name switches it on;
    // the three cert-api variables are then required and `env()` exits if any is missing. Failing at
    // startup beats discovering a half-configuration from a certificate warning weeks later.
    //
    // Unset is a complete configuration, not a degraded one: the manager serves the internal
    // certificate to everyone, which is what it did before this existed and what the operator CLI
    // wants regardless.
    ...(process.env.HELIOPAUSE_PUBLIC_SERVER_NAMES || process.env.HELIOPAUSE_PUBLIC_SERVER_NAME
      ? {
          public: {
            serverNames: (process.env.HELIOPAUSE_PUBLIC_SERVER_NAMES ?? env("HELIOPAUSE_PUBLIC_SERVER_NAME"))
              .split(",").map((name) => name.trim()).filter(Boolean),
            refreshSec: Number(process.env.HELIOPAUSE_PUBLIC_REFRESH_SEC ?? "3600"),
            // How soon to try again while there is **no** public certificate at all — a different
            // question from the one above, and it got the same answer until 2026-08-18 cost both
            // public names an hour over a cert API that was slow for a second. Given its own knob
            // because the two are tuned against different things: `refreshSec` against how often
            // cert-manager rotates, this against how long the console may be unreachable.
            retrySec: Number(process.env.HELIOPAUSE_PUBLIC_RETRY_SEC ?? "5"),
            // The token is read from a file, not an environment variable. Env is visible in
            // `/proc/<pid>/environ`, in a crash dump, and in anything that logs the environment —
            // and this one fetches a private key. A mounted Secret is read once, here.
            load: () =>
              fetchCert({
                baseUrl: env("HELIOPAUSE_CERT_API_URL"),
                name: env("HELIOPAUSE_CERT_API_NAME"),
                token: readFileSync(env("HELIOPAUSE_CERT_API_TOKEN_FILE"), "utf8").trim(),
              }),
          },
        }
      : {}),
  },
  // A one-time code on every approval and publish, for both ways of arriving. Setting the issuer
  // switches it on; the rest is then required, so a half-configuration fails at startup instead of
  // at the moment somebody tries to approve something.
  //
  // `HELIOPAUSE_OTP_USERS` maps a certificate name to a KeyStone user id — `<cert-cn>=<uuid>`. An
  // OIDC principal needs no entry: its `sub` is that id already. A writer with no entry and no OIDC
  // identity cannot approve, which is the safe direction.
  ...(process.env.HELIOPAUSE_OTP_ISSUER_URL
    ? {
        otp: {
          issuerUrl: env("HELIOPAUSE_OTP_ISSUER_URL"),
          serviceToken: readFileSync(env("HELIOPAUSE_OTP_SERVICE_TOKEN_FILE"), "utf8").trim(),
          users: parsePairs(process.env.HELIOPAUSE_OTP_USERS ?? "", "HELIOPAUSE_OTP_USERS"),
        },
      }
    : {}),
  // Browser login. Unset means the console is certificate-only, which is what it was.
  //
  // Roles are a **ladder**: each grants everything below it. KeyStone assigns one role per user per
  // service (`user_service_assignments` has a unique index on user+service), so an ordered list is
  // the shape that model can express. See docs/keystone-핸드오프.md for why that is the right trade
  // today and what would replace it.
  ...(process.env.HELIOPAUSE_OIDC_ISSUER
    ? {
        oidc: {
          issuer: env("HELIOPAUSE_OIDC_ISSUER"),
          clientId: env("HELIOPAUSE_OIDC_CLIENT_ID"),
          ...(process.env.HELIOPAUSE_OIDC_CLIENT_SECRET_FILE
            ? { clientSecret: readFileSync(env("HELIOPAUSE_OIDC_CLIENT_SECRET_FILE"), "utf8").trim() }
            : {}),
          redirectUri: env("HELIOPAUSE_OIDC_REDIRECT_URI"),
          // The `events` key this deployment's IdP uses. `env()` exits if it is missing, which
          // is the point: it used to be a constant naming one provider's domain, and any
          // other provider would then have failed silently — the token verifies, the key does
          // not match, and the authority change is dropped. A missing configuration value that
          // stops the process beats a wrong one that discards revocations.
          roleChangeEvent: env("HELIOPAUSE_OIDC_ROLE_CHANGE_EVENT"),
          operatorGroups: list("HELIOPAUSE_OIDC_OPERATOR_ROLES"),
          writerGroups: list("HELIOPAUSE_OIDC_WRITER_ROLES"),
          soloApprovalRoles: list("HELIOPAUSE_OIDC_SOLO_ROLES"),
          aliases: parsePairs(process.env.HELIOPAUSE_OIDC_ALIASES ?? "", "HELIOPAUSE_OIDC_ALIASES"),
          ...(process.env.HELIOPAUSE_OIDC_SESSION_TTL_SEC
            ? { sessionTtlSec: Number(process.env.HELIOPAUSE_OIDC_SESSION_TTL_SEC) }
            : {}),
        },
      }
    : {}),
  operatorCNs,
  writerCNs,
  timeoutMs: Number(process.env.HELIOPAUSE_RELAY_TIMEOUT_MS ?? "5000"),
  publishTimeoutMs: Number(process.env.HELIOPAUSE_PUBLISH_TIMEOUT_MS ?? "30000"),
  ...(process.env.HELIOPAUSE_PLAN_TTL_SEC
    ? {
        limits: {
          ttlSec: Number(process.env.HELIOPAUSE_PLAN_TTL_SEC),
          maxPending: Number(process.env.HELIOPAUSE_MAX_PENDING_PLANS ?? "32"),
        },
      }
    : {}),
});

if (webRoot) console.error(`[manager] console at /app from ${webRoot}`);

for (const sig of ["SIGTERM", "SIGINT"] as const) {
  process.on(sig, () => {
    console.error("[manager] shutting down");
    server.close(() => process.exit(0));
  });
}
