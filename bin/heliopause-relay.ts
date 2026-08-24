#!/usr/bin/env node
// Relay entry point. Runs on each gateway.
//
// **Node, not Bun** — see the header of src/relay.ts. Bun cannot read the client certificate, so
// under Bun the relay could not tell which agent was calling and every heartbeat's `host` field
// would be an unverified claim. Node 22+ runs the TypeScript here directly via type stripping;
// no build step is involved.

import { startRelay, loadManifest } from "../src/relay.ts";
import { boundedInteger, EnvSpecError, type NumberBounds } from "../src/env-spec.ts";
import { formatOperatorLog, installCliLanguage, logLangFromEnv } from "../src/operator-i18n.ts";

const cliLangRequested = process.argv.slice(2).some((arg) => arg === "--lang" || arg.startsWith("--lang="));
const deploymentLogLang = logLangFromEnv();
const cliLang = installCliLanguage(deploymentLogLang);
const logLang = cliLangRequested ? cliLang : deploymentLogLang;

const env = (name: string, fallback?: string): string => {
  const v = process.env[name] ?? fallback;
  if (v === undefined) {
    console.error(`[relay] ${formatOperatorLog(logLang, "server.missingEnvironment", { name })}`);
    process.exit(2);
  }
  return v;
};

/** Refuse a numeric setting the way `env()` refuses a missing one: a sentence, and exit 2. */
const number = (name: string, bounds: NumberBounds): number => {
  try {
    return boundedInteger(name, process.env[name], bounds);
  } catch (error) {
    if (!(error instanceof EnvSpecError)) throw error;
    console.error(`[relay] ${error.message}`);
    process.exit(2);
  }
};

const artifactDir = env("HELIOPAUSE_ARTIFACT_DIR");
const hostname = process.env.HELIOPAUSE_RELAY_HOST ?? "::";

/**
 * Both numbers are parsed rather than coerced, and `reloadSec` is why.
 *
 * `Number("thirty")` is `NaN`; `Math.max(5, NaN)` is `NaN`; `setInterval(fn, NaN)` fires **every
 * millisecond**. This gateway would then re-read and re-validate the whole authorized bundle — up
 * to 16 MB — roughly 875 times a second, on a machine with under a gigabyte of RAM. Measured.
 *
 * The `Math.max(5, …)` that used to guard the interval is what makes this worth a comment: it reads
 * exactly like the check that would have caught it.
 */
// `0` is allowed and means what it means to `listen` — let the kernel choose. It is what the
// service tests bind, and `heliopause-ui.ts` has accepted it since it grew a check. What this
// refuses is the value that is not a port at all, which is the one that used to get through.
const port = number("HELIOPAUSE_RELAY_PORT", { min: 0, max: 65_535, fallback: 8443 });
const reloadSec = number("HELIOPAUSE_RELOAD_SEC", { min: 5, max: 3600, fallback: 30 });

// Comma-separated certificate CNs allowed to read /status. Unset means the endpoint is off, which
// is the right default: a fleet-wide view names every host, its generation and its drift state, so
// one compromised agent should not be able to ask for a target list.
const operatorCNs = (process.env.HELIOPAUSE_OPERATOR_CNS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Comma-separated CNs allowed to POST /publish — normally just the manager's. Unset means the
// endpoint refuses everyone, which is the right default and not a degraded one: artifacts can still
// arrive by being written to HELIOPAUSE_ARTIFACT_DIR, and that path is deliberately kept as the way
// to publish when the manager is the thing that is broken.
//
// Separate from operatorCNs because reading the fleet and changing the firewall are different powers.
// Every operator certificate that exists can read /status; if that list could also write, issuing a
// read-only credential would silently hand out publish rights.
const publisherCNs = (process.env.HELIOPAUSE_PUBLISHER_CNS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const revocationFile = process.env.HELIOPAUSE_REVOCATION_FILE;
// The oldest agent build this VPC wants to be running, e.g. `0.6.0`. Unset asks nothing, which is
// what this did until 2026-08-22: every heartbeat carried `agentVersion`, the fleet view drew it as
// a column, and nothing compared it — so a half-upgraded fleet produced no sentence anywhere.
const minAgentVersion = process.env.HELIOPAUSE_MIN_AGENT_VERSION;

const { server, reload } = await startRelay({
  artifactDir,
  port,
  hostname,
  operatorCNs,
  publisherCNs,
  logLang,
  ...(minAgentVersion ? { minAgentVersion } : {}),
  ...(revocationFile
    ? {
        revocationFile,
        revocationWriterSocket: env("HELIOPAUSE_REVOCATION_WRITER_SOCKET"),
      }
    : {}),
  tls: {
    certFile: env("HELIOPAUSE_CERT_FILE"),
    keyFile: env("HELIOPAUSE_KEY_FILE"),
    caFile: env("HELIOPAUSE_CA_FILE"),
  },
});

// Poll the artifact directory rather than waiting to be told. A webhook would make publishing
// depend on the gateway being reachable from outside, which is the inbound path this design
// spent its effort removing.
// No `Math.max` here any more. The floor is part of the parse above, where a value that cannot
// satisfy it stops the process instead of becoming `NaN` and slipping past the clamp.
const timer = setInterval(() => void reload(), reloadSec * 1000);
timer.unref?.();

for (const sig of ["SIGTERM", "SIGINT"] as const) {
  process.on(sig, () => {
    console.error(`[relay] ${formatOperatorLog(logLang, "server.stopping")}`);
    clearInterval(timer);
    server.close(() => process.exit(0));
    // Agents reconnect on their own schedule, so a lingering keep-alive is not worth a slow stop
    // during a rolling restart.
    server.closeAllConnections?.();
  });
}

// Surfaced at startup so a gateway serving a stale or absent manifest is obvious in the journal
// rather than discovered when a rollout silently fails to advance.
await loadManifest(artifactDir).catch((e: Error) =>
  console.error(`[relay] ${formatOperatorLog(logLang, "server.startupManifestUnavailable", { error: e.message })}`),
);
