#!/usr/bin/env node
// Relay entry point. Runs on each gateway.
//
// **Node, not Bun** — see the header of src/relay.ts. Bun cannot read the client certificate, so
// under Bun the relay could not tell which agent was calling and every heartbeat's `host` field
// would be an unverified claim. Node 22+ runs the TypeScript here directly via type stripping;
// no build step is involved.

import { startRelay, loadManifest } from "../src/relay.ts";
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

const artifactDir = env("HELIOPAUSE_ARTIFACT_DIR");
const port = Number(env("HELIOPAUSE_RELAY_PORT", "8443"));
const hostname = process.env.HELIOPAUSE_RELAY_HOST ?? "::";
const reloadSec = Number(process.env.HELIOPAUSE_RELOAD_SEC ?? "30");

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
const timer = setInterval(() => void reload(), Math.max(5, reloadSec) * 1000);
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
