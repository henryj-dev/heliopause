#!/usr/bin/env node
import { startRevocationWriter } from "../src/revocation-writer.ts";
import { formatOperatorLog, installCliLanguage, logLangFromEnv } from "../src/operator-i18n.ts";

const cliLangRequested = process.argv.slice(2).some((arg) => arg === "--lang" || arg.startsWith("--lang="));
const deploymentLogLang = logLangFromEnv();
const cliLang = installCliLanguage(deploymentLogLang);
const logLang = cliLangRequested ? cliLang : deploymentLogLang;

const snapshotFile = process.env.HELIOPAUSE_REVOCATION_FILE;
if (!snapshotFile) {
  console.error(`[revocation-writer] ${formatOperatorLog(logLang, "server.missingEnvironment", { name: "HELIOPAUSE_REVOCATION_FILE" })}`);
  process.exit(2);
}
if (Number(process.env.LISTEN_FDS ?? "0") !== 1 || Number(process.env.LISTEN_PID ?? "0") !== process.pid) {
  console.error(`[revocation-writer] ${formatOperatorLog(logLang, "server.socketRequired")}`);
  process.exit(2);
}

const { server } = await startRevocationWriter({ snapshotFile, listenFd: 3, logLang });
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
