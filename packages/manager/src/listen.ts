// Node https listener around the Hono app.
//
// Hono is the router. TLS stays here because SNI, client certificates and
// `socket.getPeerCertificate()` are Node `https.Server` properties — Bun cannot
// expose the peer cert (see src/relay.ts), and Hono's Request cannot either.
//
// Binds 127.0.0.1:8445 so this scaffold cannot collide with the live manager on 8444
// and cannot become an unauthenticated network service by default.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getRequestListener } from "@hono/node-server";
import { app } from "./app.ts";
import { resolveWebRoot, serveConsole } from "./console.ts";

const HOST = "127.0.0.1";
const PORT = 8445;

function ephemeralTls(): { key: Buffer; cert: Buffer } {
  const dir = mkdtempSync(join(tmpdir(), "heliopause-manager-scaffold-"));
  const key = join(dir, "key.pem");
  const cert = join(dir, "cert.pem");
  // One-day throwaway. The live manager never takes this path — it refuses to start
  // without the configured certificate files. openssl is already a manager-image dependency.
  execFileSync(
    "openssl",
    ["req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
    { stdio: "ignore" },
  );
  return { key: readFileSync(key), cert: readFileSync(cert) };
}

const tls = process.env.HELIOPAUSE_CERT_FILE && process.env.HELIOPAUSE_KEY_FILE
  ? {
    cert: readFileSync(process.env.HELIOPAUSE_CERT_FILE),
    key: readFileSync(process.env.HELIOPAUSE_KEY_FILE),
  }
  : ephemeralTls();

const webRoot = resolveWebRoot(import.meta.dirname);
const serveApp = webRoot ? serveConsole(webRoot) : null;
const hono = getRequestListener(app.fetch);

createServer({ ...tls, requestCert: false }, (req, res) => {
  if (serveApp?.(req, res)) return;
  void hono(req, res);
}).listen(PORT, HOST, () => {
  console.log(`[manager-scaffold] https://${HOST}:${PORT}/healthz`);
  if (webRoot) console.log(`[manager-scaffold] console https://${HOST}:${PORT}/app`);
});
