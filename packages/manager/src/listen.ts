// Node https listener around the Hono app.
//
// Hono is the router. TLS stays here because SNI, client certificates and
// `socket.getPeerCertificate()` are Node `https.Server` properties — Bun cannot
// expose the peer cert (see src/relay.ts), and Hono's Request cannot either.
//
// Binds 127.0.0.1:8445 so this scaffold cannot collide with the live manager on 8444
// and cannot become an unauthenticated network service by default.

import { createServer } from "node:https";
import { getRequestListener } from "@hono/node-server";
import { app } from "./app.ts";
import { resolveWebRoot, serveConsole } from "./console.ts";
import { resolveTls } from "./tls.ts";

const HOST = "127.0.0.1";
const PORT = 8445;

const tls = resolveTls(process.env);

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
