// Hono routes for the manager package.
//
// `/healthz` lives here so the scaffold listener and the live manager agree on the
// unauthenticated liveness shape. `/app` is not a Hono route: static files are served
// by `serveConsole` on the Node IncomingMessage, because path traversal has to be a
// filesystem check and not a fetch rewrite. Live `/site` · `/plan` stay in
// `src/manager-server.ts` until they move one at a time.

import { Hono } from "hono";

export const app = new Hono();

app.get("/healthz", (c) => c.json({ ok: true }));
