// Serve the SvelteKit console as static files.
//
// Node stdlib only. Hono and Vite stay in workspace packages so `npm install heliopause`
// and the manager runtime image do not grow a frontend toolchain. Both the manager and
// the workstation UI call this; the browser then talks to `/api/*` on the same origin.

import { createReadStream, existsSync, statSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, relative, resolve, sep } from "node:path";

export const CONSOLE_PREFIX = "/app";

/**
 * The headers that constrain what the console's own page may do.
 *
 * ## Why these did not exist until 2026-08-22
 *
 * `manager-ui.ts` says a per-response nonce "appears both in the CSP header and on the one inline
 * script", and `policy-ui.ts` says its no-script design "removes the CSP problem entirely". Both
 * sentences describe a header that **was never sent** — a repository-wide grep for
 * `Content-Security-Policy` found nothing. The classic console those comments belong to is also no
 * longer served; the live console is this function's static files, and it had no CSP either.
 *
 * ## What each one is for, and what it is not
 *
 * `frame-ancestors 'none'` is the one with a live threat behind it. This origin holds a session that
 * can approve and publish a firewall change, and nothing stopped that page being framed. The CSRF
 * defence in `session.ts` does not cover clickjacking: `SameSite=Strict` and the custom-header token
 * both assume the *attacker's* page issues the request, and a framed click issues it from ours.
 *
 * The rest are depth. `default-src 'self'` and `object-src 'none'` decide what an injected string
 * could reach if one ever existed; `base-uri 'none'` stops a `<base>` tag from repointing every
 * relative fetch this console makes; `form-action 'self'` keeps a form from posting outward.
 *
 * ## `script-src` is deliberately absent from this list
 *
 * SvelteKit's built page starts with an inline module script, so a bare `script-src 'self'` blanks
 * the console. The hashes for it are emitted by `kit.csp` in `packages/web/svelte.config.js`, into
 * a `<meta http-equiv>` in the built HTML, which composes with what is sent here — the browser
 * enforces the intersection. Putting `script-src` in both places would mean two lists to keep in
 * step, and the failure of that is a blank page rather than a warning.
 *
 * `img-src` admits `data:` because the icon set is inlined at build time.
 */
export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "content-security-policy": [
    "default-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    "form-action 'self'",
    "img-src 'self' data:",
  ].join("; "),
  // The console's paths name hosts and generations. A referrer carries them to wherever a link goes.
  "referrer-policy": "no-referrer",
  "permissions-policy": "geolocation=(), camera=(), microphone=()",
};

const TYPES: Record<string, string> = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json",
  ".map": "application/json",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".woff2": "font/woff2",
};

/** Directory that contains `index.html`, or null when the console was not built. */
export function resolveWebRoot(
  fromBinDir: string,
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  const explicit = env.HELIOPAUSE_WEB_ROOT;
  if (explicit) return resolve(explicit);
  // `bin/` in the repo and in the image; `packages/manager/src` for the Hono scaffold.
  const nearby = [
    resolve(fromBinDir, "../packages/web/build"),
    resolve(fromBinDir, "../../web/build"),
  ];
  return nearby.find((dir) => existsSync(join(dir, "index.html"))) ?? null;
}

export function serveConsole(
  webRoot: string,
): (req: IncomingMessage, res: ServerResponse) => boolean {
  const root = resolve(webRoot);
  return (req, res) => {
    if (req.method !== "GET" && req.method !== "HEAD") return false;
    const path = new URL(req.url ?? "/", "https://manager.invalid").pathname;
    if (path !== CONSOLE_PREFIX && !path.startsWith(`${CONSOLE_PREFIX}/`)) return false;

    // ## The decode can throw, and one caller could not survive it
    //
    // `decodeURIComponent("%")` raises `URIError: URI malformed`. `new URL()` above does not
    // normalise a stray `%` away, so `GET /app/%` reached this line and threw — while the very
    // next check answered 400 for the null byte, which is the same class of input.
    //
    // Where it went depended on the caller, and that is the part worth naming:
    //
    //   `manager-server.ts` · `heliopause-ui.ts`   an async wrapper caught it → **500**
    //   `packages/manager/src/listen.ts`           a plain synchronous call → **the process exits**
    //
    // The scaffold binds `127.0.0.1:8445` with `requestCert: false`, so that last one is an
    // unauthenticated way to stop the listener. Fixing it here rather than at the three call sites
    // is the point: the throw is this function's, and a caller should not have to know it exists.
    let rel: string;
    if (path === CONSOLE_PREFIX || path === `${CONSOLE_PREFIX}/`) {
      rel = "index.html";
    } else {
      try {
        rel = decodeURIComponent(path.slice(CONSOLE_PREFIX.length + 1));
      } catch {
        // Same answer as the null byte below. A malformed escape is a bad path, not a server fault.
        rel = "";
      }
    }
    if (!rel || rel.includes("\0")) {
      res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      res.end("bad path");
      return true;
    }

    const candidate = resolve(root, rel);
    const within = relative(root, candidate);
    if (within.startsWith("..") || within.split(sep).includes("..")) {
      res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      res.end("bad path");
      return true;
    }

    let file = candidate;
    const present = existsSync(file) && statSync(file).isFile();
    if (!present) file = join(root, "index.html");
    if (!existsSync(file) || !statSync(file).isFile()) {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("console build is missing — run npm run build:web");
      return true;
    }

    const type = TYPES[extname(file)] ?? "application/octet-stream";
    res.writeHead(200, {
      "content-type": type,
      "cache-control": extname(file) === ".html" ? "no-store" : "public, max-age=31536000, immutable",
      "x-content-type-options": "nosniff",
      ...SECURITY_HEADERS,
    });
    if (req.method === "HEAD") {
      res.end();
      return true;
    }
    createReadStream(file).pipe(res);
    return true;
  };
}
