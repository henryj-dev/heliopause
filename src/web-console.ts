// Serve the SvelteKit console as static files.
//
// Node stdlib only. Hono and Vite stay in workspace packages so `npm install heliopause`
// and the manager runtime image do not grow a frontend toolchain. Both the manager and
// the workstation UI call this; the browser then talks to `/api/*` on the same origin.

// `existsSync` survives for `resolveWebRoot` only — a one-off startup question about which build
// directory to serve, where there is no second use to race against. The serving path opens instead;
// see `openRegular`.
import { closeSync, createReadStream, existsSync, fstatSync, openSync, readFileSync } from "node:fs";
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
 * SvelteKit's built page starts with an inline module script. Its hash is emitted by `kit.csp` in
 * `packages/web/svelte.config.js`, into a `<meta http-equiv>` in the built HTML. The response header
 * must repeat that exact hash: browsers intersect a header policy with a meta policy, and the
 * header's `default-src` would otherwise fall back to blocking the inline bootstrap.
 *
 * `img-src` admits `data:` because the icon set is inlined at build time.
 */
export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "content-security-policy": [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "style-src-attr 'unsafe-inline'",
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

const SCRIPT_HASH = /^'sha256-[A-Za-z0-9+/=]+'$/;

/**
 * Add the hash SvelteKit put in the document's meta CSP to the response policy.
 *
 * The fallback is intentionally fail-closed: a malformed or missing build policy leaves the
 * inline bootstrap blocked instead of copying an arbitrary directive into the HTTP header.
 */
export function securityHeadersForDocument(html: string): Record<string, string> {
  const meta = /<meta\s+http-equiv=["']content-security-policy["']\s+content="([^"]*)"\s*\/?>/i.exec(html);
  const scriptDirective = meta?.[1]
    ?.split(";")
    .map((directive) => directive.trim())
    .find((directive) => directive.toLowerCase().startsWith("script-src"));
  const tokens = scriptDirective?.split(/\s+/).slice(1) ?? [];
  const scriptSrc = tokens.length > 0 && tokens.every((token) => token === "'self'" || SCRIPT_HASH.test(token))
    ? `script-src ${tokens.join(" ")}`
    : "script-src 'self'";
  const baseCsp = SECURITY_HEADERS["content-security-policy"] ?? "";
  return { ...SECURITY_HEADERS, "content-security-policy": baseCsp.replace("script-src 'self'", scriptSrc) };
}

/**
 * Open a path as a regular file, or answer null.
 *
 * The point is that the **descriptor** is what gets checked. `existsSync` followed by `statSync`
 * followed by a read resolves the name three times, and a name is not an object: between any two of
 * those the thing it points at can change. Here the file is opened once and `fstat` asks about that
 * open handle, so "it is a regular file" and "this is the file I am reading" are the same claim.
 *
 * Returns null for anything that is not a readable regular file — missing, a directory, a dangling
 * symlink, or unreadable. The caller treats all of those the same way, which is what the two
 * separate `existsSync` checks were doing less exactly.
 */
function openRegular(path: string): number | null {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    return null;
  }
  try {
    if (fstatSync(fd).isFile()) return fd;
  } catch {
    // fall through to close
  }
  closeSync(fd);
  return null;
}

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

    // 🔴 **One handle, opened once.** This was `existsSync(file) && statSync(file).isFile()` and
    // then, separately, `readFileSync(file)` / `createReadStream(file)` — three resolutions of the
    // same name, with a window between each. CodeQL flagged it as `js/file-system-race` and it sat
    // open for ten days.
    //
    // What the window costs here is small — `root` is a local build directory — but the shape is
    // the one this repository keeps getting caught by: the check and the use are about **different
    // objects that happen to share a name**. `openRegular` collapses them. What is checked is the
    // open descriptor, and what is read is that same descriptor, so nothing can be swapped between
    // the two.
    //
    // It also removes a smaller inaccuracy: `existsSync` on a dangling symlink is false, so a
    // broken link fell through to `index.html` rather than 404-ing. Opening answers that directly.
    let file = candidate;
    let fd = openRegular(candidate);
    if (fd === null) {
      file = join(root, "index.html");
      fd = openRegular(file);
    }
    if (fd === null) {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("console build is missing — run npm run build:web");
      return true;
    }

    try {
      const type = TYPES[extname(file)] ?? "application/octet-stream";
      const isDocument = extname(file) === ".html";
      // Reading by descriptor, not by name. `readFileSync` accepts an fd and reads from it.
      const document = isDocument ? readFileSync(fd, "utf8") : null;
      res.writeHead(200, {
        "content-type": type,
        "cache-control": extname(file) === ".html" ? "no-store" : "public, max-age=31536000, immutable",
        "x-content-type-options": "nosniff",
        ...(document === null ? SECURITY_HEADERS : securityHeadersForDocument(document)),
      });
      if (req.method === "HEAD") {
        res.end();
        return true;
      }
      if (document !== null) {
        res.end(document);
        return true;
      }
      // The stream takes ownership of the descriptor and closes it (`autoClose` defaults on), so
      // this is the one path that must not also close it in `finally`.
      const stream = createReadStream("", { fd, autoClose: true });
      fd = null;
      stream.on("error", () => res.destroy());
      stream.pipe(res);
      return true;
    } finally {
      // Every other path — the document, the HEAD, and a throw from `writeHead` — leaves the
      // descriptor to be closed here. A leak would be invisible until the process ran out.
      if (fd !== null) closeSync(fd);
    }
  };
}
