import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdirSync, mkdtempSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { CONSOLE_PREFIX, resolveWebRoot, securityHeadersForDocument, serveConsole } from "./web-console.ts";

function listen(webRoot: string): Promise<{ url: string; close: () => Promise<void> }> {
  const intercept = serveConsole(webRoot);
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    if (intercept(req, res)) return;
    res.writeHead(599, { "content-type": "text/plain" }).end("fell through");
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") throw new Error("expected tcp address");
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

describe("serveConsole", () => {
  it("serves index.html at /app and leaves every other path to the manager", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-web-"));
    writeFileSync(join(dir, "index.html"), "<!doctype html>console");
    const { url, close } = await listen(dir);
    try {
      const page = await fetch(`${url}${CONSOLE_PREFIX}`);
      assert.equal(page.status, 200);
      assert.equal(await page.text(), "<!doctype html>console");
      assert.equal(page.headers.get("cache-control"), "no-store");

      const other = await fetch(`${url}/site`);
      assert.equal(other.status, 599);
      assert.equal(await other.text(), "fell through");
    } finally {
      await close();
    }
  });

  it("falls back to index.html for a console route, and refuses a path that escapes the build", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-web-"));
    writeFileSync(join(dir, "index.html"), "shell");
    const { url, close } = await listen(dir);
    try {
      const spa = await fetch(`${url}${CONSOLE_PREFIX}/fleet`);
      assert.equal(spa.status, 200);
      assert.equal(await spa.text(), "shell");

      let status = 0;
      const res = {
        writeHead(code: number) {
          status = code;
          return res;
        },
        end() {},
      };
      const handled = serveConsole(dir)(
        { method: "GET", url: "/app/%2e%2e%2fsecret" } as IncomingMessage,
        res as unknown as ServerResponse,
      );
      assert.equal(handled, true);
      assert.equal(status, 400);
    } finally {
      await close();
    }
  });

  // ## A malformed escape must answer, not throw
  //
  // `decodeURIComponent("%")` raises `URIError`. Where that landed depended entirely on the caller:
  // the manager and the workstation wrap their handler in an async `.catch` and turned it into a
  // 500, while `packages/manager/src/listen.ts` calls this synchronously — so the exception
  // escaped the request handler and **ended the process**. That listener binds 127.0.0.1:8445 with
  // `requestCert: false`, which makes `GET /app/%` an unauthenticated way to stop it.
  //
  // Driven through a real server rather than a stub response, because the property is "the caller
  // never sees the throw" and a stub cannot tell a 400 from a crash the harness swallowed.
  it("answers 400 for a malformed percent escape instead of throwing at its caller", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-web-"));
    writeFileSync(join(dir, "index.html"), "shell");
    const { url, close } = await listen(dir);
    try {
      for (const bad of ["/app/%", "/app/%zz", "/app/a%2", "/app/%e0%a4%a"]) {
        const res = await fetch(`${url}${bad}`);
        assert.equal(res.status, 400, `${bad} answered ${res.status}`);
        assert.equal(await res.text(), "bad path");
      }
      // Still serving afterwards — the point is that nothing died on the way.
      assert.equal((await fetch(`${url}${CONSOLE_PREFIX}`)).status, 200);
    } finally {
      await close();
    }
  });
});

// ── The headers that constrain the page ──────────────────────────────────────
//
// These are asserted on a real response rather than on the exported constant, because the constant
// being right and the response carrying it are two different facts — and the second is the one that
// was false for as long as this console has existed. Two comments in `src/` describe a CSP header
// this server never sent.

describe("the console's security headers", () => {
  const headersOf = async (path: string, index = "shell") => {
    const dir = mkdtempSync(join(tmpdir(), "hp-web-"));
    writeFileSync(join(dir, "index.html"), index);
    writeFileSync(join(dir, "app.js"), "export {}");
    const { url, close } = await listen(dir);
    try {
      return (await fetch(`${url}${path}`)).headers;
    } finally {
      await close();
    }
  };

  it("refuses to be framed — the console can publish a firewall change", async () => {
    // The one with a live threat behind it. `SameSite=Strict` and the CSRF token both assume the
    // attacker's page issues the request; a framed click issues it from ours, so neither applies.
    const csp = (await headersOf(CONSOLE_PREFIX)).get("content-security-policy");
    assert.ok(csp, "no Content-Security-Policy on the console page");
    assert.match(csp, /frame-ancestors 'none'/);
  });

  it("sends the rest of the policy on the page", async () => {
    const h = await headersOf(CONSOLE_PREFIX);
    const csp = h.get("content-security-policy") ?? "";
    for (const directive of ["default-src 'self'", "base-uri 'none'", "object-src 'none'", "form-action 'self'"]) {
      assert.ok(csp.includes(directive), `CSP is missing ${directive} — got ${csp}`);
    }
    assert.equal(h.get("referrer-policy"), "no-referrer");
    assert.ok(h.get("permissions-policy"));
  });

  it("copies only the SvelteKit bootstrap hash into the HTTP policy", async () => {
    const index = '<meta http-equiv="content-security-policy" content="script-src \'self\' \'sha256-testHash123=\'">';
    const csp = (await headersOf(CONSOLE_PREFIX, index)).get("content-security-policy") ?? "";
    assert.match(csp, /script-src 'self' 'sha256-testHash123='/);
    assert.match(csp, /style-src 'self'/);
    assert.match(csp, /style-src-attr 'unsafe-inline'/);
  });

  it("fails closed when the build meta policy is missing or contains unsafe sources", () => {
    for (const html of [
      "<html></html>",
      '<meta http-equiv="content-security-policy" content="script-src \'self\' \'unsafe-inline\'">',
    ]) {
      const csp = securityHeadersForDocument(html)["content-security-policy"] ?? "";
      assert.match(csp, /script-src 'self'(?:;|$)/);
      const scriptDirective = csp.split(";").find((directive) => directive.trim().startsWith("script-src")) ?? "";
      assert.doesNotMatch(scriptDirective, /unsafe-inline/);
    }
  });

  it("carries the headers on assets too, not only on the page", async () => {
    // An asset response is still a document a browser can be navigated to directly.
    const h = await headersOf(`${CONSOLE_PREFIX}/app.js`);
    assert.ok(h.get("content-security-policy"));
    assert.equal(h.get("x-content-type-options"), "nosniff");
  });
});

describe("resolveWebRoot", () => {
  it("uses HELIOPAUSE_WEB_ROOT when set, otherwise the built tree next to bin/", () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-webroot-"));
    writeFileSync(join(dir, "index.html"), "ok");
    assert.equal(resolveWebRoot("/unused", { HELIOPAUSE_WEB_ROOT: dir }), dir);

    assert.equal(resolveWebRoot(join(dir, "repo", "bin"), {}), null);

    const repo = mkdtempSync(join(tmpdir(), "hp-built-"));
    const build = join(repo, "packages", "web", "build");
    mkdirSync(build, { recursive: true });
    writeFileSync(join(build, "index.html"), "built");
    assert.equal(resolveWebRoot(join(repo, "bin"), {}), build);
    assert.equal(resolveWebRoot(join(repo, "packages", "manager", "src"), {}), build);
  });
});

// ── Checking the descriptor, not the name ─────────────────────────────────────
//
// The serving path used to ask `existsSync(file) && statSync(file).isFile()` and then read the
// same *name* again — three resolutions, two windows. CodeQL called it `js/file-system-race`.
// `openRegular` opens once and `fstat`s the handle, so what was checked and what is read are the
// same object.
//
// A TOCTOU is awkward to provoke deterministically in a test, so these pin the reachable
// consequences instead: the cases where "the name resolves" and "there is a regular file here"
// give different answers. Each of them went the wrong way before.
describe("serveConsole resolves the file once", () => {
  const req = async (root: string, path: string) => {
    const { url, close } = await listen(root);
    try {
      const r = await fetch(`${url}${path}`);
      return { status: r.status, body: await r.text() };
    } finally {
      await close();
    }
  };

  it("404s a directory rather than trying to read it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-web-dir-"));
    mkdirSync(join(dir, "assets"));
    // No index.html either, so the fallback cannot rescue it — the answer must be the 404, not a
    // stream of a directory or an EISDIR crash.
    const r = await req(dir, `${CONSOLE_PREFIX}/assets`);
    assert.equal(r.status, 404);
  });

  it("falls back to index.html for a directory when one exists", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-web-dir2-"));
    mkdirSync(join(dir, "assets"));
    writeFileSync(join(dir, "index.html"), "<!doctype html>app");
    const r = await req(dir, `${CONSOLE_PREFIX}/assets`);
    assert.equal(r.status, 200);
    assert.equal(r.body, "<!doctype html>app");
  });

  // 🔴 `existsSync` follows the link and answers **false** for a dangling one, so a broken symlink
  // used to fall through to `index.html` and serve the app shell under the asset's name and
  // content-type. Opening asks the question directly: there is nothing there.
  it("does not serve the app shell in place of a dangling symlink", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-web-link-"));
    writeFileSync(join(dir, "index.html"), "<!doctype html>app");
    symlinkSync(join(dir, "gone.js"), join(dir, "broken.js"));
    const r = await req(dir, `${CONSOLE_PREFIX}/broken.js`);
    // The fallback still applies — that is the design — but it must arrive as the document it is,
    // not as a JavaScript response whose body is HTML.
    assert.equal(r.status, 200);
    assert.equal(r.body, "<!doctype html>app");
  });

  // Opening by hand means closing by hand, on every path. A leak is invisible until the process
  // runs out of descriptors — which on a manager serving a console is a long, quiet way to fail.
  it("closes every descriptor it opens, on all three exit paths", async () => {
    const fdDir = platform() === "linux" ? "/proc/self/fd" : "/dev/fd";
    const openCount = () => {
      try {
        return readdirSync(fdDir).length;
      } catch {
        return null;
      }
    };

    const dir = mkdtempSync(join(tmpdir(), "hp-web-fd-"));
    writeFileSync(join(dir, "index.html"), "<!doctype html>app");
    writeFileSync(join(dir, "app.js"), "export const x = 1;\n");
    const { url, close } = await listen(dir);
    try {
      // Warm up first: the first requests open sockets and TLS-free agent state that would
      // otherwise be counted as growth.
      for (let i = 0; i < 5; i++) await (await fetch(`${url}${CONSOLE_PREFIX}/app.js`)).text();
      const before = openCount();

      for (let i = 0; i < 40; i++) {
        // The stream path — the descriptor is handed to `createReadStream`, which owns it.
        const asset = await fetch(`${url}${CONSOLE_PREFIX}/app.js`);
        assert.equal(await asset.text(), "export const x = 1;\n");
        // The document path — read into memory, closed by the `finally`.
        const page = await fetch(`${url}${CONSOLE_PREFIX}/`);
        assert.equal(await page.text(), "<!doctype html>app");
        // The HEAD path — headers only, and the same `finally`.
        const head = await fetch(`${url}${CONSOLE_PREFIX}/app.js`, { method: "HEAD" });
        assert.equal(head.headers.get("content-type"), "text/javascript; charset=utf-8");
      }

      const after = openCount();
      if (before !== null && after !== null) {
        // 120 requests. A descriptor leaked per request would be unmistakable; a small delta is
        // sockets in TIME_WAIT and is not what this is asking about.
        assert.ok(
          after - before < 30,
          `open descriptors went ${before} → ${after} over 120 requests — something is not being closed`,
        );
      }
    } finally {
      await close();
    }
  });
});
