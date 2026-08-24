import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { CONSOLE_PREFIX, resolveWebRoot, serveConsole } from "./web-console.ts";

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
  const headersOf = async (path: string) => {
    const dir = mkdtempSync(join(tmpdir(), "hp-web-"));
    writeFileSync(join(dir, "index.html"), "shell");
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

  // `script-src` is Kit's half, emitted as a meta tag with the inline bootstrap's hash. Asserting
  // its absence here is what keeps the two halves from being written in both places and drifting —
  // the failure of that is a blank console, which no unit test would show.
  it("leaves script-src to the build, so the two halves cannot drift", async () => {
    const csp = (await headersOf(CONSOLE_PREFIX)).get("content-security-policy") ?? "";
    assert.ok(!csp.includes("script-src"), `script-src belongs in svelte.config.js — got ${csp}`);
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
