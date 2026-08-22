import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { CONSOLE_PREFIX, serveConsole } from "./console.ts";

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
});
