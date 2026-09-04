import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { IncomingMessage } from "node:http";
import { PassThrough } from "node:stream";
import { readFileSync } from "node:fs";
import {
  expectsJsonBody,
  isWriteMethod,
  localUiBoundaryError,
  MAX_UI_BODY_BYTES,
  readUiBody,
  UiRequestError,
} from "./local-ui-security.ts";

const self = new URL("http://127.0.0.1:8500");

describe("workstation UI request boundary", () => {
  it("wires one central boundary gate before every local API route", () => {
    const source = readFileSync(new URL("../bin/heliopause-ui.ts", import.meta.url), "utf8");
    const gate = source.indexOf("localUiBoundaryError(req.headers");
    assert.ok(gate > 0, "the CLI does not call the boundary validator");
    for (const route of ['url.pathname === "/api/policies"', 'url.pathname === "/api/propose"', 'url.pathname.startsWith("/api/policies/")', 'url.pathname === "/api/site"', 'url.pathname === "/api/plans"', 'url.pathname.startsWith("/api/enrollment/")', 'url.pathname === "/api/policy/lookup"', 'url.pathname === "/api/policy/where-used"', 'url.pathname === "/api/policy/screen"', 'url.pathname === "/api/workload-traffic"', 'url.pathname === "/api/routes"']) {
      assert.ok(source.indexOf(route, gate) > gate, `${route} is not behind the central boundary gate`);
    }
    assert.match(source, /serveConsole/);
    const after = source.slice(gate);
    assert.match(after, /\/api\/policy\/lookup[\s\S]*?url\.pathname \+ url\.search/);
    assert.match(after, /\/api\/policy\/where-used[\s\S]*?url\.pathname \+ url\.search/);
  });

  // 🔴 The gate is only as good as the answer it is given. `write` used to be a hand-written list
  // of (path, method) pairs in the CLI, and **replacing that whole expression with `false` left
  // every one of 1,835 tests green** — every route CSRF-open at once, silently. The classification
  // is now derived from the method, and this is what makes that derivation a checked claim rather
  // than a comment.
  describe("what counts as a write", () => {
    it("treats every state-changing method as a write", () => {
      for (const method of ["POST", "PUT", "DELETE", "PATCH", "TRACE", undefined]) {
        assert.equal(isWriteMethod(method), true, `${method} must require the loopback Origin`);
      }
    });

    it("leaves the safe methods readable without an Origin", () => {
      for (const method of ["GET", "HEAD", "OPTIONS"]) {
        assert.equal(isWriteMethod(method), false, `${method} must not demand an Origin`);
      }
    });

    // A body-bearing method must declare JSON — which is what keeps a plain HTML `<form>`, limited
    // to url-encoded, plain-text and multipart, from reaching a write handler at all.
    it("demands a JSON content-type from exactly the body-bearing methods", () => {
      for (const method of ["POST", "PUT", "PATCH"]) assert.equal(expectsJsonBody(method), true, method);
      for (const method of ["GET", "HEAD", "DELETE", "OPTIONS", undefined]) {
        assert.equal(expectsJsonBody(method), false, String(method));
      }
    });

    // The CLI must ask by method rather than by route. Pinned as source, because the failure mode
    // is a *new* mutating route that nobody added to a list — which no behavioural test of today's
    // routes can see.
    it("is asked by method in the CLI, not rebuilt from a route list", () => {
      const source = readFileSync(new URL("../bin/heliopause-ui.ts", import.meta.url), "utf8");
      assert.match(source, /write:\s*isWriteMethod\(req\.method\)/);
      assert.match(source, /json:\s*expectsJsonBody\(req\.method\)/);
      // And the old shape must not come back beside it.
      assert.doesNotMatch(source, /const write\s*=\s*\n?\s*\(url\.pathname/);
    });
  });

  it("accepts its numeric loopback Host and rejects a DNS-rebound Host", () => {
    assert.equal(localUiBoundaryError({ host: self.host }, self, { write: false, json: false }), null);
    const refusal = localUiBoundaryError({ host: "attacker.example" }, self, { write: false, json: false });
    assert.equal(refusal?.status, 421);
  });

  it("requires the exact loopback Origin on every write", () => {
    for (const origin of [undefined, "null", "http://attacker.example"]) {
      const refusal = localUiBoundaryError(
        { host: self.host, ...(origin === undefined ? {} : { origin }) },
        self,
        { write: true, json: false },
      );
      assert.equal(refusal?.status, 403, `${String(origin)} was accepted`);
    }
    assert.equal(
      localUiBoundaryError({ host: self.host, origin: self.origin }, self, { write: true, json: false }),
      null,
    );
  });

  it("requires JSON on body-bearing mutation routes", () => {
    const base = { host: self.host, origin: self.origin };
    assert.equal(localUiBoundaryError(base, self, { write: true, json: true })?.status, 415);
    assert.equal(
      localUiBoundaryError({ ...base, "content-type": "text/plain" }, self, { write: true, json: true })?.status,
      415,
    );
    assert.equal(
      localUiBoundaryError({ ...base, "content-type": "application/jsonp" }, self, { write: true, json: true })?.status,
      415,
    );
    assert.equal(
      localUiBoundaryError(
        { ...base, "content-type": "application/json; charset=utf-8" },
        self,
        { write: true, json: true },
      ),
      null,
    );
  });
});

function bodyStream(headers: IncomingMessage["headers"] = {}): { req: IncomingMessage; stream: PassThrough } {
  const stream = new PassThrough();
  return { req: Object.assign(stream, { headers }) as unknown as IncomingMessage, stream };
}

describe("workstation UI body limit", () => {
  it("accepts a body at the 64 KiB boundary", async () => {
    const { req, stream } = bodyStream();
    const read = readUiBody(req);
    stream.end(Buffer.alloc(MAX_UI_BODY_BYTES, 120));
    assert.equal((await read).length, MAX_UI_BODY_BYTES);
  });

  it("rejects a dishonest chunked body while streaming", async () => {
    const { req, stream } = bodyStream({ "content-length": "1" });
    const read = readUiBody(req);
    stream.write(Buffer.alloc(MAX_UI_BODY_BYTES, 120));
    stream.end(Buffer.from("x"));
    await assert.rejects(
      read,
      (error: unknown) => error instanceof UiRequestError && error.status === 413,
    );
  });

  it("rejects an oversized declared length before buffering", async () => {
    const { req } = bodyStream({ "content-length": String(MAX_UI_BODY_BYTES + 1) });
    await assert.rejects(
      readUiBody(req),
      (error: unknown) => error instanceof UiRequestError && error.status === 413,
    );
  });
});
