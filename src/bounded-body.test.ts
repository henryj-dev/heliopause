// The bound, and the decode.
//
// Two properties, and they fail in opposite ways. An unbounded read fails loudly, eventually, as an
// OOM. A per-chunk decode fails **silently**: the JSON still parses and the value is wrong. So the
// decode case is the one written first here, and it is written against split points chosen to land
// inside a character rather than against a whole body — a test that hands the reader one chunk
// passes with either implementation.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import type { IncomingMessage } from "node:http";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as createHttpsServer, type Server } from "node:https";
import {
  BodyTooLargeError,
  readBoundedNodeBody,
  readBoundedStream,
  readBoundedText,
} from "./bounded-body.ts";
import { pollRelays } from "./manager-server.ts";

/**
 * A response that emits exactly the chunks it is given.
 *
 * `destroy` is recorded rather than implemented: the bound is supposed to stop the transfer, and a
 * test that cannot see whether it did would pass on a version that only stopped storing.
 */
function fakeResponse(chunks: Buffer[]): { res: IncomingMessage; destroyed: () => boolean } {
  const emitter = new EventEmitter() as unknown as IncomingMessage & { destroy: () => void };
  let destroyed = false;
  emitter.destroy = (() => { destroyed = true; }) as unknown as IncomingMessage["destroy"];
  queueMicrotask(() => {
    for (const chunk of chunks) {
      if (destroyed) break;
      emitter.emit("data", chunk);
    }
    if (!destroyed) emitter.emit("end");
  });
  return { res: emitter, destroyed: () => destroyed };
}

/** Split `buf` into fixed-size pieces, so a multi-byte character straddles a boundary. */
function slice(buf: Buffer, step: number): Buffer[] {
  const out: Buffer[] = [];
  for (let i = 0; i < buf.length; i += step) out.push(buf.subarray(i, i + step));
  return out;
}

describe("readBoundedNodeBody", () => {
  // ## The regression this file exists for
  //
  // `relayCall` accumulated with `payload += chunk`, which decodes each chunk on its own. A Korean
  // `detail` split at any of these offsets came back as replacement characters, and `JSON.parse`
  // accepted every one of them — so the fleet view showed a mangled reason with nothing anywhere
  // saying the transfer had been misread.
  //
  // The step sizes are not arbitrary: each one lands inside one of the three-byte sequences. A step
  // that happened to align with character boundaries would pass against the broken version.
  it("decodes once, so a character split across chunks survives", async () => {
    const detail = "규칙셋 확인 실패: nft 가 거부함";
    const encoded = Buffer.from(JSON.stringify({ detail }), "utf8");
    for (const step of [1, 2, 4, 5, 7, 12, 13]) {
      const { res } = fakeResponse(slice(encoded, step));
      const read = await readBoundedNodeBody(res, 1024, "test");
      assert.equal(
        (JSON.parse(read.toString("utf8")) as { detail: string }).detail,
        detail,
        `chunk size ${step} did not round-trip`,
      );
    }
  });

  it("refuses a body over the ceiling and stops the transfer", async () => {
    const { res, destroyed } = fakeResponse([Buffer.alloc(64, 0x61), Buffer.alloc(64, 0x62)]);
    await assert.rejects(
      () => readBoundedNodeBody(res, 100, "test"),
      (e: Error) => e instanceof BodyTooLargeError && /exceeds 100 bytes/.test(e.message),
    );
    // Storage stopping is not enough; the point of the ceiling is to stop spending.
    assert.equal(destroyed(), true);
  });

  it("reports a mid-body error rather than resolving short", async () => {
    const emitter = new EventEmitter() as unknown as IncomingMessage;
    queueMicrotask(() => {
      emitter.emit("data", Buffer.from("{"));
      emitter.emit("error", new Error("socket hang up"));
    });
    await assert.rejects(() => readBoundedNodeBody(emitter, 1024, "test"), /could not be read: socket hang up/);
  });
});

describe("readBoundedStream", () => {
  const streamOf = (chunks: Buffer[]): ReadableStream<Uint8Array> =>
    new ReadableStream({
      start(controller) {
        for (const c of chunks) controller.enqueue(new Uint8Array(c));
        controller.close();
      },
    });

  it("decodes once across chunk boundaries", async () => {
    const text = "정책이 렌더되지 않음";
    const read = await readBoundedStream(streamOf(slice(Buffer.from(text, "utf8"), 2)), 1024, "test");
    assert.equal(read.toString("utf8"), text);
  });

  it("refuses before the whole body is allocated", async () => {
    const chunks = Array.from({ length: 8 }, () => Buffer.alloc(32, 0x61));
    await assert.rejects(
      () => readBoundedStream(streamOf(chunks), 100, "renderer"),
      (e: Error) => e instanceof BodyTooLargeError && /renderer response exceeds 100 bytes/.test(e.message),
    );
  });
});

describe("readBoundedText", () => {
  it("streams when the response carries a body", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(c) { c.enqueue(new Uint8Array(Buffer.from("정책", "utf8").subarray(0, 3))); c.enqueue(new Uint8Array(Buffer.from("정책", "utf8").subarray(3))); c.close(); },
    });
    assert.equal(await readBoundedText({ body }, 1024, "renderer"), "정책");
  });

  // The substituted-reader shape. Bounded after the string exists — weaker, and the reason it is
  // acceptable is that production always takes the branch above. See the function's comment.
  it("still enforces the ceiling on a reader that only offers text()", async () => {
    await assert.rejects(
      () => readBoundedText({ text: async () => "x".repeat(200) }, 100, "renderer"),
      (e: Error) => e instanceof BodyTooLargeError,
    );
  });

  it("refuses on a Content-Length already over the ceiling", async () => {
    const headers = { get: (n: string) => (n === "content-length" ? "999" : null) };
    await assert.rejects(
      () => readBoundedText({ headers, text: async () => "short" }, 100, "renderer"),
      (e: Error) => e instanceof BodyTooLargeError,
    );
  });
});

// ── Through the real path ─────────────────────────────────────────────────────
//
// The unit tests above prove the helper decodes correctly. They cannot prove `relayCall` uses it —
// that was the defect, and it lived in a function no test drove. So this one runs a real mTLS relay
// that writes a `/status` body in pieces, with a gap between them so they arrive as separate reads
// rather than being coalesced into one segment.

describe("pollRelays decodes a relay answer that arrives in pieces", () => {
  it("keeps a non-ASCII detail intact", async () => {
    const dir = mkdtempSync(join(tmpdir(), "heliopause-relay-encoding-"));
    let server: Server | undefined;
    try {
      const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
      run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
          "-days", "1", "-subj", "/CN=test-ca");
      // `loadRelayCreds` picks the single `operator-*.pem` in the directory.
      for (const [file, cn, eku, san] of [
        ["operator-hp-manager", "hp-manager", "clientAuth", ""],
        ["relay", "relay", "serverAuth", "subjectAltName=IP:127.0.0.1\n"],
      ] as const) {
        run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${file}.key`, "-out", `${file}.csr`,
            "-subj", `/CN=${cn}`);
        writeFileSync(join(dir, `${file}.ext`), `extendedKeyUsage=critical,${eku}\n${san}`);
        run("x509", "-req", "-in", `${file}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-out", `${file}.pem`, "-days", "1", "-extfile", `${file}.ext`);
      }
      const read = (f: string) => readFileSync(join(dir, f));

      const detail = "규칙셋 확인 실패 — 관리 경로가 끊겼다";
      const payload = Buffer.from(JSON.stringify({
        generation: "gen1",
        issuedAt: "2026-08-24T00:00:00.000Z",
        hosts: [{ host: "gw-01.dev", detail }],
        problems: [],
        relayAgeSec: 5,
      }), "utf8");

      // Split inside the Korean run. Both offsets land mid-sequence, which is what makes this a
      // test of the decode rather than of the transport.
      const cut = payload.indexOf(Buffer.from("규", "utf8")) + 1;
      const pieces = [payload.subarray(0, cut), payload.subarray(cut, cut + 7), payload.subarray(cut + 7)];

      server = createHttpsServer(
        { cert: read("relay.pem"), key: read("relay.key"), ca: read("ca.pem"), requestCert: true, rejectUnauthorized: true },
        (_req, res) => {
          res.writeHead(200, { "content-type": "application/json", "content-length": payload.length });
          // A gap between writes, so the client sees separate `data` events. Without it the kernel
          // may coalesce the pieces into one segment and the test would pass either way.
          let i = 0;
          const next = () => {
            if (i >= pieces.length) return void res.end();
            res.write(pieces[i++], () => setTimeout(next, 5));
          };
          next();
        },
      );
      const port: number = await new Promise((resolve) => {
        server!.listen(0, "127.0.0.1", () => resolve((server!.address() as { port: number }).port));
      });

      const results = await pollRelays([{ name: "dev", url: `https://127.0.0.1:${port}`, pkiDir: dir }], 5_000);
      const first = results[0]!;
      assert.equal(first.ok, true, `poll failed: ${"error" in first ? first.error : ""}`);
      const hosts = (first as { view: { hosts: Array<{ detail: string }> } }).view.hosts;
      assert.equal(hosts[0]!.detail, detail);
      // Belt and braces: the failure mode is replacement characters, so name them.
      assert.ok(!hosts[0]!.detail.includes("�"), "the detail was decoded per chunk");
    } finally {
      if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
