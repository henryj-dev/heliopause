// The internet boundary, which had no test at all.
//
// `feed-fetch.ts` is the only code in this project that opens a socket to a stranger, and what comes
// back becomes firewall rules. Its header lists four refusals it makes and explains why each one
// follows from that. Three were implemented; the fourth was a sentence.
//
// That is the shape this file is really about. Every assertion below drives the real module against
// a real HTTPS server, because the three implemented refusals are all in the *transport* — a fake
// that returns strings would agree with any of them, and did not exist either.
//
// ## The certificate, and why `globalAgent`
//
// `makeFetchFeed` takes no CA option, deliberately: production verifies against the system store and
// a per-call trust argument is a thing an operator could get wrong. `request()` with no `agent` uses
// `https.globalAgent`, so the test trusts its own CA there and puts it back afterwards. The
// alternative is `NODE_EXTRA_CA_CERTS`, which is process-wide and cannot be set from inside a test.

import { describe, it, after, before } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, globalAgent, type Server } from "node:https";
import type { ServerResponse } from "node:http";
import { makeFetchFeed } from "./feed-fetch.ts";
import { contains } from "./test-util.ts";

const dir = mkdtempSync(join(tmpdir(), "heliopause-feed-fetch-"));
const read = (f: string) => readFileSync(join(dir, f));

/** What the next request should do. Set per test, so one server serves every case. */
let handler: (res: ServerResponse) => void = (res) => res.end("");
let server: Server | undefined;
let port = 0;
let savedCa: unknown;
/** Held at module scope so `after` can stop them even if an assertion threw first. */
let trickle: ReturnType<typeof setInterval> | undefined;
let stopTrickle: ReturnType<typeof setTimeout> | undefined;

before(async () => {
  const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
      "-days", "1", "-subj", "/CN=feed-test-ca");
  run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "s.key", "-out", "s.csr", "-subj", "/CN=feed");
  writeFileSync(join(dir, "s.ext"), "subjectAltName=IP:127.0.0.1\n");
  run("x509", "-req", "-in", "s.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", "s.pem", "-days", "1", "-extfile", "s.ext");

  savedCa = globalAgent.options.ca;
  globalAgent.options.ca = read("ca.pem");

  server = createServer({ cert: read("s.pem"), key: read("s.key") }, (_req, res) => handler(res));
  await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
  port = (server!.address() as { port: number }).port;
});

after(async () => {
  clearInterval(trickle);
  clearTimeout(stopTrickle);
  globalAgent.options.ca = savedCa as never;
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  rmSync(dir, { recursive: true, force: true });
});

const url = () => `https://127.0.0.1:${port}/feed`;
const fetchWith = (over: Partial<{ maxBytes: number; timeoutMs: number }> = {}) =>
  makeFetchFeed({ maxBytes: 32 * 1024 * 1024, timeoutMs: 30_000, ...over });

const failure = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "";
  } catch (e) {
    return (e as Error).message;
  }
};

describe("feed fetch — the known positive", () => {
  it("returns the body of a 200", async () => {
    // Without this every refusal below would pass against a function that refuses everything.
    handler = (res) => { res.writeHead(200, { "content-type": "text/csv" }); res.end("192.0.2.0/24,KR\n"); };
    assert.equal(await fetchWith()(url()), "192.0.2.0/24,KR\n");
  });

  it("decodes a body that arrives in pieces, without splitting a character", async () => {
    // The same defect class `bounded-body.ts` exists for. `chunks.push` + one `Buffer.concat` is the
    // correct shape; `text += chunk` would decode each piece alone and mangle the split character.
    const body = Buffer.from("설명,KR\n192.0.2.0/24,KR\n", "utf8");
    const cut = body.indexOf(Buffer.from("명", "utf8")) + 1;
    handler = (res) => {
      res.writeHead(200, { "content-type": "text/csv" });
      res.write(body.subarray(0, cut), () => setTimeout(() => res.end(body.subarray(cut)), 5));
    };
    assert.equal(await fetchWith()(url()), body.toString("utf8"));
  });
});

describe("feed fetch — the refusals its header promises", () => {
  it("refuses a URL that is not a URL", async () => {
    contains(await failure(fetchWith()("not a url")), "is not a URL");
  });

  it("refuses http, because rewriting the feed rewrites the firewall", async () => {
    contains(await failure(fetchWith()("http://127.0.0.1/feed")), "must be https");
  });

  it("does not follow a redirect", async () => {
    // A redirect is a third party naming a different host. The registered URL is what was reviewed,
    // so this must be a refusal and not a second request.
    handler = (res) => { res.writeHead(302, { location: "https://example.invalid/elsewhere" }); res.end(); };
    const why = await failure(fetchWith()(url()));
    contains(why, "302");
    contains(why, "not followed");
  });

  it("refuses a non-200", async () => {
    handler = (res) => { res.writeHead(500); res.end("boom"); };
    contains(await failure(fetchWith()(url())), "answered 500");
  });

  it("enforces the byte ceiling while reading, against a body with no declared length", async () => {
    // Chunked, so there is no `Content-Length` to check up front even if this wanted to — the count
    // has to happen during the read, which is the point. A server that declares a small length and
    // then sends more is not the fixture to write here: Node's own server refuses to put those extra
    // bytes on the wire, so the test would be about Node rather than about this module.
    handler = (res) => {
      res.writeHead(200, { "content-type": "text/csv" });
      const blob = Buffer.alloc(64 * 1024, 0x61);
      // Pumped through `drain`. Stopping at the first `false` — the obvious shape — sends one 64 KB
      // chunk and then nothing, which is under the ceiling, and the test then waits out the deadline
      // instead of measuring what it came to measure.
      const push = () => { while (!res.writableEnded && res.write(blob)) { /* until backpressure */ } };
      res.on("drain", push);
      push();
    };
    // A short deadline so a regression fails in a second rather than in thirty.
    contains(
      await failure(fetchWith({ maxBytes: 128 * 1024, timeoutMs: 5_000 })(url())),
      "exceeded 131072 bytes",
    );
  });

  it("says the body was too large, not that the connection dropped", async () => {
    // The reason, not just the refusal. Enforcing the ceiling means destroying the stream, and that
    // makes it emit `aborted`, whose handler rejects too — so the order of those two lines decides
    // which sentence the operator gets. Measured on this file's first run: destroying first reported
    // "feed connection aborted mid-body" for a body that was simply over the ceiling.
    //
    // Both are refusals and `refreshFeed` keeps the previous snapshot either way. They send a reader
    // opposite ways: one is a network blip worth retrying, the other is a feed larger than the
    // ceiling it was registered with, where no retry helps.
    handler = (res) => { res.writeHead(200); res.end(Buffer.alloc(4096, 0x61)); };
    contains(await failure(fetchWith({ maxBytes: 1024 })(url())), "exceeded 1024 bytes");
  });

  it("lets a feed's own smaller ceiling win over the global one", async () => {
    handler = (res) => { res.writeHead(200); res.end(Buffer.alloc(4096, 0x61)); };
    contains(await failure(fetchWith({ maxBytes: 1024 * 1024 })(url(), 1024)), "exceeded 1024 bytes");
    // …and a per-feed ceiling *larger* than the global one does not raise it. The global bound is
    // what this process will ever buffer; a feed does not get to widen it.
    contains(
      await failure(fetchWith({ maxBytes: 2048 })(url(), 1024 * 1024)),
      "exceeded 2048 bytes",
    );
  });
});

// ## The refusal that was a sentence
//
// The header has always listed "a wall-clock deadline — a feed that trickles forever holds the
// refresh open forever" among the four. `request({ timeout })` is `socket.setTimeout`, which fires on
// *inactivity*: every byte resets it. Measured 2026-08-24 before the fix — one byte every 200ms
// against a 1000ms timeout was still connected six seconds later, and would have stayed.
//
// Neither of the other two bounds covers it. The ceiling counts bytes and a trickle sends few; at the
// production settings a byte every 29 seconds reaches 32 MB in about thirty years. `refreshFeed` is
// awaiting this promise the whole time.
describe("feed fetch — the wall-clock deadline", () => {
  it("ends a body that arrives slowly enough never to trip the idle timeout", async () => {
    // The server gives up on its own after `TRICKLE_LIMIT_MS`. Not politeness — without it a
    // regression does not fail this test, it **hangs the whole run**: the fetch never settles, the
    // interval keeps writing, and `server.close()` in `after` waits on a connection that never ends.
    // A defect-injection pass against the unfixed module sat there until it was killed, which is a
    // test that reports nothing rather than a test that fails.
    const TRICKLE_LIMIT_MS = 4_000;
    handler = (res) => {
      res.writeHead(200, { "content-type": "text/csv" });
      // Well inside the deadline, so an idle timeout is reset on every write and never fires.
      trickle = setInterval(() => { if (!res.writableEnded) res.write("x"); }, 40);
      stopTrickle = setTimeout(() => { clearInterval(trickle); if (!res.writableEnded) res.end(); }, TRICKLE_LIMIT_MS);
      res.on("close", () => { clearInterval(trickle); clearTimeout(stopTrickle); });
    };
    const started = Date.now();
    const why = await failure(fetchWith({ timeoutMs: 400 })(url()));
    const took = Date.now() - started;
    clearInterval(trickle);
    clearTimeout(stopTrickle);
    contains(why, "did not finish within 400ms");
    // Bounded above as well as below: a deadline that fired at some unrelated later moment would
    // still produce the message. Generous, because CI machines are slow, and well under the point
    // where the server would have ended the body itself.
    assert.ok(took < TRICKLE_LIMIT_MS - 500, `took ${took}ms`);
  });

  it("leaves no timer armed once the fetch has finished", async () => {
    // The known positive for the deadline, and the second attempt at writing it. The first fetched,
    // waited past the deadline, and fetched again — and **passed with the clearing removed**, which
    // makes it a test of nothing. A timer that fires after the promise has settled cannot change the
    // promise; `keepAlive` means it may destroy a pooled socket instead, and the next request quietly
    // opens a new one. There is nothing to observe from the outside.
    //
    // So this observes the timer itself. `getActiveResourcesInfo` lists what is holding the loop up,
    // and the count is taken either side of one fetch in the same tick, so the delta is this fetch's.
    // With a five-second deadline against an immediate response, an uncleared timer is still pending
    // the moment `await` returns.
    handler = (res) => { res.writeHead(200); res.end("192.0.2.0/24,KR\n"); };
    const timers = () => process.getActiveResourcesInfo().filter((r) => r === "Timeout").length;
    const before = timers();
    assert.equal(await fetchWith({ timeoutMs: 5_000 })(url()), "192.0.2.0/24,KR\n");
    assert.equal(timers(), before, "the deadline timer outlived the fetch it was bounding");
  });
});
