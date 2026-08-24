// `heliopause-status` against a real mTLS relay — the first test this command has had.
//
// It is what an operator runs first during an incident, and until now it had no deadline and no
// bound on the answer. A relay that completed the TLS handshake and then said nothing left the
// command **hanging with no output**, which is the one moment a hang is indistinguishable from a
// slow fleet; a relay that answered forever filled the workstation's memory instead.
//
// Both are the failure this repository has fixed in `feed-fetch.ts`, `otp.ts`, `oidc.ts` and
// `cert-api.ts`. This one is a CLI, so the cost is a crashed command rather than an outage — which
// is why it survived, and not a reason to leave it.
//
// ## Why a subprocess
//
// The file is an entry point: it reads `process.argv` and calls `process.exit` at module scope.
// There is nothing to import. Spawning it is also the honest test — a deadline that only holds when
// the module is loaded a particular way is not a deadline.

import { describe, it, after, before } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer, type Server } from "node:https";
import type { ServerResponse } from "node:http";

const dir = mkdtempSync(join(tmpdir(), "heliopause-status-cli-"));
const read = (f: string) => readFileSync(join(dir, f));

/** What the relay should do with the next request. Set per test. */
let handler: (res: ServerResponse) => void = (res) => res.end("{}");
let server: Server | undefined;
let port = 0;
let pending: ReturnType<typeof setInterval> | undefined;

const CLI = resolve(import.meta.dirname, "../bin/heliopause-status.ts");

before(async () => {
  const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
      "-days", "1", "-subj", "/CN=status-test-ca");
  // `operatorFiles` picks the single `operator-*.pem` in the directory and its matching key.
  for (const [file, cn, eku, san] of [
    ["operator-ops", "ops", "clientAuth", ""],
    ["relay", "relay", "serverAuth", "subjectAltName=IP:127.0.0.1\n"],
  ] as const) {
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${file}.key`, "-out", `${file}.csr`,
        "-subj", `/CN=${cn}`);
    writeFileSync(join(dir, `${file}.ext`), `extendedKeyUsage=critical,${eku}\n${san}`);
    run("x509", "-req", "-in", `${file}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", `${file}.pem`, "-days", "1", "-extfile", `${file}.ext`);
  }

  server = createServer(
    { cert: read("relay.pem"), key: read("relay.key"), ca: read("ca.pem"), requestCert: true, rejectUnauthorized: true },
    (_req, res) => handler(res),
  );
  await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
  port = (server!.address() as { port: number }).port;
});

after(async () => {
  clearInterval(pending);
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  rmSync(dir, { recursive: true, force: true });
});

/** Run the CLI to completion and report what the operator would have seen. */
function status(extra: string[] = []): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((done) => {
    const child = spawn(
      process.execPath,
      [CLI, `https://127.0.0.1:${port}/`, `--pki=${dir}`, ...extra],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let out = "";
    let err = "";
    child.stdout.on("data", (c) => (out += String(c)));
    child.stderr.on("data", (c) => (err += String(c)));
    child.on("close", (code) => done({ code, out, err }));
  });
}

const FLEET = {
  generation: "abc1234",
  issuedAt: "2026-08-24T00:00:00.000Z",
  hosts: [{ host: "gw-01.dev", generation: "abc1234", state: "confirmed", lastSeen: "2026-08-24T00:00:00.000Z" }],
  problems: [],
  relayAgeSec: 5,
};

describe("heliopause-status — the known positive", () => {
  it("prints the fleet a relay reports", async () => {
    handler = (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(FLEET));
    };
    const r = await status(["--json"]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /gw-01\.dev/);
  });
});

describe("heliopause-status — the deadline", () => {
  it("gives up on a relay that answers the handshake and then says nothing", async () => {
    // The incident case. Before the deadline this ran until the operator gave up, printing nothing —
    // and a status command that hangs looks exactly like a fleet that is slow to answer.
    handler = () => { /* accept the request and never respond */ };
    const started = Date.now();
    const r = await status(["--timeout-ms=700"]);
    const took = Date.now() - started;
    assert.notEqual(r.code, 0, "a command that cannot answer must fail rather than succeed silently");
    assert.match(r.err, /700ms/);
    // Tight on purpose. Node's own server closes an idle connection after about five seconds, so a
    // command with **no** timeout still exits here — just six seconds later and with a socket error
    // instead of a reason. A generous bound would pass against exactly the version this exists to
    // catch; measured 5,851ms with the guards removed against 700ms with them.
    assert.ok(took < 3000, `took ${took}ms — this ended because the server hung up, not because of the deadline`);
  });

  it("gives up on a relay that trickles, which no idle timeout would catch", async () => {
    // `timeout` on the request is `socket.setTimeout` — inactivity, reset by every byte. A peer
    // writing inside that window holds the command open forever, which is why the wall-clock
    // deadline is a separate thing and not the same thing spelled differently.
    handler = (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write('{"hosts":[');
      pending = setInterval(() => { if (!res.writableEnded) res.write(" "); }, 40);
      res.on("close", () => clearInterval(pending));
    };
    const started = Date.now();
    const r = await status(["--timeout-ms=700"]);
    const took = Date.now() - started;
    clearInterval(pending);
    assert.notEqual(r.code, 0);
    assert.match(r.err, /700ms/);
    assert.ok(took < 3000, `took ${took}ms — nothing ended this within the deadline`);
  });

  it("refuses a --timeout-ms that is not a positive number", async () => {
    // Otherwise `Number("soon")` is `NaN`, every comparison against it is false, and the deadline is
    // armed for `NaN` milliseconds — which fires immediately and makes every run fail for a reason
    // that has nothing to do with the fleet.
    const r = await status(["--timeout-ms=soon"]);
    assert.equal(r.code, 2);
    assert.match(r.err, /positive number/);
  });
});

describe("heliopause-status — the size of the answer", () => {
  it("does not read an unbounded body into the workstation's memory", async () => {
    // The real ceiling, streamed for real — it is `MAX_RELAY_RESPONSE_BYTES`, the manager's own bound
    // on this same answer, and eight megabytes of loopback is a fraction of a second.
    // One write of just over the ceiling, not a pump that floods until backpressure. The pump was
    // the first version and it made two unrelated timing tests flaky in the full parallel run —
    // `node --test` runs files concurrently, and a test that saturates the machine is a test that
    // fails other people's. Exceeding the bound by a byte proves exactly as much.
    handler = (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(Buffer.alloc(8 * 1024 * 1024 + 1, 0x20));
    };
    // A deadline far longer than the flood needs, so the **ceiling** is the only thing that can end
    // this. The first version allowed either reason and therefore pinned neither: removing the
    // ceiling left it green because the deadline picked up the slack. 32 MB over loopback is a
    // fraction of a second.
    const started = Date.now();
    const r = await status(["--timeout-ms=30000"]);
    assert.notEqual(r.code, 0);
    assert.match(r.err, /exceeded 8388608 bytes/);
    assert.ok(Date.now() - started < 20000, "the ceiling should end this long before the deadline");
  });
});
