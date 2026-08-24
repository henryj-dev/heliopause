// The plan printout — specifically the line that tells an operator what to run next.
//
// ## Why a test for a string
//
// It said `heliopause-approve <url> <hash>`, with no `--approve`. That command is the CLI's *list*
// mode: it prints the pending plans, which prints this very line again — so an operator who follows
// the instruction verbatim sees "approved — not yet" a second time and has approved nothing. It fails
// safely and it reads exactly like a refusal.
//
// Measured 2026-08-15, on a live proposal. Nothing caught it because the string had no test and the
// two halves live in different files: the message is written here, the flags are parsed in
// `bin/heliopause-approve.ts`, and neither knows what the other says.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server } from "node:https";
import type { ServerResponse } from "node:http";
import { api, ApiError, MAX_MANAGER_RESPONSE_BYTES, printPlan, requestPath, type PlanView } from "./api-client.ts";

const plan = (over: Partial<PlanView> = {}): PlanView => ({
  hash: "sha256:abc123",
  generation: "0000000",
  proposedBy: "ops-a",
  proposedAt: "2026-01-01T00:00:00.000Z",
  approval: null,
  publishedBy: null,
  publishedAt: null,
  summary: { hosts: [{ host: "h1", stage: "canary", ruleCount: 12, rulesetHash: "sha256:deadbeefdeadbeef" }] },
  ...over,
} as PlanView);

/** Capture what `printPlan` writes, so the instruction can be read the way an operator reads it. */
const printed = (p: PlanView): string => {
  const lines: string[] = [];
  const real = console.log;
  console.log = (...args: unknown[]) => void lines.push(args.join(" "));
  try {
    printPlan(p);
  } finally {
    console.log = real;
  }
  return lines.join("\n");
};

describe("the path sent to the manager", () => {
  it("keeps the query string lookup and where-used carry", () => {
    const base = "https://manager.example";
    const lookup = new URL("/api/policy/lookup?src=10.0.0.5&dst=10.0.0.6", base);
    assert.equal(requestPath(lookup), "/api/policy/lookup?src=10.0.0.5&dst=10.0.0.6");
    assert.equal(
      requestPath(new URL("/api/policy/where-used?q=10.0.0.0%2F8", base)),
      "/api/policy/where-used?q=10.0.0.0%2F8",
    );
    assert.equal(requestPath(new URL("/api/policy/where-used?q=", base)), "/api/policy/where-used?q=");
    assert.equal(requestPath(new URL("/api/site", base)), "/api/site");
  });
});

describe("the instruction printed to the operator", () => {
  it("names the VPC the plan is for when the manager sent one", () => {
    assert.match(printed(plan({ target: "dev" })), /target     dev/);
    assert.doesNotMatch(printed(plan()), /target/);
  });

  it("names the flag that actually approves", () => {
    // Without `--approve` the command means "list", and the CLI's own usage text is the authority on
    // that: `heliopause-approve <manager-url> <plan-hash> --approve`.
    const out = printed(plan());
    assert.match(out, /heliopause-approve <url> sha256:abc123 --approve/);
  });

  it("says who has to run it", () => {
    // The other half of the sentence, and the one the manager enforces. Losing it turns a two-person
    // control into a command someone runs twice and wonders why it fails.
    assert.match(printed(plan()), /A different operator/);
  });

  it("stops instructing once the plan is approved", () => {
    // An approved plan needs `--push`, not `--approve`. Printing the approve instruction next to an
    // approval that already happened is the same class of wrong answer as the missing flag.
    const out = printed(plan({ approval: { by: "ops-b", at: "2026-01-01T00:01:00.000Z" } } as Partial<PlanView>));
    assert.match(out, /approved   ops-b/);
    assert.doesNotMatch(out, /--approve/);
  });
});


// ## The deadline on the shared client
//
// `request({ timeout })` is `socket.setTimeout` — inactivity, reset by every byte. A manager
// answering one byte at a time stayed inside it forever, and this is the client behind
// `heliopause-approve` and `heliopause-publish`: the write path. The hang is on reading the answer,
// so a deadline does not tell an operator whether the plan landed — it turns a terminal that never
// returns into an error they can act on.
//
// Driven against a real mTLS manager, because the whole thing under test is transport.
describe("the manager client's deadline", () => {
  const dir = mkdtempSync(join(tmpdir(), "heliopause-api-client-"));
  const read = (f: string) => readFileSync(join(dir, f));
  let handler: (res: ServerResponse) => void = (res) => res.end("{}");
  let server: Server | undefined;
  let port = 0;
  let pending: ReturnType<typeof setInterval> | undefined;

  before(async () => {
    const run = (...a: string[]) => execFileSync("openssl", a, { cwd: dir, stdio: "pipe" });
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
        "-days", "1", "-subj", "/CN=api-client-test-ca");
    for (const [file, cn, eku, san] of [
      ["operator", "ops", "clientAuth", ""],
      ["server", "mgr", "serverAuth", "subjectAltName=IP:127.0.0.1\n"],
    ] as const) {
      run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${file}.key`, "-out", `${file}.csr`,
          "-subj", `/CN=${cn}`);
      writeFileSync(join(dir, `${file}.ext`), `extendedKeyUsage=critical,${eku}\n${san}`);
      run("x509", "-req", "-in", `${file}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
          "-out", `${file}.pem`, "-days", "1", "-extfile", `${file}.ext`);
    }
    server = createServer(
      { cert: read("server.pem"), key: read("server.key"), ca: read("ca.pem"), requestCert: true, rejectUnauthorized: true },
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

  const creds = () => ({ cert: read("operator.pem"), key: read("operator.key"), ca: read("ca.pem"), name: "ops" });
  const call = (timeoutMs: number) =>
    api<{ ok?: boolean }>(`https://127.0.0.1:${port}/`, "/api/plans", "GET", undefined, creds(), timeoutMs);

  it("returns the manager's answer — the known positive", async () => {
    handler = (res) => { res.writeHead(200, { "content-type": "application/json" }); res.end('{"ok":true}'); };
    assert.deepEqual(await call(5_000), { ok: true });
  });

  it("ends a manager that trickles, which no idle timeout would catch", async () => {
    // The server stops on its own after a while: without that, a regression does not fail this test,
    // it hangs the run — the promise never settles and `server.close()` waits on a live connection.
    handler = (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write("{");
      pending = setInterval(() => { if (!res.writableEnded) res.write(" "); }, 40);
      setTimeout(() => { clearInterval(pending); if (!res.writableEnded) res.end("}"); }, 4_000);
      res.on("close", () => clearInterval(pending));
    };
    const started = Date.now();
    await assert.rejects(() => call(600), (e: Error) => e instanceof ApiError && /did not finish/.test(e.message));
    clearInterval(pending);
    assert.ok(Date.now() - started < 3_000, `took ${Date.now() - started}ms`);
  });

  it("refuses an answer past the ceiling instead of buffering it", async () => {
    // The bound is `readBoundedNodeBody`'s and is exercised in `bounded-body.test.ts`; what this
    // adds is that `api` hands it a real limit. Defect injection replacing the *argument* with
    // `Number.MAX_SAFE_INTEGER` left every other test here green, which is how this came to exist.
    //
    // One write of one byte past the ceiling, not a pump — a test that saturates the machine makes
    // other files' timing tests fail, which happened once already in this suite.
    handler = (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(Buffer.alloc(MAX_MANAGER_RESPONSE_BYTES + 1, 0x20));
    };
    await assert.rejects(() => call(30_000), (e: Error) => /exceeds|exceeded/.test(e.message));
  });

  it("keeps that ceiling small enough to be one", () => {
    // The test above follows the constant wherever it goes, so the constant is pinned separately.
    // Sixteen megabytes is already twice the manager's own `MAX_PLAN_BYTES`; this is a short-lived
    // workstation process, not a reason for the number to drift upward unnoticed.
    assert.ok(
      MAX_MANAGER_RESPONSE_BYTES <= 64 * 1024 * 1024,
      `${MAX_MANAGER_RESPONSE_BYTES} bytes is not a bound on a manager's answer`,
    );
  });

  it("leaves no timer armed once the call has finished", async () => {
    // A timer that fires after the promise settled cannot change it; with keep-alive it destroys a
    // pooled socket instead and the next call quietly opens a new one, so there is nothing to observe
    // from the outside. This counts the timer itself, either side of one call in the same tick.
    handler = (res) => { res.writeHead(200); res.end("{}"); };
    const timers = () => process.getActiveResourcesInfo().filter((r) => r === "Timeout").length;
    const before = timers();
    await call(5_000);
    assert.equal(timers(), before, "the deadline timer outlived the call it was bounding");
  });
});
