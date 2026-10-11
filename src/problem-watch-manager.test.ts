/**
 * The problem watch inside `startManager` and the manager binary (#148 PR 3). The runner's own
 * behaviour is in `problem-watch-runner.test.ts`; this file holds what only a running manager shows.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startManager } from "./manager-server.ts";
import { parseWatchAliases, readRelayStatus, type RelayRead } from "./problem-watch.ts";
import { startProblemWatch } from "./problem-watch-runner.ts";

const dir = mkdtempSync(join(tmpdir(), "hp-watch-mgr-"));
const RELAY = "zone-a.example";
const H1 = "h1.zone-a.example";
const ALIASES_TEXT = JSON.stringify({ relays: { [RELAY]: "za" }, hosts: { [RELAY]: { [H1]: "web" } } });
const ALIASES = parseWatchAliases(ALIASES_TEXT, [RELAY]);

before(() => {
  const run = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=test-ca");
  for (const [name, eku] of [["server", "serverAuth"], ["ops", "clientAuth"]] as const) {
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`,
      "-subj", `/CN=${name === "server" ? "manager" : "ops-alice"}`);
    writeFileSync(join(dir, `${name}.ext`),
      `extendedKeyUsage=critical,${eku}\n` + (name === "server" ? "subjectAltName=IP:127.0.0.1\n" : ""));
    run("x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", `${name}.pem`, "-days", "1", "-extfile", `${name}.ext`);
  }
  writeFileSync(join(dir, "aliases.json"), ALIASES_TEXT);
});
after(() => rmSync(dir, { recursive: true, force: true }));

function healthz(port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = request({
      host: "127.0.0.1", port, path: "/healthz", method: "GET",
      ca: [readFileSync(join(dir, "ca.pem"))], cert: readFileSync(join(dir, "ops.pem")), key: readFileSync(join(dir, "ops.key")),
    }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
    req.on("error", reject);
    req.end();
  });
}

const body = (evaluated: Record<string, Record<string, string>>): ReadonlyMap<string, RelayRead> => new Map([[RELAY, readRelayStatus({
  findings: [], evaluated, fleetEvaluated: {}, observability: { manifest: true, graceActive: false },
})]]);

/** A manager with the watch on, every watch boundary but the files replaced. */
async function manager(stateFile: string, poll?: () => Promise<ReadonlyMap<string, RelayRead>>) {
  const lines: Record<string, unknown>[] = [];
  const timers: { fn: () => void }[] = [];
  const cleared: unknown[] = [];
  let polls = 0;
  const started = await startManager({
    port: 0, hostname: "127.0.0.1",
    relays: [{ name: RELAY, url: "https://127.0.0.1:1/", pkiDir: dir }],
    tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
    operatorCNs: ["ops-alice"], timeoutMs: 200,
    problemWatch: {
      stateFile, aliases: ALIASES, intervalMs: 30_000, allowEmptyState: true,
      ...(poll ? { poll: async () => { polls += 1; return poll(); } } : {}),
      emit: (l) => lines.push(JSON.parse(l) as Record<string, unknown>),
      setInterval: (fn) => { const h = { fn }; timers.push(h); return h; },
      clearInterval: (h) => cleared.push(h),
    },
  });
  const port = (started.server.address() as { port: number }).port;
  /** What the interval does, then wait until the watch writes a line or two seconds pass. */
  const fire = async () => {
    const before = lines.length;
    for (const t of timers) t.fn();
    for (let i = 0; i < 200 && lines.length === before; i++) await new Promise((r) => setTimeout(r, 10));
    for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
  };
  const whats = () => lines.filter((l) => l.event === "heliopause.problem.watch").map((l) => l.what);
  return { started, port, lines, timers, cleared, polls: () => polls, fire, whats };
}

describe("problem watch in the manager", () => {
  it("a second watcher does not start while the lock is held, and the manager keeps serving", async () => {
    const stateFile = join(dir, "held.json");
    const holder = startProblemWatch({
      stateFile, aliases: ALIASES, intervalMs: 30_000, allowEmptyState: true,
      poll: async () => new Map(), emit: () => {}, setInterval: () => ({}), clearInterval: () => {},
    });
    const m = await manager(stateFile, async () => body({ [H1]: { silent: "yes" } }));
    try {
      assert.deepEqual(m.whats(), ["lock_held"]);
      assert.equal(await healthz(m.port), 200);
      await m.fire();
      assert.deepEqual(m.whats(), ["lock_held", "lock_held"]);
      assert.equal(m.polls(), 0);
    } finally {
      await new Promise<void>((resolve) => m.started.server.close(() => resolve()));
      holder.stop();
    }
  });

  it("an alias equal to a manifest host label turns the watch off without stopping the manager", async () => {
    const stateFile = join(dir, "collide.json");
    const m = await manager(stateFile, async () => body({ [H1]: { silent: "yes" }, "web.zone-b.example": { silent: "yes" } }));
    try {
      assert.deepEqual(m.whats(), ["lock_acquired", "state_initialized", "started"]);
      await m.fire();
      assert.equal(m.polls(), 1);
      assert.equal(m.whats().at(-1), "alias_collision");
      assert.equal(existsSync(`${stateFile}.lock`), false);
      assert.equal(await healthz(m.port), 200);
    } finally {
      await new Promise<void>((resolve) => m.started.server.close(() => resolve()));
    }
  });

  it("the default poll reads the relays through pollRelays, and an unreachable relay opens relay-unobservable after two cycles", async () => {
    const stateFile = join(dir, "default-poll.json");
    const m = await manager(stateFile);
    try {
      await m.fire();
      const opened = () => m.lines.filter((l) => l.transition === "opened").map((l) => `${String(l.relay)}/${String(l.host)}/${String(l.kind)}`);
      assert.deepEqual(opened(), []);
      const firstCycle = m.lines.find((l) => l.event === "heliopause.problem.cycle") as { relays: { reason: unknown }[] } | undefined;
      assert.deepEqual(firstCycle?.relays.map((r) => r.reason), ["unreachable"]);
      await m.fire();
      assert.deepEqual(opened(), ["za/_relay/relay-unobservable"]);
    } finally {
      await new Promise<void>((resolve) => m.started.server.close(() => resolve()));
    }
  });

  it("without a problem watch the manager serves healthz and stopProblemWatch does nothing", async () => {
    const started = await startManager({
      port: 0, hostname: "127.0.0.1",
      relays: [{ name: RELAY, url: "https://127.0.0.1:1/", pkiDir: dir }],
      tls: { certFile: join(dir, "server.pem"), keyFile: join(dir, "server.key"), caFile: join(dir, "ca.pem") },
      operatorCNs: ["ops-alice"], timeoutMs: 200,
    });
    try {
      assert.equal(await healthz((started.server.address() as { port: number }).port), 200);
      assert.doesNotThrow(() => started.stopProblemWatch());
    } finally {
      await new Promise<void>((resolve) => started.server.close(() => resolve()));
    }
  });

  it("manager close stops the watch timer", async () => {
    const stateFile = join(dir, "close.json");
    const m = await manager(stateFile, async () => body({ [H1]: { silent: "yes" } }));
    await m.fire();
    // Known positive: the watch was running and holding its lock.
    assert.ok(m.lines.some((l) => l.event === "heliopause.problem.cycle"));
    assert.equal(existsSync(`${stateFile}.lock`), true);
    await new Promise<void>((resolve) => m.started.server.close(() => resolve()));
    assert.deepEqual(m.cleared, m.timers);
    assert.equal(existsSync(`${stateFile}.lock`), false);
    assert.equal(m.whats().at(-1), "stopped");
  });
});

describe("problem watch in the manager binary", () => {
  const BIN = join(import.meta.dirname, "..", "bin", "heliopause-manager.ts");

  /** Run the binary to its exit and return the code and stderr; fails after 20 s. */
  function exitOf(extraEnv: Record<string, string>): Promise<{ code: number | null; err: string }> {
    const signingKey = join(dir, "signing.pem");
    if (!existsSync(signingKey)) {
      writeFileSync(signingKey, generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }));
      chmodSync(signingKey, 0o600);
    }
    const proc = spawn(process.execPath, [BIN], {
      env: {
        PATH: process.env.PATH ?? "",
        HELIOPAUSE_RELAYS: `${RELAY}=https://127.0.0.1:1/=${dir}`,
        HELIOPAUSE_MANAGER_PORT: "0", HELIOPAUSE_MANAGER_HOST: "127.0.0.1",
        HELIOPAUSE_CERT_FILE: join(dir, "server.pem"), HELIOPAUSE_KEY_FILE: join(dir, "server.key"),
        HELIOPAUSE_CA_FILE: join(dir, "ca.pem"), HELIOPAUSE_ARTIFACT_SIGNING_KEY_FILE: signingKey,
        HELIOPAUSE_OPERATOR_CNS: "ops-alice",
        ...extraEnv,
      },
      stdio: ["ignore", "ignore", "pipe"],
    });
    return new Promise((resolve, reject) => {
      let err = "";
      const timer = setTimeout(() => { proc.kill("SIGKILL"); reject(new Error(`still running after 20s:\n${err}`)); }, 20_000);
      proc.stderr.on("data", (b: Buffer) => { err += b; });
      proc.on("exit", (code) => { clearTimeout(timer); resolve({ code, err }); });
    });
  }

  it("refuses to start when the watch is on without an aliases file, or its lock cannot be created", { timeout: 60_000 }, async () => {
    const noAliases = await exitOf({ HELIOPAUSE_PROBLEM_WATCH_STATE_FILE: join(dir, "bin.json") });
    assert.equal(noAliases.code, 2, noAliases.err);
    assert.match(noAliases.err, /HELIOPAUSE_PROBLEM_WATCH_ALIASES_FILE is required/);
    const noDir = await exitOf({
      HELIOPAUSE_PROBLEM_WATCH_STATE_FILE: join(dir, "missing", "bin.json"),
      HELIOPAUSE_PROBLEM_WATCH_ALIASES_FILE: join(dir, "aliases.json"),
    });
    assert.equal(noDir.code, 2, noDir.err);
    assert.match(noDir.err, /cannot create the problem watch lock \(ENOENT\)/);
  });
});
