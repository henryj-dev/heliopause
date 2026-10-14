import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPO = resolve(fileURLToPath(import.meta.url), "../..");
const CLI = join(REPO, "bin/heliopause-coverage.ts");
const FROM = "synthetic-cli-test";
const TARGET = { v4: "192.0.2.42", v6: "2001:db8::42", port: 8443 };
// coverage-probe.ts의 기본 제어 목적지와 문서용 음성 대조군만 허용한다.
const CONTROL = { host: "one.one.one.one", port: 443 };
const NEGATIVE = { v4: "192.0.2.1", v6: "2001:db8::1", port: 443 };

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "hp-coverage-cli-"));
  const site = join(dir, "site.mjs");
  const preload = join(dir, "preload.mjs");
  const marker = join(dir, "evaluated.txt");
  const out = join(dir, "coverage.json");
  const journal = join(dir, "connect.jsonl");
  try {
    writeFileSync(site, `
import { appendFileSync } from "node:fs";
appendFileSync(${JSON.stringify(marker)}, "evaluated\\n");
export const site = {
  cfg: { baseline: [] },
  coverage: [{
    id: "T1", title: "synthetic reach", expect: "reach",
    targets: [{
      host: "target.example", proto: "tcp", port: ${TARGET.port},
      addr4: ${JSON.stringify(TARGET.v4)}, addr6: ${JSON.stringify(TARGET.v6)},
    }],
  }],
};
`);
    const allowed = [4, 6].flatMap((family) => [
      { host: CONTROL.host, port: CONTROL.port, family, event: "connect" },
      { host: family === 4 ? NEGATIVE.v4 : NEGATIVE.v6, port: NEGATIVE.port, family, event: "timeout" },
      { host: family === 4 ? TARGET.v4 : TARGET.v6, port: TARGET.port, family, event: "connect" },
    ]);
    writeFileSync(preload, `
import net from "node:net";
import { syncBuiltinESMExports } from "node:module";
import { EventEmitter } from "node:events";
import { appendFileSync } from "node:fs";
const allowed = ${JSON.stringify(allowed)};
// 원본 connect를 저장하거나 호출하지 않는다. 이 대체 함수에 온 호출만 기록한다.
net.connect = (options) => {
  const { host, port, family } = options;
  const match = allowed.find((entry) =>
    entry.host === host && entry.port === port && entry.family === family);
  appendFileSync(${JSON.stringify(journal)}, JSON.stringify({
    host, port, family, event: match?.event ?? null, unexpected: !match,
  }) + "\\n");
  if (!match) throw new Error("unexpected net.connect: " + JSON.stringify(options));
  const socket = new EventEmitter();
  socket.setTimeout = () => socket;
  socket.destroy = () => socket;
  queueMicrotask(() => socket.emit(match.event));
  return socket;
};
syncBuiltinESMExports();
`);
    return { dir, site, preload, marker, out, journal };
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
}

function run(f: ReturnType<typeof fixture>, args: string[]) {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  const result = spawnSync(process.execPath, [
    `--import=${pathToFileURL(f.preload).href}`, CLI, ...args,
  ], { cwd: REPO, env, encoding: "utf8", timeout: 10_000, maxBuffer: 64 * 1024 });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  assert.ifError(result.error);
  assert.equal(result.signal, null, output);
  assert.notEqual(result.status, null, output);
  return { ...result, output };
}

function argsFor(f: ReturnType<typeof fixture>): string[] {
  return [f.site, "--from", FROM, "--out", f.out];
}

function connections(f: ReturnType<typeof fixture>): {
  host: string; port: number; family: number; event: string | null; unexpected: boolean;
}[] {
  return existsSync(f.journal)
    ? readFileSync(f.journal, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line))
    : [];
}

function assertUntouched(f: ReturnType<typeof fixture>) {
  assert.equal(existsSync(f.marker), false, "site was evaluated");
  assert.equal(existsSync(f.out), false, "coverage output was written");
  assert.deepEqual(connections(f), [], "net.connect was called");
}

describe("heliopause-coverage — CLI families", () => {
  for (const { name, args, families } of [
    { name: "defaults to both families", args: [], families: ["v4", "v6"] },
    { name: "measures only v4 and trims its token", args: ["--families", " v4 "], families: ["v4"] },
    { name: "measures only v6", args: ["--families", "v6"], families: ["v6"] },
  ]) {
    it(name, () => {
      const f = fixture();
      try {
        const result = run(f, [...argsFor(f), ...args]);
        assert.equal(result.status, 0, result.output);
        assert.equal(readFileSync(f.marker, "utf8"), "evaluated\n");
        assert.equal(existsSync(f.out), true, result.output);
        const saved = JSON.parse(readFileSync(f.out, "utf8")) as {
          schemaVersion: number; observedFrom: string;
          probes: { checkId: string; family: string; addr: string; port: number; outcome: string; observedFrom: string }[];
        };
        assert.equal(saved.schemaVersion, 1);
        assert.equal(saved.observedFrom, FROM);
        assert.deepEqual(saved.probes.map((probe) => probe.family), families);
        assert.deepEqual(saved.probes.map(({ checkId, family, addr, port, outcome, observedFrom }) => ({
          checkId, family, addr, port, outcome, observedFrom,
        })), families.map((family) => ({
          checkId: "T1", family, addr: family === "v4" ? TARGET.v4 : TARGET.v6,
          port: TARGET.port, outcome: "connected", observedFrom: FROM,
        })));
        assert.match(result.output, /0 failing · 0 not measured · 1 passing/);
        const calls = connections(f);
        assert.equal(calls.length, families.length * 3);
        assert.equal(calls.filter((call) => call.unexpected).length, 0);
        const key = (call: { host: string; port: number; family: number; event: string | null }) =>
          `${call.host}|${call.port}|${call.family}|${call.event}`;
        assert.deepEqual(calls.map(key).sort(), families.flatMap((family) => {
          const numericFamily = family === "v4" ? 4 : 6;
          return [
            key({ host: CONTROL.host, port: CONTROL.port, family: numericFamily, event: "connect" }),
            key({ host: family === "v4" ? NEGATIVE.v4 : NEGATIVE.v6, port: NEGATIVE.port, family: numericFamily, event: "timeout" }),
            key({ host: family === "v4" ? TARGET.v4 : TARGET.v6, port: TARGET.port, family: numericFamily, event: "connect" }),
          ];
        }).sort());
      } finally {
        rmSync(f.dir, { recursive: true, force: true });
      }
    });
  }

  for (const { name, args } of [
    { name: "refuses v5 before evaluating the site", args: ["--families", "v5"] },
    { name: "refuses an empty family token", args: ["--families", "v4,"] },
    { name: "refuses an empty families argument", args: ["--families", ""] },
    { name: "refuses a missing families argument at the end", args: ["--families"] },
    { name: "does not consume --out as a families argument", args: ["--families", "--out"] },
  ]) {
    it(name, () => {
      const f = fixture();
      try {
        const cliArgs = args.at(-1) === "--out"
          ? [f.site, "--from", FROM, ...args, f.out]
          : [...argsFor(f), ...args];
        const result = run(f, cliArgs);
        assert.equal(result.status, 64, result.output);
        assert.match(result.output, /usage: heliopause-coverage/);
        assertUntouched(f);
      } finally {
        rmSync(f.dir, { recursive: true, force: true });
      }
    });
  }

  it("keeps help ahead of invalid families", () => {
    const f = fixture();
    try {
      const result = run(f, [...argsFor(f), "--families", "v5", "--help"]);
      assert.equal(result.status, 0, result.output);
      assert.match(result.output, /usage: heliopause-coverage/);
      assertUntouched(f);
    } finally {
      rmSync(f.dir, { recursive: true, force: true });
    }
  });

  it("still requires the site and --from", () => {
    const f = fixture();
    try {
      for (const args of [
        ["--from", FROM, "--out", f.out, "--families", "v4"],
        [f.site, "--out", f.out, "--families", "v4"],
      ]) {
        const result = run(f, args);
        assert.equal(result.status, 64, result.output);
        assert.match(result.output, /usage: heliopause-coverage/);
        assertUntouched(f);
      }
    } finally {
      rmSync(f.dir, { recursive: true, force: true });
    }
  });
});
