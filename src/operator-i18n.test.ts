import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { describe, it } from "node:test";
import { formatOperatorLog, localizeCliText, logLangFromEnv, OPERATOR_LOG_MESSAGES, parseCliLang } from "./operator-i18n.ts";

describe("operator log catalogue", () => {
  it("has both languages and preserves raw error detail", () => {
    for (const entry of Object.values(OPERATOR_LOG_MESSAGES)) assert.ok(entry.en && entry.ko);
    assert.equal(formatOperatorLog("ko", "server.unhandled", { error: "ECONNREFUSED" }), "처리되지 않은 오류: ECONNREFUSED");
  });
});

describe("operator language selection", () => {
  it("uses an explicit CLI language before LANG and removes its flag", () => {
    assert.deepEqual(parseCliLang(["--lang", "ko", "--watch"], { LANG: "en_US" }), { lang: "ko", argv: ["--watch"] });
    assert.deepEqual(parseCliLang(["--watch"], { LANG: "ko_KR.UTF-8" }), { lang: "ko", argv: ["--watch"] });
  });
  it("defaults server journals to English and rejects bad deployment values", () => {
    assert.equal(logLangFromEnv({}), "en");
    assert.equal(logLangFromEnv({ HELIOPAUSE_LOG_LANG: "ko" }), "ko");
    assert.throws(() => logLangFromEnv({ HELIOPAUSE_LOG_LANG: "fr" }), /must be en or ko/);
  });
  it("localizes prose but leaves JSON and generated code exact", () => {
    assert.equal(localizeCliText("published generation 4 — dry run"), "발행됨 generation 4 — 미리 보기 실행");
    assert.equal(localizeCliText('{"status":"active"}'), '{"status":"active"}');
    assert.equal(localizeCliText("export const X = 1;"), "export const X = 1;");
  });
  it("keeps every bin entrypoint behind the shared output localizer", () => {
    const bin = resolve(import.meta.dirname, "../bin");
    for (const name of readdirSync(bin).filter((name) => name.endsWith(".ts"))) {
      const source = readFileSync(resolve(bin, name), "utf8");
      assert.match(source, /installCliLanguage/, `${name} bypasses --lang`);
      const setup = Math.max(source.indexOf("installCliLanguage();"), source.indexOf("= installCliLanguage("));
      const output = source.search(/\b(?:console\.(?:log|error|warn)|process\.(?:stdout|stderr)\.write)\(/);
      assert.ok(setup >= 0 && (output < 0 || setup < output), `${name} emits output before installing its locale`);
    }
  });
  it("localizes PKI usage and the privileged writer's startup errors", () => {
    const bin = resolve(import.meta.dirname, "../bin");
    const pki = spawnSync(process.execPath, [resolve(bin, "heliopause-pki.ts")], { env: { ...process.env, LANG: "ko_KR.UTF-8" }, encoding: "utf8" });
    assert.equal(pki.status, 2);
    assert.match(pki.stderr, /사용법:/);
    assert.equal(pki.stderr.includes("usage:"), false);
    const writer = spawnSync(process.execPath, [resolve(bin, "heliopause-revocation-writer.ts")], { env: { ...process.env, HELIOPAUSE_LOG_LANG: "ko", HELIOPAUSE_REVOCATION_FILE: "" }, encoding: "utf8" });
    assert.equal(writer.status, 2);
    assert.match(writer.stderr, /필수 환경 변수가 없음/);
  });
});
