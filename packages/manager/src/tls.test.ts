import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { resolveTls } from "./tls.ts";

describe("manager scaffold TLS configuration", () => {
  it("reads both configured certificate files", () => {
    const dir = mkdtempSync(join(tmpdir(), "heliopause-manager-tls-"));
    const cert = join(dir, "cert.pem");
    const key = join(dir, "key.pem");
    writeFileSync(cert, "certificate");
    writeFileSync(key, "key");
    assert.deepEqual(resolveTls({ HELIOPAUSE_CERT_FILE: cert, HELIOPAUSE_KEY_FILE: key }), {
      cert: Buffer.from("certificate"), key: Buffer.from("key"),
    });
  });

  it("refuses a certificate without its key", () => {
    assert.throws(
      () => resolveTls({ HELIOPAUSE_CERT_FILE: "/tmp/cert.pem" }),
      /HELIOPAUSE_KEY_FILE/,
    );
  });

  it("refuses a key without its certificate", () => {
    assert.throws(
      () => resolveTls({ HELIOPAUSE_KEY_FILE: "/tmp/key.pem" }),
      /HELIOPAUSE_CERT_FILE/,
    );
  });

  it("keeps the self-signed development fallback when neither file is configured", () => {
    const tls = resolveTls({ HELIOPAUSE_CERT_FILE: "", HELIOPAUSE_KEY_FILE: "" });
    assert.match(tls.cert.toString("utf8"), /BEGIN CERTIFICATE/);
    assert.match(tls.key.toString("utf8"), /BEGIN PRIVATE KEY/);
  });
});
