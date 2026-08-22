import { execFileSync, spawnSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";

const cli = resolve("bin/heliopause-pki.ts");
const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture(curve = "prime256v1", subject = "/CN=host-01.example") {
  const root = mkdtempSync(join(tmpdir(), "heliopause-csr-test-"));
  dirs.push(root);
  const ca = join(root, "ca");
  const key = join(root, "host.key");
  const csr = join(root, "host.csr");
  execFileSync(process.execPath, [cli, "init", ca]);
  execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt", `ec_paramgen_curve:${curve}`, "-out", key]);
  execFileSync("openssl", ["req", "-new", "-key", key, "-subj", subject, "-out", csr]);
  const der = execFileSync("openssl", ["req", "-in", csr, "-outform", "DER"]);
  const digest = createHash("sha256").update(der).digest("hex");
  return { root, ca, csr, digest };
}

function sign(f: ReturnType<typeof fixture>, out: string, digest = f.digest) {
  return spawnSync(process.execPath, [
    cli, "sign-csr", f.ca, f.csr, out,
    "--name=host-01.example", `--expect-sha256=${digest}`,
  ], { encoding: "utf8" });
}

describe("offline host CSR signer", () => {
  it("issues only the fixed agent profile from a matching P-256 CSR", () => {
    const f = fixture();
    const out = join(f.root, "agent.pem");
    const result = sign(f, out);
    assert.equal(result.status, 0, result.stderr);
    const cert = new X509Certificate(readFileSync(out));
    assert.equal(cert.subject, "CN=host-01.example");
    assert.equal(cert.subjectAltName, undefined);
    assert.equal(cert.ca, false);
    const text = execFileSync("openssl", ["x509", "-in", out, "-noout", "-text"], { encoding: "utf8" });
    assert.match(text, /TLS Web Client Authentication/);
    assert.doesNotMatch(text, /TLS Web Server Authentication/);
  });

  it("refuses a downloaded CSR whose digest differs from the host console", () => {
    const f = fixture();
    const out = join(f.root, "agent.pem");
    const result = sign(f, out, "0".repeat(64));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /SHA-256 mismatch/);
    assert.throws(() => readFileSync(out));
  });

  it("refuses a second subject field and a non-P-256 key", () => {
    for (const f of [fixture("prime256v1", "/CN=host-01.example/O=other"), fixture("secp384r1")]) {
      const out = join(f.root, "agent.pem");
      const result = sign(f, out);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /subject mismatch|must be ECDSA P-256/);
    }
  });
});
