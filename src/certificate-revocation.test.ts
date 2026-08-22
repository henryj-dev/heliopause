import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { certificateIsRevoked } from "./certificate-revocation.ts";
import { emptyEnrollmentDocument, revokeCertificate, saveEnrollmentDocument } from "./enrollment-store.ts";

describe("certificate fingerprint revocation", () => {
  it("is immediately visible from the shared file and fails closed if it disappears", () => {
    const root = mkdtempSync(join(tmpdir(), "heliopause-revocation-")); const key = join(root, "key.pem"); const cert = join(root, "cert.pem"); const store = join(root, "store.json");
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=revoked-host"], { stdio: "ignore" });
    const document = emptyEnrollmentDocument(); const row = revokeCertificate(document, { certificatePem: readFileSync(cert, "utf8"), reason: "host retired", actor: "ops" });
    assert.equal(revokeCertificate(document, { certificatePem: readFileSync(cert, "utf8"), reason: "again", actor: "ops" }), row);
    saveEnrollmentDocument(store, document);
    const req = { socket: { authorized: true, getPeerCertificate: () => ({ fingerprint256: row.fingerprint256.match(/../g)!.join(":") }) } } as any;
    assert.equal(certificateIsRevoked(store, req, "enrollment"), true);
    assert.equal(certificateIsRevoked(join(root, "missing.json"), req), true);
    assert.equal(certificateIsRevoked(undefined, req), false);

    const snapshot = join(root, "snapshot.json");
    writeFileSync(snapshot, JSON.stringify({ schemaVersion: 1, revocations: [row] }));
    assert.equal(certificateIsRevoked(snapshot, req, "snapshot"), true);

    const malformed: unknown[] = [
      {},
      { schemaVersion: 1 },
      { schemaVersion: 1, revocations: "bad" },
      { schemaVersion: 1, revocations: [], tokens: [] },
      { schemaVersion: 1, revocations: [{ ...row, csrPem: "must-not-cross-boundary" }] },
    ];
    for (const value of malformed) {
      writeFileSync(snapshot, JSON.stringify(value));
      assert.equal(certificateIsRevoked(snapshot, req, "snapshot"), true, JSON.stringify(value));
    }

    writeFileSync(store, JSON.stringify({ ...document, unknown: true }));
    assert.equal(certificateIsRevoked(store, req, "enrollment"), true);
    writeFileSync(store, JSON.stringify({ ...document, revocations: [{ ...row, tokens: [] }] }));
    assert.equal(certificateIsRevoked(store, req, "enrollment"), true);
  });
});
