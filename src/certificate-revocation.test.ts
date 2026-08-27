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

  it("reads a store the enrollment writer actually produces, whichever fields it has", () => {
    // 🔑 The regression that this file did not have. Every case above asserts `true`, and `true` is
    // also what an unreadable file returns — so a reader that rejected the *whole store format*
    // would have looked correct here while reporting every valid certificate as revoked. That is
    // exactly what happened when the store gained `appTokens`: 30 tests failed with "client
    // certificate has been revoked", none of them in this file.
    //
    // Pinned from `saveEnrollmentDocument`, not from a literal, so the next field added to the store
    // fails here rather than in a manager an operator is locked out of.
    const root = mkdtempSync(join(tmpdir(), "heliopause-revocation-current-"));
    const store = join(root, "store.json");
    const req = { socket: { authorized: true, getPeerCertificate: () => ({ fingerprint256: "aa:bb" }) } } as any;

    saveEnrollmentDocument(store, emptyEnrollmentDocument());
    assert.equal(
      certificateIsRevoked(store, req, "enrollment"), false,
      "a store this repository just wrote was read as an unusable denylist, which revokes everyone",
    );

    // And the shape a deployment written before app tokens has on disk.
    writeFileSync(store, JSON.stringify({ schemaVersion: 1, tokens: [], requests: [], audit: [], revocations: [] }));
    assert.equal(certificateIsRevoked(store, req, "enrollment"), false);
    // Missing is still missing: a truncated denylist must never read as "nobody is revoked".
    writeFileSync(store, JSON.stringify({ schemaVersion: 1, tokens: [], requests: [], appTokens: [] }));
    assert.equal(certificateIsRevoked(store, req, "enrollment"), true);
  });
});
