import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CERT_THRESHOLDS, certFactsFromPeer, certFactsFromPem, certState } from "./cert-watch.ts";
import { RENEW_BEFORE_DAYS } from "./pki.ts";

const NOW = new Date("2026-10-06T00:00:00Z");
const inDays = (d: number) => new Date(NOW.getTime() + d * 86_400_000).toISOString();

describe("certState", () => {
  it("names each band by its boundary", () => {
    assert.deepEqual(certState(inDays(100), NOW), { state: "ok", daysLeft: 100 });
    assert.deepEqual(certState(inDays(31), NOW), { state: "ok", daysLeft: 31 });
    assert.deepEqual(certState(inDays(30), NOW), { state: "renew", daysLeft: 30 });
    assert.deepEqual(certState(inDays(25), NOW), { state: "renew", daysLeft: 25 });
    assert.deepEqual(certState(inDays(8), NOW), { state: "renew", daysLeft: 8 });
    assert.deepEqual(certState(inDays(7), NOW), { state: "critical", daysLeft: 7 });
    assert.deepEqual(certState(inDays(5), NOW), { state: "critical", daysLeft: 5 });
  });

  it("rounds down, so 7.9 days left is already critical", () => {
    assert.equal(certState(inDays(7.9), NOW).state, "critical");
  });

  it("calls a certificate past notAfter expired, including the instant itself", () => {
    assert.equal(certState(inDays(0), NOW).state, "expired");
    assert.deepEqual(certState(inDays(-2), NOW), { state: "expired", daysLeft: -2 });
  });

  it("is unknown — not ok — for a date it cannot read", () => {
    for (const bad of [null, undefined, "", "not a date"]) {
      assert.deepEqual(certState(bad, NOW), { state: "unknown", daysLeft: null }, String(bad));
    }
  });

  it("uses the issuing side's renewal window, and reports the thresholds it used", () => {
    assert.equal(CERT_THRESHOLDS.renewBeforeDays, RENEW_BEFORE_DAYS);
    assert.equal(certState(inDays(RENEW_BEFORE_DAYS + 1), NOW).state, "ok");
    assert.equal(certState(inDays(RENEW_BEFORE_DAYS), NOW).state, "renew");
  });
});

describe("certFactsFromPem", () => {
  const dir = mkdtempSync(join(tmpdir(), "hp-certwatch-"));
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("reads CN, serial, fingerprint and validity from a real certificate", () => {
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
      "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"), "-subj", "/CN=host-a", "-days", "5",
    ], { stdio: "pipe" });
    const pem = readFileSync(join(dir, "c.pem"));
    const f = certFactsFromPem(pem);
    assert.equal(f.cn, "host-a");
    assert.match(f.sha256, /^[0-9a-f]{64}$/);
    assert.match(f.serial, /^[0-9A-F]+$/);
    // A five-day certificate issued just now is critical on the clock of the machine that made it.
    assert.equal(certState(f.notAfter, new Date()).state, "critical");
    assert.ok(new Date(f.notBefore) <= new Date());
  });

  it("throws on something that is not a certificate", () => {
    assert.throws(() => certFactsFromPem("not a pem"));
  });
});

describe("certFactsFromPeer", () => {
  const peer = {
    subject: { CN: "web-01" },
    serialNumber: "0A1B",
    fingerprint256: "AB:CD:EF",
    valid_from: "Oct  6 00:00:00 2026 GMT",
    valid_to: "Nov 25 04:16:24 2026 GMT",
  };

  it("normalises what node's TLS layer hands back", () => {
    assert.deepEqual(certFactsFromPeer(peer), {
      cn: "web-01",
      serial: "0A1B",
      sha256: "abcdef",
      notBefore: "2026-10-06T00:00:00.000Z",
      notAfter: "2026-11-25T04:16:24.000Z",
    });
  });

  it("refuses an incomplete presentation rather than recording half of it", () => {
    // `getPeerCertificate()` returns `{}` when the peer sent nothing.
    assert.equal(certFactsFromPeer({}), null);
    assert.equal(certFactsFromPeer(null), null);
    assert.equal(certFactsFromPeer({ ...peer, valid_to: undefined }), null);
    assert.equal(certFactsFromPeer({ ...peer, valid_to: "garbage" }), null);
    assert.equal(certFactsFromPeer({ ...peer, fingerprint256: undefined }), null);
  });
});
