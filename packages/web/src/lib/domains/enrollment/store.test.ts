import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  activeTokenCount,
  canDecideCsr,
  canIssueToken,
  canRevokeCert,
  canRevokeToken,
  readEnrollmentView,
  type RequestRow,
  type TokenRow,
} from "./store.ts";

const token: TokenRow = {
  id: "tok-1",
  hostname: "host-01.example",
  label: "lab",
  createdAt: "2026-08-18T00:00:00.000Z",
  expiresAt: "2026-08-18T00:10:00.000Z",
  lastUsedAt: null,
  revokedAt: null,
};

const pending: RequestRow = {
  id: "req-1",
  hostname: "host-01.example",
  status: "pending",
  csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
  csrSha256: "aa".repeat(32),
  publicKeySha256: "bb".repeat(32),
  nodeTokenId: "tok-1",
  sourceIp: "10.0.0.8",
  createdAt: "2026-08-18T00:00:00.000Z",
  decisionReason: null,
  certificatePem: null,
  retrievedAt: null,
};

describe("readEnrollmentView", () => {
  it("accepts the four listings the manager would send", () => {
    const read = readEnrollmentView({
      tokens: [token],
      requests: [pending],
      revocations: [{
        fingerprint256: "cc".repeat(32),
        subject: "CN=host-01.example",
        reason: "retired",
        revokedAt: "2026-08-18T01:00:00.000Z",
      }],
      events: [{
        at: "2026-08-18T00:00:00.000Z",
        actor: "ops-alice",
        action: "token.create",
        target: "tok-1",
        sourceIp: null,
        detail: { hostname: "host-01.example" },
      }],
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.equal(read.view.tokens[0]?.id, "tok-1");
      assert.equal(read.view.events?.[0]?.action, "token.create");
    }
  });

  it("refuses a token listing that still carries the hash", () => {
    const read = readEnrollmentView({
      tokens: [{ ...token, tokenHash: "secret" }],
      requests: [],
      revocations: [],
      events: [],
    });
    assert.equal(read.ok, false);
  });

  it("keeps a missing audit trail as null rather than empty", () => {
    const read = readEnrollmentView({ tokens: [], requests: [], revocations: [], events: null });
    assert.equal(read.ok, true);
    if (read.ok) assert.equal(read.view.events, null);
  });
});

describe("enrollment actions", () => {
  it("offers writes only to a writer, and only on the states that accept them", () => {
    assert.equal(canIssueToken(true), true);
    assert.equal(canIssueToken(false), false);
    assert.equal(canIssueToken(true, true), false);
    assert.equal(canRevokeToken(token, true), true);
    assert.equal(canRevokeToken({ ...token, revokedAt: "2026-08-18T02:00:00.000Z" }, true), false);
    assert.equal(canDecideCsr(pending, true), true);
    assert.equal(canDecideCsr({ ...pending, status: "signed" }, true), false);
    assert.equal(canRevokeCert({ ...pending, status: "signed", certificatePem: "pem" }, true), true);
    assert.equal(canRevokeCert({ ...pending, status: "signed", certificatePem: null }, true), false);
    assert.equal(activeTokenCount([token, { ...token, id: "tok-2", revokedAt: "x" }]), 1);
  });
});
