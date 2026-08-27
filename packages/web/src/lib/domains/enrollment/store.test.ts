import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  activeAppTokenCount,
  activeTokenCount,
  canDecideCsr,
  canIssueAppToken,
  canIssueToken,
  canRevokeAppToken,
  canRevokeCert,
  canRevokeToken,
  readEnrollmentView,
  type AppTokenRow,
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

const appToken: AppTokenRow = {
  id: "app-1",
  label: "ci",
  scopes: ["enrollment:token-create", "enrollment:requests-read"],
  hostnamePattern: "*.dev",
  createdBy: "ops-alice",
  createdAt: "2026-08-18T00:00:00.000Z",
  expiresAt: "2026-09-18T00:00:00.000Z",
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
      appTokens: [appToken],
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
      assert.equal(read.view.appTokens[0]?.id, "app-1");
      assert.equal(read.view.events?.[0]?.action, "token.create");
    }
  });

  it("refuses a token listing that still carries the hash", () => {
    const read = readEnrollmentView({
      tokens: [{ ...token, tokenHash: "secret" }],
      appTokens: [],
      requests: [],
      revocations: [],
      events: [],
    });
    assert.equal(read.ok, false);
  });

  it("refuses an app-token listing that still carries the hash", () => {
    const read = readEnrollmentView({
      tokens: [],
      appTokens: [{ ...appToken, tokenHash: "secret" }],
      requests: [],
      revocations: [],
      events: [],
    });
    assert.equal(read.ok, false);
  });

  it("reports a reason when app tokens is not an array", () => {
    const read = readEnrollmentView({ tokens: [], appTokens: undefined, requests: [], revocations: [], events: null });
    assert.equal(read.ok, false);
    if (!read.ok) assert.equal(read.reason, "app tokens is missing");
  });

  it("keeps a missing audit trail as null rather than empty", () => {
    const read = readEnrollmentView({ tokens: [], appTokens: [], requests: [], revocations: [], events: null });
    assert.equal(read.ok, true);
    if (read.ok) assert.equal(read.view.events, null);
  });
});

describe("readAppToken", () => {
  it("accepts a well-shaped row, and refuses rows shaped wrong", () => {
    const ok = readEnrollmentView({ tokens: [], appTokens: [appToken], requests: [], revocations: [], events: [] });
    assert.equal(ok.ok, true);
    if (ok.ok) {
      assert.equal(ok.view.appTokens[0]?.hostnamePattern, "*.dev");
      assert.deepEqual(ok.view.appTokens[0]?.scopes, ["enrollment:token-create", "enrollment:requests-read"]);
    }

    const scopesNotArray = readEnrollmentView({
      tokens: [], appTokens: [{ ...appToken, scopes: "enrollment:token-create" }], requests: [], revocations: [], events: [],
    });
    assert.equal(scopesNotArray.ok, false);

    const missingPattern = readEnrollmentView({
      tokens: [], appTokens: [{ ...appToken, hostnamePattern: undefined }], requests: [], revocations: [], events: [],
    });
    assert.equal(missingPattern.ok, false);
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

  it("gates app-token writes on write capability and freshness", () => {
    assert.equal(canIssueAppToken(true), true);
    assert.equal(canIssueAppToken(false), false);
    assert.equal(canIssueAppToken(true, true), false);
    assert.equal(canRevokeAppToken(appToken, true), true);
    assert.equal(canRevokeAppToken(appToken, false), false);
    assert.equal(canRevokeAppToken({ ...appToken, revokedAt: "2026-08-18T02:00:00.000Z" }, true), false);
    assert.equal(activeAppTokenCount([appToken, { ...appToken, id: "app-2", revokedAt: "x" }]), 1);
  });
});
