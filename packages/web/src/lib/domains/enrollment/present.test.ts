import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import {
  auditActionLabel,
  AUDIT_ACTION_KEY,
  auditDetailLine,
  CSR_FILTERS,
  enrollmentFocus,
  enrollmentPath,
  enrollmentPipeline,
  filteredRequests,
  isTokenActive,
  readCsrFilter,
  REQUEST_STATUS_KEY,
  requestCardClass,
  shortDigest,
  tokenState,
} from "./present.ts";
import type { EnrollmentView, RequestRow, TokenRow } from "./store.ts";

const now = Date.parse("2026-08-18T00:05:00.000Z");

const token = (over: Partial<TokenRow> = {}): TokenRow => ({
  id: "tok-1",
  hostname: "gw-01.dev",
  label: null,
  createdAt: "2026-08-18T00:00:00.000Z",
  expiresAt: "2026-08-18T00:10:00.000Z",
  lastUsedAt: null,
  revokedAt: null,
  ...over,
});

const request = (over: Partial<RequestRow> = {}): RequestRow => ({
  id: "req-1",
  hostname: "gw-01.dev",
  status: "pending",
  csrPem: "pem",
  csrSha256: "aa".repeat(32),
  publicKeySha256: "bb".repeat(32),
  nodeTokenId: "tok-1",
  sourceIp: null,
  createdAt: "2026-08-18T00:00:00.000Z",
  decisionReason: null,
  certificatePem: null,
  retrievedAt: null,
  ...over,
});

const empty: EnrollmentView = { tokens: [], requests: [], revocations: [], events: [] };

describe("isTokenActive", () => {
  it("treats revoked and expired as not active, and unused as still active", () => {
    assert.equal(isTokenActive(token(), now), true);
    assert.equal(isTokenActive(token({ revokedAt: "2026-08-18T00:01:00.000Z" }), now), false);
    assert.equal(isTokenActive(token({ expiresAt: "2026-08-18T00:01:00.000Z" }), now), false);
  });
});

describe("enrollmentPipeline", () => {
  it("counts unused tokens separately from revoked ones", () => {
    const pipe = enrollmentPipeline({
      ...empty,
      tokens: [
        token(),
        token({ id: "tok-2", lastUsedAt: "2026-08-18T00:02:00.000Z" }),
        token({ id: "tok-3", revokedAt: "2026-08-18T00:03:00.000Z" }),
      ],
    }, now);
    assert.equal(pipe.tokens, 2);
    assert.equal(pipe.unused, 1);
  });

  it("keeps conflict out of pending, and signed-not-retrieved out of signed-done", () => {
    const pipe = enrollmentPipeline({
      ...empty,
      requests: [
        request(),
        request({ id: "req-2", status: "conflict" }),
        request({ id: "req-3", status: "signed", retrievedAt: null }),
        request({ id: "req-4", status: "signed", retrievedAt: "2026-08-18T00:04:00.000Z" }),
      ],
    }, now);
    assert.equal(pipe.pending, 1);
    assert.equal(pipe.conflict, 1);
    assert.equal(pipe.signedWait, 1);
  });
});

describe("tokenState", () => {
  it("keeps unused separate from used, and expired separate from revoked", () => {
    assert.equal(tokenState(token(), now), "unused");
    assert.equal(tokenState(token({ lastUsedAt: "2026-08-18T00:02:00.000Z" }), now), "used");
    assert.equal(tokenState(token({ expiresAt: "2026-08-18T00:01:00.000Z" }), now), "expired");
    assert.equal(tokenState(token({ revokedAt: "2026-08-18T00:01:00.000Z", expiresAt: "2026-08-18T00:01:00.000Z" }), now), "revoked");
  });
});

describe("requestCardClass", () => {
  it("marks conflict apart from pending, and signed-not-retrieved apart from retrieved", () => {
    assert.equal(requestCardClass(request()), "awaiting");
    assert.equal(requestCardClass(request({ status: "conflict" })), "conflict");
    assert.equal(requestCardClass(request({ status: "signed", retrievedAt: null })), "approved");
    assert.equal(requestCardClass(request({ status: "signed", retrievedAt: "2026-08-18T00:04:00.000Z" })), "");
  });
});

describe("shortDigest", () => {
  it("keeps the 시안 head and tail", () => {
    assert.equal(shortDigest("3fa9c7d1abcd"), "3fa9c7d1abcd");
    assert.equal(shortDigest("3fa9" + "0".repeat(56) + "c7d1"), "3fa9…c7d1");
  });
});

describe("enrollmentFocus", () => {
  it("puts the operator on pending before signed-wait, and unused tokens last", () => {
    const base = { tokens: 1, unused: 1, pending: 0, conflict: 1, signedWait: 0, revocations: 0 };
    assert.equal(enrollmentFocus({ ...base, pending: 1, signedWait: 1 }), "pending");
    assert.equal(enrollmentFocus({ ...base, signedWait: 1 }), "signed");
    assert.equal(enrollmentFocus(base), "tokens");
    assert.equal(enrollmentFocus({ ...base, unused: 0, tokens: 0 }), null);
  });

  it("does not treat conflict as a step on the line", () => {
    assert.equal(enrollmentFocus({
      tokens: 0, unused: 0, pending: 0, conflict: 2, signedWait: 0, revocations: 4,
    }), null);
  });
});

describe("REQUEST_STATUS_KEY", () => {
  it("names every CSR status the listing can show", () => {
    for (const status of CSR_FILTERS) {
      assert.equal(typeof REQUEST_STATUS_KEY[status], "string", status);
    }
  });
});

describe("auditActionLabel", () => {
  it("names the store's actions in the language asked for, and leaves an unknown code", () => {
    assert.equal(auditActionLabel("node-token.create", "ko"), "노드 토큰을 발급했다");
    assert.equal(auditActionLabel("certificate.revoke", "en"), "revoked a certificate");
    assert.equal(auditActionLabel("unknown.event", "ko"), "unknown.event");
    assert.equal(Object.keys(AUDIT_ACTION_KEY).length, 7);
  });
});

describe("auditDetailLine", () => {
  it("names known keys and status values, and leaves an unknown key", () => {
    const line = auditDetailLine({ hostname: "gw-01.dev", status: "pending", extra: "x" }, "ko");
    assert.match(line, /호스트명=gw-01\.dev/);
    assert.match(line, /상태=대기/);
    assert.match(line, /extra=x/);
  });
});

describe("the enrollment screen", () => {
  it("does not announce a completed write in English", () => {
    const src = readFileSync(new URL("./EnrollmentScreen.svelte", import.meta.url), "utf8");
    assert.doesNotMatch(src, /"(token-revoke|csr-reject|cert-upload|cert-revoke) complete"/);
    assert.doesNotMatch(src, /request · pub/);
    assert.match(src, /REQUEST_STATUS_KEY\[request\.status\]/);
    assert.match(src, /m\.requestMeta/);
    const pane = readFileSync(new URL("./CsrPane.svelte", import.meta.url), "utf8");
    assert.doesNotMatch(pane, /csr sha256/);
    assert.match(pane, /m\.csrSha/);
  });
});

describe("readCsrFilter", () => {
  it("accepts the four statuses the API already filters on, and nothing else", () => {
    assert.equal(readCsrFilter("pending"), "pending");
    assert.equal(readCsrFilter("conflict"), "conflict");
    assert.equal(readCsrFilter("signed"), "signed");
    assert.equal(readCsrFilter("rejected"), "rejected");
    assert.equal(readCsrFilter(""), null);
    assert.equal(readCsrFilter("tokens"), null);
  });
});

describe("filteredRequests", () => {
  it("does not drop the other statuses from the listing the pipeline still counts", () => {
    const rows = [
      request(),
      request({ id: "req-2", status: "conflict" }),
      request({ id: "req-3", status: "signed" }),
    ];
    assert.equal(filteredRequests(rows, null).length, 3);
    assert.deepEqual(filteredRequests(rows, "pending").map((row) => row.id), ["req-1"]);
    assert.deepEqual(filteredRequests(rows, "rejected"), []);
  });
});

describe("enrollmentPath", () => {
  it("puts the status in the path, not in a query, like /policy/files", () => {
    assert.equal(enrollmentPath(null), "/enrollment");
    assert.equal(enrollmentPath("pending"), "/enrollment/pending");
    assert.doesNotMatch(enrollmentPath("pending"), /[?&]status=/);
  });
});
