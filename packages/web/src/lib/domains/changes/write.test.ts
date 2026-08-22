import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { approveBody, CSRF_HEADER, proposeBody, writeHeaders } from "./write.ts";

describe("writeHeaders", () => {
  it("omits the CSRF header for a certificate caller", () => {
    assert.deepEqual(writeHeaders(null), { "content-type": "application/json" });
  });

  it("echoes the session token in the header a cross-origin form cannot set", () => {
    const headers = writeHeaders("tok");
    assert.equal(headers[CSRF_HEADER], "tok");
    assert.equal(CSRF_HEADER, "x-heliopause-csrf");
  });
});

describe("write bodies", () => {
  it("send the hash and otp the manager already accepts", () => {
    assert.equal(approveBody("abc", "123456"), JSON.stringify({ hash: "abc", otp: "123456" }));
    assert.equal(proposeBody("dev"), JSON.stringify({ target: "dev" }));
  });
});
