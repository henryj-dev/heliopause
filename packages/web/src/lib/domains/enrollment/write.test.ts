import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { certUploadBody, CSRF_HEADER, tokenCreateBody, writeHeaders } from "./write.ts";

describe("enrollment write bodies", () => {
  it("reuse the same CSRF header as approve/publish", () => {
    assert.equal(CSRF_HEADER, "x-heliopause-csrf");
    assert.equal(writeHeaders("tok")[CSRF_HEADER], "tok");
  });

  it("send the fields the manager already accepts", () => {
    assert.equal(
      tokenCreateBody("host-01.example", "lab", "123456"),
      JSON.stringify({ hostname: "host-01.example", label: "lab", otp: "123456" }),
    );
    assert.equal(
      certUploadBody("PEM", "site", "123456"),
      JSON.stringify({ certificatePem: "PEM", caName: "site", otp: "123456" }),
    );
  });
});
