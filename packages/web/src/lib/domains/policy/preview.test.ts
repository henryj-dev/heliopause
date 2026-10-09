import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { previewUrl, readPreviewReply, ruleLine } from "./preview.ts";

const rule = { verdict: "accept", proto: "tcp", ports: "443", sources: ["10.1.0.0/16"], destinations: ["10.2.0.7/32"], family: "ip" };

describe("render-diff preview in the console", () => {
  it("names the site it asks about", () => {
    assert.equal(previewUrl("alpha"), "/api/policy/preview?site=alpha");
    assert.equal(previewUrl("a&b"), "/api/policy/preview?site=a%26b");
    assert.equal(previewUrl(""), "/api/policy/preview");
  });

  it("reads added and removed rules and a default-policy change", () => {
    const got = readPreviewReply({
      site: "alpha",
      changes: [{ host: "h1.alpha", inputPolicy: { before: null, after: "drop" }, added: [rule], removed: [] }],
    });
    assert.deepEqual(got, {
      ok: true,
      changes: [{ host: "h1.alpha", inputPolicy: { before: null, after: "drop" }, added: [rule], removed: [] }],
    });
  });

  it("reports an empty changes list as no change rather than an error", () => {
    assert.deepEqual(readPreviewReply({ changes: [] }), { ok: true, changes: [] });
  });

  it("passes the server's refusal through, and refuses a malformed answer", () => {
    assert.deepEqual(readPreviewReply({ error: "only JSON data can be previewed" }), {
      ok: false, reason: "only JSON data can be previewed",
    });
    assert.equal(readPreviewReply(null).ok, false);
    assert.equal(readPreviewReply({ changes: "nope" }).ok, false);
  });

  it("writes a rule as one line, with any for an empty side", () => {
    assert.equal(ruleLine(rule), "accept tcp 443 from 10.1.0.0/16 to 10.2.0.7/32");
    assert.equal(ruleLine({ ...rule, proto: "", ports: "", sources: [], destinations: [] }), "accept any from any to any");
  });
});
