import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { latestOnly } from "./latest.ts";
import { previewUrl, previewView, readPreviewReply, ruleLine } from "./preview.ts";

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

  it("refuses the whole answer when any host or rule is malformed, rather than showing less", () => {
    const host = { host: "h1.alpha", added: [rule], removed: [] };
    // Each of these once read as success: the host or rule was dropped, or a side printed as "any".
    const bad = [
      { hostname: "h1", added: [{ verdict: "accept" }], removed: [] },
      { ...host, added: [{ action: "accept" }] },
      { ...host, added: [{ verdict: "accept" }] },
      { ...host, added: [{ ...rule, sources: [123] }] },
      { ...host, added: [{ ...rule, destinations: "10.2.0.7/32" }] },
      { ...host, removed: undefined },
      { ...host, inputPolicy: { before: 1, after: "drop" } },
      { ...host, inputPolicy: null },
    ];
    for (const b of bad) {
      const got = readPreviewReply({ changes: [host, b] });
      assert.equal(got.ok, false, JSON.stringify(b));
    }
  });

  it("shows a result only while the site and the rule file are the ones it was asked about", () => {
    const result = { site: "alpha", content: "draft A", changes: [] };
    assert.deepEqual(previewView(null, { site: "alpha", content: "draft A" }), { kind: "none" });
    assert.deepEqual(previewView(result, { site: "alpha", content: "draft A" }), { kind: "shown", changes: [] });
    // Edited after (or while) the request ran: the "no change" answer is about draft A, not B.
    assert.deepEqual(previewView(result, { site: "alpha", content: "draft B" }), { kind: "stale" });
    assert.deepEqual(previewView(result, { site: "beta", content: "draft A" }), { kind: "stale" });
  });

  it("lets only the newest of overlapping requests write", () => {
    const order = latestOnly();
    const first = order.begin();
    const second = order.begin();
    // The first answer arrives last; it must not be the one on screen.
    assert.equal(second(), true);
    assert.equal(first(), false);
  });

  it("writes a rule as one line, with any for an empty side", () => {
    assert.equal(ruleLine(rule), "accept tcp 443 from 10.1.0.0/16 to 10.2.0.7/32");
    assert.equal(ruleLine({ ...rule, proto: "", ports: "", sources: [], destinations: [] }), "accept any from any to any");
  });
});
