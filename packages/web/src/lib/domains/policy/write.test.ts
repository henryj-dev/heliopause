import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import {
  CSRF_HEADER,
  editBody,
  proposeBlock,
  proposePolicyBody,
  proposeRefusal,
  readEditReply,
  readProposeReply,
  writeFailMessage,
  writeHeaders,
} from "./write.ts";

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

describe("bodies", () => {
  it("lets the server name the first branch and reuses one after that", () => {
    assert.equal(editBody("policies.json", "{}\n", ""), JSON.stringify({ path: "policies.json", content: "{}\n" }));
    assert.equal(
      editBody("policies.json", "{}\n", "ops-alice/edit"),
      JSON.stringify({ path: "policies.json", content: "{}\n", branch: "ops-alice/edit" }),
    );
  });

  it("proposes the branch, not a fleet target", () => {
    assert.equal(proposePolicyBody("ops-alice/edit"), JSON.stringify({ branch: "ops-alice/edit" }));
    assert.equal(
      proposePolicyBody("ops-alice/edit", "ssh: allow 2222"),
      JSON.stringify({ branch: "ops-alice/edit", title: "ssh: allow 2222" }),
    );
  });
});

describe("replies", () => {
  it("reads a commit the same way the classic editor did", () => {
    const ok = readEditReply({ ok: true, branch: "ops-alice/edit", commit: "abcdef01deadbeef" });
    assert.deepEqual(ok, { ok: true, branch: "ops-alice/edit", commit: "abcdef01deadbeef" });
    const fail = readEditReply({ error: "refusing to commit an empty file" });
    assert.deepEqual(fail, { ok: false, reason: "refusing to commit an empty file" });
  });

  it("names a catalogue key when the manager omitted the commit", () => {
    assert.deepEqual(readEditReply(null), { ok: false, key: "write.noCommit" });
    assert.deepEqual(readEditReply({}), { ok: false, key: "write.noBranch" });
    assert.deepEqual(readEditReply({ branch: "b" }), { ok: false, key: "write.noCommitId" });
  });

  it("reads a pull request number and URL", () => {
    const ok = readProposeReply({ ok: true, number: 12, url: "https://github.com/org/repo/pull/12" });
    assert.deepEqual(ok, { ok: true, number: 12, url: "https://github.com/org/repo/pull/12" });
  });

  it("names a catalogue key when the manager omitted the pull request", () => {
    assert.deepEqual(readProposeReply(null), { ok: false, key: "write.noPr" });
    assert.deepEqual(readProposeReply({}), { ok: false, key: "write.noPrNumber" });
    assert.deepEqual(readProposeReply({ number: 1 }), { ok: false, key: "write.noPrUrl" });
  });

  it("speaks a key through the catalogue and a server error as written", () => {
    assert.equal(writeFailMessage({ ok: false, key: "write.noBranch" }, (key) => key), "write.noBranch");
    assert.equal(writeFailMessage({ ok: false, reason: "refusing to commit an empty file" }, () => "x"), "refusing to commit an empty file");
  });
});

describe("the write chrome", () => {
  it("names the branch in the catalogue and keeps it when only files are on the page", () => {
    const src = readFileSync(new URL("./PolicyWrite.svelte", import.meta.url), "utf8");
    assert.match(src, /t\(prefs\.lang, "m\.branch"\)/);
    assert.doesNotMatch(src, /placeholder="branch"/);
    assert.match(src, /showRules \|\| \(showFiles && edit\.more\.length > 0\)/);
  });

  it("takes csrf from the chrome who, and does not fetch /authz itself", () => {
    const src = readFileSync(new URL("./PolicyWrite.svelte", import.meta.url), "utf8");
    assert.match(src, /whoQuery\(\)/);
    assert.doesNotMatch(src, /fetch\("\/api\/authz"/);
  });

  it("names the editor fields in the catalogue", () => {
    const src = readFileSync(new URL("./RuleEditModal.svelte", import.meta.url), "utf8");
    assert.doesNotMatch(src, /<label>group/);
    assert.doesNotMatch(src, /<label>source/);
    assert.match(src, /t\(prefs\.lang, "c\.group"\)/);
    assert.match(src, /t\(prefs\.lang, "c\.deny"\)/);
  });

  it("binds proto and endpoint-kind slugs, and draws their labels from the catalogue", () => {
    const modal = readFileSync(new URL("./RuleEditModal.svelte", import.meta.url), "utf8");
    assert.match(modal, /value=\{kind\}/);
    assert.match(modal, /endpointKind\(prefs\.lang, kind\)/);
    assert.match(modal, /value=\{proto\}/);
    assert.match(modal, /protoWord\(prefs\.lang, proto\)/);
    const lookup = readFileSync(new URL("../lookup/LookupScreen.svelte", import.meta.url), "utf8");
    assert.match(lookup, /value="tcp"/);
    assert.match(lookup, /value="udp"/);
    assert.match(lookup, /value="icmp"/);
    assert.match(lookup, /value="any"/);
    assert.match(lookup, /protoWord\(prefs\.lang, "tcp"\)/);
    assert.doesNotMatch(lookup, /<option value="tcp">tcp<\/option>/);
    const policy = readFileSync(new URL("./PolicyScreen.svelte", import.meta.url), "utf8");
    assert.doesNotMatch(policy, /<th>v4<\/th>/);
    assert.doesNotMatch(policy, /<th>v6<\/th>/);
    assert.match(policy, /t\(prefs\.lang, "c\.v4"\)/);
    assert.match(policy, /t\(prefs\.lang, "c\.v6"\)/);
  });
});

describe("proposeBlock", () => {
  it("refuses before a POST that the server would also refuse", () => {
    assert.deepEqual(proposeBlock("", []), { ok: false, kind: "need-branch" });
    assert.deepEqual(proposeBlock("b", ["policies.json"]), {
      ok: false,
      kind: "dirty",
      paths: ["policies.json"],
    });
    assert.deepEqual(proposeBlock("b", ["policies.json", "dev.ts"]), {
      ok: false,
      kind: "dirty",
      paths: ["policies.json", "dev.ts"],
    });
    assert.deepEqual(proposeBlock("b", []), { ok: true });
  });

  it("names the catalogue keys the page speaks, not English sentences", () => {
    assert.deepEqual(proposeRefusal({ ok: false, kind: "need-branch" }), { key: "rule.saveFirst" });
    assert.deepEqual(proposeRefusal({ ok: false, kind: "dirty", paths: ["policies.json"] }), {
      key: "rule.saveBeforePropose",
    });
    assert.deepEqual(proposeRefusal({ ok: false, kind: "dirty", paths: ["policies.json", "dev.ts"] }), {
      key: "rule.saveBeforeProposeIn",
      paths: "policies.json, dev.ts",
    });
  });
});
