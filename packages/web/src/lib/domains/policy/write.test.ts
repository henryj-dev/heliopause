import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import {
  CSRF_HEADER,
  editBody,
  proposeBlock,
  proposePolicyBody,
  proposeRefusal,
  mergeBody,
  readEditReply,
  readMergeReply,
  readPrReply,
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

describe("the merge half", () => {
  it("sends the number and nothing that could be mistaken for a decision", () => {
    assert.deepEqual(JSON.parse(mergeBody(7)), { number: 7 });
  });

  // `mayMerge` is the manager's answer, not a conclusion drawn here. A browser that recomputed it
  // would be a second copy of `mergeRefusal`, and the copy is the one that goes stale.
  it("takes the verdict and the sentence from the manager", () => {
    const reply = readPrReply({
      number: 7, url: "u", state: "open", merged: false, headSha: "a".repeat(40),
      proposedBy: "ops-alice", checks: [{ name: "build", state: "success", detail: "success" }],
      mayMerge: false, why: "#7 was proposed by ops-alice",
    });
    assert.ok(reply.ok);
    assert.equal(reply.status.mayMerge, false);
    assert.equal(reply.status.why, "#7 was proposed by ops-alice");
    assert.equal(reply.status.proposedBy, "ops-alice");
  });

  // A reply with no `mayMerge` is not "may merge". The field's absence would otherwise read as
  // falsy in one place and be rendered as an enabled button in another.
  it("refuses a status that never said whether it may merge", () => {
    const reply = readPrReply({ number: 7, url: "u", checks: [] });
    assert.equal(reply.ok, false);
    assert.equal("key" in reply && reply.key, "write.noPrStatus");
  });

  // A check state this console does not know about is shown as pending. Falling back to success
  // would turn an unrecognised word into a green tick.
  it("never reads an unknown check state as a pass", () => {
    const reply = readPrReply({
      number: 7, mayMerge: true,
      checks: [{ name: "odd", state: "whatever", detail: "" }, { name: "none", detail: "" }],
    });
    assert.ok(reply.ok);
    assert.deepEqual(reply.status.checks.map((c) => c.state), ["pending", "pending"]);
  });

  it("reads a merge that happened, and refuses one that only claims to have", () => {
    const ok = readMergeReply({ ok: true, number: 7, sha: "c".repeat(40) });
    assert.ok(ok.ok);
    assert.equal(ok.sha, "c".repeat(40));
    assert.equal(readMergeReply({ ok: true, number: 7 }).ok, false);
    assert.equal(readMergeReply({ ok: true, number: 7, sha: "" }).ok, false);
  });

  it("passes the manager's refusal through rather than inventing one", () => {
    const reply = readMergeReply({ error: "checks failed on aaaaaaaa: leak scan (failure)" });
    assert.equal(reply.ok, false);
    assert.match(String("reason" in reply && reply.reason), /leak scan/);
  });
});

describe("a merge that is one person on both ends", () => {
  // The code is omitted rather than sent empty. An empty string is a code the manager must reject,
  // and a rejected code looks exactly like a wrong one on the screen.
  it("carries the one-time code only when there is one", () => {
    assert.deepEqual(JSON.parse(mergeBody(7)), { number: 7 });
    assert.deepEqual(JSON.parse(mergeBody(7, "")), { number: 7 });
    assert.deepEqual(JSON.parse(mergeBody(7, "123456")), { number: 7, otp: "123456" });
  });

  // `solo` is the manager's answer: it depends on which certificate names this deployment knows to
  // be one human, and the browser has no way to ask that.
  it("takes the solo verdict from the manager", () => {
    const reply = readPrReply({ number: 7, mayMerge: true, solo: true, checks: [] });
    assert.ok(reply.ok);
    assert.equal(reply.status.solo, true);
  });

  // Absent reads as "not solo" on purpose: the screen then asks for no code, the route demands one,
  // and the merge is refused until the operator supplies it. The opposite default would collect a
  // code for a merge that never needed one — training an operator to type codes on reflex.
  it("defaults to not solo when the manager did not say", () => {
    const reply = readPrReply({ number: 7, mayMerge: true, checks: [] });
    assert.ok(reply.ok);
    assert.equal(reply.status.solo, false);
  });

  it("reports back whether the merge that happened was solo", () => {
    const solo = readMergeReply({ ok: true, number: 7, sha: "c".repeat(40), solo: true });
    assert.ok(solo.ok);
    assert.equal(solo.solo, true);
    const two = readMergeReply({ ok: true, number: 7, sha: "c".repeat(40) });
    assert.ok(two.ok);
    assert.equal(two.solo, false);
  });
});
