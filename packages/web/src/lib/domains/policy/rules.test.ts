import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  addRule,
  applyDraft,
  deleteRule,
  draftFromRule,
  moveRule,
  readPolicyDoc,
  RULE_COLUMNS,
  rulesWithoutNotes,
  setDenyMode,
  writePolicyDoc,
  type PolicyDoc,
  type Rule,
} from "./rules.ts";

const NOTE = "why this rule exists";

const sample = (): PolicyDoc => ({
  schemaVersion: 1,
  extra: "keep-me",
  groups: {
    gwPolicies: [{
      id: "A",
      name: "a",
      enabled: true,
      priority: 100,
      proto: "tcp",
      ports: "22",
      action: "deny",
      denyMode: "drop",
      notes: NOTE,
      leftover: true,
      src: { kind: "cidr", value: "10.0.0.0/8" },
      dst: { kind: "any", value: "" },
    } as Rule],
    k3sPolicies: [],
  },
});

describe("readPolicyDoc", () => {
  it("keeps keys the table does not have a column for", () => {
    const read = readPolicyDoc(JSON.stringify(sample()));
    assert.equal(read.ok, true);
    if (!read.ok) return;
    assert.equal(read.doc.extra, "keep-me");
    assert.equal((read.doc.groups.gwPolicies[0] as { leftover?: boolean }).leftover, true);
  });

  it("refuses a file the table cannot edit, rather than offering a textarea as the editor", () => {
    const text = readPolicyDoc("export const site = {}");
    assert.equal(text.ok, false);
    const empty = readPolicyDoc("{}");
    assert.equal(empty.ok, false);
  });
});

describe("the table writes every field the document uses", () => {
  it("draws as many columns as a row has cells", () => {
    // A row one cell short shifts every heading onto the wrong data.
    // Last column is 수정/삭제 and has no heading, like the 시안.
    assert.deepEqual([...RULE_COLUMNS], [
      "c.rule", "c.action", "c.protoPorts", "c.pri", "c.group", "",
    ]);
  });

  it("saves an edited note and the fields the first table dropped", () => {
    const doc = sample();
    doc.groups.gwPolicies[0]!.notes = "a better reason";
    setDenyMode(doc.groups.gwPolicies[0]!, "reject");
    const out = JSON.parse(writePolicyDoc(doc)) as PolicyDoc;
    assert.equal(out.groups.gwPolicies[0]!.notes, "a better reason");
    assert.equal(out.groups.gwPolicies[0]!.denyMode, "reject");
    assert.equal(out.extra, "keep-me");
    assert.equal((out.groups.gwPolicies[0] as { leftover?: boolean }).leftover, true);
  });

  it("can take the deny mode away entirely", () => {
    const doc = sample();
    setDenyMode(doc.groups.gwPolicies[0]!, "");
    const out = JSON.parse(writePolicyDoc(doc)) as PolicyDoc;
    assert.equal("denyMode" in out.groups.gwPolicies[0]!, false);
  });

  it("moves a rule to another group without losing why it exists", () => {
    const doc = sample();
    const rule = doc.groups.gwPolicies[0]!;
    assert.equal(moveRule(doc, "gwPolicies", "k3sPolicies", rule), true);
    assert.equal(doc.groups.gwPolicies.length, 0);
    assert.equal(doc.groups.k3sPolicies[0], rule);
    assert.equal(doc.groups.k3sPolicies[0]!.notes, NOTE);
  });

  it("gives a new rule the notes field, so it can be given a reason before it is saved", () => {
    const doc = sample();
    const added = addRule(doc, "k3sPolicies");
    assert.ok(added);
    assert.equal("notes" in added, true);
    assert.equal(added.notes, "");
  });

  it("names the rules that reached the branch with no reason", () => {
    const doc = sample();
    doc.groups.gwPolicies[0]!.notes = "";
    assert.deepEqual(rulesWithoutNotes(doc), ["A"]);
    doc.groups.gwPolicies[0]!.notes = NOTE;
    assert.deepEqual(rulesWithoutNotes(doc), []);
  });

  it("serializes the way the classic save posted — pretty JSON and a trailing newline", () => {
    const doc = sample();
    const text = writePolicyDoc(doc);
    assert.equal(text.endsWith("\n"), true);
    assert.equal(text, `${JSON.stringify(doc, null, 2)}\n`);
  });

  it("deletes the same object the row is bound to", () => {
    const doc = sample();
    const rule = doc.groups.gwPolicies[0]!;
    assert.equal(deleteRule(doc, "gwPolicies", rule), true);
    assert.equal(doc.groups.gwPolicies.length, 0);
  });

  it("applies a modal draft without dropping leftover keys", () => {
    const doc = sample();
    const rule = doc.groups.gwPolicies[0]!;
    const draft = draftFromRule("gwPolicies", rule);
    draft.notes = "a better reason";
    draft.denyMode = "";
    draft.group = "k3sPolicies";
    applyDraft(doc, "gwPolicies", rule, draft);
    assert.equal(doc.groups.gwPolicies.length, 0);
    assert.equal(doc.groups.k3sPolicies[0], rule);
    assert.equal(rule.notes, "a better reason");
    assert.equal("denyMode" in rule, false);
    assert.equal((rule as { leftover?: boolean }).leftover, true);
  });
});
