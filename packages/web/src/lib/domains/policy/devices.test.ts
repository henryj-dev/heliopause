// What this suite protects: a save from the table must not lose what the table does not show, and a
// document the table would mangle must fall back to the textarea instead of being painted wrong.
//
// `rules.ts` learned the first half the hard way — its first table dropped `notes` and `denyMode`, so
// a rule created there was born without a reason. The same shape of mistake is available here and
// costs more: a device row decides which addresses a rule admits, so a dropped field does not fail
// loudly, it narrows a rule and looks correct.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  addDevice,
  applyDeviceDraft,
  DEVICE_COLUMNS,
  deleteDevice,
  devicesWithoutNotes,
  draftFromDevice,
  newDevice,
  readDeviceDoc,
  writeDeviceDoc,
  type DeviceDoc,
} from "./devices.ts";

const ROW = {
  deviceId: "e73e4b57-4ee0-11f1-90c8-1ec42bb3084a",
  deviceName: "a phone",
  userEmail: "someone@example.invalid",
  v4: "10.0.0.1",
  v6: "2001:db8::1c",
};

const doc = (extra: Record<string, unknown> = {}, row: Record<string, unknown> = {}): string =>
  JSON.stringify({ schemaVersion: 1, devices: [{ ...ROW, ...row }], ...extra });

describe("the device registry the table edits", () => {
  it("paints the columns the classic console already named", () => {
    // Reusing `c.device`/`c.user`/`c.v4`/`c.v6` rather than minting `c.deviceName` and friends: two
    // names for one column let the two screens disagree about the word.
    assert.deepEqual([...DEVICE_COLUMNS], ["c.device", "c.user", "c.v4", "c.v6", ""]);
  });

  it("reads a well-formed registry", () => {
    const read = readDeviceDoc(doc());
    assert.ok(read.ok);
    assert.equal(read.doc.devices.length, 1);
    assert.equal(read.doc.devices[0]!.v4, "10.0.0.1");
  });

  it("keeps keys the table does not show, so a save cannot drop them", () => {
    // The whole reason `readPolicyDoc` returns the parsed object rather than a rebuilt one.
    const read = readDeviceDoc(doc({ generatedBy: "someone" }, { retiredAt: "2026-01-01T00:00:00Z" }));
    assert.ok(read.ok);
    const back = JSON.parse(writeDeviceDoc(read.doc));
    assert.equal(back.generatedBy, "someone", "a document-level key vanished");
    assert.equal(back.devices[0].retiredAt, "2026-01-01T00:00:00Z", "a row-level key vanished");
  });

  it("round-trips byte-for-byte when nothing is edited", () => {
    const source = `${JSON.stringify({ schemaVersion: 1, devices: [ROW] }, null, 2)}\n`;
    const read = readDeviceDoc(source);
    assert.ok(read.ok);
    assert.equal(writeDeviceDoc(read.doc), source, "an untouched file must produce no diff");
  });

  it("falls back rather than painting a document it cannot show", () => {
    for (const [content, needle] of [
      ["{", /not JSON/],
      ["[]", /not an object/],
      ['{"schemaVersion":1}', /no devices list/],
      ['{"schemaVersion":1,"devices":[null]}', /devices\[0\] is not an object/],
      ['{"schemaVersion":1,"devices":[{"deviceName":"x"}]}', /no deviceId the table can edit/],
      [doc({}, { v4: 10 }), /no v4 the table can edit/],
    ] as const) {
      const read = readDeviceDoc(content);
      assert.equal(read.ok, false, `expected a refusal for ${content.slice(0, 40)}`);
      if (!read.ok) assert.match(read.reason, needle);
    }
  });

  it("does not validate — that authority stays in the policy repository", () => {
    // A bad address parses here on purpose. `policy/devices.ts` refuses it at render time, where a bad
    // row stops the render instead of shipping a rule; a second, weaker copy of those rules in front
    // of the user would be free to drift from the one that decides.
    const read = readDeviceDoc(doc({}, { v4: "10.0.0.999" }));
    assert.ok(read.ok, "the table shows it; the renderer is what refuses it");
  });

  it("adds a blank row rather than a plausible one", () => {
    // A generated UUID looks like a real device to a reviewer. An empty string cannot.
    const row = newDevice();
    assert.equal(row.deviceId, "");
    assert.equal(row.v4, "");
    const read = readDeviceDoc(doc());
    assert.ok(read.ok);
    const added = addDevice(read.doc);
    assert.equal(read.doc.devices.length, 2);
    assert.equal(added.deviceName, "");
  });

  it("applies a draft, trimming each field", () => {
    const read = readDeviceDoc(doc());
    assert.ok(read.ok);
    const row = read.doc.devices[0]!;
    const draft = draftFromDevice(row);
    draft.deviceName = "  renamed  ";
    draft.v4 = " 10.0.0.9 ";
    applyDeviceDraft(row, draft);
    assert.equal(row.deviceName, "renamed");
    assert.equal(row.v4, "10.0.0.9");
  });

  it("removes an emptied note instead of storing a blank one", () => {
    // `policy/devices.ts` refuses `notes: "   "` — a present-but-empty field reads as "a reason was
    // given" to anything checking for the key. Clearing the box must produce a document it accepts.
    const read = readDeviceDoc(doc({}, { notes: "approved because" }));
    assert.ok(read.ok);
    const row = read.doc.devices[0]!;
    const draft = draftFromDevice(row);
    assert.equal(draft.notes, "approved because");
    draft.notes = "   ";
    applyDeviceDraft(row, draft);
    assert.equal("notes" in row, false, "an emptied note must be deleted, not blanked");
  });

  it("deletes by identity, and reports when the row is not there", () => {
    const read = readDeviceDoc(doc());
    assert.ok(read.ok);
    const row = read.doc.devices[0]!;
    assert.equal(deleteDevice(read.doc, { ...row }), false, "a copy is not the row");
    assert.equal(read.doc.devices.length, 1);
    assert.equal(deleteDevice(read.doc, row), true);
    assert.equal(read.doc.devices.length, 0);
  });

  it("lists which approvals carry no stated reason", () => {
    const parsed = readDeviceDoc(
      JSON.stringify({
        schemaVersion: 1,
        devices: [ROW, { ...ROW, deviceName: "explained", notes: "because" }, { ...ROW, deviceName: "" }],
      }),
    );
    assert.ok(parsed.ok);
    const without = devicesWithoutNotes(parsed.doc as DeviceDoc);
    assert.deepEqual(without, ["a phone", ROW.deviceId], "an unnamed row falls back to its id");
  });
});
