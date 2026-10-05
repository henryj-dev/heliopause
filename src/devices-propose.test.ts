// What `heliopause-devices --propose` prints has to be pasteable into `devices.json`.
//
// ## Why this file exists
//
// The workflow that runs that command tells the operator "the block printed above is what to
// commit". That sentence was **false for weeks**: the rows moved from a TypeScript array into
// `devices.json` and the command's output did not follow, so it printed an `export const DEVICES =
// [ … ]` that no file would accept. Nobody noticed because the two people who needed it both
// transcribed it by hand instead — and the second time, the `notes` fields came within one step of
// being deleted along the way.
//
// So the property under test is not "the output looks like JSON". It is **the real parser accepts
// it, and nothing is lost on the way through** — `parseApprovedDevices` is the only judge of that,
// and it lives in the policy repository, which this repository reaches through a symlink.
import { describe, it } from "node:test";
import assert from "node:assert/strict";

/** The shape Cloudflare returns, and the shape the file holds. `notes` exists only in the file. */
interface Row {
  deviceId: string;
  deviceName: string;
  userEmail: string;
  v4: string;
  v6: string;
  notes?: string;
}

/**
 * The transform `--propose` performs, extracted so a test can exercise it without a Cloudflare
 * token or a network. Kept byte-identical in shape to `bin/heliopause-devices.ts`.
 *
 * Duplication rather than an import: that file is a script with top-level `await` and a
 * `process.exit` path, so importing it here would run the command. The risk this trades for is the
 * two drifting apart — which is why the assertions below are about **properties of the output**
 * (parses, keeps notes, keeps every id) rather than about matching a literal string. A reimplemented
 * transform that still satisfies all three is one this test is content with.
 */
function proposeDoc(fromCloudflare: readonly Omit<Row, "notes">[], approved: readonly Row[]) {
  const notesById = new Map(approved.filter((d) => d.notes).map((d) => [d.deviceId, d.notes!]));
  const rows = fromCloudflare
    .slice()
    .sort((a, b) => a.v4.localeCompare(b.v4, undefined, { numeric: true }))
    .map((r) => {
      const kept = notesById.get(r.deviceId);
      return { ...r, ...(kept ? { notes: kept } : {}) };
    });
  return { schemaVersion: 1, devices: rows };
}

const base = (over: Partial<Row> & { deviceId: string; v4: string }): Row => ({
  deviceName: "a device",
  userEmail: "someone@example.test",
  v6: "2001:db8::1",
  ...over,
});

describe("--propose prints a document that devices.json accepts", () => {
  it("is JSON, and keeps every row", () => {
    const cf = [base({ deviceId: "b", v4: "10.0.0.2" }), base({ deviceId: "a", v4: "10.0.0.1" })];
    const doc = proposeDoc(cf, []);
    const round = JSON.parse(JSON.stringify(doc)) as typeof doc;
    assert.equal(round.schemaVersion, 1);
    assert.deepEqual(round.devices.map((d) => d.deviceId), ["a", "b"], "주소 순서로 정렬돼야 한다");
  });

  it("carries `notes` across from the rows already approved", () => {
    // 🔴 The one that matters. Cloudflare does not return `notes`; it is the argument an approval
    // needed, and `ApprovedDevice` declares the field for exactly that. A block without it looks
    // complete and silently deletes the reasons. Reverting the carry-over fails here.
    const cf = [base({ deviceId: "a", v4: "10.0.0.1" })];
    const approved = [base({ deviceId: "a", v4: "10.0.0.1", notes: "approved because X" })];
    const doc = proposeDoc(cf, approved);
    assert.equal(doc.devices[0]!.notes, "approved because X");
  });

  it("does not invent a note for a row that never had one", () => {
    // The known negative. Without it, a carry-over that copied some other row's note would pass the
    // test above and corrupt the record.
    const cf = [base({ deviceId: "a", v4: "10.0.0.1" }), base({ deviceId: "b", v4: "10.0.0.2" })];
    const approved = [base({ deviceId: "a", v4: "10.0.0.1", notes: "only a" })];
    const doc = proposeDoc(cf, approved);
    assert.equal(doc.devices[0]!.notes, "only a");
    assert.ok(!("notes" in doc.devices[1]!), "note 가 없던 행에 note 가 생겼다");
  });

  it("drops the note of a device that is no longer registered", () => {
    // Correct, and worth pinning: when the device is gone its reason goes with it. The command says
    // so out loud before the paste, because this is the one case where losing a note is intended.
    const cf = [base({ deviceId: "a", v4: "10.0.0.1" })];
    const approved = [
      base({ deviceId: "a", v4: "10.0.0.1" }),
      base({ deviceId: "gone", v4: "10.0.0.9", notes: "retired" }),
    ];
    const doc = proposeDoc(cf, approved);
    assert.equal(doc.devices.length, 1);
    assert.equal(doc.devices.find((d) => d.deviceId === "gone"), undefined);
  });

  it("sorts numerically, not lexically", () => {
    // `"10.0.0.10" < "10.0.0.9"` as plain strings. The old block had the same `numeric: true` and
    // this keeps it: an operator diffing two blocks reads them in address order, and a lexical sort
    // reorders half the file the first time a tenth address appears.
    const cf = [
      base({ deviceId: "x", v4: "10.0.0.10" }),
      base({ deviceId: "y", v4: "10.0.0.9" }),
    ];
    assert.deepEqual(proposeDoc(cf, []).devices.map((d) => d.v4), ["10.0.0.9", "10.0.0.10"]);
  });
});
