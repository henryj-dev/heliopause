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
// ## 🔴 And this file was itself the better-known failure first
//
// Its first version **reimplemented the transform**, with a comment arguing that was fine because
// the assertions were about properties of the output rather than a literal string. A review
// measured it: mutating the **command** five ways — drop a row, remove the note lookup, attach one
// row's note to every row, keep departed devices, sort lexically — left **all five tests green**.
// The suite asserted true things about code nobody ships.
//
// The transform now lives in `src/device-propose.ts` and both the command and this file import it,
// so there is one place to mutate. The reimplementation also hid a real defect it could never have
// caught: it spread the whole `Registration`, and `policy/devices.ts` **refuses unsupported
// fields**, so that shape would have been rejected on paste.
//
// So the property under test is not "the output looks like JSON". It is **the real parser accepts
// it, and nothing is lost on the way through** — `parseApprovedDevices` is the only judge, and it
// lives in the policy repository, which this repository reaches through a symlink.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { Registration } from "./cf-devices.ts";
import type { ApprovedDevice } from "./device-policy.ts";
import { departedWithNotes, proposedRegistry } from "./device-propose.ts";

/**
 * The real parser, or `undefined` when `policy/` is not linked.
 *
 * ⚠️ Not skipped silently. A worktree without the symlink runs the shape tests and **says** the
 * paste check did not run — this repository has measured the cost of a green that merely means
 * "nothing matched" (`AGENTS.md`, "수를 보라").
 */
let parse: ((v: unknown) => ApprovedDevice[]) | undefined;
try {
  ({ parseApprovedDevices: parse } = (await import("../policy/devices.ts")) as {
    parseApprovedDevices: (v: unknown) => ApprovedDevice[];
  });
} catch {
  console.log("  ⚠️ policy/ not linked — the parser check did not run");
}

/** Cloudflare's shape, including the four fields the file must NOT carry. */
const reg = (over: Partial<Registration> & { deviceId: string; v4: string }): Registration => ({
  id: "0f1e2d3c-4b5a-6978-8765-432112345678",
  deviceName: "a device",
  userId: "9a8b7c6d-5e4f-3021-1234-567890abcdef",
  userEmail: "someone@example.test",
  v6: "2001:db8::1",
  lastSeenAt: "2026-10-06T00:00:00Z",
  tunnelType: "wireguard",
  ...over,
});

const approvedRow = (
  over: Partial<ApprovedDevice> & { deviceId: string; v4: string },
): ApprovedDevice => ({
  deviceName: "a device",
  userEmail: "someone@example.test",
  v6: "2001:db8::1",
  ...over,
});

// Parser-valid ids. Hand-written UUIDs rather than `randomUUID()`: a failure should name the same
// row every run.
const A = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const B = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
const GONE = "cccccccc-3333-4333-8333-cccccccccccc";

describe("--propose prints a document that devices.json accepts", () => {
  it("is accepted by the real parser, with the Cloudflare-only fields dropped", () => {
    // 🔴 The one the reimplementation could not have caught. `Registration` carries `id`, `userId`,
    // `lastSeenAt` and `tunnelType`; the parser refuses unsupported fields. A spread passes every
    // other assertion in this file and fails on paste.
    const doc = proposedRegistry([reg({ deviceId: A, v4: "10.0.0.1" })], []);
    assert.deepEqual(Object.keys(doc.devices[0]!), [
      "deviceId",
      "deviceName",
      "userEmail",
      "v4",
      "v6",
    ]);
    if (!parse) return;
    const parsed = parse(JSON.parse(JSON.stringify(doc)));
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0]!.deviceId, A);
  });

  it("keeps every row, in numeric address order", () => {
    // `"10.0.0.10" < "10.0.0.9"` as plain strings. An operator diffing two blocks reads them in
    // address order, and a lexical sort reorders half the file the first time a tenth appears.
    const doc = proposedRegistry(
      [reg({ deviceId: B, v4: "10.0.0.10" }), reg({ deviceId: A, v4: "10.0.0.9" })],
      [],
    );
    assert.equal(doc.schemaVersion, 1);
    assert.deepEqual(
      doc.devices.map((d) => d.v4),
      ["10.0.0.9", "10.0.0.10"],
    );
  });

  it("carries `notes` across from the rows already approved", () => {
    // Cloudflare does not return `notes`; it is the argument an approval needed. A block without it
    // looks complete and silently deletes the reasons.
    const doc = proposedRegistry(
      [reg({ deviceId: A, v4: "10.0.0.1" })],
      [approvedRow({ deviceId: A, v4: "10.0.0.1", notes: "approved because X" })],
    );
    assert.equal(doc.devices[0]!.notes, "approved because X");
    if (parse) assert.equal(parse(JSON.parse(JSON.stringify(doc)))[0]!.notes, "approved because X");
  });

  it("does not invent a note for a row that never had one", () => {
    // The known negative. Without it, a carry-over that copied some other row's note would pass the
    // test above and corrupt the record.
    const doc = proposedRegistry(
      [reg({ deviceId: A, v4: "10.0.0.1" }), reg({ deviceId: B, v4: "10.0.0.2" })],
      [approvedRow({ deviceId: A, v4: "10.0.0.1", notes: "only a" })],
    );
    assert.equal(doc.devices[0]!.notes, "only a");
    assert.ok(!("notes" in doc.devices[1]!), "note 가 없던 행에 note 가 생겼다");
  });

  it("drops a device that is no longer registered, and names its lost note", () => {
    // Two halves of one behaviour, asserted together: the row leaves AND the command says the note
    // left with it. Pinning only the first would let the warning be deleted silently — and that
    // warning is the only place an intentional loss becomes visible before the paste.
    const live = [reg({ deviceId: A, v4: "10.0.0.1" })];
    const approved = [
      approvedRow({ deviceId: A, v4: "10.0.0.1" }),
      approvedRow({ deviceId: GONE, v4: "10.0.0.9", notes: "retired" }),
    ];
    const doc = proposedRegistry(live, approved);
    assert.equal(doc.devices.length, 1);
    assert.equal(
      doc.devices.find((d) => d.deviceId === GONE),
      undefined,
    );
    assert.deepEqual(departedWithNotes(live, approved), [GONE]);
  });

  it("does not announce a departure for a device that is still there", () => {
    // The warning's known negative. Without it, `departedWithNotes` could return every approved id
    // and the test above would still pass.
    const live = [reg({ deviceId: A, v4: "10.0.0.1" })];
    const approved = [approvedRow({ deviceId: A, v4: "10.0.0.1", notes: "still here" })];
    assert.deepEqual(departedWithNotes(live, approved), []);
  });
});
