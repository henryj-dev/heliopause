// The device registry read, and the four ways it could quietly return the wrong list.
//
// Every failure this file guards against produces a *shorter* list rather than an error, and a
// shorter list flows straight into a diff that reads as "these devices went away". Approving that
// diff narrows policy against devices that never left. So most of these tests are about the
// difference between "empty" and "unknown".
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  diffRegistrations,
  fetchRegistrations,
  parsePage,
  totalFromCursor,
  TruncatedRead,
  userRows,
  type Registration,
} from "./cf-devices.ts";

/** Build the trailing cursor segment the API uses to carry the total. */
const cursorFor = (total: number) =>
  `2026-01-01T00:00:00Z.opaque.${Buffer.from(JSON.stringify({ total })).toString("base64")}`;

const reg = (over: Partial<Record<string, unknown>> = {}) => ({
  id: "r1",
  virtual_ipv4: "10.0.0.1",
  virtual_ipv6: "fd00::1",
  last_seen_at: "2026-08-12T00:00:00Z",
  tunnel_type: "wireguard",
  user: { id: "u1", email: "a@example.com", name: "A" },
  device: { id: "d1", name: "laptop" },
  ...over,
});

const ok = (result: unknown[], cursor = "") => ({
  success: true,
  errors: [],
  result,
  result_info: { count: result.length, cursor, per_page: 100 },
});

const row = (over: Partial<Registration> = {}): Registration => ({
  id: "r1",
  deviceId: "d1",
  deviceName: "laptop",
  userId: "u1",
  userEmail: "a@example.com",
  v4: "10.0.0.1",
  v6: "fd00::1",
  lastSeenAt: "2026-08-12T00:00:00Z",
  tunnelType: "wireguard",
  ...over,
});

describe("parsePage", () => {
  it("reads a page", () => {
    const p = parsePage(ok([reg()]));
    assert.equal(p.rows.length, 1);
    assert.equal(p.rows[0]!.v4, "10.0.0.1");
    assert.equal(p.rows[0]!.userId, "u1");
    assert.equal(p.rows[0]!.deviceName, "laptop");
  });

  // A `success: false` body is still valid JSON with a `result` key. Reading rows off it produces
  // an empty list that is indistinguishable from an account with no devices.
  it("throws when the envelope says the call failed", () => {
    const body = { success: false, errors: [{ code: 10000, message: "Authentication error" }], result: [] };
    assert.throws(() => parsePage(body), /Authentication error/);
  });

  it("throws when result is not an array", () => {
    assert.throws(() => parsePage({ success: true, errors: [], result: null }), /no result array/);
  });

  // `virtual_ipv4`/`virtual_ipv6` are nullable in the API.
  it("separates addressless registrations instead of dropping them", () => {
    const p = parsePage(ok([reg(), reg({ id: "r2", virtual_ipv4: null }), reg({ id: "r3", virtual_ipv6: null })]));
    assert.equal(p.rows.length, 1);
    assert.deepEqual(
      p.addressless.map((a) => [a.id, a.missing]),
      [
        ["r2", "v4"],
        ["r3", "v6"],
      ],
    );
  });

  it("reports both when neither address is present", () => {
    const p = parsePage(ok([reg({ virtual_ipv4: null, virtual_ipv6: null })]));
    assert.equal(p.addressless[0]!.missing, "both");
  });
});

describe("totalFromCursor", () => {
  it("decodes the total the cursor carries", () => {
    assert.equal(totalFromCursor(cursorFor(32)), 32);
  });

  // Undocumented format. Failing to decode must not throw — it only disables the cross-check.
  it("returns null rather than throwing on an undecodable cursor", () => {
    assert.equal(totalFromCursor("not-a-cursor"), null);
    assert.equal(totalFromCursor(""), null);
    assert.equal(totalFromCursor("a.b.bm90LWpzb24="), null);
  });
});

describe("fetchRegistrations", () => {
  const pager = (pages: Array<{ rows: unknown[]; cursor: string }>) => {
    const seen: string[] = [];
    let i = 0;
    return {
      seen,
      get: async (url: string) => {
        seen.push(url);
        const p = pages[i++];
        if (!p) throw new Error("asked for more pages than the fixture has");
        return ok(p.rows, p.cursor);
      },
    };
  };

  it("follows the cursor until it is empty", async () => {
    const { get, seen } = pager([
      { rows: [reg({ id: "r1", device: { id: "d1", name: "one" } })], cursor: cursorFor(2) },
      { rows: [reg({ id: "r2", device: { id: "d2", name: "two" } })], cursor: "" },
    ]);
    const read = await fetchRegistrations({ accountId: "acc", token: "t", get });
    assert.equal(read.registrations.length, 2);
    assert.equal(read.pages, 2);
    assert.match(seen[0]!, /status=active/);
    assert.match(seen[1]!, /cursor=/);
  });

  // Measured 2026-08-12: asking for 50 and receiving all 32 still returns a non-empty cursor, and
  // the follow-up returns `count: 0, cursor: ""`. A loop that stopped on a short page would work by
  // accident on a full account and stop early on a small one.
  it("keeps paging when a page comes back short but the cursor is still open", async () => {
    const { get } = pager([
      { rows: [reg({ id: "r1", device: { id: "d1", name: "one" } })], cursor: cursorFor(2) },
      { rows: [reg({ id: "r2", device: { id: "d2", name: "two" } })], cursor: "" },
    ]);
    const read = await fetchRegistrations({ accountId: "acc", token: "t", perPage: 50, get });
    assert.equal(read.registrations.length, 2);
  });

  it("stops without an extra request when the first cursor is already empty", async () => {
    const { get, seen } = pager([{ rows: [reg()], cursor: "" }]);
    const read = await fetchRegistrations({ accountId: "acc", token: "t", get });
    assert.equal(read.pages, 1);
    assert.equal(seen.length, 1);
  });

  // The cap is a truncation, never a short list.
  it("throws TruncatedRead when the page cap is hit with a cursor still open", async () => {
    const get = async () => ok([reg()], cursorFor(999));
    await assert.rejects(
      () => fetchRegistrations({ accountId: "acc", token: "t", maxPages: 3, get }),
      (e: Error) => e instanceof TruncatedRead && /incomplete, not empty/.test(e.message),
    );
  });

  it("throws TruncatedRead when fewer rows arrive than the cursor claimed", async () => {
    const { get } = pager([
      { rows: [reg({ id: "r1", device: { id: "d1", name: "one" } })], cursor: cursorFor(9) },
      { rows: [reg({ id: "r2", device: { id: "d2", name: "two" } })], cursor: "" },
    ]);
    await assert.rejects(
      () => fetchRegistrations({ accountId: "acc", token: "t", get }),
      (e: Error) => e instanceof TruncatedRead && /claimed 9/.test(e.message),
    );
  });

  // ## The per-page count, which used to be recorded and never read
  //
  // `parsePage` computed `result_info.count` into the `Page` it returned and nothing — not even a
  // test — looked at it. The aggregate check above covers the same ground, but only when the cursor
  // decodes, and that format is undocumented: `totalFromCursor` returning `null` is a normal
  // outcome. So a read whose cursor did not decode had **no completeness check at all**, with the
  // number that would have supplied one sitting unread in the same object.
  it("refuses a page that sent fewer rows than it claimed", () => {
    // No cursor, so the aggregate check cannot fire and this is the only thing standing between a
    // short page and a list that reads as the whole account.
    assert.throws(
      () => parsePage({ success: true, errors: [], result: [reg()], result_info: { count: 4, cursor: "" } }),
      (e: Error) => e instanceof TruncatedRead && /claimed 4/.test(e.message),
    );
  });

  it("accepts the page whose count matches, and does not invent one when the API sends none", () => {
    // Two known positives for the check above. The first is the ordinary case; without the second, a
    // check comparing against its own fallback would look like it worked while proving nothing —
    // which is what the unread field amounted to.
    assert.equal(parsePage({ success: true, errors: [], result: [reg()], result_info: { count: 1, cursor: "" } }).rows.length, 1);
    const noCount = parsePage({ success: true, errors: [], result: [reg()], result_info: { cursor: "" } });
    assert.deepEqual([noCount.rows.length, noCount.count], [1, 1]);
  });

  it("counts an addressless registration toward the page's own count too", () => {
    // The same distinction the aggregate check makes. A registration with no address is a row the
    // API sent; excluding it here would make every account holding one fail this check.
    const page = parsePage({
      success: true,
      errors: [],
      result: [reg(), reg({ id: "r2", virtual_ipv4: null })],
      result_info: { count: 2, cursor: "" },
    });
    assert.deepEqual([page.rows.length, page.addressless.length], [1, 1]);
  });

  it("counts addressless registrations toward the claimed total", async () => {
    const { get } = pager([{ rows: [reg(), reg({ id: "r2", virtual_ipv4: null })], cursor: "" }]);
    const read = await fetchRegistrations({ accountId: "acc", token: "t", get });
    assert.equal(read.registrations.length, 1);
    assert.equal(read.addressless.length, 1);
  });

  // The guard this whole module was designed around. Three gateway registrations last reported
  // 91–93 days before this test was written and all three were alive and taking policy.
  it("does not filter by recency", async () => {
    const { get } = pager([
      { rows: [reg({ id: "old", last_seen_at: "2025-01-01T00:00:00Z" })], cursor: "" },
    ]);
    const read = await fetchRegistrations({ accountId: "acc", token: "t", get });
    assert.equal(read.registrations.length, 1, "a long-silent registration must still be returned");
  });

  it("asks only for active registrations", async () => {
    const { get, seen } = pager([{ rows: [], cursor: "" }]);
    await fetchRegistrations({ accountId: "acc", token: "t", get });
    assert.match(seen[0]!, /[?&]status=active(&|$)/);
  });
});

describe("diffRegistrations", () => {
  // Re-registering mints a new registration id. Keyed on that, every re-registration would read as
  // a removal plus an addition and hide the fact that matters: the address moved under a device
  // that is still the same device.
  it("reports a re-registration with a new address as one move, not a remove plus an add", () => {
    const before = [row({ id: "r1", v4: "10.0.0.1" })];
    const after = [row({ id: "r2-new-registration", v4: "10.0.0.9" })];
    const d = diffRegistrations(before, after);
    assert.equal(d.length, 1);
    assert.equal(d[0]!.kind, "moved");
    assert.equal(d[0]!.before?.v4, "10.0.0.1");
    assert.equal(d[0]!.after?.v4, "10.0.0.9");
  });

  it("reports a device that is gone as removed", () => {
    const d = diffRegistrations([row()], []);
    assert.deepEqual(
      d.map((c) => [c.kind, c.deviceId]),
      [["removed", "d1"]],
    );
    assert.equal(d[0]!.before?.v4, "10.0.0.1");
  });

  it("reports a new device as added", () => {
    const d = diffRegistrations([], [row()]);
    assert.deepEqual(
      d.map((c) => [c.kind, c.deviceId]),
      [["added", "d1"]],
    );
    assert.equal(d[0]!.after?.v4, "10.0.0.1");
  });

  it("says nothing when the addresses are unchanged", () => {
    assert.deepEqual(diffRegistrations([row()], [row({ id: "different-registration-id" })]), []);
  });

  it("notices an IPv6 change on its own", () => {
    const d = diffRegistrations([row()], [row({ v6: "fd00::9" })]);
    assert.equal(d.length, 1);
    assert.equal(d[0]!.kind, "moved");
  });

  it("puts moves first so the change that breaks policy is read first", () => {
    const before = [row({ deviceId: "d1" }), row({ deviceId: "d2", v4: "10.0.0.2" })];
    const after = [row({ deviceId: "d1", v4: "10.0.0.8" }), row({ deviceId: "d3", v4: "10.0.0.3" })];
    assert.deepEqual(
      diffRegistrations(before, after).map((c) => c.kind),
      ["moved", "removed", "added"],
    );
  });
});

describe("userRows", () => {
  it("groups by user id, not by email", () => {
    const rs = [
      row({ deviceId: "d1", userId: "u1", userEmail: "a@example.com" }),
      row({ deviceId: "d2", userId: "u1", userEmail: "a@example.com", v4: "10.0.0.2" }),
      row({ deviceId: "d3", userId: "u2", userEmail: "b@example.com", v4: "10.0.0.3" }),
    ];
    const us = userRows(rs);
    assert.equal(us.length, 2);
    assert.equal(us[0]!.devices, 2);
    assert.deepEqual(us[0]!.v4, ["10.0.0.1", "10.0.0.2"]);
    assert.equal(us[1]!.devices, 1);
  });

  // Two accounts can carry the same label; the id is what H13 expands on.
  it("keeps two user ids apart even when the email matches", () => {
    const rs = [
      row({ deviceId: "d1", userId: "u1", userEmail: "same@example.com" }),
      row({ deviceId: "d2", userId: "u2", userEmail: "same@example.com" }),
    ];
    assert.equal(userRows(rs).length, 2);
  });
});
