// The device screen, and the claim it must not make for free.
//
// Cloudflare owns these addresses. A page that renders the approved registry and shows nothing wrong
// is saying something quite different depending on whether it reached Cloudflare, and only one of
// those readings is "these are correct". Most of this file is about keeping those two apart.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { deviceRows, userScreenRows, type ApprovedDevice } from "./device-view.ts";
import { deviceTable, userTable } from "./policy-ui.ts";
import type { Registration } from "./cf-devices.ts";
import type { Zone } from "./zones.ts";

const ZONES: Zone[] = [
  { id: "mgmt", name: "management", cidrs: ["10.254.0.0/16"], trust: 3 },
  { id: "backbone", name: "backbone", cidrs: ["10.255.0.0/16"], trust: 3 },
];

const approved = (over: Partial<ApprovedDevice> = {}): ApprovedDevice => ({
  deviceId: "d1",
  deviceName: "laptop",
  userEmail: "a@example.com",
  v4: "10.254.0.6",
  v6: "fd00::6",
  ...over,
});

const live = (over: Partial<Registration> = {}): Registration => ({
  id: "r1",
  deviceId: "d1",
  deviceName: "laptop",
  userId: "u1",
  userEmail: "a@example.com",
  v4: "10.254.0.6",
  v6: "fd00::6",
  lastSeenAt: "2026-08-12T00:00:00Z",
  tunnelType: "wireguard",
  ...over,
});

const read = (rs: Registration[]) => ({ registrations: rs, addressless: 0, readAt: "2026-08-12T00:00:00Z" });

describe("deviceRows", () => {
  // The guard this file exists for.
  it("marks rows unchecked, not ok, when no live read was supplied", () => {
    const s = deviceRows([approved()], ZONES);
    assert.equal(s.compared, false);
    assert.equal(s.rows[0]!.state, "unchecked");
    assert.equal(s.readAt, undefined);
  });

  it("marks a row ok only after comparing", () => {
    const s = deviceRows([approved()], ZONES, read([live()]));
    assert.equal(s.compared, true);
    assert.equal(s.rows[0]!.state, "ok");
  });

  it("reports an address that moved, and where it moved to", () => {
    const s = deviceRows([approved()], ZONES, read([live({ v4: "10.254.0.9" })]));
    assert.equal(s.rows[0]!.state, "moved");
    assert.equal(s.rows[0]!.liveV4, "10.254.0.9");
    // The approved address stays in its column — the rule still names it, and that is the problem.
    assert.equal(s.rows[0]!.v4, "10.254.0.6");
  });

  it("reports an approved device with no registration left", () => {
    const s = deviceRows([approved()], ZONES, read([]));
    assert.equal(s.rows[0]!.state, "gone");
  });

  // Reversing the diff would label these as removals, which reads as "delete this from policy".
  it("lists a device Cloudflare knows and policy has not approved", () => {
    const s = deviceRows([], ZONES, read([live({ deviceId: "new", deviceName: "phone" })]));
    assert.equal(s.rows.length, 0);
    assert.equal(s.unapproved.length, 1);
    assert.equal(s.unapproved[0]!.kind, "added");
    assert.equal(s.unapproved[0]!.deviceName, "phone");
  });

  it("classifies each approved address into a zone", () => {
    const s = deviceRows([approved(), approved({ deviceId: "d2", v4: "10.255.0.9" })], ZONES);
    assert.equal(s.rows[0]!.zone?.id, "mgmt");
    assert.equal(s.rows[1]!.zone?.id, "backbone");
  });

  // An address policy grants access on, with no stated trust, is a finding rather than a blank.
  it("leaves zone null when no zone claims the address", () => {
    const s = deviceRows([approved({ v4: "100.96.0.4" })], ZONES);
    assert.equal(s.rows[0]!.zone, null);
  });

  it("carries the addressless count through", () => {
    const s = deviceRows([approved()], ZONES, { ...read([live()]), addressless: 3 });
    assert.equal(s.addressless, 3);
  });
});

describe("userScreenRows", () => {
  it("groups devices under their user", () => {
    const us = userScreenRows(
      [approved(), approved({ deviceId: "d2", v4: "10.254.0.7" }), approved({ deviceId: "d3", userEmail: "b@example.com", v4: "10.255.0.1" })],
      ZONES,
    );
    assert.equal(us.length, 2);
    assert.equal(us[0]!.devices, 2);
    assert.deepEqual(us[0]!.v4, ["10.254.0.6", "10.254.0.7"]);
  });

  // Naming a user in a rule reaches every address below it. One that straddles zones reaches
  // further than whoever wrote the rule is likely to have pictured.
  it("reports every zone a user's devices land in", () => {
    const us = userScreenRows([approved(), approved({ deviceId: "d2", v4: "10.255.0.1" })], ZONES);
    assert.deepEqual(us[0]!.zones, ["backbone", "mgmt"]);
  });

  it("labels an unzoned address rather than omitting it", () => {
    const us = userScreenRows([approved({ v4: "100.96.0.4" })], ZONES);
    assert.deepEqual(us[0]!.zones, ["(no zone)"]);
  });
});

describe("deviceTable", () => {
  it("says it did not compare when it did not", () => {
    const html = deviceTable(deviceRows([approved()], ZONES));
    assert.match(html, /not compared against Cloudflare/);
    assert.doesNotMatch(html, /matched Cloudflare/);
  });

  it("says it matched only after a comparison", () => {
    const html = deviceTable(deviceRows([approved()], ZONES, read([live()])));
    assert.match(html, /matched Cloudflare/);
    assert.doesNotMatch(html, /not compared/);
  });

  it("counts drift in the heading", () => {
    const html = deviceTable(deviceRows([approved()], ZONES, read([live({ v4: "10.254.0.9" })])));
    assert.match(html, /1 differ from Cloudflare/);
    assert.match(html, /now 10\.254\.0\.9/);
  });

  it("counts an unapproved device as a difference too", () => {
    const s = deviceRows([approved()], ZONES, read([live(), live({ deviceId: "x", deviceName: "phone" })]));
    assert.match(deviceTable(s), /1 differ from Cloudflare/);
    assert.match(deviceTable(s), /not approved/);
  });

  it("marks an address no zone claims", () => {
    assert.match(deviceTable(deviceRows([approved({ v4: "100.96.0.4" })], ZONES)), /no zone/);
  });

  it("states how many registrations carry no address", () => {
    const s = deviceRows([approved()], ZONES, { ...read([live()]), addressless: 2 });
    assert.match(deviceTable(s), /2 registration\(s\) carry no mesh address/);
  });

  it("renders nothing when there is nothing to say", () => {
    assert.equal(deviceTable(deviceRows([], ZONES)), "");
  });

  it("escapes a device name", () => {
    const html = deviceTable(deviceRows([approved({ deviceName: "<script>x</script>" })], ZONES));
    assert.doesNotMatch(html, /<script>/);
    assert.match(html, /&lt;script&gt;/);
  });
});

describe("userTable", () => {
  it("flags a user whose devices straddle zones", () => {
    const html = userTable(userScreenRows([approved(), approved({ deviceId: "d2", v4: "10.255.0.1" })], ZONES));
    assert.match(html, /class="warn">backbone, mgmt/);
  });

  it("does not flag a user inside one zone", () => {
    const html = userTable(userScreenRows([approved()], ZONES));
    assert.match(html, /class="dim">mgmt/);
  });

  it("renders nothing for no users", () => {
    assert.equal(userTable([]), "");
  });
});
