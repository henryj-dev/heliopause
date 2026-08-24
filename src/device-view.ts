// Rows for the device and user screens.
//
// ## The one thing this file is careful about
//
// The page renders the **approved** registry — the snapshot that lives in the site module and moves
// through git like every other policy edit. A live read from Cloudflare is optional, and when it is
// absent the screen must not read as agreement. "Not compared" and "compared and identical" are
// different facts and the banner states which one it is; a page that simply showed no differences
// would be making the stronger claim for free, which is the failure `measurement-lies` catalogues.
import type { Registration, RegistryChange } from "./cf-devices.ts";
import { diffRegistrations } from "./cf-devices.ts";
import { zoneOf, type Zone } from "./zones.ts";

// The approved-device type lives with the expansion that reads it (`cf-device`/`cf-user`), not with
// the screen: it is site data, and the policy layer is the side that must not depend on a view.
// Re-exported because every existing importer names it here.
export type { ApprovedDevice } from "./device-policy.ts";
import type { ApprovedDevice } from "./device-policy.ts";

export interface DeviceRow {
  deviceName: string;
  userEmail: string;
  v4: string;
  v6: string;
  /** Which zone the v4 address falls in, or `null` when no zone claims it. */
  zone: Zone | null;
  notes: string;
  /**
   * How this row compares to the live read.
   *
   * `unchecked` when no live read was supplied — deliberately not `ok`.
   */
  state: "unchecked" | "ok" | "moved" | "gone";
  /** Set on `moved`: where Cloudflare says the device is now. */
  liveV4?: string;
  liveV6?: string;
}

export interface DeviceScreen {
  rows: DeviceRow[];
  /** Devices Cloudflare knows about that the site module has never approved. */
  unapproved: RegistryChange[];
  /** Whether a live read happened at all. */
  compared: boolean;
  /** When the live read was taken, when there was one. */
  readAt?: string;
  /** Registrations the API returned without an address — shown, never expanded into policy. */
  addressless: number;
}

export interface UserScreenRow {
  email: string;
  devices: number;
  /** Distinct zones the user's devices land in. A user spanning zones is worth seeing. */
  zones: string[];
  v4: string[];
}

/**
 * Build the device rows.
 *
 * `live` being `undefined` is the normal case for a render that did not reach Cloudflare — an
 * offline publish, or a run without the token. It produces `unchecked` rows rather than an error,
 * because refusing to render the approved registry when the network is unavailable would make the
 * screen useless exactly when someone is trying to read it during an incident.
 */
/**
 * The zone a device sits in, from either of its addresses.
 *
 * A registration carries both a virtual v4 and a virtual v6 — `cf-devices.ts` files one missing
 * either as `addressless` rather than as a row. This asked only about the v4, so a site that
 * declares its zones in `cidrs6` placed every device in "(no zone)" while the addresses were right
 * there. That is the same half-of-the-address-space gap `Zone.cidrs6` had.
 *
 * ⚠️ **v4 wins when the two disagree, and nothing here says so.** A device whose families land in
 * different zones is one machine at two trust levels, which is a finding and not a rendering
 * question — it belongs in `zoneConflicts` beside the wrong-list check, where a site author sees it
 * once rather than in a column per device. Recorded rather than resolved here; the fallback below
 * only changes rows that had no zone at all, so nothing that reads correctly today moves.
 */
function deviceZone(zones: readonly Zone[], d: { v4: string; v6: string }): Zone | null {
  return zoneOf(zones, d.v4) ?? zoneOf(zones, d.v6);
}

export function deviceRows(
  approved: readonly ApprovedDevice[],
  zones: readonly Zone[],
  live?: { registrations: readonly Registration[]; addressless: number; readAt: string },
): DeviceScreen {
  const rows: DeviceRow[] = approved.map((d) => ({
    deviceName: d.deviceName,
    userEmail: d.userEmail,
    v4: d.v4,
    v6: d.v6,
    zone: deviceZone(zones, d),
    notes: d.notes ?? "",
    state: "unchecked" as const,
  }));

  if (!live) return { rows, unapproved: [], compared: false, addressless: 0 };

  // The approved snapshot is the "before"; Cloudflare is the "after". Reversing these would label a
  // device the site has not approved yet as a removal, which reads as "delete this from policy".
  const before: Registration[] = approved.map((d) => ({
    id: d.deviceId,
    deviceId: d.deviceId,
    deviceName: d.deviceName,
    userId: "",
    userEmail: d.userEmail,
    v4: d.v4,
    v6: d.v6,
    lastSeenAt: "",
    tunnelType: null,
  }));
  const changes = diffRegistrations(before, live.registrations);
  const byDevice = new Map(changes.map((c) => [c.deviceId, c]));

  for (const [i, d] of approved.entries()) {
    const c = byDevice.get(d.deviceId);
    const row = rows[i]!;
    if (!c) {
      row.state = "ok";
    } else if (c.kind === "moved") {
      row.state = "moved";
      row.liveV4 = c.after?.v4;
      row.liveV6 = c.after?.v6;
    } else if (c.kind === "removed") {
      row.state = "gone";
    }
  }

  return {
    rows,
    unapproved: changes.filter((c) => c.kind === "added"),
    compared: true,
    readAt: live.readAt,
    addressless: live.addressless,
  };
}

/** Group approved devices by user — the `cf-user` expansion, rendered. */
export function userScreenRows(
  approved: readonly ApprovedDevice[],
  zones: readonly Zone[],
): UserScreenRow[] {
  const m = new Map<string, UserScreenRow>();
  for (const d of approved) {
    let u = m.get(d.userEmail);
    if (!u) {
      u = { email: d.userEmail, devices: 0, zones: [], v4: [] };
      m.set(d.userEmail, u);
    }
    u.devices += 1;
    u.v4.push(d.v4);
    const z = deviceZone(zones, d);
    const label = z ? z.id : "(no zone)";
    if (!u.zones.includes(label)) u.zones.push(label);
  }
  for (const u of m.values()) {
    u.v4.sort();
    u.zones.sort();
  }
  return [...m.values()].sort((a, b) => a.email.localeCompare(b.email));
}
