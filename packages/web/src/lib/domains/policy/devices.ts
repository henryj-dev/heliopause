// The approved device registry the table edits — `devices.json` in the policy repository.
//
// ## Why a second table module instead of reusing `rules.ts`
//
// Different document, different failure. A rule names endpoints and the table's job is to keep the
// keys it does not show (`notes`, `denyMode`) from being dropped on save. A device row names
// **addresses**, and the mistake that matters here is a row that parses fine and admits the wrong
// machine: `deviceCidrs` expands a `cf-user` into the union of that person's addresses, so one typo'd
// `v4` silently widens or narrows every rule scoped to them. Sharing a module would mean one set of
// guards for two different questions.
//
// ## What this module refuses to do
//
// **It does not validate.** `policy/devices.ts` already does, strictly, and it runs where the
// decision has consequences — at render time, where a bad row stops the render instead of shipping a
// rule. Re-implementing those checks here would put a second, weaker copy in front of the user and
// invite the two to drift; the table's job is to make a well-formed edit easy, not to be the
// authority on what is well-formed. `readDeviceDoc` therefore only asks "can the table show this",
// which is exactly the question `readPolicyDoc` asks about `policies.json`.
//
// The consequence is worth stating: a save from this table can still be rejected by the renderer. It
// arrives as a failed check on the pull request rather than as a form error, and that is the right
// place for it — the check is the thing that cannot be bypassed.

/**
 * Columns the table paints. `notes` is not one: it is long prose, shown in the editor instead.
 *
 * Every key here already existed in the shared catalogue — `c.device`, `c.user`, `c.v4`, `c.v6` are
 * what the classic console's device screen paints. Adding `c.deviceName` and friends would have made
 * two names for one column and left the two screens free to disagree about the word.
 */
export const DEVICE_COLUMNS = ["c.device", "c.user", "c.v4", "c.v6", ""] as const;

export interface DeviceRow {
  deviceId: string;
  deviceName: string;
  userEmail: string;
  v4: string;
  v6: string;
  notes?: string;
  /** Anything the table does not show must survive a save. Same contract as `rules.ts`. */
  [key: string]: unknown;
}

export interface DeviceDoc {
  schemaVersion: number;
  devices: DeviceRow[];
  [key: string]: unknown;
}

export type DeviceDocRead = { ok: true; doc: DeviceDoc } | { ok: false; reason: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Can the table show this document?
 *
 * The five fields below are the ones every row renders, so a row missing one would paint a blank
 * cell that saves as `undefined` — a hole the renderer then refuses at a distance from the edit. A
 * document this function rejects falls back to the textarea, which is the only honest thing to offer
 * for a file the table would mangle.
 */
export function readDeviceDoc(content: string): DeviceDocRead {
  let raw: unknown;
  try {
    raw = JSON.parse(content);
  } catch (e) {
    return { ok: false, reason: `not JSON: ${(e as Error).message}` };
  }
  if (!isRecord(raw)) return { ok: false, reason: "the device registry is not an object" };
  if (!Array.isArray(raw.devices)) return { ok: false, reason: "the device registry has no devices list" };
  for (const [index, row] of raw.devices.entries()) {
    if (!isRecord(row)) return { ok: false, reason: `devices[${index}] is not an object` };
    for (const field of ["deviceId", "deviceName", "userEmail", "v4", "v6"]) {
      if (typeof row[field] !== "string") {
        return { ok: false, reason: `devices[${index}] has no ${field} the table can edit` };
      }
    }
  }
  return { ok: true, doc: raw as DeviceDoc };
}

export function writeDeviceDoc(doc: DeviceDoc): string {
  return `${JSON.stringify(doc, null, 2)}\n`;
}

/**
 * A blank row, with the fields visibly empty rather than plausibly wrong.
 *
 * No generated id and no guessed address. Cloudflare assigns both, and a placeholder that looks like
 * a UUID is one a reviewer can miss — an empty string cannot be mistaken for a real device.
 */
export function newDevice(): DeviceRow {
  return { deviceId: "", deviceName: "", userEmail: "", v4: "", v6: "" };
}

export function addDevice(doc: DeviceDoc): DeviceRow {
  const row = newDevice();
  doc.devices.push(row);
  return row;
}

export function deleteDevice(doc: DeviceDoc, row: DeviceRow): boolean {
  const at = doc.devices.indexOf(row);
  if (at < 0) return false;
  doc.devices.splice(at, 1);
  return true;
}

/** The editor's fields, as strings. `notes` is optional in the document and empty-able here. */
export interface DeviceDraft {
  deviceId: string;
  deviceName: string;
  userEmail: string;
  v4: string;
  v6: string;
  notes: string;
}

export function draftFromDevice(row: DeviceRow): DeviceDraft {
  return {
    deviceId: row.deviceId,
    deviceName: row.deviceName,
    userEmail: row.userEmail,
    v4: row.v4,
    v6: row.v6,
    notes: typeof row.notes === "string" ? row.notes : "",
  };
}

/**
 * Write a draft back, trimming each field and **removing** an emptied `notes` rather than storing "".
 *
 * `policy/devices.ts` refuses a blank note, deliberately: a present-but-empty field reads as "a
 * reason was given" to anything that checks for the key. Deleting it keeps the two ends agreeing, so
 * clearing the box in the form produces a document the renderer accepts.
 */
export function applyDeviceDraft(row: DeviceRow, draft: DeviceDraft): void {
  row.deviceId = draft.deviceId.trim();
  row.deviceName = draft.deviceName.trim();
  row.userEmail = draft.userEmail.trim();
  row.v4 = draft.v4.trim();
  row.v6 = draft.v6.trim();
  const notes = draft.notes.trim();
  if (notes) row.notes = notes;
  else delete row.notes;
}

/**
 * Rows whose approval carries no stated reason.
 *
 * Mirrors `rulesWithoutNotes`. Most devices need no argument — a laptop is a laptop — so this is not
 * a defect list. It is what the screen shows when someone asks which approvals would leave no record
 * of why, which is the question worth asking before a review rather than after.
 */
export function devicesWithoutNotes(doc: DeviceDoc): string[] {
  return doc.devices.filter((row) => typeof row.notes !== "string" || row.notes.trim() === "")
    .map((row) => row.deviceName || row.deviceId || "(unnamed)");
}
