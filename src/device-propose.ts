// The document `heliopause-devices --propose` prints, as a function.
//
// ## Why this is not inline in the command
//
// It was, and a review measured what that cost. The test file next to it had **reimplemented** the
// transform — the command is a script with top-level `await` and `process.exit`, so importing it
// would run it — and the comment there argued the duplication was acceptable because the assertions
// were about properties of the output rather than a literal string.
//
// That argument was wrong, and the way it was wrong is the point. The reviewer mutated the
// **command** five ways (dropped a row, removed the note lookup, attached one row's note to every
// row, kept departed devices, sorted lexically) and **all five tests stayed green**, because they
// were exercising the copy. The suite asserted true things about code nobody ships.
//
// So the transform lives here, both callers import it, and a mutation in one place is a mutation in
// the only place. `@see src/device-propose.test.ts`
import type { Registration } from "./cf-devices.ts";
import type { ApprovedDevice } from "./device-policy.ts";

/** The file's top-level shape. `devices.json` holds exactly this. */
export interface ProposedRegistry {
  schemaVersion: 1;
  devices: ApprovedDevice[];
}

/**
 * Build the registry document from a Cloudflare read plus the rows already approved.
 *
 * Ordered by address, numerically — an operator diffing two blocks reads them in address order, and
 * a lexical sort reorders half the file the first time a tenth address appears.
 *
 * ## `notes` is not in Cloudflare
 *
 * It is the argument an approval needed, and `ApprovedDevice` declares it for exactly that ("Why
 * this device is in policy at all"). A document built from the read alone looks complete and
 * **silently deletes the reasons** — which came within one hand-transcription of happening twice.
 * So notes are carried across by `deviceId`.
 *
 * Matching is **exact string equality**, and that is narrower than the parser: `policy/devices.ts`
 * accepts an uppercase UUID, so an approved row written in uppercase would not match the lowercase
 * id the API returns, and its note would be reported as leaving. Normalising case instead would
 * merge two ids the parser treats as distinct, which is the worse failure — a note attached to the
 * wrong device reads as an approval argument for a machine nobody argued for. The registry holds
 * zero uppercase ids today (measured 2026-10-06).
 */
export function proposedRegistry(
  fromCloudflare: readonly Pick<Registration, "deviceId" | "deviceName" | "userEmail" | "v4" | "v6">[],
  approved: readonly ApprovedDevice[],
): ProposedRegistry {
  const notesById = notesByDeviceId(approved);
  const devices = fromCloudflare
    .slice()
    .sort((a, b) => a.v4.localeCompare(b.v4, undefined, { numeric: true }))
    .map((r) => {
      const kept = notesById.get(r.deviceId);
      // Field by field rather than a spread: `Registration` carries `id`, `userId`, `lastSeenAt`
      // and `tunnelType`, and `policy/devices.ts` **refuses unsupported fields**. A spread here
      // produces a document that looks right and the parser rejects — measured by the review that
      // found the copy, which spread and so could never have caught it.
      return {
        deviceId: r.deviceId,
        deviceName: r.deviceName,
        userEmail: r.userEmail,
        v4: r.v4,
        v6: r.v6,
        ...(kept ? { notes: kept } : {}),
      };
    });

  // `1` as a literal.
  //
  // `policy/devices.ts` refuses anything else today ("devices.json must have schemaVersion 1 and a
  // devices array"), so this is the only version the file can hold. ⚠️ But **nothing links the two**
  // — no shared constant, and that parser lives in another repository reached through a symlink. If
  // it ever requires 2, this producer keeps emitting 1 and the paste starts failing. That is a
  // visible failure (the parser refuses) rather than a silent one, which is why it is acceptable;
  // it is not a guarantee, and an earlier version of this comment claimed it was.
  return { schemaVersion: 1, devices };
}

/** The notes held by the rows already approved, by device. Rows without one are absent. */
export function notesByDeviceId(approved: readonly ApprovedDevice[]): Map<string, string> {
  return new Map(approved.filter((d) => d.notes).map((d) => [d.deviceId, d.notes as string]));
}

/**
 * Approved devices holding a note that no longer appear in the read.
 *
 * Their notes leave with them, which is correct when the device is gone — and worth printing before
 * the paste rather than leaving to the diff, because it is the one case where losing an approval
 * argument is intended.
 */
export function departedWithNotes(
  fromCloudflare: readonly Pick<Registration, "deviceId">[],
  approved: readonly ApprovedDevice[],
): string[] {
  const live = new Set(fromCloudflare.map((r) => r.deviceId));
  return [...notesByDeviceId(approved).keys()].filter((id) => !live.has(id));
}
