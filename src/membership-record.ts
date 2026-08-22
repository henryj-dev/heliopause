// The selector membership a generation was rendered against, kept beside its artifacts.
//
// ## Why this file exists
//
// `membershipJumps` compares a selector's pod count against the previous generation's, and until
// now **nothing held the previous count**. The relay keeps only the latest reading (memory-only,
// re-supplied every beat); the manifest carries pod lists per *policy*, not per selector; and the
// rendered bundle is a wire format the relay writes verbatim. So the check existed, was tested, and
// could never run — for weeks.
//
// The reading belongs to the publisher rather than to the fleet. It is an input to rendering, not
// something a host reports or applies, and the fleet has no use for it. Writing it next to the
// artifacts keeps it with the generation it describes, and the generation id is a policy commit, so
// the pairing survives in git without anything else having to remember it.
//
// **Deliberately not in the bundle.** `validateBundle` is the boundary between "some JSON arrived"
// and "this describes a generation"; adding a field the relay neither needs nor checks would widen
// what a compromised manager can put in front of an agent, to buy a diagnostic the agent never reads.
import { readFile, writeFile, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import type { SelectorMembership } from "./protocol.ts";

/** File name inside the artifact directory. Sits beside `manifest.json`. */
export const MEMBERSHIP_FILE = "membership.json";

export interface MembershipRecord {
  /** The generation this reading was rendered against. */
  generation: string;
  /** When the cluster was queried — `SelectorMembership.at`, carried verbatim. */
  at: string;
  /**
   * Selector → pod count, flattened to the keys `membershipJumps` compares.
   *
   * `k8s-namespace:arc-runners` and `k8s-label:app=idp`, so the two kinds cannot collide. Counts
   * rather than pod names: the comparison is about size, and pod names are the fleet's most
   * short-lived data — storing them would produce a file that looks stale within seconds of being
   * written and invites someone to read it as current.
   */
  counts: Record<string, number>;
}

/** Flatten a reading to the selector keys `membershipJumps` uses. */
export function countsFrom(m: SelectorMembership): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [name, pods] of Object.entries(m.namespaces)) out[`k8s-namespace:${name}`] = pods.length;
  for (const [name, pods] of Object.entries(m.labelled)) out[`k8s-label:${name}`] = pods.length;
  return out;
}

/**
 * The shape `membershipJumps` takes — pod lists, not counts.
 *
 * It compares `.length`, so a placeholder array of the right size answers the same question as the
 * real pod names. Padding rather than storing names keeps the record small and keeps it from being
 * mistaken for a current pod list, which is the failure the `at` timestamp exists to prevent.
 */
export function asPodLists(counts: Record<string, number>): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const [selector, n] of Object.entries(counts)) out[selector] = new Array(n).fill("");
  return out;
}

/** Write the record atomically, beside the manifest. */
export async function writeMembershipRecord(dir: string, rec: MembershipRecord): Promise<void> {
  const tmp = join(dir, `${MEMBERSHIP_FILE}.tmp`);
  await writeFile(tmp, JSON.stringify(rec, null, 2) + "\n", "utf8");
  try {
    await rename(tmp, join(dir, MEMBERSHIP_FILE));
  } catch (e) {
    await rm(tmp, { force: true });
    throw e;
  }
}

/**
 * Read the previous record, or `undefined` when there is none or it is unusable.
 *
 * **Never throws.** A missing or corrupt record means the comparison cannot be made, and the honest
 * outcome of that is silence — the same as the first publish ever. Refusing to publish because a
 * diagnostic file would not parse would make an observation aid into a release blocker, which is
 * the inversion `readMembership` in the CLI already avoids for the same reason.
 */
export async function readMembershipRecord(dir: string): Promise<MembershipRecord | undefined> {
  let text: string;
  try {
    text = await readFile(join(dir, MEMBERSHIP_FILE), "utf8");
  } catch {
    return undefined;
  }
  try {
    const v = JSON.parse(text) as Partial<MembershipRecord>;
    if (typeof v.generation !== "string" || typeof v.at !== "string" || !v.counts) return undefined;
    // Counts must be numbers. A string here would compare as NaN and silently report no jump —
    // the quiet-pass failure this whole file is about.
    for (const n of Object.values(v.counts)) if (typeof n !== "number" || !Number.isFinite(n)) return undefined;
    return v as MembershipRecord;
  } catch {
    return undefined;
  }
}
