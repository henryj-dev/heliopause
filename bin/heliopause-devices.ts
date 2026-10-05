#!/usr/bin/env node
// Compare the approved device registry against Cloudflare, and propose the edit.
//
// ## Why this prints a diff instead of writing the policy
//
// Changing which addresses a rule reaches is a policy change, and **git is the interface for policy
// changes** in this repository. A command that rewrote `policy/*.ts` from a network read would move
// that decision out of review and into a cron job — and the input is a registry that reassigns
// addresses on its own schedule, so the one time it would matter is the one time nobody looked.
//
// So: read, compare, print. `--propose` emits the block to paste, which is where a human reads what
// changed before it becomes policy.
//
// ## What "no differences" means here
//
// Only that every approved device still holds the address it was approved with. It is not a
// statement that the approved set is the right set — `not approved` rows say who else exists.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { fetchRegistrations, lastSeenColumn, TruncatedRead, userRows } from "../src/cf-devices.ts";
import { deviceRows } from "../src/device-view.ts";
import { TRUST_LABEL, zoneOf } from "../src/zones.ts";
import type { Site } from "./heliopause-publish.ts";
import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const has = (name: string) => args.includes(name);

const siteArg = args[0]?.startsWith("--") ? undefined : args[0];

if (!siteArg || has("--help")) {
  console.error(
    "usage: heliopause-devices <site.ts> --account <id> [--token-file <path>] [--propose]\n" +
      "\n" +
      "  Reads the Cloudflare device registry and compares it to the site module's approved list.\n" +
      "  HELIOPAUSE_CF_TOKEN_FILE may name the token file. Exits 1 when anything differs, so this\n" +
      "  can gate a pipeline; exits 2 when the read could not be trusted to be complete.",
  );
  process.exit(has("--help") ? 0 : 64);
}

const account = flag("--account") ?? process.env.HELIOPAUSE_CF_ACCOUNT;
if (!account) {
  console.error("--account is required (or set HELIOPAUSE_CF_ACCOUNT)");
  process.exit(64);
}

const tokenFile = flag("--token-file") ?? process.env.HELIOPAUSE_CF_TOKEN_FILE;
if (!tokenFile) {
  console.error("no token file — pass --token-file or set HELIOPAUSE_CF_TOKEN_FILE");
  process.exit(64);
}
const token = readFileSync(resolve(tokenFile), "utf8").trim();
if (!token) {
  console.error("Cloudflare token file is empty");
  process.exit(64);
}

const mod = (await import(pathToFileURL(resolve(siteArg)).href)) as { site?: Site };
const loaded = mod.site;
if (!loaded) {
  console.error(`${siteArg} does not export \`site\``);
  process.exit(64);
}

let read;
try {
  read = await fetchRegistrations({ accountId: account, token });
} catch (e) {
  // A truncated read is not a small read. Exiting 2 rather than reporting differences keeps a
  // partial answer from being approved as a complete one.
  if (e instanceof TruncatedRead) {
    console.error(`incomplete read: ${e.message}`);
    process.exit(2);
  }
  throw e;
}

const readAt = new Date().toISOString();
const screen = deviceRows(loaded.devices ?? [], loaded.zones ?? [], {
  registrations: read.registrations,
  addressless: read.addressless.length,
  readAt,
});

const moved = screen.rows.filter((r) => r.state === "moved");
const gone = screen.rows.filter((r) => r.state === "gone");

console.log(`read ${read.registrations.length} active registration(s) in ${read.pages} page(s) at ${readAt}`);

// Who those registrations belong to, one line per person.
//
// **The per-device lines below answer "which address moved"; this answers "how many machines does
// each person have on the network".** They are different questions and only the first was being
// asked — `userRows` computed this and nothing printed it, so the aggregation existed and no reader
// ever saw it. A device list is also a people list, and an account with far more devices than the
// rest is the shape worth noticing before it is a rule.
for (const u of userRows(read.registrations)) {
  console.log(`  ${u.email}  ${u.devices} device(s)`);
}
if (read.addressless.length) {
  console.log(`  ${read.addressless.length} carry no mesh address and are excluded`);
}
console.log(`approved: ${screen.rows.length}`);

for (const r of moved) {
  console.log(`  MOVED     ${r.deviceName} (${r.userEmail})  ${r.v4} -> ${r.liveV4}  ${r.v6} -> ${r.liveV6}`);
}
for (const r of gone) {
  console.log(`  GONE      ${r.deviceName} (${r.userEmail})  ${r.v4}  — no active registration`);
}
/**
 * An unapproved registration is only a *finding* when policy could name it.
 *
 * ## Why this split exists
 *
 * Without it the check fails on every run. This account holds registrations in a legacy range the
 * zone table places outside every named zone — `policy/dev.ts` says in as many words that their
 * absence from the approved list is deliberate and that this command reports them each time. So the
 * job that exists to catch drift went red in the normal state, and **a job that is always red is one
 * nobody reads** — which is where the real drift would then hide.
 *
 * The line is the zone model's **trust**, not a hardcoded range and not mere membership. Membership
 * was the first attempt and it caught everything: the zone table ends in a catch-all `internet` zone
 * — "everything no other zone claims" — so a legacy address is in a zone, just the untrusted one.
 * Measured on the first green run of this job.
 *
 * Trust is the property that matters. A rule scoped to a trusted zone can name a device that lands
 * there; a device in the untrusted catch-all is one the site has said nothing about, and approving it
 * into such a rule is the mistake the `--propose` annotation already warns about. Both are printed;
 * only the trusted ones decide the exit code.
 */
const trustedZone = (addr: string | undefined) => {
  const zone = addr ? zoneOf(loaded.zones ?? [], addr) : null;
  return zone && zone.trust > 0 ? zone : null;
};
const unapprovedInZone = screen.unapproved.filter((c) => trustedZone(c.after?.v4));
const unapprovedOutside = screen.unapproved.filter((c) => !trustedZone(c.after?.v4));

// What Cloudflare last recorded for each registration, keyed by device so a report line can carry
// it. Rendered by `lastSeenColumn`, which is also where the reason this is an ordering and not a
// liveness signal is written down.
const liveByDevice = new Map(read.registrations.map((r) => [r.deviceId, r]));
const seenColumn = (deviceId: string): string => lastSeenColumn(liveByDevice.get(deviceId));

for (const c of unapprovedInZone) {
  const z = zoneOf(loaded.zones ?? [], c.after?.v4 ?? "");
  console.log(
    `  UNAPPROVED ${c.deviceName} (${c.userEmail})  ${c.after?.v4}  ${c.after?.v6}` +
      `  — ${z ? `${z.id} (${TRUST_LABEL[z.trust]})` : "?"}${seenColumn(c.deviceId)}`,
  );
}
for (const c of unapprovedOutside) {
  const z = zoneOf(loaded.zones ?? [], c.after?.v4 ?? "");
  console.log(
    `  unapproved, untrusted zone: ${c.deviceName} (${c.userEmail})  ${c.after?.v4}` +
      `  — ${z ? `${z.id} (${TRUST_LABEL[z.trust]})` : "no zone"}${seenColumn(c.deviceId)}`,
  );
}

if (has("--propose")) {
  // Every live registration, in the shape the registry file takes. Deliberately the whole set
  // rather than only the changes: a reviewer comparing two full blocks in a diff sees removals,
  // which a list of additions would hide.
  //
  // ## Two blocks, because JSON cannot carry the zone column
  //
  // This printed a TypeScript array until 2026-10-06 — `export const DEVICES: ApprovedDevice[] =
  // [ { deviceId: "…" } ]` — and the workflow told the operator that "the block printed above is
  // what to commit". It was not: the rows moved to `devices.json` (see `policy/dev.ts`, "The rows
  // moved to devices.json, and why") and the output did not follow, so what it printed could not be
  // pasted anywhere. Twice it was transcribed by hand instead, and the second time a `notes` field
  // was nearly lost in the process.
  //
  // So: the first block is the file, byte for byte, and the second is the zone column as a comment
  // table. The column cannot be merged into the first — JSON has no comments, and dropping it would
  // lose the thing a reviewer actually approves against: a device sitting in the lowest-trust zone
  // is one the site has said nothing about, and approving it into a rule scoped to the management
  // range is the mistake that annotation exists to make visible before the paste rather than after.
  const sorted = read.registrations
    .slice()
    .sort((a, b) => a.v4.localeCompare(b.v4, undefined, { numeric: true }));

  // 🔴 `notes` is not in Cloudflare — it is the argument an approval needed, and `ApprovedDevice`
  // declares it for exactly that ("Why this device is in policy at all"). Carried over by deviceId
  // from the rows already approved. Without this the block looks complete and silently deletes the
  // reasons; it came within one hand-transcription of happening.
  const notesById = new Map(
    (loaded.devices ?? [])
      .filter((d: { notes?: string }) => d.notes)
      .map((d: { deviceId: string; notes?: string }) => [d.deviceId, d.notes as string]),
  );

  const rows = sorted.map((r) => {
    const kept = notesById.get(r.deviceId);
    return {
      deviceId: r.deviceId,
      deviceName: r.deviceName,
      userEmail: r.userEmail,
      v4: r.v4,
      v6: r.v6,
      ...(kept ? { notes: kept } : {}),
    };
  });

  // `1` as a literal, and that is not laziness.
  //
  // It was `loaded.devicesSchemaVersion ?? 1` first, with a comment about not hard-coding a version
  // — and typechecking refused it, because `Site` carries no such field. Looking for where the
  // version actually lives found the answer: `policy/devices.ts` **refuses** anything but 1
  // ("devices.json must have schemaVersion 1 and a devices array"). So a file this command emits
  // can only ever be version 1; emitting what was loaded would be reading a value that cannot
  // differ, and the day it can differ this parser rejects it anyway. The constraint lives there.
  const doc = { schemaVersion: 1, devices: rows };

  console.log(`\n// read from Cloudflare at ${readAt} — review before approving`);
  console.log(`// paste this over policy/devices.json:`);
  console.log(JSON.stringify(doc, null, 2));

  const dropped = [...notesById.keys()].filter((id) => !sorted.some((r) => r.deviceId === id));
  if (dropped.length > 0) {
    // Said out loud rather than left to the diff. These rows are leaving, and their `notes` go with
    // them — that is correct when the device is gone, and worth seeing before the paste.
    console.log(`\n// ⚠️ leaving, and their notes go too: ${dropped.join(", ")}`);
  }

  console.log(`\n// zones — the column to approve against (not part of the file):`);
  for (const r of sorted) {
    const z = zoneOf(loaded.zones ?? [], r.v4);
    console.log(`//   ${r.v4.padEnd(15)} ${z ? `${z.id} (${TRUST_LABEL[z.trust]})` : "no zone"}`);
  }
}

// Only what policy could name decides the exit code. The rest is printed and does not gate — see
// the note on `inNamedZone`.
const differences = moved.length + gone.length + unapprovedInZone.length;
if (differences === 0) {
  console.log("every approved device still holds the address it was approved with");
  if (unapprovedOutside.length) {
    console.log(
      `${unapprovedOutside.length} unapproved registration(s) sit in an untrusted zone and are ` +
        `reported above without failing — no rule scoped to a trusted zone can name them`,
    );
  }
}
process.exit(differences ? 1 : 0);
