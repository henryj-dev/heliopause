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
import { fetchRegistrations, TruncatedRead, userRows } from "../src/cf-devices.ts";
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

for (const c of unapprovedInZone) {
  const z = zoneOf(loaded.zones ?? [], c.after?.v4 ?? "");
  console.log(
    `  UNAPPROVED ${c.deviceName} (${c.userEmail})  ${c.after?.v4}  ${c.after?.v6}` +
      `  — ${z ? `${z.id} (${TRUST_LABEL[z.trust]})` : "?"}`,
  );
}
for (const c of unapprovedOutside) {
  const z = zoneOf(loaded.zones ?? [], c.after?.v4 ?? "");
  console.log(
    `  unapproved, untrusted zone: ${c.deviceName} (${c.userEmail})  ${c.after?.v4}` +
      `  — ${z ? `${z.id} (${TRUST_LABEL[z.trust]})` : "no zone"}`,
  );
}

if (has("--propose")) {
  // Every live registration, in the shape the site module takes. Deliberately the whole set rather
  // than only the changes: a reviewer comparing two full blocks in a diff sees removals, which a
  // list of additions would hide.
  //
  // Each line carries the zone its address lands in. That is the column a reviewer approves
  // against: a device sitting in the lowest-trust zone is one the site has said nothing about, and
  // approving it into a rule scoped to the management range is the mistake this annotation exists
  // to make visible before it is pasted rather than after.
  const lines = read.registrations
    .slice()
    .sort((a, b) => a.v4.localeCompare(b.v4, undefined, { numeric: true }))
    .map((r) => {
      const z = zoneOf(loaded.zones ?? [], r.v4);
      const tag = z ? `${z.id} (${TRUST_LABEL[z.trust]})` : "no zone";
      return (
        `  { deviceId: ${JSON.stringify(r.deviceId)}, deviceName: ${JSON.stringify(r.deviceName)}, ` +
        `userEmail: ${JSON.stringify(r.userEmail)}, v4: ${JSON.stringify(r.v4)}, v6: ${JSON.stringify(r.v6)} },` +
        `  // ${tag}`
      );
    });
  console.log(`\n// read from Cloudflare at ${readAt} — review before approving\nexport const DEVICES: ApprovedDevice[] = [\n${lines.join("\n")}\n];`);
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
