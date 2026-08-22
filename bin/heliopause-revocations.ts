#!/usr/bin/env node
// The denylist's two operator actions: create one, and make room in one.
//
// Everything else about the list is machine-driven — the manager replicates revocations to each
// relay and the privilege-separated writer installs them, refusing any update that omits a row. Both
// commands here are things the writer deliberately cannot do.

import { readFileSync, writeFileSync } from "node:fs";
import {
  MAX_REVOCATION_ROWS,
  initializeRevocationSnapshot,
  parseRevocationSnapshot,
  planRevocationCompaction,
  serializeRevocationSnapshot,
} from "../src/revocation-snapshot.ts";
import { loadEnrollmentDocument } from "../src/enrollment-store.ts";
import { installCliLanguage } from "../src/operator-i18n.ts";

installCliLanguage();

const argv = process.argv.slice(2);
const [command, path] = argv;
const flag = (name: string): string | undefined => {
  const hit = argv.find((a) => a.startsWith(`${name}=`));
  return hit ? hit.slice(name.length + 1) : undefined;
};

const usage = [
  "usage:",
  "  heliopause-revocations init <relay-revocations.json>",
  "  heliopause-revocations compact <relay-revocations.json> --enrollment=<store.json> [--apply]",
  "",
  "`compact` drops revocations whose certificate has already expired, which is the only way to make",
  "room in a list the writer will never let shrink. It reports and changes nothing without --apply.",
].join("\n");

/**
 * Which certificates the enrollment store can date.
 *
 * Only signed requests carry both a fingerprint and a `notAfter`, which is exactly the set that can
 * be proved expired. Anything else stays in the denylist forever — see `RevocationCompaction.unknown`.
 */
function expiryIndex(storeFile: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const row of loadEnrollmentDocument(storeFile).requests) {
    if (row.certificateSha256 && row.certificateNotAfter) out.set(row.certificateSha256, row.certificateNotAfter);
  }
  return out;
}

try {
  if (command === "init" && path) {
    // The denylist is not a secret. Mode 0644 lets relay read it, while only the separate locked
    // writer account owns the parent directory needed for atomic replacement.
    await initializeRevocationSnapshot(path, undefined, { mode: 0o644 });
    console.log(`initialized empty revocation denylist at ${path}`);
  } else if (command === "compact" && path) {
    const store = flag("--enrollment");
    if (!store) throw new Error(usage);
    const snapshot = parseRevocationSnapshot(JSON.parse(readFileSync(path, "utf8")));
    const plan = planRevocationCompaction(snapshot, expiryIndex(store), new Date());

    console.log(`${snapshot.revocations.length} revocation(s), cap ${MAX_REVOCATION_ROWS}`);
    console.log(`  ${plan.drop.length} expired and droppable`);
    console.log(`  ${plan.unknown.length} not dated by this enrollment store — kept`);
    console.log(`  ${plan.keep.length} would remain`);
    for (const { row, notAfter } of plan.drop) {
      console.log(`    drop ${row.fingerprint256.slice(0, 16)}… ${row.subject ?? "(no subject)"} expired ${notAfter}`);
    }

    if (!argv.includes("--apply")) {
      console.log("\nnothing written. Re-run with --apply once the list above is what you expect.");
    } else if (plan.drop.length === 0) {
      console.log("\nnothing to drop.");
    } else {
      // ## Written directly, and that is the whole point
      //
      // The writer socket refuses a snapshot that omits a row — that refusal is what stops a
      // compromised publisher from un-revoking a credential, and it must not have an exception. So
      // compaction does not go through it: an operator stops the writer, runs this, and starts it
      // again. Doing it any other way would mean building the bypass into the thing being bypassed.
      writeFileSync(path, serializeRevocationSnapshot({ schemaVersion: 1, revocations: plan.keep }), { mode: 0o644 });
      console.log(`\nwrote ${plan.keep.length} revocation(s) to ${path}`);
      console.log("the writer must be stopped while this runs, and restarted after.");
    }
  } else {
    throw new Error(usage);
  }
} catch (error) {
  console.error((error as Error).message);
  process.exitCode = 2;
}
