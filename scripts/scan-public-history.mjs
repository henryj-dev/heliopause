#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readlinkSync } from "node:fs";
import { isIP } from "node:net";

const args = process.argv.slice(2);
const has = (flag) => args.includes(flag);
const value = (flag) => {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
};
const git = (argv, encoding = "utf8") => execFileSync("git", argv, {
  encoding,
  maxBuffer: 64 * 1024 * 1024,
  stdio: ["ignore", "pipe", "pipe"],
});

const allowedV4 = ([a, b, c]) =>
  a === 10 || a === 127 || a === 0 || a >= 224 ||
  (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
  (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
  (a === 192 && b === 0 && [0, 2].includes(c)) ||
  (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113);

const allowedV6 = (address) => {
  const value = address.toLowerCase();
  return value === "::" || value === "::1" || value === "::ffff" ||
    /^2001:0?db8:/.test(value) ||
    /^f[cd][0-9a-f]{2}:/.test(value) || /^fe[89ab][0-9a-f]:/.test(value) || /^ff[0-9a-f]{2}:/.test(value);
};
const V6_GLOBAL_UNICAST_FLOOR = ["2000", "::"].join("");

let hostnamePattern = null;
if (process.env.HELIOPAUSE_SITE_HOSTNAME_PATTERN) {
  try { hostnamePattern = new RegExp(process.env.HELIOPAUSE_SITE_HOSTNAME_PATTERN, "i"); }
  catch { throw new Error("HELIOPAUSE_SITE_HOSTNAME_PATTERN is not a valid regular expression"); }
} else if (has("--require-hostname-pattern")) {
  throw new Error("HELIOPAUSE_SITE_HOSTNAME_PATTERN is required for the site-hostname scan");
}

const findings = new Set();
const sourcePath = (label) => label.replace(/^worktree:/, "").replace(/^[0-9a-f]{12}:/, "");
const safeSource = (label) => {
  const commit = /^([0-9a-f]{12}):/.exec(label)?.[1];
  const opaque = createHash("sha256").update(sourcePath(label)).digest("hex").slice(0, 12);
  return `${commit ? `commit ${commit} ` : ""}source ${opaque}`;
};
const finding = (label, message) => findings.add(`${safeSource(label)} ${message}`);
function scan(content, label) {
  // Credential scanners commonly skip binary blobs. A path naming a portable key container is
  // itself enough to refuse the commit even when NUL bytes prevent safe text inspection.
  if (/\.(?:p12|pfx|pkcs12|jks|keystore|kdb|kdbx|mobileprovision)$/i.test(sourcePath(label))) {
    finding(label, "contains a forbidden binary credential container");
  }
  if (content.includes("\0")) {
    // DER and PKCS#8 private keys are often committed with generic crypto extensions. Public
    // certificates are not secrets, but there is no reliable bounded parser here that can prove a
    // binary blob contains only a certificate, so fail closed on tracked binary key material.
    if (/\.(?:der|key|pem|pk8|p8)$/i.test(sourcePath(label))) {
      finding(label, "contains forbidden binary key material");
    }
    // A NUL byte must not become a universal scanner bypass. This repository is source and
    // deployment text; opaque artifacts belong in a separately scanned release store. Refusing all
    // tracked binary blobs is the only bounded policy that does not pretend a ZIP/PDF/unknown blob
    // was inspected for embedded inventory or credentials.
    finding(label, "contains an unreviewable binary blob");
    return;
  }

  for (const match of content.matchAll(/(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])/g)) {
    const parts = match[0].split(".").map(Number);
    if (parts.some((part) => part > 255) || allowedV4(parts)) continue;
    // An ASN.1 object identifier is a dotted sequence of small integers and is therefore a
    // syntactically perfect IPv4 address. `OID 1.3.101.112` — Ed25519 — sat in a comment in
    // `agent/heliopause-pull.py` and failed this scan on **every** commit in range, which meant CI
    // was red on a false positive while the image built and shipped anyway. A check that cries wolf
    // on a constant is a check people learn to merge past, which is worse than not having it.
    //
    // **The `$` is the mechanism, not the window.** `\boid\b[\s:=]*$` demands the word immediately
    // before the number, so a stray "OID" three lines up cannot excuse a real address; the 24-char
    // slice is only a bound so this does not re-read the whole file per match. Dropping the anchor
    // fails `history-leak-scan.test.ts`; changing the 24 does not, and should not.
    const lead = content.slice(Math.max(0, (match.index ?? 0) - 24), match.index ?? 0);
    if (/\boid\b[\s:=]*$/i.test(lead)) continue;
    finding(label, "contains a non-documentation IPv4 address");
  }

  for (const match of content.matchAll(/(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])/gi)) {
    const address = match[0];
    const end = (match.index ?? 0) + address.length;
    // Do not reinterpret the IPv6-looking prefix of an embedded dotted IPv4 address. The complete
    // IPv4 portion is checked by the IPv4 scanner above; nft deliberately rejects this syntax too.
    if (content[end] === "." && /[0-9]/.test(content[end + 1] ?? "")) continue;
    // CSS `::backdrop` matches as the IPv6 of its first three hex letters, and
    // `isIP` reports 6 for that prefix, so the address check cannot tell them
    // apart. The next character being a letter or hyphen is the identifier
    // continuing — the same shape as `::before` / `::file-selector-button`.
    // The same prefix written as a complete address still fails.
    //
    // This sat in `RuleEditModal.svelte` and failed every introduced commit, which
    // is how a check becomes something people merge past. See the OID case above.
    if (/[a-z-]/i.test(content[end] ?? "")) continue;
    // `geofeed.test.ts` deliberately checks the IANA global-unicast prefix floor. Only the complete
    // network literal is a known positive; the same address without exactly `/12` is still a leak.
    const isGlobalUnicastFloor = address.toLowerCase() === V6_GLOBAL_UNICAST_FLOOR
      && content.slice(end, end + 3) === "/12" && !/[0-9]/.test(content[end + 3] ?? "");
    if (isGlobalUnicastFloor) continue;
    if (isIP(address) !== 6 || allowedV6(address)) continue;
    finding(label, "contains a non-documentation IPv6 address");
  }

  if (hostnamePattern && hostnamePattern.test(content)) {
    hostnamePattern.lastIndex = 0;
    finding(label, "contains a configured private-site hostname");
  }

  // Gitleaks is the broad credential scanner. This cheap local guard makes the most catastrophic
  // class fail even when the external action is unavailable, without putting the matching header
  // into one contiguous string that would make this script flag itself.
  const privateKeyHeader = new RegExp(["-----BEGIN (?:[A-Z0-9 ]+ )?", "PRIVATE KEY-----"].join(""));
  if (privateKeyHeader.test(content)) finding(label, "contains private-key material");
}

function worktreeFiles() {
  const deleted = new Set(String(git(["ls-files", "-z", "--deleted"])).split("\0").filter(Boolean));
  const paths = String(git(["ls-files", "-z", "--cached", "--others", "--exclude-standard"]))
    .split("\0").filter((path) => path && !deleted.has(path));
  return paths.map((path) => {
    try {
      // Do not follow a candidate symlink outside the repository while doing a local pre-commit
      // scan. Git history stores only the link target string, so scanning that string also matches
      // what the history mode will inspect after commit.
      const content = lstatSync(path).isSymbolicLink() ? readlinkSync(path) : readFileSync(path, "utf8");
      return { label: `worktree:${path}`, content };
    }
    catch {
      finding(`worktree:${path}`, "could not be read");
      return null;
    }
  }).filter(Boolean);
}

function historyFiles() {
  const head = value("--head") ?? "HEAD";
  let base = value("--base");
  if (!base || /^0+$/.test(base)) {
    const branch = value("--default-branch");
    if (branch) {
      try { base = String(git(["merge-base", head, `origin/${branch}`])).trim(); }
      catch { base = undefined; }
    }
  }

  let commits;
  if (has("--all")) commits = String(git(["rev-list", "--reverse", "--all"])).trim().split("\n").filter(Boolean);
  else if (base) commits = String(git(["rev-list", "--reverse", `${base}..${head}`])).trim().split("\n").filter(Boolean);
  else commits = [String(git(["rev-parse", head])).trim()];
  if (commits.length === 0) commits = [String(git(["rev-parse", head])).trim()];

  const files = [];
  for (const commit of commits) {
    const entries = String(git(["ls-tree", "-r", "-z", commit])).split("\0").filter(Boolean);
    for (const entry of entries) {
      const headerEnd = entry.indexOf("\t");
      const header = entry.slice(0, headerEnd);
      const path = entry.slice(headerEnd + 1);
      const match = /^[0-7]{6} blob ([0-9a-f]{40,64})$/.exec(header);
      if (!match) continue;
      // Read by validated object id, not `commit:path`: an adversarial path can contain newlines,
      // ANSI controls, or workflow-command-looking text and must never reach a failing command's
      // stderr. Candidate paths are used only as input to the one-way label hash below.
      const buffer = git(["cat-file", "blob", match[1]], null);
      files.push({ label: `${commit.slice(0, 12)}:${path}`, content: buffer.toString("utf8") });
    }
  }
  return files;
}

for (const file of has("--worktree") ? worktreeFiles() : historyFiles()) scan(file.content, file.label);

if (findings.size) {
  for (const finding of findings) console.error(`ERROR: ${finding}`);
  console.error(`refusing ${findings.size} potential site-data/credential leak(s); values are intentionally redacted`);
  process.exitCode = 1;
} else {
  console.log(`site-data scan passed (${has("--worktree") ? "worktree" : "introduced commit history"})`);
}
