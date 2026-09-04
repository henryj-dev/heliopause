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

// The two ranges IANA reserved so text can show an address: `2001:db8::/32` (RFC 3849) and
// `3fff::/20` (RFC 9637). The second exists because the first is visibly not a real address, so
// documentation that has to demonstrate a *global unicast* prefix has nowhere else to go — which is
// exactly the shape a geofeed known-positive needs. Neither can be site data.
const documentationV6 = (value) => {
  if (/^2001:0?db8:/.test(value)) return true;
  // `/20`, not `/16` — the second hextet's top nibble must be zero. A four-digit second hextet is
  // outside the range and is refused; the literal lives in `history-leak-scan.test.ts`, because
  // naming a forbidden address here makes this file refuse itself.
  const m = /^3fff:([0-9a-f]{1,4})?(?::|$)/.exec(value);
  return !!m && parseInt(m[1] ?? "0", 16) <= 0x0fff;
};

// ## IPv4 inside IPv6, written in hex
//
// The dotted spelling (`::ffff:10.0.0.1`) is skipped by the v6 loop below on purpose and checked by
// the v4 scanner instead. The hex spelling of the same address (`::ffff:a00:1`) was refused
// unconditionally — so one value passed in one notation and failed in the other, and the comment in
// `geofeed.ts` explaining that very bypass could not be committed. Three commits went red on it.
//
// In `::ffff:0:0/96` (IPv4-mapped), `64:ff9b::/96` (NAT64) and `::/96` (the deprecated
// IPv4-compatible range) the last 32 bits *are* an IPv4 address, by definition. Decoding them and
// asking `allowedV4` gives both spellings the same answer.
//
// This is not a hole. The payload is handed to `allowedV4` unchanged, so a mapped address whose
// last 32 bits are public still fails — `history-leak-scan.test.ts` pins that direction with the
// literal assembled at runtime, because this file cannot both name a forbidden address and forbid
// it. (It cannot: writing the counter-example here made the scanner refuse itself.) And none of
// these three prefixes can carry a global address a site is actually reachable at.
const embeddedV4 = (value) => {
  const m = /^(?:::ffff:|64:ff9b::|::)(?:([0-9a-f]{1,4}):([0-9a-f]{1,4}))?$/.exec(value);
  if (!m) return null;
  const hi = parseInt(m[1] ?? "0", 16);
  const lo = parseInt(m[2] ?? "0", 16);
  return [hi >>> 8, hi & 255, lo >>> 8, lo & 255];
};

const allowedV6 = (address) => {
  const value = address.toLowerCase();
  if (value === "::" || value === "::1" || value === "::ffff") return true;
  if (documentationV6(value)) return true;
  if (/^f[cd][0-9a-f]{2}:/.test(value) || /^fe[89ab][0-9a-f]:/.test(value) || /^ff[0-9a-f]{2}:/.test(value)) {
    return true;
  }
  const v4 = embeddedV4(value);
  return v4 !== null && allowedV4(v4);
};
const V6_GLOBAL_UNICAST_FLOOR = ["2000", "::"].join("");

let hostnamePattern = null;
if (process.env.HELIOPAUSE_SITE_HOSTNAME_PATTERN) {
  try { hostnamePattern = new RegExp(process.env.HELIOPAUSE_SITE_HOSTNAME_PATTERN, "i"); }
  catch { throw new Error("HELIOPAUSE_SITE_HOSTNAME_PATTERN is not a valid regular expression"); }
} else if (has("--require-hostname-pattern")) {
  throw new Error("HELIOPAUSE_SITE_HOSTNAME_PATTERN is required for the site-hostname scan");
}

// ── Accepted findings in history ──────────────────────────────────────────────
//
// 🔴 **Why this exists, and why it is keyed by blob rather than by commit.**
//
// The scanner had no way to accept a finding, and history is immutable, so one false positive in a
// merged commit made `--all` fail for ever. That is not hypothetical: `trusted-leaks.yml`'s weekly
// full-history run failed on **every scheduled run it ever had** (2026-08-25 and 2026-09-01) on
// three files whose literals were rewritten by `aa2efae` — "누출 스캐너가 결함을 설명하는 글을
// 막고 있었다". The tree was fixed; the blobs stayed. The pull-request gate only reads introduced
// commits, so it went on passing, and the one scan that reads the whole public history — the half
// `ci.yml` calls authoritative — was a red light nobody could turn off.
//
// An alarm that can never be cleared is an alarm that stops being read. `.gitleaksignore` exists in
// this repository for exactly this reason and says so in its own header: *"removing a literal from
// the tree leaves the blob in history and the finding stands."* The site-data axis had no
// equivalent. This is it.
//
// **Keyed by blob id**, not by commit: one blob appears in every commit whose tree contains it, so
// a commit-keyed entry would need one line per commit and would grow with every merge. Ten findings
// in that failing run were three blobs.
//
// ⚠️ An entry is only ever appropriate for a value that was **never sensitive**. If something
// genuinely secret is committed, the answer is rotation plus the history work SECURITY.md
// describes — never a line here. The reason comment above each entry has to establish which it is.
// 🔴 **It must be possible to read this from somewhere other than the working directory, and in
// `trusted-leaks.yml` it must be.** That workflow runs the scanner with the *candidate's* checkout
// as the working directory, on purpose — the candidate is inert Git objects and the code executing
// is the copy from the protected default branch. If the allowlist were read from the candidate's
// tree, a pull request could **ship a leak and accept it in the same commit**, which is the one
// thing this whole trusted-checkout arrangement exists to prevent.
//
// So the path is an input. It defaults to the working directory, which is right for a local
// `--worktree` run and for `ci.yml` (where the checkout *is* the repository); `trusted-leaks.yml`
// passes the trusted copy explicitly.
const IGNORE_FILE = value("--ignore-file") ?? ".heliopause-scanignore";
/** blobSha -> Set(finding class), plus a record of which entries actually matched. */
const accepted = new Map();
const acceptedUsed = new Set();
const acceptedLines = new Map();
try {
  const text = readFileSync(IGNORE_FILE, "utf8");
  text.split("\n").forEach((raw, i) => {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) return;
    const m = /^([0-9a-f]{40,64}):(.+)$/.exec(line);
    if (!m) throw new Error(`${IGNORE_FILE}:${i + 1}: expected "<blob-sha>:<finding class>", got ${JSON.stringify(raw.trim())}`);
    const [, blob, cls] = m;
    if (!accepted.has(blob)) accepted.set(blob, new Set());
    accepted.get(blob).add(cls.trim());
    acceptedLines.set(`${blob}:${cls.trim()}`, i + 1);
  });
} catch (e) {
  // A missing file is fine — most repositories will never need one. A malformed file is not: an
  // unreadable allowlist that is silently treated as empty would turn a suppressed finding back
  // into a failure with no explanation, and the reverse mistake (silently accepting everything) is
  // worse still. Fail loudly on anything but ENOENT.
  if (e?.code !== "ENOENT") throw e;
}

const findings = new Set();
const sourcePath = (label) => label.replace(/^worktree:/, "").replace(/^[0-9a-f]{12}:/, "");
const safeSource = (label) => {
  const commit = /^([0-9a-f]{12}):/.exec(label)?.[1];
  const opaque = createHash("sha256").update(sourcePath(label)).digest("hex").slice(0, 12);
  return `${commit ? `commit ${commit} ` : ""}source ${opaque}`;
};
/**
 * The blob currently being scanned, or null in worktree mode.
 *
 * Worktree findings are deliberately **not** suppressible. There the file is in front of you and
 * the fix is to change it; an allowlist entry would only be a way to ship the thing the scan is
 * for. Only history — which cannot be changed — can be accepted.
 */
let currentBlob = null;
/**
 * Ready-to-paste allowlist lines for whatever this run refused, printed by `--print-accept-lines`.
 *
 * Maintaining a blob-keyed file by hand would otherwise mean reversing a redacted `source` hash
 * back to a path and then finding the object id — a puzzle, and puzzles are how allowlists end up
 * with entries nobody can justify. This prints only object ids and finding classes, never a
 * matched value, so it respects the same redaction boundary as the failure output.
 */
const suggestions = new Set();
const finding = (label, message) => {
  if (currentBlob && accepted.get(currentBlob)?.has(message)) {
    acceptedUsed.add(`${currentBlob}:${message}`);
    return;
  }
  if (currentBlob) suggestions.add(`${currentBlob}:${message}`);
  findings.add(`${safeSource(label)} ${message}`);
};
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

function* historyFiles() {
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

  // 🔴 **Yielded, not collected.** This built an array of every blob's *decoded text* across every
  // commit in range and returned it. For a range of a few commits that is fine; for `--all` it is
  // the entire public history resident at once, and the process is killed before it reports
  // anything — measured twice on this repository, both runs OOM-killed after several minutes.
  //
  // That mattered more than it looks: `--all` is the mode `trusted-leaks.yml` runs weekly and the
  // one `ci.yml` calls authoritative. A scan that cannot finish is a scan that is not happening,
  // and "killed" and "still running" look the same from outside.
  //
  // A generator scans each blob and lets it go. Nothing else changes — `scan()` never needed more
  // than one file at a time, and `findings` is a Set of short strings.
  //
  // The same blob is re-read once per commit that contains it, which is wasteful but not the
  // problem being solved here; deduplicating would change which commit a finding is reported
  // against, and that attribution is what makes a finding traceable.
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
      // The blob id travels with the content so a finding can be accepted per blob — see
      // `IGNORE_FILE`. It is the object's own name, so it is stable across every commit that
      // carries these bytes and across a rename that does not change them.
      yield { label: `${commit.slice(0, 12)}:${path}`, content: buffer.toString("utf8"), blob: match[1] };
    }
  }
}

for (const file of has("--worktree") ? worktreeFiles() : historyFiles()) {
  currentBlob = file.blob ?? null;
  scan(file.content, file.label);
}
currentBlob = null;

// Stale entries, but only where "stale" can be established. `--all` walks every reachable object,
// so an entry that matched nothing there names a blob that is gone or a class that no longer
// fires — dead weight that will be read as documentation of a real exception by the next person.
// A pull-request scan sees a slice of history and cannot tell the difference, so it says nothing.
if (has("--all")) {
  const stale = [...acceptedLines.keys()].filter((k) => !acceptedUsed.has(k));
  if (stale.length) {
    for (const k of stale) {
      console.error(`ERROR: ${IGNORE_FILE}:${acceptedLines.get(k)} matched nothing in full history — remove it`);
    }
    console.error(`${stale.length} stale allowlist entr(y|ies); an exception nobody can trace is not an exception`);
    process.exitCode = 1;
  }
}

if (findings.size) {
  for (const finding of findings) console.error(`ERROR: ${finding}`);
  console.error(`refusing ${findings.size} potential site-data/credential leak(s); values are intentionally redacted`);
  if (has("--print-accept-lines")) {
    console.error(`\n# Candidate ${IGNORE_FILE} entries for the refusals above.`);
    console.error(`# ⚠️ Do not paste these without establishing, one at a time, that the value was`);
    console.error(`#    never sensitive. A real secret is rotated, not accepted — see SECURITY.md.`);
    for (const line of [...suggestions].sort()) console.error(line);
  }
  process.exitCode = 1;
} else if (!process.exitCode) {
  const scope = has("--worktree") ? "worktree" : has("--all") ? "all reachable history" : "introduced commit history";
  const note = acceptedUsed.size ? `, ${acceptedUsed.size} accepted by ${IGNORE_FILE}` : "";
  console.log(`site-data scan passed (${scope}${note})`);
}
