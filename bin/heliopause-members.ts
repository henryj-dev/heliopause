#!/usr/bin/env node
/**
 * Direct-file access to the member store, for bootstrap and break-glass. Whoever can run this can
 * write the store file; there is no other check here. Audit rows written by it carry actor "cli".
 */
import { execFileSync } from "node:child_process";
import { closeSync, openSync, readSync, writeSync } from "node:fs";
import { isatty } from "node:tty";
import { parsePairs } from "../src/env-spec.ts";
import {
  createMember, findByUsername, initializeMemberDocument, loadMemberDocument, normalizeEmail, normalizeMemberName,
  passwordCredential, recordAudit, setPassword, suspendMember, unsuspendMember, withMemberTransaction, type MemberContext,
} from "../src/member-store.ts";
import { installCliLanguage } from "../src/operator-i18n.ts";
import { checkPasswordPolicy, hashPassword } from "../src/password.ts";

installCliLanguage();

const usage = `usage:
  heliopause-members init --store <members.json>
  heliopause-members create-admin --store <members.json> --username NAME --email ADDRESS [--principal-name NAME] [--otp-user-id ID]
  heliopause-members list --store <members.json> [--json]
  heliopause-members reset-password --store <members.json> --username NAME [--no-must-change] [--break-glass]
  heliopause-members suspend --store <members.json> --username NAME [--break-glass]
  heliopause-members unsuspend --store <members.json> --username NAME [--break-glass]
  heliopause-members import --dry-run

Passwords are read from the terminal without echo, or from stdin when it is not a terminal.
import reads HELIOPAUSE_OPERATOR_CNS, HELIOPAUSE_WRITER_CNS, HELIOPAUSE_OIDC_ALIASES and
HELIOPAUSE_OTP_USERS and prints a draft; it never writes a file.
A writer or admin signs in to the console with a one-time code checked against --otp-user-id
(the KeyStone user id); without one the manager refuses that member's sign-in.
--break-glass skips the "last admin who can sign in" rule (never the "last active admin" rule) and
records a member.break-glass audit row.`;

/** The flags each command accepts; anything else is refused. */
const COMMAND_FLAGS: Record<string, readonly string[]> = {
  "init": ["store"],
  "create-admin": ["store", "username", "email", "principal-name", "otp-user-id"],
  "list": ["store", "json"],
  "reset-password": ["store", "username", "no-must-change", "break-glass"],
  "suspend": ["store", "username", "break-glass"],
  "unsuspend": ["store", "username", "break-glass"],
  "import": ["dry-run"],
};
const BOOLEAN_FLAGS = new Set(["json", "dry-run", "no-must-change", "break-glass", "help"]);
const [command, ...rest] = process.argv.slice(2);
const flags = new Map<string, string>();
function usageError(message: string): Error { return Object.assign(new Error(`${message}\n${usage}`), { exitCode: 64 }); }
function parseFlags(allowed: readonly string[]): void {
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i]!;
    if (!arg.startsWith("--")) throw usageError(`unexpected argument ${JSON.stringify(arg)}`);
    const eq = arg.indexOf("=");
    const key = eq < 0 ? arg.slice(2) : arg.slice(2, eq);
    if (!allowed.includes(key)) throw usageError(`unknown flag --${key} for ${command}`);
    if (eq >= 0 && BOOLEAN_FLAGS.has(key)) throw usageError(`--${key} takes no value`);
    if (eq >= 0) flags.set(key, arg.slice(eq + 1));
    else if (BOOLEAN_FLAGS.has(key)) flags.set(key, "true");
    else if (i + 1 < rest.length) flags.set(key, rest[++i]!);
    else throw usageError(`--${key} needs a value`);
  }
}
function required(name: string): string {
  const value = flags.get(name);
  if (!value) throw usageError(`--${name} is required`);
  return value;
}
const ctx: MemberContext = { actor: "cli" };
/** `ctx`, with the break-glass bypass when the flag was given. */
const glassCtx = (): MemberContext => (flags.has("break-glass") ? { ...ctx, breakGlass: true } : ctx);
/** With --break-glass, the audit row that says so, in the same transaction as the change. */
function breakGlass(document: Parameters<typeof recordAudit>[0], memberId: string): void {
  if (flags.has("break-glass")) recordAudit(document, ctx, "member.break-glass", `${command}:${memberId}`);
}
const WAIT = new Int32Array(new SharedArrayBuffer(4));

/** All of non-terminal stdin, minus one trailing newline. Retries EAGAIN on a non-blocking fd. */
function readPipe(): string {
  const chunks: Buffer[] = []; const buffer = Buffer.alloc(4096);
  for (;;) {
    let n: number;
    try { n = readSync(0, buffer, 0, buffer.length, null); } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EAGAIN") { Atomics.wait(WAIT, 0, 0, 10); continue; }
      if (code === "EOF") break;
      throw error;
    }
    if (n === 0) break;
    chunks.push(Buffer.from(buffer.subarray(0, n)));
  }
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

/**
 * One line from `/dev/tty`, opened here so the read blocks, with echo, canonical mode and signal
 * keys turned off through `stty` and restored afterwards. Enter ends the line; backspace removes
 * one UTF-8 character; Ctrl-C and Ctrl-D abort; an escape sequence (ESC [ … final byte, ESC O x,
 * or ESC x) is discarded; other control bytes are ignored.
 *
 * Restoring the terminal happens in `finally`, so it does not run when the process is killed by a
 * signal (SIGTERM, SIGHUP) during the blocking read: the terminal is then left without echo.
 * `stty sane` recovers it.
 * @see members-cli.test.ts "reads the password from a terminal"
 */
function readTerminal(prompt: string): string {
  const fd = openSync("/dev/tty", "r+");
  const stty = (args: string[]): string => execFileSync("stty", args, { stdio: [fd, "pipe", "inherit"], encoding: "utf8" });
  const saved = stty(["-g"]).trim();
  const bytes: number[] = [];
  let failed = false;
  try {
    stty(["-echo", "-icanon", "-isig", "min", "1", "time", "0"]);
    writeSync(fd, prompt);
    const one = Buffer.alloc(1);
    // 0: text, 1: after ESC, 2: inside CSI (ESC [), 3: after ESC O (one more byte).
    let escape = 0;
    for (;;) {
      if (readSync(fd, one, 0, 1, null) === 0) throw new Error("input ended");
      const c = one[0]!;
      if (c === 0x03) throw new Error("interrupted");
      if (c === 0x04) throw new Error("input ended");
      if (escape === 1) { escape = c === 0x5b ? 2 : c === 0x4f ? 3 : 0; continue; }
      if (escape === 2) { if (c >= 0x40 && c <= 0x7e) escape = 0; continue; }
      if (escape === 3) { escape = 0; continue; }
      if (c === 0x1b) { escape = 1; continue; }
      if (c === 0x0d || c === 0x0a) break;
      if (c === 0x7f || c === 0x08) {
        while (bytes.length > 0 && (bytes[bytes.length - 1]! & 0xc0) === 0x80) bytes.pop();
        bytes.pop();
        continue;
      }
      if (c < 0x20) continue;
      bytes.push(c);
    }
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    // A restore failure is reported only when nothing else failed, so it never hides the reason.
    try {
      stty([saved]);
    } catch (restoreError) {
      if (!failed) throw restoreError;
    } finally {
      try { writeSync(fd, "\n"); } finally { closeSync(fd); }
    }
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bytes));
}

async function newPasswordHash(): Promise<string> {
  const terminal = isatty(0);
  const password = terminal ? readTerminal("new password: ") : readPipe();
  if (terminal && readTerminal("repeat: ") !== password) throw new Error("passwords do not match");
  const problems = checkPasswordPolicy(password);
  if (problems.length > 0) throw new Error(`password refused: ${problems.join("; ")}`);
  return hashPassword(password);
}

function memberFor(store: string, username: string) {
  const member = findByUsername(loadMemberDocument(store), username);
  if (!member) throw new Error(`no member named ${username}`);
  return member;
}

/** Proposed members from the current certificate/OIDC/OTP environment. Nothing is written. */
function importDraft(): unknown {
  const list = (name: string): string[] => (process.env[name] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const operators = list("HELIOPAUSE_OPERATOR_CNS");
  const writers = list("HELIOPAUSE_WRITER_CNS");
  const aliases = parsePairs(process.env.HELIOPAUSE_OIDC_ALIASES ?? "", "HELIOPAUSE_OIDC_ALIASES");
  const otpUsers = parsePairs(process.env.HELIOPAUSE_OTP_USERS ?? "", "HELIOPAUSE_OTP_USERS");
  const notes: string[] = [];
  const cns = [...new Set([...operators, ...writers])];
  for (const cn of writers) if (!operators.includes(cn)) notes.push(`${cn} is a writer but not an operator; the manager refuses that configuration`);
  const members = cns.map((cn) => {
    let username: string | null = null;
    try { username = normalizeMemberName(cn); } catch { notes.push(`${cn}: not a valid username; choose one by hand`); }
    const aliasKeys = [...aliases].filter(([, value]) => value === cn).map(([key]) => key);
    const emails = aliasKeys.filter((key) => key.includes("@")).flatMap((key) => {
      try { return [normalizeEmail(key)]; } catch { return []; }
    });
    if (emails.length > 1) notes.push(`${cn}: several alias email addresses; pick one`);
    return {
      username, principalName: username, certCNs: [cn],
      roles: writers.includes(cn) ? ["reader", "writer"] : ["reader"],
      email: emails[0] ?? null,
      // Whether HELIOPAUSE_OTP_USERS maps this CN; the KeyStone id itself is not printed.
      otpUser: otpUsers.has(cn),
      // OIDC alias keys are an email, username or subject without an issuer. They cannot become
      // identity links; the member links the SSO account by signing in.
      oidcAliasKeys: aliasKeys,
    };
  });
  for (const [key, cn] of aliases) if (!cns.includes(cn)) notes.push(`alias ${key} names ${cn}, which is not an allowed CN`);
  for (const cn of otpUsers.keys()) if (!cns.includes(cn)) notes.push(`an OTP user entry names ${cn}, which is not an allowed CN`);
  notes.push("no member is marked admin: choose the admin by hand");
  return { dryRun: true, members, notes };
}

try {
  if (rest.includes("--help") || command === "--help") {
    console.log(usage);
  } else {
    if (!command) throw usageError("");
    const allowed = COMMAND_FLAGS[command];
    if (!allowed) throw usageError(`unknown command ${command}`);
    parseFlags(allowed);
    if (command === "import") {
      if (!flags.has("dry-run")) throw usageError("import only supports --dry-run");
      console.log(JSON.stringify(importDraft(), null, 2));
    } else {
      const store = required("store");
      if (command === "init") {
        initializeMemberDocument(store); console.log(`created ${store}`);
      } else if (command === "create-admin") {
        const input = {
          username: required("username"), principalName: flags.get("principal-name") ?? required("username"),
          email: required("email"), emailVerified: true, status: "active" as const, roles: ["reader", "writer", "admin"],
          otpUserId: flags.get("otp-user-id") ?? null,
        };
        // Run the same creation on a copy first, so a taken name or email is refused before the prompt.
        const preview = createMember(loadMemberDocument(store), input, ctx);
        const hash = await newPasswordHash();
        const member = withMemberTransaction(store, (document) => {
          const created = createMember(document, input, ctx);
          setPassword(document, created.id, hash, { mustChange: false }, ctx);
          return created;
        });
        console.log(`created admin ${member.username} (${member.id})`);
      } else if (command === "list") {
        const document = loadMemberDocument(store);
        const rows = document.members.map((m) => ({
          id: m.id, username: m.username, principalName: m.principalName, status: m.status, roles: m.roles,
          hasCredential: passwordCredential(document, m.id) !== null,
          identities: document.identities.filter((i) => i.memberId === m.id).length,
        }));
        if (flags.has("json")) console.log(JSON.stringify({ members: rows }, null, 2));
        else for (const r of rows) console.log(`${r.id}\t${r.username}\t${r.principalName}\t${r.status}\t${r.roles.join(",")}\tcredential=${r.hasCredential}\tidentities=${r.identities}`);
      } else if (command === "reset-password") {
        const member = memberFor(store, required("username"));
        if (member.status === "deleted") throw new Error(`member ${member.username} is deleted`);
        const hash = await newPasswordHash();
        withMemberTransaction(store, (document) => {
          breakGlass(document, member.id);
          setPassword(document, member.id, hash, { mustChange: !flags.has("no-must-change") }, glassCtx());
        });
        console.log(`password reset for ${member.username}`);
      } else {
        const id = memberFor(store, required("username")).id;
        const member = withMemberTransaction(store, (document) => {
          breakGlass(document, id);
          return (command === "suspend" ? suspendMember : unsuspendMember)(document, id, glassCtx());
        });
        console.log(`${member.username} is ${member.status}`);
      }
    }
  }
} catch (error) {
  console.error((error as Error).message.trim());
  process.exitCode = (error as { exitCode?: number }).exitCode ?? 2;
}
