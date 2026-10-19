// Minimal SMTP submission client: implicit TLS only, one recipient, text/plain, no dependencies.
//
// What this module does and does not do, so a reader does not have to infer it:
//  - It speaks to ONE relay over TLS from the first byte (port 465 style). There is no STARTTLS and
//    no plaintext path; `sendMail` refuses a config that asks for either.
//  - Certificates are always verified (`rejectUnauthorized: true`). A private relay is trusted by
//    handing in its CA as `ca`, never by switching verification off.
//  - The body is always sent as base64 (Content-Transfer-Encoding: base64). That keeps every line
//    short and ASCII, so the server's 8BITMIME advertisement is irrelevant and is not read.
//  - Every reply is bounded (64 KiB, 100 lines) and every wait is bounded (per step and overall).
//  - Errors carry the step and the numeric reply code only. Server text, credentials and the
//    message are never put in an error.
//
// Tests: src/mail.test.ts names each of these properties.
import { connect as tlsConnect } from "node:tls";
import type { TLSSocket } from "node:tls";
import { constants as fsConstants, closeSync, fstatSync, openSync, readSync } from "node:fs";
import { isIP } from "node:net";
import { randomBytes } from "node:crypto";
import { privateKeyFileModeError, privateKeyFileOwnerError } from "./artifact-signature.ts";

export const MAX_REPLY_BYTES = 64 * 1024;
export const MAX_REPLY_LINES = 100;
export const MAX_BODY_BYTES = 64 * 1024;
const MAX_SUBJECT_CHARS = 200;
const MAX_PASSWORD_FILE_BYTES = 4096;
const MAX_CA_FILE_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_STEP_TIMEOUT_MS = 10_000;

export interface MailConfig {
  host: string;
  /** Default 465. */
  port?: number;
  /** Credentials are both-or-neither. */
  user?: string;
  password?: string;
  from: string;
  /** PEM text of the CA that signed a private relay's certificate. */
  ca?: string;
  /** Only "implicit-tls" is accepted. Present so a config asking for anything else is refused. */
  security?: string;
}

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
}

export interface SendMailOptions {
  /** Whole-exchange bound. Default 15 s. */
  timeoutMs?: number;
  /** Bound on each single wait for the server. Default 10 s. */
  stepTimeoutMs?: number;
  /** Name given in EHLO. Default "heliopause-manager". */
  clientName?: string;
}

/**
 * A failure at or after the end-of-data step (for example a timeout at `data-end`) does not prove the
 * mail was not delivered: the server may have accepted it. Retrying such a failure can duplicate it.
 */
export class MailError extends Error {
  readonly step: string;
  /** SMTP reply code, or 0 when the failure was not a reply (timeout, TLS, closed, validation). */
  readonly code: number;
  constructor(step: string, code: number, detail: string) {
    super(`mail ${step}: ${detail}${code ? ` (${code})` : ""}`);
    this.name = "MailError";
    this.step = step;
    this.code = code;
  }
}

// ---------------------------------------------------------------------------------------------
// Message building

/** Host names and IP literals only; shared by `sendMail` and `mailConfigFromEnv`. */
const HOST_PATTERN = /^[A-Za-z0-9.:-]+$/;

const ADDRESS = new RegExp(
  "^[A-Za-z0-9._%+-]{1,64}@" +
  "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$",
);

export function checkAddress(value: unknown, what: string): string {
  if (typeof value !== "string" || /[\r\n\0]/.test(value)) throw new MailError("validate", 0, `${what} has a control character`);
  const local = value.slice(0, value.indexOf("@"));
  if (value.length > 254 || !ADDRESS.test(value) || value.includes("..") || local.startsWith(".") || local.endsWith(".")) {
    throw new MailError("validate", 0, `${what} is not an acceptable address`);
  }
  return value;
}

/** Dot-stuff per RFC 5321 4.5.2: a line starting with "." gets a second ".". Input is CRLF text. */
export function dotStuff(data: string): string {
  return data.replace(/(^|\r\n)\./g, "$1..");
}

function encodeSubject(subject: string): string {
  if (/^[\x20-\x7e]*$/.test(subject) && !subject.includes("=?")) return subject;
  // RFC 2047 encoded-words, UTF-8 / B, split on code-point boundaries so each word stays <= 60 chars; with "Subject: " the first line is well under 76.
  const words: string[] = [];
  let chunk = "";
  for (const ch of subject) {
    if (Buffer.byteLength(chunk + ch) > 36) { words.push(chunk); chunk = ""; }
    chunk += ch;
  }
  if (chunk) words.push(chunk);
  return words.map((w) => `=?UTF-8?B?${Buffer.from(w, "utf8").toString("base64")}?=`).join("\r\n ");
}

function rfc5322Date(now: Date): string {
  return now.toUTCString().replace("GMT", "+0000");
}

export function buildMessage(from: string, message: MailMessage, now: Date = new Date()): string {
  checkAddress(from, "from");
  checkAddress(message.to, "to");
  if (typeof message.subject !== "string" || /[\r\n\0]/.test(message.subject)) {
    throw new MailError("validate", 0, "subject has a control character");
  }
  if (message.subject.length > MAX_SUBJECT_CHARS) throw new MailError("validate", 0, "subject is too long");
  if (typeof message.text !== "string" || Buffer.byteLength(message.text) > MAX_BODY_BYTES) {
    throw new MailError("validate", 0, "body is missing or over the size limit");
  }
  const body = message.text.replace(/\r\n|\r|\n/g, "\r\n");
  const wrapped = (Buffer.from(body, "utf8").toString("base64").match(/.{1,76}/g) ?? []).join("\r\n");
  const domain = from.slice(from.indexOf("@") + 1);
  const headers = [
    `From: <${from}>`,
    `To: <${message.to}>`,
    `Subject: ${encodeSubject(message.subject)}`,
    `Date: ${rfc5322Date(now)}`,
    `Message-ID: <${randomBytes(16).toString("hex")}@${domain}>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: base64",
  ];
  return headers.join("\r\n") + "\r\n\r\n" + wrapped + (wrapped ? "\r\n" : "");
}

// ---------------------------------------------------------------------------------------------
// Transport

interface Reply { code: number; lines: string[] }

export async function sendMail(config: MailConfig, message: MailMessage, opts: SendMailOptions = {}): Promise<void> {
  // Everything that can be refused is refused here, before a socket exists.
  if (config.security !== undefined && config.security !== "implicit-tls") {
    throw new MailError("validate", 0, "only implicit TLS is supported (no STARTTLS, no plaintext)");
  }
  if (typeof config.host !== "string" || !HOST_PATTERN.test(config.host)) {
    throw new MailError("validate", 0, "host is not acceptable");
  }
  const port = config.port ?? 465;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new MailError("validate", 0, "port is not acceptable");
  if ((config.user === undefined) !== (config.password === undefined)) {
    throw new MailError("validate", 0, "user and password must be given together");
  }
  if (config.user !== undefined && (!config.user || !config.password || /[\0\r\n]/.test(config.user + config.password))) {
    throw new MailError("validate", 0, "credentials are not acceptable");
  }
  const clientName = opts.clientName ?? "heliopause-manager";
  if (!/^[A-Za-z0-9.-]{1,253}$/.test(clientName)) throw new MailError("validate", 0, "client name is not acceptable");
  const data = dotStuff(buildMessage(config.from, message));

  const overallMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const stepMs = opts.stepTimeoutMs ?? DEFAULT_STEP_TIMEOUT_MS;
  for (const ms of [overallMs, stepMs]) {
    if (!Number.isSafeInteger(ms) || ms <= 0) throw new MailError("validate", 0, "timeouts must be positive integers");
  }

  let step = "connect";
  let failure: MailError | null = null;
  let waiter: { resolve: (r: Reply) => void; reject: (e: MailError) => void } | null = null;

  const socket: TLSSocket = tlsConnect({
    host: config.host,
    port,
    // RFC 6066 forbids an IP literal as SNI, so none is sent for one; the certificate identity is still
    // checked against `host` (its IP SAN).
    servername: isIP(config.host) ? undefined : config.host,
    rejectUnauthorized: true,
    ...(config.ca ? { ca: config.ca } : {}),
  });

  const fail = (e: MailError): void => {
    if (failure) return;
    failure = e;
    socket.destroy();
    const w = waiter;
    waiter = null;
    w?.reject(e);
  };
  // Until the handshake finishes, every failure is a connect failure; the greeting step starts after.
  socket.once("secureConnect", () => { if (step === "connect") step = "greeting"; });
  const overall = setTimeout(() => fail(new MailError(step, 0, "timed out")), overallMs);

  let buf = "";
  let cur: string[] = [];
  let curBytes = 0;
  let curCode = 0;
  socket.on("data", (chunk: Buffer) => {
    buf += chunk.toString("latin1");
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).replace(/\r$/, "");
      curBytes += nl + 1;
      buf = buf.slice(nl + 1);
      const m = /^(\d{3})([ -]|$)/.exec(line);
      if (!m || (cur.length > 0 && Number(m[1]) !== curCode)) return fail(new MailError(step, 0, "malformed reply"));
      curCode = Number(m[1]);
      cur.push(line.slice(4));
      if (cur.length > MAX_REPLY_LINES) return fail(new MailError(step, 0, "reply has too many lines"));
      if (curBytes > MAX_REPLY_BYTES) return fail(new MailError(step, 0, "reply is too large"));
      if (m[2] !== "-") {
        // A bare "250" is a valid last line (RFC 5321 4.2). We never pipeline, so a reply that
        // completes while nobody is waiting for one is not an answer to anything we sent.
        const reply = { code: curCode, lines: cur };
        cur = []; curBytes = 0; curCode = 0;
        if (!waiter) return fail(new MailError(step, 0, "unsolicited reply"));
        const w = waiter;
        waiter = null;
        w.resolve(reply);
      }
    }
    if (curBytes + buf.length > MAX_REPLY_BYTES) fail(new MailError(step, 0, "reply is too large"));
  });
  socket.on("error", (err: NodeJS.ErrnoException) => fail(new MailError(step, 0, `connection failed: ${err.code ?? "error"}`)));
  socket.on("close", () => fail(new MailError(step, 0, "connection closed")));

  const read = (ms: number = stepMs): Promise<Reply> => {
    if (failure) return Promise.reject(failure);
    return new Promise<Reply>((resolve, reject) => {
      const timer = setTimeout(() => fail(new MailError(step, 0, "timed out")), ms);
      waiter = {
        resolve: (r) => { clearTimeout(timer); resolve(r); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      };
    });
  };
  const say = (line: string): void => { if (!failure) socket.write(line + "\r\n"); };
  const expect = async (name: string, ok: number[]): Promise<Reply> => {
    if (step !== "connect") step = name;
    const r = await read();
    if (!ok.includes(r.code)) throw new MailError(name, r.code, "unexpected reply");
    return r;
  };

  try {
    await expect("greeting", [220]);
    say(`EHLO ${clientName}`);
    const ehlo = await expect("ehlo", [250]);
    if (config.user !== undefined) {
      const offersPlain = ehlo.lines.some((l) => /^AUTH[ =]/i.test(l) && /(^|[ =])PLAIN(\s|$)/i.test(l));
      if (!offersPlain) throw new MailError("auth", 0, "server does not offer AUTH PLAIN");
      step = "auth";
      say("AUTH PLAIN " + Buffer.from(`\0${config.user}\0${config.password}`, "utf8").toString("base64"));
      await expect("auth", [235]);
    }
    say(`MAIL FROM:<${config.from}>`);
    await expect("mail-from", [250]);
    say(`RCPT TO:<${message.to}>`);
    await expect("rcpt-to", [250, 251]);
    say("DATA");
    await expect("data", [354]);
    if (!failure) socket.write(data + ".\r\n");
    await expect("data-end", [250]);
    say("QUIT");
    await read(2000).catch(() => undefined);
  } finally {
    clearTimeout(overall);
    socket.destroy();
  }
}

// ---------------------------------------------------------------------------------------------
// Environment

/**
 * Open without following a symlink and without blocking (a FIFO would otherwise hang startup in
 * `open`), then require a regular file, bounded in size. `secret` adds the mode and owner checks.
 */
function readBoundedFile(variable: string, path: string, maxBytes: number, secret: boolean): string {
  let fd: number;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    throw new Error(`${variable}: cannot open ${path} (${code === "ELOOP" ? "symlinks are refused" : code ?? "error"})`);
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error(`${variable}: ${path} is not a regular file`);
    if (secret) {
      const modeError = privateKeyFileModeError(st, process.getgid?.());
      if (modeError) throw new Error(`${variable}: ${path} ${modeError}`);
      const ownerError = privateKeyFileOwnerError(st, process.getuid?.());
      if (ownerError) throw new Error(`${variable}: ${path} ${ownerError}`);
    }
    if (st.size > maxBytes) throw new Error(`${variable}: ${path} is too large`);
    const b = Buffer.alloc(st.size);
    let off = 0;
    while (off < st.size) {
      const n = readSync(fd, b, off, st.size - off, off);
      if (n === 0) break;
      off += n;
    }
    return b.subarray(0, off).toString("utf8");
  } finally {
    closeSync(fd);
  }
}

/** `null` means mail is not configured. A partial configuration throws and names the variable. */
export function mailConfigFromEnv(env: Record<string, string | undefined>): MailConfig | null {
  const host = env.HELIOPAUSE_SMTP_HOST;
  if (!host) return null;
  if (!HOST_PATTERN.test(host)) throw new Error("HELIOPAUSE_SMTP_HOST is not an acceptable host");
  const security = env.HELIOPAUSE_SMTP_SECURITY;
  if (security && security !== "implicit-tls") {
    throw new Error("HELIOPAUSE_SMTP_SECURITY must be unset or implicit-tls (no STARTTLS, no plaintext)");
  }
  const from = env.HELIOPAUSE_SMTP_FROM;
  if (!from) throw new Error("HELIOPAUSE_SMTP_FROM is required when HELIOPAUSE_SMTP_HOST is set");
  try { checkAddress(from, "HELIOPAUSE_SMTP_FROM"); } catch { throw new Error("HELIOPAUSE_SMTP_FROM is not an acceptable address"); }
  let port = 465;
  if (env.HELIOPAUSE_SMTP_PORT) {
    if (!/^\d{1,5}$/.test(env.HELIOPAUSE_SMTP_PORT) || Number(env.HELIOPAUSE_SMTP_PORT) < 1 || Number(env.HELIOPAUSE_SMTP_PORT) > 65535) {
      throw new Error("HELIOPAUSE_SMTP_PORT must be a port number");
    }
    port = Number(env.HELIOPAUSE_SMTP_PORT);
  }
  const user = env.HELIOPAUSE_SMTP_USER;
  const passwordFile = env.HELIOPAUSE_SMTP_PASSWORD_FILE;
  if (user && !passwordFile) throw new Error("HELIOPAUSE_SMTP_PASSWORD_FILE is required when HELIOPAUSE_SMTP_USER is set");
  if (passwordFile && !user) throw new Error("HELIOPAUSE_SMTP_USER is required when HELIOPAUSE_SMTP_PASSWORD_FILE is set");
  const config: MailConfig = { host, port, from };
  if (user && passwordFile) {
    const password = readBoundedFile("HELIOPAUSE_SMTP_PASSWORD_FILE", passwordFile, MAX_PASSWORD_FILE_BYTES, true).replace(/\r?\n$/, "");
    if (!password) throw new Error("HELIOPAUSE_SMTP_PASSWORD_FILE is empty");
    config.user = user;
    config.password = password;
  }
  const caFile = env.HELIOPAUSE_SMTP_CA_FILE;
  if (caFile) {
    config.ca = readBoundedFile("HELIOPAUSE_SMTP_CA_FILE", caFile, MAX_CA_FILE_BYTES, false);
  }
  return config;
}
