// SMTP client against a fake relay speaking implicit TLS. Every socket here is bounded and every
// server is closed in `finally` / `after`: a hang is not a red.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync, symlinkSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { createServer } from "node:tls";
import { EventEmitter, once } from "node:events";
import type { Server, TLSSocket } from "node:tls";
import {
  MailError, MAX_REPLY_BYTES, buildMessage, dotStuff, mailConfigFromEnv, sendMail,
} from "./mail.ts";
import type { MailConfig } from "./mail.ts";

const dir = mkdtempSync(join(tmpdir(), "hp-mail-"));
let key = "";
let cert = "";

before(() => {
  const run = (...a: string[]) => execFileSync("openssl", a, { cwd: dir, stdio: "pipe" });
  run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "relay.key", "-out", "relay.csr", "-subj", "/CN=relay");
  writeFileSync(join(dir, "relay.ext"), "subjectAltName=IP:127.0.0.1\n");
  run("x509", "-req", "-in", "relay.csr", "-signkey", "relay.key", "-out", "relay.pem", "-days", "1", "-extfile", "relay.ext");
  key = readFileSync(join(dir, "relay.key"), "utf8");
  cert = readFileSync(join(dir, "relay.pem"), "utf8");
});
after(() => rmSync(dir, { recursive: true, force: true }));

interface Fake {
  port: number;
  commands: string[];
  data: string[];
  connections: number;
  sockets: Set<TLSSocket>;
  bus: EventEmitter;
  server: Server;
}
interface FakeOpts {
  ehlo?: string[];
  greeting?: string;
  stallAfterGreeting?: boolean;
  /** Replace the reply to one command prefix. */
  reply?: Record<string, string>;
}

async function fake(opts: FakeOpts = {}): Promise<Fake> {
  const f = { commands: [] as string[], data: [] as string[], connections: 0, sockets: new Set<TLSSocket>(), bus: new EventEmitter() } as Fake;
  f.server = createServer({ key, cert }, (s) => {
    f.sockets.add(s);
    s.on("error", () => {});
    s.on("close", () => { f.sockets.delete(s); f.bus.emit("close"); });
    s.write(opts.greeting ?? "220 relay ready\r\n");
    if (opts.stallAfterGreeting) return;
    let buf = "";
    let inData = false;
    s.on("data", (d) => {
      buf += d.toString("latin1");
      for (;;) {
        if (inData) {
          const end = buf.indexOf("\r\n.\r\n");
          if (end < 0) return;
          f.data.push(buf.slice(0, end + 2));
          buf = buf.slice(end + 5);
          inData = false;
          s.write(opts.reply?.["."] ?? "250 queued\r\n");
          continue;
        }
        const nl = buf.indexOf("\r\n");
        if (nl < 0) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        f.commands.push(line);
        const verb = line.split(" ")[0]!.toUpperCase();
        const override = opts.reply?.[verb];
        if (override === "CLOSE") { s.destroy(); return; }
        if (override !== undefined) { s.write(override); if (verb === "DATA" && override.startsWith("354")) inData = true; continue; }
        if (verb === "EHLO") {
          const ext = opts.ehlo ?? ["AUTH PLAIN LOGIN", "8BITMIME"];
          s.write(["250-relay", ...ext.map((e) => `250-${e}`)].join("\r\n").replace(/-([^-]*)$/, " $1") + "\r\n");
        }
        else if (verb === "AUTH") s.write("235 ok\r\n");
        else if (verb === "MAIL" || verb === "RCPT") s.write("250 ok\r\n");
        else if (verb === "DATA") { s.write("354 go\r\n"); inData = true; }
        else if (verb === "QUIT") { s.write("221 bye\r\n"); s.end(); }
      }
    });
  });
  // Counted at TCP accept, so a connection whose TLS handshake the client refuses still counts.
  f.server.on("connection", () => { f.connections++; });
  await new Promise<void>((r) => f.server.listen(0, "127.0.0.1", r));
  f.port = (f.server.address() as { port: number }).port;
  return f;
}
async function withFake<T>(opts: FakeOpts, body: (f: Fake) => Promise<T>): Promise<T> {
  const f = await fake(opts);
  try { return await body(f); }
  finally {
    for (const s of f.sockets) s.destroy();
    await new Promise<void>((r) => f.server.close(() => r()));
  }
}

const SECRET = "hunter2-" + "pw";
const BODY = "line one\n.leading dot line\n\u00e9\u00e8 bodytext\n";
const cfg = (f: Fake, extra: Partial<MailConfig> = {}): MailConfig =>
  ({ host: "127.0.0.1", port: f.port, from: "ops@example.com", ca: cert, ...extra });
const MSG = { to: "alice@example.org", subject: "Reset", text: BODY };
const FAST = { timeoutMs: 3000, stepTimeoutMs: 1500 };

/** Resolves when the server has no open connection left; bounded by AbortSignal.timeout. */
async function serverClosed(f: Fake): Promise<void> {
  const signal = AbortSignal.timeout(3000);
  while (f.sockets.size > 0) await once(f.bus, "close", { signal });
}
/** A hang is not a red: bound a promise that must settle, without measuring wall-clock time. */
async function within<T>(ms: number, p: Promise<T>): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([p, new Promise<never>((_, rej) => { timer = setTimeout(() => rej(new Error(`still pending after ${ms}ms`)), ms); })]);
  } finally { clearTimeout(timer); }
}

const reject = async (p: Promise<unknown>): Promise<MailError> => {
  try { await p; } catch (e) { assert.ok(e instanceof MailError, String(e)); return e; }
  assert.fail("expected sendMail to reject");
};

describe("sendMail", () => {
  it("runs the exact command sequence and delivers a decodable message", () =>
    withFake({}, async (f) => {
      await sendMail(cfg(f), MSG, FAST);
      assert.deepEqual(f.commands, [
        "EHLO heliopause-manager",
        "MAIL FROM:<ops@example.com>",
        "RCPT TO:<alice@example.org>",
        "DATA",
        "QUIT",
      ]);
      const raw = f.data[0]!;
      assert.ok(raw.endsWith("\r\n") && !raw.endsWith("\r\n\r\n"), "data must end with one CRLF before the terminator");
      const [head, body] = raw.split("\r\n\r\n") as [string, string];
      assert.match(head, /^From: <ops@example.com>\r\nTo: <alice@example.org>\r\nSubject: Reset\r\n/);
      assert.match(head, /Content-Type: text\/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64$/);
      assert.match(head, /Message-ID: <[0-9a-f]{32}@example.com>/);
      assert.match(head, /Date: \w{3}, \d{1,2} \w{3} \d{4} \d\d:\d\d:\d\d \+0000/);
      assert.equal(Buffer.from(body.replace(/\r\n/g, ""), "base64").toString("utf8"), BODY.replace(/\n/g, "\r\n"));
    }));

  it("sends AUTH PLAIN with the right payload", () =>
    withFake({}, async (f) => {
      await sendMail(cfg(f, { user: "mailer", password: SECRET }), MSG, FAST);
      const auth = f.commands.find((c) => c.startsWith("AUTH "))!;
      assert.equal(auth, "AUTH PLAIN " + Buffer.from(`\0mailer\0${SECRET}`).toString("base64"));
      assert.ok(f.commands.indexOf(auth) < f.commands.findIndex((c) => c.startsWith("MAIL")));
    }));

  it("authenticates with the Cloudflare-style user api_token and a long token over AUTH PLAIN", () =>
    withFake({ ehlo: ["AUTH PLAIN LOGIN", "SIZE 1000"] }, async (f) => {
      const token = "t".repeat(60);
      await sendMail(cfg(f, { user: "api_token", password: token }), MSG, FAST);
      assert.equal(f.commands.find((c) => c.startsWith("AUTH ")), "AUTH PLAIN " + Buffer.from(`\0api_token\0${token}`).toString("base64"));
    }));

  it("refuses to authenticate when the server does not advertise AUTH PLAIN, and sends no credentials", () =>
    withFake({ ehlo: ["AUTH LOGIN", "8BITMIME"] }, async (f) => {
      const e = await reject(sendMail(cfg(f, { user: "mailer", password: SECRET }), MSG, FAST));
      assert.equal(e.step, "auth");
      assert.ok(!f.commands.some((c) => c.startsWith("AUTH")));
      assert.ok(!f.commands.some((c) => c.startsWith("MAIL")));
    }));

  it("sends no AUTH when there are no credentials, even if the server offers it", () =>
    withFake({}, async (f) => {
      await sendMail(cfg(f), MSG, FAST);
      assert.ok(!f.commands.some((c) => c.startsWith("AUTH")));
    }));

  it("refuses an untrusted certificate without ca, and accepts it with ca", () =>
    withFake({}, async (f) => {
      const e = await reject(sendMail(cfg(f, { ca: undefined }), MSG, FAST));
      assert.equal(e.step, "connect");
      assert.match(e.message, /DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN/);
      assert.equal(f.connections, 1, "the handshake must have been reached");
      assert.equal(f.commands.length, 0);
      await sendMail(cfg(f), MSG, FAST);
      assert.equal(f.commands[0], "EHLO heliopause-manager");
    }));

  it("refuses a hostname that is not on the certificate", () =>
    withFake({}, async (f) => {
      // The certificate only names the IP, and the CA is trusted: the only thing wrong is the name.
      const e = await reject(sendMail({ ...cfg(f), host: "localhost" }, MSG, FAST));
      assert.equal(e.step, "connect");
      assert.match(e.message, /ERR_TLS_CERT_ALTNAME_INVALID/);
      assert.equal(f.connections, 1, "refused for the name, not because nothing answered");
      assert.equal(f.commands.length, 0);
    }));

  it("refuses STARTTLS/plaintext configs before connecting", () =>
    withFake({}, async (f) => {
      for (const security of ["starttls", "plaintext", "none", ""]) {
        await reject(sendMail({ ...cfg(f), security }, MSG, FAST));
      }
      assert.equal(f.connections, 0);
    }));

  it("refuses header injection and bad addresses before connecting", () =>
    withFake({}, async (f) => {
      const bad: Array<[string, Partial<MailConfig>, Partial<typeof MSG>]> = [
        ["CR in subject", {}, { subject: "x\rBcc: evil@example.net" }],
        ["LF in subject", {}, { subject: "x\nBcc: evil@example.net" }],
        ["LF in to", {}, { to: "a@example.org\nBcc: evil@example.net" }],
        ["CRLF in from", { from: "ops@example.com\r\nX: y" }, {}],
        ["angle brackets", {}, { to: "<a@example.org>" }],
        ["two recipients", {}, { to: "a@example.org,b@example.org" }],
        ["no domain dot", {}, { to: "a@localhost" }],
        ["spaces", {}, { to: "a b@example.org" }],
        ["double dot", {}, { to: "a..b@example.org" }],
        ["over 64 KiB body", {}, { text: "x".repeat(64 * 1024 + 1) }],
      ];
      for (const [name, c, m] of bad) {
        await assert.rejects(sendMail(cfg(f, c), { ...MSG, ...m }, FAST), MailError, name);
      }
      assert.equal(f.connections, 0);
    }));

  it("encodes a non-ASCII subject as RFC 2047 words and keeps ASCII subjects plain", () => {
    const m = buildMessage("ops@example.com", { ...MSG, subject: "\ube44\ubc00\ubc88\ud638 \uc7ac\uc124\uc815 \uc548\ub0b4\ub4dc\ub9bd\ub2c8\ub2e4 \ud655\uc778\ud574 \uc8fc\uc138\uc694" });
    const subject = /Subject: ((?:[^\r]|\r\n )*)\r\n/.exec(m)![1]!;
    const words = subject.split("\r\n ");
    assert.ok(words.length > 1);
    for (const w of words) assert.match(w, /^=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=$/);
    assert.ok(words.every((w) => w.length <= 75));
    assert.ok(("Subject: " + words[0]).length <= 76, "first line too long");
    const decoded = words.map((w) => Buffer.from(w.slice(10, -2), "base64").toString("utf8")).join("");
    assert.equal(decoded, "\ube44\ubc00\ubc88\ud638 \uc7ac\uc124\uc815 \uc548\ub0b4\ub4dc\ub9bd\ub2c8\ub2e4 \ud655\uc778\ud574 \uc8fc\uc138\uc694");
  });

  // `sendMail` calls dotStuff on a base64 body, which never has a line starting with ".", so deleting
  // that call is invisible end to end today. This unit test is what pins the function itself.
  it("dot-stuffs every line that starts with a dot", () => {
    assert.equal(dotStuff(".a\r\nb\r\n.\r\n..c"), "..a\r\nb\r\n..\r\n...c");
  });

  it("aborts on a reply with too many lines", () =>
    withFake({ greeting: "220-x\r\n".repeat(150) + "220 done\r\n" }, async (f) => {
      const e = await reject(sendMail(cfg(f), MSG, FAST));
      assert.match(e.message, /too many lines/);
      assert.equal(f.commands.length, 0);
    }));

  it("aborts on an oversized reply, including one with no line break", () =>
    withFake({ greeting: "220 " + "a".repeat(MAX_REPLY_BYTES + 10) }, async (f) => {
      const e = await reject(sendMail(cfg(f), MSG, FAST));
      assert.match(e.message, /too large/);
    }));

  it("aborts on an oversized multi-line reply made of short lines", () =>
    withFake({ greeting: ("220-" + "a".repeat(990) + "\r\n").repeat(80) + "220 done\r\n" }, async (f) => {
      const e = await reject(sendMail(cfg(f), MSG, FAST));
      assert.match(e.message, /too large/);
    }));

  it("fails on a reply with a mismatched code inside a multi-line reply", () =>
    withFake({ greeting: "220-a\r\n250 b\r\n" }, async (f) => {
      const e = await reject(sendMail(cfg(f), MSG, FAST));
      assert.match(e.message, /malformed/);
      assert.equal(f.commands.length, 0);
    }));

  it("times out against a server that stalls, within the bound, and closes the socket", () =>
    withFake({ stallAfterGreeting: true, greeting: "" }, async (f) => {
      const e = await within(5000, reject(sendMail(cfg(f), MSG, { timeoutMs: 60_000, stepTimeoutMs: 300 })));
      assert.match(e.message, /timed out/);
      await serverClosed(f);
    }));

  it("applies the overall bound even when the per-step bound is long", () =>
    withFake({ reply: { DATA: "" } }, async (f) => {
      // The server never answers DATA with 354.
      const e = await within(5000, reject(sendMail(cfg(f), MSG, { timeoutMs: 400, stepTimeoutMs: 60_000 })));
      assert.match(e.message, /timed out/);
      assert.equal(e.step, "data");
      await serverClosed(f);
    }));

  it("throws a typed error with step and code on an unexpected reply, never echoing credentials or body", () =>
    withFake({ reply: { RCPT: "550 mailbox unavailable\r\n" } }, async (f) => {
      const e = await reject(sendMail(cfg(f, { user: "mailer", password: SECRET }), MSG, FAST));
      assert.equal(e.step, "rcpt-to");
      assert.equal(e.code, 550);
      for (const secret of [SECRET, Buffer.from(`\0mailer\0${SECRET}`).toString("base64"), "line one", "bodytext", "mailbox unavailable"]) {
        assert.ok(!e.message.includes(secret), `error leaks ${secret}`);
        assert.ok(!String(e.stack).includes(secret), `stack leaks ${secret}`);
      }
    }));

  it("reports a rejected AUTH as step auth without the password", () =>
    withFake({ reply: { AUTH: "535 nope\r\n" } }, async (f) => {
      const e = await reject(sendMail(cfg(f, { user: "mailer", password: SECRET }), MSG, FAST));
      assert.equal(e.step, "auth");
      assert.equal(e.code, 535);
      assert.ok(!e.message.includes(SECRET));
    }));

  it("accepts 251 for RCPT and fails on a rejected end-of-data", () =>
    withFake({ reply: { RCPT: "251 forwarded\r\n", ".": "554 spam\r\n" } }, async (f) => {
      const e = await reject(sendMail(cfg(f), MSG, FAST));
      assert.equal(e.step, "data-end");
      assert.equal(e.code, 554);
    }));
});

describe("sendMail, protocol edges", () => {
  it("fails on an unsolicited reply instead of letting a later step consume it", () =>
    withFake({ reply: { MAIL: "250 ok\r\n250 ok\r\n", RCPT: "550 no\r\n" } }, async (f) => {
      const e = await reject(sendMail(cfg(f), MSG, FAST));
      assert.match(e.message, /unsolicited/);
      assert.ok(!f.commands.includes("DATA"), "a rejected RCPT must not reach DATA");
    }));

  it("accepts a reply that is only a code, as the last line", () =>
    withFake({ reply: { DATA: "354\r\n", MAIL: "250\r\n" } }, async (f) => {
      await sendMail(cfg(f), MSG, FAST);
      assert.equal(f.data.length, 1);
    }));

  it("treats a bare code inside a multi-line reply as its end", () =>
    withFake({ greeting: "220-first\r\n220\r\n" }, async (f) => {
      await sendMail(cfg(f), MSG, FAST);
      assert.equal(f.commands[0], "EHLO heliopause-manager");
    }));

  it("fails with the greeting step on a 554 greeting", () =>
    withFake({ greeting: "554 no service\r\n" }, async (f) => {
      const e = await reject(sendMail(cfg(f), MSG, FAST));
      assert.equal(e.step, "greeting");
      assert.equal(e.code, 554);
      assert.equal(f.commands.length, 0);
    }));

  it("fails when the server closes mid-conversation, and holds no socket afterwards", () =>
    withFake({ reply: { RCPT: "CLOSE" } }, async (f) => {
      const e = await within(5000, reject(sendMail(cfg(f), MSG, FAST)));
      assert.match(e.message, /closed/);
      assert.equal(e.step, "rcpt-to");
      await serverClosed(f);
    }));

  it("rejects non-positive or non-integer timeouts before connecting", () =>
    withFake({}, async (f) => {
      for (const t of [0, -1, 1.5, Number.NaN, Infinity]) {
        await reject(sendMail(cfg(f), MSG, { timeoutMs: t }));
        await reject(sendMail(cfg(f), MSG, { stepTimeoutMs: t }));
      }
      assert.equal(f.connections, 0);
    }));

  it("encodes an ASCII subject that contains an encoded-word marker", () => {
    const m = buildMessage("ops@example.com", { ...MSG, subject: "=?UTF-8?B?aGk=?=" });
    assert.match(m, /Subject: =\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=(\r\n|$)/);
    assert.ok(!m.includes("Subject: =?UTF-8?B?aGk=?=\r\n"));
  });
});

describe("mailConfigFromEnv", () => {
  const base = { HELIOPAUSE_SMTP_HOST: "smtp.example.com", HELIOPAUSE_SMTP_FROM: "ops@example.com" };
  const secretFile = (mode: number, content = SECRET + "\n", name = "pw") => {
    const p = join(dir, name + "-" + mode.toString(8));
    writeFileSync(p, content);
    chmodSync(p, mode);
    return p;
  };

  it("returns null when no host is set", () => {
    assert.equal(mailConfigFromEnv({}), null);
    assert.equal(mailConfigFromEnv({ HELIOPAUSE_SMTP_HOST: "", HELIOPAUSE_SMTP_FROM: "x" }), null);
  });

  it("defaults the port to 465 and needs no credentials", () => {
    assert.deepEqual(mailConfigFromEnv(base), { host: "smtp.example.com", port: 465, from: "ops@example.com" });
  });

  it("reads the password file and trims one trailing newline only", () => {
    const c = mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_PORT: "2465", HELIOPAUSE_SMTP_USER: "mailer", HELIOPAUSE_SMTP_PASSWORD_FILE: secretFile(0o600) });
    assert.equal(c!.port, 2465);
    assert.equal(c!.user, "mailer");
    assert.equal(c!.password, SECRET);
    const spaced = mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_USER: "m", HELIOPAUSE_SMTP_PASSWORD_FILE: secretFile(0o600, " pw \n\n", "sp") });
    assert.equal(spaced!.password, " pw \n");
  });

  it("accepts a 0640 password file whose group is this process's group", (t) => {
    const p = secretFile(0o640, SECRET + "\n", "grp");
    if (statSync(p).gid !== process.getgid?.()) return t.skip("new files do not take this process's gid here");
    assert.equal(mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_USER: "u", HELIOPAUSE_SMTP_PASSWORD_FILE: p })!.password, SECRET);
  });

  it("refuses a FIFO for the password file and the CA file without blocking", (t) => {
    const fifo = join(dir, "fifo");
    try { execFileSync("mkfifo", [fifo]); } catch { return t.skip("mkfifo is not available"); }
    assert.throws(() => mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_USER: "u", HELIOPAUSE_SMTP_PASSWORD_FILE: fifo }), /not a regular file/);
    assert.throws(() => mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_CA_FILE: fifo }), /not a regular file/);
  });

  it("refuses a CA file over 64 KiB and a symlinked CA file", () => {
    const big = join(dir, "bigca");
    writeFileSync(big, "x".repeat(64 * 1024 + 1));
    assert.throws(() => mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_CA_FILE: big }), /too large/);
    const real = join(dir, "realca");
    writeFileSync(real, cert);
    symlinkSync(real, join(dir, "calink"));
    assert.throws(() => mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_CA_FILE: join(dir, "calink") }), /symlink/);
  });

  it("accepts only unset or implicit-tls for HELIOPAUSE_SMTP_SECURITY, and a sane host", () => {
    assert.ok(mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_SECURITY: "implicit-tls" }));
    assert.ok(mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_SECURITY: "" }));
    for (const v of ["starttls", "none", "plaintext", "tls"]) {
      assert.throws(() => mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_SECURITY: v }), /HELIOPAUSE_SMTP_SECURITY/, v);
    }
    assert.throws(() => mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_HOST: "smtp.example.com/x" }), /HELIOPAUSE_SMTP_HOST/);
  });

  it("reads the optional CA file", () => {
    const p = join(dir, "ca.pem");
    writeFileSync(p, cert);
    assert.equal(mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_CA_FILE: p })!.ca, cert);
    assert.throws(() => mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_CA_FILE: join(dir, "missing") }), /HELIOPAUSE_SMTP_CA_FILE/);
  });

  it("names the missing variable for a partial config, never the password", () => {
    assert.throws(() => mailConfigFromEnv({ HELIOPAUSE_SMTP_HOST: "h" }), /HELIOPAUSE_SMTP_FROM/);
    assert.throws(() => mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_USER: "u" }), /HELIOPAUSE_SMTP_PASSWORD_FILE/);
    assert.throws(() => mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_PASSWORD_FILE: secretFile(0o600) }), (e: Error) =>
      /HELIOPAUSE_SMTP_USER/.test(e.message) && !e.message.includes(SECRET));
    assert.throws(() => mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_PORT: "99999" }), /HELIOPAUSE_SMTP_PORT/);
    assert.throws(() => mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_PORT: "25x" }), /HELIOPAUSE_SMTP_PORT/);
    assert.throws(() => mailConfigFromEnv({ ...base, HELIOPAUSE_SMTP_FROM: "not an address" }), /HELIOPAUSE_SMTP_FROM/);
  });

  it("refuses a password file that others or the group can reach, a symlink, and an empty file", () => {
    const env = (p: string) => ({ ...base, HELIOPAUSE_SMTP_USER: "u", HELIOPAUSE_SMTP_PASSWORD_FILE: p });
    for (const mode of [0o644, 0o604, 0o660, 0o620]) {
      assert.throws(() => mailConfigFromEnv(env(secretFile(mode))), (e: Error) =>
        /HELIOPAUSE_SMTP_PASSWORD_FILE/.test(e.message) && !e.message.includes(SECRET), `mode ${mode.toString(8)}`);
    }
    const target = secretFile(0o600, SECRET, "tgt");
    const link = join(dir, "link");
    symlinkSync(target, link);
    assert.throws(() => mailConfigFromEnv(env(link)), /symlink/);
    assert.throws(() => mailConfigFromEnv(env(secretFile(0o600, "\n", "empty"))), /empty/);
    mkdirSync(join(dir, "adir"));
    assert.throws(() => mailConfigFromEnv(env(join(dir, "adir"))), /HELIOPAUSE_SMTP_PASSWORD_FILE/);
    assert.throws(() => mailConfigFromEnv(env(join(dir, "nonexistent"))), /cannot open/);
  });
});
