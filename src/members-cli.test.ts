import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, describe, it } from "node:test";
import { createMember, deleteMember, loadMemberDocument, withMemberTransaction } from "./member-store.ts";
import { verifyPassword } from "./password.ts";

const cli = resolve(import.meta.dirname, "../bin/heliopause-members.ts");
const root = mkdtempSync(join(tmpdir(), "heliopause-members-cli-"));
after(() => rmSync(root, { recursive: true, force: true }));
const PASSWORD = "a long enough passphrase";
let counter = 0;
const freshStore = (): string => {
  const store = join(root, `s${++counter}`, "members.json");
  assert.equal(run(["init", "--store", store]).status, 0);
  return store;
};

function run(args: string[], input = "", env: Record<string, string> = {}, cwd = root) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd, input, encoding: "utf8",
    env: { PATH: process.env.PATH ?? "", ...env },
  });
}

describe("heliopause-members CLI", () => {
  it("init, create-admin, list, suspend refused for the last admin, reset-password", () => {
    const store = freshStore();
    const created = run(["create-admin", "--store", store, "--username", "Henry", "--email", "h@example.com"], `${PASSWORD}\n`);
    assert.equal(created.status, 0, created.stderr);

    const document = loadMemberDocument(store);
    assert.equal(document.members.length, 1);
    assert.deepEqual(document.members[0]!.roles, ["reader", "writer", "admin"]);
    assert.equal(document.members[0]!.status, "active");
    assert.equal(document.credentials[0]!.mustChange, false);
    assert.equal(document.audit.every((row) => row.actor === "cli"), true);
    assert.equal(readFileSync(store, "utf8").includes(PASSWORD), false);

    const listed = run(["list", "--store", store, "--json"]);
    const rows = JSON.parse(listed.stdout).members;
    assert.deepEqual(Object.keys(rows[0]).sort(), ["hasPassword", "id", "identities", "principalName", "roles", "status", "username"]);
    assert.equal(rows[0].hasPassword, true);

    const suspended = run(["suspend", "--store", store, "--username", "henry"]);
    assert.equal(suspended.status, 2);
    assert.match(suspended.stderr, /no active admin/);

    const reset = run(["reset-password", "--store", store, "--username", "henry"], "another long passphrase\n");
    assert.equal(reset.status, 0, reset.stderr);
    assert.equal(loadMemberDocument(store).credentials[0]!.mustChange, true);
  });

  it("suspends and unsuspends an admin while another admin remains", () => {
    const store = freshStore();
    for (const name of ["first", "second"]) {
      const created = run(["create-admin", "--store", store, "--username", name, "--email", `${name}@example.com`], `${PASSWORD}\n`);
      assert.equal(created.status, 0, created.stderr);
    }
    assert.equal(run(["suspend", "--store", store, "--username", "second"]).status, 0);
    assert.equal(loadMemberDocument(store).members[1]!.status, "suspended");
    const back = run(["unsuspend", "--store", store, "--username", "second"]);
    assert.equal(back.status, 0, back.stderr);
    assert.equal(loadMemberDocument(store).members[1]!.status, "active");
    const again = run(["unsuspend", "--store", store, "--username", "second"]);
    assert.equal(again.status, 2);
    assert.match(again.stderr, /not suspended/);
  });

  it("create-admin refuses a password the policy refuses and writes nothing", () => {
    const store = freshStore();
    const before = readFileSync(store, "utf8");
    const short = run(["create-admin", "--store", store, "--username", "henry", "--email", "h@example.com"], "short\n");
    assert.equal(short.status, 2);
    assert.match(short.stderr, /at least 12/);
    const containing = run(["create-admin", "--store", store, "--username", "henry", "--email", "h@example.com"], "henry-is-my-password\n");
    assert.match(containing.stderr, /username/);
    assert.equal(readFileSync(store, "utf8"), before);
  });

  it("checks a taken username or email before reading a password", () => {
    const store = freshStore();
    run(["create-admin", "--store", store, "--username", "henry", "--email", "h@example.com"], `${PASSWORD}\n`);
    // Empty stdin: a prompt would fail with the policy message, not the conflict.
    const taken = run(["create-admin", "--store", store, "--username", "HENRY", "--email", "x@example.com"]);
    assert.equal(taken.status, 2);
    assert.match(taken.stderr, /username henry is taken/);
    const email = run(["create-admin", "--store", store, "--username", "other", "--email", "H@example.com"]);
    assert.match(email.stderr, /email is already in use/);
    const missing = run(["reset-password", "--store", store, "--username", "nobody"]);
    assert.match(missing.stderr, /no member named nobody/);
  });

  it("reset-password refuses a deleted member before reading a password", () => {
    const store = freshStore();
    withMemberTransaction(store, (document) => {
      createMember(document, { username: "root-admin", status: "active", roles: ["admin"] }, { actor: "cli" });
      const gone = createMember(document, { username: "gone", status: "active", roles: ["reader"] }, { actor: "cli" });
      deleteMember(document, gone.id, { actor: "cli" });
    });
    const result = run(["reset-password", "--store", store, "--username", "gone"]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /member gone is deleted/);
  });

  it("import --dry-run prints a draft, hides OTP user ids, and writes nothing in its working directory", () => {
    const cwd = join(root, "import-cwd");
    mkdirSync(cwd);
    const otpId = "11111111-2222-3333-4444-555555555555";
    const result = run(["import", "--dry-run"], "", {
      HELIOPAUSE_OPERATOR_CNS: "ops-henry,ops-reader",
      HELIOPAUSE_WRITER_CNS: "ops-henry",
      HELIOPAUSE_OIDC_ALIASES: "h@example.com=ops-henry",
      HELIOPAUSE_OTP_USERS: `ops-henry=${otpId},ops-gone=22222222-0000-0000-0000-000000000000`,
    }, cwd);
    assert.equal(result.status, 0, result.stderr);
    const draft = JSON.parse(result.stdout);
    assert.equal(draft.dryRun, true);
    const henry = draft.members.find((m: { username: string }) => m.username === "ops-henry");
    assert.deepEqual(henry.roles, ["reader", "writer"]);
    assert.equal(henry.email, "h@example.com");
    assert.equal(henry.otpUser, true);
    assert.equal(result.stdout.includes(otpId), false);
    assert.equal(result.stdout.includes("22222222"), false);
    assert.deepEqual(readdirSync(cwd), []);
  });

  it("import without --dry-run is refused", () => {
    const result = run(["import"]);
    assert.equal(result.status, 64);
    assert.match(result.stderr, /only supports --dry-run/);
  });

  it("--help exits 0; an unknown flag or a value on a boolean flag exits 64", () => {
    const help = run(["--help"]);
    assert.equal(help.status, 0);
    assert.match(help.stdout, /heliopause-members init/);
    const bad = run(["list", "--store", "x.json", "--dry-run"]);
    assert.equal(bad.status, 64);
    assert.match(bad.stderr, /unknown flag --dry-run for list/);
    const valued = run(["list", "--store", "x.json", "--json=false"]);
    assert.equal(valued.status, 64);
    assert.match(valued.stderr, /--json takes no value/);
  });
});

/**
 * Drive the terminal branch through a pseudo-terminal from `script`. The input goes in only after
 * each prompt has been printed, so the bytes reach the raw-mode reader rather than the line
 * discipline. `cat |` gives `script` a pipe on stdin; macOS `script` refuses the socket Node uses.
 */
const scriptArgs = (argv: string[]): string[] | null => {
  if (spawnSync("sh", ["-c", "command -v script"]).status !== 0) return null;
  const quoted = argv.map((a) => `'${a.replaceAll("'", "'\\''")}'`).join(" ");
  if (process.platform === "darwin") return ["-c", `cat | script -q /dev/null ${quoted}`];
  if (process.platform === "linux") return ["-c", `cat | script -qec ${JSON.stringify(quoted)} /dev/null`];
  return null;
};
const noScript = scriptArgs(["true"]) === null ? "needs script(1) on macOS or Linux" : false;

const TERMINAL_KILL_MS = 15_000;

/**
 * Runs the CLI under `script`. The outer `sh`, `cat` and `script` share a new process group;
 * `script` starts the CLI in a session of its own, so the CLI writes its pid to a file first
 * (`echo $$; exec`) and is killed by pid. A timer kills both after TERMINAL_KILL_MS, and `finally`
 * kills both again so no child outlives the test.
 */
async function viaTerminal(argv: string[], answers: string[]): Promise<{ code: number | null; output: string }> {
  const pidFile = join(root, `cli-${++counter}.pid`);
  const args = scriptArgs(["sh", "-c", 'echo $$ > "$0"; exec "$@"', pidFile, process.execPath, cli, ...argv])!;
  const child = spawn("sh", args, { env: { PATH: process.env.PATH ?? "" }, detached: true });
  const killGroup = (): void => {
    try { process.kill(-child.pid!, "SIGKILL"); } catch { /* already gone */ }
    try { process.kill(Number(readFileSync(pidFile, "utf8").trim()), "SIGKILL"); } catch { /* not started, or gone */ }
  };
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; killGroup(); }, TERMINAL_KILL_MS);
  try {
    const result = await new Promise<{ code: number | null; output: string }>((done, fail) => {
      const prompts = ["new password: ", "repeat: "];
      let pending = ""; let sent = 0; let output = "";
      child.stdout.on("data", (chunk: Buffer) => {
        output += chunk; pending += chunk;
        // Input is written only after its prompt is visible, so it reaches the raw-mode reader.
        const prompt = prompts[sent];
        if (prompt && sent < answers.length && pending.includes(prompt)) { child.stdin.write(answers[sent]!); sent += 1; pending = ""; }
        if (/created admin|password reset|refused|input ended|interrupted|do not match/.test(output)) child.stdin.end();
      });
      child.on("error", fail);
      child.on("exit", (code) => done({ code, output }));
    });
    assert.equal(timedOut, false, `the CLI under script(1) did not exit within ${TERMINAL_KILL_MS} ms; output so far: ${JSON.stringify(result.output)}`);
    return result;
  } finally {
    clearTimeout(timer);
    killGroup();
  }
}

describe("heliopause-members on a terminal", { skip: noScript, timeout: 30_000 }, () => {
  it("reads the password from a terminal, without echo, with UTF-8 backspace", async () => {
    const store = freshStore();
    const typed = "a long enough passé";
    // "X" and the two-byte "é" are erased, then "é" is typed again.
    const result = await viaTerminal(
      ["create-admin", "--store", store, "--username", "henry", "--email", "h@example.com"],
      [`a long enough passéX\x7f\x7fé\r`, `${typed}\r`],
    );
    assert.equal(result.code, 0, result.output);
    assert.match(result.output, /created admin henry/);
    assert.equal(result.output.includes("passé"), false, "the password was echoed");
    const hash = loadMemberDocument(store).credentials[0]!.hash;
    assert.equal((await verifyPassword(typed, hash)).ok, true);
  });

  it("discards escape sequences such as arrow and modified arrow keys", async () => {
    const store = freshStore();
    const result = await viaTerminal(
      ["create-admin", "--store", store, "--username", "henry", "--email", "h@example.com"],
      ["a long enough pa\x1b[Ass\x1bOB\x1b[1;5C\r", "a long enough pass\r"],
    );
    assert.equal(result.code, 0, result.output);
    const hash = loadMemberDocument(store).credentials[0]!.hash;
    assert.equal((await verifyPassword("a long enough pass", hash)).ok, true);
  });

  it("Ctrl-C aborts instead of submitting what was typed", async () => {
    const store = freshStore();
    const result = await viaTerminal(
      ["create-admin", "--store", store, "--username", "henry", "--email", "h@example.com"],
      ["a long enough pass\x03"],
    );
    assert.equal(result.code, 2, result.output);
    assert.match(result.output, /interrupted/);
    assert.equal(loadMemberDocument(store).members.length, 0);
  });

  it("Ctrl-D aborts instead of submitting what was typed", async () => {
    const store = freshStore();
    const result = await viaTerminal(
      ["create-admin", "--store", store, "--username", "henry", "--email", "h@example.com"],
      ["a long enough pass\x04"],
    );
    assert.equal(result.code, 2, result.output);
    assert.match(result.output, /input ended/);
    assert.equal(loadMemberDocument(store).members.length, 0);
  });
});
