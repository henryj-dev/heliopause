import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { closeSync, existsSync, fstatSync, mkdtempSync, openSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { atomicWriteFile, createExclusiveFile, withFileLock } from "./json-store.ts";

class StoreError extends Error {
  readonly statusCode: number;
  constructor(message: string, statusCode = 400) { super(message); this.statusCode = statusCode; }
}
const fail = (message: string, statusCode?: number): Error => new StoreError(message, statusCode);
const scratch = (): string => mkdtempSync(join(tmpdir(), "hp-json-store-"));
/** Read text, inode and mode through one descriptor, so all three describe the same file. */
function snapshot(path: string): { text: string; ino: number; mode: number } {
  const fd = openSync(path, "r");
  try {
    const st = fstatSync(fd);
    return { text: readFileSync(fd, "utf8"), ino: st.ino, mode: st.mode & 0o777 };
  } finally { closeSync(fd); }
}

describe("json-store", () => {
  it("replaces a file by rename (new inode) with mode 0600 and leaves no temp file behind", () => {
    const dir = scratch();
    const path = join(dir, "doc.json");
    writeFileSync(path, "old\n");
    const before = snapshot(path).ino;
    atomicWriteFile(path, "new\n");
    const after = snapshot(path);
    assert.notEqual(after.ino, before, "the file was rewritten in place, not replaced");
    assert.equal(after.text, "new\n");
    assert.equal(after.mode, 0o600);
    assert.deepEqual(readdirSync(dir), ["doc.json"]);
  });

  it("does not create a missing directory — the caller decides that", () => {
    const path = join(scratch(), "absent", "doc.json");
    assert.throws(() => atomicWriteFile(path, "x"), (e: NodeJS.ErrnoException) => e.code === "ENOENT");
  });

  it("creates a store once and refuses to overwrite it, naming the store", () => {
    const path = join(scratch(), "members.json");
    createExclusiveFile(path, "{}\n", "member store", fail);
    const created = snapshot(path);
    assert.equal(created.text, "{}\n");
    assert.equal(created.mode, 0o600);
    assert.throws(
      () => createExclusiveFile(path, "{\"x\":1}\n", "member store", fail),
      (e: StoreError) => e instanceof StoreError && e.message === `refusing to overwrite existing member store: ${path}`,
    );
    assert.equal(snapshot(path).text, "{}\n");
  });

  it("fails closed with 503 while another owner holds the lock", () => {
    const path = join(scratch(), "doc.json");
    writeFileSync(`${path}.lock`, "someone else");
    let ran = false;
    assert.throws(
      () => withFileLock(path, 0, "member store", fail, () => { ran = true; }),
      (e: StoreError) => e.statusCode === 503 && e.message === `${path}: member store is busy`,
    );
    assert.equal(ran, false);
    assert.equal(readFileSync(`${path}.lock`, "utf8"), "someone else");
  });

  it("releases its own lock when the body throws, and returns the body's value otherwise", () => {
    const path = join(scratch(), "doc.json");
    assert.throws(() => withFileLock(path, 0, "member store", fail, () => { throw new Error("boom"); }), /boom/);
    assert.equal(existsSync(`${path}.lock`), false);
    assert.equal(withFileLock(path, 0, "member store", fail, () => {
      assert.equal(existsSync(`${path}.lock`), true);
      return 7;
    }), 7);
    assert.equal(existsSync(`${path}.lock`), false);
  });

  it("never removes a lock that a later owner put in its place", () => {
    const path = join(scratch(), "doc.json");
    withFileLock(path, 0, "member store", fail, () => { writeFileSync(`${path}.lock`, "a later owner"); });
    assert.equal(readFileSync(`${path}.lock`, "utf8"), "a later owner");
  });
});
