import { execFileSync } from "node:child_process";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { closeSync, existsSync, fstatSync, mkdtempSync, openSync, readdirSync, readFileSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { atomicWriteFile, createExclusiveFile, readBoundedStoreFile, withFileLock } from "./json-store.ts";

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


describe("bounded descriptor store reads", () => {
  it("accepts empty/exact-limit UTF-8 files and preserves ENOENT", () => {
    const dir = scratch(); const path = join(dir, "doc.json");
    try {
      assert.throws(() => readBoundedStoreFile(path, 4), (error: NodeJS.ErrnoException) => error.code === "ENOENT");
      writeFileSync(path, ""); assert.equal(readBoundedStoreFile(path, 0), "");
      writeFileSync(path, "éé"); assert.equal(readBoundedStoreFile(path, 4), "éé");
      assert.throws(() => readBoundedStoreFile(path, 3), /size limit/);
      assert.throws(() => readBoundedStoreFile(path, -1), /invalid store read limit/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("refuses a final symlink and a directory", () => {
    const dir = scratch(); const path = join(dir, "doc.json");
    try {
      writeFileSync(path, "{}"); symlinkSync(path, join(dir, "link.json"));
      assert.throws(() => readBoundedStoreFile(join(dir, "link.json"), 16), (error: NodeJS.ErrnoException) => error.code === "ELOOP");
      assert.throws(() => readBoundedStoreFile(dir, 16), /regular file/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("refuses a FIFO without waiting for a writer", () => {
    const dir = scratch(); const path = join(dir, "fifo.json");
    try {
      execFileSync("mkfifo", [path]);
      const script = `import {readBoundedStoreFile} from ${JSON.stringify(new URL("./json-store.ts", import.meta.url).href)};try {readBoundedStoreFile(process.argv[1], 16);process.exit(2)} catch(e) {if(!e.message.includes('regular file')) throw e}`;
      execFileSync("node", ["--input-type=module", "-e", script, path], { timeout: 2000, stdio: "pipe" });
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("reads the checked descriptor even when the pathname is replaced after fstat", () => {
    const dir = scratch(); const path = join(dir, "doc.json");
    try {
      writeFileSync(path, "safe");
      const script = `import fs from 'node:fs';import {syncBuiltinESMExports} from 'node:module';import {readBoundedStoreFile} from ${JSON.stringify(new URL("./json-store.ts", import.meta.url).href)};
        const original=fs.fstatSync;fs.fstatSync=(fd)=>{const info=original(fd);fs.renameSync(process.argv[1],process.argv[1]+'.old');fs.writeFileSync(process.argv[1],'replacement');return info};syncBuiltinESMExports();console.log(readBoundedStoreFile(process.argv[1],4));`;
      const result = execFileSync("node", ["--input-type=module", "-e", script, path], { encoding: "utf8", timeout: 2000 });
      assert.equal(result.trim(), "safe"); assert.equal(readFileSync(path, "utf8"), "replacement");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("bounds reads to limit+1 and rejects an append after the descriptor size check", () => {
    const dir = scratch(); const path = join(dir, "doc.json");
    try {
      writeFileSync(path, "safe");
      const script = `import fs from 'node:fs';import {syncBuiltinESMExports} from 'node:module';import {readBoundedStoreFile} from ${JSON.stringify(new URL("./json-store.ts", import.meta.url).href)};
        const stat=fs.fstatSync,read=fs.readSync;const requests=[],actual=[];fs.fstatSync=(fd)=>{const info=stat(fd);fs.appendFileSync(process.argv[1],'x'.repeat(1000));return info};fs.readSync=(fd,buffer,offset,length,position)=>{requests.push(length);const size=read(fd,buffer,offset,length,position);actual.push(size);return size};syncBuiltinESMExports();let rejected=false;try{readBoundedStoreFile(process.argv[1],4)}catch(e){rejected=e.message.includes('size limit')}console.log(JSON.stringify({rejected,requests,actual}));`;
      const result = JSON.parse(execFileSync("node", ["--input-type=module", "-e", script, path], { encoding: "utf8", timeout: 2000 }));
      assert.deepEqual(result, { rejected: true, requests: [5], actual: [5] });
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
