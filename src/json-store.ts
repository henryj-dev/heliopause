/**
 * Durable-file primitives: atomic replace, one-time exclusive creation, and an adjacent `O_EXCL`
 * lock around a caller's body.
 *
 * Callers today: the enrollment store and the member store (all three), and the problem-watch
 * runner (atomic replace and `discardOwnedPath`). Errors come from the caller's `fail` factory and messages are built from the
 * caller's `name`, so each store keeps its own error class and wording.
 */
import { randomBytes } from "node:crypto";
import {
  constants, chmodSync, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, renameSync, unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";

/** Read one regular file through the descriptor that was checked, with a hard byte ceiling.
 * O_NONBLOCK prevents a substituted FIFO from hanging open; O_NOFOLLOW refuses a final symlink.
 * ENOENT is preserved so stores can distinguish an absent document from an invalid one.
 */
export function readBoundedStoreFile(path: string, maxBytes: number): string {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes >= 0x7fffffff) throw new Error("invalid store read limit");
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = fstatSync(fd);
    if (!info.isFile()) throw new Error("store document is not a regular file");
    if (info.size > maxBytes) throw new Error("store document exceeds size limit");
    // A concurrent append after fstat must still be bounded. Read one extra byte to
    // distinguish exact-limit EOF from a file that grew; never reread the pathname.
    const data = Buffer.alloc(maxBytes + 1);
    let size = 0;
    while (size < data.length) {
      const count = readSync(fd, data, size, data.length - size, size);
      if (count === 0) break;
      size += count;
    }
    if (size > maxBytes) throw new Error("store document exceeds size limit");
    return data.subarray(0, size).toString("utf8");
  } finally { closeSync(fd); }
}

export type StoreFailure = (message: string, statusCode?: number) => Error;

const LOCK_SLEEP = new Int32Array(new SharedArrayBuffer(4));
const randomHex = (bytes: number): string => randomBytes(bytes).toString("hex");

function fsyncDirectory(full: string): void {
  const directory = openSync(dirname(full), "r");
  try { fsyncSync(directory); } finally { closeSync(directory); }
}

/**
 * Write `text` to `path` through a 0600 temp file, fsync, rename, then fsync the directory.
 * It does not create the directory: a caller that wants that does it first.
 */
export function atomicWriteFile(path: string, text: string): void {
  const full = resolve(path);
  const tmp = `${full}.tmp-${process.pid}-${randomHex(4)}`;
  try {
    writeFileSync(tmp, text, { mode: 0o600, flag: "wx" });
    chmodSync(tmp, 0o600);
    const fd = openSync(tmp, "r");
    try { fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, full);
    fsyncDirectory(full);
  } catch (error) {
    try { unlinkSync(tmp); } catch { /* the rename may already have installed it */ }
    throw error;
  }
}

/** Unlink `path` only if it is still the inode `fd` opened, then close `fd`. */
export function discardOwnedPath(path: string, fd: number): void {
  try {
    const owned = fstatSync(fd);
    const current = lstatSync(path);
    if (owned.dev === current.dev && owned.ino === current.ino) unlinkSync(path);
  } catch {
    // If creation failed before the pathname was installed, or another process already removed it,
    // there is no owned lock left to clean up.
  } finally {
    closeSync(fd);
  }
}

/** Explicit one-time provisioning: create `path` with `text`, refusing to overwrite anything. */
export function createExclusiveFile(path: string, text: string, name: string, fail: StoreFailure): void {
  const full = resolve(path);
  mkdirSync(dirname(full), { recursive: true, mode: 0o700 });
  let fd: number;
  try {
    fd = openSync(full, "wx", 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw fail(`refusing to overwrite existing ${name}: ${full}`);
    }
    throw fail(`${full}: cannot initialize ${name}`);
  }
  try {
    writeFileSync(fd, text, "utf8");
    chmodSync(full, 0o600);
    fsyncSync(fd);
  } catch {
    discardOwnedPath(full, fd);
    throw fail(`${full}: cannot initialize ${name}`);
  }
  closeSync(fd);
  fsyncDirectory(full);
}

/**
 * Run `body` while holding `<path>.lock`.
 *
 * Atomic rename protects readers from partial JSON, but it does not protect two writers that both
 * loaded the same old document. The adjacent `O_EXCL` lock covers load → mutate → save as one unit.
 * An existing owner always makes the caller wait and then fail closed. Automatically unlinking a
 * supposedly stale pathname has no compare-and-delete primitive in portable Node: two reclaimers
 * can otherwise delete a newly acquired lock and reintroduce lost updates. After a confirmed crash,
 * an operator must stop every writer and explicitly remove the adjacent `.lock` file.
 */
export function withFileLock<T>(path: string, waitMs: number, name: string, fail: StoreFailure, body: () => T): T {
  const full = resolve(path);
  const lockPath = `${full}.lock`;
  mkdirSync(dirname(full), { recursive: true, mode: 0o700 });
  const owner = JSON.stringify({ pid: process.pid, nonce: randomHex(16), createdAt: Date.now() });
  const deadline = Date.now() + waitMs;
  let fd: number | null = null;

  while (fd === null) {
    let opened: number;
    try {
      opened = openSync(lockPath, "wx", 0o600);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") throw fail(`${full}: cannot lock ${name}`);
      if (Date.now() >= deadline) throw fail(`${full}: ${name} is busy`, 503);
      Atomics.wait(LOCK_SLEEP, 0, 0, 20);
      continue;
    }

    try {
      writeFileSync(opened, owner, "utf8");
      fd = opened;
    } catch {
      // `open("wx")` has already made the pathname visible. If writing the owner record fails,
      // release both the descriptor and that exact inode so restart cannot inherit a poison lock.
      discardOwnedPath(lockPath, opened);
      throw fail(`${full}: cannot initialize ${name} lock`);
    }
  }

  try {
    return body();
  } finally {
    closeSync(fd);
    try {
      if (readFileSync(lockPath, "utf8") === owner) unlinkSync(lockPath);
    } catch {
      // A missing lock cannot make a committed mutation unsafe. A mismatched lock belongs to a
      // later owner and must never be removed here.
    }
  }
}
