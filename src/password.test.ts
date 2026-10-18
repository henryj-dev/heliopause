import assert from "node:assert/strict";
import { scryptSync } from "node:crypto";
import { describe, it } from "node:test";
import {
  checkPasswordPolicy, dummyVerify, hashPassword, MAX_PASSWORD_BYTES, parseEncodedHash, PasswordBusyError, verifyPassword,
} from "./password.ts";

const PASSWORD = "correct horse battery staple";

/** An encoded hash at lower parameters than the defaults, built without going through the limiter. */
function weakHash(password: string): string {
  const salt = Buffer.alloc(16, 7);
  const dk = scryptSync(password, salt, 32, { N: 1024, r: 8, p: 1 });
  return `scrypt$1024$8$1$${salt.toString("base64url")}$${dk.toString("base64url")}`;
}

describe("password hashing", () => {
  it("encodes scrypt parameters, salt and key, and verifies the right password", async () => {
    const encoded = await hashPassword(PASSWORD);
    assert.match(encoded, /^scrypt\$32768\$8\$1\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/);
    assert.deepEqual(await verifyPassword(PASSWORD, encoded), { ok: true, needsRehash: false });
  });

  it("refuses a wrong password", async () => {
    const encoded = await hashPassword(PASSWORD);
    assert.equal((await verifyPassword(`${PASSWORD}!`, encoded)).ok, false);
  });

  it("salts every hash", async () => {
    assert.notEqual(await hashPassword(PASSWORD), await hashPassword(PASSWORD));
  });

  it("verifies NFKC-equivalent input as the same password", async () => {
    const encoded = await hashPassword("ｃｏｒｒｅｃｔ horse battery");
    assert.equal((await verifyPassword("correct horse battery", encoded)).ok, true);
  });

  it("reads parameters from the stored hash and flags hashes below the defaults", async () => {
    const encoded = weakHash(PASSWORD);
    assert.deepEqual(await verifyPassword(PASSWORD, encoded), { ok: true, needsRehash: true });
    assert.deepEqual(await verifyPassword("wrong password here", encoded), { ok: false, needsRehash: true });
  });

  it("flags a salt shorter than the default", async () => {
    const salt = Buffer.alloc(8, 5);
    const dk = scryptSync(PASSWORD, salt, 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
    const encoded = `scrypt$32768$8$1$${salt.toString("base64url")}$${dk.toString("base64url")}`;
    assert.deepEqual(await verifyPassword(PASSWORD, encoded), { ok: true, needsRehash: true });
  });

  it("accepts parameters just inside the memory and CPU caps", () => {
    const tail = `${"A".repeat(22)}$${"A".repeat(43)}`;
    // Memory: 2·128·7·(2^17 + 3) bytes ≈ 224 MiB, under the 256 MiB cap.
    assert.ok(parseEncodedHash(`scrypt$${2 ** 17}$7$1$${tail}`));
    // CPU: N·r·p = 2^14·32·4 = 2^21, exactly 8× the default.
    assert.ok(parseEncodedHash(`scrypt$${2 ** 14}$32$4$${tail}`));
  });

  it("refuses parameters just outside the memory and CPU caps", () => {
    const tail = `${"A".repeat(22)}$${"A".repeat(43)}`;
    // Memory: 2·128·2·(2^19 + 3) bytes is 1.5 KiB over 256 MiB; N·r·p = 2^20 is under the CPU cap.
    assert.equal(parseEncodedHash(`scrypt$${2 ** 19}$2$1$${tail}`), null);
    // Memory here is ~128 MiB; only the CPU cap refuses it.
    assert.equal(parseEncodedHash(`scrypt$${2 ** 14}$32$8$${tail}`), null);
  });

  it("throws on a malformed or out-of-bounds stored hash", async () => {
    for (const bad of [
      "plain", "scrypt$32768$8$1$short$short",
      `scrypt$3000$8$1$${"A".repeat(22)}$${"A".repeat(43)}`, // N not a power of two
      `scrypt$${2 ** 21}$8$1$${"A".repeat(22)}$${"A".repeat(43)}`, // memory above the bound via N
      `scrypt$${2 ** 20}$32$16$${"A".repeat(22)}$${"A".repeat(43)}`, // memory above the bound
      `scrypt$${2 ** 16}$1$1$${"A".repeat(22)}$${"A".repeat(43)}`, // N ≥ 2^(16·r)
    ]) {
      assert.equal(parseEncodedHash(bad), null, bad);
      await assert.rejects(verifyPassword(PASSWORD, bad), /malformed/);
    }
  });
});

describe("the hash limiter", () => {
  it("a failing call releases its limiter slot", async () => {
    for (let i = 0; i < 3; i += 1) {
      await assert.rejects(verifyPassword(42 as unknown as string, weakHash(PASSWORD)), TypeError);
      await assert.rejects(hashPassword(undefined as unknown as string), TypeError);
    }
    assert.ok(parseEncodedHash(await hashPassword(PASSWORD)));
  });

  it("small N with large r verifies (maxmem covers OpenSSL's estimate)", async () => {
    const salt = Buffer.alloc(16, 3);
    const dk = scryptSync(PASSWORD, salt, 32, { N: 2, r: 8, p: 1 });
    const encoded = `scrypt$2$8$1$${salt.toString("base64url")}$${dk.toString("base64url")}`;
    assert.deepEqual(await verifyPassword(PASSWORD, encoded), { ok: true, needsRehash: true });
  });

  it("refuses a third concurrent hash immediately", async () => {
    const first = hashPassword(PASSWORD);
    const second = verifyPassword(PASSWORD, weakHash(PASSWORD));
    await assert.rejects(hashPassword(PASSWORD), PasswordBusyError);
    await Promise.all([first, second]);
    // Slots are released when the derivations finish.
    await hashPassword(PASSWORD);
  });

  it("dummyVerify spends a scrypt derivation and a limiter slot", async () => {
    const started = performance.now();
    assert.equal(await dummyVerify(PASSWORD), false);
    const dummy = performance.now() - started;
    // A lower bound only: load makes scrypt slower, never faster, so this does not flake under a
    // busy machine. A default-cost derivation took ~55 ms on the machine that wrote this.
    assert.ok(dummy >= 5, `dummyVerify took ${dummy.toFixed(1)}ms`);

    const a = dummyVerify(PASSWORD); const b = dummyVerify(PASSWORD);
    await assert.rejects(dummyVerify(PASSWORD), PasswordBusyError);
    await Promise.all([a, b]);
  });
});

describe("password policy", () => {
  it("accepts 12 code points and refuses 11", () => {
    assert.deepEqual(checkPasswordPolicy("abcdefghijkl"), []);
    assert.deepEqual(checkPasswordPolicy("abcdefghijk"), ["must be at least 12 characters"]);
  });

  it("counts code points, not UTF-16 units, after NFKC", () => {
    // Six astral characters are twelve UTF-16 units and six code points.
    assert.deepEqual(checkPasswordPolicy("😀".repeat(6)), ["must be at least 12 characters"]);
    assert.deepEqual(checkPasswordPolicy("😀".repeat(12)), []);
  });

  it("refuses more than the byte limit", () => {
    assert.deepEqual(checkPasswordPolicy("a".repeat(MAX_PASSWORD_BYTES)), []);
    assert.deepEqual(checkPasswordPolicy("a".repeat(MAX_PASSWORD_BYTES + 1)), [`must be at most ${MAX_PASSWORD_BYTES} bytes`]);
  });

  it("refuses the username or email local part, case-insensitively", () => {
    assert.deepEqual(checkPasswordPolicy("my-HENRY-password", { username: "henry" }), ["must not contain the username"]);
    assert.deepEqual(checkPasswordPolicy("my-jang-password1", { email: "Jang@example.com" }), ["must not contain the email address"]);
  });

  it("ignores a username or local part shorter than three characters", () => {
    assert.deepEqual(checkPasswordPolicy("my-ab-password1", { username: "ab", email: "ab@example.com" }), []);
  });

  it("has no composition rules", () => {
    assert.deepEqual(checkPasswordPolicy("aaaaaaaaaaaa"), []);
  });
});
