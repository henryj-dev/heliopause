import assert from "node:assert/strict";
import { scryptSync } from "node:crypto";
import { describe, it } from "node:test";
import {
  checkPasswordPolicy, dummyVerify, hashPassword, parseEncodedHash, PasswordBusyError, SCRYPT_DEFAULTS, verifyPassword,
} from "./password.ts";

const PASSWORD = "Correct horse battery staple";
const CLASSES = "must use at least 3 of: lowercase letters, uppercase letters, digits, other characters";

/** An encoded hash at lower parameters than the defaults, built without going through the limiter. */
function weakHash(password: string): string {
  const salt = Buffer.alloc(16, 7);
  const dk = scryptSync(password, salt, 32, { N: 1024, r: 8, p: 1 });
  return `scrypt$1024$8$1$${salt.toString("base64url")}$${dk.toString("base64url")}`;
}

describe("password hashing", () => {
  it("encodes scrypt parameters, salt and key, and verifies the right password", async () => {
    const encoded = await hashPassword(PASSWORD);
    // N=2^16, r=8, p=2, a 16-byte salt and a 32-byte key.
    assert.match(encoded, /^scrypt\$65536\$8\$2\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/);
    assert.deepEqual(SCRYPT_DEFAULTS, { N: 65536, r: 8, p: 2, keylen: 32, saltBytes: 16 });
    assert.deepEqual(await verifyPassword(PASSWORD, encoded), { ok: true, needsRehash: false });
  });

  it("refuses a wrong password", async () => {
    const encoded = await hashPassword(PASSWORD);
    assert.equal((await verifyPassword(`${PASSWORD}!`, encoded)).ok, false);
  });

  it("salts every hash", async () => {
    assert.notEqual(await hashPassword(PASSWORD), await hashPassword(PASSWORD));
  });

  it("verifies NFC-equivalent input as the same password, and not NFKC-only equivalents", async () => {
    // "é" precomposed (U+00E9) and decomposed (e + U+0301) are one password under NFC.
    const encoded = await hashPassword("Caf\u00e9 horse battery");
    assert.equal((await verifyPassword("Cafe\u0301 horse battery", encoded)).ok, true);
    // Full-width letters are equal only under NFKC, which is no longer applied.
    const wide = await hashPassword("\uff43\uff4f\uff52\uff52\uff45\uff43\uff54 Horse 1");
    assert.equal((await verifyPassword("correct Horse 1", wide)).ok, false);
  });

  it("flags a hash at the previous default (2^15, 8, 1) for rehash", async () => {
    const salt = Buffer.alloc(16, 9);
    const dk = scryptSync(PASSWORD, salt, 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
    const encoded = `scrypt$32768$8$1$${salt.toString("base64url")}$${dk.toString("base64url")}`;
    assert.deepEqual(await verifyPassword(PASSWORD, encoded), { ok: true, needsRehash: true });
  });

  it("reads parameters from the stored hash and flags hashes below the defaults", async () => {
    const encoded = weakHash(PASSWORD);
    assert.deepEqual(await verifyPassword(PASSWORD, encoded), { ok: true, needsRehash: true });
    assert.deepEqual(await verifyPassword("wrong password here", encoded), { ok: false, needsRehash: true });
  });

  it("flags a salt shorter than the default", async () => {
    const salt = Buffer.alloc(8, 5);
    const dk = scryptSync(PASSWORD, salt, 32, { N: 2 ** 16, r: 8, p: 2, maxmem: 256 * 1024 * 1024 });
    const encoded = `scrypt$65536$8$2$${salt.toString("base64url")}$${dk.toString("base64url")}`;
    assert.deepEqual(await verifyPassword(PASSWORD, encoded), { ok: true, needsRehash: true });
  });

  it("accepts parameters just inside the memory and CPU caps", () => {
    const tail = `${"A".repeat(22)}$${"A".repeat(43)}`;
    // Memory: 2·128·7·(2^17 + 3) bytes ≈ 224 MiB, under the 256 MiB cap.
    assert.ok(parseEncodedHash(`scrypt$${2 ** 17}$7$1$${tail}`));
    // CPU: N·r·p = 2^14·32·4 = 2^21, the cap: 2× the default (2^20).
    assert.ok(parseEncodedHash(`scrypt$${2 ** 14}$32$4$${tail}`));
    // The defaults themselves, with room under both caps.
    assert.ok(parseEncodedHash(`scrypt$${2 ** 16}$8$2$${tail}`));
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
  it("accepts 8 code points and refuses 7", () => {
    assert.deepEqual(checkPasswordPolicy("Abcdef1g"), []);
    assert.deepEqual(checkPasswordPolicy("Abcde1g"), ["must be at least 8 characters"]);
  });

  it("counts code points, not UTF-16 units, after NFC", () => {
    // Four astral characters are eight UTF-16 units and four code points.
    assert.deepEqual(checkPasswordPolicy("Ab1" + "😀".repeat(4)), ["must be at least 8 characters"]);
    assert.deepEqual(checkPasswordPolicy("Ab1" + "😀".repeat(5)), []);
    // "e" + U+0301 composes to one code point under NFC: 8 units, 7 code points.
    assert.deepEqual(checkPasswordPolicy("Abcde1e\u0301"), ["must be at least 8 characters"]);
  });

  it("needs three of the four classes", () => {
    assert.deepEqual(checkPasswordPolicy("abcdefgh"), [CLASSES]);
    assert.deepEqual(checkPasswordPolicy("abcdEFGH"), [CLASSES]);
    assert.deepEqual(checkPasswordPolicy("abcd1234"), [CLASSES]);
    assert.deepEqual(checkPasswordPolicy("abcdEF12"), []);
    assert.deepEqual(checkPasswordPolicy("abcdef1!"), []);
    assert.deepEqual(checkPasswordPolicy("ABCDEF1!"), []);
    assert.deepEqual(checkPasswordPolicy("abc"), ["must be at least 8 characters", CLASSES]);
  });

  it("counts Hangul, accented letters and spaces as other characters", () => {
    // Hangul is a letter, but not an ASCII one: lowercase + other is two classes, + digit is three.
    assert.deepEqual(checkPasswordPolicy("password한글"), [CLASSES]);
    assert.deepEqual(checkPasswordPolicy("password한글1"), []);
    // A space is "other".
    assert.deepEqual(checkPasswordPolicy("pass word"), [CLASSES]);
    assert.deepEqual(checkPasswordPolicy("Pass word"), []);
    // Uppercase outside ASCII is not uppercase: "É" is other, like "é".
    assert.deepEqual(checkPasswordPolicy("passwordÉé"), [CLASSES]);
    // All-Hangul is one class however long.
    assert.deepEqual(checkPasswordPolicy("비밀번호비밀번호"), [CLASSES]);
  });

  it("has no maximum length and no username or email rule", () => {
    assert.deepEqual(checkPasswordPolicy("Aa1" + "x".repeat(100_000)), []);
  });

  it("refuses a password with an unpaired surrogate", () => {
    assert.deepEqual(checkPasswordPolicy("Abcdefg1\ud800"), ["must be valid Unicode text (no unpaired surrogates)"]);
    assert.deepEqual(checkPasswordPolicy("Abcdefg1\udc00x"), ["must be valid Unicode text (no unpaired surrogates)"]);
    // A paired surrogate is a character like any other.
    assert.deepEqual(checkPasswordPolicy("Abcdefg1\ud83d\ude00"), []);
  });
});
