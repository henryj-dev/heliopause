import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { parsePairs, parseRelays, EnvSpecError } from "./env-spec.ts";

/**
 * The point of this file is one property that had no test when it was fixed: **a refused entry must
 * not appear in the refusal.** `HELIOPAUSE_OTP_USERS` carries shared OTP secrets, so the message a
 * misconfiguration produces is itself a disclosure surface.
 *
 * Every "does not disclose" case below was checked against the pre-fix behaviour — quoting the
 * entry — and fails there. That is what makes them tests rather than decoration.
 */

/** A value shaped like a real TOTP secret, so a leak is unmistakable in the assertion output. */
const SECRET = "JBSWY3DPEHPK3PXPTOTPSECRET";

const refusal = (fn: () => unknown): string => {
  try {
    fn();
  } catch (error) {
    assert.ok(error instanceof EnvSpecError, `expected EnvSpecError, got ${String(error)}`);
    return (error as Error).message;
  }
  return assert.fail("expected a refusal, got none");
};

describe("parsePairs refuses without quoting what it refused", () => {
  test("an entry with no '=' is refused by position, not by content", () => {
    // How a secret gets here: a secret containing a comma is split by the comma, and the half
    // without the `=` arrives as its own entry.
    const message = refusal(() => parsePairs(SECRET, "HELIOPAUSE_OTP_USERS"));
    assert.ok(!message.includes(SECRET), `the secret is in the message: ${message}`);
    assert.match(message, /entry 1 is malformed/);
  });

  test("the ordinal says which entry, so the operator can still act", () => {
    const message = refusal(() => parsePairs(`a=1,b=2,${SECRET}`, "HELIOPAUSE_OTP_USERS"));
    assert.match(message, /entry 3 is malformed/);
    assert.ok(!message.includes(SECRET));
  });

  test("an empty value does not name the key either", () => {
    // A transposed entry puts the secret in the key position, and this branch is what catches it —
    // so naming "the key" here would name the secret.
    const message = refusal(() => parsePairs(`${SECRET}=`, "HELIOPAUSE_OTP_USERS"));
    assert.ok(!message.includes(SECRET), `the secret is in the message: ${message}`);
    assert.match(message, /entry 1 has an empty value/);
  });

  test("the two refusals stay distinguishable", () => {
    const noEquals = refusal(() => parsePairs("nope", "X"));
    const emptyValue = refusal(() => parsePairs("k=", "X"));
    assert.notEqual(noEquals, emptyValue);
    assert.match(noEquals, /malformed/);
    assert.match(emptyValue, /empty value/);
  });

  test("a leading '=' is malformed rather than an empty key", () => {
    assert.match(refusal(() => parsePairs("=v", "X")), /entry 1 is malformed/);
  });

  test("the duplicate-key message may name the key, because by then it is a key", () => {
    // Reaching this branch means the entry parsed, so the quoted half is the key half — and naming
    // it is the only way to say which one repeats.
    assert.match(refusal(() => parsePairs("a=1,a=2", "X")), /"a" is declared twice/);
  });

  test("a duplicate never discloses either value", () => {
    const message = refusal(() => parsePairs(`k=${SECRET},k=other`, "X"));
    assert.ok(!message.includes(SECRET), `the secret is in the message: ${message}`);
  });
});

describe("parsePairs parses what it should", () => {
  test("pairs, trimmed, in order", () => {
    const got = parsePairs(" a = 1 , b=2 ", "X");
    assert.deepEqual([...got], [["a", "1"], ["b", "2"]]);
  });

  test("an empty spec is an empty map, not a refusal", () => {
    // Every caller passes `?? ""` for an unset variable, so "unset" has to mean "none configured".
    assert.equal(parsePairs("", "X").size, 0);
    assert.equal(parsePairs("  ,  ", "X").size, 0);
  });

  test("a value may contain '=' — only the first one splits", () => {
    // `HELIOPAUSE_OIDC_ALIASES` and config strings both rely on this.
    assert.deepEqual([...parsePairs("a.b=c=d", "X")], [["a.b", "c=d"]]);
  });

  test("a value may look like a secret and is returned intact", () => {
    assert.equal(parsePairs(`alice=${SECRET}`, "X").get("alice"), SECRET);
  });
});

describe("parseRelays", () => {
  test("three fields per entry, named", () => {
    const got = parseRelays("dev=https://192.0.2.1:8443=./pki,prod=https://192.0.2.2:8443=./pki-prod");
    assert.deepEqual(got, [
      { name: "dev", url: "https://192.0.2.1:8443", pkiDir: "./pki" },
      { name: "prod", url: "https://192.0.2.2:8443", pkiDir: "./pki-prod" },
    ]);
  });

  test("plain http is refused rather than upgraded", () => {
    // The site view names every host in the fleet and travels over this connection.
    assert.match(
      refusal(() => parseRelays("dev=http://192.0.2.1:8443=./pki")),
      /must be https/,
    );
  });

  test("a missing field is refused", () => {
    assert.match(refusal(() => parseRelays("dev=https://192.0.2.1:8443")), /malformed relay entry/);
    assert.match(refusal(() => parseRelays("dev==./pki")), /malformed relay entry/);
  });

  test("an empty spec is refused, because there would be nothing to aggregate", () => {
    // Unlike parsePairs: a manager with no relays has no reason to start.
    assert.match(refusal(() => parseRelays("")), /is empty/);
  });
});
