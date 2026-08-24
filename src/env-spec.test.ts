import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  boundedInteger, boundedNumber, ENV_BOUNDS, parsePairs, parseRelays, EnvSpecError,
  type BoundedEnvName,
} from "./env-spec.ts";

/**
 * The point of this file is one property that had no test when it was fixed: **a refused entry must
 * not appear in the refusal.** `HELIOPAUSE_OTP_USERS` carries shared OTP secrets, so the message a
 * misconfiguration produces is itself a disclosure surface.
 *
 * Every "does not disclose" case below was checked against the pre-fix behaviour — quoting the
 * entry — and fails there. That is what makes them tests rather than decoration.
 */

/**
 * The stand-in for a secret value. Shaped like one — long, opaque, no `=` — because that shape is
 * what the code under test has to handle, but **it says what it is in the value itself.**
 *
 * The first version of this used the canonical base32 TOTP example string. `gitleaks`, which scans
 * every commit on every push, flagged it as a `generic-api-key` and turned CI red — correctly, on
 * the information it had: a long opaque literal assigned to something called `SECRET` is exactly
 * what it is looking for, and it cannot know a value is fictional. The lesson is the same one this
 * repository already applies to addresses (RFC 5737 ranges) and hostnames (RFC 2606): **a fixture
 * standing in for sensitive data should be self-evidently fake**, so that neither a scanner nor a
 * reader has to decide.
 */
const FAKE_OTP_VALUE = "example-otp-value-not-a-real-secret-000000";

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
    const message = refusal(() => parsePairs(FAKE_OTP_VALUE, "HELIOPAUSE_OTP_USERS"));
    assert.ok(!message.includes(FAKE_OTP_VALUE), `the secret is in the message: ${message}`);
    assert.match(message, /entry 1 is malformed/);
  });

  test("the ordinal says which entry, so the operator can still act", () => {
    const message = refusal(() => parsePairs(`a=1,b=2,${FAKE_OTP_VALUE}`, "HELIOPAUSE_OTP_USERS"));
    assert.match(message, /entry 3 is malformed/);
    assert.ok(!message.includes(FAKE_OTP_VALUE));
  });

  test("an empty value does not name the key either", () => {
    // A transposed entry puts the secret in the key position, and this branch is what catches it —
    // so naming "the key" here would name the secret.
    const message = refusal(() => parsePairs(`${FAKE_OTP_VALUE}=`, "HELIOPAUSE_OTP_USERS"));
    assert.ok(!message.includes(FAKE_OTP_VALUE), `the secret is in the message: ${message}`);
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
    const message = refusal(() => parsePairs(`k=${FAKE_OTP_VALUE},k=other`, "X"));
    assert.ok(!message.includes(FAKE_OTP_VALUE), `the secret is in the message: ${message}`);
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
    assert.equal(parsePairs(`alice=${FAKE_OTP_VALUE}`, "X").get("alice"), FAKE_OTP_VALUE);
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

// ── Numeric settings ──────────────────────────────────────────────────────────
//
// These are not tests about tidy parsing. Each row below is a **measured** behaviour of this
// repository's own code when a numeric environment value came through as `NaN`, and every one of
// them fails open:
//
//   session TTL    `new Date(now + NaN)` is Invalid Date, and `invalid <= now` is false
//                  → a session that may approve and publish never expires
//   plan TTL       `elapsed > NaN` is false
//                  → an approved plan stays publishable forever, which is the thing the window exists to stop
//   max pending    `size >= NaN` is false
//                  → the bound on pending plans is gone
//   reload/refresh `setInterval(fn, NaN)` fires every millisecond
//                  → a gateway re-reads a 16 MB bundle ~875 times a second
//
// So what is pinned here is that an unreadable value **stops the process**, rather than becoming a
// number that quietly means "no limit".
describe("boundedInteger", () => {
  const bounds = { min: 1, max: 100, fallback: 10 };

  test("uses the fallback when unset or blank", () => {
    assert.equal(boundedInteger("X", undefined, bounds), 10);
    assert.equal(boundedInteger("X", "", bounds), 10);
    // `Number(" ")` is 0. Blank means unset, not zero — otherwise an accidentally-cleared variable
    // becomes the most aggressive value in the range rather than the default.
    assert.equal(boundedInteger("X", "   ", bounds), 10);
  });

  test("takes a whole number inside the range", () => {
    assert.equal(boundedInteger("X", "42", bounds), 42);
    assert.equal(boundedInteger("X", " 42 ", bounds), 42);
  });

  test("refuses a value that is not a number at all", () => {
    assert.throws(
      () => boundedInteger("HELIOPAUSE_RELOAD_SEC", "thirty", bounds),
      (e: unknown) =>
        e instanceof EnvSpecError && /HELIOPAUSE_RELOAD_SEC must be a number/.test((e as Error).message),
    );
  });

  test("refuses infinity, which Number() happily produces", () => {
    assert.throws(() => boundedInteger("X", "Infinity", bounds), EnvSpecError);
    assert.throws(() => boundedInteger("X", "-Infinity", bounds), EnvSpecError);
  });

  test("refuses a fraction where a whole number is required", () => {
    assert.throws(
      () => boundedInteger("X", "1.5", bounds),
      (e: unknown) => e instanceof EnvSpecError && /must be a whole number/.test((e as Error).message),
    );
  });

  test("refuses either side of the range", () => {
    assert.throws(() => boundedInteger("X", "0", bounds), /must be between 1 and 100/);
    assert.throws(() => boundedInteger("X", "101", bounds), /must be between 1 and 100/);
  });

  test("names the variable and quotes the value, truncated", () => {
    assert.throws(() => boundedInteger("HELIOPAUSE_PLAN_TTL_SEC", "x".repeat(80), bounds), (e: unknown) => {
      const message = (e as Error).message;
      // The variable, so the operator knows which line to look at. `parsePairs` deliberately does
      // not quote what it refused; these settings hold a port or an interval, never a secret, and
      // an operator who mistyped needs to see what they typed.
      assert.ok(message.includes("HELIOPAUSE_PLAN_TTL_SEC"), message);
      assert.ok(message.includes("…"), message);
      assert.ok(message.length < 130, `message is ${message.length} chars`);
      return true;
    });
  });
});

// ── The bound and the values it will actually judge ───────────────────────────
//
// ## What this exists to stop happening again
//
// `bin/heliopause-relay.ts` had `Math.max(5, reloadSec)` before any of this existed. That is a
// **clamp**: `HELIOPAUSE_RELOAD_SEC=2` was accepted and quietly became 5. Replacing it with a
// refusal that kept the same 5 turned an accepted value into a startup failure — and
// `scripts/rollback-test.sh` sets exactly that 2.
//
// Every unit test passed. So did `typecheck`, `check:web`, the agent suites and the hook suites. The
// job that caught it needs a real kernel and cannot run on a workstation, so the first sign was CI
// going red on `main` eight commits later.
//
// A number written in one file and depended on in another is what made that possible. The bound now
// lives in `ENV_BOUNDS`, and this reads the values the scripts and the env examples actually set and
// puts them through it. It is deliberately a *scan* rather than a list: a list would be a third copy.
describe("the bounds accept what this repository actually configures", () => {
  const root = join(import.meta.dirname, "..");
  const sources = [
    "scripts/rollback-test.sh",
    "scripts/e2e-roundtrip.sh",
    "packaging/manager.env.example",
    "packaging/systemd/relay.env.example",
    "packaging/systemd/agent.env.example",
  ];

  /** `NAME=value` assignments for names the entry points bound, commented-out ones included. */
  function configured(): Array<{ file: string; name: BoundedEnvName; raw: string }> {
    const found: Array<{ file: string; name: BoundedEnvName; raw: string }> = [];
    for (const file of sources) {
      const path = join(root, file);
      if (!existsSync(path)) continue;
      // Matched anywhere on the line, not anchored to its start: a shell script sets several in one
      // command (`HELIOPAUSE_CA_FILE=… HELIOPAUSE_RELOAD_SEC=2 \`), and an anchored pattern finds the
      // first and silently misses the rest — including the one that went red.
      for (const m of readFileSync(path, "utf8").matchAll(/(HELIOPAUSE_[A-Z0-9_]+)=("?)([^\s"\\]*)\2/g)) {
        const name = m[1] as BoundedEnvName;
        // Only the numeric settings, and only a literal: `PORT="$SOME_VAR"` says nothing about a value.
        if (!(name in ENV_BOUNDS) || !/^[0-9]+(\.[0-9]+)?$/.test(m[3]!)) continue;
        found.push({ file, name, raw: m[3]! });
      }
    }
    return found;
  }

  test("the scan finds something, so a passing run means more than an empty loop", () => {
    const rows = configured();
    assert.ok(rows.length >= 5, `only found ${rows.length} configured numeric settings — did the scan break?`);
  });

  test("every value a script or an env example sets is accepted", () => {
    for (const { file, name, raw } of configured()) {
      const bounds = ENV_BOUNDS[name];
      // Fractions are legal for exactly one setting, so the integer form is what the rest get —
      // matching how the entry points read them.
      const read = name === "HELIOPAUSE_PUBLIC_RETRY_SEC" ? boundedNumber : boundedInteger;
      assert.doesNotThrow(
        () => read(name, raw, bounds),
        `${file} sets ${name}=${raw}, which ${name}'s bound (${bounds.min}..${bounds.max}) refuses`,
      );
    }
  });

  test("rollback-test.sh's two-second reload is one of them", () => {
    // Named, not just covered by the sweep. This is the value that went red, and a scan that stopped
    // finding it would go quiet rather than fail.
    const rows = configured();
    const reload = rows.find((r) => r.file.endsWith("rollback-test.sh") && r.name === "HELIOPAUSE_RELOAD_SEC");
    assert.ok(reload, "rollback-test.sh no longer sets HELIOPAUSE_RELOAD_SEC — update this test with it");
    assert.doesNotThrow(() => boundedInteger(reload.name, reload.raw, ENV_BOUNDS[reload.name]));
  });

  test("every default is inside its own range", () => {
    // A fallback that the bound would refuse is a setting that cannot be left unset.
    for (const [name, bounds] of Object.entries(ENV_BOUNDS)) {
      assert.ok(
        bounds.fallback >= bounds.min && bounds.fallback <= bounds.max,
        `${name} defaults to ${bounds.fallback}, outside ${bounds.min}..${bounds.max}`,
      );
    }
  });
});

describe("boundedNumber", () => {
  // `HELIOPAUSE_PUBLIC_RETRY_SEC` is documented as accepting fractions so a test can drive the whole
  // retry ladder without waiting. Two functions rather than a flag, so the call site says which
  // kind of number it is asking for.
  test("accepts a fraction the integer form would refuse", () => {
    assert.equal(boundedNumber("X", "0.05", { min: 0.001, max: 10, fallback: 5 }), 0.05);
    assert.throws(() => boundedInteger("X", "0.05", { min: 0.001, max: 10, fallback: 5 }), EnvSpecError);
  });

  test("still refuses NaN and the range", () => {
    assert.throws(() => boundedNumber("X", "soon", { min: 0, max: 10, fallback: 5 }), EnvSpecError);
    assert.throws(() => boundedNumber("X", "11", { min: 0, max: 10, fallback: 5 }), EnvSpecError);
  });
});
