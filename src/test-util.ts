// Assertion helpers for the test suite.
//
// `node:assert` covers everything here except substring matching, which the tests use heavily —
// most failures in this codebase are reported as a *reason string* (which host is blocking a
// rollout, which certificate did not match, which baseline a policy would have overridden), and
// asserting on those is how the tests pin that operators get told something useful.
//
// `assert.ok(s.includes(x))` would do the job but reports "Expected values to be truthy", which
// tells you nothing about what the string actually was. One helper is cheaper than losing that.

import assert from "node:assert/strict";

/**
 * Assert `haystack` contains `needle`, reporting both when it does not.
 *
 * Takes `unknown` because most call sites pass an optional field — a reason that may be absent is
 * exactly the case worth catching, and `String(undefined)` fails the check rather than throwing a
 * TypeError that would obscure which assertion broke.
 */
export function contains(haystack: unknown, needle: string): void {
  const s = String(haystack);
  assert.ok(
    s.includes(needle),
    `expected ${JSON.stringify(s)} to contain ${JSON.stringify(needle)}`,
  );
}

/**
 * Assert `haystack` does **not** contain `needle`.
 *
 * The negative cases are the load-bearing ones in the renderer tests — that no `forward` hook is
 * ever emitted, that an unrestricted policy renders no source match. Printing the offending text
 * matters more here than in the positive case, because "it contains something it should not" is
 * useless without seeing what.
 */
export function excludes(haystack: unknown, needle: string): void {
  const s = String(haystack);
  assert.ok(
    !s.includes(needle),
    `expected ${JSON.stringify(s)} not to contain ${JSON.stringify(needle)}`,
  );
}

/** Assert `earlier` appears before `later` in `text`. Both must be present. */
export function ordered(text: string, earlier: string, later: string): void {
  const a = text.indexOf(earlier);
  const b = text.indexOf(later);
  assert.ok(a !== -1, `expected to find ${JSON.stringify(earlier)}`);
  assert.ok(b !== -1, `expected to find ${JSON.stringify(later)}`);
  assert.ok(a < b, `expected ${JSON.stringify(earlier)} to appear before ${JSON.stringify(later)}`);
}
