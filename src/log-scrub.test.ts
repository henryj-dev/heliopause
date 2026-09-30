// Every claim in `log-scrub.ts`'s doc comment has a case here, because that file's whole subject is a
// property, and a property stated without a test is how five review rounds of this PR were spent.
//
// WARNING: nothing in this file may contain a literal U+2028 or U+2029. Both are `LineTerminator` in
// ECMAScript, so one inside a regex literal terminates the literal: writing these cases as characters
// made this file fail to parse with `Invalid regular expression: missing /` — the property under test
// breaking the test for it. They are built with `String.fromCharCode` below for that reason.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { oneLine } from "./log-scrub.ts";

const LS = String.fromCharCode(0x2028);
const PS = String.fromCharCode(0x2029);
const ESC = String.fromCharCode(0x1b);
const MARK = String.fromCharCode(0xfffd);
const ENDS_A_LINE = new RegExp(`[\\r\\n${LS}${PS}]`);

describe("text from an untrusted party cannot become a second log line", () => {
  it("replaces every character that ends a line", () => {
    // A lone `\r` ends a line, so a pattern written as `/\n+/` lets it through — which is what the
    // renderer's own earlier copy did, with no test to notice.
    for (const ch of ["\n", "\r", "\r\n", LS, PS]) {
      const got = oneLine(`boom${ch}[policy-render] verified prod — 12 hosts`);
      assert.doesNotMatch(got, ENDS_A_LINE, `${JSON.stringify(ch)} survived`);
      assert.ok(got.startsWith(`boom${MARK}`), `${JSON.stringify(ch)} unmarked: ${JSON.stringify(got)}`);
      assert.ok(got.endsWith("12 hosts"), "the text after the break was lost");
    }
  });

  it("replaces the escapes that let a message repaint a line it did not write", () => {
    // `ESC[2K ESC[1A` erases the current line and moves up one, so the next write lands on top of
    // whatever the process said before. No newline required.
    const got = oneLine(`boom${ESC}[2K${ESC}[1A[policy-render] verified prod — 12 hosts`);
    assert.ok(!got.includes(ESC), "an ANSI escape survived");
    assert.ok(got.startsWith(`boom${MARK}`));
  });

  it("replaces a tab, which is the forgery primitive in anything column-aligned", () => {
    assert.equal(oneLine("a\tb"), `a${MARK}b`);
  });

  it("leaves ordinary text, including non-ASCII, exactly alone", () => {
    // The known negative. Without it every assertion above is satisfied by a function that mangles
    // everything, and this is the text an operator actually has to read.
    const plain = "the policy module could not be evaluated: 존 이름이 어긋납니다 — gw-01.prod";
    assert.equal(oneLine(plain), plain);
  });

  it("caps length without splitting a surrogate pair", () => {
    // The cap's input is attacker-chosen, so its length is too: a module can pick padding that puts
    // the cut inside an emoji, and a plain `slice` then yields a lone high surrogate.
    const got = oneLine("a".repeat(9) + "\u{1F642}".repeat(4), 10);
    assert.equal([...got].length, 10, "the cap did not hold");
    // `encodeURIComponent` throws `URIError` on a lone surrogate, which is the portable way to ask
    // this — `String.prototype.isWellFormed` needs an es2024 lib and this tree targets lower.
    assert.doesNotThrow(() => encodeURIComponent(got), `cut inside a surrogate pair: ${JSON.stringify(got)}`);
    assert.equal(oneLine("short", 10), "short", "a short string was touched");
  });

  it("flattens before it slices, so a cut cannot manufacture a line break", () => {
    // Only one order is safe: slicing first could end a line mid-escape and leave a real newline as
    // the last character of the output.
    assert.doesNotMatch(oneLine("a\nb".repeat(50), 20), ENDS_A_LINE);
  });
});
