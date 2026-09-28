// The zone rule, held against the incident it was written for.
//
// Every assertion below is a sentence about 2026-09-28: three publishes were addressed to three
// VPCs and all three carried one VPC's hosts. The check that would have stopped it is one line, and
// these tests exist so that line cannot be loosened into agreement with whatever it is handed.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { zoneLabelOf, zoneMismatch } from "./site-zone.ts";

/** The six hosts that actually went out under two other VPCs' names. */
const DEV = [
  "gw-01.dev-icn-vtr",
  "k3s-01.dev-icn-vtr",
  "mailer-01.dev-icn-vtr",
  "mailer-02.dev-icn-vtr",
  "mailer-03.dev-icn-vtr",
  "web-01.dev-icn-vtr",
];

describe("a host id's last label", () => {
  it("is the text after the last dot", () => {
    assert.equal(zoneLabelOf("gw-01.prod-icn-vtr"), "prod-icn-vtr");
    // Several dots: the *last* label, not the second. `web-01.dev.example.com` belongs to `com` by
    // this rule, which is why the rule is only ever used to compare against a name someone declared.
    assert.equal(zoneLabelOf("web-01.dev.example.com"), "com");
  });

  it("is absent rather than empty when there is no label", () => {
    // `null`, not `""`. The lenient branch in `zoneMismatch` turns on this distinction, and `""` is
    // a value that would compare equal to a target nobody configured.
    assert.equal(zoneLabelOf("h1"), null);
    assert.equal(zoneLabelOf("gw-01."), null, "a trailing dot is a typo, not a label");
    assert.equal(zoneLabelOf(""), null);
  });
});

describe("whether a rendered site may be published to a target", () => {
  it("accepts hosts that all carry the target's name", () => {
    // The known positive. Without it every refusal below is satisfied by a function that refuses
    // everything, which is a publish outage with a good error message.
    assert.equal(zoneMismatch({ target: "dev-icn-vtr", hostIds: DEV }), null);
    assert.equal(zoneMismatch({ target: "prod-icn-vtr", hostIds: ["gw-01.prod-icn-vtr"] }), null);
  });

  it("refuses the incident: one VPC's hosts addressed to another", () => {
    // 2026-09-28, exactly. dev's six rendered, `prod-icn-vtr` selected, nothing compared them.
    const said = zoneMismatch({ target: "prod-icn-vtr", hostIds: DEV });
    assert.ok(said, "dev's hosts were accepted for prod");
    assert.match(said, /prod-icn-vtr/, "the message does not say which VPC the plan was for");
    assert.match(said, /gw-01\.dev-icn-vtr/, "the message does not name a host that gave it away");
    assert.match(said, /6 of its 6/, "the message does not say how much of the site was wrong");
  });

  it("names a few of the offenders and counts the rest", () => {
    // An operator reads this at the moment a publish is refused. A bare count sends them to a
    // terminal; three ids and a count is enough to recognise the VPC without filling the screen.
    const said = zoneMismatch({ target: "prod-icn-vtr", hostIds: DEV }) ?? "";
    assert.match(said, /and 3 more/);
    assert.equal(/mailer-03/.test(said), false, "every id was listed — the count is doing nothing");
  });

  it("matches the whole last label, not a substring and not a bare ending", () => {
    // Three ways to write this comparison wrong, each one keystroke from the real implementation.
    //
    // `includes(target)`:
    assert.ok(
      zoneMismatch({ target: "prod-icn-vtr", hostIds: ["gw-01.prod-icn-vtr-old"] }),
      "a longer zone that merely contains this one was accepted",
    );
    // `endsWith(target)` for a target that is a suffix of the real label:
    assert.ok(
      zoneMismatch({ target: "icn-vtr", hostIds: ["gw-01.prod-icn-vtr"] }),
      "a suffix of the zone name was accepted",
    );
    // `endsWith(target)` without the dot. This one needs a labelled host beside it, because an id
    // with no dot at all goes to the lenient branch and never reaches the comparison — which is
    // exactly why the obvious probe (`hostIds: ["prod-icn-vtr"]`) proves nothing and was wrong here
    // until this test failed and said so.
    assert.ok(
      zoneMismatch({ target: "dev-icn-vtr", hostIds: ["gw-01.dev-icn-vtr", "xdev-icn-vtr"] }),
      "an id ending in the zone name without the separating dot was accepted",
    );
  });

  it("lets a site that claims no zone through, and says so by doing nothing", () => {
    // The deliberate lenient branch. Fixtures, examples and the real-kernel rollback harness name
    // their hosts `h1` / `h-a` / `h-rb-01`; those sites have not claimed a zone and this function
    // does not invent one for them. See the docblock — read as an oversight, this is the first thing
    // somebody would "fix" into a fleet-wide publish refusal.
    assert.equal(zoneMismatch({ target: "dev", hostIds: ["h1"] }), null);
    assert.equal(zoneMismatch({ target: "rb", hostIds: ["h-rb-01"] }), null);
    assert.equal(zoneMismatch({ target: "anything", hostIds: [] }), null);
  });

  it("switches the whole set into the strict rule as soon as one host claims a zone", () => {
    // The leniency is per-site, not per-host. A site that grows one labelled host must not carry its
    // unlabelled ones along unchecked — that is how a real site would drift into the lenient branch.
    const said = zoneMismatch({ target: "dev-icn-vtr", hostIds: ["h1", "gw-01.dev-icn-vtr"] });
    assert.ok(said, "an unlabelled host rode along beside a labelled one");
    assert.match(said, /h1/);
  });
});
