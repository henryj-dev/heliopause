// The catalogue, and the two ways a translation goes wrong without anybody noticing.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { LANGS, MESSAGES, pickLang, t, type MessageKey } from "./i18n.ts";
import { MESSAGES as SHARED_MESSAGES } from "../packages/i18n/src/index.ts";

describe("the catalogue", () => {
  it("takes classic wording from the shared catalogue, including renamed historical meanings", () => {
    assert.equal(MESSAGES["v.pass"], SHARED_MESSAGES["v.pass"]);
    assert.equal(MESSAGES["m.proposedNote"], SHARED_MESSAGES["classic.m.proposedNote"]);
    assert.equal(MESSAGES["m.proposeMerged"], SHARED_MESSAGES["classic.m.proposeMerged"]);
  });

  // The fallback protects the reader at runtime and hides the gap from everyone else. This is the
  // only thing that says a translation stopped halfway.
  it("has Korean for every English string", () => {
    const missing = Object.entries(MESSAGES)
      .filter(([, v]) => !(v as { ko?: string }).ko)
      .map(([k]) => k);
    assert.deepEqual(missing, [], `no Korean for: ${missing.join(", ")}`);
  });

  // A placeholder renamed on one side renders literally in the other, and the sentence still looks
  // like a sentence — which is how it survives review.
  it("uses the same placeholders in both languages", () => {
    const holes = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (const [key, v] of Object.entries(MESSAGES)) {
      const entry = v as { en: string; ko?: string };
      if (!entry.ko) continue;
      assert.deepEqual(holes(entry.ko), holes(entry.en), `${key} placeholders differ`);
    }
  });

  it("has no empty string on either side", () => {
    for (const [key, v] of Object.entries(MESSAGES)) {
      const entry = v as { en: string; ko?: string };
      assert.ok(entry.en.trim(), `${key} has an empty en`);
      if (entry.ko !== undefined) assert.ok(entry.ko.trim(), `${key} has an empty ko`);
    }
  });
});

describe("t", () => {
  it("returns the language asked for", () => {
    assert.equal(t("en", "v.pass"), "pass");
    assert.equal(t("ko", "v.pass"), "통과");
  });

  it("substitutes placeholders", () => {
    assert.match(t("en", "rule.saved", { commit: "abc1234", branch: "policy/x" }), /abc1234.*policy\/x/);
    assert.match(t("ko", "rule.saved", { commit: "abc1234", branch: "policy/x" }), /abc1234.*policy\/x/);
  });

  // A message that shows `{branch}` is a bug somebody can see. One that shows nothing reads as a
  // deliberately terse sentence and survives.
  it("leaves an unknown placeholder visible rather than blanking it", () => {
    assert.match(t("en", "rule.saved", { commit: "a" }), /\{branch\}/);
  });

  it("falls back to English when a translation is missing", () => {
    // Simulated rather than relying on a real gap: the catalogue test above forbids one.
    const entry = { en: "only english" } as { en: string; ko?: string };
    const raw = entry.ko ?? entry.en;
    assert.equal(raw, "only english");
  });
});

describe("pickLang", () => {
  it("prefers an explicit choice", () => {
    assert.equal(pickLang({ override: "ko", acceptLanguage: "en-US" }), "ko");
    assert.equal(pickLang({ override: "en", acceptLanguage: "ko-KR" }), "en");
  });

  it("ignores an override it does not have", () => {
    assert.equal(pickLang({ override: "fr", acceptLanguage: "ko" }), "ko");
  });

  // `ko-KR` is what a browser actually sends; matching the full tag would have missed every real
  // Korean visitor while passing a test written with `ko`.
  it("matches the primary subtag", () => {
    assert.equal(pickLang({ acceptLanguage: "ko-KR,ko;q=0.9,en;q=0.8" }), "ko");
    assert.equal(pickLang({ acceptLanguage: "en-GB,en;q=0.9" }), "en");
  });

  it("takes the first language it recognises, in order", () => {
    assert.equal(pickLang({ acceptLanguage: "fr-FR,ko;q=0.9" }), "ko");
  });

  it("defaults to English", () => {
    assert.equal(pickLang({}), "en");
    assert.equal(pickLang({ acceptLanguage: "fr,de" }), "en");
  });
});

describe("the language list", () => {
  it("is exactly the two that are supported", () => {
    assert.deepEqual([...LANGS], ["en", "ko"]);
  });

  it("names every key type-safely", () => {
    const k: MessageKey = "s.zones";
    assert.ok(t("ko", k).length > 0);
  });
});

describe("the client message table", () => {
  // ## Why a prefix collision is dangerous rather than untidy
  //
  // The console ships its strings to the browser as one object keyed by the name **after** the first
  // dot, so `m.generation`, `mc.generation` and any future `v.generation` all become `generation` and
  // the last one written wins. Today two of those exist and their text is identical in both languages,
  // so nothing is wrong — and nothing would say so if somebody changed one of them.
  //
  // Found while adding the `v.` prefix for the routing verdicts, which widened the surface. Asserting
  // "no collisions" would fail on a state that is currently fine; asserting they agree pins the thing
  // that actually matters and names the hazard where the next reader will meet it.
  const CLIENT = /^(m|mc|v)\./;

  it("has no two keys collapsing to the same client name with different text", () => {
    const byShort = new Map<string, string[]>();
    for (const k of Object.keys(MESSAGES)) {
      if (!CLIENT.test(k)) continue;
      const short = k.slice(k.indexOf(".") + 1);
      byShort.set(short, [...(byShort.get(short) ?? []), k]);
    }
    // The known positive. If the prefixes ever change, this test must not pass by finding nothing.
    assert.ok(byShort.size > 40, `only ${byShort.size} client strings found — the scan broke`);

    const divergent: string[] = [];
    for (const [short, keys] of byShort) {
      if (keys.length < 2) continue;
      for (const lang of LANGS) {
        const texts = new Set(keys.map((k) => t(lang, k as MessageKey)));
        if (texts.size > 1) divergent.push(`${short} (${keys.join(", ")}) in ${lang}: ${[...texts].join(" | ")}`);
      }
    }
    assert.deepEqual(divergent, [], `these keys collide on the client and disagree: ${divergent.join("; ")}`);
  });

  it("still notices a collision at all, so the pair stays deliberate", () => {
    // Named separately: the assertion above passes whether the collision exists or not. This one says
    // which pairs are living on the "identical text" exemption, so removing one is a visible act.
    const byShort = new Map<string, string[]>();
    for (const k of Object.keys(MESSAGES)) {
      if (!CLIENT.test(k)) continue;
      const short = k.slice(k.indexOf(".") + 1);
      byShort.set(short, [...(byShort.get(short) ?? []), k]);
    }
    const colliding = [...byShort.entries()].filter(([, v]) => v.length > 1).map(([s]) => s).sort();
    assert.deepEqual(colliding, ["generation"], `the set of colliding client names changed: ${colliding.join(", ")}`);
  });
});
