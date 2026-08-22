import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  coveringUsages,
  exactUsages,
  lookupSearch,
  readLookupView,
  readWhereUsedView,
  remainingUndecidable,
  replayLookupLang,
  type LookupHit,
  type Usage,
  verdictWhy,
} from "./lookup.ts";

const matchHit = (over: Partial<LookupHit> = {}): LookupHit => ({
  id: "p-1",
  name: "allow web",
  action: "allow",
  layer: "host",
  proto: "tcp",
  ports: "443",
  priority: 100,
  src: { kind: "matches" },
  dst: { kind: "matches" },
  port: { kind: "matches" },
  proto_: { kind: "matches" },
  ...over,
});

const usage = (over: Partial<Usage> = {}): Usage => ({
  policyId: "p-1",
  where: "src",
  text: "cidr 10.0.0.0/8",
  action: "allow",
  layer: "host",
  enabled: true,
  match: "exact",
  ...over,
});

describe("readLookupView", () => {
  it("accepts the two lists the manager would send", () => {
    const read = readLookupView({
      matches: [matchHit()],
      undecidable: [matchHit({
        id: "p-2",
        src: { kind: "undecidable", why: "names a workload", needsWorkload: true },
      })],
      needsWorkload: 1,
      considered: 12,
      generation: "abc1234",
      dirty: false,
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.equal(read.view.matches[0]?.id, "p-1");
      assert.equal(read.view.needsWorkload, 1);
      assert.equal(read.view.generation, "abc1234");
    }
  });

  it("refuses a payload that folds undecidable into nothing", () => {
    const read = readLookupView({ matches: [], considered: 0, needsWorkload: 0 });
    assert.equal(read.ok, false);
  });
});

describe("readWhereUsedView", () => {
  it("accepts usages and the naming candidates", () => {
    const read = readWhereUsedView({
      query: "10.0.0.0/8",
      usages: [usage()],
      repeated: [{ value: "10.0.0.0/8", count: 2, policyIds: ["p-1", "p-2"] }],
      considered: 12,
      generation: "abc1234",
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.equal(read.view.usages[0]?.policyId, "p-1");
      assert.equal(read.view.repeated[0]?.count, 2);
    }
  });

  it("keeps an empty query as empty usages, not as a missing list", () => {
    const read = readWhereUsedView({
      query: "",
      usages: [],
      repeated: [{ value: "10.0.0.0/8", count: 2, policyIds: ["p-1", "p-2"] }],
      considered: 12,
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.deepEqual(read.view.usages, []);
      assert.equal(read.view.repeated.length, 1);
    }
  });
});

describe("lookup helpers", () => {
  it("builds the same query string the old console sent", () => {
    assert.equal(
      lookupSearch({
        src: " 10.0.0.5 ",
        dst: "10.0.0.6",
        srcWorkload: "",
        dstWorkload: "ns/k=v",
        port: "443",
        proto: "tcp",
      }),
      "src=10.0.0.5&dst=10.0.0.6&srcWorkload=&dstWorkload=ns%2Fk%3Dv&port=443&proto=tcp",
    );
  });

  it("carries the language the chrome is in", () => {
    assert.match(
      lookupSearch({
        src: "10.0.0.5",
        dst: "10.0.0.6",
        srcWorkload: "",
        dstWorkload: "",
        port: "443",
        proto: "tcp",
        lang: "ko",
      }),
      /lang=ko/,
    );
  });

  it("replays the last lookup in a new language, and not when the language did not change", () => {
    assert.equal(replayLookupLang(null, "ko"), null);
    const last = {
      src: "10.0.0.5",
      dst: "10.0.0.6",
      srcWorkload: "",
      dstWorkload: "",
      port: "443",
      proto: "tcp",
      lang: "en",
    };
    assert.equal(replayLookupLang(last, "ko")?.lang, "ko");
    assert.equal(replayLookupLang(last, "en"), null);
  });

  it("lists only the undecidable remainder, and says why a hit deferred", () => {
    const deferred = matchHit({
      id: "p-fix",
      src: { kind: "undecidable", why: "names a workload", needsWorkload: true },
    });
    const rest = matchHit({
      id: "p-rest",
      dst: { kind: "undecidable", why: "IPv6 object" },
    });
    assert.deepEqual(remainingUndecidable([deferred, rest]).map((h) => h.id), ["p-rest"]);
    assert.equal(verdictWhy(deferred.src), "names a workload");
    assert.equal(verdictWhy(matchHit().src), "");
  });

  it("splits exact writes from covering ranges", () => {
    const exact = usage({ match: "exact" });
    const cover = usage({ match: "contains", text: "cidr 10.0.0.0/8" });
    assert.deepEqual(exactUsages([exact, cover]), [exact]);
    assert.deepEqual(coveringUsages([exact, cover]), [cover]);
  });
});
