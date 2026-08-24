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

describe("the rules the layer ruled out", () => {
  const hit = {
    id: "MESH", name: "mesh", action: "allow", denyMode: "drop", proto: "tcp", ports: "5432",
    priority: 100, enabled: true, layer: "workload",
    src: { kind: "no", why: "on the workload layer a CIDR names no pod" },
    dst: { kind: "matches" }, port: { kind: "matches" }, proto_: { kind: "matches" },
  };
  const base = { matches: [], undecidable: [], needsWorkload: 0, considered: 1 };

  it("carries the section through", () => {
    const read = readLookupView({ ...base, ruledOutByLayer: [hit] });
    assert.equal(read.ok, true);
    if (read.ok) assert.deepEqual(read.view.ruledOutByLayer.map((h) => h.id), ["MESH"]);
  });

  it("accepts an answer from a manager that predates the section", () => {
    // Absent, not empty. Refusing the whole answer over a section that did not exist yet would take
    // the screen away in order to add a paragraph to it.
    const read = readLookupView(base);
    assert.equal(read.ok, true);
    if (read.ok) assert.deepEqual(read.view.ruledOutByLayer, []);
  });

  it("refuses a section that is there and malformed", () => {
    // Present and wrong is not the same as absent — that is a manager sending something this cannot
    // read, and rendering half of it would be worse than saying so.
    assert.equal(readLookupView({ ...base, ruledOutByLayer: "nope" }).ok, false);
    assert.equal(readLookupView({ ...base, ruledOutByLayer: [{ id: "X" }] }).ok, false);
  });
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
