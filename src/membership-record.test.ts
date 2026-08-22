// The record that lets `membershipJumps` run at all.
//
// That function was written, tested, and could never fire: nothing held the previous generation's
// selector counts. These tests are about the two ways storing them could go wrong — losing the
// comparison, and making the stored numbers look like something they are not.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  countsFrom,
  asPodLists,
  readMembershipRecord,
  writeMembershipRecord,
  MEMBERSHIP_FILE,
} from "./membership-record.ts";
import { membershipJumps } from "./cilium.ts";

const dir = () => mkdtempSync(join(tmpdir(), "hp-mem-"));

const reading = {
  at: "2026-08-11T00:00:00Z",
  namespaces: { "arc-runners": ["a", "b"] },
  labelled: { "app=idp": ["p1"] },
};

describe("flattening a reading to selector counts", () => {
  it("keys the two kinds apart", () => {
    // `arc-runners` as a namespace and `arc-runners` as a label value are different selectors, and a
    // shared key would compare one against the other — a jump reported on a selector that never moved.
    assert.deepEqual(countsFrom(reading), { "k8s-namespace:arc-runners": 2, "k8s-label:app=idp": 1 });
  });

  it("uses the same keys membershipJumps compares", () => {
    // The property that makes the record usable at all. If these disagreed, every selector would look
    // absent on both sides and the check would pass in silence — which is what it did before, for a
    // different reason.
    const before = asPodLists(countsFrom(reading));
    const after = { "k8s-namespace:arc-runners": new Array(40).fill("p"), "k8s-label:app=idp": ["p1"] };
    const jumps = membershipJumps(before, after);
    assert.deepEqual(jumps.map((j) => j.selector), ["k8s-namespace:arc-runners"]);
  });

  it("pads to length rather than storing pod names", () => {
    // Pod names are the fleet's shortest-lived data. Storing them would produce a file that is stale
    // seconds after it is written and reads as a current pod list; the comparison only needs size.
    assert.equal(asPodLists({ s: 3 })["s"]!.length, 3);
  });
});

describe("reading a record back", () => {
  it("round-trips", async () => {
    const d = dir();
    await writeMembershipRecord(d, { generation: "abc1234", at: reading.at, counts: countsFrom(reading) });
    const back = await readMembershipRecord(d);
    assert.equal(back?.generation, "abc1234");
    assert.deepEqual(back?.counts, { "k8s-namespace:arc-runners": 2, "k8s-label:app=idp": 1 });
  });

  it("says undefined when there is no record — the first publish ever", async () => {
    assert.equal(await readMembershipRecord(dir()), undefined);
  });

  it("says undefined rather than throwing on a corrupt file", async () => {
    // A diagnostic that cannot parse must not stop a firewall generation from shipping. The CLI
    // already refuses to let an unreachable observation endpoint block a publish, for the same reason.
    const d = dir();
    writeFileSync(join(d, MEMBERSHIP_FILE), "{ not json", "utf8");
    assert.equal(await readMembershipRecord(d), undefined);
  });

  it("rejects counts that are not finite numbers", async () => {
    // The quiet-pass case. A string count compares as NaN, every comparison is false, and the check
    // reports no jump while looking like it ran — the exact failure mode this file exists to end.
    const d = dir();
    writeFileSync(
      join(d, MEMBERSHIP_FILE),
      JSON.stringify({ generation: "g", at: reading.at, counts: { s: "12" } }),
      "utf8",
    );
    assert.equal(await readMembershipRecord(d), undefined);
  });

  it("rejects a record missing its generation or timestamp", async () => {
    // Both are what make the numbers mean something: which generation they describe, and when they
    // were true. A record without them is a pile of counts.
    const d = dir();
    writeFileSync(join(d, MEMBERSHIP_FILE), JSON.stringify({ counts: { s: 1 } }), "utf8");
    assert.equal(await readMembershipRecord(d), undefined);
  });
});

describe("the whole path — record, read back, compare", () => {
  // What "wired" means, asserted rather than assumed. Every piece of this passed its own test while
  // the check could not fire, because nothing joined them: the function compared, the reading
  // existed, and no one wrote the previous counts down.
  //
  // Measured against the live fleet 2026-08-11: no selector there holds more than 7 pods, so the
  // floor of 10 silences every comparison. That is the check behaving correctly and it is also why
  // a live run proves nothing — the numbers here are the ones that would matter.
  it("reports a selector that widened, from a record written by a previous publish", async () => {
    const d = dir();
    await writeMembershipRecord(d, {
      generation: "prev123",
      at: "2026-08-11T00:00:00Z",
      counts: { "k8s-namespace:arc-runners": 2 },
    });
    const previous = await readMembershipRecord(d);
    const now = { at: "2026-08-11T09:00:00Z", namespaces: { "arc-runners": new Array(40).fill("p") }, labelled: {} };

    const jumps = membershipJumps(asPodLists(previous!.counts), asPodLists(countsFrom(now)));
    assert.equal(jumps.length, 1);
    assert.equal(jumps[0]!.selector, "k8s-namespace:arc-runners");
    assert.equal(jumps[0]!.before, 2);
    assert.equal(jumps[0]!.after, 40);
  });

  it("stays silent when the same selector merely fills up normally", async () => {
    // The known negative, at the size the live fleet actually produces. A CI namespace going 2 → 7 is
    // a working day, and an alarm that fires on it is one nobody reads by the second week.
    const d = dir();
    await writeMembershipRecord(d, {
      generation: "prev123",
      at: "2026-08-11T00:00:00Z",
      counts: { "k8s-namespace:cert-sync": 2 },
    });
    const previous = await readMembershipRecord(d);
    const now = { at: "2026-08-11T09:00:00Z", namespaces: { "cert-sync": new Array(7).fill("p") }, labelled: {} };
    assert.deepEqual(membershipJumps(asPodLists(previous!.counts), asPodLists(countsFrom(now))), []);
  });
});
