import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readTrafficView, trafficListing } from "./traffic.ts";

const row = {
  endpoint: "1234",
  direction: "egress",
  peer: "k8s:app=web",
  port: "443/TCP",
  packets: 9,
  bytes: 1200,
};

describe("readTrafficView", () => {
  it("accepts a summary the manager would send", () => {
    const read = readTrafficView({
      entries: 2,
      withTraffic: 1,
      dead: 1,
      top: [row],
      deadSample: [{ ...row, packets: 0, bytes: 0 }],
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.equal(read.view.kind, "summary");
      if (read.view.kind === "summary") {
        assert.equal(read.view.dead, 1);
        assert.equal(read.view.top[0]?.peer, "k8s:app=web");
      }
    }
  });

  it("keeps 'the reader has not produced a dump' apart from an empty summary", () => {
    const read = readTrafficView({ unavailable: "the reader has not produced a dump yet" });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.equal(read.view.kind, "unavailable");
      if (read.view.kind === "unavailable") {
        assert.match(read.view.message, /has not produced a dump/);
      }
    }
  });

  it("does not call an empty dump 'unread'", () => {
    const empty = readTrafficView({ entries: 0, withTraffic: 0, dead: 0, top: [], deadSample: [] });
    const unread = readTrafficView({ unavailable: "the reader has not produced a dump yet" });
    assert.equal(empty.ok && trafficListing(empty.view), "empty");
    assert.equal(unread.ok && trafficListing(unread.view), "unavailable");
  });

  it("refuses a payload that has neither a summary nor an unavailable reason", () => {
    const read = readTrafficView({ top: [], deadSample: [] });
    assert.equal(read.ok, false);
  });
});
