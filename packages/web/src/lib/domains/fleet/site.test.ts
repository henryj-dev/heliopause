import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readSiteView } from "./site.ts";

describe("readSiteView", () => {
  it("accepts a site the manager would send", () => {
    const read = readSiteView({
      asked: 1,
      reachable: 1,
      vpcs: [{ name: "dev", url: "https://10.0.0.1:8443", ok: true }],
      hosts: [{
        vpc: "dev",
        host: "gw-01.dev",
        state: "confirmed",
        generation: "abc",
        current: true,
        drifted: false,
        ageSec: 4,
        stage: "canary",
        blockedBy: null,
        maintenance: null,
      }],
      problems: ["dev: k8s-a1.dev drifted"],
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.equal(read.site.hosts[0]?.host, "gw-01.dev");
      assert.equal(read.site.hosts[0]?.stage, "canary");
      assert.deepEqual(read.site.problems, ["dev: k8s-a1.dev drifted"]);
      assert.equal(read.site.hosts[0]?.unexpectedFilters, null);
      assert.equal(read.site.hosts[0]?.intrusions, null);
      assert.equal(read.site.hosts[0]?.publishedPorts, null);
      assert.equal(read.site.hosts[0]?.routes, null);
    }
  });

  it("keeps a missing problems list as empty rather than malformed", () => {
    const read = readSiteView({
      asked: 0,
      reachable: 0,
      vpcs: [],
      hosts: [],
    });
    assert.equal(read.ok, true);
    if (read.ok) assert.deepEqual(read.site.problems, []);
  });

  it("refuses a payload that is missing the reachability counts", () => {
    const read = readSiteView({ vpcs: [], hosts: [] });
    assert.equal(read.ok, false);
  });

  it("keeps a missing contradiction list as empty, not as a parse failure", () => {
    const read = readSiteView({
      asked: 1,
      reachable: 1,
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [{
        vpc: "dev", host: "gw-01.dev", state: "confirmed", generation: "abc",
        current: true, drifted: false, ageSec: 4,
      }],
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.deepEqual(read.site.hosts[0]?.contradictions, []);
      assert.equal(read.site.hosts[0]?.workload, null);
    }
  });

  it("reads a certain contradiction and a rolled-back workload without folding them", () => {
    const read = readSiteView({
      asked: 1,
      reachable: 1,
      vpcs: [{ name: "prod", url: "https://x", ok: true }],
      hosts: [{
        vpc: "prod",
        host: "k8s-a1.prod",
        state: "confirmed",
        generation: "abc",
        current: true,
        drifted: true,
        ageSec: 3,
        contradictions: [{
          kind: "artifact-hash-wrong",
          certainty: "certain",
          detail: "the ruleset digest the host reports was never issued",
        }],
        workload: {
          cluster: "prod-a",
          state: "rolled-back",
          expected: 34,
          detail: null,
          membership: {
            at: "2026-08-19T00:00:48Z",
            namespaces: { default: ["a", "b", "c"] },
            labelled: { "app=web": ["w"] },
          },
        },
      }],
    });
    assert.equal(read.ok, true);
    if (!read.ok) return;
    const row = read.site.hosts[0]!;
    assert.equal(row.state, "confirmed");
    assert.equal(row.drifted, true);
    assert.equal(row.contradictions[0]?.certainty, "certain");
    assert.equal(row.workload?.state, "rolled-back");
    assert.equal(row.workload?.membership?.at, "2026-08-19T00:00:48Z");
  });

  it("keeps null extra-filter lists distinct from empty ones", () => {
    const empty = readSiteView({
      asked: 1, reachable: 1,
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [{
        vpc: "dev", host: "gw-01.dev", state: "confirmed", generation: "abc",
        current: true, drifted: false, ageSec: 4,
        unexpectedFilters: [], intrusions: [], publishedPorts: [],
      }],
    });
    const silent = readSiteView({
      asked: 1, reachable: 1,
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [{
        vpc: "dev", host: "gw-01.dev", state: "confirmed", generation: "abc",
        current: true, drifted: false, ageSec: 4,
        unexpectedFilters: null, intrusions: null, publishedPorts: null,
      }],
    });
    assert.equal(empty.ok && empty.site.hosts[0]?.unexpectedFilters?.length, 0);
    assert.equal(silent.ok && silent.site.hosts[0]?.unexpectedFilters, null);
    assert.equal(empty.ok && empty.site.hosts[0]?.intrusions?.length, 0);
    assert.equal(silent.ok && silent.site.hosts[0]?.intrusions, null);
  });

  it("reads a foreign intrusion and ignores a malformed one without dropping the host", () => {
    const read = readSiteView({
      asked: 1, reachable: 1,
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [{
        vpc: "dev", host: "gw-01.dev", state: "confirmed", generation: "abc",
        current: true, drifted: false, ageSec: 4,
        unexpectedFilters: ["docker", "ufw-user-input"],
        publishedPorts: ["8443/tcp"],
        intrusions: [
          { at: "2026-08-19T12:04:11Z", table: "inet heliopause", raw: "add rule", pid: 8821, process: "ufw", byAgent: false },
          { not: "an event" },
        ],
      }],
    });
    assert.equal(read.ok, true);
    if (!read.ok) return;
    const row = read.site.hosts[0]!;
    assert.deepEqual(row.unexpectedFilters, ["docker", "ufw-user-input"]);
    assert.deepEqual(row.publishedPorts, ["8443/tcp"]);
    assert.equal(row.intrusions?.length, 1);
    assert.equal(row.intrusions?.[0]?.process, "ufw");
    assert.equal(row.intrusions?.[0]?.byAgent, false);
  });

  it("drops a malformed workload rather than losing the host", () => {
    const read = readSiteView({
      asked: 1,
      reachable: 1,
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [{
        vpc: "dev", host: "gw-01.dev", state: "confirmed", generation: "abc",
        current: true, drifted: false, ageSec: 4, workload: { cluster: 1 },
      }],
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.equal(read.site.hosts[0]?.host, "gw-01.dev");
      assert.equal(read.site.hosts[0]?.workload, null);
    }
  });

  it("keeps unreported routes distinct from an empty list, and reads a hand-added one", () => {
    const empty = readSiteView({
      asked: 1, reachable: 1,
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [{
        vpc: "dev", host: "gw-01.dev", state: "confirmed", generation: "abc",
        current: true, drifted: false, ageSec: 4, routes: [],
      }],
    });
    const hand = readSiteView({
      asked: 1, reachable: 1,
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [{
        vpc: "dev", host: "gw-01.dev", state: "confirmed", generation: "abc",
        current: true, drifted: false, ageSec: 4,
        routes: [
          { dst: "default", via: "192.0.2.1", dev: "eth0", proto: "dhcp", table: "main", handAdded: false },
          { dst: "10.17.128.0/18", via: "10.17.0.10", dev: "enp8s0", proto: "static", table: "main", handAdded: true },
          { not: "a route" },
        ],
      }],
    });
    assert.equal(empty.ok && empty.site.hosts[0]?.routes?.length, 0);
    assert.equal(hand.ok && hand.site.hosts[0]?.routes?.length, 2);
    assert.equal(hand.ok && hand.site.hosts[0]?.routes?.[1]?.handAdded, true);
    assert.equal(hand.ok && hand.site.hosts[0]?.routes?.[1]?.dst, "10.17.128.0/18");
  });
});
