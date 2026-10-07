import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { hostIsClean, readRoutingView, routingListing, siteGenerationSplit } from "./routing.ts";

describe("readRoutingView", () => {
  it("accepts a comparison the manager would send", () => {
    const read = readRoutingView({
      generation: "abc1234",
      dirty: false,
      hosts: [{
        vpc: "dev",
        host: "gw-01.dev",
        missing: 1,
        undeclared: 0,
        unstated: 0,
        rows: [{
          dst: "10.17.128.0/18",
          via: "10.0.0.1",
          dev: "eth0",
          table: "main",
          verdict: "missing",
          owner: "provisioning",
          note: "pod range",
        }],
      }],
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.equal(read.view.hosts[0]?.rows?.[0]?.verdict, "missing");
      assert.equal(hostIsClean(read.view.hosts[0]!), false);
    }
  });

  it("keeps rows === null as no model, not as an empty declaration", () => {
    const read = readRoutingView({
      generation: "abc1234",
      hosts: [{ vpc: "prod", host: "mail-01.prod", rows: null, missing: 0, undeclared: 0, unstated: 0 }],
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.equal(read.view.hosts[0]?.rows, null);
      assert.equal(hostIsClean(read.view.hosts[0]!), false);
    }
  });

  it("keeps an empty declaration as [], which is a different claim from no model", () => {
    const read = readRoutingView({
      hosts: [{ vpc: "dev", host: "looked.dev", rows: [], missing: 0, undeclared: 0, unstated: 0 }],
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.deepEqual(read.view.hosts[0]?.rows, []);
      assert.equal(hostIsClean(read.view.hosts[0]!), true);
    }
  });

  it("treats hosts: [] as empty, not as unread", () => {
    const read = readRoutingView({ hosts: [] });
    assert.equal(read.ok && routingListing(read.view), "empty");
  });

  it("refuses a host whose rows are neither a list nor null", () => {
    const read = readRoutingView({ hosts: [{ vpc: "dev", host: "gw-01.dev" }] });
    assert.equal(read.ok, false);
  });
});

describe("per-site reading", () => {
  it("keeps a host whose site could not be read apart from a host with no model", () => {
    const read = readRoutingView({
      generation: "d".repeat(40), dirty: false,
      sites: [{ site: "dev", generation: "d".repeat(40), dirty: false, error: null },
        { site: "az01", generation: null, dirty: false, error: "the renderer returned 503" }],
      hosts: [
        { vpc: "dev", host: "k3s-01.dev", rows: null, missing: 0, undeclared: 0, unstated: 0, declarationError: null },
        { vpc: "az01", host: "gw-01.az01", rows: null, missing: 0, undeclared: 0, unstated: 0, declarationError: "the renderer returned 503" },
      ],
    });
    assert.equal(read.ok, true);
    if (!read.ok) return;
    assert.equal(read.view.hosts[0]!.declarationError, null, "no model");
    assert.equal(read.view.hosts[1]!.declarationError, "the renderer returned 503", "unreadable site");
    assert.deepEqual(read.view.sites.map((x) => [x.site, x.error]), [["dev", null], ["az01", "the renderer returned 503"]]);
  });

  it("reads a manager that predates sites as no sites and no errors", () => {
    const read = readRoutingView({ generation: "abc1234", dirty: false, hosts: [{ vpc: "dev", host: "h", rows: null }] });
    assert.equal(read.ok, true);
    if (!read.ok) return;
    assert.deepEqual(read.view.sites, []);
    assert.equal(read.view.hosts[0]!.declarationError, null);
  });

  it("names the sites when they were read at different commits, and nothing when they agree", () => {
    // The top-level `generation` is the first readable site's. Mid-sync the others may be elsewhere,
    // and this is what the screen shows instead of letting one commit stand for all four.
    const at = (site: string, generation: string | null) => ({ site, generation, dirty: false, error: generation ? null : "down" });
    const split = readRoutingView({ generation: "a".repeat(40), dirty: false, hosts: [],
      sites: [at("dev", "a".repeat(40)), at("prod", "b".repeat(40)), at("util", null)] });
    assert.equal(split.ok, true);
    if (!split.ok) return;
    assert.deepEqual(siteGenerationSplit(split.view).map((x) => x.site), ["dev", "prod"]);
    const same = readRoutingView({ generation: "a".repeat(40), dirty: false, hosts: [],
      sites: [at("dev", "a".repeat(40)), at("prod", "a".repeat(40))] });
    assert.equal(same.ok && siteGenerationSplit(same.view).length, 0);
  });

  it("refuses a site entry without a name", () => {
    assert.equal(readRoutingView({ hosts: [], sites: [{ generation: "x" }] }).ok, false);
  });
});
