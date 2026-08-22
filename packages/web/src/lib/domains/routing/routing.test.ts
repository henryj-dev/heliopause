import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { hostIsClean, readRoutingView, routingListing } from "./routing.ts";

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
