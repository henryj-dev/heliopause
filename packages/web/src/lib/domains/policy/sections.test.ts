import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readPolicyScreen, type PolicyScreenView } from "./screen.ts";
import { ALL_SECTION, presentSections, resolveSection, sectionPath } from "./sections.ts";

const emptyView = (over: Partial<PolicyScreenView> = {}): PolicyScreenView => ({
  rows: [],
  baseline: [],
  hosts: [],
  workload: [],
  zones: [],
  crossings: [],
  coverage: null,
  devices: null,
  users: [],
  objects: [],
  services: [],
  feeds: [],
  membership: [],
  addressSpace: [],
  history: [],
  site: "dev",
  generation: "abc",
  hostIds: [],
  freshness: null,
  renderer: null,
  canWrite: false,
  edit: null,
  ...over,
});

describe("section paths", () => {
  it("names the section in the path, not in a query string", () => {
    assert.equal(sectionPath("files"), "/policy/files");
    assert.equal(sectionPath("address-space"), "/policy/address-space");
    assert.equal(sectionPath(ALL_SECTION), "/policy/all");
    assert.doesNotMatch(sectionPath("files"), /[?&]s=/);
  });
});

describe("resolveSection", () => {
  const present = ["policies", "zones", "files"] as const;

  it("keeps a section that rendered", () => {
    assert.equal(resolveSection([...present], "files"), "files");
  });

  it("falls back to the first rendered section rather than an empty page", () => {
    assert.equal(resolveSection([...present], ""), "policies");
    assert.equal(resolveSection([...present], "devices"), "policies");
  });

  it("treats all as a mode, not as a missing table", () => {
    assert.equal(resolveSection([...present], "all"), "all");
  });
});

describe("presentSections", () => {
  it("always lists policies and crossings, and omits empty optional tables", () => {
    const listed = presentSections(emptyView()).map((s) => s.id);
    assert.deepEqual(listed, ["policies", "crossings"]);
  });

  it("omits an empty device registry the manager always sends", () => {
    const listed = presentSections(emptyView({
      devices: { rows: [], unapproved: 0, compared: false },
      coverage: { rows: [], failing: 0, unknown: 0, passing: 0 },
    })).map((s) => s.id);
    assert.ok(!listed.includes("devices"), "an empty devices object is not a devices table");
    assert.ok(!listed.includes("coverage"), "an empty coverage object is not a coverage table");
  });

  it("lists files only when there is a second editable file", () => {
    const without = presentSections(emptyView({
      edit: { path: "policies.json", content: "{}", more: [] },
    })).map((s) => s.id);
    assert.ok(without.includes("rules"));
    assert.ok(!without.includes("files"));
    assert.deepEqual(
      presentSections(emptyView({ edit: { path: "policies.json", content: "{}", more: [] } })).map((s) => s.id).slice(0, 2),
      ["policies", "rules"],
      "the 시안 lands on policies, not on the editor table",
    );
    const withFiles = presentSections(emptyView({
      edit: { path: "policies.json", content: "{}", more: [{ path: "dev.ts", content: "export {}" }] },
    })).map((s) => s.id);
    assert.ok(withFiles.includes("files"));
  });
});

describe("readPolicyScreen", () => {
  it("accepts the payload the manager would send", () => {
    const read = readPolicyScreen({
      rows: [{
        id: "p-1",
        name: "allow web",
        action: "allow",
        denyMode: "drop",
        proto: "tcp",
        ports: "443",
        priority: 100,
        enabled: true,
        notes: null,
        hosts: ["gw-01.dev"],
        skippedOn: [],
        placementKnown: true,
        egressHosts: [],
        srcCidrs: ["10.0.0.0/8"],
        risks: [],
      }],
      extra: {
        zones: [{ zone: { id: "mgmt", name: "management", cidrs: ["10.254.0.0/16"], trust: 3 }, asSource: 1, asDestination: 0, admits: 0 }],
      },
      site: "dev",
      generation: "abc1234",
      hosts: ["gw-01.dev"],
      canWrite: false,
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.equal(read.view.rows[0]?.id, "p-1");
      assert.equal(read.view.zones[0]?.id, "mgmt");
      assert.equal(read.view.generation, "abc1234");
    }
  });

  it("refuses a payload that drops the policy rows", () => {
    const read = readPolicyScreen({ extra: {}, site: "dev" });
    assert.equal(read.ok, false);
  });

  it("keeps a real empty devices extra as empty, not as a parse failure", () => {
    const read = readPolicyScreen({
      rows: [],
      extra: { devices: { rows: [], unapproved: [], compared: false } },
      site: "dev",
    });
    assert.equal(read.ok, true);
    if (read.ok) {
      assert.equal(read.view.devices?.rows.length, 0);
      assert.ok(!presentSections(read.view).some((s) => s.id === "devices"));
    }
  });

  it("keeps coverage verdict and staleness as two facts", () => {
    const read = readPolicyScreen({
      rows: [],
      extra: {
        coverage: {
          rows: [{
            check: { title: "ssh-closed", expect: "blocked" },
            targets: ["edge-07.prod"],
            v4: { verdict: "pass", stale: true, at: "12:02:10", observedFrom: "probe-a" },
            v6: { verdict: "n/a" },
          }],
          failing: 0,
          unknown: 0,
          passing: 1,
        },
      },
      site: "dev",
    });
    assert.equal(read.ok, true);
    if (!read.ok) return;
    const row = read.view.coverage?.rows[0];
    assert.equal(row?.v4.verdict, "pass");
    assert.equal(row?.v4.stale, true);
    assert.equal(row?.v6.verdict, "n/a");
    assert.equal(row?.expect, "blocked");
  });

  it("refuses a coverage object that cannot be read, rather than hiding it", () => {
    const read = readPolicyScreen({ rows: [], extra: { coverage: { rows: "no" } }, site: "dev" });
    assert.equal(read.ok, false);
  });
});
