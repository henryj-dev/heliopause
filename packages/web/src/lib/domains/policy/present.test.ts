import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { t } from "../../i18n.ts";
import { placement, policyFindings, riskLabel } from "./present.ts";
import type { PolicyRow } from "./screen.ts";

const row = (over: Partial<PolicyRow> = {}): PolicyRow => ({
  id: "DEV-SSH",
  name: "ssh from mgmt",
  action: "allow",
  denyMode: "drop",
  proto: "tcp",
  ports: "22",
  priority: 100,
  enabled: true,
  notes: null,
  hosts: ["gw-01.dev"],
  skippedOn: [],
  egressHosts: [],
  srcCidrs: ["10.254.0.0/16"],
  placementKnown: true,
  risks: [],
  ...over,
});

describe("policyFindings", () => {
  it("omits a finding that is not in play", () => {
    assert.deepEqual(policyFindings([row()]), []);
  });

  it("counts each G1 finding and keeps placement unknown separate from renders-nowhere", () => {
    const findings = policyFindings([
      row({ id: "a", risks: ["renders-nowhere"] }),
      row({ id: "b", risks: ["any-source", "all-ports"] }),
      row({ id: "c", risks: ["disabled"], enabled: false }),
      row({ id: "d", placementKnown: false, hosts: ["gw-01.dev"] }),
    ]);
    assert.deepEqual(
      findings.map((f) => [f.key, f.count]),
      [
        ["renders-nowhere", 1],
        ["any-source", 1],
        ["all-ports", 1],
        ["disabled", 1],
        ["placement-unknown", 1],
      ],
    );
    const unknown = findings.find((f) => f.key === "placement-unknown");
    assert.equal(unknown?.hatch, true);
    assert.equal(unknown?.kind, "none");
  });

  it("does not treat an unknown placement as renders-nowhere", () => {
    const findings = policyFindings([row({ placementKnown: false, hosts: [], risks: [] })]);
    assert.deepEqual(findings.map((f) => f.key), ["placement-unknown"]);
  });

  it("names each finding in the language asked for, not the slug", () => {
    const [nowhere] = policyFindings([row({ risks: ["renders-nowhere"] })], "ko");
    assert.equal(nowhere?.label, t("ko", "m.riskNowhere"));
    assert.equal(riskLabel("any-source", "ko"), t("ko", "m.anySource"));
  });
});

describe("placement", () => {
  it("names egress and skipped in the language asked for", () => {
    const text = placement({
      hosts: ["gw-01.dev"],
      egressHosts: ["nat-01.dev"],
      skippedOn: ["gw-02.dev"],
      placementKnown: true,
    }, "ko");
    assert.match(text, /아웃바운드 nat-01\.dev/);
    assert.match(text, /건너뜀 gw-02\.dev/);
    assert.doesNotMatch(text, /egress:/);
  });
});
