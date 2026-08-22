import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { answeredVpcNames, fleetListing, fleetSummary, hostMatches, hostStateChips, routesView, whyBits, vpcLabel, vpcTone, workloadChip, type SiteHost } from "./present.ts";

const host = (over: Partial<SiteHost> = {}): SiteHost => ({
  vpc: "dev",
  host: "gw-01.dev",
  state: "confirmed",
  generation: "abc",
  current: true,
  drifted: false,
  ageSec: 4,
  stage: "rest",
  blockedBy: null,
  maintenance: null,
  contradictions: [],
  workload: null,
  unexpectedFilters: [],
  intrusions: [],
  publishedPorts: [],
  routes: [],
  ...over,
});

describe("hostStateChips", () => {
  it("draws never-seen as a hatched none, not as a fault", () => {
    const chips = hostStateChips(host({ state: null, ageSec: null }));
    assert.deepEqual(chips, [{ kind: "none", word: "never seen", hatch: true }]);
  });

  it("keeps confirmed next to drifted, and does not fold them", () => {
    assert.deepEqual(hostStateChips(host()).map((c) => c.word), ["confirmed"]);
    assert.deepEqual(hostStateChips(host({ drifted: true })).map((c) => c.word), ["confirmed", "drifted"]);
    assert.deepEqual(hostStateChips(host({ maintenance: "disk" })).map((c) => c.word), ["maintenance"]);
    assert.deepEqual(
      hostStateChips(host({ blockedBy: "canary has not confirmed" })).map((c) => c.word),
      ["confirmed", "holding"],
    );
  });
});

describe("fleetSummary", () => {
  it("counts a problem when a host is not on the wanted generation", () => {
    const summary = fleetSummary({
      asked: 1,
      reachable: 1,
      problems: [],
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [host(), host({ host: "gw-02.dev", current: false })],
    });
    assert.equal(summary.problems, 1);
    assert.deepEqual(summary.generations, ["abc"]);
  });

  it("prefers the relay's problem sentences over a recount", () => {
    const summary = fleetSummary({
      asked: 1,
      reachable: 0,
      problems: ["dev: relay unreachable — hosts behind it are receiving nothing"],
      vpcs: [{ name: "dev", url: "https://x", ok: false, error: "timeout" }],
      hosts: [],
    });
    assert.equal(summary.problems, 1);
  });
});

describe("vpcTone", () => {
  it("hatches an unread VPC as bad, not as zero hosts", () => {
    const down = { name: "util", url: "https://x", ok: false as const, error: "timeout" };
    assert.equal(vpcTone(down, []), "bad");
    assert.equal(vpcLabel(down, []), "unread");
    assert.equal(vpcLabel(down, [], "ko"), "못 읽음");
  });
});

describe("fleetListing", () => {
  it("treats an answered VPC with no hosts as empty, not as unread", () => {
    const empty = {
      asked: 1, reachable: 1, problems: [],
      vpcs: [{ name: "dev", url: "https://x", ok: true as const }],
      hosts: [],
    };
    assert.equal(fleetListing(empty), "empty");
    assert.deepEqual(answeredVpcNames(empty), ["dev"]);
  });

  it("does not call unread 'zero hosts' when no relay answered", () => {
    const down = {
      asked: 1, reachable: 0, problems: ["dev: timeout"],
      vpcs: [{ name: "dev", url: "https://x", ok: false as const, error: "timeout" }],
      hosts: [],
    };
    assert.equal(fleetListing(down), "unread");
    assert.deepEqual(answeredVpcNames(down), []);
  });

  it("stays on the host table when any host is present", () => {
    assert.equal(fleetListing({
      asked: 1, reachable: 1, problems: [],
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [host()],
    }), "hosts");
  });
});

describe("hostMatches", () => {
  it("filters by host or vpc text", () => {
    assert.equal(hostMatches(host(), "gw-01"), true);
    assert.equal(hostMatches(host(), "prod"), false);
    assert.equal(hostMatches(host(), ""), true);
  });
});

describe("contradictions and workload", () => {
  it("keeps certain apart from unexplained, and does not fold them into drifted", () => {
    const chips = hostStateChips(host({
      drifted: true,
      contradictions: [
        { kind: "artifact-hash-wrong", certainty: "certain", detail: "digest never issued" },
        { kind: "unknown-generation", certainty: "unexplained", detail: "predates this manager" },
      ],
    }));
    assert.deepEqual(chips.map((c) => [c.kind, c.word, Boolean(c.hatch)]), [
      ["ok", "confirmed", false],
      ["bad", "drifted", false],
      ["bad", "artifact-hash-wrong", false],
      ["mute", "unknown-generation", true],
    ]);
    assert.deepEqual(
      hostStateChips(host({
        contradictions: [
          { kind: "artifact-hash-wrong", certainty: "certain", detail: "digest never issued" },
          { kind: "unknown-generation", certainty: "unexplained", detail: "predates this manager" },
        ],
      }), "ko").filter((c) => c.kind === "bad" || c.kind === "mute").map((c) => c.word),
      ["아티팩트 해시가 틀림", "알 수 없는 세대"],
    );
    const why = host({
      contradictions: [{ kind: "artifact-hash-wrong", certainty: "certain", detail: "digest never issued" }],
    });
    assert.match(whyBits(why).join("\n"), /artifact-hash-wrong · certain — digest never issued/);
    assert.match(whyBits(why, "ko").join("\n"), /아티팩트 해시가 틀림 · 확실 — digest never issued/);
  });

  it("does not treat an unexplained contradiction as a fleet problem", () => {
    const summary = fleetSummary({
      asked: 1,
      reachable: 1,
      problems: [],
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [host({
        contradictions: [{ kind: "unknown-generation", certainty: "unexplained", detail: "old" }],
      })],
    });
    assert.equal(summary.problems, 0);
  });

  it("treats a rolled-back workload as a problem even when the host is confirmed", () => {
    const summary = fleetSummary({
      asked: 1,
      reachable: 1,
      problems: [],
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [host({
        workload: {
          cluster: "prod-a",
          state: "rolled-back",
          expected: 34,
          detail: null,
          membership: { at: "2026-08-19T00:00:00Z", namespaces: { default: ["a", "b"] }, labelled: {} },
        },
      })],
    });
    assert.equal(summary.problems, 1);
    const half = {
      cluster: "prod-a",
      state: "rolled-back",
      expected: 34,
      detail: null,
      membership: null,
    };
    assert.equal(workloadChip(half).word, "rolled-back");
    assert.equal(workloadChip(half, "ko").word, "되돌아감");
    assert.deepEqual(
      hostStateChips(host({ state: "rolled-back" }), "ko").map((c) => c.word),
      ["되돌아감"],
    );
  });
});

describe("intrusions, extra filters, published ports", () => {
  const evt = (over: Partial<NonNullable<SiteHost["intrusions"]>[number]> = {}) => ({
    at: "2026-08-19T12:04:11Z",
    table: "inet heliopause",
    raw: "add rule …",
    pid: 8821,
    process: "ufw",
    byAgent: false,
    ...over,
  });

  it("does not count the agent's own writes as an intrusion", () => {
    const chips = hostStateChips(host({
      intrusions: [evt({ byAgent: true }), evt({ byAgent: true, pid: 1 })],
    }));
    assert.equal(chips.some((c) => c.word.startsWith("intrusion") || c.word.startsWith("개입")), false);
    assert.equal(whyBits(host({ intrusions: [evt({ byAgent: true })] })).join(""), "");
  });

  it("counts only foreign changes, and names the last one", () => {
    const row = host({
      intrusions: [evt({ process: "nft", pid: 1 }), evt({ process: "ufw", pid: 8821 })],
    });
    assert.ok(hostStateChips(row).some((c) => c.word === "intrusion 2" && c.kind === "warn"));
    assert.ok(hostStateChips(row, "ko").some((c) => c.word === "개입 2"));
    assert.match(whyBits(row).join("\n"), /intrusions: .*ufw/);
    assert.match(whyBits(row, "ko").join("\n"), /개입: .*ufw/);
  });

  it("treats unexpected filters as a problem and does not treat published ports as one", () => {
    const filters = fleetSummary({
      asked: 1, reachable: 1, problems: [],
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [host({ unexpectedFilters: ["docker"] })],
    });
    const ports = fleetSummary({
      asked: 1, reachable: 1, problems: [],
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [host({ publishedPorts: ["8443/tcp"] })],
    });
    assert.equal(filters.problems, 1);
    assert.equal(ports.problems, 0);
    assert.match(whyBits(host({ publishedPorts: ["8443/tcp"] })).join("\n"), /publishedPorts: 8443\/tcp/);
    assert.match(whyBits(host({ publishedPorts: ["8443/tcp"] }), "ko").join("\n"), /게시 포트: 8443\/tcp/);
    assert.match(whyBits(host({ unexpectedFilters: ["docker"] }), "ko").join("\n"), /예상 밖 필터: docker/);
  });

  it("does not treat unreported (null) as empty (looked, none)", () => {
    const silent = host({ unexpectedFilters: null, intrusions: null, publishedPorts: null });
    assert.equal(whyBits(silent).join(""), "");
    assert.equal(hostStateChips(silent).some((c) => c.word.startsWith("intrusion") || c.word.startsWith("개입")), false);
  });
});

describe("the routes cell", () => {
  const dhcp = {
    dst: "default", via: "192.0.2.1", dev: "eth0", proto: "dhcp", table: "main",
    origin: "automatic" as const, handAdded: false,
  };
  const staticRoute = {
    dst: "10.17.128.0/18", via: "10.17.0.10", dev: "enp8s0", proto: "static", table: "main",
    origin: "static" as const, handAdded: true,
  };

  it("draws unreported and none differently — the distinction the field exists for", () => {
    assert.equal(routesView(host({ routes: null })).kind, "unreported");
    assert.deepEqual(routesView(host({ routes: [] })), { kind: "owned", total: 0 });
  });

  it("counts the hand-added ones and keeps the total beside them", () => {
    const view = routesView(host({ routes: [dhcp, staticRoute] }));
    assert.equal(view.kind, "by-hand");
    if (view.kind !== "by-hand") return;
    assert.equal(view.hand, 1);
    assert.equal(view.total, 2);
    assert.match(view.title, /10\.17\.128\.0\/18/);
  });

  it("stays quiet when every route has an owner, and does not count them as a fleet problem", () => {
    assert.deepEqual(routesView(host({ routes: [dhcp] })), { kind: "owned", total: 1 });
    const summary = fleetSummary({
      asked: 1, reachable: 1, problems: [],
      vpcs: [{ name: "dev", url: "https://x", ok: true }],
      hosts: [host({ routes: [dhcp, staticRoute] })],
    });
    assert.equal(summary.problems, 0);
  });
});
