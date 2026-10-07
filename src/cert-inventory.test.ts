import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  CERT_KINDS, MAX_WIRE_STRING, certificateInventory, certificateProblems, prose,
  type CertificateReport, type InventoryInput,
} from "./cert-inventory.ts";
import type { CertFacts } from "./cert-watch.ts";
import type { HostView } from "./relay.ts";
import type { RelayResult } from "./manager.ts";

const NOW = new Date("2026-10-06T00:00:00Z");
const inDays = (d: number) => new Date(NOW.getTime() + d * 86_400_000).toISOString();

const facts = (over: Partial<CertFacts> = {}): CertFacts => ({
  cn: "x", serial: "01", sha256: "ab".repeat(32),
  notBefore: inDays(-60), notAfter: inDays(100), ...over,
});

const host = (name: string, agentCert: HostView["agentCert"]) => ({ host: name, agentCert }) as HostView;

const relay = (name: string, hosts: HostView[], relayCert: CertFacts | null = facts({ cn: `gw.${name}` })): RelayResult => ({
  name, url: `https://${name}.invalid`, ok: true, relayCert,
  view: { generation: "g", hosts, problems: [] } as unknown as Extract<RelayResult, { ok: true }>["view"],
});

const base = (over: Partial<InventoryInput> = {}): InventoryInput => ({
  now: NOW,
  relays: [relay("dev", [host("web-01.dev", { ...facts({ cn: "web-01.dev" }), observedAt: NOW.toISOString() })])],
  vpcFiles: [{ vpc: "dev", client: facts({ cn: "hp-manager" }), ca: facts({ cn: "heliopause-ca" }) }],
  manager: { loaded: facts({ cn: "hp-manager" }), file: facts({ cn: "hp-manager" }) },
  operators: [],
  ...over,
});

/**
 * Two of stardust cert-drift's reasons to discard a whole report — any string over 512 characters, any
 * `kind` outside `^[a-z][a-z-]{0,31}$` — and only those two. A **partial** restatement: the
 * consumer's type rules (a string `cn`, a numeric `daysLeft`, a parseable `notAfter`) are not here,
 * and the cert-drift deployed with stardust #23 discarded reports this module produces on purpose for
 * exactly those. Passing this says nothing about whether stardust accepts a report; stardust's own
 * fixture, run against this module, is the authority on that.
 *
 * Pinned by its own known positives below, so a check that accepts everything cannot make the other
 * tests pass.
 */
function breaksLengthOrKindRule(report: unknown): string | null {
  const kind = /^[a-z][a-z-]{0,31}$/;
  const walk = (v: unknown, path: string): string | null => {
    if (typeof v === "string") return v.length > MAX_WIRE_STRING ? `${path}: ${v.length} characters` : null;
    if (Array.isArray(v)) {
      for (const [i, x] of v.entries()) { const bad = walk(x, `${path}[${i}]`); if (bad) return bad; }
      return null;
    }
    if (v && typeof v === "object") {
      for (const [k, x] of Object.entries(v)) {
        if (k === "kind" && (typeof x !== "string" || !kind.test(x))) return `${path}.kind: ${JSON.stringify(x)}`;
        const bad = walk(x, `${path}.${k}`); if (bad) return bad;
      }
    }
    return null;
  };
  return walk(report, "$");
}

describe("the length and kind rules, as restated here", () => {
  it("rejects over-long strings and bad kinds — the known positives that keep the other tests honest", () => {
    assert.equal(breaksLengthOrKindRule({ s: "a".repeat(512) }), null);
    assert.match(breaksLengthOrKindRule({ s: "a".repeat(513) }) ?? "", /513 characters/);
    assert.match(breaksLengthOrKindRule({ rows: [{ kind: "agent-v2" }] }) ?? "", /agent-v2/);
    assert.match(breaksLengthOrKindRule({ rows: [{ kind: "relay_server" }] }) ?? "", /relay_server/);
    assert.equal(breaksLengthOrKindRule({ rows: [{ kind: "relay-server" }] }), null);
  });

  it("accepts every kind this module can emit", () => {
    for (const k of CERT_KINDS) assert.equal(breaksLengthOrKindRule({ kind: k }), null, k);
  });
});

describe("certificateInventory", () => {
  it("reports every expected certificate when everything answered", () => {
    const r = certificateInventory(base());
    assert.equal(r.complete, true);
    assert.deepEqual(r.missing, []);
    assert.equal(r.expected.total, r.observed.total);
    assert.deepEqual(r.expected.byKind, {
      agent: 1, "relay-server": 1, "manager-client": 1, "manager-server": 2, ca: 1, operator: 0,
    });
    assert.deepEqual(r.observed.byKind, r.expected.byKind);
    assert.equal(breaksLengthOrKindRule(r), null);
  });

  it("names a host the relay lists but has no certificate for, and is then incomplete", () => {
    const r = certificateInventory(base({
      relays: [relay("dev", [host("web-01.dev", null)])],
    }));
    assert.equal(r.complete, false);
    assert.deepEqual(r.missing.map((m) => [m.kind, m.vpc, m.host]), [["agent", "dev", "web-01.dev"]]);
    assert.equal(r.expected.byKind.agent, 1);
    assert.equal(r.observed.byKind.agent, 0);
  });

  it("names an unreachable relay and its uncounted agents as missing; the agent count is then a lower bound", () => {
    const r = certificateInventory(base({
      relays: [
        relay("dev", [host("web-01.dev", { ...facts(), observedAt: NOW.toISOString() })]),
        { name: "prod", url: "https://prod.invalid", ok: false, error: "ECONNREFUSED" },
      ],
    }));
    assert.equal(r.complete, false);
    assert.deepEqual(
      r.missing.map((m) => [m.kind, m.vpc, m.host]),
      [["relay-server", "prod", null], ["agent", "prod", null]],
    );
    assert.match(r.missing[0]!.reason, /ECONNREFUSED/);
    assert.equal(r.expected.byKind["relay-server"], 2);
    // Only dev's host is counted: prod's are behind the relay that did not answer.
    assert.equal(r.expected.byKind.agent, 1);
  });

  it("does not read a relay without a manifest as a VPC with no agents", () => {
    const empty = relay("dev", []);
    (empty as { view: { generation: string | null } }).view.generation = null;
    const r = certificateInventory(base({ relays: [empty] }));
    assert.equal(r.complete, false);
    assert.deepEqual(r.missing.map((m) => [m.kind, m.vpc, m.host]), [["agent", "dev", null]]);
    assert.match(r.missing[0]!.reason, /no manifest/);
  });

  it("sends a malformed reading from a relay to missing rather than throwing or passing it through", () => {
    const bad: unknown[] = [{}, "abc", { ...facts(), serial: 123, observedAt: NOW.toISOString() }, { ...facts(), cn: ["y".repeat(600)], observedAt: NOW.toISOString() }];
    const r = certificateInventory(base({
      relays: [relay("dev", bad.map((c, i) => host(`h${i}.dev`, c as HostView["agentCert"])))],
    }));
    assert.deepEqual(r.missing.map((m) => m.host), ["h0.dev", "h1.dev", "h2.dev", "h3.dev"]);
    assert.ok(r.missing.every((m) => /malformed/.test(m.reason)));
    assert.equal(r.observed.byKind.agent, 0);
    assert.equal(breaksLengthOrKindRule(r), null);
  });

  it("digests an identifying value that is not a string instead of carrying it through", () => {
    const r = certificateInventory(base({
      relays: [relay("dev", [host(["z".repeat(600)] as unknown as string, { ...facts(), observedAt: NOW.toISOString() })])],
    }));
    assert.match(r.certificates.find((c) => c.kind === "agent")!.host!, /^sha256:[0-9a-f]{64}$/);
    assert.equal(breaksLengthOrKindRule(r), null);
  });

  it("reports that a CA bundle file holds more certificates than the first", () => {
    const r = certificateInventory(base({
      vpcFiles: [{ vpc: "dev", client: facts(), ca: facts({ cn: "heliopause-ca" }), caBlocks: 2 }],
    }));
    assert.equal(r.observed.byKind.ca, 1);
    assert.deepEqual(r.missing.map((m) => [m.kind, m.vpc]), [["ca", "dev"]]);
    assert.match(r.missing[0]!.reason, /holds 2 certificates/);
  });

  it("reports the manager's serving and on-disk certificates separately, so a missed restart shows", () => {
    const r = certificateInventory(base({
      manager: { loaded: facts({ sha256: "11".repeat(32), notAfter: inDays(5) }), file: facts({ sha256: "22".repeat(32) }) },
    }));
    const rows = r.certificates.filter((c) => c.kind === "manager-server");
    assert.deepEqual(rows.map((c) => [c.source, c.sha256.slice(0, 2), c.state]), [["loaded", "11", "critical"], ["file", "22", "ok"]]);
    assert.notEqual(rows[0]!.id, rows[1]!.id);
  });

  it("flags an agent reading the relay took long ago, and still judges it", () => {
    const old = new Date(NOW.getTime() - 3_600_000).toISOString();
    const r = certificateInventory(base({
      relays: [relay("dev", [host("web-01.dev", { ...facts({ notAfter: inDays(3) }), observedAt: old })])],
    }));
    const a = r.certificates.find((c) => c.kind === "agent")!;
    assert.equal(a.stale, true);
    assert.equal(a.state, "critical");
    assert.equal(a.observedAt, old);
    assert.equal(a.observedBy, "relay:dev");
  });

  it("tells an unconfigured operator directory from an empty one, and counts an unreadable file as expected", () => {
    assert.equal(certificateInventory(base({ operators: null })).operatorsConfigured, false);
    assert.equal(certificateInventory(base({ operators: [] })).operatorsConfigured, true);
    const r = certificateInventory(base({
      operators: [{ file: "ops.pem", reading: facts({ cn: "ops" }) }, { file: "broken.pem", reading: { error: "not a certificate" } }],
    }));
    assert.equal(r.expected.byKind.operator, 2);
    assert.equal(r.observed.byKind.operator, 1);
    // The file name goes in the reason, not in `host`: a consumer reads `host` as a host name.
    assert.deepEqual(r.missing.map((m) => [m.kind, m.host]), [["operator", null]]);
    assert.match(r.missing[0]!.reason, /^broken\.pem: not a certificate$/);
  });

  it("gives two operator files carrying one CN two different ids", () => {
    const r = certificateInventory(base({
      operators: [{ file: "a.pem", reading: facts({ cn: "ops" }) }, { file: "b.pem", reading: facts({ cn: "ops" }) }],
    }));
    const ids = r.certificates.map((c) => c.id);
    assert.equal(new Set(ids).size, ids.length, `duplicate ids: ${ids.join(", ")}`);
    assert.equal(r.observed.byKind.operator, 2);
  });

  it("keeps an identifying string of exactly 512 characters and replaces one of 513 with its digest", () => {
    const at512 = "h".repeat(512), at513 = "h".repeat(513);
    const r = certificateInventory(base({
      relays: [relay("dev", [
        host(at512, { ...facts(), observedAt: NOW.toISOString() }),
        host(at513, { ...facts(), observedAt: NOW.toISOString() }),
      ])],
    }));
    const hosts = r.certificates.filter((c) => c.kind === "agent").map((c) => c.host!);
    assert.equal(hosts[0], at512);
    assert.match(hosts[1]!, /^sha256:[0-9a-f]{64}$/);
    assert.equal(breaksLengthOrKindRule(r), null);
  });

  it("does not let two long names that differ only past the limit collide", () => {
    const a = "h".repeat(600) + "a", b = "h".repeat(600) + "b";
    const r = certificateInventory(base({
      relays: [relay("dev", [
        host(a, { ...facts(), observedAt: NOW.toISOString() }),
        host(b, { ...facts(), observedAt: NOW.toISOString() }),
      ])],
    }));
    const rows = r.certificates.filter((c) => c.kind === "agent");
    assert.notEqual(rows[0]!.host, rows[1]!.host);
    assert.notEqual(rows[0]!.id, rows[1]!.id);
  });

  it("keeps every string within 512 characters and every kind valid even when every input is hostile", () => {
    const huge = "x".repeat(5_000);
    const r = certificateInventory({
      now: NOW,
      relays: [
        relay(huge, [host(huge, { cn: huge, serial: huge, sha256: huge, notBefore: huge, notAfter: huge, observedAt: huge })],
          { cn: huge, serial: huge, sha256: huge, notBefore: huge, notAfter: huge }),
        relay(huge + "2", [host(huge, null)]),
        { name: huge + "3", url: huge, ok: false, error: huge },
      ],
      vpcFiles: [{ vpc: huge, client: { error: huge }, ca: facts({ cn: huge }) }],
      manager: { loaded: facts({ cn: huge }), file: { error: huge } },
      operators: [{ file: huge, reading: { error: huge } }, { file: huge, reading: facts({ cn: huge }) }],
    });
    assert.equal(breaksLengthOrKindRule(r), null);
    // And still a report: the unreadable expiry is `unknown`, not dropped and not `ok`.
    assert.equal(r.certificates.find((c) => c.kind === "agent")!.state, "unknown");
    const ids = r.certificates.map((c) => c.id);
    assert.equal(new Set(ids).size, ids.length);
  });
});

describe("dates on the wire", () => {
  it("normalises a parseable date, so a padded one is not reported as a digest beside a real state", () => {
    const padded = new Date(inDays(23)).toUTCString() + " ".repeat(600);
    const r = certificateInventory(base({
      relays: [relay("dev", [host("web-01.dev", { ...facts({ notAfter: padded, notBefore: padded }), observedAt: padded })])],
    }));
    const a = r.certificates.find((c) => c.kind === "agent")!;
    assert.equal(a.state, "renew");
    assert.equal(a.notAfter, new Date(padded).toISOString());
    assert.equal(a.notBefore, new Date(padded).toISOString());
    assert.equal(a.observedAt, new Date(padded).toISOString());
  });

  it("digests a date it cannot parse and reports the row unknown", () => {
    const junk = "x".repeat(600);
    const r = certificateInventory(base({
      relays: [relay("dev", [host("web-01.dev", { ...facts({ notAfter: junk }), observedAt: NOW.toISOString() })])],
    }));
    const a = r.certificates.find((c) => c.kind === "agent")!;
    assert.match(a.notAfter, /^sha256:/);
    assert.deepEqual([a.state, a.daysLeft], ["unknown", null]);
  });
});

describe("prose", () => {
  it("leaves 512 characters alone and cuts 513 to exactly 512, marked", () => {
    assert.equal(prose("a".repeat(512)), "a".repeat(512));
    const cut = prose("a".repeat(513));
    assert.equal(cut.length, 512);
    assert.match(cut, /…\[truncated\]$/);
  });

  it("does not cut through a surrogate pair", () => {
    const keep = 512 - "…[truncated]".length;
    const cut = prose("a".repeat(keep - 1) + "😀" + "b".repeat(100));
    assert.equal(cut, "a".repeat(keep - 1) + "…[truncated]");
  });
});

describe("certificateProblems", () => {
  it("lists renew, critical and expired, and nothing that is ok", () => {
    const r: CertificateReport = certificateInventory(base({
      relays: [relay("dev", [
        host("ok.dev", { ...facts({ notAfter: inDays(100) }), observedAt: NOW.toISOString() }),
        host("renew.dev", { ...facts({ notAfter: inDays(25) }), observedAt: NOW.toISOString() }),
        host("critical.dev", { ...facts({ notAfter: inDays(5) }), observedAt: NOW.toISOString() }),
        host("expired.dev", { ...facts({ notAfter: inDays(-2) }), observedAt: NOW.toISOString() }),
      ])],
    }));
    const lines = certificateProblems(r);
    assert.equal(lines.length, 3, lines.join("\n"));
    assert.match(lines.find((l) => l.includes("renew.dev"))!, /renew — 25 day\(s\) left/);
    assert.match(lines.find((l) => l.includes("critical.dev"))!, /critical — 5 day\(s\) left/);
    assert.match(lines.find((l) => l.includes("expired.dev"))!, /expired — expired 2 day\(s\) ago/);
  });

  it("does not say \"0 day(s) left\" about a certificate that expired within the day", () => {
    const r = certificateInventory(base({
      relays: [relay("dev", [host("just.dev", { ...facts({ notAfter: new Date(NOW.getTime() - 3_600_000).toISOString() }), observedAt: NOW.toISOString() })])],
    }));
    const line = certificateProblems(r).find((l) => l.includes("just.dev"))!;
    assert.match(line, /expired — expired less than a day ago/);
    assert.doesNotMatch(line, /left/);
  });
});
