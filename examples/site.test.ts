import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { renderHostRuleset } from "../src/nft.ts";
import { exampleConfig, exampleHosts, exampleSite } from "./site.ts";

/**
 * The example is only worth shipping if it renders, so this renders it.
 *
 * **The point is not coverage of the renderer** — `src/nft.test.ts` does that far more thoroughly.
 * The point is that a public clone has *something* that exercises the whole path from a site module
 * to a ruleset. Without `policy/`, `npm test` here runs the unit tests and nothing that puts them
 * together, and the count says so in a way nobody reads.
 *
 * The assertions below are the claims the README makes. If one of them stops holding, the README is
 * wrong and this is where that shows up.
 */

const hostNamed = (id: string) => {
  const found = exampleHosts.find((h) => h.id === id);
  assert.ok(found, `the example lost its ${id} host`);
  return found;
};

const renderFor = (id: string) => {
  const host = hostNamed(id);
  return renderHostRuleset(exampleConfig, host.id, host.items, host.egress ?? []);
};

describe("the example site renders", () => {
  test("both hosts produce a ruleset", () => {
    for (const host of exampleHosts) {
      const out = renderFor(host.id);
      assert.ok(out.ruleset.length > 0, `${host.id} rendered nothing`);
    }
  });

  test("nothing was skipped, and nothing errored", () => {
    // A skipped rule is the failure mode this project is about — a port everyone believes is
    // closed. An example that silently skips would teach the wrong shape.
    for (const host of exampleHosts) {
      const out = renderFor(host.id);
      assert.deepEqual(out.skipped, [], `${host.id} skipped something`);
    }
  });
});

describe("the properties the README claims", () => {
  test("it only ever touches its own table", () => {
    const out = renderFor("web-01.example.com");
    assert.match(out.ruleset, /table inet heliopause/);
    // The negative is the load-bearing half: no other table is named, and `flush ruleset` — one
    // line away from wiping a host's firewall — never appears.
    assert.doesNotMatch(out.ruleset, /flush ruleset/);
    // ⚠️ Comment lines have to come out first. A naive `table\s+\w+\s+(\S+)` over the whole text
    // also matches the header sentence "Only this table is managed …" and reports a table called
    // `managed` — a false failure that reads exactly like the real one it is meant to catch.
    const tables = out.ruleset
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("#"))
      .flatMap((line) => [...line.matchAll(/\btable\s+(?:inet|ip6?|arp|bridge|netdev)\s+(\S+)/g)])
      .map((m) => m[1]);
    assert.ok(tables.length > 0, "no table declaration was rendered");
    assert.deepEqual([...new Set(tables)], ["heliopause"]);
  });

  test("established,related comes before any policy rule", () => {
    // Without it a broad deny drops the replies to connections the host itself opened, and SSH
    // dies mid-session while the ruleset still reads as correct.
    const out = renderFor("web-01.example.com");
    const ct = out.ruleset.indexOf("ct state established,related accept");
    const firstPolicy = out.ruleset.indexOf("dport");
    assert.ok(ct >= 0, "no established,related rule was rendered");
    assert.ok(ct < firstPolicy, "a policy rule renders before established,related");
  });

  test("the management path survives a dropping input hook", () => {
    // The baseline is what stands between a deny-by-default host and nobody being able to reach it.
    const out = renderFor("web-01.example.com");
    assert.match(out.ruleset, /policy drop/);
    assert.match(out.ruleset, /192\.0\.2\.0\/24/);
    assert.match(out.ruleset, /dport 22/);
  });

  test("a narrower policy keeps its source match", () => {
    // The metrics port is open to the management range and to nothing else. If the source match
    // were dropped the rule would still render — and the port would be open to the internet.
    const out = renderFor("web-01.example.com");
    const metrics = out.ruleset.split("\n").filter((l) => l.includes("9100"));
    assert.equal(metrics.length > 0, true, "the metrics rule did not render");
    for (const line of metrics) {
      assert.match(line, /192\.0\.2\.0\/24/, `metrics rule lost its source match: ${line}`);
    }
  });
});

describe("the example stays an example", () => {
  test("every address is a documentation range", () => {
    // CONTRIBUTING requires RFC 5737 / RFC 2606 in tests and examples, and the leak scanner
    // enforces the address half on every commit. Checking it here means someone adapting this file
    // finds out from a test rather than from the gate.
    const source = exampleHosts.flatMap((h) =>
      h.items.flatMap((i) => [...i.srcCidrs, ...i.dstCidrs]),
    );
    const declared = [...source, ...exampleConfig.baseline.flatMap((b) => b.srcCidrs),
                      exampleConfig.internalSupernet];
    for (const cidr of declared) {
      assert.match(
        cidr,
        /^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/,
        `${cidr} is not an RFC 5737 documentation range`,
      );
    }
  });

  test("host names use example.com", () => {
    for (const host of exampleHosts) {
      assert.match(host.id, /\.example\.com$/, `${host.id} is not an RFC 2606 name`);
    }
  });

  test("there is a canary, because publishing refuses a generation without one", () => {
    // With every host in one stage the first bad ruleset reaches all of them at once.
    assert.ok(exampleHosts.some((h) => h.stage === "canary"), "no canary host");
    assert.ok(exampleHosts.some((h) => h.stage !== "canary"), "only one stage — nothing is staged");
  });

  test("the exported site is the shape a publisher takes", () => {
    assert.equal(exampleSite.cfg, exampleConfig);
    assert.deepEqual(exampleSite.hosts, exampleHosts);
  });
});
