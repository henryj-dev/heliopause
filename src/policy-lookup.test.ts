// The lookup's job is to be right about what it does not know.
//
// A matcher that answers "no match" for a rule naming `app=dispatcher` when asked about an address
// is not slightly wrong — it is wrong in the direction that hides the rule the reader was looking
// for. That happened for real on 2026-08-16: three pods sat inside a `fromCIDR` range, were dropped
// anyway, and establishing why took two document round trips with another team. Most of what is
// below pins the undecidable answer rather than the matching one.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { lookupPolicies, portMatches, type LookupQuery } from "./policy-lookup.ts";
import type { Policy } from "./policy.ts";

const policy = (over: Partial<Policy> = {}): Policy => ({
  id: "P", name: "n", src: { kind: "cidr", value: "10.0.0.0/8" }, dst: { kind: "cidr", value: "10.0.0.0/8" },
  proto: "tcp", ports: "443", action: "allow", denyMode: "drop", priority: 100, enabled: true, ...over,
});

const ask = (over: Partial<LookupQuery> = {}): LookupQuery => ({
  src: "10.17.128.184", dst: "10.17.192.45", port: 5432, proto: "tcp", ...over,
});

const site = { internalSupernet: "10.0.0.0/8" };

describe("what an address can decide", () => {
  it("matches a rule whose ranges and port cover the flow — the known positive", () => {
    // Written first. Everything below asserts that something is *not* matched or *cannot* be decided,
    // and a wall of negatives with no positive cannot tell a working matcher from one that never
    // matches anything.
    const r = lookupPolicies([policy({ ports: "5432" })], ask(), site);
    assert.equal(r.matches.length, 1);
    assert.equal(r.matches[0]?.id, "P");
    assert.equal(r.undecidable.length, 0);
    assert.equal(r.considered, 1);
  });

  it("drops a rule whose range excludes the address", () => {
    const r = lookupPolicies([policy({ ports: "5432", dst: { kind: "cidr", value: "192.168.0.0/16" } })], ask(), site);
    assert.deepEqual([r.matches.length, r.undecidable.length], [0, 0]);
  });

  it("drops a rule on the wrong port or protocol", () => {
    assert.equal(lookupPolicies([policy({ ports: "443" })], ask(), site).matches.length, 0);
    assert.equal(lookupPolicies([policy({ ports: "5432", proto: "udp" })], ask(), site).matches.length, 0);
  });

  it("reads an internet rule as the complement of the internal supernet", () => {
    const p = policy({ ports: "443", src: { kind: "internet", value: "" } });
    // A public address is outside 10/8, so the rule names it.
    assert.equal(lookupPolicies([p], ask({ src: "203.0.113.9", port: 443 }), site).matches.length, 1);
    // A mesh address is inside, so it does not.
    assert.equal(lookupPolicies([p], ask({ src: "10.17.0.1", port: 443 }), site).matches.length, 0);
  });

  it("resolves a named address object instead of deferring it", () => {
    const p = policy({ ports: "5432", src: { kind: "object", value: "gateways" } });
    const withCatalogue = lookupPolicies([p], ask(), {
      ...site,
      objects: new Map([["gateways", ["10.17.128.0/18"]]]),
    });
    assert.equal(withCatalogue.matches.length, 1, "a named object should be answered, not deferred");

    // Without the catalogue it must defer rather than guess — an object it cannot resolve is not an
    // object that fails to match.
    const without = lookupPolicies([p], ask(), site);
    assert.equal(without.matches.length, 0);
    assert.equal(without.undecidable.length, 1);
    const objVerdict = without.undecidable[0]?.src;
    assert.equal(objVerdict?.kind, "undecidable");
    assert.match(objVerdict?.kind === "undecidable" ? objVerdict.why : "", /catalogue/);
  });

  it("ignores a disabled rule entirely", () => {
    // Listing it would put the reader one careless glance from believing a flow is covered by
    // something switched off.
    const r = lookupPolicies([policy({ ports: "5432", enabled: false })], ask(), site);
    assert.deepEqual([r.matches.length, r.undecidable.length, r.considered], [0, 0, 0]);
  });
});

describe("what an address cannot decide, and must say so", () => {
  it("defers a rule that names a workload, and explains why", () => {
    // The 2026-08-16 case exactly: an address inside the pod range, a rule selecting pods by label.
    // "No match" here is the wrong answer, and it is the answer a two-valued matcher gives.
    const p = policy({
      ports: "8080",
      src: { kind: "k8s-label", value: "k8s:io.kubernetes.pod.namespace=dispatcher,app=dispatcher" },
    });
    const r = lookupPolicies([p], ask({ port: 8080 }), site);
    assert.equal(r.matches.length, 0, "it claimed to decide something an address cannot decide");
    assert.equal(r.undecidable.length, 1);
    const v = r.undecidable[0]?.src;
    assert.match(v?.kind === "undecidable" ? v.why : "", /identity rather than by address/);
  });

  it("explains a deferred workload in the language asked for", () => {
    const p = policy({
      ports: "8080",
      src: { kind: "k8s-label", value: "k8s:io.kubernetes.pod.namespace=dispatcher,app=dispatcher" },
    });
    const r = lookupPolicies([p], ask({ port: 8080 }), site, "ko");
    const v = r.undecidable[0]?.src;
    assert.match(v?.kind === "undecidable" ? v.why : "", /신원으로 분류/);
  });

  it("defers on IPv6 rather than inheriting a conservative yes", () => {
    // `cidrsOverlap` answers `true` for anything it cannot parse, which is the right default for a
    // renderer and the wrong one to copy into an answer a person reads. Screened out here instead.
    const r = lookupPolicies([policy({ ports: "5432" })], ask({ dst: "2001:db8::1" }), site);
    assert.equal(r.matches.length, 0);
    assert.equal(r.undecidable.length, 1);
    const v6 = r.undecidable[0]?.dst;
    assert.match(v6?.kind === "undecidable" ? v6.why : "", /IPv4/);
  });

  it("defers when the ports come from a service object", () => {
    const r = lookupPolicies([policy({ ports: "@pg" })], ask(), site);
    assert.equal(r.undecidable.length, 1);
    const pv = r.undecidable[0]?.port;
    assert.match(pv?.kind === "undecidable" ? pv.why : "", /service object pg/);
  });

  it("still applies the parts it can decide before deferring", () => {
    // A workload rule on the wrong port is not undecidable — it is out. Deferring everything that
    // touches a workload would bury the reader in rules that plainly do not apply.
    const p = policy({ ports: "443", src: { kind: "k8s-namespace", value: "dispatcher" } });
    const r = lookupPolicies([p], ask({ port: 5432 }), site);
    assert.deepEqual([r.matches.length, r.undecidable.length], [0, 0]);
  });
});

describe("the order the reader meets them in", () => {
  it("puts a deny above an allow", () => {
    // Not cosmetic. On the workload layer a deny is evaluated before every allow and no later rule
    // can carve an exception out of it, so the first line is the one that decides.
    const r = lookupPolicies(
      [policy({ id: "ALLOW", ports: "5432", priority: 10 }), policy({ id: "DENY", ports: "5432", action: "deny", priority: 900 })],
      ask(),
      site,
    );
    assert.deepEqual(r.matches.map((m) => m.id), ["DENY", "ALLOW"]);
  });

  it("orders by priority within an action", () => {
    const r = lookupPolicies(
      [policy({ id: "LATE", ports: "5432", priority: 900 }), policy({ id: "EARLY", ports: "5432", priority: 10 })],
      ask(),
      site,
    );
    assert.deepEqual(r.matches.map((m) => m.id), ["EARLY", "LATE"]);
  });

  it("says which enforcement point each rule renders on", () => {
    // The same rule `cilium.ts` uses: a policy reaches the workload layer when either endpoint names
    // a workload, and belongs to the host layer otherwise.
    const r = lookupPolicies(
      [
        policy({ id: "HOST", ports: "5432" }),
        policy({ id: "WORKLOAD", ports: "5432", dst: { kind: "k8s-namespace", value: "tinyuniverse" } }),
      ],
      ask(),
      site,
    );
    assert.equal(r.matches.find((m) => m.id === "HOST")?.layer, "host");
    assert.equal(r.undecidable.find((m) => m.id === "WORKLOAD")?.layer, "workload");
  });
});

describe("port specifications", () => {
  it("reads a list, a range and the empty spec", () => {
    assert.equal(portMatches("80,443", 443).kind, "matches");
    assert.equal(portMatches("80,443", 8080).kind, "no");
    assert.equal(portMatches("1000:2000", 1500).kind, "matches");
    assert.equal(portMatches("1000:2000", 2001).kind, "no");
    // Empty means every port, which is what the model means by it.
    assert.equal(portMatches("", 22).kind, "matches");
  });

  it("treats a query with no port as covering every rule's ports", () => {
    assert.equal(portMatches("443", null).kind, "matches");
  });
});

describe("naming the workload turns a list into an answer", () => {
  // The first version took addresses only, and on the live fleet every query came back with forty-odd
  // deferred rules and nothing decided — a workload rule cannot be ruled in or out by an address, so
  // every workload rule deferred on every question. Honest and useless.
  const dispatcherRule = policy({
    id: "GOATCOUNTER-DISPATCHER", ports: "8080",
    src: { kind: "k8s-label", value: "k8s:io.kubernetes.pod.namespace=dispatcher,app=dispatcher" },
    dst: { kind: "k8s-label", value: "k8s:io.kubernetes.pod.namespace=goatcounter,app=goatcounter" },
  });
  const q = { src: "", dst: "", port: 8080, proto: "tcp" as const };

  it("matches the workload the rule names — the known positive", () => {
    const r = lookupPolicies([dispatcherRule], {
      ...q, srcWorkload: "dispatcher/app=dispatcher", dstWorkload: "goatcounter/app=goatcounter",
    }, site);
    assert.deepEqual(r.matches.map((m) => m.id), ["GOATCOUNTER-DISPATCHER"]);
  });

  it("rules out the workload it does not name — the narrowing, asked as a question", () => {
    // This is the 2026-08-16 change stated as a query. Before the narrowing the rule selected the
    // whole `dispatcher` namespace and the broker matched; after it, the broker does not. A lookup
    // that could not tell these apart would not have been worth building.
    const r = lookupPolicies([dispatcherRule], {
      ...q, srcWorkload: "dispatcher/app=vultr-broker", dstWorkload: "goatcounter/app=goatcounter",
    }, site);
    assert.deepEqual([r.matches.length, r.undecidable.length], [0, 0]);
  });

  it("defers on a label the query did not state rather than failing it", () => {
    // Missing is not different. A query that names the namespace and no labels has not said the pod
    // fails the selector — it has said nothing about it.
    const r = lookupPolicies([dispatcherRule], { ...q, srcWorkload: "dispatcher", dstWorkload: "goatcounter" }, site);
    assert.equal(r.undecidable.length, 1);
    const v = r.undecidable[0]?.src;
    assert.match(v?.kind === "undecidable" ? v.why : "", /did not state/);
  });

  it("counts the deferrals a better question would fix, apart from the ones it would not", () => {
    // So the screen can say it once. Forty identical explanations is a list nobody reads to the end.
    const r = lookupPolicies([dispatcherRule, policy({ id: "V6", ports: "8080" })], {
      ...q, dst: "2001:db8::1",
    }, site);
    assert.equal(r.needsWorkload, 1, "the workload rule is waiting on a workload");
    assert.equal(r.undecidable.length, 2, "the IPv6 one is deferred too, but not for that reason");
  });

  it("still says a Service cannot be decided from labels", () => {
    // A Service names pods through a selector this policy does not carry. Guessing from the name
    // would be a match invented out of a string that looks similar.
    const p = policy({ ports: "5432", dst: { kind: "k8s-service", value: "tinyuniverse/vultr-broker" } });
    const r = lookupPolicies([p], { ...q, port: 5432, dstWorkload: "tinyuniverse/app=vultr-broker" }, site);
    assert.equal(r.undecidable.length, 1);
    const v = r.undecidable[0]?.dst;
    assert.match(v?.kind === "undecidable" ? v.why : "", /selector is not in this policy/);
  });
});

describe("what a CIDR means depends on which layer renders it", () => {
  // The first live run of this lookup answered that `GOATCOUNTER-MESH` — source `10.17.0.0/17`,
  // which covers the pod range — matched a query about the broker pod. On the workload layer that
  // rule matches no pod at all, and saying otherwise reproduces on screen the exact misreading that
  // took two teams two document round trips on 2026-08-16.
  const meshRule = policy({
    id: "GOATCOUNTER-MESH", ports: "8080",
    src: { kind: "cidr", value: "10.17.0.0/17" },
    dst: { kind: "k8s-label", value: "k8s:io.kubernetes.pod.namespace=goatcounter,app=goatcounter" },
  });

  it("rules a workload out of a CIDR on the workload layer", () => {
    const r = lookupPolicies([meshRule], {
      src: "", dst: "", srcWorkload: "dispatcher/app=vultr-broker",
      dstWorkload: "goatcounter/app=goatcounter", port: 8080, proto: "tcp",
    }, site);
    assert.deepEqual([r.matches.length, r.undecidable.length], [0, 0],
      "a fromCIDR covering the pod range was reported as matching a pod");
  });

  it("defers rather than matches when a host-layer CIDR is asked about a workload", () => {
    // nftables does see addresses, so the answer is not "no" — it is that the query did not give the
    // one thing that would decide it.
    const hostRule = policy({ id: "DEV-MX-ADMIN", ports: "8080" });
    const r = lookupPolicies([hostRule], {
      src: "", dst: "", srcWorkload: "dispatcher/app=vultr-broker", port: 8080, proto: "tcp",
    }, site);
    assert.equal(r.matches.length, 0, "a host rule matched a workload query it could not decide");
    assert.equal(r.undecidable.length, 1);
    const v = r.undecidable[0]?.src;
    assert.match(v?.kind === "undecidable" ? v.why : "", /host layer filters by address/);
  });

  it("still matches a CIDR when the query gives the address", () => {
    // The known positive for the rule above: giving an address is what makes a host-layer CIDR
    // answerable, and it must still answer.
    const hostRule = policy({ id: "DEV-MX-ADMIN", ports: "8080" });
    const r = lookupPolicies([hostRule], { src: "10.17.0.1", dst: "", port: 8080, proto: "tcp" }, site);
    assert.deepEqual(r.matches.map((m) => m.id), ["DEV-MX-ADMIN"]);
  });
});
