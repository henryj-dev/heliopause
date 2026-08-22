import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseTrafficDump, DEAD_N } from "./workload-traffic.ts";

const DUMP = `Endpoint ID: 25
Path: /sys/fs/bpf/tc/globals/cilium_policy_v2_00025

POLICY   DIRECTION   LABELS (source:key[=value])       PORT/PROTO   PROXY PORT   AUTH TYPE   BYTES    PACKETS   PREFIX
Allow    Ingress     k8s:app=dashboard                 8080/TCP     NONE         disabled    41535    165       24
                     k8s:io.cilium.k8s.policy.cluster=default
Allow    Ingress     cidr:10.254.0.1/32                8444/TCP     NONE         disabled    -        -         24
Allow    Ingress     ANY                               ANY          NONE         disabled    99       9         0
Allow    Egress      ANY                               ANY          NONE         disabled    -        -         0
`;

describe("what has passed the workload allows", () => {
  it("reads a row and its counters — the known positive", () => {
    const s = parseTrafficDump(DUMP);
    assert.equal(s.top.length, 1);
    assert.deepEqual(
      { ...s.top[0] },
      { endpoint: "25", policy: "allow", direction: "ingress", peer: "k8s:app=dashboard", port: "8080/TCP", bytes: 41535, packets: 165 },
    );
  });

  it("keeps an allow that has carried nothing", () => {
    // The finding this exists for, and the one no other instrument reports. A dash means the counter
    // was never touched; dropping those would throw away the whole point.
    const s = parseTrafficDump(DUMP);
    assert.equal(s.dead, 1);
    assert.equal(s.deadSample[0]?.peer, "cidr:10.254.0.1/32");
    assert.equal(s.deadSample[0]?.packets, 0);
  });

  it("drops the catch-all and nothing else", () => {
    // `Allow Ingress ANY ANY` is what an endpoint with no policy has — hundreds of them, none ours.
    const s = parseTrafficDump(DUMP);
    assert.equal(s.entries, 2);
    assert.ok([...s.top, ...s.deadSample].every((r) => r.peer !== "ANY" || r.port !== "ANY"));
  });

  it("says how many it is not showing", () => {
    // A list of forty that does not say it is forty of sixty reads as the whole answer. Truncation
    // that does not announce itself is what this asserts against.
    const lines = ["Endpoint ID: 1", ""];
    for (let i = 0; i < DEAD_N + 20; i++) {
      lines.push(`Allow    Ingress     cidr:10.0.0.${i}/32     80/TCP     NONE     disabled    -    -    24`);
    }
    const s = parseTrafficDump(lines.join("\n"));
    assert.equal(s.dead, DEAD_N + 20);
    assert.equal(s.deadSample.length, DEAD_N);
  });

  it("puts the busiest first, so the top slice is the busiest", () => {
    const s = parseTrafficDump(`Endpoint ID: 1

Allow    Ingress     k8s:app=quiet     80/TCP     NONE     disabled    10     1     24
Allow    Ingress     k8s:app=busy      80/TCP     NONE     disabled    9000   900   24
`);
    assert.deepEqual(s.top.map((r) => r.peer), ["k8s:app=busy", "k8s:app=quiet"]);
  });

  it("survives a line it does not understand", () => {
    // `cilium bpf policy get` is a table meant for people, not a stable API. One odd line must not
    // take the whole reading down — the alternative is a cluster reporting no traffic because of a
    // format change in a column nobody uses.
    assert.equal(parseTrafficDump("Endpoint ID: 7\nnonsense\n").entries, 0);
  });

  it("reads an entry with no endpoint header as belonging to nothing, rather than guessing", () => {
    // Rows before the first `Endpoint ID:` line cannot be attributed. Attaching them to whatever came
    // next would put one endpoint's traffic under another's name.
    assert.equal(parseTrafficDump("Allow    Ingress     k8s:app=x     80/TCP     NONE     disabled    1    1    24\n").entries, 0);
  });
});
