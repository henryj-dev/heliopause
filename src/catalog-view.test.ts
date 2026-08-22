// The catalogue projections — objects, services, feeds, membership, address space.
//
// The case that carries this file is **`usedBy` empty**. An object nobody references is dead
// configuration that still reads as protection when somebody scans the catalogue, and it is the one
// finding here that cannot be seen by reading the policy file: it is an absence across two lists.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  addressSpaceRows, feedRows, membershipRows, objectRows, serviceRows,
} from "./catalog-view.ts";
import type { Policy } from "./policy.ts";
import type { PublishHost } from "./publish.ts";

const policy = (over: Partial<Policy> = {}): Policy => ({
  id: "p1", name: "n", src: { kind: "cidr", value: "10.0.0.0/8" },
  dst: { kind: "host", value: "h" }, proto: "tcp", ports: "22",
  action: "allow", denyMode: "drop", priority: 100, enabled: true, ...over,
});

describe("address objects", () => {
  const obj = { id: "ao-mgmt", kind: "address" as const, name: "management", members: [{ kind: "cidr" as const, value: "10.254.0.0/16" }] };

  it("names the policies that reference it", () => {
    const rows = objectRows([obj], [
      policy({ id: "USES", src: { kind: "object", value: "ao-mgmt" } }),
      policy({ id: "OTHER" }),
    ]);
    assert.deepEqual(rows[0]!.usedBy, ["USES"]);
  });

  it("finds a reference on either end", () => {
    const rows = objectRows([obj], [policy({ id: "DST", dst: { kind: "object", value: "ao-mgmt" } })]);
    assert.deepEqual(rows[0]!.usedBy, ["DST"]);
  });

  it("leaves usedBy empty for an object nothing references", () => {
    // The finding. Dead configuration reads as protection to whoever scans the catalogue, and no
    // amount of reading the policy file shows it — the evidence is an absence across two lists.
    const rows = objectRows([obj], [policy()]);
    assert.deepEqual(rows[0]!.usedBy, []);
  });

  it("labels members with their kind", () => {
    const rows = objectRows([obj], []);
    assert.deepEqual(rows[0]!.members, ["cidr:10.254.0.0/16"]);
  });
});

describe("service objects", () => {
  const svc = { id: "ssh-admin", kind: "service" as const, name: "ssh", members: ["22"] };

  it("matches a reference from the ports field, not from an endpoint", () => {
    // A service object is referenced as `@id` in `ports`. Looking for it among endpoints — the way
    // address objects are found — would report every service as unused.
    const rows = serviceRows([svc], [policy({ id: "USES", ports: "@ssh-admin" })]);
    assert.deepEqual(rows[0]!.usedBy, ["USES"]);
  });

  it("finds it inside a port list", () => {
    const rows = serviceRows([svc], [policy({ id: "USES", ports: "80, @ssh-admin ,443" })]);
    assert.deepEqual(rows[0]!.usedBy, ["USES"]);
  });

  it("does not match a different id that shares a prefix", () => {
    const rows = serviceRows([svc], [policy({ id: "NO", ports: "@ssh-admin-extra" })]);
    assert.deepEqual(rows[0]!.usedBy, []);
  });
});

describe("feeds", () => {
  it("collects the feeds policy asks for, with who asks", () => {
    const rows = feedRows([
      policy({ id: "A", src: { kind: "geofeed", value: "https://feed.example.invalid/kr" } }),
      policy({ id: "B", src: { kind: "geofeed", value: "https://feed.example.invalid/kr" } }),
      policy({ id: "C" }),
    ]);
    assert.equal(rows.length, 1);
    assert.deepEqual(rows[0]!.usedBy, ["A", "B"]);
  });

  it("is empty when no policy uses one", () => {
    // Which is this site. The table disappears rather than showing a header over nothing.
    assert.deepEqual(feedRows([policy()]), []);
  });
});

describe("membership", () => {
  const host = (over = {}) => ({
    host: "k3s-01.dev",
    workload: {
      membership: {
        at: "2026-08-07T01:00:00Z",
        namespaces: { "arc-runners": [], "arc-systems": ["ctl-1"] },
        labelled: {},
      },
    },
    ...over,
  });

  it("keeps the read time on every row", () => {
    // Pod membership goes stale in seconds. A count without the instant it was true is one an
    // operator reads as current.
    const rows = membershipRows([host()]);
    assert.ok(rows.every((r) => r.at === "2026-08-07T01:00:00Z"));
  });

  it("keeps an empty namespace as a row", () => {
    // Zero pods in a CI namespace means "no job right now", not "safe" — they appear the moment one
    // starts. Dropping the row would hide the namespace that matters most.
    const rows = membershipRows([host()]);
    const empty = rows.find((r) => r.name === "arc-runners");
    assert.ok(empty, "the empty namespace must still be listed");
    assert.deepEqual(empty!.members, []);
  });

  it("names the policies whose endpoints produced the query (M10)", () => {
    // The count says how many pods matched. It cannot say whether zero is normal — `arc-runners` is
    // legitimately empty between CI jobs — and that ambiguity is why a bare count was not enough to
    // notice a rule governing nothing. Pairing the row with the rules that depend on it is what
    // separates "idle" from "inert".
    const rows = membershipRows([host()], [
      policy({ id: "RUNNERS-DENY-IDP", src: { kind: "k8s-namespace", value: "arc-runners" } }),
      policy({ id: "SYSTEMS", dst: { kind: "k8s-namespace", value: "arc-systems" } }),
      policy({ id: "ELSEWHERE" }),
    ]);
    assert.deepEqual(rows.find((r) => r.name === "arc-runners")!.usedBy, ["RUNNERS-DENY-IDP"]);
    assert.deepEqual(rows.find((r) => r.name === "arc-systems")!.usedBy, ["SYSTEMS"]);
  });

  it("leaves usedBy empty for a query no policy explains", () => {
    // The finding, not a blank. A selector the applier is answering that no rule references means
    // the question outlived the policy that asked it — cost on every heartbeat for nothing.
    const rows = membershipRows([host()], [policy({ id: "ELSEWHERE" })]);
    assert.deepEqual(rows.find((r) => r.name === "arc-runners")!.usedBy, []);
  });

  it("matches a label selector verbatim, the way the manager asked it", () => {
    // `selectorsToWatch` sends the selector as the policy wrote it, so anything normalised here
    // would stop keying to the question — and the row would read as unreferenced.
    const rows = membershipRows(
      [{ host: "h", workload: { membership: { at: "t", namespaces: {}, labelled: { "k8s:io.kubernetes.pod.namespace=util,app=runner": ["p"] } } } }],
      [policy({ id: "PINNED", src: { kind: "k8s-label", value: "k8s:io.kubernetes.pod.namespace=util,app=runner" } })],
    );
    assert.deepEqual(rows[0]!.usedBy, ["PINNED"]);
  });

  it("separates namespaces from label selectors", () => {
    const rows = membershipRows([{
      host: "h",
      workload: { membership: { at: "t", namespaces: { ns: [] }, labelled: { "app=x": ["p"] } } },
    }]);
    assert.deepEqual(rows.map((r) => r.kind).sort(), ["namespace", "selector"]);
  });

  it("skips a host that reported nothing", () => {
    assert.deepEqual(membershipRows([{ host: "h", workload: null }]), []);
    assert.deepEqual(membershipRows([{ host: "h" }]), []);
  });
});

describe("address space", () => {
  const host = (id: string, src: string[], dst: string[]): PublishHost => ({
    id, stage: "general",
    items: [{ policy: policy(), srcCidrs: src, dstCidrs: dst }],
    egress: [],
  });

  it("unions sources and destinations across hosts", () => {
    const rows = addressSpaceRows([
      host("a", ["10.254.0.0/16"], ["10.17.0.1/32"]),
      host("b", ["10.254.0.0/16"], ["10.17.0.2/32"]),
    ]);
    const mgmt = rows.find((r) => r.cidr === "10.254.0.0/16")!;
    assert.equal(mgmt.asSource, 2, "counted once per referencing item");
    assert.deepEqual(mgmt.asHost, []);
  });

  it("names the hosts a destination CIDR belongs to", () => {
    const rows = addressSpaceRows([host("a", [], ["10.17.0.1/32"])]);
    assert.deepEqual(rows.find((r) => r.cidr === "10.17.0.1/32")!.asHost, ["a"]);
  });

  it("sorts, so the same site renders the same table twice", () => {
    const rows = addressSpaceRows([host("a", ["10.2.0.0/16", "10.1.0.0/16"], [])]);
    assert.deepEqual(rows.map((r) => r.cidr), ["10.1.0.0/16", "10.2.0.0/16"]);
  });
});
