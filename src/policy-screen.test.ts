// Which policies the catalogue tables are built from.
//
// `objectRows`, `serviceRows` and `feedRows` each answer "who references this", and they answer it
// about whatever list `buildScreen` hands them. That list left out `site.workload`, so anything
// referenced only by a CiliumNetworkPolicy came back with no references at all — and an empty
// `usedBy` is not a blank cell on this screen. `catalog-view.ts` defines it as dead configuration
// that still reads as protection, which makes the omission an assertion rather than a gap.
//
// Tested through `buildScreen` rather than through `objectRows`: the projections were always
// correct about the list they were given, and a test at that level passes either way.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildScreen } from "./policy-screen.ts";
import { DEFAULT_CONFIG } from "./config.ts";
import type { Policy } from "./policy.ts";

const policy = (over: Partial<Policy> = {}): Policy => ({
  id: "p1", name: "n", src: { kind: "cidr", value: "10.0.0.0/8" },
  dst: { kind: "host", value: "h" }, proto: "tcp", ports: "22",
  action: "allow", denyMode: "drop", priority: 100, enabled: true, ...over,
});

const operators = {
  id: "ao-operators",
  kind: "address" as const,
  name: "operators",
  members: [{ kind: "cf-user" as const, value: "jang@example.com" }],
};

/** A site whose only reference to the object is a workload policy — the case that was invisible. */
const siteWith = (workload: Array<{ policy: Policy }>) => ({
  // A real config, so the renderer inside `buildScreen` succeeds. Half a config would be caught by
  // its `try` and the tables would still be built — the assertions below would then be passing on the
  // failure path, which is a different code path from the one operators see.
  cfg: { ...DEFAULT_CONFIG, hookPolicy: { input: "drop" as const, output: "accept" as const } },
  // `stage` is required by the renderer: without a canary every host would apply at once, and it
  // refuses rather than render that. Set here so the tables below come from a successful render.
  hosts: [{ id: "h1", stage: "canary" as const, items: [{ policy: policy({ id: "HOST-RULE" }), srcCidrs: ["10.0.0.0/8"], dstCidrs: ["10.0.0.1/32"] }] }],
  workload,
  objects: [operators],
});

const screenFor = (workload: Array<{ policy: Policy }>) =>
  // `sitePath` is only read for git history and coverage files; a path with neither yields empty
  // sections rather than an error, which is what makes this assembly testable without a fixture repo.
  buildScreen({ site: siteWith(workload) as never, sitePath: "/nonexistent/site.ts", label: "test" });

describe("the object catalogue sees every layer", () => {
  it("names a workload policy that references an object", () => {
    const rows = screenFor([{ policy: policy({ id: "WORKLOAD-RULE", src: { kind: "object", value: "ao-operators" } }) }]);
    const row = rows.extra.objects?.find((o) => o.id === "ao-operators");
    assert.ok(row, "the object is missing from the catalogue entirely");
    assert.deepEqual(row.usedBy, ["WORKLOAD-RULE"]);
  });

  it("still reports an object nothing references", () => {
    // The other half. If the fix had been "assume anything in the catalogue is used", this passes
    // nothing — the screen's one finding is exactly this row.
    const rows = screenFor([{ policy: policy({ id: "WORKLOAD-RULE" }) }]);
    assert.deepEqual(rows.extra.objects?.find((o) => o.id === "ao-operators")?.usedBy, []);
  });

  it("counts a policy placed on both layers once", () => {
    // Host placement and workload placement of one rule is a legitimate combination, and a rule
    // listed twice reads as two independent callers of the object.
    const shared = policy({ id: "BOTH", src: { kind: "object", value: "ao-operators" } });
    const site = siteWith([{ policy: shared }]);
    site.hosts[0]!.items.push({ policy: shared, srcCidrs: ["10.0.0.0/8"], dstCidrs: ["10.0.0.1/32"] });
    const rows = buildScreen({ site: site as never, sitePath: "/nonexistent/site.ts", label: "test" });
    assert.deepEqual(rows.extra.objects?.find((o) => o.id === "ao-operators")?.usedBy, ["BOTH"]);
  });
});
