import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { Policy } from "./policy.ts";
import type { InputItem } from "./nft.ts";
import type { ScreenSite } from "./policy-screen.ts";
import { diffOpenings, siteOpenings } from "./preview-diff.ts";

function allow(id: string, ports: string, srcCidrs: string[]): InputItem {
  const policy: Policy = {
    id,
    name: id,
    src: { kind: "cidr", value: "10.0.0.0/8" },
    dst: { kind: "host", value: "h1.alpha" },
    proto: "tcp",
    ports,
    action: "allow",
    denyMode: "drop",
    priority: 100,
    enabled: true,
    notes: "",
  };
  return { policy, srcCidrs, dstCidrs: ["10.2.0.7/32"] };
}

const site = (items: InputItem[]): ScreenSite => ({
  cfg: {
    tableName: "heliopause",
    internalSupernet: "10.0.0.0/8",
    hookPolicy: { input: "drop", output: "accept" },
    baseline: [{ desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: ["10.9.0.0/16"] }],
  },
  hosts: [{ id: "h1.alpha", stage: "canary", items }],
} as unknown as ScreenSite);

describe("render-diff preview", () => {
  it("lists the ports a host accepts with the sources they are open to", () => {
    const [h] = siteOpenings(site([allow("web", "443", ["10.1.0.0/16"])]));
    assert.equal(h!.host, "h1.alpha");
    assert.deepEqual(
      h!.open.find((o) => o.ports === "443"),
      { proto: "tcp", ports: "443", sources: ["10.1.0.0/16"] },
    );
    // The baseline is part of what the host accepts, and is reported like any other opening.
    assert.ok(h!.open.some((o) => o.ports === "22"), "the baseline port is missing");
  });

  it("reports a widened source as one removed and one added opening", () => {
    // The case that motivated the preview: the same rule, a wider source.
    const before = siteOpenings(site([allow("relay", "8443", ["10.112.0.0/16"])]));
    const after = siteOpenings(site([allow("relay", "8443", ["10.0.0.0/8"])]));
    assert.deepEqual(diffOpenings(before, after), [{
      host: "h1.alpha",
      added: [{ proto: "tcp", ports: "8443", sources: ["10.0.0.0/8"] }],
      removed: [{ proto: "tcp", ports: "8443", sources: ["10.112.0.0/16"] }],
    }]);
  });

  it("reports nothing for an edit that changes no opening", () => {
    const one = siteOpenings(site([allow("web", "443", ["10.1.0.0/16"])]));
    const two = siteOpenings(site([allow("web", "443", ["10.1.0.0/16"])]));
    assert.deepEqual(diffOpenings(one, two), []);
  });

  it("reads an empty source list as open to any source", () => {
    const [h] = siteOpenings(site([allow("any", "80", [])]));
    assert.deepEqual(h!.open.find((o) => o.ports === "80")?.sources, []);
  });
});
