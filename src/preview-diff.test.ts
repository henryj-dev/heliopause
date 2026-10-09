import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { Policy } from "./policy.ts";
import type { InputItem } from "./nft.ts";
import type { ScreenSite } from "./policy-screen.ts";
import { diffRules, siteRules } from "./preview-diff.ts";

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
  it("lists the host's input rules with their sources and destinations", () => {
    const [h] = siteRules(site([allow("web", "443", ["10.1.0.0/16"])]));
    assert.equal(h!.host, "h1.alpha");
    assert.deepEqual(h!.rules.find((r) => r.ports === "443"), {
      verdict: "accept", proto: "tcp", ports: "443",
      sources: ["10.1.0.0/16"], destinations: ["10.2.0.7/32"], family: "ip",
    });
    // The baseline is part of what the host accepts, and is reported like any other rule.
    assert.ok(h!.rules.some((r) => r.ports === "22"), "the baseline rule is missing");
    // Replies and loopback are not policy and are left out.
    assert.ok(h!.rules.every((r) => r.ports !== "" || r.proto !== ""), "an infrastructure rule was listed");
  });

  it("reports a widened source as one removed and one added rule", () => {
    // The case that motivated the preview: the same rule, a wider source.
    const before = siteRules(site([allow("relay", "8443", ["10.112.0.0/16"])]));
    const after = siteRules(site([allow("relay", "8443", ["10.0.0.0/8"])]));
    const rule = (sources: string[]) => ({
      verdict: "accept", proto: "tcp", ports: "8443", sources, destinations: ["10.2.0.7/32"], family: "ip",
    });
    assert.deepEqual(diffRules(before, after), [{
      host: "h1.alpha", added: [rule(["10.0.0.0/8"])], removed: [rule(["10.112.0.0/16"])],
    }]);
  });

  it("reports nothing for an edit that changes no rule", () => {
    const one = siteRules(site([allow("web", "443", ["10.1.0.0/16"])]));
    const two = siteRules(site([allow("web", "443", ["10.1.0.0/16"])]));
    assert.deepEqual(diffRules(one, two), []);
  });

  it("reads an empty source list as open to any source", () => {
    const [h] = siteRules(site([allow("any", "80", [])]));
    assert.deepEqual(h!.rules.find((r) => r.ports === "80")?.sources, []);
  });

  // ## Each of these returned "no change" for an edit that changed what the host accepts
  //
  // Found by review with these exact inputs. A preview that says nothing changed when something did
  // hides the thing it exists to show.
  describe("does not report no change for an edit that changes the host's rules", () => {
    const changed = (a: InputItem[], b: InputItem[]) =>
      diffRules(siteRules(site(a)), siteRules(site(b))).length > 0;

    it("removing a deny that sat in front of an allow", () => {
      const open = allow("web", "443", ["10.1.0.0/16"]);
      const deny: InputItem = {
        ...allow("block", "443", ["10.1.1.9/32"]),
        policy: { ...allow("block", "443", []).policy, action: "deny" },
      };
      assert.ok(changed([deny, open], [open]));
    });

    it("moving an allow to another destination", () => {
      const at = (dst: string): InputItem => ({ ...allow("web", "443", ["10.1.0.0/16"]), dstCidrs: [dst] });
      assert.ok(changed([at("10.2.0.7/32")], [at("10.2.0.8/32")]));
    });

    it("moving an allow from IPv4 to IPv6", () => {
      const at = (dst: string): InputItem => ({ ...allow("web", "443", []), dstCidrs: [dst] });
      assert.ok(changed([at("10.2.0.7/32")], [at("2001:db8::7/128")]));
    });

    it("adding an allow for every protocol, with no ports", () => {
      const base = allow("all", "", ["10.1.0.0/16"]);
      const any: InputItem = { ...base, policy: { ...base.policy, proto: "any", ports: "" } };
      assert.ok(changed([], [any]));
    });
  });
});
