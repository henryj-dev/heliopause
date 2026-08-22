// The `cf-device` / `cf-user` expansion (H13).
//
// Two halves are tested here and they fail differently. Normalisation refuses a *shape* — a device
// name where an id belongs — and that refusal happens without any registry present. Expansion refuses
// a *lookup* — a device nobody approved, a user with no addresses — and every one of those refusals
// exists because the alternative is a wider firewall, not an error: the site wiring feeds this into
// `srcCidrs`, where an empty list means "from anywhere".
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { contains } from "./test-util.ts";
import { deviceCidrs, type ApprovedDevice } from "./device-policy.ts";
import { normalizePolicy, policyFingerprint, PolicyError, type Endpoint } from "./policy.ts";

const DEVICES: ApprovedDevice[] = [
  {
    deviceId: "11111111-2222-4333-8444-555555555551",
    deviceName: "Laptop-A",
    userEmail: "first@example.com",
    v4: "10.254.0.2",
    v6: "2001:db8:1000::1b",
  },
  {
    deviceId: "11111111-2222-4333-8444-555555555552",
    deviceName: "Desktop-B",
    userEmail: "first@example.com",
    v4: "10.254.0.5",
    v6: "2001:db8:1000::9",
  },
  {
    deviceId: "11111111-2222-4333-8444-555555555553",
    deviceName: "Laptop-C",
    userEmail: "second@example.com",
    v4: "10.254.0.3",
    v6: "2001:db8:1000::8",
  },
];

const dev = (value: string): Endpoint => ({ kind: "cf-device", value });
const user = (value: string): Endpoint => ({ kind: "cf-user", value });

describe("expanding an approved device", () => {
  it("renders both families as single-host prefixes", () => {
    // The known positive. Without it every refusal below could pass because the kind expands to
    // nothing at all.
    assert.deepEqual(deviceCidrs(DEVICES, dev("11111111-2222-4333-8444-555555555551")), [
      "10.254.0.2/32",
      "2001:db8:1000::1b/128",
    ]);
  });

  it("unions the devices of one user", () => {
    assert.deepEqual(deviceCidrs(DEVICES, user("first@example.com")), [
      "10.254.0.2/32",
      "10.254.0.5/32",
      "2001:db8:1000::1b/128",
      "2001:db8:1000::9/128",
    ]);
  });

  it("leaves the other user's devices out of that union", () => {
    // The half of the union test that would still pass if the filter were dropped entirely.
    const first = deviceCidrs(DEVICES, user("first@example.com"));
    assert.ok(!first.includes("10.254.0.3/32"), "the other user.s device must not appear in this union");
  });

  it("matches a device id and a user email case-insensitively", () => {
    // Cloudflare writes ids lowercase and `normalizePolicy` lowercases the value, but the registry is
    // hand-edited: an entry typed in upper case must not become a device no policy can name.
    const upper: ApprovedDevice[] = [{ ...DEVICES[0]!, deviceId: DEVICES[0]!.deviceId.toUpperCase(), userEmail: "First@Example.com" }];
    assert.deepEqual(deviceCidrs(upper, dev("11111111-2222-4333-8444-555555555551")), [
      "10.254.0.2/32",
      "2001:db8:1000::1b/128",
    ]);
    assert.deepEqual(deviceCidrs(upper, user("first@example.com")).length, 2);
  });

  it("accepts an address already written as a prefix", () => {
    const pre: ApprovedDevice[] = [{ ...DEVICES[0]!, v4: "10.254.0.2/32", v6: "2001:db8:1000::1b/128" }];
    assert.deepEqual(deviceCidrs(pre, dev(DEVICES[0]!.deviceId)), ["10.254.0.2/32", "2001:db8:1000::1b/128"]);
  });

  it("sorts and deduplicates", () => {
    // Two orderings of the same addresses are the same rule. Left distinct, every hash taken over the
    // rendered ruleset reports a change nobody made.
    const dupe: ApprovedDevice[] = [
      { ...DEVICES[0]!, deviceId: "aaaaaaaa-0000-0000-0000-000000000001", v6: "" },
      { ...DEVICES[1]!, deviceId: "aaaaaaaa-0000-0000-0000-000000000002", v4: "10.254.0.2", v6: "" },
    ];
    assert.deepEqual(deviceCidrs(dupe, user("first@example.com")), ["10.254.0.2/32"]);
  });
});

describe("what expansion refuses", () => {
  it("refuses a device that is not in the approved registry", () => {
    // Not "a device with no addresses yet" — a policy naming something nobody approved. Approving is
    // an edit to the site module, which is where the human decision is recorded.
    assert.throws(() => deviceCidrs(DEVICES, dev("99999999-8888-4777-8666-555555555555")), (e: unknown) => {
      assert.ok(e instanceof PolicyError);
      contains((e as Error).message, "not in the approved registry");
      return true;
    });
  });

  it("refuses a user with no approved devices", () => {
    assert.throws(() => deviceCidrs(DEVICES, user("nobody@example.com")), (e: unknown) => {
      assert.ok(e instanceof PolicyError);
      contains((e as Error).message, "no approved devices");
      return true;
    });
  });

  it("refuses a device that is approved but has no address at all", () => {
    // The case that is fatal even though the lookup succeeded: an empty list handed to `srcCidrs`
    // renders a rule with no address condition, which matches every peer rather than none.
    const blank: ApprovedDevice[] = [{ ...DEVICES[0]!, v4: "", v6: "" }];
    assert.throws(() => deviceCidrs(blank, dev(DEVICES[0]!.deviceId)), (e: unknown) => {
      assert.ok(e instanceof PolicyError);
      contains((e as Error).message, "none of them has an address");
      return true;
    });
  });

  it("keeps a device that has only one family", () => {
    // The other side of the check above. An addressless *family* is normal — the API returns null
    // addresses — and refusing it would make a v4-only device unusable in policy.
    const v4only: ApprovedDevice[] = [{ ...DEVICES[0]!, v6: "" }];
    assert.deepEqual(deviceCidrs(v4only, dev(DEVICES[0]!.deviceId)), ["10.254.0.2/32"]);
  });

  it("refuses a malformed address rather than passing it to the renderer", () => {
    // M-6 in the security audit: an unvalidated address reaching the ruleset. A `PolicyError`, not
    // the renderer's own error class, so a caller catching bad policy input sees this as bad input.
    const bogus: ApprovedDevice[] = [{ ...DEVICES[0]!, v4: "10.254.0.999" }];
    assert.throws(() => deviceCidrs(bogus, dev(DEVICES[0]!.deviceId)), (e: unknown) => {
      assert.ok(e instanceof PolicyError, "must be a PolicyError, not a RenderError");
      contains((e as Error).message, "octet above 255");
      return true;
    });
  });

  it("refuses a registry that lists one device twice", () => {
    const twice: ApprovedDevice[] = [DEVICES[0]!, { ...DEVICES[1]!, deviceId: DEVICES[0]!.deviceId }];
    assert.throws(() => deviceCidrs(twice, dev(DEVICES[0]!.deviceId)), (e: unknown) => {
      contains((e as Error).message, "twice");
      return true;
    });
  });

  it("refuses a registry that spells one user two ways", () => {
    // A cf-user union over both spellings covers a device the screen shows under a different user.
    // Wider than either row reads, which is the direction that matters.
    const mixed: ApprovedDevice[] = [DEVICES[0]!, { ...DEVICES[1]!, userEmail: "FIRST@example.com" }];
    assert.throws(() => deviceCidrs(mixed, user("first@example.com")), (e: unknown) => {
      contains((e as Error).message, "two ways");
      return true;
    });
  });

  it("refuses to expand a kind it does not own", () => {
    assert.throws(() => deviceCidrs(DEVICES, { kind: "cidr", value: "10.0.0.0/8" }), PolicyError);
  });
});

const base = {
  name: "operator laptop to k3s api",
  src: { kind: "cf-device", value: "11111111-2222-4333-8444-555555555551" },
  dst: { kind: "host", value: "k3s-01.dev" },
  proto: "tcp",
  ports: "6443",
  action: "allow",
};

const norm = (over: Record<string, unknown> = {}) => normalizePolicy({ ...base, ...over }, "p-1");

describe("normalising the identity kinds", () => {
  it("accepts a device id on either side", () => {
    assert.equal(norm().src.value, "11111111-2222-4333-8444-555555555551");
    // Unlike a Service, a device is a real host traffic can be sent to, so an egress rule naming one
    // is expressible and is not refused here.
    assert.equal(norm({ src: { kind: "any", value: "" }, dst: { kind: "cf-device", value: base.src.value } }).dst.kind, "cf-device");
  });

  it("accepts a user email", () => {
    assert.deepEqual(norm({ src: { kind: "cf-user", value: "first@example.com" } }).src, {
      kind: "cf-user",
      value: "first@example.com",
    });
  });

  it("refuses a device name where an id belongs", () => {
    // The refusal the kind exists for. A name is a label its owner can rename in the dashboard, and
    // nothing downstream can tell a rename from a different machine.
    assert.throws(() => norm({ src: { kind: "cf-device", value: "Laptop-A" } }), (e: unknown) => {
      assert.ok(e instanceof PolicyError);
      contains((e as Error).message, "device id");
      return true;
    });
  });

  it("refuses an id that is not a device id", () => {
    for (const v of ["11111111", "11111111-2222-4333", "zzzzzzzz-2222-4333-8444-555555555551", ""]) {
      assert.throws(() => norm({ src: { kind: "cf-device", value: v } }), PolicyError, `"${v}" must be refused`);
    }
  });

  it("refuses a cf-user value that is not an email", () => {
    for (const v of ["first", "first@example", "@example.com", ""]) {
      assert.throws(() => norm({ src: { kind: "cf-user", value: v } }), PolicyError, `"${v}" must be refused`);
    }
  });

  it("fingerprints one device the same however its id was typed", () => {
    // Two spellings of one machine must not read as two policies — `policyFingerprint` would report
    // an edit that did not happen, the same hazard `normalizePorts` sorts for.
    const upper = policyFingerprint(norm({ src: { kind: "cf-device", value: base.src.value.toUpperCase() } }));
    assert.equal(upper, policyFingerprint(norm()));
    const mixed = policyFingerprint(norm({ src: { kind: "cf-user", value: "First@Example.Com" } }));
    assert.equal(mixed, policyFingerprint(norm({ src: { kind: "cf-user", value: "first@example.com" } })));
  });

  it("lists the identity kinds when refusing an unknown one", () => {
    assert.throws(() => norm({ src: { kind: "cf-devices", value: base.src.value } }), (e: unknown) => {
      contains((e as Error).message, "cf-device");
      contains((e as Error).message, "cf-user");
      return true;
    });
  });
});
