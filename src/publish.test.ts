// Publishing tests.
//
// The properties here are about what a generation *means*. A generation that is partly published,
// or that cannot be staged, or whose id does not identify its content, is worse than no generation
// at all — because the hosts that did receive it report success.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { contains } from "./test-util.ts";
import { defineConfig } from "./config.ts";
import { planPublish, PublishError, type PublishHost } from "./publish.ts";
import { normalizePolicy, type Policy } from "./policy.ts";
import { isSingleAddress } from "./nft.ts";
import type { ServiceSelector } from "./cilium.ts";

const cfg = defineConfig({
  tableName: "heliopause",
  internalSupernet: "10.0.0.0/8",
  baseline: [{ desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: [] }],
});

const policy = (over: Partial<Policy> = {}): Policy => ({
  id: "P1",
  name: "test",
  src: { kind: "cidr", value: "10.1.0.0/16" },
  dst: { kind: "host", value: "h" },
  proto: "tcp",
  ports: "5432",
  action: "deny",
  denyMode: "drop",
  priority: 100,
  enabled: true,
  notes: "",
  ...over,
});

const host = (id: string, stage: PublishHost["stage"], items: PublishHost["items"] = []) => ({
  id,
  stage,
  items,
});

const input = (hosts: PublishHost[]) => ({
  cfg,
  generation: "abc1234",
  issuedAt: "2026-07-31T00:00:00.000Z",
  hosts,
});

describe("planPublish", () => {
  it("renders one artifact per host", () => {
    const plan = planPublish(input([host("a", "canary"), host("b", "general")]));
    assert.equal(plan.artifacts.length, 2);
    assert.deepEqual(Object.keys(plan.manifest.hosts).sort(), ["a", "b"]);
  });

  it("hashes the artifact it actually emits", async () => {
    const plan = planPublish(input([host("a", "canary")]));
    const { createHash } = await import("node:crypto");
    const a = plan.artifacts[0]!;
    assert.equal(a.entry.rulesetHash, "sha256:" + createHash("sha256").update(a.json).digest("hex"));
  });

  it("carries each host's assertions into the manifest", () => {
    const plan = planPublish(input([host("a", "canary")]));
    contains(plan.manifest.hosts["a"]!.mustContain.join("|"), "baseline: management SSH");
  });

  it("reports skipped policies without failing the publish", () => {
    const items = [{ policy: policy({ enabled: false }), srcCidrs: [], dstCidrs: ["10.2.0.7"] }];
    const plan = planPublish(input([host("a", "canary", items)]));
    assert.equal(plan.artifacts[0]!.skipped.length, 1);
  });
});

// The address a policy targets has to travel with the artifact, because the agent is the only party
// that can check it: the publisher is pure and the relay deliberately cannot interpret what it
// serves. Measured failure this closes — mailer-01 rebooted onto a different address, the publish
// succeeded, the rules rendered, the baseline assertions passed, and every service rule matched
// traffic that would never arrive.
describe("expectAddrs", () => {
  const withDst = (dst: string) => [{ policy: policy({ action: "allow" }), srcCidrs: [], dstCidrs: [dst] }];

  it("carries the single address the rules target", () => {
    const cfgDrop = defineConfig({ ...cfg, hookPolicy: { input: "drop", output: "accept" } });
    const plan = planPublish({
      cfg: cfgDrop,
      generation: "abc1234",
      issuedAt: "2026-07-31T00:00:00Z",
      hosts: [host("a", "canary", withDst("10.17.101.12"))],
    });
    assert.deepEqual(plan.manifest.hosts["a"]!.expectAddrs, ["10.17.101.12"]);
  });

  // A prefix is satisfied by any address inside it, so it would pass for a host that moved within
  // its own VPC — which is precisely the failure being caught.
  it("ignores prefixes, which identify no single host", () => {
    const cfgDrop = defineConfig({ ...cfg, hookPolicy: { input: "drop", output: "accept" } });
    const plan = planPublish({
      cfg: cfgDrop,
      generation: "abc1234",
      issuedAt: "2026-07-31T00:00:00Z",
      hosts: [host("a", "canary", withDst("10.17.0.0/16"))],
    });
    assert.equal(plan.manifest.hosts["a"]!.expectAddrs, undefined);
  });

  // No interface ever holds the all-ones broadcast address; DHCP rules name it because a client
  // without an address can only send there.
  it("ignores the broadcast address", () => {
    const cfgDrop = defineConfig({ ...cfg, hookPolicy: { input: "drop", output: "accept" } });
    const plan = planPublish({
      cfg: cfgDrop,
      generation: "abc1234",
      issuedAt: "2026-07-31T00:00:00Z",
      hosts: [host("a", "canary", withDst("255.255.255.255"))],
    });
    assert.equal(plan.manifest.hosts["a"]!.expectAddrs, undefined);
  });

  // Absent rather than `[]`: "nothing to check" and "checked and found nothing" are different, and
  // the agent treats the first as success.
  it("omits the field when no address is targeted", () => {
    const plan = planPublish(input([host("a", "canary")]));
    assert.equal(plan.manifest.hosts["a"]!.expectAddrs, undefined);
  });

  // ## The `/32` cases
  //
  // Every test above writes addresses bare, and that is what let the defect through: the filter was
  // `!c.includes("/")`, which discards `10.17.0.1/32` as though it were a subnet. A resolver emitting
  // full-length CIDRs therefore produced no `expectAddrs` at all, the agent returned early on the
  // empty list, and the address check silently did not run.
  //
  // Measured 2026-08-03 with three gateway addresses in `/32` form. The live fleet was unaffected only
  // because `policy/dev.ts` happens to write them bare — an accident, and stardust's
  // `makeResolveCidrs` returns `${ip}/32`.

  it("treats a /32 as the single address it is", () => {
    const cfgDrop = defineConfig({ ...cfg, hookPolicy: { input: "drop", output: "accept" } });
    const plan = planPublish({
      cfg: cfgDrop,
      generation: "abc1234",
      issuedAt: "2026-07-31T00:00:00Z",
      hosts: [host("a", "canary", withDst("10.17.101.12/32"))],
    });
    // Normalised bare, because the agent compares against what its interfaces hold. Carrying the
    // suffix through would fail for every host — worse than not checking, since it reverts every
    // generation rather than accepting a wrong one.
    assert.deepEqual(plan.manifest.hosts["a"]!.expectAddrs, ["10.17.101.12"]);
  });

  it("treats a /128 as the single address it is", () => {
    const cfgDrop = defineConfig({ ...cfg, hookPolicy: { input: "drop", output: "accept" } });
    const plan = planPublish({
      cfg: cfgDrop,
      generation: "abc1234",
      issuedAt: "2026-07-31T00:00:00Z",
      hosts: [host("a", "canary", withDst("2001:db8:1c01:2d0::1/128"))],
    });
    assert.deepEqual(plan.manifest.hosts["a"]!.expectAddrs, ["2001:db8:1c01:2d0::1"]);
  });

  it("still ignores the broadcast address written as a /32", () => {
    // Dropped this filter once while rewriting the expression. A host whose only inbound policy is
    // DHCP would have had `expectAddrs: ["255.255.255.255"]`, which no interface holds.
    const cfgDrop = defineConfig({ ...cfg, hookPolicy: { input: "drop", output: "accept" } });
    const plan = planPublish({
      cfg: cfgDrop,
      generation: "abc1234",
      issuedAt: "2026-07-31T00:00:00Z",
      hosts: [host("a", "canary", withDst("255.255.255.255/32"))],
    });
    assert.equal(plan.manifest.hosts["a"]!.expectAddrs, undefined);
  });

  it("does not list one address twice for being written two ways", () => {
    const cfgDrop = defineConfig({ ...cfg, hookPolicy: { input: "drop", output: "accept" } });
    const plan = planPublish({
      cfg: cfgDrop,
      generation: "abc1234",
      issuedAt: "2026-07-31T00:00:00Z",
      hosts: [
        host("a", "canary", [
          { policy: policy({ id: "P1", action: "allow" }), srcCidrs: [], dstCidrs: ["10.17.101.12"] },
          { policy: policy({ id: "P2", action: "allow", ports: "8443" }), srcCidrs: [], dstCidrs: ["10.17.101.12/32"] },
        ]),
      ],
    });
    assert.deepEqual(plan.manifest.hosts["a"]!.expectAddrs, ["10.17.101.12"]);
  });

  it("keeps ignoring a prefix that is not full length", () => {
    // The property the /32 fix must not break: `10.17.0.0/16` is satisfied by any address on the VPC.
    const cfgDrop = defineConfig({ ...cfg, hookPolicy: { input: "drop", output: "accept" } });
    for (const wide of ["10.17.0.0/16", "10.0.0.0/8", "2001:db8:1c01::/48", "0.0.0.0/0"]) {
      const plan = planPublish({
        cfg: cfgDrop,
        generation: "abc1234",
        issuedAt: "2026-07-31T00:00:00Z",
        hosts: [host("a", "canary", withDst(wide))],
      });
      assert.equal(plan.manifest.hosts["a"]!.expectAddrs, undefined, `${wide} was treated as one host`);
    }
  });
});

describe("isSingleAddress", () => {
  // Tested directly as well as through the publisher, because it is the predicate that decides
  // whether the address check runs at all — and the failure mode is a check that quietly does not.
  it("accepts a bare address and a full-length prefix, in both families", () => {
    for (const one of ["10.17.0.1", "10.17.0.1/32", "2001:db8::1", "2001:db8::1/128"]) {
      assert.equal(isSingleAddress(one), true, `${one} names one machine`);
    }
  });

  it("rejects anything wider", () => {
    for (const many of ["10.17.0.0/16", "10.0.0.0/8", "0.0.0.0/0", "2001:db8::/48", "::/0"]) {
      assert.equal(isSingleAddress(many), false, `${many} names more than one machine`);
    }
  });

  it("does not mistake an IPv6 address for a prefix, nor a /32 IPv6 for a host", () => {
    // An IPv6 address has colons and no slash; a naive "contains a colon" test would get this wrong.
    // And `/32` is a full length for IPv4 only — on IPv6 it is a very wide prefix.
    assert.equal(isSingleAddress("2001:db8:1c01:2d0:5400:6ff:fe77:7373"), true);
    assert.equal(isSingleAddress("2001:db8::1/32"), false);
    assert.equal(isSingleAddress("10.17.0.1/128"), false);
  });

  it("rejects a malformed prefix length rather than guessing", () => {
    assert.equal(isSingleAddress("10.17.0.1/"), false);
    assert.equal(isSingleAddress("10.17.0.1/abc"), false);
  });
});

describe("refusals", () => {
  // Publishing the rest would hand out a generation that is *partly* what was intended, and the
  // hosts that did receive it would report success.
  it("aborts the whole publish when one host cannot render", () => {
    const bad = [{ policy: policy(), srcCidrs: ["not-an-ip"], dstCidrs: ["10.2.0.7"] }];
    assert.throws(
      () => planPublish(input([host("a", "canary"), host("b", "general", bad)])),
      /cannot render b/,
    );
  });

  // Without a canary the first stage to open is `general`, and every host in it applies at once —
  // the exact failure staging exists to prevent.
  it("refuses a generation with no canary", () => {
    assert.throws(() => planPublish(input([host("a", "general")])), /no host is assigned the canary/);
  });

  it("refuses a duplicated host", () => {
    assert.throws(() => planPublish(input([host("a", "canary"), host("a", "general")])), /twice/);
  });

  it("refuses an empty host list", () => {
    assert.throws(() => planPublish(input([])), PublishError);
  });

  it("refuses an empty generation id", () => {
    assert.throws(
      () => planPublish({ ...input([host("a", "canary")]), generation: "" }),
      /generation id is empty/,
    );
  });
});

// ── The config guard, at the render boundary ────────────────────────────────
//
// `defineConfig` holds the safety invariants and, until 2026-08-22, ran only inside the policy
// repository's site modules. `planPublish` is also reached from `POST /policy/plan`, where `cfg`
// arrives as JSON from the policy renderer — the process the manager's own header calls "the
// untrusted side of that connection", and whose payload `parsePolicySource` checks only far enough
// to render. So the guard was inside the trust boundary rather than at it.
//
// The dangerous case is the one `config.ts` calls "the one configuration that is certainly wrong":
// a dropping input hook with an empty baseline. It renders cleanly, its only assertion is
// `baseline: loopback`, so the agent's `mustContain` check passes; the heartbeat leaves through the
// output chain and returns on the input chain's conntrack rule, so the host confirms — with the
// management path gone and the rollback timer never firing, because the relay path survived.

describe("the config is validated where it is rendered from", () => {
  // The known positive, and it is not decoration: every refusal below would also pass against a
  // `planPublish` that had been broken into refusing everything, and that failure is invisible.
  it("still renders a config that defineConfig accepts", () => {
    const plan = planPublish(input([host("a", "canary")]));
    assert.equal(plan.artifacts.length, 1);
    assert.equal(plan.manifest.hosts["a"]!.stage, "canary");
  });

  // Idempotent for anything already built with `defineConfig` — which is what every site module
  // does — so re-validating changes nothing about what publishes today.
  it("re-validating an already-validated config changes nothing", () => {
    const once = planPublish(input([host("a", "canary")]));
    const twice = planPublish({ ...input([host("a", "canary")]), cfg: defineConfig(cfg) });
    assert.deepEqual(twice.manifest.hosts, once.manifest.hosts);
  });

  it("refuses a dropping input hook with an empty baseline", () => {
    assert.throws(
      () =>
        planPublish({
          ...input([host("a", "canary")]),
          cfg: { ...cfg, hookPolicy: { input: "drop", output: "accept" }, baseline: [] },
        }),
      /config is unsafe to render from.*locks every host out of itself/s,
    );
  });

  it("refuses a confirm window too short for a heartbeat to land in", () => {
    assert.throws(
      () =>
        planPublish({
          ...input([host("a", "canary")]),
          cfg: {
            ...cfg,
            relay: { url: "https://gw.invalid:8443", heartbeatIntervalSec: 15 },
            tls: { certFile: "c", keyFile: "k", caFile: "a", pins: [] },
            confirmTimeoutSec: 5,
          },
        }),
      /config is unsafe to render from.*confirmTimeoutSec/s,
    );
  });

  it("refuses a table name that is not an nftables identifier", () => {
    assert.throws(
      () => planPublish({ ...input([host("a", "canary")]), cfg: { ...cfg, tableName: "not a name" } }),
      /config is unsafe to render from.*tableName/s,
    );
  });

  // A workload config `defineConfig` refuses is refused here too. Note what this does *not* prove —
  // see the comment on `planWorkload`'s `cfg` parameter. The guard at the top of `planPublish`
  // catches this before `planWorkload` runs, so this test passes whichever config that function
  // reads. Written out because the obvious reading of it is wrong.
  it("refuses a workload timer that does not clear the host timer", () => {
    assert.throws(
      () =>
        planPublish({
          ...input([host("a", "canary")]),
          cfg: {
            ...cfg,
            workload: {
              cluster: "k3s",
              applier: "a",
              ciliumVersion: [1, 17],
              // Must exceed confirmTimeoutSec: Cilium converges after the API server returns, so a
              // shorter window rolls back healthy policy mid-convergence (H20).
              confirmTimeoutSec: 1,
            },
          },
        }),
      /config is unsafe to render from.*workload\.confirmTimeoutSec/s,
    );
  });
});

// ── Seam: what the publisher writes, the relay must be able to serve ─────────
//
// These two are the only pair in the system that communicate through the filesystem rather than a
// typed call, so nothing but a test crossing the boundary can catch them drifting apart.

describe("publisher → relay", () => {
  it("writes a directory the relay can load and serve from", async (t) => {
    const { mkdtemp, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { generateKeyPairSync } = await import("node:crypto");
    const { bundleFromPlan } = await import("./bundle.ts");
    const {
      loadAuthorizedArtifactBundle,
      signAuthorizedArtifactBundle,
      verifyHostArtifactAuthorization,
      writeAuthorizedArtifactBundle,
    } = await import("./artifact-signature.ts");

    const dir = await mkdtemp(join(tmpdir(), "hp-publish-"));
    t.after(() => rm(dir, { recursive: true, force: true }));

    const plan = planPublish(input([host("h-a", "canary"), host("h-b", "gateway")]));
    const keys = generateKeyPairSync("ed25519");
    const authorized = signAuthorizedArtifactBundle({
      target: "dev",
      bundle: bundleFromPlan(plan),
      authorizedAt: "2026-07-31T00:01:00.000Z",
      expiresAt: "2026-08-01T00:01:00.000Z",
      authorizationMode: "two-person",
    }, keys.privateKey);
    await writeAuthorizedArtifactBundle(dir, authorized);

    const stored = await loadAuthorizedArtifactBundle(dir);
    const manifest = stored.manifest;
    assert.equal(manifest.generation, "abc1234");
    assert.deepEqual(Object.keys(manifest.hosts).sort(), ["h-a", "h-b"]);

    // The digest the relay hands an agent has to describe the bytes the relay hands it, or the
    // agent refuses the artifact and the rollout stalls on every host.
    const served = verifyHostArtifactAuthorization(stored.artifacts["h-a"], {
      trustedKeys: { manager: [keys.publicKey], breakGlass: [] },
      expectedTarget: "dev",
      expectedHost: "h-a",
      now: new Date("2026-07-31T00:02:00.000Z"),
    }).ruleset;
    const { createHash } = await import("node:crypto");
    assert.equal(
      manifest.hosts["h-a"]!.rulesetHash,
      "sha256:" + createHash("sha256").update(served).digest("hex"),
    );

    contains(manifest.hosts["h-a"]!.mustContain.join("|"), "baseline: management SSH");
  });

  // The relay polls this directory on a timer and has no idea a publish is running. If the
  // manifest appeared before the files it names, an agent could be told to apply a generation
  // whose ruleset does not exist yet.
  it("leaves no temporary file behind", async (t) => {
    const { mkdtemp, rm, readdir } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { generateKeyPairSync } = await import("node:crypto");
    const { bundleFromPlan } = await import("./bundle.ts");
    const { signAuthorizedArtifactBundle, writeAuthorizedArtifactBundle } = await import("./artifact-signature.ts");

    const dir = await mkdtemp(join(tmpdir(), "hp-publish-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const keys = generateKeyPairSync("ed25519");
    const plan = planPublish(input([host("h-a", "canary")]));
    const signed = signAuthorizedArtifactBundle({
      target: "dev", bundle: bundleFromPlan(plan),
      authorizedAt: "2026-07-31T00:01:00.000Z", expiresAt: "2026-08-01T00:01:00.000Z",
      authorizationMode: "two-person",
    }, keys.privateKey);
    await writeAuthorizedArtifactBundle(dir, signed);
    assert.deepEqual((await readdir(dir)).sort(), ["authorized-bundle.json"]);
  });
});

// ── The workload half ─────────────────────────────────────────────────────────
//
// The property under test throughout: a generation is one thing. If the nftables half can be
// published while the workload half is missing or unassigned, a host confirms cleanly over a policy
// set that is only partly enforced — and for a pod destination there is no second layer behind it
// (evaluation rule 8).

const NS = "k8s:io.kubernetes.pod.namespace";

const SERVICES: Record<string, ServiceSelector> = {
  "util/zot": { namespace: "util", name: "zot", selector: { app: "zot" }, pods: ["util/zot-abc"] },
};

const wlCfg = defineConfig({
  tableName: "heliopause",
  internalSupernet: "10.0.0.0/8",
  baseline: [{ desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: [] }],
  workload: {
    cluster: "dev",
    applier: "h-k3s-01",
    ciliumVersion: [1, 17],
    // Must exceed the 60s host default — the workload layer needs Cilium's convergence time (H20).
    confirmTimeoutSec: 300,
  },
});

/** A policy the workload layer owns: an address source reaching a Service. */
const wlPolicy = (over: Partial<Policy> = {}) =>
  normalizePolicy(
    {
      name: "runners to zot",
      src: { kind: "cidr", value: "10.17.0.0/16" },
      dst: { kind: "k8s-service", value: "util/zot" },
      proto: "tcp",
      ports: "443",
      action: "allow",
      priority: 100,
      ...over,
    },
    over.id ?? "P700",
  );

const wlInput = (hosts: PublishHost[], workload: Policy[] = [wlPolicy()]) => ({
  cfg: wlCfg,
  generation: "abc1234",
  issuedAt: "2026-07-31T00:00:00Z",
  hosts,
  // The address side needs resolution injected, same as the host renderer. A `cidr` endpoint carries
  // its own value, but the renderer takes resolved CIDRs rather than re-parsing the endpoint.
  workload: workload.map((policy) => ({
    policy,
    ...(policy.src.kind === "cidr" ? { srcCidrs: [policy.src.value] } : {}),
  })),
  resolveService: (ref: string) => SERVICES[ref] ?? null,
});

describe("planPublish — the workload half", () => {
  it("ships a namespace ingress-default-deny baseline even without a flow policy", () => {
    const plan = planPublish({
      ...wlInput([host("h-k3s-01", "canary")], []),
      workloadBaselines: [{
        kind: "namespace-ingress-default-deny", id: "STARDUST-DATABASES", namespace: "stardust-databases",
        description: "Default deny ingress for Stardust-managed database workloads.",
      }],
    });
    const baseline = (JSON.parse(plan.workload!.json) as { items: Array<{ metadata: { name: string; annotations: Record<string, string> }; spec: Record<string, unknown> }> }).items[0]!;
    assert.equal(baseline.metadata.name, "hp-dev-stardust-databases-baseline");
    assert.equal(baseline.metadata.annotations["heliopause.io/policy-kind"], "namespace-ingress-default-deny");
    assert.deepEqual(baseline.spec, {
      description: "Default deny ingress for Stardust-managed database workloads.",
      endpointSelector: { matchLabels: { [NS]: "stardust-databases" } },
      enableDefaultDeny: { ingress: true },
      ingress: [{ fromEndpoints: [{ matchLabels: { [NS]: "HELI0PAUSE-NEVER" } }] }],
    });
    assert.deepEqual(plan.manifest.hosts["h-k3s-01"]!.workload!.ingressDefaultDenyNamespaces, ["stardust-databases"]);
  });
  it("ships a selector-scoped egress baseline and watches the pods it closes", () => {
    // The egress posture the deny-list form could never express: reach nothing except what is
    // named. What is asserted here beyond the object itself is the watch — the agent will not call
    // a generation confirmed until it has seen a pod under every selector published, and an egress
    // baseline that selects nobody closes nobody while reading as containment.
    const plan = planPublish({
      ...wlInput([host("h-k3s-01", "canary")], []),
      workloadBaselines: [{
        kind: "selector-egress-default-deny", id: "VULTR-BROKER-EGRESS", namespace: "dispatcher",
        selector: `${NS}=dispatcher,app=vultr-broker`,
        description: "Default deny egress for the Vultr root-key broker.",
      }],
    });
    const obj = (JSON.parse(plan.workload!.json) as { items: Array<{ metadata: { name: string; annotations: Record<string, string> }; spec: Record<string, unknown> }> }).items[0]!;
    assert.equal(obj.metadata.name, "hp-dev-vultr-broker-egress-egress-baseline");
    assert.equal(obj.metadata.annotations["heliopause.io/policy-kind"], "selector-egress-default-deny");
    assert.deepEqual(obj.spec.enableDefaultDeny, { egress: true });
    const entry = plan.manifest.hosts["h-k3s-01"]!.workload!;
    // An ingress-only field. An egress baseline protects nothing the relay's exposure check is
    // about, so it must not appear here — a HostPort is not made safe by a closed *egress* posture.
    assert.equal(entry.ingressDefaultDenyNamespaces, undefined);
    assert.deepEqual(entry.watchSelectors, { namespaces: [], labels: [`${NS}=dispatcher,app=vultr-broker`] });
  });

  it("renders it once and addresses it to the applier, not to every host", () => {
    // CiliumNetworkPolicy is cluster-scoped. Three nodes writing one object is API contention with
    // flapping, so exactly one manifest entry carries the assignment.
    const plan = planPublish(
      wlInput([host("h-k3s-01", "canary"), host("h-k3s-02", "general")]),
    );
    assert.equal(plan.workload?.applier, "h-k3s-01");
    assert.ok(plan.manifest.hosts["h-k3s-01"]!.workload);
    assert.equal(plan.manifest.hosts["h-k3s-02"]!.workload, undefined);
  });

  it("derives mustExist from the objects it emitted, so the check cannot drift from them", () => {
    const plan = planPublish(wlInput([host("h-k3s-01", "canary")]));
    const objects = (JSON.parse(plan.workload!.json) as { items: Array<{ metadata: { namespace: string; name: string } }> }).items;
    assert.deepEqual(
      plan.manifest.hosts["h-k3s-01"]!.workload!.mustExist,
      objects.map((o) => `${o.metadata.namespace}/${o.metadata.name}`),
    );
  });

  it("records rendered ingress selectors for eBPF exposure accounting", () => {
    const plan = planPublish(wlInput([host("h-k3s-01", "canary")]));
    assert.deepEqual(
      plan.manifest.hosts["h-k3s-01"]!.workload!.ingressProtectedSelectors,
      [{ [NS]: "util", app: "zot" }],
    );
  });

  it("hashes the document it actually emits", async () => {
    const plan = planPublish(wlInput([host("h-k3s-01", "canary")]));
    const { createHash } = await import("node:crypto");
    assert.equal(
      plan.manifest.hosts["h-k3s-01"]!.workload!.policiesHash,
      "sha256:" + createHash("sha256").update(plan.workload!.json).digest("hex"),
    );
  });

  it("carries the workload timeout, not the host one", () => {
    // H20: the two layers fail differently. Reusing 60s here would roll back healthy policy while
    // Cilium was still converging.
    const plan = planPublish(wlInput([host("h-k3s-01", "canary")]));
    assert.equal(plan.manifest.hosts["h-k3s-01"]!.workload!.confirmTimeoutSec, 300);
    assert.equal(plan.manifest.hosts["h-k3s-01"]!.confirmTimeoutSec, 90);
  });

  it("surfaces render warnings rather than swallowing them", () => {
    // A rendered rule narrower or wider than written has to reach the operator before they believe
    // the generation. An icmp policy renders with no protocol condition at all.
    const plan = planPublish(
      wlInput([host("h-k3s-01", "canary")], [wlPolicy({ id: "P701", proto: "icmp", ports: "" })]),
    );
    contains(plan.workload!.warnings.map((w) => w.warning).join("\n"), "covers every protocol");
  });

  it("refuses a workload policy when no workload layer is configured", () => {
    // The failure this prevents: publishing the host half alone, which confirms cleanly over traffic
    // netfilter cannot see.
    assert.throws(
      () =>
        planPublish({
          ...wlInput([host("h-k3s-01", "canary")]),
          cfg,
        }),
      (e: unknown) => {
        assert.ok(e instanceof PublishError);
        contains((e as Error).message, "cfg.workload is null");
        contains((e as Error).message, "never reaches a netfilter hook");
        return true;
      },
    );
  });

  it("refuses an applier that is not among the published hosts", () => {
    // The manifest would name an assignment nothing ever fetches, and the workload half would
    // silently never be applied.
    assert.throws(
      () => planPublish(wlInput([host("h-other", "canary")])),
      (e: unknown) => {
        assert.ok(e instanceof PublishError);
        contains((e as Error).message, "would never fetch");
        return true;
      },
    );
  });

  it("aborts the whole generation when the workload half cannot render", () => {
    // All or nothing, like the host half. A partly-published generation is worse than none, because
    // the hosts that got it report success.
    assert.throws(
      () =>
        planPublish(
          wlInput([host("h-k3s-01", "canary")], [
            wlPolicy({ id: "P702", dst: { kind: "k8s-service", value: "util/missing" } }),
          ]),
        ),
      (e: unknown) => {
        assert.ok(e instanceof PublishError);
        contains((e as Error).message, "cannot render the workload layer");
        return true;
      },
    );
  });

  it("emits nothing when no policy needs the layer, even with workload configured", () => {
    // A host-only policy set should not produce an empty workload assignment — the agent would then
    // have an apply step whose document governs nothing.
    const plan = planPublish({
      ...wlInput([host("h-k3s-01", "canary")]),
      workload: [{ policy: policy({ id: "P703" }) }],
    });
    assert.equal(plan.workload, undefined);
    assert.equal(plan.manifest.hosts["h-k3s-01"]!.workload, undefined);
  });

  it("writes the workload document beside the rulesets", async (t) => {
    const { mkdtemp, rm, readdir } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { writePublish } = await import("./publish.ts");

    const dir = await mkdtemp(join(tmpdir(), "hp-publish-wl-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    await writePublish(dir, planPublish(wlInput([host("h-k3s-01", "canary")])));
    assert.deepEqual((await readdir(join(dir, "hosts"))).sort(), [
      "h-k3s-01.cnp.json",
      "h-k3s-01.nft",
    ]);
  });

  it("keeps the label selector's namespace out of the applier's own", () => {
    // A sanity check on the join between the two halves: the CNP lands in the namespace its selector
    // names, which has nothing to do with which node applies it.
    const plan = planPublish(
      wlInput([host("h-k3s-01", "canary")], [
        wlPolicy({ id: "P704", dst: { kind: "k8s-label", value: `${NS}=arc-runners,app=runner` } }),
      ]),
    );
    const objects = (JSON.parse(plan.workload!.json) as { items: Array<{ metadata: { namespace: string } }> }).items;
    assert.equal(objects[0]!.metadata.namespace, "arc-runners");
  });
});
