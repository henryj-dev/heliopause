import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { normalizePolicy, PolicyError, type Policy } from "./policy.ts";
import {
  membershipJumps,
  podsFromMembership,
  selectorsToWatch,
  CiliumRenderError,
  assignsToWorkloadLayer,
  planCiliumPolicies,
  renderCiliumPolicies,
  type CiliumItem,
  type CiliumRenderInput,
  type ServiceSelector,
} from "./cilium.ts";
import { contains } from "./test-util.ts";

const NS = "k8s:io.kubernetes.pod.namespace";

function policy(over: Partial<Policy> = {}): Policy {
  return normalizePolicy(
    {
      name: "test",
      src: { kind: "any", value: "" },
      dst: { kind: "k8s-namespace", value: "arc-runners" },
      proto: "tcp",
      ports: "443",
      action: "allow",
      priority: 100,
      ...over,
    },
    over.id ?? "p1",
  );
}

const SERVICES: Record<string, ServiceSelector> = {
  "postgres/postgres-rw": {
    namespace: "postgres",
    name: "postgres-rw",
    selector: { app: "postgres", role: "primary" },
    pods: ["postgres/postgres-0"],
  },
  "util/zot": { namespace: "util", name: "zot", selector: { app: "zot" }, pods: ["util/zot-abc"] },
  // A Service whose endpoints are managed outside Kubernetes: no selector at all.
  "util/external-db": { namespace: "util", name: "external-db", selector: {} },
};

function input(over: Partial<CiliumRenderInput> = {}): CiliumRenderInput {
  return {
    k8sApplier: "h-k3s-01",
    cluster: "dev",
    generation: "0123456789abcdef",
    resolveService: (ref) => SERVICES[ref] ?? null,
    ciliumVersion: [1, 17],
    ...over,
  };
}

function plan(items: CiliumItem[], over: Partial<CiliumRenderInput> = {}) {
  return planCiliumPolicies(input(over), items);
}

describe("policy model — workload endpoint kinds (H14)", () => {
  it("accepts only the kubelet host Cilium entity", () => {
    const p = normalizePolicy(policy({
      src: { kind: "k8s-entity", value: "host" },
      dst: { kind: "k8s-namespace", value: "heliopause" },
    }), "P050");
    assert.deepEqual(p.src, { kind: "k8s-entity", value: "host" });
    assert.throws(
      () => normalizePolicy(policy({
        src: { kind: "k8s-entity", value: "world" },
        dst: { kind: "k8s-namespace", value: "heliopause" },
      }), "P051"),
      /must be host/,
    );
  });
  it("accepts a Service reference as a destination", () => {
    const p = policy({ dst: { kind: "k8s-service", value: "postgres/postgres-rw" } });
    assert.equal(p.dst.kind, "k8s-service");
    assert.equal(p.dst.value, "postgres/postgres-rw");
  });

  it("refuses a Service as a source — traffic comes from pods, not from a Service", () => {
    assert.throws(
      () => policy({ src: { kind: "k8s-service", value: "postgres/postgres-rw" } }),
      (e: unknown) => {
        assert.ok(e instanceof PolicyError);
        contains((e as Error).message, "traffic comes from the pods behind a Service");
        return true;
      },
    );
  });

  it("accepts a namespace as either side — a sending workload has no Service", () => {
    assert.equal(policy({ src: { kind: "k8s-namespace", value: "arc-runners" } }).src.value, "arc-runners");
    assert.equal(policy({ dst: { kind: "k8s-namespace", value: "arc-runners" } }).dst.value, "arc-runners");
  });

  it("refuses a Service reference that is not namespace/name", () => {
    assert.throws(() => policy({ dst: { kind: "k8s-service", value: "postgres-rw" } }), PolicyError);
    assert.throws(
      () => policy({ dst: { kind: "k8s-service", value: "a/b/c" } }),
      PolicyError,
    );
  });

  it("refuses an empty label selector — it would match every pod", () => {
    assert.throws(
      () => policy({ dst: { kind: "k8s-label", value: " , " } }),
      (e: unknown) => {
        contains((e as Error).message, "would match every pod");
        return true;
      },
    );
  });

  it("refuses a selector term that is not key=value", () => {
    assert.throws(
      () => policy({ dst: { kind: "k8s-label", value: "app in (runner)" } }),
      (e: unknown) => {
        contains((e as Error).message, "equality only");
        return true;
      },
    );
  });

  it("accepts a Cilium-prefixed key — that is how a selector crosses namespaces", () => {
    const p = policy({ dst: { kind: "k8s-label", value: `${NS}=arc-runners,app=runner` } });
    contains(p.dst.value, NS);
  });

  it("sorts selector terms so an equivalent selector keeps one fingerprint", () => {
    const a = policy({ dst: { kind: "k8s-label", value: "b=2,a=1" } });
    const b = policy({ dst: { kind: "k8s-label", value: "a=1,b=2" } });
    assert.equal(a.dst.value, b.dst.value);
  });
});

describe("layer assignment (evaluation rule 8)", () => {
  it("sends a workload destination to the workload layer alone — netfilter cannot see it", () => {
    const a = assignsToWorkloadLayer(policy({ dst: { kind: "k8s-service", value: "util/zot" } }));
    assert.deepEqual(a, { workload: true, host: false });
  });

  it("sends a workload source to both — the pod address survives on the wire (V14)", () => {
    const a = assignsToWorkloadLayer(
      policy({ src: { kind: "k8s-namespace", value: "arc-runners" }, dst: { kind: "cidr", value: "10.17.0.0/18" } }),
    );
    assert.deepEqual(a, { workload: true, host: true });
  });

  it("leaves an address-only policy to the host layer", () => {
    const a = assignsToWorkloadLayer(
      policy({ src: { kind: "cidr", value: "10.254.0.0/16" }, dst: { kind: "cidr", value: "10.17.0.10/32" } }),
    );
    assert.deepEqual(a, { workload: false, host: true });
  });
});

describe("renderer — refusals that must not become skips", () => {
  it("refuses to render at all without a designated applier (H17)", () => {
    assert.throws(
      () => plan([{ policy: policy() }], { k8sApplier: "" }),
      (e: unknown) => {
        assert.ok(e instanceof CiliumRenderError);
        contains((e as Error).message, "cluster-scoped");
        return true;
      },
    );
  });

  it("refuses an unresolved Service rather than skipping it — there is no fallback layer", () => {
    assert.throws(
      () => plan([{ policy: policy({ dst: { kind: "k8s-service", value: "util/missing" } }) }]),
      (e: unknown) => {
        assert.ok(e instanceof CiliumRenderError);
        contains((e as Error).message, "no fallback");
        return true;
      },
    );
  });

  it("refuses a selector-less Service — an empty selector matches the whole namespace", () => {
    assert.throws(
      () => plan([{ policy: policy({ dst: { kind: "k8s-service", value: "util/external-db" } }) }]),
      (e: unknown) => {
        contains((e as Error).message, "whole namespace");
        return true;
      },
    );
  });

  it("refuses an unresolved service-object port reference", () => {
    // `normalizePolicy` keeps `@web` as a reference; the resolver is meant to have replaced it.
    assert.throws(
      () => plan([{ policy: policy({ ports: "@web" }) }]),
      (e: unknown) => {
        contains((e as Error).message, "unresolved service-object reference");
        return true;
      },
    );
  });

  it("refuses an address endpoint that resolved to nothing", () => {
    assert.throws(
      () =>
        plan([
          {
            policy: policy({ src: { kind: "host", value: "gone" } }),
            srcCidrs: [],
          },
        ]),
      (e: unknown) => {
        contains((e as Error).message, "match every peer");
        return true;
      },
    );
  });

  it("refuses a bare label selector with no namespace — the object would govern nothing", () => {
    assert.throws(
      () => plan([{ policy: policy({ dst: { kind: "k8s-label", value: "app=runner" } }) }]),
      (e: unknown) => {
        contains((e as Error).message, "does not say which namespace");
        return true;
      },
    );
  });

  it("refuses an unresolved Service on the egress path too, where toServices needs no selector", () => {
    // The egress branch emits native `toServices` and never reads the selector, so it could render
    // this without noticing. Cilium does not reject an unknown Service reference — it resolves it to
    // no backends, which makes an allow open nothing and a deny deny nothing, both reporting a clean
    // apply. `cidr → util/missing` and `arc-runners → util/missing` must fail the same way.
    assert.throws(
      () =>
        plan([
          {
            policy: policy({
              src: { kind: "k8s-namespace", value: "arc-runners" },
              dst: { kind: "k8s-service", value: "util/missing" },
            }),
          },
        ]),
      (e: unknown) => {
        assert.ok(e instanceof CiliumRenderError);
        contains((e as Error).message, "did not resolve");
        return true;
      },
    );
  });

  it("refuses an unresolved Service destination on a deny, where the no-op is worst", () => {
    assert.throws(
      () =>
        plan([
          {
            policy: policy({
              action: "deny",
              src: { kind: "k8s-namespace", value: "arc-runners" },
              dst: { kind: "k8s-service", value: "util/missing" },
            }),
          },
        ]),
      (e: unknown) => {
        contains((e as Error).message, "did not resolve");
        return true;
      },
    );
  });

  it("refuses k8s-service as a source even when normalizePolicy was bypassed", () => {
    // `normalizePolicy` refuses this, but the renderer is exported and takes a `Policy` struct — one
    // rebuilt from stored JSON has not been normalised. Unchecked, it resolves the Service and
    // selects the pods behind it: the guess rule 8 forbids, rendered as a clean policy.
    const raw = {
      ...policy(),
      src: { kind: "k8s-service" as const, value: "postgres/postgres-rw" },
      dst: { kind: "cidr" as const, value: "10.0.0.1/32" },
    };
    assert.throws(
      () => plan([{ policy: raw, dstCidrs: ["10.0.0.1/32"] }]),
      (e: unknown) => {
        assert.ok(e instanceof CiliumRenderError);
        contains((e as Error).message, "cannot be a source");
        return true;
      },
    );
  });

  it("refuses a selector that sets one key to two values", () => {
    // `normalizePolicy` dedupes whole terms, so `app=a,app=b` reaches the renderer as two terms.
    // Building the object would let the last win — an unsatisfiable AND rendering as a live rule
    // aimed at pods the operator never named.
    assert.throws(
      () =>
        plan([
          { policy: policy({ dst: { kind: "k8s-label", value: `${NS}=util,app=a,app=b` } }) },
        ]),
      (e: unknown) => {
        assert.ok(e instanceof CiliumRenderError);
        contains((e as Error).message, "no pod can satisfy both");
        return true;
      },
    );
  });

  it("refuses a namespace label value that is not a valid namespace name", () => {
    // A label value permits uppercase and `_`; a namespace name does not. Rendering it produces an
    // object the API server rejects at apply, where the error no longer names the policy.
    assert.throws(
      () =>
        plan([{ policy: policy({ dst: { kind: "k8s-label", value: `${NS}=Util_Prod,app=idp` } }) }]),
      (e: unknown) => {
        assert.ok(e instanceof CiliumRenderError);
        contains((e as Error).message, "lowercase DNS-1123");
        return true;
      },
    );
  });

  it("refuses a pod-to-pod peer selector with no namespace of its own", () => {
    // Cilium fills a missing namespace on a *peer* selector with the policy's own namespace rather
    // than leaving it unscoped, so this would render, apply, and target arc-runners instead of the
    // pods named. The `endpointSelector` guard does not cover the peer side.
    assert.throws(
      () =>
        plan([
          {
            policy: policy({
              src: { kind: "k8s-namespace", value: "arc-runners" },
              dst: { kind: "k8s-label", value: "app=idp" },
            }),
          },
        ]),
      (e: unknown) => {
        assert.ok(e instanceof CiliumRenderError);
        contains((e as Error).message, "peer selector");
        return true;
      },
    );
  });

  it("builds toServices from the resolved Service, not from splitting the raw value", () => {
    // A value with no slash would yield `serviceName: undefined`, which `JSON.stringify` drops and
    // Cilium's `omitempty` accepts — a Service reference with no name, referencing nothing. The
    // resolver already returns namespace and name it vouches for, so those are used instead of
    // trusting the caller's string to have been through `normalizePolicy`.
    const raw = {
      ...policy(),
      src: { kind: "k8s-namespace" as const, value: "arc-runners" },
      dst: { kind: "k8s-service" as const, value: "zot" },
    };
    const out = planCiliumPolicies(
      input({
        resolveService: (ref) =>
          ref === "zot" ? { namespace: "util", name: "zot", selector: { app: "zot" } } : null,
      }),
      [{ policy: raw }],
    );
    assert.deepEqual(out.policies[0]!.spec.egress?.[0]?.toServices, [
      { k8sService: { serviceName: "zot", namespace: "util" } },
    ]);
  });

  it("refuses a resolver that returns a Service missing its name", () => {
    // Such an entry serialises to `{namespace: "util"}` and references nothing.
    assert.throws(
      () =>
        planCiliumPolicies(
          input({
            resolveService: () => ({ namespace: "util", name: "", selector: { app: "zot" } }),
          }),
          [
            {
              policy: policy({
                src: { kind: "k8s-namespace", value: "arc-runners" },
                dst: { kind: "k8s-service", value: "util/zot" },
              }),
            },
          ],
        ),
      (e: unknown) => {
        assert.ok(e instanceof CiliumRenderError);
        contains((e as Error).message, "with no name");
        return true;
      },
    );
  });

  it("refuses a selector term with no equals sign rather than misparsing it", () => {
    // `indexOf("=")` is -1 and `slice(0, -1)` truncates the last character into a key: `"app"` would
    // become `{ap: "app"}` — a selector that is valid, renders, and matches nothing.
    const raw = {
      ...policy(),
      dst: { kind: "k8s-label" as const, value: "app" },
    };
    assert.throws(
      () => plan([{ policy: raw }]),
      (e: unknown) => {
        assert.ok(e instanceof CiliumRenderError);
        contains((e as Error).message, "is not key=value");
        return true;
      },
    );
  });

  it("refuses two policies that would collide on one object name", () => {
    assert.throws(
      // `p_600` and `p-600` both slug to `hp-dev-p-600`: two policies, one object, and the second
      // apply would overwrite the first while both report success.
      () => plan([{ policy: policy({ id: "p_600" }) }, { policy: policy({ id: "p-600" }) }]),
      (e: unknown) => {
        contains((e as Error).message, "same object name");
        return true;
      },
    );
  });
});

describe("renderer — direction decides which side becomes the selector", () => {
  it("renders an address source to a workload destination as ingress", () => {
    const p = policy({
      id: "P601",
      src: { kind: "cidr", value: "10.254.0.0/16" },
      dst: { kind: "k8s-service", value: "postgres/postgres-rw" },
      ports: "5432",
    });
    const out = plan([{ policy: p, srcCidrs: ["10.254.0.0/16"] }]);
    assert.equal(out.policies.length, 1);
    const cnp = out.policies[0]!;
    // The selector names the pods being protected, and it carries the Service's own namespace —
    // without that, `app=postgres` would match a pod anywhere.
    assert.deepEqual(cnp.spec.endpointSelector.matchLabels, {
      app: "postgres",
      role: "primary",
      [NS]: "postgres",
    });
    assert.equal(cnp.metadata.namespace, "postgres");
    assert.deepEqual(cnp.spec.ingress?.[0]?.fromCIDR, ["10.254.0.0/16"]);
    assert.deepEqual(cnp.spec.ingress?.[0]?.toPorts, [{ ports: [{ port: "5432", protocol: "TCP" }] }]);
    assert.equal(cnp.spec.egress, undefined);
  });

  it("renders a workload source to a Service as egress with toServices — the native form", () => {
    const p = policy({
      id: "P602",
      src: { kind: "k8s-namespace", value: "arc-runners" },
      dst: { kind: "k8s-service", value: "util/zot" },
      ports: "5000",
    });
    const out = plan([{ policy: p }]);
    const cnp = out.policies[0]!;
    assert.deepEqual(cnp.spec.endpointSelector.matchLabels, { [NS]: "arc-runners" });
    assert.equal(cnp.metadata.namespace, "arc-runners");
    // `toServices` rather than a resolved selector: Cilium re-resolves it, so the rule stays correct
    // when the Service's selector changes.
    assert.deepEqual(cnp.spec.egress?.[0]?.toServices, [
      { k8sService: { serviceName: "zot", namespace: "util" } },
    ]);
    assert.equal(cnp.spec.ingress, undefined);

    // ## And the receiver's half, which this branch used to skip
    //
    // Cilium enforces the two directions independently, so the sender's egress object alone leaves
    // the flow dropped at the destination — measured 2026-08-10 at `endpoint 1586`, which is why the
    // `k8s-label` form renders both. `k8s-service` is caught before that branch and rendered one.
    //
    // The selector is the **Service's**, pinned to the Service's namespace: `endpointSelector` names
    // pods, and `toServices` names a Service.
    const ingressHalf = out.policies.find((o) => o.metadata.name.endsWith("-ingress"))!;
    assert.ok(ingressHalf, "a Service destination must get the receiver's half too");
    assert.equal(ingressHalf.metadata.namespace, "util", "it lands where the backend pods are");
    assert.deepEqual(ingressHalf.spec.endpointSelector.matchLabels, { app: "zot", [NS]: "util" });
    assert.deepEqual(ingressHalf.spec.ingress?.[0]?.fromEndpoints, [
      { matchLabels: { [NS]: "arc-runners" } },
    ]);
    // Closing the destination is the point of an ingress allow — and it is also a consequence the
    // author did not write, so it is warned about rather than left to be discovered.
    assert.equal(ingressHalf.spec.enableDefaultDeny?.ingress, true);
    contains(out.warnings.map((w) => w.warning).join("\n"), "ingress default-deny");
  });

  it("does not mirror a deny to a Service", () => {
    // Same carve-out the `k8s-label` branch makes: a deny needs only the sender's side to be
    // effective, and mirroring it would place an `ingressDeny` on pods the author never named —
    // where Cilium's deny-beats-every-allow rule makes an accidental blast radius expensive.
    const out = plan([{
      policy: policy({
        id: "P602D",
        src: { kind: "k8s-namespace", value: "arc-runners" },
        dst: { kind: "k8s-service", value: "util/zot" },
        action: "deny",
      }),
    }]);
    assert.equal(out.policies.length, 1);
    assert.equal(out.policies[0]!.spec.egressDeny?.length, 1);
  });

  it("renders a workload source to an address destination as egress", () => {
    const p = policy({
      id: "P603",
      src: { kind: "k8s-namespace", value: "build-jobs" },
      dst: { kind: "cidr", value: "10.17.101.12/32" },
      ports: "5432",
    });
    const out = plan([{ policy: p, dstCidrs: ["10.17.101.12/32"] }]);
    assert.deepEqual(out.policies[0]!.spec.egress?.[0]?.toCIDR, ["10.17.101.12/32"]);
  });

  it("renders pod-to-pod as egress on the sender, paired with ingress on the receiver", () => {
    // **This test used to assert the opposite** — that only the sender's half rendered and a warning
    // named the gap. That is what shipped, and on 2026-08-10 it was measured to be a broken flow:
    // the egress object applied cleanly and the packets were dropped at the destination endpoint.
    // The warning was accurate and useless, and this test was holding the defect in place.
    const p = policy({
      id: "P604",
      src: { kind: "k8s-namespace", value: "arc-runners" },
      dst: { kind: "k8s-label", value: `${NS}=util,app=idp` },
    });
    const out = plan([{ policy: p }]);
    const cnp = out.policies.find((o) => !o.metadata.name.endsWith("-ingress"))!;
    assert.deepEqual(cnp.spec.endpointSelector.matchLabels, { [NS]: "arc-runners" });
    // Wrapped in `matchLabels`, not a bare map. A bare map is unknown fields against the structural
    // schema: pruned to `{}`, which is a wildcard Cilium scopes to the policy's own namespace.
    assert.deepEqual(cnp.spec.egress?.[0]?.toEndpoints, [
      { matchLabels: { [NS]: "util", app: "idp" } },
    ]);
    // The half that makes it a flow rather than a statement about the sender.
    const peer = out.policies.find((o) => o.metadata.name.endsWith("-ingress"))!;
    assert.equal(peer.metadata.namespace, "util");
    assert.deepEqual(peer.spec.ingress?.[0]?.fromEndpoints, [{ matchLabels: { [NS]: "arc-runners" } }]);
  });

  it("maps internet to the world entity, not 0.0.0.0/0", () => {
    const p = policy({
      id: "P605",
      src: { kind: "k8s-namespace", value: "arc-runners" },
      dst: { kind: "internet", value: "" },
    });
    const out = plan([{ policy: p }]);
    // `0.0.0.0/0` would also cover in-cluster peers, making an internet rule match pod traffic.
    assert.deepEqual(out.policies[0]!.spec.egress?.[0]?.toEntities, ["world"]);
    assert.equal(out.policies[0]!.spec.egress?.[0]?.toCIDR, undefined);
  });

  it("maps the kubelet host identity without widening it to all peers", () => {
    const p = policy({
      id: "P606",
      src: { kind: "k8s-entity", value: "host" },
      dst: {
        kind: "k8s-label",
        value: `${NS}=heliopause,app=heliopause-manager`,
      },
      ports: "8444",
    });
    const out = plan([{ policy: p }]);
    assert.deepEqual(out.policies[0]!.spec.ingress?.[0]?.fromEntities, ["host"]);
    assert.deepEqual(out.policies[0]!.spec.ingress?.[0]?.toPorts, [
      { ports: [{ port: "8444", protocol: "TCP" }] },
    ]);
  });
});

describe("renderer — IPv4 only (evaluation rule 6)", () => {
  it("warns and drops the IPv6 half rather than rendering unenforceable coverage", () => {
    const p = policy({
      id: "P610",
      src: { kind: "object", value: "ao-mgmt" },
      dst: { kind: "k8s-service", value: "util/zot" },
    });
    const out = plan([{ policy: p, srcCidrs: ["10.254.0.0/16", "2001:db8:cf1:1000::/64"] }]);
    assert.deepEqual(out.policies[0]!.spec.ingress?.[0]?.fromCIDR, ["10.254.0.0/16"]);
    assert.equal(out.warnings.length, 1);
    contains(out.warnings[0]!.warning, "enable-ipv6 = false");
    contains(out.warnings[0]!.warning, "covers IPv4 only");
  });

  it("refuses an all-IPv6 endpoint — an empty condition matches all peers, not none", () => {
    const p = policy({
      id: "P611",
      src: { kind: "object", value: "ao-mgmt-v6" },
      dst: { kind: "k8s-service", value: "util/zot" },
    });
    assert.throws(
      () => plan([{ policy: p, srcCidrs: ["2001:db8:cf1:1000::/64"] }]),
      (e: unknown) => {
        contains((e as Error).message, "would match all peers");
        return true;
      },
    );
  });
});

describe("renderer — deny semantics differ from the host layer", () => {
  it("renders a deny into ingressDeny, not as a skip", () => {
    const p = policy({
      id: "P620",
      action: "deny",
      src: { kind: "any", value: "" },
      dst: { kind: "k8s-service", value: "util/zot" },
      ports: "5000",
    });
    const out = plan([{ policy: p }]);
    assert.equal(out.skipped.length, 0);
    const cnp = out.policies[0]!;
    assert.equal(cnp.spec.ingress, undefined);
    assert.deepEqual(cnp.spec.ingressDeny?.[0]?.toPorts, [{ ports: [{ port: "5000", protocol: "TCP" }] }]);
  });

  it("renders an egress deny into egressDeny", () => {
    const p = policy({
      id: "P621",
      action: "deny",
      src: { kind: "k8s-namespace", value: "arc-runners" },
      dst: { kind: "internet", value: "" },
    });
    const out = plan([{ policy: p }]);
    assert.deepEqual(out.policies[0]!.spec.egressDeny?.[0]?.toEntities, ["world"]);
  });

  // ── enableDefaultDeny ─────────────────────────────────────────────────────
  //
  // The difference between containment and an outage, and the one defect found so far that makes the
  // rule *larger* than written rather than smaller. Cilium switches an endpoint to default-deny for a
  // direction as soon as any policy selects it, and `Sanitize()` counts `egressDeny` alone as
  // selecting it (`len(r.Egress) > 0 || len(r.EgressDeny) > 0`). With no allow rules present that
  // means every egress dropped: "stop the runners reaching idp" becomes "the runners reach nothing".

  it("does not close the endpoint on a deny — that would drop all egress, not just the denied peer", () => {
    const out = plan([
      {
        policy: policy({
          id: "P625",
          action: "deny",
          src: { kind: "k8s-namespace", value: "arc-runners" },
          dst: { kind: "k8s-label", value: `${NS}=idp,app=idp` },
        }),
      },
    ]);
    const spec = out.policies[0]!.spec;
    assert.deepEqual(spec.enableDefaultDeny, { egress: false });
    // The pairing is the point: a deny rule present, and the posture left open so it subtracts from
    // what the pods already reach instead of replacing it.
    assert.ok(spec.egressDeny, "the deny rule itself must still be emitted");
  });

  it("closes the endpoint on an allow — an allow only means anything if the rest is refused", () => {
    const out = plan([{ policy: policy({ id: "P626", dst: { kind: "k8s-service", value: "util/zot" } }) }]);
    assert.deepEqual(out.policies[0]!.spec.enableDefaultDeny, { ingress: true });
  });

  it("names only the direction it renders, leaving the other untouched", () => {
    // Setting both would make an egress policy close the pods' ingress as a side effect — a second,
    // unrequested rule riding along with the one that was written.
    //
    // **This asserted `{ egress: true }` until 2026-08-10**, when that value took DNS out from under
    // the dashboard pods — see "an egress allow must not close the sender". The property the test
    // was written for is untouched and still worth holding: exactly one direction appears. What
    // changed is the value, and the two assertions are separate claims rather than one.
    const egress = plan([
      {
        policy: policy({
          id: "P627",
          src: { kind: "k8s-namespace", value: "arc-runners" },
          dst: { kind: "k8s-service", value: "util/zot" },
        }),
      },
    ]);
    assert.deepEqual(egress.policies[0]!.spec.enableDefaultDeny, { egress: false });
    assert.equal("ingress" in egress.policies[0]!.spec.enableDefaultDeny, false);
  });

  it("emits the field on every object, including where it matches Cilium's own default", () => {
    // The default is the dangerous one, so a reader should not have to know which way it falls. An
    // omitted field and an explicit `true` behave identically and read very differently in a diff.
    for (const p of [
      policy({ id: "P628", dst: { kind: "k8s-service", value: "util/zot" } }),
      policy({ id: "P629", action: "deny", dst: { kind: "k8s-service", value: "util/zot" } }),
    ]) {
      const spec = plan([{ policy: p }]).policies[0]!.spec;
      assert.ok(spec.enableDefaultDeny, `${p.id} must carry enableDefaultDeny`);
      assert.equal(Object.keys(spec.enableDefaultDeny).length, 1);
    }
  });

  it("warns that an allow on the same pods overrides the deny's request", () => {
    // Cilium enables default-deny if *any* policy asks for it, so the deny's `false` loses. Neither
    // policy is wrong on its own, which is exactly why this is worth saying out loud.
    const out = plan([
      {
        policy: policy({
          id: "P62a",
          action: "deny",
          src: { kind: "k8s-namespace", value: "arc-runners" },
          dst: { kind: "k8s-label", value: `${NS}=idp,app=idp` },
        }),
      },
    ]);
    contains(out.warnings.map((w) => w.warning).join("\n"), "loses to any allow policy");
  });

  it("warns that a deny here cannot be carved out by a later allow", () => {
    const out = plan([
      { policy: policy({ id: "P622", action: "deny", dst: { kind: "k8s-service", value: "util/zot" } }) },
    ]);
    contains(out.warnings.map((w) => w.warning).join("\n"), "no later rule can carve an exception");
  });

  it("says so when a portless deny covers every port", () => {
    const out = plan([
      {
        policy: policy({
          id: "P623",
          action: "deny",
          proto: "any",
          ports: "",
          dst: { kind: "k8s-service", value: "util/zot" },
        }),
      },
    ]);
    // "every protocol and port", not just port — an L3 Cilium rule restricts neither.
    contains(out.warnings.map((w) => w.warning).join("\n"), "covers every protocol and port");
  });

  it("warns that reject degrades to a drop on this layer", () => {
    const out = plan([
      {
        policy: policy({
          id: "P624",
          action: "deny",
          denyMode: "reject",
          dst: { kind: "k8s-service", value: "util/zot" },
        }),
      },
    ]);
    contains(out.warnings.map((w) => w.warning).join("\n"), "callers will time out");
  });
});

describe("renderer — skips are for policies that were understood", () => {
  it("skips a disabled policy", () => {
    const out = plan([{ policy: policy({ enabled: false }) }]);
    assert.equal(out.policies.length, 0);
    contains(out.skipped[0]!.reason, "disabled");
  });

  it("skips an address-only policy — it belongs to the host layer", () => {
    const p = policy({
      src: { kind: "cidr", value: "10.254.0.0/16" },
      dst: { kind: "cidr", value: "10.17.0.10/32" },
    });
    const out = plan([{ policy: p, srcCidrs: ["10.254.0.0/16"], dstCidrs: ["10.17.0.10/32"] }]);
    assert.equal(out.policies.length, 0);
    contains(out.skipped[0]!.reason, "host layer only");
  });
});

describe("renderer — what the operator has to be shown", () => {
  it("reports the pods a policy actually selects, not just the selector", () => {
    const out = plan([
      { policy: policy({ id: "P630", dst: { kind: "k8s-service", value: "postgres/postgres-rw" } }) },
    ]);
    // A pod behind two Services is covered by the union of both policies, which reads narrower than
    // it is. The pod list is where that becomes visible.
    assert.deepEqual(out.affectedPods["P630"], ["postgres/postgres-0"]);
  });

  // ── "not known" is not "none" (H14a) ──────────────────────────────────────
  //
  // The renderer is pure, so pod membership is injected. Without an injection there is no honest
  // answer but `null`, and the distinction is the point: `arc-runners` genuinely holds zero pods
  // between CI jobs, so `[]` is a real state a reader may act on. Collapsing the two lets an
  // unreported selector read as a policy that selects nothing — which is how a live containment
  // policy gets mistaken for a dormant one.

  it("reports null for a namespace nobody reported — not an empty list", () => {
    const out = plan([
      { policy: policy({ id: "P631", src: { kind: "k8s-namespace", value: "build-jobs" }, dst: { kind: "internet", value: "" } }) },
    ]);
    assert.equal(out.affectedPods["P631"], null);
  });

  it("reports an empty list when membership was reported and is genuinely empty", () => {
    // `build-jobs` between CI jobs. Distinct from the case above, and an operator has to be able to
    // tell them apart: this one says the policy is correct and currently selects nothing.
    const out = plan(
      [
        { policy: policy({ id: "P631b", src: { kind: "k8s-namespace", value: "build-jobs" }, dst: { kind: "internet", value: "" } }) },
      ],
      { resolvePods: (kind, value) => (kind === "k8s-namespace" && value === "build-jobs" ? [] : null) },
    );
    assert.deepEqual(out.affectedPods["P631b"], []);
  });

  it("reports the pods a namespace selector currently matches", () => {
    const out = plan(
      [
        { policy: policy({ id: "P631c", src: { kind: "k8s-namespace", value: "arc-runners" }, dst: { kind: "internet", value: "" } }) },
      ],
      {
        resolvePods: (kind, value) =>
          kind === "k8s-namespace" && value === "arc-runners"
            ? ["arc-runners/runner-abc", "arc-runners/runner-def"]
            : null,
      },
    );
    assert.deepEqual(out.affectedPods["P631c"], ["arc-runners/runner-abc", "arc-runners/runner-def"]);
  });

  it("reports the pods a label selector currently matches", () => {
    const out = plan(
      [
        {
          policy: policy({
            id: "P631d",
            src: { kind: "k8s-label", value: `${NS}=arc-runners,app=runner` },
            dst: { kind: "internet", value: "" },
          }),
        },
      ],
      { resolvePods: (kind) => (kind === "k8s-label" ? ["arc-runners/runner-abc"] : null) },
    );
    assert.deepEqual(out.affectedPods["P631d"], ["arc-runners/runner-abc"]);
  });

  it("labels every object so flux can be told to leave it alone", () => {
    const out = plan([{ policy: policy({ id: "P632", dst: { kind: "k8s-service", value: "util/zot" } }) }]);
    assert.equal(out.policies[0]!.metadata.labels["managed-by"], "heliopause");
    assert.equal(out.policies[0]!.metadata.labels["heliopause.io/cluster"], "dev");
  });

  it("records the applier on each object so a stray writer is identifiable", () => {
    const out = plan([{ policy: policy({ id: "P633", dst: { kind: "k8s-service", value: "util/zot" } }) }]);
    assert.equal(out.policies[0]!.metadata.annotations["heliopause.io/applier"], "h-k3s-01");
    assert.equal(out.policies[0]!.metadata.annotations["heliopause.io/policy-id"], "P633");
    assert.equal(out.policies[0]!.metadata.annotations["heliopause.io/generation"], "0123456789abcdef");
    assert.equal(out.applier, "h-k3s-01");
  });

  it("validates the final peer-ingress name after reserving its suffix", () => {
    const paired = (id: string) => [{
      policy: policy({
        id,
        src: { kind: "k8s-namespace", value: "arc-runners" },
        dst: { kind: "k8s-label", value: `${NS}=util,app=zot` },
      }),
    }];
    const boundary = plan(paired("p".repeat(48)));
    assert.equal(boundary.policies[1]!.metadata.name.length, 63);
    assert.throws(() => plan(paired("p".repeat(49))), /DNS-1123 object name/);
  });

  it("warns that an icmp policy renders with no port condition at all", () => {
    const out = plan([
      { policy: policy({ id: "P634", proto: "icmp", ports: "", dst: { kind: "k8s-service", value: "util/zot" } }) },
    ]);
    const text = out.warnings.map((w) => w.warning).join("\n");
    contains(text, "covers every protocol rather than icmp alone");
    contains(text, "separate field this renderer does not emit");
  });

  it("keeps the protocol restriction on a portless tcp policy instead of warning about losing it", () => {
    // Omitting `toPorts` would render as every protocol, not "any TCP port" — an L3 Cilium rule
    // restricts neither. `port: "0"` is the wildcard that still carries the protocol, which is the
    // `meta l4proto tcp` equivalent the host layer emits. No `endPort`: Cilium ignores it when the
    // base port is 0, so a 65535 bound would read as meaningful and mean nothing.
    const out = plan([
      { policy: policy({ id: "P635", proto: "tcp", ports: "", dst: { kind: "k8s-service", value: "util/zot" } }) },
    ]);
    assert.deepEqual(out.policies[0]!.spec.ingress?.[0]?.toPorts, [
      { ports: [{ port: "0", protocol: "TCP" }] },
    ]);
    assert.equal(
      out.warnings.filter((w) => w.warning.includes("covers every protocol")).length,
      0,
    );
  });

  it("emits no toPorts when proto is any — an L3 rule is what that means", () => {
    // `any` with no ports restricts nothing, so a wildcard `toPorts` would add a field without
    // adding a condition.
    const out = plan([
      { policy: policy({ id: "P636", proto: "any", ports: "", dst: { kind: "k8s-service", value: "util/zot" } }) },
    ]);
    assert.equal(out.policies[0]!.spec.ingress?.[0]?.toPorts, undefined);
    assert.equal(
      out.warnings.filter((w) => w.warning.includes("covers every protocol")).length,
      0,
    );
  });

  it("refuses toServices with ports on Cilium 1.16, which rejects the combination", () => {
    // `l3DependentL4Support` lists ToServices false through 1.16.x and true from 1.17.0. Rendering
    // without the ports would widen "reach this Service on 443" to every port; rendering with them
    // would be rejected at apply, where the error no longer names the policy.
    assert.throws(
      () =>
        plan(
          [
            {
              policy: policy({
                id: "P637",
                src: { kind: "k8s-namespace", value: "arc-runners" },
                dst: { kind: "k8s-service", value: "util/zot" },
              }),
            },
          ],
          { ciliumVersion: [1, 16] },
        ),
      (e: unknown) => {
        assert.ok(e instanceof CiliumRenderError);
        contains((e as Error).message, "rejects toServices combined with toPorts");
        return true;
      },
    );
  });

  it("allows toServices with ports on 1.17, where the restriction was lifted", () => {
    const out = plan(
      [
        {
          policy: policy({
            id: "P638",
            src: { kind: "k8s-namespace", value: "arc-runners" },
            dst: { kind: "k8s-service", value: "util/zot" },
          }),
        },
      ],
      { ciliumVersion: [1, 17] },
    );
    const egress = out.policies[0]!.spec.egress?.[0];
    assert.deepEqual(egress?.toServices, [{ k8sService: { serviceName: "zot", namespace: "util" } }]);
    assert.deepEqual(egress?.toPorts, [{ ports: [{ port: "443", protocol: "TCP" }] }]);
  });

  it("renders a portless toServices on 1.16 — only the combination is refused", () => {
    const out = plan(
      [
        {
          policy: policy({
            id: "P639",
            proto: "any",
            ports: "",
            src: { kind: "k8s-namespace", value: "arc-runners" },
            dst: { kind: "k8s-service", value: "util/zot" },
          }),
        },
      ],
      { ciliumVersion: [1, 16] },
    );
    assert.deepEqual(out.policies[0]!.spec.egress?.[0]?.toServices, [
      { k8sService: { serviceName: "zot", namespace: "util" } },
    ]);
  });

  it("refuses a malformed ciliumVersion rather than treating it as new enough", () => {
    // NaN comparisons would fall through to the >= 1.17 branch and render a combination the cluster
    // rejects.
    assert.throws(
      () =>
        plan([{ policy: policy({ id: "P63a" }) }], {
          ciliumVersion: undefined as unknown as readonly [number, number],
        }),
      (e: unknown) => {
        assert.ok(e instanceof CiliumRenderError);
        contains((e as Error).message, "must be [major, minor] integers");
        return true;
      },
    );
  });
});

describe("renderer — ports", () => {
  it("renders a range as port + endPort", () => {
    const out = plan([
      { policy: policy({ id: "P640", ports: "9000:9100", dst: { kind: "k8s-service", value: "util/zot" } }) },
    ]);
    assert.deepEqual(out.policies[0]!.spec.ingress?.[0]?.toPorts, [
      { ports: [{ port: "9000", endPort: 9100, protocol: "TCP" }] },
    ]);
  });

  it("renders a list as separate port entries", () => {
    const out = plan([
      { policy: policy({ id: "P641", ports: "80,443", dst: { kind: "k8s-service", value: "util/zot" } }) },
    ]);
    const ports = out.policies[0]!.spec.ingress?.[0]?.toPorts?.[0]?.ports;
    assert.deepEqual(ports, [
      { port: "80", protocol: "TCP" },
      { port: "443", protocol: "TCP" },
    ]);
  });

  it("emits no port condition when the policy names none", () => {
    const out = plan([
      { policy: policy({ id: "P642", proto: "any", ports: "", dst: { kind: "k8s-service", value: "util/zot" } }) },
    ]);
    assert.equal(out.policies[0]!.spec.ingress?.[0]?.toPorts, undefined);
  });
});

describe("serialisation", () => {
  it("emits the plan's objects and nothing else", () => {
    const items: CiliumItem[] = [
      { policy: policy({ id: "P650", dst: { kind: "k8s-service", value: "util/zot" } }) },
    ];
    const { json, plan: p } = renderCiliumPolicies(input(), items);
    assert.deepEqual(JSON.parse(json).items, p.policies);
    contains(json, "cilium.io/v2");
    contains(json, "CiliumNetworkPolicy");
  });

  it("wraps the objects in a v1/List, which is what kubectl apply accepts", () => {
    // A bare JSON array is rejected by kubectl before it reaches the API server — a top-level array
    // carries no apiVersion/kind for it to dispatch on. Measured against the live cluster: the array
    // failed a server-side dry-run with "invalid object to validate", and the identical objects
    // wrapped in a List applied cleanly.
    //
    // Pinned because nothing else exercises it. Every other test reads `plan.policies`, and the
    // agent's validator parses the JSON itself rather than shelling out to kubectl — so the one
    // consumer that cares about the wrapper was the only thing never covered.
    const { json } = renderCiliumPolicies(input(), [
      { policy: policy({ id: "P651", dst: { kind: "k8s-service", value: "util/zot" } }) },
    ]);
    const doc = JSON.parse(json) as { apiVersion: string; kind: string; items: unknown[] };
    assert.equal(doc.apiVersion, "v1");
    assert.equal(doc.kind, "List");
    assert.equal(doc.items.length, 1);
  });
});

// ── H14a: selector membership ────────────────────────────────────────────────
//
// The renderer is pure, so pod membership is injected. These cover the two ends of that path — what
// the manager asks the applier to watch, and what it does with the answer — plus the guardrail the
// design asks for: hold when a selector's pod count jumps.

describe("selectorsToWatch", () => {
  it("collects both sides of every policy", () => {
    // The source selector decides which pods the rule is written on; the destination decides who
    // they may reach. An operator reviewing a generation needs both.
    const w = selectorsToWatch([
      {
        policy: policy({
          id: "W1",
          src: { kind: "k8s-namespace", value: "arc-runners" },
          dst: { kind: "k8s-label", value: `${NS}=idp,app=idp` },
        }),
      },
    ]);
    assert.deepEqual(w.namespaces, ["arc-runners"]);
    // normalizePolicy sorts selector terms so an equivalent selector keeps one fingerprint, and the
    // watch list carries that normalised form — the agent answers keyed to what it was asked.
    assert.deepEqual(w.labels, [`app=idp,${NS}=idp`]);
  });

  it("ignores address and Service endpoints — neither is a selector to watch", () => {
    // `k8s-service` membership already arrives through `ServiceSelector.pods`, and an address has no
    // pods at all. Asking about them would be asking the applier a question with no answer.
    const w = selectorsToWatch([
      { policy: policy({ id: "W2", src: { kind: "cidr", value: "10.0.0.0/8" }, dst: { kind: "k8s-service", value: "util/zot" } }) },
    ]);
    assert.deepEqual(w.namespaces, []);
    assert.deepEqual(w.labels, []);
  });

  it("deduplicates and sorts, so the same policy set asks the same question every time", () => {
    // A question that changes shape between generations makes the answers incomparable, which is
    // what the guardrail depends on.
    const w = selectorsToWatch([
      { policy: policy({ id: "W3", src: { kind: "k8s-namespace", value: "build-jobs" }, dst: { kind: "internet", value: "" } }) },
      { policy: policy({ id: "W4", src: { kind: "k8s-namespace", value: "arc-runners" }, dst: { kind: "internet", value: "" } }) },
      { policy: policy({ id: "W5", src: { kind: "k8s-namespace", value: "arc-runners" }, dst: { kind: "internet", value: "" } }) },
    ]);
    assert.deepEqual(w.namespaces, ["arc-runners", "build-jobs"]);
  });

  it("refuses more selector queries than the agent will service", () => {
    const items = Array.from({ length: 33 }, (_, i) => ({
      policy: policy({
        id: `bound-${i}`,
        src: { kind: "k8s-namespace" as const, value: `ns-${i}` },
        dst: { kind: "internet" as const, value: "" },
      }),
    }));
    assert.throws(() => selectorsToWatch(items), /limit is 32/);
  });

  it("refuses an unscoped label instead of asking the agent for every namespace", () => {
    const item = { policy: policy({ dst: { kind: "k8s-label", value: "app=idp" } }) };
    assert.throws(() => selectorsToWatch([item]), /refuses cluster-wide pod queries/);
  });

  it("mirrors the agent's selector term and duplicate-key bounds", () => {
    const tooMany = [NS + "=util", ...Array.from({ length: 16 }, (_, i) => `k${i}=v`)].join(",");
    assert.throws(
      () => selectorsToWatch([{ policy: policy({ dst: { kind: "k8s-label", value: tooMany } }) }]),
      /agent limit is 1\.\.16/,
    );
    assert.throws(
      () => selectorsToWatch([{
        policy: policy({ dst: { kind: "k8s-label", value: `${NS}=util,app=a,app=b` } }),
      }]),
      /repeats key "app"/,
    );
  });
});

describe("podsFromMembership", () => {
  const m = {
    at: "2026-08-02T05:00:00Z",
    namespaces: { "arc-runners": ["runner-a", "runner-b"], "build-jobs": [] },
    labelled: { [`${NS}=idp,app=idp`]: ["idp/idp-0"] },
  };

  it("qualifies namespace pods so two namespaces' pods are never confused", () => {
    // Reported as bare names; shown as `namespace/name`.
    assert.deepEqual(podsFromMembership(m)("k8s-namespace", "arc-runners"), [
      "arc-runners/runner-a",
      "arc-runners/runner-b",
    ]);
  });

  it("passes label matches through — they are already qualified", () => {
    assert.deepEqual(podsFromMembership(m)("k8s-label", `${NS}=idp,app=idp`), ["idp/idp-0"]);
  });

  it("keeps 'queried and empty' distinct from 'not known'", () => {
    // The whole reason this returns `string[] | null`.
    assert.deepEqual(podsFromMembership(m)("k8s-namespace", "build-jobs"), []);
    assert.equal(podsFromMembership(m)("k8s-namespace", "never-reported"), null);
  });

  it("returns null for everything when there is no report at all", () => {
    assert.equal(podsFromMembership(undefined)("k8s-namespace", "arc-runners"), null);
  });
});

describe("membershipJumps", () => {
  const L = { minGrowth: 10, factor: 3 };

  it("reports a selector that suddenly matches far more pods", () => {
    // The symptom of a Service selector that widened: `app=idp` becoming `app`.
    const jumps = membershipJumps({ "k8s-label:app=idp": new Array(2).fill("p") }, { "k8s-label:app=idp": new Array(40).fill("p") }, L);
    assert.equal(jumps.length, 1);
    assert.equal(jumps[0]!.before, 2);
    assert.equal(jumps[0]!.after, 40);
    contains(jumps[0]!.reason, "usually means the selector changed");
  });

  it("stays quiet for ordinary autoscaling", () => {
    // A runner set going 1 → 3 is a 200% jump and is exactly what it is supposed to do. An alarm
    // that fires on normal operation gets acknowledged without being read.
    assert.deepEqual(membershipJumps({ "k8s-namespace:arc-runners": ["a"] }, { "k8s-namespace:arc-runners": ["a", "b", "c"] }, L), []);
  });

  it("needs both the floor and the ratio", () => {
    // 20 → 31 clears the floor but not 3×, and must not fire: a large namespace naturally moves by
    // more than ten pods.
    assert.deepEqual(membershipJumps({ s: new Array(20).fill("p") }, { s: new Array(31).fill("p") }, L), []);
  });

  it("treats growth from zero by the floor alone", () => {
    // No ratio exists from 0. `arc-runners` filling with 40 runners is a jump on any measure.
    assert.equal(membershipJumps({ s: [] }, { s: new Array(40).fill("p") }, L).length, 1);
  });

  it("says nothing about a selector that shrank", () => {
    // Possibly a problem, but not this one. Folding both in makes the signal mean "something moved".
    assert.deepEqual(membershipJumps({ s: new Array(40).fill("p") }, { s: [] }, L), []);
  });

  it("cannot compare against an unknown, so it stays silent", () => {
    // Treating unknown as 0 would make the first report after an outage look like a jump from
    // nothing — precisely when an operator is least able to check.
    assert.deepEqual(membershipJumps({ s: null }, { s: new Array(40).fill("p") }, L), []);
    assert.deepEqual(membershipJumps({ s: new Array(2).fill("p") }, { s: null }, L), []);
  });

  it("has nothing to compare on the first generation", () => {
    assert.deepEqual(membershipJumps(undefined, { s: new Array(40).fill("p") }, L), []);
  });
});

describe("workload to workload — both directions, because one is not a flow", () => {
  // ## What this pins, and what it cost to learn
  //
  // Cilium enforces egress at the sender and ingress at the receiver **independently**. A
  // workload→workload allow used to render only the sender's half plus a warning saying the
  // receiver might also need one. Measured 2026-08-10: the dashboard could not reach dispatcher,
  // the egress object rendered and applied cleanly, `Valid=True`, and every packet was dropped at
  // the receiving endpoint. The warning was true and changed nothing.
  //
  // A policy that says "these pods may talk to those pods" and delivers no working flow has not
  // been rendered — it has been half-rendered. So both objects are emitted and this is the test
  // that keeps them together.
  const pair = () =>
    plan([
      {
        policy: policy({
          id: "APP-TO-API",
          src: { kind: "k8s-namespace", value: "stardust" },
          dst: { kind: "k8s-label", value: `${NS}=dispatcher,app=dispatcher` },
          ports: "8080",
        }),
      },
    ]);

  it("emits the sender's egress and the receiver's ingress", () => {
    const names = pair().policies.map((o) => o.metadata.name);
    assert.equal(names.length, 2, `expected both halves, got ${names.join(", ")}`);
    assert.ok(names.some((n) => n.endsWith("-ingress")), names.join(", "));
  });

  it("puts each half in the namespace whose pods it governs", () => {
    // A CiliumNetworkPolicy only applies inside its own namespace. An ingress object landing in the
    // sender's namespace would apply to nothing while reporting a clean apply — the failure shape
    // this layer exists to remove, since no host rule sits behind pod traffic.
    const objects = pair().policies;
    const egress = objects.find((o) => !o.metadata.name.endsWith("-ingress"))!;
    const ingress = objects.find((o) => o.metadata.name.endsWith("-ingress"))!;
    assert.equal(egress.metadata.namespace, "stardust", "egress governs the sender");
    assert.equal(ingress.metadata.namespace, "dispatcher", "ingress governs the receiver");
  });

  it("selects the receiver and admits the sender, not the other way round", () => {
    // The direction that is easy to get backwards and impossible to see in a diff: an ingress rule
    // selecting the *sender* and admitting the *receiver* renders, applies, and blocks the flow.
    const ingress = pair().policies.find((o) => o.metadata.name.endsWith("-ingress"))!;
    assert.equal(ingress.spec.endpointSelector.matchLabels[NS], "dispatcher");
    const from = ingress.spec.ingress?.[0]?.fromEndpoints?.[0]?.matchLabels ?? {};
    assert.equal(from[NS], "stardust", `ingress admits ${JSON.stringify(from)}`);
  });

  it("carries the port condition onto the ingress half", () => {
    // Without this the receiver's half is wider than the rule that asked for it — the sender is
    // limited to 8080 and the destination accepts it on anything.
    const ingress = pair().policies.find((o) => o.metadata.name.endsWith("-ingress"))!;
    assert.deepEqual(
      (ingress.spec.ingress?.[0]?.toPorts ?? []).flatMap((t) => t.ports.map((p) => p.port)),
      ["8080"],
    );
  });

  it("ties both halves to the policy that asked for them", () => {
    // So an operator reading either object can find the rule, and so removing the rule removes both.
    for (const o of pair().policies) {
      assert.equal(o.metadata.annotations["heliopause.io/policy-id"], "APP-TO-API");
    }
  });

  it("does not mirror a deny", () => {
    // Deny needs only the sender's side to be effective. Mirroring it would place an `ingressDeny`
    // on pods the author never named, and on this layer a deny beats every allow and cannot be
    // carved out — an accidental blast radius with no ordering escape.
    const objects = (
      plan([
        {
          policy: policy({
            id: "APP-DENY-API",
            src: { kind: "k8s-namespace", value: "stardust" },
            dst: { kind: "k8s-label", value: `${NS}=dispatcher,app=dispatcher` },
            action: "deny",
          }),
        },
      ])
    ).policies;
    assert.equal(objects.length, 1, "a deny must not gain an ingress half");
    assert.ok(objects[0]!.spec.egressDeny, "and it stays a deny");
  });
});

describe("an egress allow must not close the sender", () => {
  // ## The outage this pins
  //
  // Cilium puts an endpoint in default-deny for a direction as soon as **any** policy selecting it
  // asks for that. So an egress allow that requests it does not merely add a permission — it
  // replaces the sender's entire egress posture with "only what this policy names".
  //
  // Measured 2026-08-10. The first egress allow this repository ever rendered went to the dashboard
  // pods, and three seconds later they could not resolve DNS:
  //
  //     identity 6565 -> 10.17.128.128:53 udp   bpf_lxc.c:1361   (coredns)
  //
  // Login had been broken for 2.5 days; this replaced it with a worse break, and the object
  // rendered, applied and reported `Valid=True` throughout.
  //
  // The repository already warned about this trap — on the deny path, about somebody else's future
  // allow. Then the renderer emitted such an allow itself. That is the shape worth remembering: the
  // warning was addressed to a stranger, and the caller it actually applied to was us.
  const egressAllow = () =>
    plan([
      {
        policy: policy({
          id: "APP-TO-API",
          src: { kind: "k8s-namespace", value: "stardust" },
          dst: { kind: "k8s-label", value: `${NS}=dispatcher,app=dispatcher` },
          ports: "8080",
        }),
      },
    ]).policies;

  it("leaves the sender's other egress alone", () => {
    // The assertion that would have prevented the outage. `true` here means the dashboard keeps
    // exactly the flows this policy names and loses DNS, the API server, and everything else.
    const sender = egressAllow().find((o) => o.metadata.namespace === "stardust")!;
    assert.equal(
      sender.spec.enableDefaultDeny?.egress,
      false,
      "an egress allow that closes its sender takes out DNS — see the drop capture above",
    );
  });

  it("still closes the destination on the ingress half", () => {
    // The known negative, and the reason this is not a blanket "never close anything": closing the
    // destination is what makes an ingress allow mean "this caller and no other". Weakening both
    // directions together would turn the pair into decoration.
    const receiver = egressAllow().find((o) => o.metadata.namespace === "dispatcher")!;
    assert.equal(receiver.spec.enableDefaultDeny?.ingress, true);
  });

  it("says out loud that closing the destination is a side effect the author did not write", () => {
    // The behaviour above is kept; what was missing is that it is *visible*. The author wrote "these
    // pods may reach those pods" and got, as a consequence, "and nothing else may reach those pods"
    // — the exact shape of claim this file refused to make silently in the egress direction, where
    // an allow renders `{ egress: false }` for the same reason.
    //
    // Cilium's aggregation rule makes it unfixable from any other policy: default-deny is enabled
    // for an endpoint if *any* policy asks for it, so a second policy cannot reopen those pods.
    const warned = plan([
      {
        policy: policy({
          id: "APP-TO-API",
          src: { kind: "k8s-namespace", value: "stardust" },
          dst: { kind: "k8s-label", value: `${NS}=dispatcher,app=dispatcher` },
          ports: "8080",
        }),
      },
    ]).warnings.map((w) => w.warning).join("\n");
    contains(warned, "ingress default-deny");
    contains(warned, "stops working");
  });

  it("keeps a deny subtractive rather than closing the pods it names", () => {
    // Unchanged behaviour, asserted so the fix above cannot be "simplified" into applying to denies
    // too. A deny asks `false` so it subtracts from what the pods already reach; that request loses
    // to any allow selecting the same pods, which is the warning this file already carries.
    const denied = plan([
      {
        policy: policy({
          id: "RUNNER-DENY",
          src: { kind: "k8s-namespace", value: "arc-runners" },
          dst: { kind: "k8s-label", value: `${NS}=util,app=idp` },
          action: "deny",
        }),
      },
    ]).policies;
    assert.equal(denied[0]!.spec.enableDefaultDeny?.egress, false);
  });
});

// ── The egress baseline, and the allow-list it makes expressible ──────────────
//
// Until this object existed, egress containment on this layer could only be written as a deny list
// — `BUILD-JOBS-DENY-*`, fifteen policies naming every namespace the build pods must not reach. That
// is exact and absolute, and it is an *enumeration*: a namespace created tomorrow is reachable until
// somebody adds a line. The opposite polarity could not be assembled out of allows, because an
// egress allow deliberately renders `{ egress: false }` — it must not close its sender (2026-08-10,
// where the first one that did took DNS down three seconds later).
//
// So the closing is its own named object and the allows beside it are unchanged.
describe("selector-egress-default-deny baseline", () => {
  const baseline = (over: Record<string, unknown> = {}) => ({
    kind: "selector-egress-default-deny" as const,
    id: "VULTR-BROKER-EGRESS",
    namespace: "dispatcher",
    selector: `${NS}=dispatcher,app=vultr-broker`,
    description: "Default deny egress for the Vultr root-key broker.",
    ...over,
  });

  it("closes exactly the selected pods, with a destination no pod can be in", () => {
    const { plan: p } = renderCiliumPolicies(input(), [], [baseline()]);
    const obj = p.policies[0]!;
    assert.equal(obj.metadata.name, "hp-dev-vultr-broker-egress-egress-baseline");
    assert.equal(obj.metadata.namespace, "dispatcher");
    assert.equal(obj.metadata.annotations["heliopause.io/policy-kind"], "selector-egress-default-deny");
    assert.deepEqual(obj.spec, {
      description: "Default deny egress for the Vultr root-key broker.",
      endpointSelector: { matchLabels: { "app": "vultr-broker", [NS]: "dispatcher" } },
      enableDefaultDeny: { egress: true },
      // Not `egress: [{}]`. Cilium's `Sanitize()` decides enforcement with
      // `len(r.Egress) > 0 || len(r.EgressDeny) > 0`, so a spec with no egress section leaves the
      // endpoint exactly where it was — and an empty rule goes the other way and allows every peer,
      // which reads as containment while removing it.
      egress: [{ toEndpoints: [{ matchLabels: { [NS]: "HELI0PAUSE-NEVER" } }] }],
    });
  });

  it("refuses a selector that names nothing but the namespace", () => {
    // An empty `EndpointSelector` is a *wildcard* in Cilium and `getEndpointSelector` fills the
    // policy's own namespace in. The object that meant "close the broker" would mean "close every
    // pod in dispatcher" — which also holds `dispatcher`, `cron-runner` and `vworld-proxy`. Both
    // requests for this feature ruled that out by name, so it is refused rather than defaulted.
    assert.throws(
      () => renderCiliumPolicies(input(), [], [baseline({ selector: `${NS}=dispatcher` })]),
      /names no label besides the namespace/,
    );
    assert.throws(() => renderCiliumPolicies(input(), [], [baseline({ selector: "" })]), /does not pin/);
  });

  it("refuses a selector pinned to a different namespace than the object lands in", () => {
    // A CiliumNetworkPolicy only governs pods in its own namespace, so the two names cannot disagree
    // — one of them describes pods this object can never reach, and it applies cleanly either way.
    assert.throws(
      () => renderCiliumPolicies(input(), [], [baseline({ selector: `${NS}=build-jobs,app=vultr-broker` })]),
      /but the baseline declares namespace/,
    );
  });

  it("asks about the pods it selects, by the selector rather than by the namespace", () => {
    // The ingress baseline is namespace-wide, so `k8s-namespace` is the right question for it. This
    // one closes a label, and asking about the namespace would report pods it does not select — the
    // agent's enforcement gate would then confirm a generation on the strength of somebody else's
    // pod.
    const asked: Array<[string, string]> = [];
    const { plan: p } = renderCiliumPolicies(
      input({ resolvePods: (kind, value) => (asked.push([kind, value]), ["dispatcher/vultr-broker-0"]) }),
      [], [baseline()],
    );
    assert.deepEqual(asked, [["k8s-label", `${NS}=dispatcher,app=vultr-broker`]]);
    assert.deepEqual(p.affectedPods["VULTR-BROKER-EGRESS"], ["dispatcher/vultr-broker-0"]);
  });

  it("still refuses an unknown baseline kind", () => {
    assert.throws(
      () => renderCiliumPolicies(input(), [], [baseline({ kind: "selector-egress-allow" }) as never]),
      /invalid kind, id, or description/,
    );
  });

  it("does not collide with the ingress baseline for the same policy id", () => {
    // The two carry different suffixes precisely so one workload can have both postures without the
    // second silently overwriting the first at apply.
    const { plan: p } = renderCiliumPolicies(input(), [], [
      { kind: "namespace-ingress-default-deny", id: "BROKER", namespace: "dispatcher", description: "in" },
      baseline({ id: "BROKER" }),
    ]);
    assert.deepEqual(p.policies.map((o) => o.metadata.name), ["hp-dev-broker-baseline", "hp-dev-broker-egress-baseline"]);
  });

  it("is watched by its selector, and counts against the same query budget", () => {
    const w = selectorsToWatch([], [baseline()]);
    assert.deepEqual(w, { namespaces: [], labels: [`${NS}=dispatcher,app=vultr-broker`] });
    // Merged in *here* rather than at the call site: the bound is the agent's, enforced
    // independently, so a set of baselines that pushed the request past it used to be discovered on
    // the node instead of at the render.
    const many = Array.from({ length: 33 }, (_, i) => baseline({ id: `B${i}`, selector: `${NS}=dispatcher,app=b${i}` }));
    assert.throws(() => selectorsToWatch([], many), /limit is 32/);
  });
});

// ── applierNamespaces: the half heliopause was never able to apply ────────────
describe("applierNamespaces", () => {
  const ns = ["arc-runners", "util", "dispatcher"];

  it("refuses an object addressed outside the applier's RoleBindings", () => {
    // Not a narrower policy — the agent refuses the whole document over one such object, so the
    // generation never applies at all. Caught here, where the policy id is still in hand.
    assert.throws(
      () => plan([{ policy: policy({ id: "P1", dst: { kind: "k8s-namespace", value: "kube-system" } }) }],
        { applierNamespaces: ns }),
      /outside the applier's namespaces/,
    );
  });

  it("renders the sender's half alone when the destination is one we cannot write to", () => {
    // Every closed egress posture needs DNS, and DNS is CoreDNS in `kube-system` — a pod-backed
    // destination, so `toCIDR` can never match it. Emitting the receiver's half too is what made
    // that allow unpublishable: the agent throws the document away, taking the sender's half with
    // it. The half we keep is enough here for a reason specific to this case — heliopause holds no
    // RoleBinding in `kube-system`, so nothing we publish could put CoreDNS into ingress
    // default-deny either.
    const p = plan(
      [{
        policy: policy({
          id: "BROKER-DNS",
          src: { kind: "k8s-label", value: `${NS}=dispatcher,app=vultr-broker` },
          dst: { kind: "k8s-label", value: `${NS}=kube-system,k8s-app=kube-dns` },
          proto: "any",
          ports: "53",
        }),
      }],
      { applierNamespaces: ns },
    );
    assert.deepEqual(p.policies.map((o) => `${o.metadata.namespace}/${o.metadata.name}`), ["dispatcher/hp-dev-broker-dns"]);
    assert.equal(p.policies[0]!.spec.enableDefaultDeny?.egress, false);
    const warned = p.warnings.map((w) => w.warning).join("\n");
    contains(warned, "sender's egress half only");
    contains(warned, "no RoleBinding there");
  });

  it("still renders both halves for a destination inside the list", () => {
    const p = plan(
      [{
        policy: policy({
          id: "P2",
          src: { kind: "k8s-namespace", value: "arc-runners" },
          dst: { kind: "k8s-label", value: `${NS}=util,app=idp` },
        }),
      }],
      { applierNamespaces: ns },
    );
    assert.deepEqual(p.policies.map((o) => `${o.metadata.namespace}/${o.metadata.name}`),
      ["arc-runners/hp-dev-p2", "util/hp-dev-p2-ingress"]);
  });

  it("withholds a Service destination's half too, and says which pods it withheld it for", () => {
    const p = plan(
      [{ policy: policy({ id: "P3", src: { kind: "k8s-namespace", value: "arc-runners" }, dst: { kind: "k8s-service", value: "util/zot" } }) }],
      { applierNamespaces: ["arc-runners"] },
    );
    assert.deepEqual(p.policies.map((o) => o.metadata.namespace), ["arc-runners"]);
    contains(p.warnings.map((w) => w.warning).join("\n"), 'the pods behind Service "util/zot"');
  });

  it("changes nothing when the caller does not say what the applier can write to", () => {
    // Most callers of this exported renderer have no reason to know the applier's RBAC, and the
    // absent field must not quietly mean "nothing is writable".
    const p = plan([{ policy: policy({ id: "P4", dst: { kind: "k8s-namespace", value: "kube-system" } }) }]);
    assert.equal(p.policies.length, 1);
  });

  it("applies to baselines as well as to flows", () => {
    assert.throws(
      () => renderCiliumPolicies(input({ applierNamespaces: ns }), [], [
        { kind: "namespace-ingress-default-deny", id: "X", namespace: "kube-system", description: "d" },
      ]),
      /outside the applier's namespaces/,
    );
  });
});
