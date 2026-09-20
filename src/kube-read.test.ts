// The measurement, and the ways a measured selector still ends up wrong.
//
// A selector that matches nothing does not fail: Cilium renders it, applies it, and the rule allows
// no one while every status stays green. So the tests that matter here are the ones about labels
// that are true at the moment they are read and false after the next rollout, and about a namespace
// answering less than all of itself.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  KubeReadError,
  MAX_PODS,
  measureNamespace,
  measureNamespaces,
  selectorText,
  stableLabels,
  suggestedLabelKeys,
  VOLATILE_LABELS,
  type KubeFetcher,
  type KubeReadConfig,
} from "./kube-read.ts";

const config = (over: Partial<KubeReadConfig> & { fetch: KubeFetcher }): KubeReadConfig => ({
  namespaces: ["stardust-databases"],
  apiUrl: "https://kubernetes.invalid",
  tokenFile: "/dev/null",
  caFile: "/dev/null",
  ...over,
});

const answering = (routes: Record<string, unknown>, seen: string[] = []): { fetch: KubeFetcher; seen: string[] } => ({
  seen,
  fetch: async (path) => {
    seen.push(path);
    const key = Object.keys(routes).find((k) => path.includes(k));
    if (!key) throw new Error(`no route for ${path}`);
    const value = routes[key];
    if (typeof value === "number") return { status: value, text: `{"message":"forbidden"}` };
    return { status: 200, text: JSON.stringify(value) };
  },
});

const podList = (items: unknown[], extra: Record<string, unknown> = {}) => ({ items, ...extra });

describe("stableLabels", () => {
  // The rollout is the whole point. `pod-template-hash` is correct when it is copied and wrong the
  // next time the Deployment rolls, and the rule that carried it silently matches nothing.
  it("drops every label a controller rewrites", () => {
    const labels: Record<string, string> = { app: "hub" };
    for (const key of VOLATILE_LABELS) labels[key] = "whatever";
    assert.deepEqual(stableLabels(labels), { app: "hub" });
  });

  it("keeps the hash out even when it is the only other label", () => {
    assert.deepEqual(stableLabels({ "pod-template-hash": "5fd8cf5d59" }), {});
  });
});

describe("suggestedLabelKeys", () => {
  // Two kinds, and the second is the one that gets forgotten: the identity label is what stops a
  // grant written for one database being inherited by the next workload that reuses the name.
  it("offers the name label and the identity label", () => {
    assert.deepEqual(
      suggestedLabelKeys({
        "app.kubernetes.io/name": "test",
        "stardust.io/database-id": "74e4726f",
        "pod-template-hash": "abc123",
        "helm.sh/chart": "postgres-1.2.3",
      }),
      ["app.kubernetes.io/name", "stardust.io/database-id"],
    );
  });

  // The in-cluster sender from request 230 carries `app` and the controller's hash and nothing else.
  // `app` alone is the half that survives a redeploy, and the suggestion must be exactly that half.
  it("takes app when that is all a pod carries", () => {
    assert.deepEqual(suggestedLabelKeys({ app: "cloudflared-hyperdrive", "pod-template-hash": "np5wj" }), ["app"]);
  });

  it("never suggests a volatile label, even one shaped like an identity", () => {
    assert.deepEqual(suggestedLabelKeys({ "controller-uid": "9f2c", "batch.kubernetes.io/controller-uid": "9f2c" }), []);
  });
});

describe("selectorText", () => {
  // A selector without the namespace term matches by label across the whole cluster. For a label as
  // ordinary as `app=hub` that is a grant nobody intended and nobody would notice in a diff.
  it("always leads with the namespace", () => {
    const out = selectorText("stardust-databases", { app: "hub" }, ["app"]);
    assert.equal(out, "k8s:io.kubernetes.pod.namespace=stardust-databases,app=hub");
  });

  it("writes the terms in a stable order so two authors produce the same string", () => {
    const labels = { "stardust.io/database-id": "74e4726f", "app.kubernetes.io/name": "test" };
    assert.equal(
      selectorText("stardust-databases", labels, ["stardust.io/database-id", "app.kubernetes.io/name"]),
      selectorText("stardust-databases", labels, ["app.kubernetes.io/name", "stardust.io/database-id"]),
    );
  });

  // A key the pod does not carry would render as `key=undefined`, which matches nothing and reads
  // like a label whose value happens to be the word undefined.
  it("leaves out a key the pod does not have", () => {
    assert.equal(selectorText("ns", { app: "hub" }, ["app", "absent"]), "k8s:io.kubernetes.pod.namespace=ns,app=hub");
  });
});

describe("measureNamespace", () => {
  it("reports the labels, the stable half, the probes and the ports", async () => {
    const { fetch } = answering({
      "/pods": podList([
        {
          metadata: { name: "test-0", labels: { "app.kubernetes.io/name": "test", "controller-revision-hash": "x" } },
          spec: { containers: [{ ports: [{ containerPort: 5432 }, { containerPort: 5432 }] }] },
        },
      ]),
      "/services": podList([
        { metadata: { name: "test" }, spec: { clusterIP: "10.17.202.239", selector: { app: "test" }, ports: [{ port: 5432 }] } },
      ]),
    });
    const out = await measureNamespace(config({ fetch }), "stardust-databases");
    const pod = out.pods[0]!;
    assert.deepEqual(pod.stable, { "app.kubernetes.io/name": "test" });
    assert.deepEqual(pod.suggested, ["app.kubernetes.io/name"], "the ticked keys travel with the pod");
    assert.equal(Object.keys(pod.labels).length, 2, "the raw labels stay visible");
    assert.deepEqual(pod.probes, { readiness: false, liveness: false });
    assert.deepEqual(pod.ports, [5432], "a port declared twice is one port");
    assert.equal(out.services[0]?.clusterIP, "10.17.202.239");
    assert.deepEqual(out.services[0]?.ports, [{ port: 5432, protocol: "TCP" }]);
  });

  // The probe answer decides whether the workload needs a host-allow exemption, and a pod is a set
  // of containers: one sidecar with a readiness probe makes the pod probed.
  it("finds a probe on any container, not just the first", async () => {
    const { fetch } = answering({
      "/pods": podList([
        {
          metadata: { name: "hub-0", labels: { app: "hub" } },
          spec: { containers: [{}, { livenessProbe: { httpGet: { path: "/healthz" } } }] },
        },
      ]),
      "/services": podList([]),
    });
    const out = await measureNamespace(config({ fetch }), "stardust-databases");
    assert.deepEqual(out.pods[0]?.probes, { readiness: false, liveness: true });
  });

  // `None` is a headless service. Printing it where an address goes puts a string that is not an
  // address in front of somebody who is about to write one down.
  it("does not report None as an address", async () => {
    const { fetch } = answering({
      "/pods": podList([]),
      "/services": podList([{ metadata: { name: "test-headless" }, spec: { clusterIP: "None" } }]),
    });
    const out = await measureNamespace(config({ fetch }), "stardust-databases");
    assert.equal(out.services[0]?.clusterIP, null);
  });

  // The allowlist is checked here and not only in RBAC, because the two are edited by different
  // people: a namespace in one and not the other should refuse as a sentence, not as a 403 that
  // reads like the cluster is broken.
  it("refuses a namespace it was not configured for, before asking the apiserver", async () => {
    const { fetch, seen } = answering({});
    await assert.rejects(
      () => measureNamespace(config({ fetch }), "kube-system"),
      (e: unknown) => e instanceof KubeReadError && e.status === 403,
    );
    assert.deepEqual(seen, [], "nothing was asked");
  });

  // A truncated list is the dangerous answer: the operator picks from what fitted and never learns
  // the workload they wanted was on the part that did not.
  it("refuses a namespace it cannot see all of", async () => {
    const many = Array.from({ length: MAX_PODS + 1 }, (_, i) => ({ metadata: { name: `p-${i}`, labels: {} }, spec: {} }));
    const { fetch } = answering({ "/pods": podList(many), "/services": podList([]) });
    await assert.rejects(() => measureNamespace(config({ fetch }), "stardust-databases"), /more than 200 pods/);
  });

  it("refuses a page that says there is more after it", async () => {
    const { fetch } = answering({
      "/pods": podList([{ metadata: { name: "one", labels: {} }, spec: {} }], { metadata: { continue: "token" } }),
      "/services": podList([]),
    });
    await assert.rejects(() => measureNamespace(config({ fetch }), "stardust-databases"), /more than 200 pods/);
  });

  // The apiserver's own sentence. A 403 means the RoleBinding is missing or names another namespace,
  // and that is the difference between a one-minute fix and reading this file to find out what was
  // asked for.
  it("passes the apiserver's refusal through with its status", async () => {
    const { fetch } = answering({ "/pods": 403 });
    await assert.rejects(
      () => measureNamespace(config({ fetch }), "stardust-databases"),
      (e: unknown) => e instanceof KubeReadError && e.status === 403 && /forbidden/.test(e.message),
    );
  });

  it("refuses an answer that is not JSON", async () => {
    const fetch: KubeFetcher = async () => ({ status: 200, text: "<html>proxy error</html>" });
    await assert.rejects(() => measureNamespace(config({ fetch }), "stardust-databases"), /did not answer JSON/);
  });
});

describe("measureNamespaces", () => {
  // Unset and empty are the same answer — the feature is off — and neither may stop the manager
  // starting, because every other route has nothing to do with the cluster.
  it("is empty for an unset, blank or comma-only value", () => {
    assert.deepEqual(measureNamespaces({}), []);
    assert.deepEqual(measureNamespaces({ HELIOPAUSE_K8S_MEASURE_NAMESPACES: "" }), []);
    assert.deepEqual(measureNamespaces({ HELIOPAUSE_K8S_MEASURE_NAMESPACES: " , ,, " }), []);
  });

  it("trims the spaces a hand-edited env var collects", () => {
    assert.deepEqual(
      measureNamespaces({ HELIOPAUSE_K8S_MEASURE_NAMESPACES: "stardust-databases, tinyuniverse " }),
      ["stardust-databases", "tinyuniverse"],
    );
  });
});
