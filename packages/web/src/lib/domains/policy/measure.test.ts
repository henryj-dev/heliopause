// The measurement as the browser reads it, and the selector it builds from it.
//
// A selector that matches nothing is the failure this whole panel exists to prevent, and it is
// silent: Cilium renders it, applies it, and no status ever goes red. So every case here is about a
// string that looks right — a term missing, a term that says `undefined`, a namespace left off.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { droppedLabelCount, probeWords, readMeasureReply, selectorText, type MeasuredPod } from "./measure.ts";

const pod = (over: Partial<MeasuredPod> = {}): MeasuredPod => ({
  name: "test-0",
  labels: { "app.kubernetes.io/name": "test", "pod-template-hash": "abc" },
  stable: { "app.kubernetes.io/name": "test" },
  suggested: ["app.kubernetes.io/name"],
  probes: { readiness: false, liveness: false },
  ports: [5432],
  ...over,
});

describe("selectorText", () => {
  // Without the namespace term the selector matches by label across the whole cluster. `app=hub` is
  // ordinary enough that some other namespace has one, and nothing in the diff would say so.
  it("always leads with the namespace", () => {
    assert.equal(
      selectorText("stardust-databases", { app: "hub" }, ["app"]),
      "k8s:io.kubernetes.pod.namespace=stardust-databases,app=hub",
    );
  });

  // The manager builds the same string once, to suggest. The browser rebuilds it on every checkbox.
  // If the two ever ordered terms differently, a rule would appear to change when nothing did.
  it("orders terms the same way however they were ticked", () => {
    const labels = { "stardust.io/database-id": "74e4726f", "app.kubernetes.io/name": "test" };
    assert.equal(
      selectorText("ns", labels, ["stardust.io/database-id", "app.kubernetes.io/name"]),
      selectorText("ns", labels, ["app.kubernetes.io/name", "stardust.io/database-id"]),
    );
  });

  // Otherwise the term renders as `key=undefined`, which matches nothing and reads like a label
  // whose value happens to be that word.
  it("drops a key the pod does not carry", () => {
    assert.equal(selectorText("ns", { app: "hub" }, ["app", "gone"]), "k8s:io.kubernetes.pod.namespace=ns,app=hub");
  });

  it("is still a valid selector when nothing is ticked", () => {
    assert.equal(selectorText("ns", { app: "hub" }, []), "k8s:io.kubernetes.pod.namespace=ns");
  });
});

describe("readMeasureReply", () => {
  // The first call the editor makes carries no namespace, because the operator has not chosen one.
  // Treating that as a failure would put an error message on the panel's opening state.
  it("accepts a namespace list on its own", () => {
    const reply = readMeasureReply({ namespaces: ["stardust-databases"] });
    assert.ok(reply.ok);
    assert.deepEqual(reply.measurement.namespaces, ["stardust-databases"]);
    assert.deepEqual(reply.measurement.pods, []);
  });

  it("passes the manager's refusal through as its own words", () => {
    const reply = readMeasureReply({ error: "this console may only look in: stardust-databases" });
    assert.equal(reply.ok, false);
    assert.equal("reason" in reply && reply.reason, "this console may only look in: stardust-databases");
  });

  it("refuses an answer with no namespace list at all", () => {
    assert.equal(readMeasureReply({}).ok, false);
    assert.equal(readMeasureReply(null).ok, false);
    assert.equal(readMeasureReply("stardust-databases").ok, false);
  });

  // A label whose value is not a string would land in a selector as `key=undefined` or, worse, as
  // `key=[object Object]`. Dropping it is visible in the panel; rendering it is not.
  it("keeps only labels that are strings", () => {
    const reply = readMeasureReply({
      namespaces: ["ns"],
      namespace: "ns",
      pods: [{ name: "p", labels: { app: "hub", n: 5, o: { a: 1 } }, stable: { app: "hub" }, suggested: ["app"] }],
    });
    assert.ok(reply.ok);
    assert.deepEqual(reply.measurement.pods[0]?.labels, { app: "hub" });
  });

  it("defaults the probes to absent rather than to true", () => {
    const reply = readMeasureReply({ namespaces: ["ns"], pods: [{ name: "p" }] });
    assert.ok(reply.ok);
    assert.deepEqual(reply.measurement.pods[0]?.probes, { readiness: false, liveness: false });
  });
});

describe("what the panel says about a pod", () => {
  // The count is shown so the operator knows something was left out. A panel that silently shrank
  // the label set would be indistinguishable from a pod that never had those labels.
  it("counts the labels the manager left out", () => {
    assert.equal(droppedLabelCount(pod()), 1);
    assert.equal(droppedLabelCount(pod({ labels: { app: "hub" }, stable: { app: "hub" } })), 0);
  });

  // Whether a workload is probed decides whether it needs a host-allow exemption — a fact that
  // otherwise gets carried in somebody's head from a terminal to a rule.
  it("names the probes a workload declares", () => {
    assert.deepEqual(probeWords(pod()), []);
    assert.deepEqual(probeWords(pod({ probes: { readiness: true, liveness: true } })), ["readiness", "liveness"]);
    assert.deepEqual(probeWords(pod({ probes: { readiness: false, liveness: true } })), ["liveness"]);
  });
});
