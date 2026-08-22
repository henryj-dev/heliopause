// Config construction tests.
//
// These pin the constraints that only bite at runtime — a config that typechecks but guarantees
// every apply rolls back, or that turns on mutual TLS with nothing to verify the peer against.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { contains } from "./test-util.ts";
import {
  defineConfig,
  MIN_PULL_CONFIRM_TIMEOUT_SEC,
  type RelayConfig,
  type TlsConfig,
  type WorkloadConfig,
} from "./config.ts";

const tls: TlsConfig = {
  certFile: "/etc/heliopause/agent.pem",
  keyFile: "/etc/heliopause/agent.key",
  caFile: "/etc/heliopause/relay-ca.pem",
  pins: [],
};

const relay: RelayConfig = { url: "https://gw.dev.internal:8443", heartbeatIntervalSec: 15 };

describe("defaults", () => {
  it("builds without any transport configured", () => {
    const cfg = defineConfig();
    assert.equal(cfg.relay, null);
    assert.equal(cfg.tls, null);
    assert.equal(cfg.artifactStore.dir, ".heliopause/artifacts");
  });
});

describe("relay", () => {
  it("accepts the receiver-derived confirmation safety floor", () => {
    const cfg = defineConfig({ relay, tls, confirmTimeoutSec: MIN_PULL_CONFIRM_TIMEOUT_SEC });
    assert.equal(cfg.confirmTimeoutSec, 90);
  });

  // The failure this prevents is quiet and expensive: every host applies, never confirms in
  // time, and reverts — looking like a heliopause fault rather than a mistyped number.
  it("rejects a confirm window below the receiver's bounded apply and retry path", () => {
    assert.throws(
      () => defineConfig({ relay, tls, confirmTimeoutSec: MIN_PULL_CONFIRM_TIMEOUT_SEC - 1 }),
      /safety floor/,
    );
  });

  it("rejects a zero heartbeat interval", () => {
    assert.throws(
      () => defineConfig({
        relay: { ...relay, heartbeatIntervalSec: 0 }, tls,
        confirmTimeoutSec: MIN_PULL_CONFIRM_TIMEOUT_SEC,
      }),
      /at least 1/,
    );
  });

  it("refuses to run the pull transport unauthenticated", () => {
    assert.throws(
      () => defineConfig({ relay, confirmTimeoutSec: MIN_PULL_CONFIRM_TIMEOUT_SEC }),
      /requires tls/,
    );
  });
});

describe("tls", () => {
  it("accepts an anchor without pins", () => {
    assert.equal(defineConfig({ tls }).tls?.caFile, "/etc/heliopause/relay-ca.pem");
  });

  it("accepts pins alongside an anchor", () => {
    const pinned = defineConfig({ tls: { ...tls, pins: ["sha256/AAAA"] } });
    assert.equal((pinned.tls?.pins)?.length, 1);
  });

  // There is no unverified mode. An empty anchor would mean encryption to whoever answered,
  // and the peer that answers is the one that gets to set this host's firewall.
  it("rejects an empty anchor even when pins are set", () => {
    assert.throws(
      () => defineConfig({ tls: { ...tls, caFile: "", pins: ["sha256/AAAA"] } }),
      /caFile is required/,
    );
  });
});

describe("workload", () => {
  const workload: WorkloadConfig = {
    cluster: "dev",
    applier: "h-k3s-01",
    ciliumVersion: [1, 17],
    confirmTimeoutSec: 300,
  };

  it("is null by default — a site with no cluster should not have to say so", () => {
    assert.equal(defineConfig().workload, null);
  });

  it("accepts a complete block", () => {
    assert.equal(defineConfig({ workload }).workload?.applier, "h-k3s-01");
  });

  it("rejects an empty applier", () => {
    // CiliumNetworkPolicy is cluster-scoped; with no designated node every agent writes the same
    // object.
    assert.throws(() => defineConfig({ workload: { ...workload, applier: "" } }), /one designated/);
  });

  it("rejects a missing Cilium version rather than guessing one", () => {
    // Both guesses fail. High is rejected at apply where the error no longer names the policy; low
    // silently drops the port condition from every toServices rule.
    assert.throws(
      () =>
        defineConfig({
          workload: { ...workload, ciliumVersion: undefined as unknown as readonly [number, number] },
        }),
      /must be \[major, minor\] integers/,
    );
  });

  it("tells you how to read the Cilium version off the cluster", () => {
    // The error has to be actionable — this value cannot be inferred from anything in the repo.
    try {
      defineConfig({ workload: { ...workload, ciliumVersion: [0, 0] } });
      assert.fail("expected a throw");
    } catch (e) {
      contains((e as Error).message, "kubectl -n kube-system get ds cilium");
    }
  });

  // H20. The two layers fail differently, so one timer cannot serve both: Cilium's identity cache
  // and eBPF maps settle after the API server returns, and a window at or below the nftables figure
  // rolls back policy that was on its way to healthy — which then reads as "the policy was bad".
  it("rejects a workload timeout that does not exceed the host one", () => {
    assert.throws(
      () => defineConfig({ workload: { ...workload, confirmTimeoutSec: 60 } }),
      /must exceed confirmTimeoutSec/,
    );
  });

  it("rejects a workload timeout shorter than the host one", () => {
    assert.throws(
      () => defineConfig({ workload: { ...workload, confirmTimeoutSec: 30 } }),
      /needs longer/,
    );
  });
});
