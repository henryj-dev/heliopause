// What has passed the workload allows, and what has not.
//
// ## Where this runs, and why not where it was first written
//
// The first version of this parser lived in the agent, next to the `kubectl exec` that produces its
// input. It could never have run: the agent's kubeconfig is deliberately least-privilege and cannot
// read pods in `kube-system`, let alone `exec` into one — measured, not assumed. Giving it that
// would hand the process that applies the firewall a way to reach into the dataplane and go round
// it, which is the opposite of what this system has done since audit C1.
//
// So the exec happens in a pod that holds nothing else — the same shape as `heliopause-policy-render`
// — and that pod serves the dump verbatim. **The parsing is here rather than there on purpose**: a
// reader with no logic has no logic to get wrong, and this file can be tested against a real dump
// without a cluster.
//
// ## What the numbers mean, and what they do not
//
// Cilium counts per (endpoint, direction, identity, port). It does **not** record which policy
// produced an allow, so nothing here says "rule X carried N packets" — two rules selecting the same
// pods on the same port collapse into one map entry. Attribution is left unmade because it is not
// available, and inventing it would put a number under a rule that did not earn it.
//
// What it answers, and nothing else does: **which allows carry nothing.** On the first real dump,
// 491 of 546 entries had never passed a packet.

/** One row of `cilium bpf policy get --all`, after the label noise is dropped. */
export interface TrafficEntry {
  endpoint: string;
  policy: "allow" | "deny";
  direction: "ingress" | "egress";
  /** `reserved:host`, `k8s:app=dashboard`, `cidr:10.0.0.0/8` — as Cilium prints it. */
  peer: string;
  port: string;
  bytes: number;
  packets: number;
}

export interface TrafficSummary {
  /** Every entry a policy produced, catch-alls excluded. Always `withTraffic + dead`. */
  entries: number;
  withTraffic: number;
  /** How many have carried nothing — the finding no other instrument reports. */
  dead: number;
  /**
   * Rows whose counters this could not read, and which are therefore in neither list above.
   *
   * Zero and "never" are the same thing here and both are the finding — but "unreadable" is a third
   * thing, and it used to be folded in by accident. `Number("1.2k")` is `NaN`, `NaN > 0` is false and
   * `NaN === 0` is false, so such a row fell out of both `live` and `dead` while still being counted
   * in `entries`. The three numbers on the screen stopped adding up, the row appeared in no list, and
   * the headline `dead / entries` percentage was understated by exactly the rows nobody could see.
   *
   * Reported rather than dropped, for the same reason `top` and `deadSample` carry their totals: a
   * count that has quietly stopped covering everything is worse than no count.
   */
  unreadable: number;
  top: TrafficEntry[];
  deadSample: TrafficEntry[];
}

/**
 * A counter column, or `null` if it is not one.
 *
 * `-` means the counter was never touched, which is zero. Anything else that is not a plain
 * non-negative integer is not evidence about traffic in either direction, and `Number()` turning it
 * into `NaN` must not be mistaken for one.
 */
function counter(raw: string): number | null {
  if (raw === "-") return 0;
  if (!/^\d+$/.test(raw)) return null;
  const n = Number(raw);
  return Number.isSafeInteger(n) ? n : null;
}

const ROW = /^(Allow|Deny)\s+(Ingress|Egress)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+\d+\s*$/;

/** How many of each list travels. Bounded so a large cluster cannot turn a screen into a download. */
export const TOP_N = 20;
export const DEAD_N = 40;

export function parseTrafficDump(text: string): TrafficSummary {
  const rows: TrafficEntry[] = [];
  let unreadable = 0;
  let endpoint: string | null = null;
  for (const line of text.split("\n")) {
    if (line.startsWith("Endpoint ID:")) {
      endpoint = line.slice("Endpoint ID:".length).trim();
      continue;
    }
    const m = ROW.exec(line);
    if (!m || endpoint === null) continue;
    const [, policy, direction, peer, port, bytes, packets] = m;
    // The catch-all is dropped. `Allow Ingress ANY ANY` is what an endpoint with no policy has; there
    // are hundreds and none is one of ours. What survives is every entry naming a peer or a port,
    // which is exactly the set a policy produced.
    if (peer === "ANY" && port === "ANY") continue;
    // A dash means the counter was never touched. Zero and "never" are the same thing here, and both
    // are the finding — but a column this cannot read is a third thing, and it is counted as such
    // rather than sorted into one of the two. See `TrafficSummary.unreadable`.
    const b = counter(bytes!);
    const pk = counter(packets!);
    if (b === null || pk === null) {
      unreadable += 1;
      continue;
    }
    rows.push({
      endpoint,
      policy: policy!.toLowerCase() as "allow" | "deny",
      direction: direction!.toLowerCase() as "ingress" | "egress",
      peer: peer!,
      port: port!,
      bytes: b,
      packets: pk,
    });
  }
  rows.sort((a, b) => b.packets - a.packets || a.endpoint.localeCompare(b.endpoint) || a.peer.localeCompare(b.peer));
  const live = rows.filter((r) => r.packets > 0);
  const dead = rows.filter((r) => r.packets === 0);
  // **Totals travel with the samples so the truncation is visible.** A list of forty that does not
  // say it is forty of four hundred and ninety-one reads as the whole answer, and this project has a
  // standing rule against caps that do not announce themselves.
  return {
    entries: rows.length,
    withTraffic: live.length,
    dead: dead.length,
    unreadable,
    top: live.slice(0, TOP_N),
    deadSample: dead.slice(0, DEAD_N),
  };
}
