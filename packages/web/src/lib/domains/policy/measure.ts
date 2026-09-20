// What `GET /api/policy/measure` says, and the one string the editor builds from it.
//
// The parsing is defensive for the same reason `write.ts` is: this arrives over the wire, and a
// field that is quietly absent would render as `undefined` inside a selector — a term that matches
// nothing and reads like a label whose value happens to be that word.

export interface MeasuredPod {
  name: string;
  labels: Record<string, string>;
  /** The labels that survive a rollout. The manager strips the rest; see `src/kube-read.ts`. */
  stable: Record<string, string>;
  /** The keys the manager would tick — a starting point, never a decision made for the operator. */
  suggested: string[];
  probes: { readiness: boolean; liveness: boolean };
  ports: number[];
}

export interface MeasuredService {
  name: string;
  clusterIP: string | null;
  selector: Record<string, string>;
  ports: { port: number; protocol: string }[];
}

export interface Measurement {
  namespaces: string[];
  namespace: string;
  pods: MeasuredPod[];
  services: MeasuredService[];
}

export type MeasureReply =
  | { ok: true; measurement: Measurement }
  | { ok: false; reason: string }
  | { ok: false; key: "measure.unreadable" };

function strings(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) if (typeof v === "string") out[k] = v;
  }
  return out;
}

export function readMeasureReply(data: unknown): MeasureReply {
  if (typeof data !== "object" || data === null) return { ok: false, key: "measure.unreadable" };
  const rec = data as Record<string, unknown>;
  if (typeof rec.error === "string") return { ok: false, reason: rec.error };
  if (!Array.isArray(rec.namespaces)) return { ok: false, key: "measure.unreadable" };
  const namespaces = rec.namespaces.filter((n): n is string => typeof n === "string");
  // The namespace list alone is a complete answer: it is what the editor asks for before the
  // operator has chosen anything. Treating a missing `pods` as a failure would turn the first,
  // successful call into an error message.
  const pods = Array.isArray(rec.pods) ? rec.pods : [];
  const services = Array.isArray(rec.services) ? rec.services : [];
  return {
    ok: true,
    measurement: {
      namespaces,
      namespace: typeof rec.namespace === "string" ? rec.namespace : "",
      pods: pods.map((raw) => {
        const pod = (raw ?? {}) as Record<string, unknown>;
        const probes = (pod.probes ?? {}) as Record<string, unknown>;
        return {
          name: typeof pod.name === "string" ? pod.name : "",
          labels: strings(pod.labels),
          stable: strings(pod.stable),
          suggested: Array.isArray(pod.suggested) ? pod.suggested.filter((k): k is string => typeof k === "string") : [],
          probes: { readiness: probes.readiness === true, liveness: probes.liveness === true },
          ports: Array.isArray(pod.ports) ? pod.ports.filter((p): p is number => typeof p === "number") : [],
        };
      }),
      services: services.map((raw) => {
        const svc = (raw ?? {}) as Record<string, unknown>;
        return {
          name: typeof svc.name === "string" ? svc.name : "",
          clusterIP: typeof svc.clusterIP === "string" ? svc.clusterIP : null,
          selector: strings(svc.selector),
          ports: Array.isArray(svc.ports)
            ? svc.ports
              .map((p) => (p ?? {}) as Record<string, unknown>)
              .filter((p) => typeof p.port === "number")
              .map((p) => ({ port: p.port as number, protocol: typeof p.protocol === "string" ? p.protocol : "TCP" }))
            : [],
        };
      }),
    },
  };
}

/**
 * The selector string the editor writes into a rule's source or destination.
 *
 * The other half of this lives in `src/kube-read.ts` and the two are deliberately separate: the
 * manager builds one to suggest, the browser rebuilds it every time a checkbox moves, and shipping
 * the string back and forth on each tick would put a network round trip inside a checkbox. What must
 * not drift is the namespace term — first, and never optional, because a selector without it matches
 * by label across every namespace in the cluster. Both sides pin that.
 */
export function selectorText(namespace: string, labels: Record<string, string>, keys: readonly string[]): string {
  const terms = [`k8s:io.kubernetes.pod.namespace=${namespace}`];
  for (const key of [...keys].sort()) {
    const value = labels[key];
    if (value !== undefined) terms.push(`${key}=${value}`);
  }
  return terms.join(",");
}

/** How many labels the manager left out, so the editor can say so rather than silently shrink. */
export function droppedLabelCount(pod: MeasuredPod): number {
  return Math.max(0, Object.keys(pod.labels).length - Object.keys(pod.stable).length);
}

/**
 * Which probes a pod declares, as the words the rule's author needs.
 *
 * A pod with no probe needs no host-allow exemption and one with a probe does. It is the kind of
 * fact that gets carried in somebody's head between a terminal and a rule, and carried wrong.
 */
export function probeWords(pod: MeasuredPod): string[] {
  const out: string[] = [];
  if (pod.probes.readiness) out.push("readiness");
  if (pod.probes.liveness) out.push("liveness");
  return out;
}
