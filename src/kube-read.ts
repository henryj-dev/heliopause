/**
 * What the cluster says a workload is labelled, for the console's rule editor.
 *
 * ## Why this exists
 *
 * A rule's destination is a selector, and a selector is only ever as right as the labels it was
 * written against. Every wrong one this fleet has shipped was written by transcribing a label out of
 * a request document instead of reading it off the pod: the request says what the sender believes,
 * the pod says what Cilium will actually match. The console could not read a pod at all, so the one
 * step that has to be measured was the one step that could only be done at a terminal — and a rule
 * authored in a browser was a rule authored from a transcription.
 *
 * ## Why it is read-only, namespace-listed, and off unless configured
 *
 * The neighbouring grant in `packaging/kubernetes/heliopause-agent-podreader.example.yaml` already
 * paid for this lesson: the agent's applier Role carries `ciliumnetworkpolicies: create`, and binding
 * *that* in a peer namespace would let a credential that only needed to look put CoreDNS into
 * default-deny. So the manager gets the smaller shape — `pods` and `services`, `get`/`list`, in named
 * namespaces, and nothing else — and this module offers no call that could write even if the Role
 * were widened by accident.
 *
 * An empty namespace list leaves the feature off and every route answering 404, which is what a
 * deployment that has not granted anything should look like.
 */
import { readFileSync } from "node:fs";
import { request as httpsRequest } from "node:https";

/** Bounded like the GitHub reader: a reply this large is a bug or an attack, not a namespace. */
const MAX_RESPONSE_BYTES = 4_000_000;

/**
 * A pod list this long is not a namespace anybody is authoring a rule against, and a truncated
 * answer is worse than a refusal — the operator would pick from what fitted and never know the
 * workload they wanted was on the part that did not.
 */
export const MAX_PODS = 200;

export class KubeReadError extends Error {
  readonly status: number | undefined;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "KubeReadError";
    this.status = status;
  }
}

/** The single call this module makes. Injectable so the tests never need an apiserver. */
export type KubeFetcher = (path: string) => Promise<{ status: number; text: string }>;

export interface KubeReadConfig {
  /**
   * The namespaces this console may look in.
   *
   * Listed rather than open even though the credential is read-only, because the RBAC and this list
   * are edited by different people at different times. A namespace that appears in one and not the
   * other should fail as a refusal here, not as a 403 from the apiserver that reads like an outage.
   */
  namespaces: readonly string[];
  /** `https://kubernetes.default.svc` in a cluster; a test server's origin under test. */
  apiUrl: string;
  /**
   * Path to the projected service-account token.
   *
   * A path and not a value. Projected tokens are rotated roughly hourly, and a process that read the
   * token once at boot works perfectly for an hour and then answers 401 forever — a failure that
   * arrives long after the deploy that caused it and looks like a revoked credential.
   */
  tokenFile: string;
  /** The cluster CA. Without it this would be an https connection with no one authenticated at the far end. */
  caFile: string;
  fetch?: KubeFetcher;
}

/**
 * Labels a controller rewrites, which must never end up in a rule.
 *
 * The rollout is the thing to picture. `pod-template-hash` is correct at the moment it is copied and
 * wrong the next time the Deployment is rolled, and the rule that carried it does not fail loudly —
 * it silently matches nothing, which is a policy that allows nothing and complains to no one. The
 * same applies to a StatefulSet's revision hash and to the per-pod name and index, which identify
 * one replica out of several.
 */
export const VOLATILE_LABELS: ReadonlySet<string> = new Set([
  "pod-template-hash",
  "controller-revision-hash",
  "statefulset.kubernetes.io/pod-name",
  "apps.kubernetes.io/pod-index",
  "batch.kubernetes.io/job-name",
  "batch.kubernetes.io/controller-uid",
  "job-name",
  "controller-uid",
]);

export interface MeasuredPod {
  name: string;
  /** Everything the pod carries, so an operator can see what was left out as well as what was taken. */
  labels: Record<string, string>;
  /** `labels` minus `VOLATILE_LABELS` — the half that survives a rollout. */
  stable: Record<string, string>;
  /**
   * The keys `suggestedLabelKeys` would tick.
   *
   * Computed here rather than in the browser so the heuristic has one home. The console offers the
   * rest of `stable` beside these as checkboxes, so a suggestion is a starting point the operator
   * edits and never a decision made for them.
   */
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
  namespace: string;
  pods: MeasuredPod[];
  services: MeasuredService[];
}

/** Strip the labels that belong to a replica rather than to the workload. */
export function stableLabels(labels: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(labels)) if (!VOLATILE_LABELS.has(k)) out[k] = v;
  return out;
}

/**
 * The labels a destination selector should be pinned on, given what the pod actually carries.
 *
 * Two kinds, and the second is the one that gets forgotten. The **name** label is what a reader
 * recognises the workload by. The **identity** label is what stops the rule being inherited: a
 * database called `test` is deleted and a different database called `test` is created next week, and
 * a grant written against the name alone follows the name to a workload nobody granted anything to.
 * Request 191 established that and recorded it in a note; a note is not a check, and this is the
 * closest a rule editor can come to one — the identity label is offered by default, so leaving it
 * out becomes a decision somebody made rather than one they never saw.
 *
 * A key ending in `-id` or `/id` is the shape every identity label in this fleet has taken
 * (`stardust.io/database-id`). Heuristic, and deliberately visible: the console shows the remaining
 * labels beside it so the operator can add what this did not guess.
 */
export function suggestedLabelKeys(labels: Record<string, string>): string[] {
  const keys = Object.keys(stableLabels(labels));
  const named = keys.filter((k) => ["app.kubernetes.io/name", "app", "k8s-app"].includes(k));
  const identity = keys.filter((k) => k.endsWith("-id") || k.endsWith("/id"));
  return [...new Set([...named, ...identity])].sort();
}

/**
 * The `k8s:`-prefixed selector string the rule editor writes into a destination.
 *
 * The namespace term is always first and never optional. A selector without it matches by label
 * across every namespace in the cluster, which for a label as ordinary as `app=hub` is a grant
 * nobody intended and nobody would see in the diff.
 */
export function selectorText(namespace: string, labels: Record<string, string>, keys: readonly string[]): string {
  const terms = [`k8s:io.kubernetes.pod.namespace=${namespace}`];
  for (const key of [...keys].sort()) {
    const value = labels[key];
    if (value !== undefined) terms.push(`${key}=${value}`);
  }
  return terms.join(",");
}

function liveFetcher(config: KubeReadConfig): KubeFetcher {
  const ca = readFileSync(config.caFile);
  return (path) =>
    new Promise((resolve, reject) => {
      // Re-read per call. See `tokenFile`.
      let token: string;
      try {
        token = readFileSync(config.tokenFile, "utf8").trim();
      } catch (e) {
        return reject(new KubeReadError(`cannot read the service account token: ${(e as Error).message}`));
      }
      const req = httpsRequest(
        `${config.apiUrl}${path}`,
        { method: "GET", ca, headers: { authorization: `Bearer ${token}`, accept: "application/json" } },
        (res) => {
          let size = 0;
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => {
            size += chunk.length;
            if (size > MAX_RESPONSE_BYTES) {
              req.destroy();
              return reject(new KubeReadError(`${path} answered more than ${MAX_RESPONSE_BYTES} bytes`));
            }
            chunks.push(chunk);
          });
          res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }));
        },
      );
      req.on("error", (e) => reject(new KubeReadError(e.message)));
      req.end();
    });
}

async function get(config: KubeReadConfig, path: string): Promise<unknown> {
  const call = config.fetch ?? liveFetcher(config);
  const res = await call(path);
  if (res.status < 200 || res.status >= 300) {
    // The apiserver's own sentence. A 403 here means the RoleBinding is missing or names another
    // namespace, and "forbidden" with the namespace in it is the difference between fixing that in a
    // minute and reading the console's source to find out what it asked for.
    throw new KubeReadError(`${path} → ${res.status}: ${res.text.slice(0, 300)}`, res.status);
  }
  try {
    return JSON.parse(res.text);
  } catch {
    throw new KubeReadError(`${path} did not answer JSON`);
  }
}

function labelsOf(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (typeof v === "string") out[k] = v;
    }
  }
  return out;
}

/** Everything in one namespace that a destination selector could name. */
export async function measureNamespace(config: KubeReadConfig, namespace: string): Promise<Measurement> {
  if (!config.namespaces.includes(namespace)) {
    throw new KubeReadError(`this console may only look in: ${config.namespaces.join(", ") || "(nothing)"}`, 403);
  }
  const ns = encodeURIComponent(namespace);
  const podList = (await get(config, `/api/v1/namespaces/${ns}/pods?limit=${MAX_PODS + 1}`)) as {
    items?: Array<{
      metadata?: { name?: string; labels?: unknown };
      spec?: {
        containers?: Array<{
          readinessProbe?: unknown;
          livenessProbe?: unknown;
          ports?: Array<{ containerPort?: number }>;
        }>;
      };
    }>;
    metadata?: { continue?: string };
  };
  const items = podList.items ?? [];
  if (items.length > MAX_PODS || (podList.metadata?.continue ?? "") !== "") {
    throw new KubeReadError(`${namespace} has more than ${MAX_PODS} pods — too many to choose from here`);
  }
  const pods: MeasuredPod[] = [];
  for (const item of items) {
    const name = item.metadata?.name;
    if (typeof name !== "string") throw new KubeReadError(`${namespace} returned a pod with no name`);
    const containers = item.spec?.containers ?? [];
    const labels = labelsOf(item.metadata?.labels);
    pods.push({
      name,
      labels,
      stable: stableLabels(labels),
      suggested: suggestedLabelKeys(labels),
      probes: {
        readiness: containers.some((c) => c.readinessProbe != null),
        liveness: containers.some((c) => c.livenessProbe != null),
      },
      ports: [
        ...new Set(
          containers.flatMap((c) => (c.ports ?? []).map((p) => p.containerPort)).filter(
            (p): p is number => typeof p === "number",
          ),
        ),
      ].sort((a, b) => a - b),
    });
  }

  const svcList = (await get(config, `/api/v1/namespaces/${ns}/services?limit=${MAX_PODS + 1}`)) as {
    items?: Array<{
      metadata?: { name?: string };
      spec?: {
        clusterIP?: string;
        selector?: unknown;
        ports?: Array<{ port?: number; protocol?: string }>;
      };
    }>;
  };
  const services: MeasuredService[] = [];
  for (const item of svcList.items ?? []) {
    const name = item.metadata?.name;
    if (typeof name !== "string") throw new KubeReadError(`${namespace} returned a service with no name`);
    const ip = item.spec?.clusterIP;
    services.push({
      name,
      // `None` is a headless service. Reporting it as an address would put a string that is not an
      // address in front of somebody about to write one down.
      clusterIP: typeof ip === "string" && ip !== "None" && ip !== "" ? ip : null,
      selector: labelsOf(item.spec?.selector),
      ports: (item.spec?.ports ?? [])
        .filter((p): p is { port: number; protocol?: string } => typeof p.port === "number")
        .map((p) => ({ port: p.port, protocol: typeof p.protocol === "string" ? p.protocol : "TCP" })),
    });
  }

  return { namespace, pods, services };
}

/**
 * Read the console's namespace allowlist out of the environment.
 *
 * Unset and empty are the same answer — the feature is off — and both are spelled as an empty list
 * rather than as a thrown error, because a manager that has not been granted anything must still
 * start and serve every other route.
 */
export function measureNamespaces(env: NodeJS.ProcessEnv): string[] {
  return (env.HELIOPAUSE_K8S_MEASURE_NAMESPACES ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}
