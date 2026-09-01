// Renders policies into CiliumNetworkPolicy objects. Pure — no I/O, no kube client.
//
// ── Why this layer exists at all ──────────────────────────────────────────────
// A k3s node runs two independent datapaths, and nftables only sees one of them. Pod traffic is
// handled in eBPF and never traverses netfilter (V15: conntrack entries for the pod CIDR, zero).
// V31 measured the same fact from the other side and is the reason this file exists now: after
// default-deny landed on dev, k3s-01's public 443 was still answering. A counting chain at priority
// −250 showed **0 packets while external connections succeeded**, and there was no listener.
// `cilium-dbg service list` gave the answer — `10.17.192.1:443 → 10.17.0.10:6443` is a ClusterIP
// resolved in BPF, so the packet never reaches a netfilter hook. **That port is not something
// nftables can close.** No amount of host-layer policy reaches it.
//
// So the two renderers are not alternatives to pick between. They cover different traffic, and each
// is blind to the other's. `nft.ts` renders the host datapath; this renders the pod datapath.
//
// ── What is deliberately the same as nft.ts ───────────────────────────────────
// Two-step: `planCiliumPolicies` decides (which policies render, which are skipped and why, what
// warnings an operator has to see), and a dumb emitter turns the plan into CRD objects. Same reason
// as the host layer — a preview that disagrees with what is applied is the worst failure a firewall
// tool has, and two independent emitters drift into exactly that.
//
// `CiliumRenderError` versus `Skipped` carries the same weight it does in `nft.ts`, and here it is
// sharper: a skipped destination policy is not merely an open port, it is an open port that the host
// layer **cannot** compensate for. Under a `default-deny` host config an unrenderable host rule at
// least leaves the chain policy behind it. There is no chain policy behind this one.
//
// ── What is deliberately different ────────────────────────────────────────────
//   · **IPv4 only.** Cilium runs with `enable-ipv6 = false`, so pods have no IPv6 address at all.
//     An IPv6 condition on a workload policy is not narrowed here, it is unenforceable — so it
//     warns rather than rendering something that looks like coverage (evaluation rule 6).
//   · **Cluster-scoped, not per-host.** One CRD set for the cluster, applied by the single node
//     named in `k8sApplier` (H17). Three agents writing the same CRD would contend over one object.
//   · **Selectors, not addresses.** Pod addresses are short-lived; the identity is the selector.
import {
  K8S_KINDS,
  isWorkload,
  isPortsRef,
  type Endpoint,
  type Policy,
  type PolicyAction,
} from "./policy.ts";
import type { SelectorMembership, WatchSelectors } from "./protocol.ts";

// ── Cluster facts the renderer is given ───────────────────────────────────────

/**
 * A Service's namespace, name and the selector it publishes.
 *
 * Injected rather than discovered, exactly like `ResolveCidrs`: heliopause has no inventory. The
 * agent reports the mapping in its heartbeat and the manager renders from it (H14a), so the renderer
 * stays pure and the kube client stays in one place.
 */
export interface ServiceSelector {
  namespace: string;
  name: string;
  /** `spec.selector`. Empty is refused — see `assertServiceUsable`. */
  selector: Record<string, string>;
  /**
   * Pods currently matched by that selector, as `namespace/name`.
   *
   * Reported so the render can *show* who a policy will actually hit. A pod behind two Services is
   * covered by the union of both policies, which is wider than either one reads, and the pod list is
   * the only place that becomes visible (workload-layer design, 주의).
   */
  pods?: string[];
}

/** Resolves `namespace/name` to that Service's selector. Returns null when it is not known. */
export type ResolveService = (ref: string) => ServiceSelector | null;

/**
 * Resolves a selector to the pods it currently matches, as `namespace/name`.
 *
 * **`null` and `[]` are different answers.** `null` is "not known" — nobody reported this selector,
 * or the cluster could not be queried. `[]` is "queried, and it matches nothing", which is a real and
 * temporary state: `arc-runners` holds zero pods between CI jobs and fills the moment work arrives.
 * A caller that treats them alike will read an unreported selector as a harmless policy.
 */
export type ResolvePods = (kind: "k8s-namespace" | "k8s-label", value: string) => string[] | null;

export interface CiliumRenderInput {
  /**
   * Host id of the node that applies these CRDs (H17).
   *
   * Not optional and not defaulted. CiliumNetworkPolicy is cluster-scoped, so "whichever node gets
   * there first" means three agents writing one object — declarative convergence, but with API
   * contention and flapping. Absent, the render is refused rather than assigned a guess.
   */
  k8sApplier: string;
  /** Cluster identifier, used in CRD names so two clusters' policies never collide. */
  cluster: string;
  /** Published generation, stamped on every object so rollback cannot act on a replacement. */
  generation: string;
  resolveService?: ResolveService;
  /**
   * Which pods a selector currently matches (H14a). Injected, because the renderer is pure.
   *
   * Absent, or returning `null`, means "not known" — and the render says so rather than showing an
   * empty list, which reads as "this policy selects nothing".
   */
  resolvePods?: ResolvePods;
  /**
   * Cilium's minor version, as `[major, minor]` — e.g. `[1, 17]`. Required, not defaulted.
   *
   * One rendering decision depends on it. Cilium rejects `toServices` combined with `toPorts` before
   * 1.17: `EgressCommonRule.l3DependentL4Support()` lists `ToServices: false` through 1.16.x
   * (upstream issue 20067) and `true` from 1.17.0, and `sanitize()` returns
   * `"combining ToServices and ToPorts is not supported yet"` when the two meet. The same gate covers
   * `egress` and `egressDeny` — there is no deny-specific carve-out.
   *
   * That combination is the primary case on this cluster (a CI runner reaching a Service on one port),
   * so guessing is not viable in either direction. Guess high and the CRD is rejected at apply, where
   * the error no longer names the policy. Guess low and every such rule silently loses its port
   * condition. Neither is a default worth having, so the caller states the version.
   */
  ciliumVersion: readonly [number, number];
  /**
   * Label put on every rendered object so flux can be told to leave them alone.
   *
   * flux is the cluster's source of truth; without an exclusion it prunes anything it does not
   * find in git, which here means deleting the network policy while reporting a successful
   * reconcile. Coordinating the two is required under any structure (flux와의 조율).
   */
  managedByLabel?: string;
}

export const DEFAULT_MANAGED_BY = "heliopause";
/** Not a Kubernetes-valid namespace: the baseline ingress rule can never whitelist a pod. */
export const BASELINE_NEVER_NAMESPACE = "HELI0PAUSE-NEVER";
/** Independent matching bound in the agent; crossing it refuses publish before a host sees it. */
export const MAX_WATCH_SELECTORS = 32;

// ── Output shape ──────────────────────────────────────────────────────────────

/** `matchLabels` — equality only, which is all Cilium's own `EndpointSelector` expresses. */
export type MatchLabels = Record<string, string>;

/**
 * One `EndpointSelector` item. The `matchLabels` wrapper is not decoration.
 *
 * The CRD is `apiextensions.k8s.io/v1` with a structural schema and no
 * `x-kubernetes-preserve-unknown-fields`, so an item declares exactly `matchLabels` and
 * `matchExpressions`. A bare label map here is a set of *unknown* fields: the API server either
 * rejects it under strict field validation or **prunes every key**, leaving `{}`. Cilium does not
 * then complain — an empty selector validates — but an empty `EndpointSelector` is a **wildcard**,
 * and `getEndpointSelector` fills in the policy's own namespace label. The item that meant
 * "pods labelled `app=idp` in `util`" becomes "every pod in this policy's namespace": wrong target,
 * broader match, clean apply.
 */
export interface EndpointSelector {
  matchLabels: MatchLabels;
}

export interface CiliumPortRule {
  /** Decimal, as text. Cilium's schema takes a string here even though it is a number. */
  port: string;
  /** Present only for a range; Cilium reads `port`..`endPort` inclusive. */
  endPort?: number;
  protocol: "TCP" | "UDP" | "ANY";
}

export interface CiliumIngressRule {
  fromEndpoints?: EndpointSelector[];
  /** `0.0.0.0/0` and the like — an address source reaching a pod destination. */
  fromCIDR?: string[];
  fromEntities?: string[];
  toPorts?: Array<{ ports: CiliumPortRule[] }>;
}

export interface CiliumEgressRule {
  toEndpoints?: EndpointSelector[];
  toCIDR?: string[];
  toEntities?: string[];
  /** Native Service reference — no selector resolution needed in this direction. */
  toServices?: Array<{ k8sService: { serviceName: string; namespace: string } }>;
  toPorts?: Array<{ ports: CiliumPortRule[] }>;
}

/**
 * A deny rule. Same fields as the allow forms, in `ingressDeny`/`egressDeny`.
 *
 * Cilium evaluates deny **before** every allow and it cannot be overridden by a later rule. That is
 * a stronger guarantee than the host layer's first-match ordering, and it means the host layer's
 * trick of "narrow deny before broad allow" is unnecessary here — but also that the reverse,
 * "broad deny with a narrow allow carved out", is impossible. A deny and an allow that overlap
 * resolve to deny, always.
 *
 * `toPorts` is the one asymmetry worth noting: a deny with no port condition denies **all** ports to
 * the selected endpoints, so an over-broad port spec is much more expensive on a deny than an allow.
 */
export type CiliumIngressDenyRule = CiliumIngressRule;
export type CiliumEgressDenyRule = CiliumEgressRule;

/**
 * Either deny form. Kept as a union rather than an intersection so a rule cannot carry `fromCIDR`
 * and `toCIDR` at once — an intersection type-checks that, and the field names are the only thing
 * distinguishing the two directions.
 */
export type CiliumDenyRule = CiliumIngressDenyRule | CiliumEgressDenyRule;

/**
 * `spec.enableDefaultDeny` for one policy. **This is the difference between containment and outage.**
 *
 * ## What goes wrong without it
 *
 * A pod that no policy selects allows everything (`enable-policy: default`). The moment any policy
 * selects it, Cilium switches that endpoint to default-deny **for that direction** — and a deny-only
 * rule counts as selecting it. `Sanitize()` decides with
 * `len(r.Egress) > 0 || len(r.EgressDeny) > 0`, so `egressDeny` alone flips the switch, and
 * `computePolicyEnforcementAndRules` then declines to synthesise an allow-all.
 *
 * With no allow rules present that means **all egress dropped**. A policy written as "stop the CI
 * runners reaching the identity provider" silently becomes "the CI runners reach nothing" — they
 * cannot resolve DNS, cannot pull an image, cannot reach GitHub. That is not a narrower rule than
 * intended, which is the failure mode the rest of this file guards against; it is a different and
 * larger rule, and it takes the workload down.
 *
 * So a deny gets `false` for its direction: keep the endpoint's existing posture and subtract the
 * denied peer from it. Cilium inserts the implicit allow-all, the deny carves out of it, and the
 * result is what the policy says.
 *
 * ## Why an allow gets `true`
 *
 * An allow is a statement about what is permitted, and it is only meaningful if everything else is
 * refused — `true` is both Cilium's default and what the policy means. Written out anyway rather
 * than omitted, because the two cases must be visibly different in the rendered object: an operator
 * reading a diff should see which policies close the endpoint and which do not, without having to
 * remember that the absent field means "closed".
 *
 * ## The aggregation trap
 *
 * "If multiple policies apply to an endpoint, that endpoint's default deny will be enabled if any
 * policy requests it." So one allow policy selecting these pods puts them in default-deny no matter
 * what every deny policy asks for — which is correct and is also why a deny cannot be read in
 * isolation. `planCiliumPolicies` warns when both kinds land on one selector.
 *
 * Verified against `pkg/policy/api/rule.go`, `pkg/policy/api/rule_validation.go` and
 * `pkg/policy/repository.go` at tag v1.18.1; the field arrived in 1.16.0 and is gated by the agent
 * flag `enable-non-default-deny-policies`, which defaults to true and is `true` on this cluster.
 */
/**
 * **Ingress only, deliberately.** An egress allow always renders `{ egress: false }` — see the
 * comment at that call site. Passing a direction here at all invited the mistake this signature now
 * makes impossible: an allow's default-deny closes the *selected* pods, which is the intent when
 * they are the destination and an outage when they are the sender.
 */
function defaultDenyFor(action: PolicyAction): { ingress: boolean } {
  return { ingress: action === "allow" };
}

/**
 * One CiliumNetworkPolicy object, ready to serialise.
 *
 * `spec.endpointSelector` names the pods the policy is *about*; `ingress`/`egress` name the other
 * end. That is a different shape from the host layer, where a rule states both ends symmetrically —
 * so which side of the policy becomes the selector depends on direction, and getting it backwards
 * produces a valid CRD that guards the wrong pods.
 */
export interface CiliumNetworkPolicy {
  apiVersion: "cilium.io/v2";
  kind: "CiliumNetworkPolicy";
  metadata: {
    name: string;
    namespace: string;
    labels: Record<string, string>;
    annotations: Record<string, string>;
  };
  spec: {
    description: string;
    endpointSelector: { matchLabels: MatchLabels };
    /**
     * Whether this policy puts the selected endpoints into default-deny, per direction.
     *
     * Emitted on every object rather than only where it changes the outcome, because the default is
     * the dangerous one and a reader should not have to know that. See `defaultDenyFor`.
     */
    enableDefaultDeny: { ingress?: boolean; egress?: boolean };
    ingress?: CiliumIngressRule[];
    egress?: CiliumEgressRule[];
    ingressDeny?: CiliumIngressDenyRule[];
    egressDeny?: CiliumEgressDenyRule[];
  };
}

export interface CiliumSkipped {
  policyId: string;
  name: string;
  reason: string;
}

/**
 * Something an operator has to read before believing the policy does what it says.
 *
 * Separate from `CiliumSkipped` because the rule **did** render. A skip says "this produced
 * nothing"; a warning says "this produced something narrower than you wrote". Folding them together
 * would let a v6 condition that cannot be enforced read as a clean render.
 */
export interface CiliumWarning {
  policyId: string;
  name: string;
  warning: string;
}

export interface CiliumPlan {
  cluster: string;
  /** Host id responsible for applying these. Every other node reads and ignores them. */
  applier: string;
  policies: CiliumNetworkPolicy[];
  skipped: CiliumSkipped[];
  warnings: CiliumWarning[];
  /**
   * Pods each rendered policy selects, keyed by policy id — **where they are known**.
   *
   * The render result has to show this rather than only the selector. A pod sitting behind two
   * Services is covered by the union of both policies, which is broader than reading either one
   * suggests, and the pod list is where that becomes visible.
   *
   * Only the `k8s-service` kind populates it today, because `ServiceSelector.pods` is the sole
   * injected pod source — `k8s-namespace` and `k8s-label` always yield `[]`. So an empty list means
   * "not known", never "no pods", and the union check above is **not** available for the namespace
   * and label kinds. That is the gap H14a's heartbeat mapping closes; until it lands, the case the
   * design calls the highest-risk (`arc-runners`, which holds zero pods between CI jobs and fills up
   * the moment work arrives) is exactly the one this cannot show.
   */
  affectedPods: Record<string, string[] | null>;
}

/**
 * The renderer was handed input it cannot turn into a policy.
 *
 * Same distinction from `CiliumSkipped` that `RenderError` has from `Skipped` in `nft.ts`, and it
 * bites harder here. A workload destination has no fallback layer: if this refuses to render and the
 * caller treats that as "nothing to do", the traffic is not merely governed by a chain policy
 * somewhere else — it is ungoverned, because netfilter cannot see it.
 */
export class CiliumRenderError extends Error {
  readonly statusCode = 500;
}

// ── Selector construction ─────────────────────────────────────────────────────

/**
 * Cilium's own namespace label. Also `k8s:io.kubernetes.pod.namespace` in `cilium-dbg` output.
 *
 * `matchLabels` in a CNF spec is namespace-scoped by default, so this is only needed when a rule
 * reaches *across* namespaces — which the `k8s-namespace` and `k8s-label` kinds routinely do.
 */
const NS_LABEL = "k8s:io.kubernetes.pod.namespace";

/**
 * Parse `a=1,b=2` into `matchLabels`.
 *
 * Two refusals, both for input that `normalizePolicy` would have caught — re-checked here because the
 * renderer is exported and takes a `Policy` struct, so one rebuilt from stored JSON has not been
 * normalised.
 *
 * A term with no `=` is refused rather than parsed. `indexOf` returns -1, and `slice(0, -1)` then
 * truncates the last character into a key: `"app"` becomes `{ap: "app"}`, a selector that is valid,
 * renders, and matches nothing.
 *
 * A repeated key with two values is refused rather than collapsed. `normalizePolicy` dedupes whole
 * terms, so `app=a,app=b` survives it as two distinct terms; building the object would then let the
 * last one win. `matchLabels` is an AND, so the operator wrote something unsatisfiable — and rather
 * than an empty result they would get a policy governing a real pod set they never named.
 */
function labelsFromSelector(value: string, at: string): MatchLabels {
  const out: MatchLabels = {};
  for (const part of value.split(",").map((x) => x.trim()).filter(Boolean)) {
    const eq = part.indexOf("=");
    if (eq <= 0) {
      throw new CiliumRenderError(
        `${at}: selector term ${JSON.stringify(part)} is not key=value — matchLabels has no form for ` +
          `a bare term, and parsing it anyway would build a key that matches no pod.`,
      );
    }
    const key = part.slice(0, eq);
    const val = part.slice(eq + 1);
    const prev = out[key];
    if (prev !== undefined && prev !== val) {
      throw new CiliumRenderError(
        `${at}: selector sets ${JSON.stringify(key)} to both ${JSON.stringify(prev)} and ` +
          `${JSON.stringify(val)} — matchLabels is an AND, so no pod can satisfy both. Rendering it ` +
          `would silently keep one and aim the rule at pods you did not name.`,
      );
    }
    out[key] = val;
  }
  return out;
}

function assertServiceUsable(sel: ServiceSelector, ref: string, at: string): void {
  if (Object.keys(sel.selector).length === 0) {
    // A Service with no selector has externally-managed endpoints (a manual `Endpoints` object, or
    // an ExternalName). There are no pods to put in an `endpointSelector`, so an empty one would be
    // emitted — and an empty selector in Cilium matches **every endpoint in the namespace**. The
    // rule would silently govern far more than the Service.
    throw new CiliumRenderError(
      `${at}: Service ${JSON.stringify(ref)} publishes no selector — its endpoints are managed ` +
        `outside Kubernetes, so there are no pods to select. An empty selector would match the ` +
        `whole namespace.`,
    );
  }
}

/**
 * Can this Cilium express `toServices` and `toPorts` in one rule?
 *
 * False through 1.16.x, true from 1.17.0. See `ciliumVersion` for the upstream mechanism.
 */
function supportsServicePorts([major, minor]: readonly [number, number]): boolean {
  return major > 1 || (major === 1 && minor >= 17);
}

/**
 * The Service a `toServices` reference names, or a refusal.
 *
 * For the `toServices` direction, where Cilium resolves the name itself and the selector is never
 * needed. Existence still has to be checked here rather than left to the cluster: Cilium does not
 * reject a `toServices` naming a Service that is not there, it resolves it to an empty backend set.
 * An allow then opens nothing and a deny denies nothing, both reporting a clean apply.
 *
 * Returns the resolved Service rather than just asserting, so the caller can build `k8sService` from
 * `namespace`/`name` fields the resolver vouches for. Splitting `ref` on `/` instead would put the
 * caller's unvalidated string in the CRD: a value with no slash yields `serviceName: undefined`,
 * which `JSON.stringify` drops and Cilium's `omitempty` accepts, leaving a Service reference with no
 * name.
 */
function resolveServiceRef(ref: string, input: CiliumRenderInput, at: string): ServiceSelector {
  const resolved = input.resolveService?.(ref) ?? null;
  if (!resolved) {
    throw new CiliumRenderError(
      `${at}: Service ${JSON.stringify(ref)} did not resolve — the agent has not reported it, or it ` +
        `does not exist. Cilium resolves an unknown toServices reference to no backends rather than ` +
        `failing, so this is refused rather than rendered.`,
    );
  }
  if (!resolved.namespace || !resolved.name) {
    throw new CiliumRenderError(
      `${at}: the resolver returned a Service for ${JSON.stringify(ref)} with no ` +
        `${!resolved.name ? "name" : "namespace"} — a toServices entry missing either field is ` +
        `dropped on serialisation and references nothing.`,
    );
  }
  return resolved;
}

/**
 * The `endpointSelector` for a workload endpoint — the pods the policy is *about*.
 *
 * Called for whichever side of the policy is the workload. `k8s-service` goes through the resolver
 * because a Service is a name plus a selector, and only the cluster knows the second half.
 */
function endpointSelectorFor(
  e: Endpoint,
  side: "source" | "destination",
  input: CiliumRenderInput,
  at: string,
  // `pods` is `null` for "not known", never `[]`. A namespace nobody reported and a namespace that
  // genuinely holds no pods are different facts, and only one of them means the policy is inert.
): { labels: MatchLabels; pods: string[] | null } {
  switch (e.kind) {
    case "k8s-namespace":
      return {
        labels: { [NS_LABEL]: e.value },
        pods: input.resolvePods?.("k8s-namespace", e.value) ?? null,
      };
    case "k8s-label":
      return {
        labels: labelsFromSelector(e.value, at),
        pods: input.resolvePods?.("k8s-label", e.value) ?? null,
      };
    case "k8s-service": {
      // `normalizePolicy` already refuses this, but the renderer is exported and takes a `Policy`
      // struct directly — one rebuilt from stored JSON has not been through normalisation. Left
      // unchecked, this resolves the Service and renders a policy selecting the pods behind it: a
      // clean-looking rule built on the guess rule 8 forbids. `nft.ts` re-checks ports for the same
      // reason.
      if (side === "source") {
        throw new CiliumRenderError(
          `${at}: k8s-service cannot be a source — traffic comes from the pods behind a Service, ` +
            `not from the Service. Selecting those pods would be a guess about which senders were ` +
            `meant. Name them with k8s-namespace or k8s-label.`,
        );
      }
      const resolved = input.resolveService?.(e.value) ?? null;
      if (!resolved) {
        // Not a skip. The policy names a destination this layer is solely responsible for, so
        // producing no rule leaves that traffic unenforced with nothing behind it.
        throw new CiliumRenderError(
          `${at}: Service ${JSON.stringify(e.value)} did not resolve to a selector — the agent has ` +
            `not reported it, or it does not exist. A destination on this layer has no fallback ` +
            `renderer, so this is refused rather than skipped.`,
        );
      }
      assertServiceUsable(resolved, e.value, at);
      const labels: MatchLabels = { ...resolved.selector };
      // The Service's own namespace has to be pinned. Its selector is often something as generic as
      // `app=postgres`, which without this would match a pod carrying that label in any namespace.
      labels[NS_LABEL] = resolved.namespace;
      return { labels, pods: resolved.pods ?? [] };
    }
    default:
      throw new CiliumRenderError(`${at}: ${e.kind} is not a workload endpoint`);
  }
}

// ── Ports ─────────────────────────────────────────────────────────────────────

function ciliumProto(p: Policy): "TCP" | "UDP" | "ANY" {
  if (p.proto === "tcp") return "TCP";
  if (p.proto === "udp") return "UDP";
  return "ANY";
}

/**
 * `toPorts` for a policy that names a protocol but no ports — the `meta l4proto tcp` equivalent.
 *
 * Omitting `toPorts` entirely is **not** the same thing. An L3-only Cilium rule carries no protocol
 * condition at all, so `proto: tcp` with no ports would render as every protocol, and the same policy
 * row would mean TCP on the host layer and anything here.
 *
 * `port: "0"` is the wildcard. `PortProtocol.sanitize` accepts it (`isZero`), `createL4Filter` builds
 * `Port=0` while carrying `Protocol` through unchanged, and `toMapState` treats port 0 as
 * `isWildcardPort` on a key that still embeds the protocol. `endPort` is deliberately omitted:
 * `keysForRange` returns early when `port == 0` and ignores `endPort`, so `endPort: 65535` would be a
 * no-op that reads like a meaningful bound. (Verified in `pkg/policy/api/rule_validation.go` and
 * `pkg/policy/l4.go`; port 0 is refused only for L7 and DNS rules, neither of which this emits.)
 */
function protocolOnlyPorts(p: Policy): Array<{ ports: CiliumPortRule[] }> {
  return [{ ports: [{ port: "0", protocol: ciliumProto(p) }] }];
}

function portRules(p: Policy, at: string): Array<{ ports: CiliumPortRule[] }> {
  if (isPortsRef(p.ports)) {
    // Same hazard as in `nft.ts`: an unresolved `@web` is not a syntax error anywhere downstream,
    // it is a string that lands in the CRD and matches nothing.
    throw new CiliumRenderError(
      `${at}: unresolved service-object reference ${JSON.stringify(p.ports)} — ` +
        `the resolver did not run, or did not know this object`,
    );
  }
  if (!p.ports) {
    // `any` with no ports genuinely is an L3 rule — nothing is being restricted, so emitting a
    // wildcard `toPorts` would add a field without adding a condition. `icmp` has no port form at all
    // (Cilium matches ICMP in a separate field this renderer does not emit), and rendering it as
    // `protocol: ANY` would claim a restriction that is not there.
    if (p.proto === "any" || p.proto === "icmp") return [];
    return protocolOnlyPorts(p);
  }

  const protocol = ciliumProto(p);
  const ports: CiliumPortRule[] = [];
  for (const entry of p.ports.split(",").map((x) => x.trim()).filter(Boolean)) {
    const m = /^(\d{1,5})(?::(\d{1,5}))?$/.exec(entry);
    if (!m) throw new CiliumRenderError(`${at}: ${JSON.stringify(entry)} is not a port or port range`);
    const lo = Number(m[1]);
    const hi = m[2] === undefined ? lo : Number(m[2]);
    if (lo < 1 || hi > 65535) throw new CiliumRenderError(`${at}: port ${JSON.stringify(entry)} is outside 1-65535`);
    if (hi < lo) throw new CiliumRenderError(`${at}: port range ${JSON.stringify(entry)} runs backwards`);
    ports.push(hi === lo ? { port: String(lo), protocol } : { port: String(lo), endPort: hi, protocol });
  }
  return [{ ports }];
}

// ── Address endpoints on the other side ───────────────────────────────────────

/** Is this an IPv6 CIDR or address? Used to warn, not to filter — see `enable-ipv6 = false`. */
function isV6(cidr: string): boolean {
  return cidr.includes(":");
}

/**
 * What goes in `fromCIDR`/`toCIDR`/`*Entities` for the non-workload side.
 *
 * `internet` becomes the `world` entity rather than `0.0.0.0/0`: Cilium's `world` means "outside the
 * cluster's known identities", which is what the policy says, whereas `0.0.0.0/0` also covers pods
 * and would make an internet rule match in-cluster traffic.
 */
function otherSide(
  e: Endpoint,
  cidrs: string[],
  at: string,
): { cidr: string[]; entities: string[]; v6: string[] } {
  if (e.kind === "any") return { cidr: [], entities: ["all"], v6: [] };
  if (e.kind === "internet") return { cidr: [], entities: ["world"], v6: [] };
  if (e.kind === "k8s-entity") {
    if (e.value !== "host") {
      throw new CiliumRenderError(`${at}: unsupported Cilium entity ${JSON.stringify(e.value)}`);
    }
    return { cidr: [], entities: ["host"], v6: [] };
  }

  if (cidrs.length === 0) {
    throw new CiliumRenderError(
      `${at}: ${e.kind} ${JSON.stringify(e.value)} resolved to no addresses — a rule with no ` +
        `address condition would match every peer`,
    );
  }
  // v6 entries are kept out of the CRD and reported instead. Emitting them would produce a rule
  // Cilium accepts and can never match, which reads on review as coverage that does not exist.
  const v6 = cidrs.filter(isV6);
  const v4 = cidrs.filter((c) => !isV6(c));
  if (v4.length === 0) {
    // Every resolved address was IPv6. Nothing is left to match on, and a rule with no address
    // condition matches *every* peer rather than none — the inversion that makes this fatal instead
    // of a warning.
    throw new CiliumRenderError(
      `${at}: every resolved address is IPv6 (${v6.join(", ")}) and this cluster runs Cilium with ` +
        `enable-ipv6 = false, so pods have no IPv6 address. No condition is left to render, and an ` +
        `empty one would match all peers.`,
    );
  }
  return { cidr: v4, entities: [], v6 };
}

/** The IPv6 half of a mixed-family endpoint is dropped from the CRD. Say so, per side. */
function v6Warning(side: "source" | "destination", v6: string[]): string {
  const what =
    side === "source"
      ? "so pods have no IPv6 address and these cannot be enforced"
      : "so pods cannot originate IPv6 traffic and these cannot be enforced";
  return (
    `${side} has IPv6 addresses (${v6.join(", ")}) that are not rendered — this cluster runs Cilium ` +
    `with enable-ipv6 = false, ${what}. This policy covers IPv4 only.`
  );
}

// ── Naming ────────────────────────────────────────────────────────────────────

/** DNS-1123 name for the CRD, derived from cluster and policy id so it is stable across renders. */
function crdName(cluster: string, policyId: string, suffix = ""): string {
  const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "");
  const name = `hp-${slug(cluster)}-${slug(policyId)}${suffix}`;
  // The renderer emits one DNS label (no dots), so Kubernetes' per-label 63-byte limit applies.
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(name)) {
    throw new CiliumRenderError(
      `cannot build a DNS-1123 object name from cluster ${JSON.stringify(cluster)} and policy ` +
        `${JSON.stringify(policyId)} — got ${JSON.stringify(name)}`,
    );
  }
  return name;
}

/**
 * The namespace `metadata.namespace` gets, checked as a DNS-1123 label.
 *
 * It comes from a label *value*, and a label value is a laxer alphabet than a namespace name —
 * uppercase and `_` are legal in one and not the other. Without this, `...namespace=Util_Prod`
 * renders an object the API server rejects at apply. Failing at render says which policy and which
 * selector; failing at apply says only that some object was malformed.
 */
function assertNamespace(ns: string, at: string): void {
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(ns)) {
    throw new CiliumRenderError(
      `${at}: ${JSON.stringify(ns)} is not a valid namespace name — Kubernetes namespaces are ` +
        `lowercase DNS-1123 labels. A label value may contain uppercase or underscores, a namespace ` +
        `may not, so this selector cannot name a namespace that exists.`,
    );
  }
}

// ── The plan ──────────────────────────────────────────────────────────────────

/**
 * One policy to render on this layer, with whatever address resolution the non-workload side needs.
 *
 * The workload side is resolved inside the renderer through `resolveService`, because a selector is
 * not an address and the address resolver has no way to produce one.
 */
export interface CiliumItem {
  policy: Policy;
  /** Resolved CIDRs for `src`, when `src` is an address kind. Ignored when `src` is a workload. */
  srcCidrs?: string[];
  /** Resolved CIDRs for `dst`, when `dst` is an address kind. Ignored when `dst` is a workload. */
  dstCidrs?: string[];
}

/** A namespace-wide ingress posture, deliberately separate from an allow/deny traffic flow. */
export interface WorkloadBaseline {
  kind: "namespace-ingress-default-deny";
  id: string;
  namespace: string;
  description: string;
}

/**
 * Decide the CRD set for one cluster without serialising it.
 *
 * Only pass items whose policy touches a workload on at least one side — `assignsToWorkloadLayer`
 * answers that, and is the same predicate the host renderer's caller should use to decide what *not*
 * to hand to `nft.ts` as a destination.
 */
export function planCiliumPolicies(input: CiliumRenderInput, items: CiliumItem[]): CiliumPlan {
  if (!input.k8sApplier) {
    // Evaluation rule 8: a workload destination is this layer's sole responsibility, and refusing is
    // the only honest outcome when the layer cannot act. Rendering the host half and reporting
    // success is the failure this check exists to prevent.
    throw new CiliumRenderError(
      "k8sApplier is empty — CiliumNetworkPolicy is cluster-scoped and needs one designated node " +
        "to apply it. Without it every node's agent would write the same object.",
    );
  }
  if (!input.cluster) throw new CiliumRenderError("cluster id is empty — CRD names are derived from it");
  if (!input.generation || input.generation.length > 253) {
    throw new CiliumRenderError("generation is empty or overlong — rollback identity cannot be stamped safely");
  }

  // A malformed version would silently take the `>= 1.17` branch through `NaN` comparisons and render
  // a combination the cluster rejects, so it is checked here rather than trusted at the use site.
  const [maj, min] = input.ciliumVersion ?? [];
  if (!Number.isInteger(maj) || !Number.isInteger(min) || maj! < 1 || min! < 0) {
    throw new CiliumRenderError(
      `ciliumVersion must be [major, minor] integers, got ${JSON.stringify(input.ciliumVersion)} — ` +
        `whether toServices may carry toPorts depends on it (1.16 refuses, 1.17 allows), and both ` +
        `guesses fail: one is rejected at apply, the other silently drops the port condition.`,
    );
  }

  const managedBy = input.managedByLabel ?? DEFAULT_MANAGED_BY;
  const policies: CiliumNetworkPolicy[] = [];
  const skipped: CiliumSkipped[] = [];
  const warnings: CiliumWarning[] = [];
  const affectedPods: Record<string, string[] | null> = {};
  const seenNames = new Set<string>();

  for (const it of items) {
    const p = it.policy;
    const at = `policy ${p.id} (${p.name})`;

    if (!p.enabled) {
      skipped.push({ policyId: p.id, name: p.name, reason: "policy is disabled" });
      continue;
    }

    const srcWorkload = isWorkload(p.src);
    const dstWorkload = isWorkload(p.dst);
    if (!srcWorkload && !dstWorkload) {
      skipped.push({
        policyId: p.id,
        name: p.name,
        reason: "neither endpoint is a workload — this policy belongs to the host layer only",
      });
      continue;
    }

    const name = crdName(input.cluster, p.id);
    if (seenNames.has(name)) {
      throw new CiliumRenderError(`two policies render to the same object name ${JSON.stringify(name)}`);
    }
    seenNames.add(name);

    const toPorts = portRules(p, at);
    // ICMP is the one protocol whose restriction cannot be kept. tcp/udp with no ports render as a
    // wildcard port that carries the protocol (`protocolOnlyPorts`), matching the host layer's
    // `meta l4proto tcp`. ICMP has no port form — Cilium matches it in a field this renderer does not
    // emit — so the rule goes out with no protocol condition and covers everything.
    if (!p.ports && p.proto === "icmp") {
      warnings.push({
        policyId: p.id,
        name: p.name,
        warning:
          "proto is icmp — this renders as an L3 rule, which on this layer carries no protocol " +
          "condition, so it covers every protocol rather than icmp alone. Cilium expresses ICMP in a " +
          "separate field this renderer does not emit." +
          (p.action === "deny" ? " On a deny this is much wider than written." : ""),
      });
    }

    // Which side becomes `endpointSelector` follows the direction table in the workload-layer
    // design, and it is not a free choice — Cilium enforces egress at the sending endpoint and
    // ingress at the receiving one, so the selector has to name the pods on the enforcing side.
    //
    // A **workload source** therefore renders as egress, and that is the branch that reaches
    // `toServices` — the native form, which Cilium re-resolves itself and which stays correct across
    // a Service selector change. Reading the selector by hand instead (the ingress form) freezes the
    // pod set at render time.
    //
    // A workload destination with a non-workload source has no sending endpoint inside the cluster,
    // so it renders as ingress and the Service selector does have to be read.
    let spec: CiliumNetworkPolicy["spec"];
    // `null` when nobody reported this selector's membership — distinct from `[]`, which is a
    // selector that was queried and matches nothing. See `ResolvePods`.
    let pods: string[] | null;

    // Set when a workload→workload allow also needs the receiver's half. See where it is assigned.
    let peerIngress: { from: { matchLabels: Record<string, string> }; allow: CiliumIngressRule } | null = null;

    if (srcWorkload) {
      const target = endpointSelectorFor(p.src, "source", input, `${at} source`);
      pods = target.pods;
      const rule: CiliumEgressRule = { ...(toPorts.length ? { toPorts } : {}) };

      if (p.dst.kind === "k8s-service") {
        // `toServices` is native — Cilium resolves the name itself, so this branch never needs the
        // selector. It still has to check that the Service *exists*: an unresolvable name is not a
        // syntax error, it is a rule Cilium resolves to nothing. On a deny that is a no-op reported
        // as applied, and rule 8 leaves nothing behind a Service destination. The ingress direction
        // refuses this case (`endpointSelectorFor`); refusing it here too means `arc → util/typo`
        // and `cidr → util/typo` fail the same way rather than one silently rendering.
        const svc = resolveServiceRef(p.dst.value, input, `${at} destination`);
        // Before 1.17, Cilium refuses `toServices` together with `toPorts`. Refused rather than
        // rendered without the ports: dropping the port condition would turn "reach this Service on
        // 5432" into "reach it on anything", and a rule that is wider than written is exactly what
        // rule 8 says this layer cannot do quietly. Refused rather than rendered *with* them too,
        // since the CRD would be rejected at apply where the error no longer names the policy.
        if (toPorts.length && !supportsServicePorts(input.ciliumVersion)) {
          const [maj, min] = input.ciliumVersion;
          throw new CiliumRenderError(
            `${at}: Cilium ${maj}.${min} rejects toServices combined with toPorts (fixed in 1.17), ` +
              `and this policy names both Service ${JSON.stringify(p.dst.value)} and ports ` +
              `${JSON.stringify(p.ports)}. Rendering without the ports would widen the rule to every ` +
              `port on that Service. Name the destination pods with k8s-label instead, which reaches ` +
              `them through toEndpoints and takes ports, or upgrade Cilium.`,
          );
        }
        // Built from the resolved Service, not from splitting `p.dst.value` — see `resolveServiceRef`.
        rule.toServices = [{ k8sService: { serviceName: svc.name, namespace: svc.namespace } }];
        // ## The receiver's half, which this branch used to skip
        //
        // `peerIngress` is built in the `else if (dstWorkload)` branch below. `k8s-service` is a
        // workload kind and would reach it — but it is caught here first, so a Service destination
        // rendered the sender's egress object and nothing else.
        //
        // The measurement behind `peerIngress` applies here unchanged: Cilium enforces egress at the
        // sender and ingress at the receiver **independently**, and on 2026-08-10 the dashboard could
        // not reach dispatcher because only the first existed — the egress object applied cleanly and
        // the packets were dropped at `endpoint 1586`.
        //
        // So the same intent written two ways behaved differently, and `toServices` is the way this
        // file recommends (Cilium re-resolves the name, so the rule survives a Service selector
        // change). Measured against dev on 2026-08-24 before changing it: **no policy in the live
        // cluster uses `toServices`**, so nothing was relying on the old shape — and the pods a
        // Service destination would name are the same ones the `-ingress` objects already close.
        //
        // The selector comes from the resolved Service rather than from `toServices`, because
        // `endpointSelector` names pods and `toServices` names a Service. `resolveServiceRef` has
        // already refused an unresolvable name and `assertServiceUsable` an empty selector — an empty
        // one here would match the whole namespace.
        if (p.action === "allow") {
          assertServiceUsable(svc, p.dst.value, `${at} destination`);
          const backends: MatchLabels = { ...svc.selector, [NS_LABEL]: svc.namespace };
          assertNamespace(svc.namespace, `${at} destination`);
          peerIngress = {
            from: { matchLabels: backends },
            allow: { fromEndpoints: [{ matchLabels: target.labels }], ...(toPorts.length ? { toPorts } : {}) },
          };
          // Same sentence the `k8s-label` branch carries, and for the same reason: the object below
          // closes the pods behind this Service to everything a heliopause policy does not name, and
          // the author asked for one flow rather than for that.
          warnings.push({
            policyId: p.id,
            name: p.name,
            warning:
              `this allow also renders the receiver's half, which puts the pods behind Service ` +
              `${JSON.stringify(p.dst.value)} into ingress default-deny — Cilium enforces the two ` +
              `directions independently, so the sender's egress rule alone leaves the flow dropped ` +
              `at the destination. Anything else that reaches those pods and is not named by a ` +
              `heliopause policy stops working.`,
          });
        }
      } else if (dstWorkload) {
        const to = endpointSelectorFor(p.dst, "destination", input, `${at} destination`);
        // A *peer* selector needs the namespace label as much as the selected side does, for a
        // different reason: Cilium fills a missing one in with the policy's own namespace rather than
        // leaving it unscoped. So `dst: k8s-label "app=idp"` on a policy landing in `arc-runners`
        // quietly means "app=idp in arc-runners" — a rule that renders, applies, and aims at the
        // wrong namespace. The guard below covers `spec.endpointSelector`; this covers the peer.
        const peerNs = to.labels[NS_LABEL];
        if (!peerNs) {
          throw new CiliumRenderError(
            `${at} destination: the peer selector ${JSON.stringify(p.dst.value)} names no namespace. ` +
              `Cilium scopes a peer selector to the policy's own namespace when one is missing, so ` +
              `this would silently target ${JSON.stringify(p.src.value)}'s namespace instead of the ` +
              `pods you named. Add ${NS_LABEL}=<namespace>.`,
          );
        }
        assertNamespace(peerNs, `${at} destination`);
        rule.toEndpoints = [{ matchLabels: to.labels }];
        if (p.action === "allow") {
          // ## Both halves, because one half is not a policy — it is a broken flow
          //
          // Cilium enforces egress at the sender **and** ingress at the receiver, independently: as
          // soon as any policy selects the destination pods for ingress, everything else to them is
          // denied. This used to emit the egress half and a warning saying the ingress half might
          // also be needed, and that was measured to be inadequate on 2026-08-10 — the dashboard
          // could not reach dispatcher, the egress object rendered and applied cleanly, and the
          // packets were dropped at `endpoint 1586` on the receiving side.
          //
          // A warning is the wrong instrument here. The author wrote "these pods may talk to those
          // pods"; emitting only the sender's half satisfies the letter of that and delivers no
          // working flow. So the receiver's half is rendered too, and the two travel together —
          // deleting the policy removes both, which is the property a warning could never give.
          //
          // Deny is deliberately excluded: a deny needs only the sender's side to be effective, and
          // mirroring it would place an `ingressDeny` on pods the author never named, where Cilium's
          // deny-beats-every-allow rule makes an accidental blast radius expensive.
          peerIngress = {
            from: { matchLabels: to.labels },
            allow: { fromEndpoints: [{ matchLabels: target.labels }], ...(toPorts.length ? { toPorts } : {}) },
          };
          // ## The half this renderer adds also **closes** the pods it was added for
          //
          // The object below carries `enableDefaultDeny: { ingress: true }`, which is right for an
          // ingress allow the author wrote about that destination — it admits the named caller and
          // refuses the rest. Here the author named those pods as a *peer* of a rule about somebody
          // else, and the closing arrives as a side effect.
          //
          // That is the same argument this file already accepted in the other direction: an egress
          // allow renders `{ egress: false }` precisely because "these pods may also reach that" is
          // not "these pods may reach nothing else". The asymmetry is deliberate — an ingress allow
          // that did not close its destination would admit everyone — but it is not obvious from the
          // policy text, and Cilium's aggregation rule makes it irreversible from any other policy.
          //
          // Said rather than changed. Flipping it to `false` would make every ingress allow on this
          // layer non-enforcing, which is a larger decision than this warning; and the deny path
          // already warns about the same aggregation rule from the other side.
          warnings.push({
            policyId: p.id,
            name: p.name,
            warning:
              `this allow also renders the receiver's half, which puts ${p.dst.value} into ingress ` +
              `default-deny — Cilium enforces the two directions independently, so the sender's ` +
              `egress rule alone leaves the flow dropped at the destination. Anything else that ` +
              `reaches those pods and is not named by a heliopause policy stops working.`,
          });
        }
      } else {
        // Destination is an address. The host layer sees this traffic too — pod source addresses are
        // preserved on the wire (V14) so the receiving host's input hook can match by CIDR — but only
        // down to a CIDR, where this matches by namespace or label. For a destination *outside* the
        // cluster (`pg-01`, `mailer-01`) the host layer is in fact the only one that works, because
        // no CiliumNetworkPolicy applies to a non-cluster VM (rule 8-a).
        const side = otherSide(p.dst, it.dstCidrs ?? [], `${at} destination`);
        if (side.cidr.length) rule.toCIDR = side.cidr;
        if (side.entities.length) rule.toEntities = side.entities;
        if (side.v6.length) {
          warnings.push({ policyId: p.id, name: p.name, warning: v6Warning("destination", side.v6) });
        }
      }

      spec = {
        description: `${p.id} ${p.name}`,
        endpointSelector: { matchLabels: target.labels },
        // ## An egress allow must not close the sender. Measured, and it took DNS down
        //
        // This said `defaultDenyFor(p.action, "egress")`, which was `true` for an allow. On
        // 2026-08-10 the first egress allow this repository ever rendered went out, and the pods it
        // named lost **everything it did not mention** — starting with DNS, three seconds later:
        //
        //     identity 6565 -> 10.17.128.128:53 udp   bpf_lxc.c:1361   (coredns)
        //
        // The trap was already documented here, on the deny path: "Cilium enables default-deny if
        // *any* policy asks for it. So adding an allow for these pods later also cuts off everything
        // it does not name." That warning was written about someone *else's* future allow. This
        // renderer then emitted exactly such an allow itself.
        //
        // An ingress allow closing its destination is the point — that is what admits a named
        // caller and refuses the rest. An egress allow closing its *source* is a different claim
        // altogether: the author said "these pods may also reach that", not "these pods may reach
        // nothing else". Egress containment in this repository is expressed by deny policies, which
        // already carry `false` here for the same reason.
        //
        // So an egress allow adds to the sender's posture instead of replacing it. A policy set that
        // genuinely wants a closed sender needs a deny naming what to close, which is visible in the
        // catalogue — unlike a default-deny that arrives as a side effect of an unrelated allow.
        enableDefaultDeny: { egress: false },
        ...(p.action === "deny" ? { egressDeny: [rule] } : { egress: [rule] }),
      };
    } else {
      // Workload destination, address source. This is the combination evaluation rule 8 assigns to
      // this layer **alone**: the packet is resolved in eBPF and never reaches a netfilter hook, so
      // there is no host-layer rule that could cover it and nothing behind a failure here.
      const target = endpointSelectorFor(p.dst, "destination", input, `${at} destination`);
      pods = target.pods;
      const rule: CiliumIngressRule = { ...(toPorts.length ? { toPorts } : {}) };

      const side = otherSide(p.src, it.srcCidrs ?? [], `${at} source`);
      if (side.cidr.length) rule.fromCIDR = side.cidr;
      if (side.entities.length) rule.fromEntities = side.entities;
      if (side.v6.length) {
        warnings.push({ policyId: p.id, name: p.name, warning: v6Warning("source", side.v6) });
      }

      spec = {
        description: `${p.id} ${p.name}`,
        endpointSelector: { matchLabels: target.labels },
        enableDefaultDeny: defaultDenyFor(p.action),
        ...(p.action === "deny" ? { ingressDeny: [rule] } : { ingress: [rule] }),
      };
    }

    // Cilium's deny is evaluated before every allow and cannot be carved out by a later rule. The
    // host layer's "narrow deny, then broad allow" ordering has no equivalent here, so a deny that
    // overlaps an intended allow silently wins. Said once per deny rather than left to be discovered.
    if (p.action === "deny") {
      warnings.push({
        policyId: p.id,
        name: p.name,
        warning:
          "deny on this layer is absolute — Cilium evaluates ingressDeny/egressDeny before all " +
          "allows and no later rule can carve an exception out of it. Unlike the host layer, " +
          "ordering cannot be used to make a narrower allow win." +
          (p.ports
            ? ""
            : " This deny names no ports, so it covers every protocol and port to the selected " +
              "endpoints — an L3 Cilium rule restricts neither."),
      });
    }

    // The deny carries `enableDefaultDeny: false` for its direction so it subtracts from the
    // endpoint's existing posture instead of closing it. But that request is not the last word:
    // "that endpoint's default deny will be enabled if any policy requests it", so a single allow
    // policy selecting the same pods puts them in default-deny regardless. The deny then still
    // works, and everything else those pods reached stops working — which is correct behaviour and
    // an easy thing to be surprised by, since neither policy is wrong on its own.
    if (p.action === "deny") {
      warnings.push({
        policyId: p.id,
        name: p.name,
        warning:
          "this deny asks not to close the endpoint (enableDefaultDeny false for its direction), so " +
          "it subtracts from whatever the pods already reach. That request loses to any allow policy " +
          "selecting the same pods: Cilium enables default-deny if *any* policy asks for it. So " +
          "adding an allow for these pods later also cuts off everything it does not name.",
      });
    }

    // `denyMode` has no representation here: Cilium drops, and there is no reject form. A policy
    // written as `reject` for fast failure inside a trusted segment silently becomes a timeout on
    // this layer, which changes how the failure looks to whatever is calling.
    if (p.action === "deny" && p.denyMode === "reject") {
      warnings.push({
        policyId: p.id,
        name: p.name,
        warning:
          "denyMode is reject but this layer only drops — callers will time out rather than fail " +
          "immediately. The reject applies on the host layer only.",
      });
    }

    // A CiliumNetworkPolicy is namespaced and only governs pods in its own namespace, so the object
    // has to land where the selected pods are. Defaulting to `default` would produce a policy that
    // applies to nothing while reporting a clean apply — the exact shape of failure this layer exists
    // to remove, since there is no host-layer rule behind it.
    const ns = spec.endpointSelector.matchLabels[NS_LABEL];
    if (!ns) {
      throw new CiliumRenderError(
        `${at}: the selected endpoint has no namespace — a bare label selector ` +
          `${JSON.stringify(srcWorkload ? p.src.value : p.dst.value)} does not say which namespace's ` +
          `pods it governs, and a CiliumNetworkPolicy only applies inside its own namespace. Add ` +
          `${NS_LABEL}=<namespace> to the selector, or name the namespace with k8s-namespace.`,
      );
    }
    assertNamespace(ns, at);

    const meta = (objectName: string, objectNs: string) => ({
      name: objectName,
      namespace: objectNs,
      labels: { "managed-by": managedBy, "heliopause.io/cluster": input.cluster },
      annotations: {
        "heliopause.io/policy-id": p.id,
        "heliopause.io/applier": input.k8sApplier,
        "heliopause.io/generation": input.generation,
      },
    });

    policies.push({
      apiVersion: "cilium.io/v2",
      kind: "CiliumNetworkPolicy",
      metadata: meta(name, ns),
      spec,
    });

    // The receiver's half of a workload→workload allow. Cilium enforces the two directions
    // independently, so the sender's egress object alone leaves the flow dropped at the destination
    // as soon as anything selects those pods for ingress — measured, see where `peerIngress` is set.
    //
    // It lands in the *destination's* namespace because a CiliumNetworkPolicy only governs pods in
    // its own, and it carries the same `policy-id` annotation so both objects are traceable to the
    // one rule that asked for them and are removed together when it goes.
    if (peerIngress) {
      const peerNs = peerIngress.from.matchLabels[NS_LABEL];
      if (!peerNs) {
        throw new CiliumRenderError(
          `${at}: the destination selector names no namespace, so the ingress half of this ` +
            `workload-to-workload allow has nowhere to land.`,
        );
      }
      assertNamespace(peerNs, `${at} destination`);
      policies.push({
        apiVersion: "cilium.io/v2",
        kind: "CiliumNetworkPolicy",
        metadata: meta(crdName(input.cluster, p.id, "-ingress"), peerNs),
        spec: {
          description: `${p.id} ${p.name} (ingress half)`,
          endpointSelector: { matchLabels: peerIngress.from.matchLabels },
          enableDefaultDeny: defaultDenyFor(p.action),
          ingress: [peerIngress.allow],
        },
      });
    }
    affectedPods[p.id] = pods;
  }

  return { cluster: input.cluster, applier: input.k8sApplier, policies, skipped, warnings, affectedPods };
}

// ── Selector membership (H14a) ────────────────────────────────────────────────
//
// The renderer is pure and cannot query a cluster, so which pods a selector currently matches is
// injected — the same shape as `ResolveCidrs` and `ResolveService`. These two functions are the ends
// of that path: one says what to ask about, the other turns the answer into something the render can
// show and the publisher can refuse on.

/**
 * Selectors these policies need membership for, so the manager can ask the applier about exactly
 * those and nothing else.
 *
 * Both sides of a policy are collected. A policy's *source* selector decides which pods the rule is
 * written on (`endpointSelector`), and its *destination* selector decides who they may reach — an
 * operator reviewing a generation needs both, and a guardrail watching for a selector that suddenly
 * matches forty pods cares about whichever side widened.
 */
function validateWatchLabelSelector(selector: string): void {
  if (new TextEncoder().encode(selector).length > 512) {
    throw new CiliumRenderError("workload policy contains a selector longer than the agent's 512-byte limit");
  }
  const terms = selector.split(",").map((part) => part.trim()).filter(Boolean);
  if (terms.length === 0 || terms.length > 16) {
    throw new CiliumRenderError(`workload selector has ${terms.length} terms; agent limit is 1..16`);
  }
  const keys = new Set<string>();
  let namespace: string | undefined;
  for (const term of terms) {
    const eq = term.indexOf("=");
    if (eq <= 0) throw new CiliumRenderError(`workload selector term ${JSON.stringify(term)} is not key=value`);
    const key = term.slice(0, eq);
    if (keys.has(key)) {
      throw new CiliumRenderError(`workload selector repeats key ${JSON.stringify(key)}`);
    }
    keys.add(key);
    if (key === NS_LABEL) namespace = term.slice(eq + 1);
  }
  if (!namespace) {
    throw new CiliumRenderError(
      `workload selector ${JSON.stringify(selector)} does not pin ${NS_LABEL}; ` +
        "the agent refuses cluster-wide pod queries",
    );
  }
}

export function selectorsToWatch(items: CiliumItem[]): WatchSelectors {
  const namespaces = new Set<string>();
  const labels = new Set<string>();
  for (const it of items) {
    for (const e of [it.policy.src, it.policy.dst]) {
      if (e.kind === "k8s-namespace") namespaces.add(e.value);
      // Label selectors are watched verbatim, in the form the policy wrote them. Normalising here
      // would mean the agent's answer no longer keys to the question the manager asked.
      else if (e.kind === "k8s-label") {
        validateWatchLabelSelector(e.value);
        labels.add(e.value);
      }
    }
  }
  const out = { namespaces: [...namespaces].sort(), labels: [...labels].sort() };
  const count = out.namespaces.length + out.labels.length;
  if (count > MAX_WATCH_SELECTORS) {
    throw new CiliumRenderError(
      `workload policies require ${count} selector-membership queries; limit is ${MAX_WATCH_SELECTORS}. ` +
        "Split the policy set or consolidate selectors before publishing.",
    );
  }
  return out;
}

/**
 * Turn a reported membership into a `ResolvePods` the renderer can use.
 *
 * Returns `null` for anything the report does not cover, and that is the load-bearing part: `null`
 * means "not known" while `[]` means "queried, and there are none". Collapsing them is how
 * `arc-runners` — genuinely empty between CI jobs — becomes indistinguishable from a namespace
 * nobody ever asked about, and an operator reads "0 pods" as "this policy is harmless".
 */
export function podsFromMembership(m: SelectorMembership | undefined): ResolvePods {
  return (kind, value) => {
    if (!m) return null;
    const table = kind === "k8s-namespace" ? m.namespaces : m.labelled;
    const pods = table[value];
    if (!pods) return null;
    // Namespace membership is reported as bare pod names; the render shows `namespace/name` so two
    // namespaces' pods are never confused in one list.
    return kind === "k8s-namespace" ? pods.map((p) => `${value}/${p}`) : pods;
  };
}

/**
 * A selector whose pod count grew enough to be worth stopping for.
 *
 * The design calls for this directly: "a Service selector that changes changes the set of pods the
 * policy applies to — like FQDN it needs change detection and a guardrail: hold when the target pod
 * count jumps" (workload-layer design, 주의).
 */
export interface MembershipJump {
  /** `k8s-namespace:arc-runners` or `k8s-label:app=runner`, so the two kinds never collide. */
  selector: string;
  before: number;
  after: number;
  reason: string;
}

/** Tuning for `membershipJumps`. Both bounds must be crossed before a jump is reported. */
export interface JumpLimits {
  /**
   * Minimum absolute growth. Below this nothing is reported however large the ratio.
   *
   * Without a floor, 1 → 3 pods is a 200% jump and every CI job that starts two runners becomes an
   * alarm. An alarm that fires on normal operation is one that gets acknowledged without reading.
   */
  minGrowth: number;
  /** Minimum ratio. `3` means "three times as many pods as last time". */
  factor: number;
}

export const DEFAULT_JUMP_LIMITS: JumpLimits = { minGrowth: 10, factor: 3 };

/**
 * Selectors whose membership grew sharply since the last generation.
 *
 * ## Why growth and not any change
 *
 * Pod membership changes constantly and legitimately — that is what an autoscaling runner set *is*.
 * What is not normal is a selector suddenly matching far more pods than it did, which is the visible
 * symptom of a Service selector that widened. `app=idp` becoming `app` matches every pod in the
 * namespace, renders cleanly, and applies successfully.
 *
 * Shrinking is deliberately not reported. A policy that covers fewer pods than before may well be a
 * problem, but it is not *this* problem, and folding both into one signal makes the signal mean
 * "something moved" — which is true on every beat.
 *
 * ## Why `null` is silence rather than zero
 *
 * A selector nobody reported has no count, so it cannot have jumped. Treating unknown as 0 would
 * make the first report after an outage look like a jump from nothing, exactly when an operator is
 * least able to check.
 */
export function membershipJumps(
  before: Record<string, string[] | null> | undefined,
  after: Record<string, string[] | null>,
  limits: JumpLimits = DEFAULT_JUMP_LIMITS,
): MembershipJump[] {
  if (!before) return [];
  const out: MembershipJump[] = [];
  for (const [selector, nowPods] of Object.entries(after)) {
    const wasPods = before[selector];
    // Either side unknown means there is nothing to compare. Not a jump, and not a silent pass —
    // the render already reports unknown membership on its own.
    if (wasPods == null || nowPods == null) continue;
    const was = wasPods.length;
    const now = nowPods.length;
    const growth = now - was;
    if (growth < limits.minGrowth) continue;
    // `was === 0` cannot produce a ratio. Growth from nothing is judged by the floor alone, which is
    // the honest reading: 0 → 40 is a jump on any measure.
    if (was > 0 && now < was * limits.factor) continue;
    out.push({
      selector,
      before: was,
      after: now,
      reason:
        `matched ${was} pod(s) at the last generation and ${now} now — a selector that widens this ` +
        `sharply usually means the selector changed, not the workload. Check what it now covers ` +
        `before publishing.`,
    });
  }
  return out.sort((a, b) => b.after - a.after);
}

/**
 * Does this policy need the workload layer, and does it need the host layer too?
 *
 * The caller uses this to route a policy, and the asymmetry is the point (evaluation rule 8):
 * a workload **destination** goes to this layer alone, because netfilter cannot see the packet. A
 * workload **source** goes to both — the pod's own address is preserved on the wire (V14) so the
 * receiving host's input hook matches it by CIDR, while this layer matches it by namespace or label.
 */
export function assignsToWorkloadLayer(p: Policy): { workload: boolean; host: boolean } {
  const dstWorkload = K8S_KINDS.has(p.dst.kind);
  const srcWorkload = K8S_KINDS.has(p.src.kind);
  if (dstWorkload) return { workload: true, host: false };
  if (srcWorkload) return { workload: true, host: true };
  return { workload: false, host: true };
}

/**
 * Serialise a plan as a `v1/List`, which is what `kubectl apply -f` accepts.
 *
 * **Not a bare JSON array.** That was the first shape and it does not work: kubectl rejects it with
 * "invalid object to validate" before ever reaching the API server, because a top-level array has no
 * `apiVersion`/`kind` for it to dispatch on. Measured against the live cluster — a server-side
 * dry-run of the array failed, and the identical objects wrapped in a List applied cleanly.
 *
 * Worth stating why this was not caught earlier: every test here reads `plan.policies`, the
 * structured half, and the agent's `validate_workload` parses the JSON itself rather than shelling
 * out to kubectl. So the one consumer that cares about the wrapper — `kubectl apply` on the applier
 * node — was the only thing never exercised until a real generation was published.
 */
export function renderCiliumPolicies(input: CiliumRenderInput, items: CiliumItem[], baselines: WorkloadBaseline[] = []): {
  json: string;
  plan: CiliumPlan;
} {
  const plan = planCiliumPolicies(input, items);
  const names = new Set(plan.policies.map((p) => `${p.metadata.namespace}/${p.metadata.name}`));
  for (const baseline of baselines) {
    if (baseline.kind !== "namespace-ingress-default-deny" || !baseline.id || !baseline.description) {
      throw new CiliumRenderError("workload baseline has an invalid kind, id, or description");
    }
    assertNamespace(baseline.namespace, `baseline ${baseline.id}`);
    const name = crdName(input.cluster, baseline.id, "-baseline");
    const ref = `${baseline.namespace}/${name}`;
    if (names.has(ref)) throw new CiliumRenderError(`workload baseline ${baseline.id} collides with ${ref}`);
    names.add(ref);
    plan.policies.push({
      apiVersion: "cilium.io/v2", kind: "CiliumNetworkPolicy",
      metadata: {
        name, namespace: baseline.namespace,
        labels: { "managed-by": input.managedByLabel ?? DEFAULT_MANAGED_BY, "heliopause.io/cluster": input.cluster },
        annotations: {
          "heliopause.io/policy-id": baseline.id,
          "heliopause.io/applier": input.k8sApplier,
          "heliopause.io/generation": input.generation,
          "heliopause.io/policy-kind": baseline.kind,
        },
      },
      spec: {
        description: baseline.description,
        endpointSelector: { matchLabels: { [NS_LABEL]: baseline.namespace } },
        enableDefaultDeny: { ingress: true },
        // Cilium enters ingress default-deny only when an ingress section exists. An empty rule
        // would allow all peers, so this is an intentionally unmatchable source instead.
        ingress: [{ fromEndpoints: [{ matchLabels: { [NS_LABEL]: BASELINE_NEVER_NAMESPACE } }] }],
      },
    } as CiliumNetworkPolicy);
    plan.affectedPods[baseline.id] = input.resolvePods?.("k8s-namespace", baseline.namespace) ?? null;
  }
  const doc = { apiVersion: "v1", kind: "List", items: plan.policies };
  return { json: JSON.stringify(doc, null, 2) + "\n", plan };
}
