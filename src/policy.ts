// The abstract policy model: what a user writes, independent of how it is enforced.
//
// A policy says "this source, to this destination, on these ports → allow or deny". It never
// mentions nftables. Rendering happens in `nft.ts`; resolving names to addresses is injected by
// the caller (heliopause does not discover your infrastructure).
import { createHash } from "node:crypto";
// One-directional: `geofeed.ts` imports nothing from here. It owns the selector grammar because it also
// owns the feed contents that grammar selects from, and splitting the two would let them drift.
import { parseSelector } from "./geofeed.ts";

export type EndpointKind =
  /** A single host, by name. Resolved to addresses by the caller's resolver. */
  | "host"
  /** A named set of hosts. Also resolver-defined. */
  | "host-group"
  /** A literal CIDR, e.g. `10.0.0.0/8` or `192.0.2.7/32`. */
  | "cidr"
  /** Reference to a reusable address object by name (see `objects.ts`). */
  | "object"
  /** Everything outside `internalSupernet`. */
  | "internet"
  /** No address constraint at all. */
  | "any"
  /**
   * A Kubernetes Service, `namespace/name` — e.g. `postgres/postgres-rw`.
   *
   * The unit people actually think in, and the only stable one: pod addresses are short-lived, so
   * an address-based rule against a workload is wrong within hours. A Service is stable, already
   * carries a selector, and matches how the system is discussed.
   *
   * **Valid as a destination only.** Traffic does not come *from* a Service — it comes from the
   * pods behind it — so this kind in `src` is rejected at normalisation.
   */
  | "k8s-service"
  /**
   * A Kubernetes namespace, e.g. `arc-runners`. Every pod in it.
   *
   * The kind that covers what Services cannot: workloads that only *send*. CI runners and jobs
   * have no Service, and they are the highest-risk pods on the fleet — arbitrary code with mesh
   * reach. A pod count of zero there means "no job running right now", not "safe": the pods appear
   * when work arrives, and a policy has to already be in place when they do.
   */
  | "k8s-namespace"
  /**
   * A pod label selector — `app=runner`, or several ANDed with commas.
   *
   * Namespace scoping is done through Cilium's own namespace label rather than a second field:
   * `k8s:io.kubernetes.pod.namespace=arc-runners,app=runner`. Overloading the value with a
   * `namespace/` prefix would collide with label-key prefixes (`example.com/team=ci`), which are
   * also `<something>/<name>` and cannot be told apart by shape.
   */
  | "k8s-label"
  /**
   * A Cilium reserved identity used as the non-workload side of a workload policy.
   *
   * Deliberately limited to `host`: kubelet probes originate with Cilium's reserved host identity,
   * not a CIDR identity, so a fromCIDR rule for the node address does not reliably preserve probes
   * when an ingress allow turns the selected pod into default-deny. Other Cilium entities stay
   * unavailable until a concrete policy needs them.
   */
  | "k8s-entity"
  /**
   * Prefixes a geofeed attributes to a place — `<feed>:<selector>`, e.g. `cloudflare:KR`.
   *
   * Resolved the same way `host` is: **injected**, never fetched here. The renderer stays pure, and
   * what it renders comes from a snapshot with a recorded hash rather than from a live URL — a third
   * party editing a CSV must not be able to edit our ruleset (see `snapshot.ts`).
   *
   * ## This narrows an origin; it does not authenticate one
   *
   * The distinction is the whole safety of the kind. `vultr:KR` contains every other Vultr customer in
   * Seoul — as an allow source it means "anyone who rents an instance there gets through". `cloudflare:KR`
   * is every request that passed through Cloudflare, including an attacker who pointed their own zone at
   * our origin. The real effect is a smaller attack surface: internet-wide scanning and direct hits are
   * removed. Authentication is Authenticated Origin Pulls or a shared secret, not an address list.
   *
   * **Valid as a source only.** A geofeed names where traffic comes from; as a destination it would
   * describe sending to a whole country, which no policy in this project wants and which would render a
   * very wide egress rule from a single typo.
   */
  | "geofeed"
  /**
   * One approved WARP device, by Cloudflare device id.
   *
   * The host layer has no notion of identity, so this renders as the device's mesh addresses — v4 and
   * v6 both. That substitution is sound here only because the mesh has no NAT and each device holds a
   * fixed address, and it is exactly as strong as the device→address binding: Cloudflare reassigns
   * that on re-registration, so the binding is approved in git and diffed against the live registry
   * (`cf-devices.ts`) rather than trusted. Expansion is `deviceCidrs` in `device-policy.ts` — the
   * registry is site data, so the renderer never sees this kind, exactly as with `geofeed`.
   *
   * **The value is the device id, not the device name.** A name is a label its owner can change in
   * the dashboard, and a rule keyed on it would retarget itself the moment someone renames a laptop —
   * silently, since nothing downstream can tell a rename from a different machine. The id is what
   * `diffRegistrations` keys on for the same reason.
   *
   * Valid on either side: unlike a Service, a device is a real host that traffic can be sent to, and
   * an egress rule naming one is expressible. What is refused is naming a device nobody approved.
   */
  | "cf-device"
  /**
   * One approved user, by email — the union of the devices registered to them.
   *
   * A union is the whole risk of the kind: it grows when that person registers a device, and it grows
   * without an edit to the policy that uses it. The growth is not silent, though — a new device
   * reaches policy only by being approved into the site module, which is a commit like any other.
   */
  | "cf-user";

export type Proto = "tcp" | "udp" | "icmp" | "any";
export type PolicyAction = "allow" | "deny";

/**
 * How a deny behaves on the wire.
 *
 * This is a sub-mode of `deny` rather than a third action on purpose. Enforcement layers other
 * than the host (cloud edge ACLs, provider firewalls) can express "block" but not "reject"; a
 * three-valued action would silently degrade to `deny` on those layers. As a sub-mode, the
 * policy is `deny` everywhere and only its *style* is host-specific.
 */
export type DenyMode = "drop" | "reject";

export interface Endpoint {
  kind: EndpointKind;
  /**
   * Meaning depends on `kind`: host name, CIDR, or object name.
   * Ignored (and cleared) for `internet` and `any`.
   */
  value: string;
}

export interface Policy {
  id: string;
  name: string;
  src: Endpoint;
  dst: Endpoint;
  proto: Proto;
  /** `"22"` · `"80,443"` · `"1000:2000"` · `"@service-object"` · `""` (all ports) */
  ports: string;
  action: PolicyAction;
  /** Only meaningful when `action === "deny"`; normalisation forces `"drop"` otherwise. */
  denyMode: DenyMode;
  /** Lower runs first. Only significant once the chain default is deny. */
  priority: number;
  enabled: boolean;
  notes?: string;
}

/** Resolves an endpoint to concrete CIDRs. Injected — heliopause has no inventory of its own. */
export type ResolveCidrs = (e: Endpoint) => string[];

const PROTOS = new Set<Proto>(["tcp", "udp", "icmp", "any"]);
const KINDS = new Set<EndpointKind>([
  "host", "host-group", "cidr", "object", "internet", "any",
  "k8s-service", "k8s-namespace", "k8s-label",
  "k8s-entity",
  "geofeed",
  "cf-device", "cf-user",
]);

/** A Cloudflare device id, as the registry writes it. */
const DEVICE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * An email, checked for shape only.
 *
 * Deliberately loose. Whether this address belongs to anyone is a question the approved registry
 * answers and this layer cannot — the same split as `geofeed`, where the grammar is checked here and
 * membership where the data is. What is worth refusing early is the value that is not an address at
 * all, because that one reads as a typo'd user and would expand to nothing.
 */
const USER_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** The two kinds that name an identity rather than an address. */

/**
 * Shape-check an identity value and return it in the form a lookup compares.
 *
 * Exported because an address object may hold these kinds as members and must check them the same
 * way. Two checkers would drift, and the direction they drift in is a value one side accepts and the
 * other cannot resolve — a group member that silently contributes nothing.
 *
 * Lower-cased before the check: the value is a lookup key, and `E73E4B57-…` and `e73e4b57-…` are the
 * same device. Left as written they would be two policies with two fingerprints selecting one
 * machine, and `policyFingerprint` would report an edit nobody made.
 */
export function normalizeIdentityValue(kind: "cf-device" | "cf-user", raw: string, label: string): string {
  const value = String(raw ?? "").trim().toLowerCase();
  if (kind === "cf-device") {
    if (!DEVICE_ID.test(value)) {
      throw bad(
        // A made-up id, for the reason the proposal examples were changed: this string is printed to
        // users and read in a repository that is going to be published, and a real one names a real
        // machine of a real person.
        `${label}.value must be a Cloudflare device id, e.g. 11111111-2222-4333-8444-555555555555 — ` +
          `got ${JSON.stringify(value)}. A device *name* is refused on purpose: it is a label its ` +
          `owner can change, and a rule keyed on it retargets itself on a rename.`,
      );
    }
    return value;
  }
  if (!USER_EMAIL.test(value)) {
    throw bad(`${label}.value must be a user email, e.g. someone@example.com — got ${JSON.stringify(value)}`);
  }
  return value;
}

/** Endpoint kinds that carry no address of their own. */
export const NO_VALUE_KINDS: ReadonlySet<EndpointKind> = new Set<EndpointKind>(["internet", "any"]);

/**
 * Kinds naming a Kubernetes workload rather than an address.
 *
 * These cannot be rendered by the host layer at all when they are the **destination**: pod and
 * ClusterIP traffic is handled in eBPF and never reaches netfilter (V15), and the public-443
 * measurement in V31 is the same fact from the other side — a counting chain showed 0 packets while
 * external connections succeeded, because `cilium-dbg service list` maps `10.17.192.1:443` to the
 * API server in BPF. So the split is not a preference between two renderers; one of them is
 * physically unable to see the packet.
 */
export const K8S_KINDS: ReadonlySet<EndpointKind> = new Set<EndpointKind>([
  "k8s-service",
  "k8s-namespace",
  "k8s-label",
]);

/** Does this endpoint name a workload (pod/service) rather than an address? */
export function isWorkload(e: Endpoint): boolean {
  return K8S_KINDS.has(e.kind);
}

/** `namespace/name`, both DNS-1123 labels — the shape `kubectl` accepts. */
const DNS_LABEL = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?";
const SERVICE_REF = new RegExp(`^${DNS_LABEL}/${DNS_LABEL}$`);
const NAMESPACE_REF = new RegExp(`^${DNS_LABEL}$`);

/**
 * A label selector: `k=v` pairs, comma-separated, ANDed.
 *
 * Only equality is accepted. Cilium's `matchLabels` is equality-only, and `matchExpressions`
 * (`In`, `NotIn`, `Exists`) would need a second representation with its own negation semantics —
 * a `NotIn` selector widens the policy target set as pods change, which is the failure mode the
 * selector guardrails exist to catch. Refused until there is a case for it.
 *
 * The key admits `:` and `/` because both appear in the keys this layer has to name: Cilium prefixes
 * label sources (`k8s:io.kubernetes.pod.namespace`, which is how a selector reaches across
 * namespaces) and Kubernetes allows a DNS-subdomain prefix (`example.com/team`).
 */
const LABEL_SELECTOR = /^[A-Za-z0-9]([A-Za-z0-9._:/-]{0,251}[A-Za-z0-9])?=[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$/;

export class PolicyError extends Error {
  readonly statusCode = 400;
}

function bad(msg: string): PolicyError {
  return new PolicyError(msg);
}

/** Prefix marking a service-object reference in `ports`, e.g. `"@web"`. */
export const OBJECT_REF_PREFIX = "@";

export function isPortsRef(ports: string): boolean {
  return ports.startsWith(OBJECT_REF_PREFIX);
}

/** Validate and normalise one port spec (`"22"` or `"1000:2000"`). */
function normalizeOnePort(p: string): string {
  const m = /^(\d{1,5})(?::(\d{1,5}))?$/.exec(p);
  if (!m) throw bad(`port must be "22" or "1000:2000" — got "${p}"`);
  const lo = Number(m[1]);
  const hi = m[2] === undefined ? lo : Number(m[2]);
  if (lo < 1 || hi > 65535) throw bad("port out of range 1-65535");
  if (hi < lo) throw bad("port range start is greater than its end");
  return m[2] === undefined ? String(lo) : `${lo}:${hi}`;
}

/**
 * Normalise `ports`. Accepts `""` (all), a single port, a range, a comma list, or `"@name"`.
 *
 * Lists are **deduplicated and sorted**. Without that, `"443,80"` and `"80,443"` are the same
 * policy with different fingerprints, which makes change detection report edits that did not
 * happen.
 */
export function normalizePorts(raw: unknown, proto: Proto): string {
  const p = String(raw ?? "").trim();
  if (!p) return "";
  if (proto === "icmp") return ""; // icmp has no ports; drop quietly rather than erroring

  if (isPortsRef(p)) {
    const name = p.slice(OBJECT_REF_PREFIX.length).trim();
    if (!name) throw bad("service object name is empty (expected e.g. @web)");
    if (!/^[A-Za-z0-9_.\- ]{1,60}$/.test(name)) {
      throw bad(`service object name has disallowed characters: "${name}"`);
    }
    return `${OBJECT_REF_PREFIX}${name}`;
  }

  const parts = p.split(",").map((x) => x.trim()).filter((x) => x !== "");
  if (parts.length === 0) throw bad('ports must be "22", "80,443", "1000:2000" or "@name"');
  const norm = parts.map(normalizeOnePort);
  const uniq = [...new Set(norm)].sort((a, b) => Number(a.split(":")[0]) - Number(b.split(":")[0]));
  return uniq.join(",");
}

function normalizeEndpoint(e: unknown, label: "src" | "dst"): Endpoint {
  const o = (e ?? {}) as Partial<Endpoint>;
  const kind = String(o.kind ?? "").trim() as EndpointKind;
  if (!KINDS.has(kind)) throw bad(`${label}.kind must be one of ${[...KINDS].join("|")}`);
  let value = String(o.value ?? "").trim();
  if (NO_VALUE_KINDS.has(kind)) {
    value = ""; // carries no address; discard whatever was sent
  } else if (!value) {
    throw bad(`${label}.value is required for kind=${kind}`);
  }
  if (kind === "cidr" && !/^[0-9a-fA-F.:]+\/\d{1,3}$/.test(value)) {
    throw bad(`${label}.value must be a CIDR, e.g. 10.0.0.0/8`);
  }
  if (kind === "k8s-entity" && value !== "host") {
    throw bad(`${label}.value for kind=k8s-entity must be host`);
  }

  // A Service is a receiving concept — a stable name plus a selector for the pods behind it.
  // Nothing sends *as* a Service, so `src: k8s-service` has no meaning to render. It is refused
  // here rather than in the renderer because the policy is wrong as written, not unrenderable on
  // some layer: silently reading it as "the pods behind that Service" would be a guess, and a wrong
  // one whenever those pods also sit behind another Service.
  if (kind === "k8s-service" && label === "src") {
    throw bad(
      "src.kind cannot be k8s-service — traffic comes from the pods behind a Service, not from " +
        "the Service. Use k8s-namespace or k8s-label to name the sending pods.",
    );
  }

  // The mirror image of the `k8s-service` rule above, and refused for a comparable reason: the kind
  // names where traffic *originates*. As a destination it would mean "to everything in that country",
  // which no policy here wants — and a single typo would render an egress rule over thousands of
  // prefixes. Refused as written rather than left to a renderer, so the mistake surfaces at the edit.
  if (kind === "geofeed" && label === "dst") {
    throw bad(
      "dst.kind cannot be geofeed — a geofeed names where traffic comes from. Restricting where " +
        "traffic may go needs an explicit destination (cidr, host, or object).",
    );
  }
  if (kind === "geofeed") {
    // Shape only. Whether the selector matches anything depends on a snapshot, which this layer does
    // not have — that check lives in `selectPrefixes`, where the feed's contents are known.
    //
    // Normalised through the parser rather than regex-checked here, so `Cloudflare:kr` and
    // `cloudflare:KR` fingerprint as one policy instead of two.
    //
    // Re-thrown as a `PolicyError`: this function documents itself as the authority on policy input and
    // callers catch that type. Letting `geofeed.ts`'s own error class escape would make a bad selector
    // the one kind of bad policy that does not look like bad policy to a caller — both carry
    // `statusCode: 400`, so nothing would fail loudly; it would just be classified wrong.
    try {
      const sel = parseSelector(value);
      value = `${sel.feed}:${sel.scope}`;
    } catch (e) {
      throw bad(e instanceof Error ? e.message : String(e));
    }
  }

  if (kind === "cf-device" || kind === "cf-user") {
    value = normalizeIdentityValue(kind, value, label);
  }

  if (kind === "k8s-service" && !SERVICE_REF.test(value)) {
    throw bad(`${label}.value must be a Service reference "namespace/name", e.g. postgres/postgres-rw`);
  }
  if (kind === "k8s-namespace" && !NAMESPACE_REF.test(value)) {
    throw bad(`${label}.value must be a namespace name, e.g. arc-runners`);
  }
  if (kind === "k8s-label") {
    const parts = value.split(",").map((x) => x.trim()).filter(Boolean);
    if (parts.length === 0) {
      // An empty selector matches *every* pod in the cluster. Same hazard as an empty address
      // group, and the same answer: refuse rather than render the widest possible rule.
      throw bad(`${label}.value is an empty label selector — it would match every pod`);
    }
    for (const part of parts) {
      if (!LABEL_SELECTOR.test(part)) {
        throw bad(
          `${label}.value has an unusable selector term ${JSON.stringify(part)} — ` +
            `expected key=value pairs separated by commas (equality only)`,
        );
      }
    }
    // Sorted and deduplicated: `a=1,b=2` and `b=2,a=1` select the same pods, and leaving them
    // distinct makes `policyFingerprint` report an edit that did not happen.
    value = [...new Set(parts)].sort().join(",");
  }

  return { kind, value };
}

/**
 * Validate and normalise a policy. This is the authority — callers should not pre-validate.
 */
export function normalizePolicy(input: unknown, id: string): Policy {
  const o = (input ?? {}) as Record<string, unknown>;
  const name = String(o.name ?? "").trim();
  if (!name) throw bad("name is required");
  if (name.length > 120) throw bad("name must be 120 characters or fewer");

  const proto = String(o.proto ?? "any").trim().toLowerCase() as Proto;
  if (!PROTOS.has(proto)) throw bad(`proto must be one of ${[...PROTOS].join("|")}`);

  const action = String(o.action ?? "").trim().toLowerCase() as PolicyAction;
  if (action !== "allow" && action !== "deny") throw bad("action must be allow or deny");

  // Meaningless on allow — discard it so two equivalent policies share a fingerprint.
  const denyModeRaw = String(o.denyMode ?? "drop").trim().toLowerCase();
  if (denyModeRaw !== "drop" && denyModeRaw !== "reject") throw bad("denyMode must be drop or reject");
  const denyMode: DenyMode = action === "deny" ? (denyModeRaw as DenyMode) : "drop";

  const priority = Number(o.priority ?? 100);
  if (!Number.isInteger(priority) || priority < 1 || priority > 100000) {
    throw bad("priority must be an integer in 1-100000");
  }

  return {
    id,
    name,
    src: normalizeEndpoint(o.src, "src"),
    dst: normalizeEndpoint(o.dst, "dst"),
    proto,
    ports: normalizePorts(o.ports, proto),
    action,
    denyMode,
    priority,
    enabled: o.enabled === undefined ? true : Boolean(o.enabled),
    notes: String(o.notes ?? "").trim(),
  };
}

/**
 * Partial update: only fields present in `input` replace those in `cur`.
 *
 * Split out because the merge semantics are subtle and getting them wrong deletes data quietly.
 * Only `undefined` counts as "not supplied", so falsy-but-valid values (`ports: ""` meaning all
 * ports, `enabled: false`) survive.
 */
export function mergePolicy(cur: Policy, input: unknown, id: string): Policy {
  const o = (input ?? {}) as Record<string, unknown>;
  const pick = (k: keyof Policy): unknown => (o[k] === undefined ? cur[k] : o[k]);
  return normalizePolicy(
    {
      name: pick("name"),
      src: pick("src"),
      dst: pick("dst"),
      proto: pick("proto"),
      ports: pick("ports"),
      action: pick("action"),
      denyMode: pick("denyMode"),
      priority: pick("priority"),
      enabled: pick("enabled"),
      notes: pick("notes"),
    },
    id,
  );
}

/**
 * Stable fingerprint of a policy's meaning.
 *
 * Useful for change detection against a remote system that rewrites what you sent it (many
 * cloud APIs reformat expressions), where comparing the rendered text produces false diffs.
 *
 * Note this covers the policy *as written*. If your endpoints reference objects whose members
 * can change, fingerprint the **rendered output** instead — otherwise a group edit leaves the
 * fingerprint unchanged and the change is missed.
 */
export function policyFingerprint(p: Policy): string {
  const canon = [
    p.src.kind, p.src.value,
    p.dst.kind, p.dst.value,
    p.proto, p.ports,
    p.action, p.denyMode, String(p.priority), p.enabled ? "1" : "0",
  ].join("|");
  return createHash("sha256").update(canon).digest("hex").slice(0, 12);
}
