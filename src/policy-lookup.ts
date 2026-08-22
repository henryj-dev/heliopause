// "Would this flow be allowed?" — asked of the policy, not of the network.
//
// ## Why this exists
//
// There are two enforcement points and nobody can hold their union in their head. On 2026-08-16 a
// neighbouring team spent two document round trips establishing which of two layers was blocking a
// connection, and the answer — that a `fromCIDR` covering the pod range matches no pod, because
// Cilium classifies pods by identity rather than by address — was written down in a comment in a
// file that does not travel with the rule. This is the screen that should have answered it.
//
// ## What it is careful not to claim
//
// **This reads declarations, not packets.** A rule naming a flow is not proof the flow works, and
// the absence of one is not proof it is blocked: the host baseline, the hook policy, and the
// workload's own native NetworkPolicy — which belongs to whoever owns the workload, not to
// heliopause — all decide things this cannot see. Saying so is the feature. A lookup that answers
// "allowed" when it means "one of the two layers I can read does not object" is worse than no
// lookup, because it is believed.
//
// ## The three-valued answer
//
// Every comparison returns `matches`, `no`, or **`undecidable` with a reason**, and the third is the
// one that carries the lesson. An address cannot tell you whether a rule naming `app=dispatcher`
// applies to it — not "probably not", *cannot*. Collapsing that into "no match" is precisely the
// mistake that made the `fromCIDR` question take two round trips: the rule was right there in the
// list and the reader concluded it did not apply.
import { isWorkload, type Endpoint, type Policy, type Proto } from "./policy.ts";
import { cidrsOverlap } from "./nft.ts";
import { t, type Lang } from "./i18n.ts";

/**
 * What the operator typed.
 *
 * Two ways to name each end, because this system has two ways to name an endpoint and neither
 * translates into the other. An address answers rules written as CIDRs; a workload — `dispatcher`,
 * or `dispatcher/app=vultr-broker` — answers rules written as selectors. Giving only one leaves the
 * other kind undecidable, which is reported rather than hidden.
 *
 * The first version of this took addresses alone, and on the live fleet it answered every query with
 * forty-odd deferred rules and nothing decided: a workload rule cannot be ruled in or out by an
 * address, so *every* workload rule deferred on *every* question. The list was honest and useless.
 * Being unable to answer is worth reporting once; it is not worth reporting forty times.
 */
export interface LookupQuery {
  /** Source address, e.g. `10.17.128.184`. Empty means "do not constrain by address". */
  src: string;
  /** Destination address. Empty means "do not constrain by address". */
  dst: string;
  /** Source workload: `namespace` or `namespace/k=v,k2=v2`. Empty means "not given". */
  srcWorkload?: string;
  /** Destination workload, same shape. */
  dstWorkload?: string;
  /** Destination port. `null` means "any port". */
  port: number | null;
  proto: Proto;
}

/** `dispatcher` or `dispatcher/app=vultr-broker,tier=web` as the operator writes it. */
export interface WorkloadRef {
  namespace: string;
  labels: ReadonlyMap<string, string>;
}

export function parseWorkloadRef(raw: string): WorkloadRef | null {
  const text = raw.trim();
  if (!text) return null;
  const slash = text.indexOf("/");
  const namespace = slash === -1 ? text : text.slice(0, slash);
  const labels = new Map<string, string>();
  if (slash !== -1) {
    for (const pair of text.slice(slash + 1).split(",")) {
      const eq = pair.indexOf("=");
      if (eq === -1) continue;
      labels.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }
  return { namespace, labels };
}

/**
 * The namespace and labels a `k8s-label` selector requires.
 *
 * The selector arrives as Cilium writes it — `k8s:io.kubernetes.pod.namespace=dispatcher,app=x` —
 * so the namespace is one of the labels rather than a separate field, and the `k8s:` prefix is
 * optional depending on who wrote the rule. Both shapes are read here because both are in the live
 * policy.
 */
function selectorParts(value: string): { namespace: string | null; labels: Map<string, string> } {
  const labels = new Map<string, string>();
  let namespace: string | null = null;
  for (const pair of value.split(",")) {
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    const key = pair.slice(0, eq).trim().replace(/^k8s:/, "");
    const val = pair.slice(eq + 1).trim();
    if (key === "io.kubernetes.pod.namespace") namespace = val;
    else labels.set(key, val);
  }
  return { namespace, labels };
}

export type Verdict =
  | { kind: "matches" }
  | { kind: "no"; why: string }
  /**
   * `needsWorkload` marks the one deferral a better question can fix.
   *
   * Kept apart from the others so the screen can say it once instead of forty times. The rest —
   * IPv6, an unresolved service object, a Service whose selector is not in this policy — are not
   * things the operator can restate their way out of, and burying them in the same list as the
   * fixable one is how a reader learns to skim past all of them.
   */
  | { kind: "undecidable"; why: string; needsWorkload?: boolean };

export interface LookupHit {
  id: string;
  name: string;
  action: Policy["action"];
  denyMode: Policy["denyMode"];
  proto: Proto;
  ports: string;
  priority: number;
  enabled: boolean;
  /** Which enforcement point this policy renders on, by the same rule `cilium.ts` uses. */
  layer: "host" | "workload";
  src: Verdict;
  dst: Verdict;
  port: Verdict;
  proto_: Verdict;
  /** `matches` only when every part decided yes; `undecidable` when any part could not be decided. */
  outcome: "matches" | "undecidable";
}

export interface LookupResult {
  /** Rules that name this flow, most decisive first. */
  matches: LookupHit[];
  /** Rules this query could not rule in or out, with the reason for each. */
  undecidable: LookupHit[];
  /**
   * How many of `undecidable` are waiting only on the query naming a workload.
   *
   * Reported as a number so the screen can offer one sentence — "name a workload to decide these" —
   * rather than repeating the same explanation on every row. On the live fleet an address-only query
   * defers forty-odd rules for exactly this reason, and forty identical explanations is a list
   * nobody reads to the end of.
   */
  needsWorkload: number;
  /** How many enabled policies were considered, so an empty answer is not confused with an empty input. */
  considered: number;
}

const V4 = /^(\d{1,3}\.){3}\d{1,3}$/;

/**
 * Is `addr` inside `cidr`?
 *
 * Built on `cidrsOverlap` by asking whether a single address overlaps the range, which is the same
 * question for a /32. That function is deliberately conservative — it answers `true` for anything it
 * could not parse — so IPv6 is screened out here first and reported as undecidable rather than
 * inherited as a silent yes. Over-reporting is the safe direction for a security lookup, but only
 * when the reader is told it happened.
 */
function addrInCidr(addr: string, cidr: string, lang: Lang): Verdict {
  if (!V4.test(addr)) {
    return { kind: "undecidable", why: t(lang, "lookup.notV4", { addr }) };
  }
  if (!V4.test(cidr.split("/")[0] ?? "")) {
    return { kind: "undecidable", why: t(lang, "lookup.ruleNotNarrow", { cidr }) };
  }
  return cidrsOverlap(`${addr}/32`, cidr)
    ? { kind: "matches" }
    : { kind: "no", why: t(lang, "lookup.outside", { addr, cidr }) };
}

/**
 * Does an endpoint name this address?
 *
 * `objects` resolves the `object` kind against the site's address catalogue, so a rule written
 * against a named object is answered rather than deferred. Everything that names a workload is
 * deferred on purpose, with the reason spelled out — that sentence is the most useful output this
 * function produces.
 */
function endpointMatches(
  e: Endpoint,
  addr: string,
  workload: WorkloadRef | null,
  layer: "host" | "workload",
  ctx: { internalSupernet: string; objects: ReadonlyMap<string, readonly string[]> },
  lang: Lang,
): Verdict {
  if (isWorkload(e)) return workloadMatches(e, workload, lang);

  // ## An address-shaped rule, asked about a workload
  //
  // This is where the lookup earns its keep, and where the first live run got it wrong. Asked about
  // the broker pod reaching goatcounter, it answered that `GOATCOUNTER-MESH` matched — a rule whose
  // source is `10.17.0.0/17`, which covers the pod range. On the workload layer that rule **matches
  // no pod at all**: Cilium classifies in-cluster pods by identity, so a `fromCIDR` covering their
  // addresses admits none of them. Reporting it as a match reproduces, on the screen, the exact
  // misreading that took two teams two document round trips on 2026-08-16.
  //
  // The host layer is the other way around. nftables sees packets, and a pod's packet has an
  // address — but this query did not give one, so the honest answer there is that it cannot be
  // decided rather than that it matches.
  if (workload && e.kind !== "any") {
    return layer === "workload"
      ? {
          kind: "no",
          why: t(lang, "lookup.cidrNoPod", { named: e.kind === "cidr" ? e.value : e.kind }),
        }
      : {
          kind: "undecidable",
          why: t(lang, "lookup.hostNeedsAddr"),
        };
  }

  // An empty box means "do not constrain this side", which is what a search form means by empty.
  // Reading it as "undecidable" instead would turn a half-filled query into forty deferred rules,
  // which is the failure this module already had once in the other direction.
  if (addr === "") return { kind: "matches" };
  switch (e.kind) {
    case "any":
      return { kind: "matches" };
    case "cidr":
      return addrInCidr(addr, e.value, lang);
    case "object": {
      const members = ctx.objects.get(e.value);
      if (!members) {
        return { kind: "undecidable", why: t(lang, "lookup.objectMissing", { name: e.value }) };
      }
      for (const m of members) {
        const v = addrInCidr(addr, m, lang);
        if (v.kind === "matches") return v;
        if (v.kind === "undecidable") return v;
      }
      return { kind: "no", why: t(lang, "lookup.notInMembers", { addr, name: e.value }) };
    }
    case "internet": {
      const inside = addrInCidr(addr, ctx.internalSupernet, lang);
      if (inside.kind === "undecidable") return inside;
      return inside.kind === "matches"
        ? { kind: "no", why: t(lang, "lookup.insideInternet", { addr, supernet: ctx.internalSupernet }) }
        : { kind: "matches" };
    }
    default:
      return { kind: "undecidable", why: t(lang, "lookup.kindOutside", { kind: e.kind }) };
  }
}

/**
 * Does a workload endpoint name this workload?
 *
 * The sentence this whole module exists for lives in the `null` branch: **an address can neither
 * match a workload rule nor rule it out**, because Cilium classifies pods by identity. Given a
 * workload, though, the question is answerable, and answering it is what turns a list of everything
 * into a lookup.
 */
function workloadMatches(e: Endpoint, w: WorkloadRef | null, lang: Lang): Verdict {
  if (!w) {
    return {
      kind: "undecidable",
      why: t(lang, "lookup.namesWorkload", { named: e.value ? `${e.kind} ${e.value}` : e.kind }),
      needsWorkload: true,
    };
  }
  if (e.kind === "k8s-namespace") {
    return e.value === w.namespace
      ? { kind: "matches" }
      : { kind: "no", why: t(lang, "lookup.namesNamespace", { ns: e.value }) };
  }
  if (e.kind === "k8s-label") {
    const want = selectorParts(e.value);
    if (want.namespace !== null && want.namespace !== w.namespace) {
      return { kind: "no", why: t(lang, "lookup.namesNamespace", { ns: want.namespace }) };
    }
    for (const [k, v] of want.labels) {
      const got = w.labels.get(k);
      if (got === undefined) {
        // Missing, not different. A selector this query said nothing about is not a selector it fails.
        return { kind: "undecidable", why: t(lang, "lookup.requiresUnstated", { kv: `${k}=${v}` }) };
      }
      if (got !== v) return { kind: "no", why: t(lang, "lookup.requires", { kv: `${k}=${v}` }) };
    }
    return { kind: "matches" };
  }
  if (e.kind === "k8s-service") {
    // A Service names pods through a selector this process does not have. Guessing from the name
    // would be a match invented from a string that happens to look similar.
    return { kind: "undecidable", why: t(lang, "lookup.serviceSelector", { name: e.value }) };
  }
  return { kind: "undecidable", why: t(lang, "lookup.kindOutside", { kind: e.kind }) };
}

/** Does the rule's port spec cover this port? `""` is every port; `@ref` needs a catalogue this has not got. */
export function portMatches(spec: string, port: number | null, lang: Lang = "en"): Verdict {
  if (spec === "") return { kind: "matches" };
  if (spec.startsWith("@")) {
    return { kind: "undecidable", why: t(lang, "lookup.portsFromObject", { name: spec.slice(1) }) };
  }
  if (port === null) return { kind: "matches" };
  for (const part of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    const range = part.split(":");
    if (range.length === 2) {
      const lo = Number(range[0]);
      const hi = Number(range[1]);
      if (Number.isFinite(lo) && Number.isFinite(hi) && port >= lo && port <= hi) return { kind: "matches" };
      continue;
    }
    if (Number(part) === port) return { kind: "matches" };
  }
  return { kind: "no", why: t(lang, "lookup.portNotIn", { port, spec }) };
}

function protoMatches(rule: Proto, asked: Proto, lang: Lang): Verdict {
  if (rule === "any" || asked === "any") return { kind: "matches" };
  return rule === asked ? { kind: "matches" } : { kind: "no", why: t(lang, "lookup.ruleIs", { proto: rule }) };
}

/**
 * Which declared rules name this flow.
 *
 * Disabled policies are excluded and counted nowhere: a rule that is off is not an answer to
 * "what decides this", and listing it would put the reader one careless glance from believing a
 * flow is covered by something switched off.
 */
export function lookupPolicies(
  policies: readonly Policy[],
  query: LookupQuery,
  site: { internalSupernet: string; objects?: ReadonlyMap<string, readonly string[]> },
  lang: Lang = "en",
): LookupResult {
  const ctx = { internalSupernet: site.internalSupernet, objects: site.objects ?? new Map() };
  const srcWorkload = parseWorkloadRef(query.srcWorkload ?? "");
  const dstWorkload = parseWorkloadRef(query.dstWorkload ?? "");
  const matches: LookupHit[] = [];
  const undecidable: LookupHit[] = [];
  let considered = 0;

  for (const p of policies) {
    if (!p.enabled) continue;
    considered++;
    // Computed before the endpoints are judged, because on this system what a CIDR means depends on
    // which enforcement point renders it.
    const layer: "host" | "workload" = isWorkload(p.src) || isWorkload(p.dst) ? "workload" : "host";
    const src = endpointMatches(p.src, query.src, srcWorkload, layer, ctx, lang);
    const dst = endpointMatches(p.dst, query.dst, dstWorkload, layer, ctx, lang);
    const port = portMatches(p.ports, query.port, lang);
    const proto_ = protoMatches(p.proto, query.proto, lang);
    const parts = [src, dst, port, proto_];
    if (parts.some((v) => v.kind === "no")) continue;

    const hit: LookupHit = {
      id: p.id, name: p.name, action: p.action, denyMode: p.denyMode,
      proto: p.proto, ports: p.ports, priority: p.priority, enabled: p.enabled,
      layer,
      src, dst, port, proto_,
      outcome: parts.some((v) => v.kind === "undecidable") ? "undecidable" : "matches",
    };
    (hit.outcome === "matches" ? matches : undecidable).push(hit);
  }

  // Deny first, then by priority. Not cosmetic: on the workload layer a deny beats every allow and no
  // later rule can carve an exception out of it, so a reader scanning from the top meets the rule that
  // actually decides. The host layer is ordered by priority, which is why that is the second key.
  const order = (a: LookupHit, b: LookupHit): number =>
    (a.action === b.action ? 0 : a.action === "deny" ? -1 : 1) || a.priority - b.priority;
  matches.sort(order);
  undecidable.sort(order);
  const needsWorkload = undecidable.filter((h) =>
    [h.src, h.dst].some((v) => v.kind === "undecidable" && v.needsWorkload)
  ).length;
  return { matches, undecidable, needsWorkload, considered };
}
